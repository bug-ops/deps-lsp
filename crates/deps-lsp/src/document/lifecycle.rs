//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::loader::load_document_from_disk;
use super::state::{DocumentState, ServerState};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use crate::progress::{ProgressSender, RegistryProgress};
use deps_core::Ecosystem;
use deps_core::Registry;
use deps_core::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{MessageType, Uri};

/// Preserves cached version data from old document state to new state.
/// Called during document updates to avoid re-fetching versions for unchanged deps.
fn preserve_cache(new_state: &mut DocumentState, old_state: &DocumentState) {
    tracing::trace!(
        cached = old_state.cached_versions.len(),
        resolved = old_state.resolved_versions.len(),
        "preserving version cache"
    );
    new_state
        .cached_versions
        .clone_from(&old_state.cached_versions);
    new_state
        .resolved_versions
        .clone_from(&old_state.resolved_versions);
}

/// Diff between old and new dependency sets.
#[derive(Debug, Clone, Default)]
struct DependencyDiff {
    added: Vec<String>,
    #[allow(dead_code)]
    removed: Vec<String>,
}

impl DependencyDiff {
    fn compute(old_deps: &HashSet<String>, new_deps: &HashSet<String>) -> Self {
        Self {
            added: new_deps.difference(old_deps).cloned().collect(),
            removed: old_deps.difference(new_deps).cloned().collect(),
        }
    }

    #[cfg(test)]
    fn needs_fetch(&self) -> bool {
        !self.added.is_empty()
    }
}

/// Result of parallel version fetching.
struct FetchResult {
    /// Successfully fetched versions (package -> latest version)
    versions: HashMap<String, String>,
    /// Number of packages that failed to fetch (timeout or error)
    failed_count: usize,
}

/// Fetches latest versions for multiple packages in parallel with progress reporting.
///
/// Returns a [`FetchResult`] containing successfully fetched versions and failure count.
/// Packages that fail to fetch are omitted from the versions map.
///
/// This function executes all registry requests concurrently with per-dependency
/// timeout isolation, preventing slow packages from blocking others.
///
/// # Arguments
///
/// * `registry` - Package registry to fetch from
/// * `package_names` - List of package names to fetch
/// * `progress` - Optional progress tracker (will be updated after each fetch)
/// * `timeout_secs` - Timeout for each individual package fetch (default: 10s)
/// * `max_concurrent` - Maximum concurrent fetches (default: 20)
///
/// # Timeout Behavior
///
/// Each package fetch is wrapped in an individual timeout. If a package
/// takes longer than `timeout_secs` to fetch, it fails fast with a warning
/// and does NOT block other packages.
///
/// # Performance
///
/// With 50 dependencies and 100ms per request:
/// - Sequential: 50 × 100ms = 5000ms
/// - Parallel (no timeout): max(100ms) ≈ 150ms
/// - Parallel (10s timeout, 1 slow package at 30s): max(10s) ≈ 10s
async fn fetch_latest_versions_parallel(
    registry: Arc<dyn Registry>,
    package_names: Vec<String>,
    progress_sender: Option<ProgressSender>,
    timeout_secs: u64,
    max_concurrent: usize,
) -> FetchResult {
    use futures::stream::{self, StreamExt};
    use std::time::Duration;

    let fetched = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let timeout = Duration::from_secs(timeout_secs);

    let results: Vec<_> = stream::iter(package_names)
        .map(|name| {
            let registry = Arc::clone(&registry);
            let fetched = Arc::clone(&fetched);
            let failed = Arc::clone(&failed);
            let progress_sender = progress_sender.clone();
            async move {
                let result =
                    tokio::time::timeout(timeout, registry.get_latest_matching(&name, "*")).await;

                let version = match result {
                    Ok(Ok(Some(v))) => {
                        tracing::debug!(package = %name, version = %v.version_string(), "fetched");
                        Some((name.clone(), v.version_string().to_string()))
                    }
                    Ok(Ok(None)) => {
                        tracing::debug!(package = %name, "no version found");
                        None
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(package = %name, error = %e, "fetch failed");
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        None
                    }
                    Err(_) => {
                        tracing::warn!(package = %name, "fetch timed out ({}s)", timeout.as_secs());
                        failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        None
                    }
                };

                let count = fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(ref sender) = progress_sender {
                    sender.send(count);
                }

                version
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    FetchResult {
        versions: results.into_iter().flatten().collect(),
        failed_count: failed.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// Generic document open handler using ecosystem registry.
///
/// Parses manifest using the ecosystem's parser, creates document state,
/// and spawns a background task to fetch version information from the registry.
pub async fn handle_document_open(
    uri: Uri,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {:?}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
                "{uri:?}"
            )));
        }
    };

    tracing::info!(
        "Opening {:?} with ecosystem: {}",
        uri,
        ecosystem.display_name()
    );

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = ecosystem.parse_manifest(&content, &uri).await.ok();

    // Create document state (parse_result may be None)
    let doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(ecosystem.id(), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(ecosystem.id(), content)
    };

    state.update_document(uri.clone(), doc_state);

    // Clone cache config before spawning background task
    let cache_config = { config.read().await.cache.clone() };

    // Spawn background task to fetch versions
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let client_clone = client.clone();

    let task = tokio::spawn(async move {
        tracing::debug!("background task started");

        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Update document state with resolved versions immediately
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
            // Use resolved versions as cached versions for instant display
            doc.update_cached_versions(resolved_versions.clone());
        }

        // Collect dependency names while holding reference (can't hold across await)
        let dep_names: Vec<String> = {
            let doc = match state_clone.get_document(&uri_clone) {
                Some(d) => d,
                None => {
                    tracing::warn!("document not found, aborting fetch");
                    return;
                }
            };
            let parse_result = match doc.parse_result() {
                Some(p) => p,
                None => {
                    tracing::warn!("no parse result, aborting fetch");
                    return;
                }
            };
            parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().to_string())
                .collect()
        };

        tracing::debug!(count = dep_names.len(), "starting registry fetch");

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(client_clone.clone(), uri_clone.as_str(), dep_names.len()),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        };

        tracing::debug!("progress started, fetching versions");

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            dep_names,
            progress_sender,
            cache_config.fetch_timeout_secs,
            cache_config.max_concurrent_fetches,
        )
        .await;

        let success = !fetch_result.versions.is_empty();
        tracing::debug!(
            fetched = fetch_result.versions.len(),
            failed = fetch_result.failed_count,
            "registry fetch complete"
        );

        // Update document state with cached versions (latest from registry)
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.update_cached_versions(fetch_result.versions);
            if success {
                doc.set_loaded();
            } else {
                doc.set_failed();
            }
        }

        // End progress
        if let Some(progress) = progress {
            progress.end(success).await;
        }

        // Notify user about failed packages
        if fetch_result.failed_count > 0 {
            client_clone
                .show_message(
                    tower_lsp_server::ls_types::MessageType::WARNING,
                    format!(
                        "deps-lsp: {} package(s) failed to fetch (timeout or network error)",
                        fetch_result.failed_count
                    ),
                )
                .await;
        }

        // Refresh inlay hints IMMEDIATELY after loading completes
        // (before diagnostics which may take longer due to additional network calls)
        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }

        // Publish diagnostics (may be slower, runs after hints are already visible)
        let diags =
            diagnostics::generate_diagnostics_internal(Arc::clone(&state_clone), &uri_clone).await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;
    });

    Ok(task)
}

/// Generic document change handler using ecosystem registry.
///
/// Re-parses manifest when document content changes and spawns a debounced
/// task to update diagnostics and request inlay hint refresh.
pub async fn handle_document_change(
    uri: Uri,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {:?}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(format!(
                "{uri:?}"
            )));
        }
    };

    // Extract old dependency names before parsing (for diff computation)
    let old_dep_names: HashSet<String> =
        state.get_document(&uri).map_or_else(HashSet::new, |doc| {
            doc.parse_result()
                .map(|pr| {
                    pr.dependencies()
                        .into_iter()
                        .map(|d| d.name().to_string())
                        .collect()
                })
                .unwrap_or_default()
        });

    // Try to parse manifest (may fail for incomplete syntax)
    let parse_result = ecosystem.parse_manifest(&content, &uri).await.ok();

    // Extract new dependency names for diff
    let new_dep_names: HashSet<String> = parse_result
        .as_ref()
        .map(|pr| {
            pr.dependencies()
                .into_iter()
                .map(|d| d.name().to_string())
                .collect()
        })
        .unwrap_or_default();

    // Compute dependency diff
    let diff = DependencyDiff::compute(&old_dep_names, &new_dep_names);
    tracing::debug!(
        added = diff.added.len(),
        removed = diff.removed.len(),
        "dependency diff"
    );

    let mut doc_state = if let Some(pr) = parse_result {
        DocumentState::new_from_parse_result(ecosystem.id(), content, pr)
    } else {
        tracing::debug!("Failed to parse manifest, storing document without parse result");
        DocumentState::new_without_parse_result(ecosystem.id(), content)
    };

    if let Some(old_doc) = state.get_document(&uri) {
        preserve_cache(&mut doc_state, &old_doc);
    }

    // Prune stale cache entries for removed dependencies
    for removed_dep in &diff.removed {
        doc_state.cached_versions.remove(removed_dep);
        doc_state.resolved_versions.remove(removed_dep);
    }

    state.update_document(uri.clone(), doc_state);

    // Clone cache config before spawning background task
    let cache_config = { config.read().await.cache.clone() };

    // Spawn background task to update diagnostics
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let client_clone = client.clone();
    let deps_to_fetch = diff.added;

    let task = tokio::spawn(async move {
        // Small debounce delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Update document state with resolved versions only
        // Do NOT touch cached_versions - they contain latest registry versions
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
        }

        // Skip registry fetch if no new dependencies
        if deps_to_fetch.is_empty() {
            tracing::debug!("no new dependencies, skipping registry fetch");

            if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
                doc.set_loaded();
            }

            if let Err(e) = client_clone.inlay_hint_refresh().await {
                tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
            }

            let diags =
                diagnostics::generate_diagnostics_internal(Arc::clone(&state_clone), &uri_clone)
                    .await;
            client_clone
                .publish_diagnostics(uri_clone.clone(), diags, None)
                .await;
            return;
        }

        tracing::info!(
            count = deps_to_fetch.len(),
            "fetching versions for new dependencies"
        );

        // Mark as loading and start progress
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.set_loading();
        }

        let (progress, progress_sender) = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            RegistryProgress::start(
                client_clone.clone(),
                uri_clone.as_str(),
                deps_to_fetch.len(),
            ),
        )
        .await
        {
            Ok(Ok((p, s))) => (Some(p), Some(s)),
            _ => (None, None),
        };

        // Fetch latest versions only for NEW dependencies
        let registry = ecosystem_clone.registry();
        let fetch_result = fetch_latest_versions_parallel(
            registry,
            deps_to_fetch,
            progress_sender,
            cache_config.fetch_timeout_secs,
            cache_config.max_concurrent_fetches,
        )
        .await;

        let success = !fetch_result.versions.is_empty();

        // Merge new versions into existing cache
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            for (name, version) in fetch_result.versions {
                doc.cached_versions.insert(name, version);
            }
            if success {
                doc.set_loaded();
            } else {
                doc.set_failed();
            }
        }

        if let Some(progress) = progress {
            progress.end(success).await;
        }

        // Notify user about failed packages
        if fetch_result.failed_count > 0 {
            client_clone
                .show_message(
                    tower_lsp_server::ls_types::MessageType::WARNING,
                    format!(
                        "deps-lsp: {} package(s) failed to fetch (timeout or network error)",
                        fetch_result.failed_count
                    ),
                )
                .await;
        }

        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }

        let diags =
            diagnostics::generate_diagnostics_internal(Arc::clone(&state_clone), &uri_clone).await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;
    });

    Ok(task)
}

/// Loads resolved versions from lock file for a given manifest URI.
///
/// Uses the ecosystem's lockfile provider to parse the lock file.
/// Returns a HashMap mapping package names to their resolved versions.
/// Returns an empty HashMap if no lock file is found or parsing fails.
async fn load_resolved_versions(
    uri: &Uri,
    state: &ServerState,
    ecosystem: &dyn Ecosystem,
) -> HashMap<String, String> {
    let lock_provider = match ecosystem.lockfile_provider() {
        Some(p) => p,
        None => {
            tracing::debug!("No lock file provider for ecosystem {}", ecosystem.id());
            return HashMap::new();
        }
    };

    let lockfile_path = match lock_provider.locate_lockfile(uri) {
        Some(path) => path,
        None => {
            tracing::debug!("No lock file found for {:?}", uri);
            return HashMap::new();
        }
    };

    match state
        .lockfile_cache
        .get_or_parse(lock_provider.as_ref(), &lockfile_path)
        .await
    {
        Ok(resolved) => {
            tracing::info!(
                "Loaded {} resolved versions from {}",
                resolved.len(),
                lockfile_path.display()
            );
            resolved
                .iter()
                .map(|(name, pkg)| (name.clone(), pkg.version.clone()))
                .collect()
        }
        Err(e) => {
            tracing::warn!("Failed to parse lock file: {}", e);
            HashMap::new()
        }
    }
}

/// Ensures a document is loaded in state.
///
/// If the document is not already in state, loads it from disk,
/// parses it, and spawns a background task to fetch version information.
///
/// This function is idempotent - calling it multiple times with the
/// same URI is safe and will only load once.
///
/// # Arguments
///
/// * `uri` - Document URI
/// * `state` - Server state
/// * `client` - LSP client for notifications
/// * `config` - Server configuration
///
/// # Returns
///
/// * `true` - Document is now loaded (either already existed or was just loaded)
/// * `false` - Document could not be loaded (unsupported file type, read error, etc.)
///
/// # Behavior
///
/// - If document exists in state → Return true immediately (no-op)
/// - If document doesn't exist → Load from disk, parse, update state, spawn bg task
/// - If load fails → Log warning and return false (graceful degradation)
///
/// # Examples
///
/// ```no_run
/// use deps_lsp::document::ensure_document_loaded;
/// use deps_lsp::document::ServerState;
/// use tower_lsp_server::ls_types::Uri;
/// use std::sync::Arc;
///
/// # async fn example(
/// #     uri: &Uri,
/// #     state: Arc<ServerState>,
/// #     client: tower_lsp_server::Client,
/// #     config: Arc<tokio::sync::RwLock<deps_lsp::config::DepsConfig>>,
/// # ) {
/// let loaded = ensure_document_loaded(uri, state, client, config).await;
/// if loaded {
///     println!("Document is available for processing");
/// }
/// # }
/// ```
pub async fn ensure_document_loaded(
    uri: &Uri,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> bool {
    // Fast path: document already loaded
    if state.get_document(uri).is_some() {
        tracing::debug!("Document already loaded: {:?}", uri);
        return true;
    }

    // Clone cold start config before async operations to release lock
    let cold_start_config = { config.read().await.cold_start.clone() };

    // Check if cold start is enabled
    if !cold_start_config.enabled {
        tracing::debug!("Cold start disabled via configuration");
        return false;
    }

    // Rate limiting check
    if !state.cold_start_limiter.allow_cold_start(uri) {
        tracing::warn!("Cold start rate limited: {:?}", uri);
        return false;
    }

    // Check if we support this file type
    if state.ecosystem_registry.get_for_uri(uri).is_none() {
        tracing::debug!("Unsupported file type: {:?}", uri);
        return false;
    }

    // Load from disk
    tracing::info!("Loading document from disk (cold start): {:?}", uri);
    let content = match load_document_from_disk(uri).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to load document {:?}: {}", uri, e);
            client
                .log_message(MessageType::WARNING, format!("Could not load file: {e}"))
                .await;
            return false;
        }
    };

    // Reuse existing handle_document_open logic
    match handle_document_open(
        uri.clone(),
        content,
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    {
        Ok(task) => {
            state.spawn_background_task(uri.clone(), task).await;
            tracing::info!("Document loaded successfully from disk: {:?}", uri);
            true
        }
        Err(e) => {
            tracing::warn!("Failed to process loaded document {:?}: {}", uri, e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generic tests (no feature flag required)

    #[test]
    fn test_ecosystem_registry_unknown_file() {
        let state = ServerState::new();
        let unknown_uri =
            tower_lsp_server::ls_types::Uri::from_file_path("/test/unknown.txt").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&unknown_uri).is_none());
    }

    #[tokio::test]
    async fn test_ensure_document_loaded_unsupported_file_check() {
        // Returns false for unknown file types (e.g., README.md)
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/README.md").unwrap();

        // Verify ecosystem registry correctly identifies unsupported files
        assert!(
            state.ecosystem_registry.get_for_uri(&uri).is_none(),
            "README.md should not have an ecosystem handler"
        );

        // This would cause ensure_document_loaded to return false
        // We test the underlying condition without needing Client
    }

    #[tokio::test]
    async fn test_ensure_document_loaded_file_not_found_check() {
        // Test that load_document_from_disk fails gracefully for missing files
        use super::load_document_from_disk;

        let uri = Uri::from_file_path("/nonexistent/Cargo.toml").unwrap();
        let result = load_document_from_disk(&uri).await;

        assert!(result.is_err(), "Should fail for missing files");

        // This error would cause ensure_document_loaded to return false
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_with_timeout() {
        use async_trait::async_trait;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        // Mock registry that always times out
        struct TimeoutRegistry;

        #[async_trait]
        impl Registry for TimeoutRegistry {
            async fn get_versions(&self, _name: &str) -> deps_core::Result<Vec<Box<dyn Version>>> {
                // Sleep longer than timeout (10s default)
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(vec![])
            }

            async fn get_latest_matching(
                &self,
                _name: &str,
                _req: &str,
            ) -> deps_core::Result<Option<Box<dyn Version>>> {
                // Sleep longer than timeout
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(None)
            }

            async fn search(
                &self,
                _query: &str,
                _limit: usize,
            ) -> deps_core::Result<Vec<Box<dyn Metadata>>> {
                Ok(vec![])
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(TimeoutRegistry);
        let packages = vec!["slow-package".to_string()];

        // Use 1 second timeout for test speed
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;

        // Should return empty (timeout, not success)
        assert!(result.versions.is_empty(), "Slow package should timeout");
        assert_eq!(result.failed_count, 1, "Should track 1 failed package");
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_fast_packages_not_blocked() {
        use async_trait::async_trait;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        // Mock registry with one slow, one fast package
        struct MixedRegistry;

        #[async_trait]
        impl Registry for MixedRegistry {
            async fn get_versions(&self, name: &str) -> deps_core::Result<Vec<Box<dyn Version>>> {
                if name == "slow-package" {
                    // Sleep longer than timeout
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                // Fast package or unknown: return immediately
                Ok(vec![])
            }

            async fn get_latest_matching(
                &self,
                name: &str,
                _req: &str,
            ) -> deps_core::Result<Option<Box<dyn Version>>> {
                if name == "slow-package" {
                    // Sleep longer than timeout
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
                // Fast package or unknown: return immediately (no versions)
                Ok(None)
            }

            async fn search(
                &self,
                _query: &str,
                _limit: usize,
            ) -> deps_core::Result<Vec<Box<dyn Metadata>>> {
                Ok(vec![])
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(MixedRegistry);
        let packages = vec!["slow-package".to_string(), "fast-package".to_string()];

        let start = std::time::Instant::now();
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;
        let elapsed = start.elapsed();

        // Should complete in ~1s (timeout), not 10s (slow package duration)
        assert!(
            elapsed < Duration::from_secs(3),
            "Should not wait for slow package: {:?}",
            elapsed
        );

        // Fast package processed (no versions), slow package timed out
        assert!(
            result.versions.is_empty(),
            "No versions returned (test registry returns empty)"
        );
        assert_eq!(
            result.failed_count, 1,
            "Slow package should be marked as failed"
        );
    }

    #[tokio::test]
    async fn test_fetch_latest_versions_parallel_concurrency_limit() {
        use async_trait::async_trait;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // Mock registry that tracks concurrent requests
        struct ConcurrencyTrackingRegistry {
            current: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl Registry for ConcurrencyTrackingRegistry {
            async fn get_versions(&self, _name: &str) -> deps_core::Result<Vec<Box<dyn Version>>> {
                // Increment concurrent counter
                let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;

                // Track max concurrent
                self.max_seen.fetch_max(current, Ordering::SeqCst);

                // Simulate work
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Decrement counter
                self.current.fetch_sub(1, Ordering::SeqCst);

                Ok(vec![])
            }

            async fn get_latest_matching(
                &self,
                _name: &str,
                _req: &str,
            ) -> deps_core::Result<Option<Box<dyn Version>>> {
                // Increment concurrent counter
                let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;

                // Track max concurrent
                self.max_seen.fetch_max(current, Ordering::SeqCst);

                // Simulate work
                tokio::time::sleep(Duration::from_millis(50)).await;

                // Decrement counter
                self.current.fetch_sub(1, Ordering::SeqCst);

                Ok(None)
            }

            async fn search(
                &self,
                _query: &str,
                _limit: usize,
            ) -> deps_core::Result<Vec<Box<dyn Metadata>>> {
                Ok(vec![])
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let registry: Arc<dyn Registry> = Arc::new(ConcurrencyTrackingRegistry {
            current: Arc::clone(&current),
            max_seen: Arc::clone(&max_seen),
        });

        // Create 50 packages, limit concurrency to 20
        let packages: Vec<String> = (0..50).map(|i| format!("package-{}", i)).collect();

        fetch_latest_versions_parallel(registry, packages, None, 5, 20).await;

        // Max concurrent should not exceed limit (allow small margin for timing)
        let max = max_seen.load(Ordering::SeqCst);
        assert!(
            max <= 22,
            "Concurrency limit violated: {} concurrent requests (limit: 20)",
            max
        );
    }

    #[tokio::test]
    async fn test_fetch_partial_success_with_mixed_outcomes() {
        use async_trait::async_trait;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        // Mock version for successful fetches
        #[derive(Debug)]
        struct MockVersion {
            version: String,
        }

        impl Version for MockVersion {
            fn version_string(&self) -> &str {
                &self.version
            }

            fn is_prerelease(&self) -> bool {
                false
            }

            fn is_yanked(&self) -> bool {
                false
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        // Mock registry with mixed outcomes:
        // - "package-fast" returns quickly with version
        // - "package-slow" times out
        // - "package-error" returns error
        struct MixedOutcomeRegistry;

        #[async_trait]
        impl Registry for MixedOutcomeRegistry {
            async fn get_versions(&self, name: &str) -> deps_core::Result<Vec<Box<dyn Version>>> {
                match name {
                    "package-fast" => {
                        // Return immediately with a stable version
                        Ok(vec![Box::new(MockVersion {
                            version: "1.0.0".to_string(),
                        })])
                    }
                    "package-slow" => {
                        // Sleep longer than timeout (test uses 1s timeout)
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        Ok(vec![])
                    }
                    "package-error" => {
                        // Return cache error (simpler for testing)
                        Err(deps_core::error::DepsError::CacheError(
                            "Mock registry error".to_string(),
                        ))
                    }
                    _ => Ok(vec![]),
                }
            }

            async fn get_latest_matching(
                &self,
                name: &str,
                _req: &str,
            ) -> deps_core::Result<Option<Box<dyn Version>>> {
                match name {
                    "package-fast" => Ok(Some(Box::new(MockVersion {
                        version: "1.0.0".to_string(),
                    }))),
                    "package-slow" => {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        Ok(None)
                    }
                    "package-error" => Err(deps_core::error::DepsError::CacheError(
                        "Mock registry error".to_string(),
                    )),
                    _ => Ok(None),
                }
            }

            async fn search(
                &self,
                _query: &str,
                _limit: usize,
            ) -> deps_core::Result<Vec<Box<dyn Metadata>>> {
                Ok(vec![])
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(MixedOutcomeRegistry);
        let packages = vec![
            "package-fast".to_string(),
            "package-slow".to_string(),
            "package-error".to_string(),
        ];

        // Use 1 second timeout for test speed
        let result = fetch_latest_versions_parallel(registry, packages, None, 1, 10).await;

        // Only the fast package should be in results
        assert_eq!(
            result.versions.len(),
            1,
            "Should have exactly 1 successful package"
        );
        assert_eq!(
            result.versions.get("package-fast"),
            Some(&"1.0.0".to_string()),
            "Fast package should have correct version"
        );
        assert!(
            !result.versions.contains_key("package-slow"),
            "Slow package should not be in results (timeout)"
        );
        assert!(
            !result.versions.contains_key("package-error"),
            "Error package should not be in results"
        );
    }

    #[tokio::test]
    async fn test_fetch_registry_error_handled() {
        use async_trait::async_trait;
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        // Mock registry that returns errors for all packages
        struct ErrorRegistry;

        #[async_trait]
        impl Registry for ErrorRegistry {
            async fn get_versions(&self, name: &str) -> deps_core::Result<Vec<Box<dyn Version>>> {
                Err(deps_core::error::DepsError::CacheError(format!(
                    "Failed to fetch package: {}",
                    name
                )))
            }

            async fn get_latest_matching(
                &self,
                name: &str,
                _req: &str,
            ) -> deps_core::Result<Option<Box<dyn Version>>> {
                Err(deps_core::error::DepsError::CacheError(format!(
                    "Failed to fetch package: {}",
                    name
                )))
            }

            async fn search(
                &self,
                _query: &str,
                _limit: usize,
            ) -> deps_core::Result<Vec<Box<dyn Metadata>>> {
                Ok(vec![])
            }

            fn package_url(&self, name: &str) -> String {
                format!("https://example.com/{}", name)
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let registry: Arc<dyn Registry> = Arc::new(ErrorRegistry);
        let packages = vec![
            "package-1".to_string(),
            "package-2".to_string(),
            "package-3".to_string(),
        ];

        // Should not panic, just return empty result
        let result = fetch_latest_versions_parallel(registry, packages, None, 5, 10).await;

        // All packages failed, result should be empty
        assert!(
            result.versions.is_empty(),
            "All packages with errors should be omitted from results"
        );
        assert_eq!(
            result.failed_count, 3,
            "All 3 packages should be marked as failed"
        );
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let cargo_uri =
                tower_lsp_server::ls_types::Uri::from_file_path("/test/Cargo.toml").unwrap();
            assert!(state.ecosystem_registry.get_for_uri(&cargo_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/Cargo.toml").unwrap();
            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                "cargo",
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            assert_eq!(state.document_count(), 1);
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id, "cargo");
        }

        #[tokio::test]
        async fn test_document_stored_even_when_parsing_fails() {
            let state = Arc::new(ServerState::new());
            let uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/Cargo.toml").unwrap();
            // Invalid TOML that will fail parsing
            let content = r#"[dependencies
serde = "1.0"
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem not found");

            // Try to parse (will fail)
            let parse_result = ecosystem.parse_manifest(content, &uri).await.ok();
            assert!(
                parse_result.is_none(),
                "Parsing should fail for invalid TOML"
            );

            // Create document state without parse result
            let doc_state = if let Some(pr) = parse_result {
                DocumentState::new_from_parse_result("cargo", content.to_string(), pr)
            } else {
                DocumentState::new_without_parse_result("cargo", content.to_string())
            };

            state.update_document(uri.clone(), doc_state);

            // Document should be stored despite parse failure
            let doc = state.get_document(&uri);
            assert!(
                doc.is_some(),
                "Document should be stored even when parsing fails"
            );

            let doc = doc.unwrap();
            assert_eq!(doc.ecosystem_id, "cargo");
            assert_eq!(doc.content, content);
            assert!(
                doc.parse_result().is_none(),
                "Parse result should be None for failed parse"
            );
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_fast_path() {
            // Fast path: document already loaded, should return true without loading
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let content = r#"[dependencies]
serde = "1.0""#;

            // Pre-populate state with document
            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state =
                DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
            state.update_document(uri.clone(), doc_state);

            // Fast path check: document exists
            assert!(
                state.get_document(&uri).is_some(),
                "Document should exist in state"
            );
            assert_eq!(state.document_count(), 1, "Document count should be 1");

            // The fast path in ensure_document_loaded would return true here without
            // requiring a Client. We test the condition directly since creating a test
            // Client requires complex tower-lsp-server internals (ServerState, ClientSocket).
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_successful_disk_load() {
            // Test successful load from filesystem with temp file
            use super::super::load_document_from_disk;
            use std::fs;
            use tempfile::TempDir;

            // Create a temporary directory with a Cargo.toml file
            let temp_dir = TempDir::new().unwrap();
            let cargo_toml_path = temp_dir.path().join("Cargo.toml");
            let content = r#"[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#;
            fs::write(&cargo_toml_path, content).unwrap();

            let uri = Uri::from_file_path(&cargo_toml_path).unwrap();

            // Test that load_document_from_disk succeeds
            let loaded_content = load_document_from_disk(&uri).await.unwrap();
            assert_eq!(loaded_content, content);

            // Test that parsing succeeds
            let state = Arc::new(ServerState::new());
            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");
            let parse_result = ecosystem.parse_manifest(&loaded_content, &uri).await;
            assert!(parse_result.is_ok(), "Should parse successfully");

            // These successful operations are the building blocks of ensure_document_loaded
        }

        #[tokio::test]
        async fn test_ensure_document_loaded_idempotent_check() {
            // Test that repeated loads are idempotent at the state level
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let content = r#"[dependencies]
serde = "1.0""#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("Cargo ecosystem");

            // Parse twice to simulate idempotent loads
            let parse_result1 = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let parse_result2 = ecosystem.parse_manifest(content, &uri).await.unwrap();

            // First update
            let doc_state1 =
                DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result1);
            state.update_document(uri.clone(), doc_state1);
            assert_eq!(state.document_count(), 1);

            // Second update (idempotent)
            let doc_state2 =
                DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result2);
            state.update_document(uri.clone(), doc_state2);
            assert_eq!(
                state.document_count(),
                1,
                "Should still have only 1 document"
            );
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let npm_uri =
                tower_lsp_server::ls_types::Uri::from_file_path("/test/package.json").unwrap();
            assert!(state.ecosystem_registry.get_for_uri(&npm_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri =
                tower_lsp_server::ls_types::Uri::from_file_path("/test/package.json").unwrap();
            let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("npm ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                "npm",
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id, "npm");
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let pypi_uri =
                tower_lsp_server::ls_types::Uri::from_file_path("/test/pyproject.toml").unwrap();
            assert!(state.ecosystem_registry.get_for_uri(&pypi_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri =
                tower_lsp_server::ls_types::Uri::from_file_path("/test/pyproject.toml").unwrap();
            let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#;

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("pypi ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                "pypi",
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id, "pypi");
        }
    }

    // Go-specific tests
    #[cfg(feature = "go")]
    mod go_tests {
        use super::*;

        #[test]
        fn test_ecosystem_registry_lookup() {
            let state = ServerState::new();
            let go_uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/go.mod").unwrap();
            assert!(state.ecosystem_registry.get_for_uri(&go_uri).is_some());
        }

        #[tokio::test]
        async fn test_document_parsing() {
            let state = Arc::new(ServerState::new());
            let uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/go.mod").unwrap();
            let content = r"module example.com/mymodule

go 1.21

require github.com/gorilla/mux v1.8.0
";

            let ecosystem = state
                .ecosystem_registry
                .get_for_uri(&uri)
                .expect("go ecosystem not found");

            let parse_result = ecosystem.parse_manifest(content, &uri).await;
            assert!(parse_result.is_ok());

            let doc_state = DocumentState::new_from_parse_result(
                "go",
                content.to_string(),
                parse_result.unwrap(),
            );
            state.update_document(uri.clone(), doc_state);

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(doc.ecosystem_id, "go");
        }
    }

    // Phase 1: Cache Preservation Tests
    #[cfg(feature = "cargo")]
    mod incremental_fetch_tests {
        use super::*;

        #[tokio::test]
        async fn test_preserve_cached_versions_on_change() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

            // Initial document with 2 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 =
                DocumentState::new_from_parse_result("cargo", content1.to_string(), parse_result1);
            state.update_document(uri.clone(), doc_state1);

            // Manually populate cache (simulating background fetch)
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".to_string(), "1.0.210".to_string());
                doc.cached_versions
                    .insert("tokio".to_string(), "1.40.0".to_string());
                doc.resolved_versions
                    .insert("serde".to_string(), "1.0.195".to_string());
                doc.resolved_versions
                    .insert("tokio".to_string(), "1.35.0".to_string());
            }

            // Verify cache populated
            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(doc.cached_versions.len(), 2);
                assert_eq!(doc.resolved_versions.len(), 2);
            }

            // Change document (modify serde version)
            let content2 = r#"[dependencies]
serde = "1.0.210"
tokio = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 =
                DocumentState::new_from_parse_result("cargo", content2.to_string(), parse_result2);

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache preserved after update
            {
                let doc = state.get_document(&uri).unwrap();
                assert_eq!(
                    doc.cached_versions.len(),
                    2,
                    "Cached versions should be preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("serde"),
                    Some(&"1.0.210".to_string()),
                    "serde cache preserved"
                );
                assert_eq!(
                    doc.cached_versions.get("tokio"),
                    Some(&"1.40.0".to_string()),
                    "tokio cache preserved"
                );
                assert_eq!(
                    doc.resolved_versions.len(),
                    2,
                    "Resolved versions should be preserved"
                );
            }
        }

        #[tokio::test]
        async fn test_first_open_has_empty_cache() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

            let content = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let doc_state =
                DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
            state.update_document(uri.clone(), doc_state);

            // First open: cache should be empty (no old state to preserve)
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                0,
                "First open should have empty cache"
            );
        }

        #[tokio::test]
        async fn test_preserve_cache_on_parse_failure() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

            // Valid initial document
            let content1 = r#"[dependencies]
serde = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 =
                DocumentState::new_from_parse_result("cargo", content1.to_string(), parse_result1);
            state.update_document(uri.clone(), doc_state1);

            // Populate cache
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".to_string(), "1.0.210".to_string());
            }

            // Invalid TOML (parse will fail)
            let content2 = r#"[dependencies
serde = "1.0"
"#;

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.ok();
            assert!(
                parse_result2.is_none(),
                "Parse should fail for invalid TOML"
            );

            let mut doc_state2 =
                DocumentState::new_without_parse_result("cargo", content2.to_string());

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            state.update_document(uri.clone(), doc_state2);

            // Cache should be preserved despite parse failure
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                1,
                "Cache should be preserved on parse failure"
            );
            assert_eq!(
                doc.cached_versions.get("serde"),
                Some(&"1.0.210".to_string())
            );
        }

        #[test]
        fn test_dependency_diff_detects_additions() {
            let old: HashSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();
            let new: HashSet<String> = ["serde", "tokio", "anyhow"]
                .iter()
                .map(|s| s.to_string())
                .collect();

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 1);
            assert!(diff.added.contains(&"anyhow".to_string()));
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
        }

        #[test]
        fn test_dependency_diff_detects_removals() {
            let old: HashSet<String> = ["serde", "tokio", "anyhow"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let new: HashSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert_eq!(diff.removed.len(), 1);
            assert!(diff.removed.contains(&"anyhow".to_string()));
            assert!(!diff.needs_fetch());
        }

        #[test]
        fn test_dependency_diff_no_changes() {
            let old: HashSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();
            let new: HashSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();

            let diff = DependencyDiff::compute(&old, &new);

            assert!(diff.added.is_empty());
            assert!(diff.removed.is_empty());
            assert!(!diff.needs_fetch());
        }

        #[test]
        fn test_dependency_diff_empty_to_new() {
            let old: HashSet<String> = HashSet::new();
            let new: HashSet<String> = ["serde", "tokio"].iter().map(|s| s.to_string()).collect();

            let diff = DependencyDiff::compute(&old, &new);

            assert_eq!(diff.added.len(), 2);
            assert!(diff.removed.is_empty());
            assert!(diff.needs_fetch());
        }

        #[tokio::test]
        async fn test_cache_pruned_on_dependency_removal() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

            // Initial document with 3 dependencies
            let content1 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
anyhow = "1.0"
"#;

            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let parse_result1 = ecosystem.parse_manifest(content1, &uri).await.unwrap();
            let doc_state1 =
                DocumentState::new_from_parse_result("cargo", content1.to_string(), parse_result1);
            state.update_document(uri.clone(), doc_state1);

            // Populate cache for all 3 deps
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.cached_versions
                    .insert("serde".to_string(), "1.0.210".to_string());
                doc.cached_versions
                    .insert("tokio".to_string(), "1.40.0".to_string());
                doc.cached_versions
                    .insert("anyhow".to_string(), "1.0.89".to_string());
            }

            // Remove anyhow from manifest
            let content2 = r#"[dependencies]
serde = "1.0"
tokio = "1.0"
"#;

            // Compute diff and apply cache pruning
            let old_dep_names: HashSet<String> = ["serde", "tokio", "anyhow"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let new_dep_names: HashSet<String> =
                ["serde", "tokio"].iter().map(|s| s.to_string()).collect();
            let diff = DependencyDiff::compute(&old_dep_names, &new_dep_names);

            let parse_result2 = ecosystem.parse_manifest(content2, &uri).await.unwrap();
            let mut doc_state2 =
                DocumentState::new_from_parse_result("cargo", content2.to_string(), parse_result2);

            if let Some(old_doc) = state.get_document(&uri) {
                preserve_cache(&mut doc_state2, &old_doc);
            }

            // Prune removed dependencies
            for removed_dep in &diff.removed {
                doc_state2.cached_versions.remove(removed_dep);
            }

            state.update_document(uri.clone(), doc_state2);

            // Verify cache was pruned
            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.cached_versions.len(),
                2,
                "anyhow should be removed from cache"
            );
            assert!(doc.cached_versions.contains_key("serde"));
            assert!(doc.cached_versions.contains_key("tokio"));
            assert!(!doc.cached_versions.contains_key("anyhow"));
        }
    }
}

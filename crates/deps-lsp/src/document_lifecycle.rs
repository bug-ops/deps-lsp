//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use crate::config::DepsConfig;
use crate::document::{DocumentState, ServerState};
use crate::handlers::diagnostics;
use deps_core::Ecosystem;
use deps_core::Registry;
use deps_core::Result;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp::Client;
use tower_lsp::lsp_types::Url;

/// Fetches latest versions for multiple packages in parallel.
///
/// Returns a HashMap mapping package names to their latest version strings.
/// Packages that fail to fetch are omitted from the result.
///
/// Filters out pre-release and yanked versions when finding the latest version.
/// Falls back to first version if all versions are pre-releases.
///
/// This function executes all registry requests concurrently, reducing
/// total fetch time from O(N × network_latency) to O(max(network_latency)).
///
/// # Examples
///
/// With 50 dependencies and 100ms per request:
/// - Sequential: 50 × 100ms = 5000ms
/// - Parallel: max(100ms) ≈ 150ms
async fn fetch_latest_versions_parallel(
    registry: Arc<dyn Registry>,
    package_names: Vec<String>,
) -> HashMap<String, String> {
    let futures: Vec<_> = package_names
        .into_iter()
        .map(|name| {
            let registry = Arc::clone(&registry);
            async move {
                registry
                    .get_versions(&name)
                    .await
                    .ok()
                    .and_then(|versions| {
                        // Find first stable (non-yanked, non-prerelease) version
                        versions
                            .iter()
                            .find(|v| !v.is_yanked() && !v.is_prerelease())
                            .or_else(|| versions.first())
                            .map(|v| (name, v.version_string().to_string()))
                    })
            }
        })
        .collect();

    join_all(futures).await.into_iter().flatten().collect()
}

/// Generic document open handler using ecosystem registry.
///
/// Parses manifest using the ecosystem's parser, creates document state,
/// and spawns a background task to fetch version information from the registry.
pub async fn handle_document_open(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(
                uri.to_string(),
            ));
        }
    };

    tracing::info!(
        "Opening {} with ecosystem: {}",
        uri,
        ecosystem.display_name()
    );

    // Parse manifest
    let parse_result = ecosystem.parse_manifest(&content, &uri).await?;

    // Create document state
    let doc_state = DocumentState::new_from_parse_result(ecosystem.id(), content, parse_result);

    state.update_document(uri.clone(), doc_state);

    // Spawn background task to fetch versions
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let config_clone = Arc::clone(&config);
    let client_clone = client.clone();

    let task = tokio::spawn(async move {
        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Collect dependency names while we have access to the original document
        // Note: get_document_clone() doesn't preserve parse_result (trait objects can't be cloned)
        let dep_names: Vec<String> = {
            let doc = match state_clone.get_document(&uri_clone) {
                Some(d) => d,
                None => return,
            };

            match doc.parse_result() {
                Some(p) => p
                    .dependencies()
                    .into_iter()
                    .map(|d| d.name().to_string())
                    .collect(),
                None => return,
            }
        }; // DashMap lock released here

        // Update document state with resolved versions immediately
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
            // Don't initialize cached_versions - leave empty until registry data arrives
            // This allows inlay hints to show ⏳ (waiting) indicator
        }

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let cached_versions = fetch_latest_versions_parallel(registry, dep_names).await;

        tracing::debug!(
            "Fetched {} cached versions for {}",
            cached_versions.len(),
            uri_clone
        );

        // Update document state with cached versions (latest from registry)
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.update_cached_versions(cached_versions);
        }

        // Publish diagnostics
        let config_read = config_clone.read().await;
        let diags = diagnostics::handle_diagnostics(
            Arc::clone(&state_clone),
            &uri_clone,
            &config_read.diagnostics,
        )
        .await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;

        // Refresh inlay hints
        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
    });

    Ok(task)
}

/// Generic document change handler using ecosystem registry.
///
/// Re-parses manifest when document content changes and spawns a debounced
/// task to update diagnostics and request inlay hint refresh.
pub async fn handle_document_change(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    // Find appropriate ecosystem for this URI
    let ecosystem = match state.ecosystem_registry.get_for_uri(&uri) {
        Some(e) => e,
        None => {
            tracing::debug!("No ecosystem handler for {}", uri);
            return Err(deps_core::error::DepsError::UnsupportedEcosystem(
                uri.to_string(),
            ));
        }
    };

    // Parse manifest
    let parse_result = ecosystem.parse_manifest(&content, &uri).await?;

    // Update document state
    let doc_state = DocumentState::new_from_parse_result(ecosystem.id(), content, parse_result);

    state.update_document(uri.clone(), doc_state);

    // Spawn background task to update diagnostics
    let uri_clone = uri.clone();
    let state_clone = Arc::clone(&state);
    let ecosystem_clone = Arc::clone(&ecosystem);
    let config_clone = Arc::clone(&config);
    let client_clone = client.clone();

    let task = tokio::spawn(async move {
        // Small debounce delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Load resolved versions from lock file first (instant, no network)
        let resolved_versions =
            load_resolved_versions(&uri_clone, &state_clone, ecosystem_clone.as_ref()).await;

        // Collect dependency names while we have access to the original document
        // Note: get_document_clone() doesn't preserve parse_result (trait objects can't be cloned)
        let dep_names: Vec<String> = {
            let doc = match state_clone.get_document(&uri_clone) {
                Some(d) => d,
                None => return,
            };

            match doc.parse_result() {
                Some(p) => p
                    .dependencies()
                    .into_iter()
                    .map(|d| d.name().to_string())
                    .collect(),
                None => return,
            }
        }; // DashMap lock released here

        // Update document state with resolved versions immediately
        if !resolved_versions.is_empty()
            && let Some(mut doc) = state_clone.documents.get_mut(&uri_clone)
        {
            doc.update_resolved_versions(resolved_versions.clone());
            // Don't initialize cached_versions - leave empty until registry data arrives
            // This allows inlay hints to show ⏳ (waiting) indicator
        }

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let cached_versions = fetch_latest_versions_parallel(registry, dep_names).await;

        tracing::debug!(
            "Fetched {} cached versions for {}",
            cached_versions.len(),
            uri_clone
        );

        // Update document state with cached versions (latest from registry)
        if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
            doc.update_cached_versions(cached_versions);
        }

        // Publish diagnostics
        let config_read = config_clone.read().await;
        let diags = diagnostics::handle_diagnostics(
            Arc::clone(&state_clone),
            &uri_clone,
            &config_read.diagnostics,
        )
        .await;

        client_clone
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;

        // Refresh inlay hints
        if let Err(e) = client_clone.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
    });

    Ok(task)
}

/// Loads resolved versions from lock file for a given manifest URI.
///
/// Uses the ecosystem's lockfile provider to parse the lock file.
/// Returns a HashMap mapping package names to their resolved versions.
/// Returns an empty HashMap if no lock file is found or parsing fails.
async fn load_resolved_versions(
    uri: &Url,
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
            tracing::debug!("No lock file found for {}", uri);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_registry_lookup() {
        let state = ServerState::new();

        let cargo_uri = tower_lsp::lsp_types::Url::parse("file:///test/Cargo.toml").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&cargo_uri).is_some());

        let npm_uri = tower_lsp::lsp_types::Url::parse("file:///test/package.json").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&npm_uri).is_some());

        let pypi_uri = tower_lsp::lsp_types::Url::parse("file:///test/pyproject.toml").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&pypi_uri).is_some());

        let unknown_uri = tower_lsp::lsp_types::Url::parse("file:///test/unknown.txt").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&unknown_uri).is_none());
    }

    #[tokio::test]
    async fn test_document_parsing_cargo() {
        let state = Arc::new(ServerState::new());
        let uri = tower_lsp::lsp_types::Url::parse("file:///test/Cargo.toml").unwrap();
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
    async fn test_document_parsing_npm() {
        let state = Arc::new(ServerState::new());
        let uri = tower_lsp::lsp_types::Url::parse("file:///test/package.json").unwrap();
        let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

        let ecosystem = state
            .ecosystem_registry
            .get_for_uri(&uri)
            .expect("npm ecosystem not found");

        let parse_result = ecosystem.parse_manifest(content, &uri).await;
        assert!(parse_result.is_ok());

        let doc_state =
            DocumentState::new_from_parse_result("npm", content.to_string(), parse_result.unwrap());
        state.update_document(uri.clone(), doc_state);

        let doc = state.get_document(&uri).unwrap();
        assert_eq!(doc.ecosystem_id, "npm");
    }

    #[tokio::test]
    async fn test_document_parsing_pypi() {
        let state = Arc::new(ServerState::new());
        let uri = tower_lsp::lsp_types::Url::parse("file:///test/pyproject.toml").unwrap();
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

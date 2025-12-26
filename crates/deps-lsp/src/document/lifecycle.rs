//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use super::loader::load_document_from_disk;
use super::state::{DocumentState, ServerState};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;
use deps_core::Ecosystem;
use deps_core::Registry;
use deps_core::Result;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{MessageType, Uri};

/// Fetches latest versions for multiple packages in parallel.
///
/// Returns a HashMap mapping package names to their latest version strings.
/// Packages that fail to fetch are omitted from the result.
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
                        // Use shared utility for consistent behavior with diagnostics
                        deps_core::find_latest_stable(&versions)
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
                "{:?}",
                uri
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
                None => return,
            };
            let parse_result = match doc.parse_result() {
                Some(p) => p,
                None => return,
            };
            parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().to_string())
                .collect()
        };

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let cached_versions = fetch_latest_versions_parallel(registry, dep_names).await;

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
                "{:?}",
                uri
            )));
        }
    };

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
                None => return,
            };
            let parse_result = match doc.parse_result() {
                Some(p) => p,
                None => return,
            };
            parse_result
                .dependencies()
                .into_iter()
                .map(|d| d.name().to_string())
                .collect()
        };

        // Fetch latest versions from registry in parallel (for update hints)
        let registry = ecosystem_clone.registry();
        let cached_versions = fetch_latest_versions_parallel(registry, dep_names).await;

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
/// use deps_lsp::document_lifecycle::ensure_document_loaded;
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
                .log_message(MessageType::WARNING, format!("Could not load file: {}", e))
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

    #[test]
    fn test_ecosystem_registry_lookup() {
        let state = ServerState::new();

        let cargo_uri =
            tower_lsp_server::ls_types::Uri::from_file_path("/test/Cargo.toml").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&cargo_uri).is_some());

        let npm_uri =
            tower_lsp_server::ls_types::Uri::from_file_path("/test/package.json").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&npm_uri).is_some());

        let pypi_uri =
            tower_lsp_server::ls_types::Uri::from_file_path("/test/pyproject.toml").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&pypi_uri).is_some());

        let unknown_uri =
            tower_lsp_server::ls_types::Uri::from_file_path("/test/unknown.txt").unwrap();
        assert!(state.ecosystem_registry.get_for_uri(&unknown_uri).is_none());
    }

    #[tokio::test]
    async fn test_document_parsing_cargo() {
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
    async fn test_document_parsing_npm() {
        let state = Arc::new(ServerState::new());
        let uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/package.json").unwrap();
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
        let uri = tower_lsp_server::ls_types::Uri::from_file_path("/test/pyproject.toml").unwrap();
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
    async fn test_ensure_document_loaded_successful_disk_load() {
        // Test successful load from filesystem with temp file
        use super::load_document_from_disk;
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

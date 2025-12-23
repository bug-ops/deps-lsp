//! New simplified document lifecycle using ecosystem registry.
//!
//! This module provides unified open/change/close handlers that work with
//! the ecosystem trait architecture, eliminating per-ecosystem duplication.

use crate::config::DepsConfig;
use crate::document::{DocumentState, ServerState};
use crate::handlers::diagnostics;
use deps_core::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp::Client;
use tower_lsp::lsp_types::Url;

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
        let doc = match state_clone.get_document(&uri_clone) {
            Some(d) => d,
            None => return,
        };

        let parse_result = match doc.parse_result() {
            Some(p) => p,
            None => return,
        };

        // Collect dependency names to fetch
        let dep_names: Vec<String> = parse_result
            .dependencies()
            .into_iter()
            .map(|d| d.name().to_string())
            .collect();

        drop(doc); // Release guard before async operations

        // Fetch versions for all dependencies
        let registry = ecosystem_clone.registry();
        let mut cached_versions = HashMap::new();

        for name in dep_names {
            if let Ok(versions) = registry.get_versions(&name).await
                && let Some(latest) = versions.first()
            {
                cached_versions.insert(name, latest.version_string().to_string());
            }
        }

        // Update document state with cached versions
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

        let doc = match state_clone.get_document(&uri_clone) {
            Some(d) => d,
            None => return,
        };

        let parse_result = match doc.parse_result() {
            Some(p) => p,
            None => return,
        };

        // Collect dependency names to fetch
        let dep_names: Vec<String> = parse_result
            .dependencies()
            .into_iter()
            .map(|d| d.name().to_string())
            .collect();

        drop(doc);

        // Fetch versions for all dependencies
        let registry = ecosystem_clone.registry();
        let mut cached_versions = HashMap::new();

        for name in dep_names {
            if let Ok(versions) = registry.get_versions(&name).await
                && let Some(latest) = versions.first()
            {
                cached_versions.insert(name, latest.version_string().to_string());
            }
        }

        // Update document state with cached versions
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

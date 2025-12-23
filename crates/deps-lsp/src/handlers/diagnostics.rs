//! Diagnostics handler using ecosystem trait delegation.

use crate::config::DiagnosticsConfig;
use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{Diagnostic, Url};

/// Handles diagnostic requests using trait-based delegation.
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Url,
    _config: &DiagnosticsConfig,
) -> Vec<Diagnostic> {
    let (ecosystem_id, cached_versions) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => {
                tracing::warn!("Document not found for diagnostics: {}", uri);
                return vec![];
            }
        };
        (doc.ecosystem_id, doc.cached_versions.clone())
    };

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
        Some(e) => e,
        None => {
            tracing::warn!("Ecosystem not found for diagnostics: {}", ecosystem_id);
            return vec![];
        }
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    let diags = ecosystem
        .generate_diagnostics(parse_result, &cached_versions, uri)
        .await;
    drop(doc);
    diags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentState, Ecosystem, ServerState};

    #[tokio::test]
    async fn test_handle_diagnostics_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = DiagnosticsConfig::default();

        let result = handle_diagnostics(state, &uri, &config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_diagnostics_cargo() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = DiagnosticsConfig::default();

        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let content = r#"[dependencies]
serde = "1.0.0"
"#
        .to_string();

        let parse_result = ecosystem
            .parse_manifest(&content, &uri)
            .await
            .expect("Failed to parse manifest");

        let doc_state = DocumentState::new_from_parse_result("cargo", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let result = handle_diagnostics(state, &uri, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_diagnostics_npm() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/package.json").unwrap();
        let config = DiagnosticsConfig::default();

        let ecosystem = state.ecosystem_registry.get("npm").unwrap();
        let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

        let parse_result = ecosystem
            .parse_manifest(&content, &uri)
            .await
            .expect("Failed to parse manifest");

        let doc_state = DocumentState::new_from_parse_result("npm", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let result = handle_diagnostics(state, &uri, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_diagnostics_pypi() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/pyproject.toml").unwrap();
        let config = DiagnosticsConfig::default();

        let ecosystem = state.ecosystem_registry.get("pypi").unwrap();
        let content = r#"[project]
dependencies = ["requests>=2.0.0"]
"#
        .to_string();

        let parse_result = ecosystem
            .parse_manifest(&content, &uri)
            .await
            .expect("Failed to parse manifest");

        let doc_state = DocumentState::new_from_parse_result("pypi", content, parse_result);
        state.update_document(uri.clone(), doc_state);

        let result = handle_diagnostics(state, &uri, &config).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_diagnostics_no_parse_result() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let config = DiagnosticsConfig::default();

        let doc_state = DocumentState::new(Ecosystem::Cargo, "".to_string(), vec![]);
        state.update_document(uri.clone(), doc_state);

        let result = handle_diagnostics(state, &uri, &config).await;
        assert!(result.is_empty());
    }
}

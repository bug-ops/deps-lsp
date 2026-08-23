//! Diagnostics handler using ecosystem trait delegation.

use crate::config::{DepsConfig, DiagnosticsConfig};
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::VersionData;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Diagnostic, Uri};

/// Handles diagnostic requests using trait-based delegation.
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Uri,
    _config: &DiagnosticsConfig,
    client: Client,
    full_config: Arc<RwLock<DepsConfig>>,
) -> Vec<Diagnostic> {
    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, full_config).await {
        tracing::warn!("Could not load document for diagnostics: {:?}", uri);
        return vec![];
    }

    generate_diagnostics_internal(state, uri).await
}

/// Internal diagnostic generation without cold start support.
///
/// This is used when we know the document is already loaded (e.g., from background tasks).
pub(crate) async fn generate_diagnostics_internal(
    state: Arc<ServerState>,
    uri: &Uri,
) -> Vec<Diagnostic> {
    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for diagnostics: {:?}", uri);
            return vec![];
        }
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id()) {
        Some(e) => e,
        None => {
            tracing::warn!(
                "Ecosystem not found for diagnostics: {}",
                doc.ecosystem_id()
            );
            return vec![];
        }
    };

    // Skip diagnostics while versions are still loading to avoid
    // false "Unknown package" warnings from empty cache
    if doc.loading_state == deps_core::LoadingState::Loading {
        return vec![];
    }

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    // Generate diagnostics while holding the lock
    ecosystem
        .generate_diagnostics(
            parse_result,
            VersionData::new(&doc.cached_versions, &doc.resolved_versions)
                .with_vulnerabilities(&doc.vulnerabilities),
            uri,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DiagnosticsConfig;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;

    // Generic tests (no feature flag required)

    #[tokio::test]
    async fn test_handle_diagnostics_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let config = DiagnosticsConfig::default();

        let (client, full_config) = create_test_client_and_config();
        let result = handle_diagnostics(state, &uri, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
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

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_diagnostics_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let config = DiagnosticsConfig::default();

            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            assert!(result.is_empty());
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/package.json");
            let config = DiagnosticsConfig::default();

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Npm, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_diagnostics() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
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

            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Pypi, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_diagnostics(state, &uri, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }
}

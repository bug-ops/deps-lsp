//! Inlay hints handler using ecosystem trait delegation.
//!
//! This handler uses the ecosystem registry to delegate inlay hint generation
//! to the appropriate ecosystem implementation.

use crate::config::{DepsConfig, InlayHintsConfig};
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::EcosystemConfig;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{InlayHint, InlayHintParams};

/// Handles inlay hint requests using trait-based delegation.
///
/// Returns version status hints for all registry dependencies in the document.
/// Gracefully degrades by returning empty vec on any errors.
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
    client: Client,
    full_config: Arc<RwLock<DepsConfig>>,
) -> Vec<InlayHint> {
    if !config.enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, Arc::clone(&full_config)).await {
        tracing::warn!("Could not load document for inlay hints: {:?}", uri);
        return vec![];
    }

    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found: {:?}", uri);
            return vec![];
        }
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id) {
        Some(e) => e,
        None => {
            tracing::warn!("Ecosystem not found: {}", doc.ecosystem_id);
            return vec![];
        }
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    // Get loading indicator config
    let loading_config = { full_config.read().await.loading_indicator.clone() };

    let ecosystem_config = EcosystemConfig {
        show_up_to_date_hints: true,
        up_to_date_text: config.up_to_date_text.clone(),
        needs_update_text: config.needs_update_text.clone(),
        loading_text: loading_config.loading_text,
        show_loading_hints: loading_config.enabled && loading_config.fallback_to_hints,
    };

    // Generate hints while holding the lock
    ecosystem
        .generate_inlay_hints(
            parse_result,
            &doc.cached_versions,
            &doc.resolved_versions,
            doc.loading_state,
            &ecosystem_config,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{TextDocumentIdentifier, Uri};

    // Generic tests (no feature flag required)

    #[test]
    fn test_handle_inlay_hints_disabled() {
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        assert!(!config.enabled);
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_disabled_returns_empty() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(100, 0),
            ),
        };

        let (client, full_config) = create_test_client_and_config();
        let result = handle_inlay_hints(state, params, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inlay_hints_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let params = InlayHintParams {
            text_document: TextDocumentIdentifier { uri },
            work_done_progress_params: Default::default(),
            range: tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(100, 0),
            ),
        };

        let (client, full_config) = create_test_client_and_config();
        let result = handle_inlay_hints(state, params, &config, client, full_config).await;
        assert!(result.is_empty());
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::{DocumentState, Ecosystem};

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_inlay_hints_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

            let doc_state = DocumentState::new(Ecosystem::Cargo, String::new(), vec![]);
            state.update_document(uri.clone(), doc_state);

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let result = handle_inlay_hints(state, params, &config, client, full_config).await;
            assert!(result.is_empty());
        }

        #[tokio::test]
        async fn test_handle_inlay_hints_custom_config() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "OK".to_string(),
                needs_update_text: "UPDATE: {}".to_string(),
            };

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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/package.json").unwrap();
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state = DocumentState::new_from_parse_result("npm", content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }

    // PyPI-specific tests
    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_inlay_hints() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/pyproject.toml").unwrap();
            let config = InlayHintsConfig {
                enabled: true,
                up_to_date_text: "✅".to_string(),
                needs_update_text: "❌ {}".to_string(),
            };

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

            let params = InlayHintParams {
                text_document: TextDocumentIdentifier { uri },
                work_done_progress_params: Default::default(),
                range: tower_lsp_server::ls_types::Range::new(
                    tower_lsp_server::ls_types::Position::new(0, 0),
                    tower_lsp_server::ls_types::Position::new(100, 0),
                ),
            };

            let (client, full_config) = create_test_client_and_config();
            let _result = handle_inlay_hints(state, params, &config, client, full_config).await;
            // Test passes if no panic occurs
        }
    }
}

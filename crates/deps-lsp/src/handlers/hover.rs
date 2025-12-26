//! Hover handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
pub async fn handle_hover(
    state: Arc<ServerState>,
    params: HoverParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, config).await {
        tracing::warn!("Could not load document for hover: {:?}", uri);
        return None;
    }

    // Single document lookup: extract all needed data at once
    let doc = state.get_document(uri)?;
    let ecosystem = state.ecosystem_registry.get(doc.ecosystem_id)?;
    let parse_result = doc.parse_result()?;

    // Generate hover while holding the lock
    ecosystem
        .generate_hover(
            parse_result,
            position,
            &doc.cached_versions,
            &doc.resolved_versions,
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ServerState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams, Uri,
    };

    // Generic tests (no feature flag required)

    #[tokio::test]
    async fn test_handle_hover_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
        let (client, config) = create_test_client_and_config();

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params, client, config).await;
        assert!(result.is_none());
    }

    // Cargo-specific tests
    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use crate::document::{DocumentState, Ecosystem};

        #[tokio::test]
        async fn test_handle_hover() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

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

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(1, 0),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_hover(state, params, client, config).await;
            // Test passes if no panic occurs
        }

        #[tokio::test]
        async fn test_handle_hover_no_parse_result() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

            let doc_state = DocumentState::new(Ecosystem::Cargo, String::new(), vec![]);
            state.update_document(uri.clone(), doc_state);

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 0),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let result = handle_hover(state, params, client, config).await;
            assert!(result.is_none());
        }
    }

    // npm-specific tests
    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use crate::document::DocumentState;

        #[tokio::test]
        async fn test_handle_hover() {
            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/test/package.json").unwrap();

            let ecosystem = state.ecosystem_registry.get("npm").unwrap();
            let content = r#"{"dependencies": {"express": "4.0.0"}}"#.to_string();

            let parse_result = ecosystem
                .parse_manifest(&content, &uri)
                .await
                .expect("Failed to parse manifest");

            let doc_state = DocumentState::new_from_parse_result("npm", content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let params = HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 20),
                },
                work_done_progress_params: Default::default(),
            };

            let (client, config) = create_test_client_and_config();
            let _result = handle_hover(state, params, client, config).await;
            // Test passes if no panic occurs
        }
    }
}

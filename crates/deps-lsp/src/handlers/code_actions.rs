//! Code actions handler using ecosystem trait delegation.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{CodeActionOrCommand, CodeActionParams};

/// Handles code action requests using trait-based delegation.
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let position = params.range.start;

    // Ensure document is loaded (cold start support)
    if !ensure_document_loaded(uri, Arc::clone(&state), client, config).await {
        tracing::warn!("Could not load document for code actions: {:?}", uri);
        return vec![];
    }

    // Single document lookup: extract all needed data at once
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let ecosystem = match state.ecosystem_registry.get(doc.ecosystem_id) {
        Some(e) => e,
        None => return vec![],
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    // Generate code actions while holding the lock
    let actions = ecosystem
        .generate_code_actions(parse_result, position, &doc.cached_versions, uri)
        .await;

    actions
        .into_iter()
        .map(CodeActionOrCommand::CodeAction)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentState, ServerState};
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{Position, Range, TextDocumentIdentifier, Uri};

    #[tokio::test]
    async fn test_handle_code_actions_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_code_actions(state, params, client, config).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_code_actions_cargo() {
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

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(1, 9), Position::new(1, 16)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let (client, config) = create_test_client_and_config();
        let _result = handle_code_actions(state, params, client, config).await;
        // Test passes if no panic occurs
    }

    #[tokio::test]
    async fn test_handle_code_actions_npm() {
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

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 25), Position::new(0, 32)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let (client, config) = create_test_client_and_config();
        let _result = handle_code_actions(state, params, client, config).await;
        // Test passes if no panic occurs
    }

    #[tokio::test]
    async fn test_handle_code_actions_no_parse_result() {
        use crate::document::Ecosystem;

        let state = Arc::new(ServerState::new());
        let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();

        let doc_state = DocumentState::new(Ecosystem::Cargo, "".to_string(), vec![]);
        state.update_document(uri.clone(), doc_state);

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_code_actions(state, params, client, config).await;
        assert!(result.is_empty());
    }
}

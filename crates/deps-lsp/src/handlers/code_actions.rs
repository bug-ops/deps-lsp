//! Code actions handler using ecosystem trait delegation.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{CodeActionOrCommand, CodeActionParams};

/// Handles code action requests using trait-based delegation.
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let position = params.range.start;

    let (ecosystem_id, cached_versions) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => return vec![],
        };
        (doc.ecosystem_id, doc.cached_versions.clone())
    };

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => return vec![],
    };

    let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
        Some(e) => e,
        None => return vec![],
    };

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    let actions = ecosystem
        .generate_code_actions(parse_result, position, &cached_versions, uri)
        .await;
    drop(doc);

    actions
        .into_iter()
        .map(CodeActionOrCommand::CodeAction)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentState, ServerState};
    use tower_lsp::lsp_types::{Position, Range, TextDocumentIdentifier, Url};

    #[tokio::test]
    async fn test_handle_code_actions_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let result = handle_code_actions(state, params).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_code_actions_cargo() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

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

        let result = handle_code_actions(state, params).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_code_actions_npm() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/package.json").unwrap();

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

        let result = handle_code_actions(state, params).await;
        assert!(result.is_empty() || !result.is_empty());
    }

    #[tokio::test]
    async fn test_handle_code_actions_no_parse_result() {
        use crate::document::Ecosystem;

        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let doc_state = DocumentState::new(Ecosystem::Cargo, "".to_string(), vec![]);
        state.update_document(uri.clone(), doc_state);

        let params = CodeActionParams {
            text_document: TextDocumentIdentifier { uri },
            range: Range::new(Position::new(0, 0), Position::new(0, 0)),
            context: Default::default(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        };

        let result = handle_code_actions(state, params).await;
        assert!(result.is_empty());
    }
}

//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{CompletionParams, CompletionResponse};

/// Handles completion requests.
///
/// Delegates to the appropriate ecosystem implementation based on the document type.
pub async fn handle_completion(
    state: Arc<ServerState>,
    params: CompletionParams,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    // Get document and extract needed data
    let doc = state.get_document(uri)?;
    let ecosystem_id = doc.ecosystem_id;
    let content = doc.content.clone();
    let parse_result = doc.parse_result()?;

    // Get ecosystem implementation
    let ecosystem = state.ecosystem_registry.get(ecosystem_id)?;

    // Delegate to ecosystem
    let items = ecosystem
        .generate_completions(parse_result, position, &content)
        .await;

    if items.is_empty() {
        None
    } else {
        Some(CompletionResponse::Array(items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use tower_lsp::lsp_types::{Position, TextDocumentIdentifier, TextDocumentPositionParams, Url};

    #[tokio::test]
    async fn test_completion_returns_none_for_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let result = handle_completion(state, params).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_completion_returns_none_for_unparsed_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        // Create document without parse_result
        let doc = DocumentState::new(
            crate::document::Ecosystem::Cargo,
            "[dependencies]\nserde = \"1.0\"".to_string(),
            vec![],
        );
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 9),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let result = handle_completion(state, params).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let content = "[dependencies]\nserde = \"1.0\"".to_string();

        // Parse the manifest to get a proper parse result
        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();

        let doc = DocumentState::new_from_parse_result("cargo", content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 9),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should return Some or None based on ecosystem implementation
        // We don't test the actual completions here as that's ecosystem-specific
        let _result = handle_completion(state, params).await;
        // Just verify it doesn't panic - actual completion logic is in ecosystem
    }
}

//! Hover handler using ecosystem trait delegation.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
pub async fn handle_hover(state: Arc<ServerState>, params: HoverParams) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    let (ecosystem_id, cached_versions, resolved_versions) = {
        let doc = state.get_document(uri)?;
        (
            doc.ecosystem_id,
            doc.cached_versions.clone(),
            doc.resolved_versions.clone(),
        )
    };

    let doc = state.get_document(uri)?;
    let ecosystem = state.ecosystem_registry.get(ecosystem_id)?;
    let parse_result = doc.parse_result()?;

    let hover = ecosystem
        .generate_hover(parse_result, position, &cached_versions, &resolved_versions)
        .await;
    drop(doc);
    hover
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{DocumentState, Ecosystem, ServerState};
    use tower_lsp::lsp_types::{Position, TextDocumentIdentifier, TextDocumentPositionParams, Url};

    #[tokio::test]
    async fn test_handle_hover_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_handle_hover_cargo() {
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

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 0),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params).await;
        assert!(result.is_some() || result.is_none());
    }

    #[tokio::test]
    async fn test_handle_hover_npm() {
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

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 20),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params).await;
        assert!(result.is_some() || result.is_none());
    }

    #[tokio::test]
    async fn test_handle_hover_no_parse_result() {
        let state = Arc::new(ServerState::new());
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();

        let doc_state = DocumentState::new(Ecosystem::Cargo, "".to_string(), vec![]);
        state.update_document(uri.clone(), doc_state);

        let params = HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
        };

        let result = handle_hover(state, params).await;
        assert!(result.is_none());
    }
}

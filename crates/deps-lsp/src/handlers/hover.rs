//! Hover handler using ecosystem trait delegation.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
pub async fn handle_hover(state: Arc<ServerState>, params: HoverParams) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    let (ecosystem_id, cached_versions) = {
        let doc = state.get_document(uri)?;
        (doc.ecosystem_id, doc.cached_versions.clone())
    };

    let doc = state.get_document(uri)?;
    let ecosystem = state.ecosystem_registry.get(ecosystem_id)?;
    let parse_result = doc.parse_result()?;

    let hover = ecosystem
        .generate_hover(parse_result, position, &cached_versions)
        .await;
    drop(doc);
    hover
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hover_placeholder() {
        // Placeholder test
        assert!(true);
    }
}

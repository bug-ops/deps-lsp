//! New simplified hover handler using ecosystem trait delegation.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{Hover, HoverParams};

/// Handles hover requests using trait-based delegation.
pub async fn handle_hover(state: Arc<ServerState>, params: HoverParams) -> Option<Hover> {
    let uri = &params.text_document_position_params.text_document.uri;
    let position = params.text_document_position_params.position;

    // Try new architecture first - check if document has parse_result
    let (ecosystem_id, cached_versions, has_parse_result) = {
        let doc = state.get_document(uri)?;
        (
            doc.ecosystem_id,
            doc.cached_versions.clone(),
            doc.parse_result().is_some(),
        )
    };

    if has_parse_result {
        // Re-acquire doc to get parse_result
        let doc = state.get_document(uri)?;
        let ecosystem = state.ecosystem_registry.get(ecosystem_id)?;

        if let Some(parse_result) = doc.parse_result() {
            let hover = ecosystem
                .generate_hover(parse_result, position, &cached_versions)
                .await;
            drop(doc);
            return hover;
        }
    }

    // Fallback to legacy architecture
    tracing::debug!("Using legacy hover handler for {}", uri);
    super::hover::handle_hover(state, params).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_hover_placeholder() {
        // Placeholder test
        assert!(true);
    }
}

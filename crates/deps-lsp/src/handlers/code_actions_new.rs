//! New simplified code actions handler using ecosystem trait delegation.

use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{CodeActionOrCommand, CodeActionParams};

/// Handles code action requests using trait-based delegation.
pub async fn handle_code_actions(
    state: Arc<ServerState>,
    params: CodeActionParams,
) -> Vec<CodeActionOrCommand> {
    let uri = &params.text_document.uri;
    let position = params.range.start; // Use start of range for position

    // Try new architecture first - check if document has parse_result
    let (ecosystem_id, cached_versions, has_parse_result) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => return vec![],
        };
        (
            doc.ecosystem_id,
            doc.cached_versions.clone(),
            doc.parse_result().is_some(),
        )
    };

    if has_parse_result {
        // Re-acquire doc to get parse_result
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => return vec![],
        };

        let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
            Some(e) => e,
            None => return vec![],
        };

        if let Some(parse_result) = doc.parse_result() {
            let actions = ecosystem
                .generate_code_actions(parse_result, position, &cached_versions, uri)
                .await;
            drop(doc);
            return actions
                .into_iter()
                .map(CodeActionOrCommand::CodeAction)
                .collect();
        }
    }

    // Fallback to legacy architecture
    tracing::debug!("Using legacy code actions handler for {}", uri);
    super::code_actions::handle_code_actions(state, params).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_actions_placeholder() {
        // Placeholder test
        assert!(true);
    }
}

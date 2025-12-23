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
    #[test]
    fn test_code_actions_placeholder() {
        // Placeholder test
        assert!(true);
    }
}

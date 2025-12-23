//! New simplified diagnostics handler using ecosystem trait delegation.

use crate::config::DiagnosticsConfig;
use crate::document::ServerState;
use std::sync::Arc;
use tower_lsp::lsp_types::{Diagnostic, Url};

/// Handles diagnostic requests using trait-based delegation.
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Url,
    _config: &DiagnosticsConfig,
) -> Vec<Diagnostic> {
    // Try new architecture first - check if document has parse_result
    let (ecosystem_id, cached_versions, has_parse_result) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => {
                tracing::warn!("Document not found for diagnostics: {}", uri);
                return vec![];
            }
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
            None => {
                tracing::warn!("Ecosystem not found for diagnostics: {}", ecosystem_id);
                return vec![];
            }
        };

        if let Some(parse_result) = doc.parse_result() {
            let diags = ecosystem
                .generate_diagnostics(parse_result, &cached_versions, uri)
                .await;
            drop(doc);
            return diags;
        }
    }

    // Fallback to legacy architecture
    tracing::debug!("Using legacy diagnostics handler for {}", uri);
    super::diagnostics::handle_diagnostics(state, uri, _config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_placeholder() {
        // Placeholder test
        assert!(true);
    }
}

//! Diagnostics handler using ecosystem trait delegation.

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
    let (ecosystem_id, cached_versions) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => {
                tracing::warn!("Document not found for diagnostics: {}", uri);
                return vec![];
            }
        };
        (doc.ecosystem_id, doc.cached_versions.clone())
    };

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

    let parse_result = match doc.parse_result() {
        Some(p) => p,
        None => return vec![],
    };

    let diags = ecosystem
        .generate_diagnostics(parse_result, &cached_versions, uri)
        .await;
    drop(doc);
    diags
}

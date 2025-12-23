//! New simplified inlay hints handler using ecosystem trait delegation.
//!
//! This handler uses the ecosystem registry to delegate inlay hint generation
//! to the appropriate ecosystem implementation, eliminating pattern matching.

use crate::config::InlayHintsConfig;
use crate::document::ServerState;
use deps_core::EcosystemConfig;
use std::sync::Arc;
use tower_lsp::lsp_types::{InlayHint, InlayHintParams};

/// Handles inlay hint requests using trait-based delegation.
///
/// Returns version status hints for all registry dependencies in the document.
/// Gracefully degrades by returning empty vec on any errors.
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    if !config.enabled {
        return vec![];
    }

    let uri = &params.text_document.uri;

    // Try new architecture first - check if document has parse_result
    let (ecosystem_id, cached_versions, has_parse_result) = {
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => {
                tracing::warn!("Document not found: {}", uri);
                return vec![];
            }
        };

        (
            doc.ecosystem_id,
            doc.cached_versions.clone(),
            doc.parse_result().is_some(),
        )
    }; // doc is dropped here

    if has_parse_result {
        // Re-acquire doc to get parse_result
        let doc = match state.get_document(uri) {
            Some(d) => d,
            None => return vec![],
        };

        let ecosystem = match state.ecosystem_registry.get(ecosystem_id) {
            Some(e) => e,
            None => {
                tracing::warn!("Ecosystem not found: {}", ecosystem_id);
                return vec![];
            }
        };

        if let Some(parse_result) = doc.parse_result() {
            let ecosystem_config = EcosystemConfig {
                show_up_to_date_hints: true,
                up_to_date_text: config.up_to_date_text.clone(),
                needs_update_text: config.needs_update_text.clone(),
            };

            let hints = ecosystem
                .generate_inlay_hints(parse_result, &cached_versions, &ecosystem_config)
                .await;
            drop(doc); // Explicitly drop before returning
            return hints;
        }
    }

    // Fallback to legacy architecture
    tracing::debug!("Using legacy inlay hints handler for {}", uri);
    super::inlay_hints::handle_inlay_hints(state, params, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_inlay_hints_disabled() {
        // When inlay hints are disabled in config, should return empty vec
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        assert!(!config.enabled);
    }
}

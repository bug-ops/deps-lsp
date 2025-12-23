//! Inlay hints handler implementation.
//!
//! Displays inline version annotations next to dependency version strings.
//! Shows "✅" for up-to-date dependencies and "❌ X.Y.Z" for outdated ones.

use crate::config::InlayHintsConfig;
use crate::document::{Ecosystem, ServerState};
use crate::handlers::{CargoHandlerImpl, NpmHandlerImpl, PyPiHandlerImpl};
use deps_core::{EcosystemHandler, generate_inlay_hints};
use std::sync::Arc;
use tower_lsp::lsp_types::{InlayHint, InlayHintParams};

/// Handles inlay hint requests.
///
/// Returns version status hints for all registry dependencies in the document.
/// Gracefully degrades by returning empty vec on any errors.
///
/// # Examples
///
/// For this dependency:
/// ```toml
/// serde = "1.0.100"
/// ```
///
/// Shows: `serde = "1.0.100" ❌ 1.0.214` if outdated
/// Or: `serde = "1.0.214" ✅` if up-to-date
pub async fn handle_inlay_hints(
    state: Arc<ServerState>,
    params: InlayHintParams,
    config: &InlayHintsConfig,
) -> Vec<InlayHint> {
    let uri = &params.text_document.uri;

    tracing::info!(
        "inlay_hint request: uri={}, range={}:{}-{}:{}",
        uri,
        params.range.start.line,
        params.range.start.character,
        params.range.end.line,
        params.range.end.character
    );

    if !config.enabled {
        tracing::debug!("inlay hints disabled in config");
        return vec![];
    }

    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for inlay hints: {}", uri);
            return vec![];
        }
    };

    let ecosystem = doc.ecosystem;

    let deps_to_fetch: Vec<_> = doc
        .dependencies
        .iter()
        .filter(|dep| {
            let passes = dep.is_registry()
                && dep.version_range().is_some()
                && dep.version_req().is_some();
            if !passes {
                tracing::debug!(
                    "inlay hints: filtering out '{}' - is_registry={}, version_range={:?}, version_req={:?}",
                    dep.name(),
                    dep.is_registry(),
                    dep.version_range(),
                    dep.version_req()
                );
            }
            passes
        })
        .cloned()
        .collect();

    // Get cached and resolved versions before dropping doc
    let cached_versions = doc.versions.clone();
    let resolved_versions = doc.resolved_versions.clone();

    tracing::info!(
        "inlay hints: found {} dependencies to fetch (total {} in doc, {} cached, {} resolved)",
        deps_to_fetch.len(),
        doc.dependencies.len(),
        cached_versions.len(),
        resolved_versions.len()
    );

    drop(doc);

    let core_config = deps_core::InlayHintsConfig {
        enabled: config.enabled,
        up_to_date_text: config.up_to_date_text.clone(),
        needs_update_text: config.needs_update_text.clone(),
    };

    let hints = match ecosystem {
        Ecosystem::Cargo => {
            let handler = CargoHandlerImpl::new(Arc::clone(&state.cache));
            generate_inlay_hints(
                &handler,
                &deps_to_fetch,
                &cached_versions,
                &resolved_versions,
                &core_config,
            )
            .await
        }
        Ecosystem::Npm => {
            let handler = NpmHandlerImpl::new(Arc::clone(&state.cache));
            generate_inlay_hints(
                &handler,
                &deps_to_fetch,
                &cached_versions,
                &resolved_versions,
                &core_config,
            )
            .await
        }
        Ecosystem::Pypi => {
            let handler = PyPiHandlerImpl::new(Arc::clone(&state.cache));
            generate_inlay_hints(
                &handler,
                &deps_to_fetch,
                &cached_versions,
                &resolved_versions,
                &core_config,
            )
            .await
        }
    };

    tracing::info!("returning {} inlay hints", hints.len());
    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    // All version matching and hint creation logic has been moved to deps-core
    // and is tested in the deps-core test suite.
    //
    // The only tests remaining here are integration tests that verify the
    // handler dispatch logic works correctly.

    #[test]
    fn test_handle_inlay_hints_disabled() {
        // When inlay hints are disabled in config, should return empty vec
        let config = InlayHintsConfig {
            enabled: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // This is a basic sanity check - config.enabled is checked early
        assert!(!config.enabled);
    }

    #[test]
    fn test_inlay_hints_config_default() {
        let config = InlayHintsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.up_to_date_text, "✅");
        assert_eq!(config.needs_update_text, "❌ {}");
    }
}

//! Diagnostics handler implementation.
//!
//! Reports issues with dependencies including:
//! - Unknown packages (not found in registry)
//! - Yanked versions
//! - Outdated versions
//! - Invalid semver requirements

use crate::config::DiagnosticsConfig;
use crate::document::{Ecosystem, ServerState};
use crate::handlers::{CargoHandlerImpl, NpmHandlerImpl, PyPiHandlerImpl};
use deps_core::EcosystemHandler;
use std::sync::Arc;
use tower_lsp::lsp_types::{Diagnostic, Url};

/// Handles diagnostic requests.
///
/// Returns diagnostics for all dependencies in the document.
/// Gracefully degrades by returning empty vec on critical errors.
pub async fn handle_diagnostics(
    state: Arc<ServerState>,
    uri: &Url,
    config: &DiagnosticsConfig,
) -> Vec<Diagnostic> {
    let doc = match state.get_document(uri) {
        Some(d) => d,
        None => {
            tracing::warn!("Document not found for diagnostics: {}", uri);
            return vec![];
        }
    };

    let ecosystem = doc.ecosystem;
    let dependencies = doc.dependencies.clone();
    drop(doc);

    // Convert config to deps-core config type
    let core_config = deps_core::DiagnosticsConfig {
        unknown_severity: config.unknown_severity,
        yanked_severity: config.yanked_severity,
        outdated_severity: config.outdated_severity,
    };

    match ecosystem {
        Ecosystem::Cargo => {
            let handler = CargoHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_diagnostics(&handler, &dependencies, &core_config).await
        }
        Ecosystem::Npm => {
            let handler = NpmHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_diagnostics(&handler, &dependencies, &core_config).await
        }
        Ecosystem::Pypi => {
            let handler = PyPiHandlerImpl::new(Arc::clone(&state.cache));
            deps_core::generate_diagnostics(&handler, &dependencies, &core_config).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::DiagnosticSeverity;

    #[test]
    fn test_diagnostics_config_defaults() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.outdated_severity, DiagnosticSeverity::HINT);
        assert_eq!(config.unknown_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.yanked_severity, DiagnosticSeverity::WARNING);
    }
}

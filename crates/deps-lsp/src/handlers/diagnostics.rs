//! Diagnostics handler implementation.
//!
//! Reports issues with dependencies including:
//! - Unknown packages (not found in registry)
//! - Yanked versions
//! - Outdated versions
//! - Invalid semver requirements

use crate::config::DiagnosticsConfig;
use crate::document::{Ecosystem, ServerState, UnifiedDependency};
use deps_cargo::{CratesIoRegistry, DependencySource, ParsedDependency};
use deps_pypi::{PypiDependency, PypiDependencySource, PypiRegistry};
use futures::future::join_all;
use semver::VersionReq;
use std::sync::Arc;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Url};

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

    match doc.ecosystem {
        Ecosystem::Cargo => {
            let registry = CratesIoRegistry::new(Arc::clone(&state.cache));
            compute_cargo_diagnostics(&doc, &registry, config).await
        }
        Ecosystem::Pypi => {
            let registry = PypiRegistry::new(Arc::clone(&state.cache));
            compute_pypi_diagnostics(&doc, &registry, config).await
        }
        Ecosystem::Npm => {
            // TODO: Implement npm diagnostics
            tracing::debug!("Diagnostics not yet implemented for npm");
            vec![]
        }
    }
}

async fn compute_cargo_diagnostics(
    doc: &crate::document::DocumentState,
    registry: &CratesIoRegistry,
    config: &DiagnosticsConfig,
) -> Vec<Diagnostic> {
    let cargo_deps: Vec<&ParsedDependency> = doc
        .dependencies
        .iter()
        .filter_map(|dep| {
            if let UnifiedDependency::Cargo(cargo_dep) = dep
                && matches!(cargo_dep.source, DependencySource::Registry)
            {
                return Some(cargo_dep);
            }
            None
        })
        .collect();

    let futures: Vec<_> = cargo_deps
        .iter()
        .map(|dep| {
            let name = dep.name.clone();
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, versions)
            }
        })
        .collect();

    let version_results = join_all(futures).await;

    let mut diagnostics = Vec::new();

    for (i, dep) in cargo_deps.iter().enumerate() {
        let (name, version_result) = &version_results[i];

        let versions = match version_result {
            Ok(v) => v,
            Err(_) => {
                diagnostics.push(Diagnostic {
                    range: dep.name_range,
                    severity: Some(config.unknown_severity),
                    message: format!("Unknown package '{}'", name),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            }
        };

        if let Some(version_req) = &dep.version_req
            && let Some(version_range) = dep.version_range
        {
            if version_req.parse::<VersionReq>().is_err() {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(DiagnosticSeverity::ERROR),
                    message: format!("Invalid version requirement '{}'", version_req),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            }

            let matching = registry
                .get_latest_matching(&dep.name, version_req)
                .await
                .ok()
                .flatten();

            if let Some(current) = &matching
                && current.yanked
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.yanked_severity),
                    message: "This version has been yanked".into(),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }

            let latest = versions.iter().find(|v| !v.yanked);
            if let (Some(latest), Some(current)) = (latest, &matching)
                && latest.num != current.num
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.outdated_severity),
                    message: format!("Newer version available: {}", latest.num),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
        }
    }

    diagnostics
}

async fn compute_pypi_diagnostics(
    doc: &crate::document::DocumentState,
    registry: &PypiRegistry,
    config: &DiagnosticsConfig,
) -> Vec<Diagnostic> {
    let pypi_deps: Vec<&PypiDependency> = doc
        .dependencies
        .iter()
        .filter_map(|dep| {
            if let UnifiedDependency::Pypi(pypi_dep) = dep
                && matches!(pypi_dep.source, PypiDependencySource::PyPI)
            {
                return Some(pypi_dep);
            }
            None
        })
        .collect();

    let futures: Vec<_> = pypi_deps
        .iter()
        .map(|dep| {
            let name = dep.name.clone();
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, versions)
            }
        })
        .collect();

    let version_results = join_all(futures).await;

    let mut diagnostics = Vec::new();

    for (i, dep) in pypi_deps.iter().enumerate() {
        let (name, version_result) = &version_results[i];

        let versions = match version_result {
            Ok(v) => v,
            Err(_) => {
                diagnostics.push(Diagnostic {
                    range: dep.name_range,
                    severity: Some(config.unknown_severity),
                    message: format!("Unknown package '{}'", name),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            }
        };

        if let Some(version_req) = &dep.version_req
            && let Some(version_range) = dep.version_range
        {
            // PyPI uses PEP 440 version specifiers, not semver
            // We'll use get_latest_matching which handles PEP 440
            let matching = registry
                .get_latest_matching(&dep.name, version_req)
                .await
                .ok()
                .flatten();

            if let Some(current) = &matching
                && current.yanked
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.yanked_severity),
                    message: "This version has been yanked".into(),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }

            let latest = versions.iter().find(|v| !v.yanked);
            if let (Some(latest), Some(current)) = (latest, &matching)
                && latest.version != current.version
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.outdated_severity),
                    message: format!("Newer version available: {}", latest.version),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostics_config_defaults() {
        let config = DiagnosticsConfig::default();
        assert_eq!(config.outdated_severity, DiagnosticSeverity::HINT);
        assert_eq!(config.unknown_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.yanked_severity, DiagnosticSeverity::WARNING);
    }
}

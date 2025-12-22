//! PyPiHandler implementation with UnifiedDependency extraction.
//!
//! This module provides the glue between PypiRegistry from deps-pypi
//! and UnifiedDependency from deps-lsp.

use crate::document::UnifiedDependency;
use async_trait::async_trait;
use deps_core::{EcosystemHandler, HttpCache, Pep440Matcher, VersionRequirementMatcher};
use deps_pypi::{PypiDependency, PypiRegistry};
use std::sync::Arc;

/// PyPI ecosystem handler with UnifiedDependency support.
///
/// This is a wrapper around deps_pypi::PypiRegistry that knows how to
/// extract PypiDependency from UnifiedDependency.
pub struct PyPiHandlerImpl {
    registry: PypiRegistry,
}

#[async_trait]
impl EcosystemHandler for PyPiHandlerImpl {
    type Registry = PypiRegistry;
    type Dependency = PypiDependency;
    type UnifiedDep = UnifiedDependency;

    fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: PypiRegistry::new(cache),
        }
    }

    fn registry(&self) -> &Self::Registry {
        &self.registry
    }

    fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
        match dep {
            UnifiedDependency::Pypi(pypi_dep) => Some(pypi_dep),
            _ => None,
        }
    }

    fn package_url(name: &str) -> String {
        format!("https://pypi.org/project/{}/", name)
    }

    fn ecosystem_display_name() -> &'static str {
        "PyPI"
    }

    fn is_version_latest(version_req: &str, latest: &str) -> bool {
        Pep440Matcher.is_latest_satisfying(version_req, latest)
    }

    fn format_version_for_edit(dep: &Self::Dependency, version: &str) -> String {
        match &dep.section {
            deps_pypi::PypiDependencySection::Dependencies
            | deps_pypi::PypiDependencySection::OptionalDependencies { .. }
            | deps_pypi::PypiDependencySection::DependencyGroup { .. } => {
                format!(">={}", version)
            }
            deps_pypi::PypiDependencySection::PoetryDependencies
            | deps_pypi::PypiDependencySection::PoetryGroup { .. } => {
                format!("\"^{}\"", version)
            }
        }
    }

    fn is_deprecated(version: &deps_pypi::PypiVersion) -> bool {
        version.yanked
    }

    fn is_valid_version_syntax(_version_req: &str) -> bool {
        true
    }

    fn parse_version_req(version_req: &str) -> Option<String> {
        Some(version_req.to_string())
    }
}

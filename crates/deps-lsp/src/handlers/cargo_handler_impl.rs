//! CargoHandler implementation with UnifiedDependency extraction.
//!
//! This module provides the glue between CargoHandler from deps-cargo
//! and UnifiedDependency from deps-lsp.

use crate::document::UnifiedDependency;
use async_trait::async_trait;
use deps_cargo::{CargoLockParser, CratesIoRegistry, ParsedDependency, crate_url};
use deps_core::{
    EcosystemHandler, HttpCache, LockFileProvider, SemverMatcher, VersionRequirementMatcher,
};
use std::sync::Arc;

/// Cargo ecosystem handler with UnifiedDependency support.
///
/// This is a wrapper around deps_cargo::CargoHandler that knows how to
/// extract ParsedDependency from UnifiedDependency.
pub struct CargoHandlerImpl {
    registry: CratesIoRegistry,
}

#[async_trait]
impl EcosystemHandler for CargoHandlerImpl {
    type Registry = CratesIoRegistry;
    type Dependency = ParsedDependency;
    type UnifiedDep = UnifiedDependency;

    fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: CratesIoRegistry::new(cache),
        }
    }

    fn registry(&self) -> &Self::Registry {
        &self.registry
    }

    fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
        match dep {
            UnifiedDependency::Cargo(cargo_dep) => Some(cargo_dep),
            _ => None,
        }
    }

    fn package_url(name: &str) -> String {
        crate_url(name)
    }

    fn ecosystem_display_name() -> &'static str {
        "crates.io"
    }

    fn is_version_latest(version_req: &str, latest: &str) -> bool {
        SemverMatcher.is_latest_satisfying(version_req, latest)
    }

    fn format_version_for_edit(_dep: &Self::Dependency, version: &str) -> String {
        format!("\"{}\"", version)
    }

    fn is_deprecated(version: &deps_cargo::CargoVersion) -> bool {
        version.yanked
    }

    fn is_valid_version_syntax(version_req: &str) -> bool {
        version_req.parse::<semver::VersionReq>().is_ok()
    }

    fn parse_version_req(version_req: &str) -> Option<semver::VersionReq> {
        version_req.parse().ok()
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
        Some(Arc::new(CargoLockParser))
    }
}

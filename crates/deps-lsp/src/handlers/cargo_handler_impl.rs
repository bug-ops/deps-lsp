//! CargoHandler implementation with UnifiedDependency extraction.
//!
//! This module provides the glue between CargoHandler from deps-cargo
//! and UnifiedDependency from deps-lsp.

use crate::document::UnifiedDependency;
use async_trait::async_trait;
use deps_cargo::{CratesIoRegistry, ParsedDependency, crate_url};
use deps_core::{EcosystemHandler, HttpCache, SemverMatcher, VersionRequirementMatcher};
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

    fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: CratesIoRegistry::new(cache),
        }
    }

    fn registry(&self) -> &Self::Registry {
        &self.registry
    }

    fn extract_dependency<'a, UnifiedDep>(dep: &'a UnifiedDep) -> Option<&'a Self::Dependency> {
        // SAFETY: UnifiedDep must be UnifiedDependency when this is called.
        // We use transmute to convert the reference.
        let unified = unsafe { &*(dep as *const UnifiedDep as *const UnifiedDependency) };
        match unified {
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
}

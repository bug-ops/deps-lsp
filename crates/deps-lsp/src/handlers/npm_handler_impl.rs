//! NpmHandler implementation with UnifiedDependency extraction.
//!
//! This module provides the glue between NpmRegistry from deps-npm
//! and UnifiedDependency from deps-lsp.

use crate::document::UnifiedDependency;
use async_trait::async_trait;
use deps_core::{EcosystemHandler, HttpCache, SemverMatcher, VersionRequirementMatcher};
use deps_npm::{NpmDependency, NpmRegistry, package_url};
use std::sync::Arc;

/// npm ecosystem handler with UnifiedDependency support.
///
/// This is a wrapper around deps_npm::NpmRegistry that knows how to
/// extract NpmDependency from UnifiedDependency.
pub struct NpmHandlerImpl {
    registry: NpmRegistry,
}

#[async_trait]
impl EcosystemHandler for NpmHandlerImpl {
    type Registry = NpmRegistry;
    type Dependency = NpmDependency;
    type UnifiedDep = UnifiedDependency;

    fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: NpmRegistry::new(cache),
        }
    }

    fn registry(&self) -> &Self::Registry {
        &self.registry
    }

    fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
        match dep {
            UnifiedDependency::Npm(npm_dep) => Some(npm_dep),
            _ => None,
        }
    }

    fn package_url(name: &str) -> String {
        package_url(name)
    }

    fn ecosystem_display_name() -> &'static str {
        "npmjs.com"
    }

    fn is_version_latest(version_req: &str, latest: &str) -> bool {
        SemverMatcher.is_latest_satisfying(version_req, latest)
    }
}

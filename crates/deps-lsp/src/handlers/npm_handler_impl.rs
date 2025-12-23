//! NpmHandler implementation with UnifiedDependency extraction.
//!
//! This module provides the glue between NpmRegistry from deps-npm
//! and UnifiedDependency from deps-lsp.

use crate::document::UnifiedDependency;
use async_trait::async_trait;
use deps_core::{
    EcosystemHandler, HttpCache, LockFileProvider, SemverMatcher, VersionRequirementMatcher,
};
use deps_npm::{NpmDependency, NpmLockParser, NpmRegistry, package_url};
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

    fn format_version_for_edit(_dep: &Self::Dependency, version: &str) -> String {
        format!("\"{}\"", version)
    }

    fn is_deprecated(version: &deps_npm::NpmVersion) -> bool {
        version.deprecated
    }

    fn is_valid_version_syntax(_version_req: &str) -> bool {
        true
    }

    fn parse_version_req(version_req: &str) -> Option<deps_npm::NpmVersionReq> {
        version_req.parse().ok()
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
        Some(Arc::new(NpmLockParser))
    }
}

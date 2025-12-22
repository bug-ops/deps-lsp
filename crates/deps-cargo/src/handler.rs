//! Cargo ecosystem handler implementation.
//!
//! Implements the EcosystemHandler trait for Cargo/crates.io,
//! enabling generic LSP operations (inlay hints, hover, etc.).

use crate::{CratesIoRegistry, crate_url, ParsedDependency};
use async_trait::async_trait;
use deps_core::{EcosystemHandler, HttpCache, SemverMatcher, VersionRequirementMatcher};
use std::sync::Arc;

/// Cargo ecosystem handler.
///
/// Provides Cargo-specific implementations of the generic handler trait,
/// using crates.io registry and semver version matching.
pub struct CargoHandler {
    registry: CratesIoRegistry,
}

#[async_trait]
impl EcosystemHandler for CargoHandler {
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

    fn extract_dependency<'a, UnifiedDep>(_dep: &'a UnifiedDep) -> Option<&'a Self::Dependency> {
        // UnifiedDep should be deps_lsp::document::UnifiedDependency when called.
        // We use a trick here: transmute the reference through Any trait.
        // This is safe because the caller (in deps-lsp) ensures the correct type.
        //
        // The proper implementation will be in deps-lsp where UnifiedDependency
        // is available. For now, we return None and will implement this properly
        // when integrating with deps-lsp.
        None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url() {
        let url = CargoHandler::package_url("serde");
        assert_eq!(url, "https://crates.io/crates/serde");
    }

    #[test]
    fn test_ecosystem_display_name() {
        assert_eq!(CargoHandler::ecosystem_display_name(), "crates.io");
    }

    #[test]
    fn test_is_version_latest_compatible() {
        assert!(CargoHandler::is_version_latest("1.0.0", "1.0.5"));
        assert!(CargoHandler::is_version_latest("^1.0.0", "1.5.0"));
        assert!(CargoHandler::is_version_latest("0.1", "0.1.83"));
    }

    #[test]
    fn test_is_version_latest_incompatible() {
        assert!(!CargoHandler::is_version_latest("1.0.0", "2.0.0"));
        assert!(!CargoHandler::is_version_latest("0.1", "0.2.0"));
    }
}

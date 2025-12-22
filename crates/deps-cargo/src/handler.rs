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
    type UnifiedDep = ParsedDependency; // Self-contained: no UnifiedDependency needed

    fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: CratesIoRegistry::new(cache),
        }
    }

    fn registry(&self) -> &Self::Registry {
        &self.registry
    }

    fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
        // In standalone use, UnifiedDep is just ParsedDependency
        Some(dep)
    }

    fn package_url(name: &str) -> String {
        crate_url(name)
    }

    fn ecosystem_display_name() -> &'static str {
        "crates.io"
    }

    #[inline]
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

    #[test]
    fn test_new_creates_handler() {
        let cache = Arc::new(HttpCache::new());
        let handler = CargoHandler::new(cache);
        let registry = handler.registry();
        assert!(std::ptr::addr_of!(*registry) == std::ptr::addr_of!(handler.registry));
    }

    #[test]
    fn test_extract_dependency_returns_some() {
        use crate::ParsedDependency;
        use tower_lsp::lsp_types::{Position, Range};

        let dep = ParsedDependency {
            name: "test".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 4)),
            version_req: Some("1.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 8), Position::new(0, 13))),
            features: vec![],
            features_range: None,
            source: crate::DependencySource::Registry,
            workspace_inherited: false,
            section: crate::DependencySection::Dependencies,
        };
        let result = CargoHandler::extract_dependency(&dep);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "test");
    }

    #[test]
    fn test_is_version_latest_with_tilde() {
        assert!(CargoHandler::is_version_latest("~1.0.0", "1.0.5"));
        assert!(!CargoHandler::is_version_latest("~1.0.0", "1.1.0"));
    }

    #[test]
    fn test_is_version_latest_with_exact() {
        assert!(CargoHandler::is_version_latest("=1.0.0", "1.0.0"));
        assert!(!CargoHandler::is_version_latest("=1.0.0", "1.0.1"));
    }

    #[test]
    fn test_is_version_latest_edge_cases() {
        assert!(CargoHandler::is_version_latest("0.0.1", "0.0.1"));
        assert!(!CargoHandler::is_version_latest("0.0.1", "0.0.2"));
    }
}

//! Types for Go module dependency management.

use deps_core::parser::DependencySource;
use std::any::Any;
use tower_lsp_server::ls_types::Range;

/// A dependency from a go.mod file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoDependency {
    /// Module path (e.g., "github.com/gin-gonic/gin")
    pub module_path: deps_core::PackageName,
    /// LSP range of the module path in source
    pub module_path_range: Range,
    /// Version requirement (e.g., "v1.9.1", "v0.0.0-20191109021931-daa7c04131f5")
    pub version: Option<deps_core::VersionReq>,
    /// LSP range of version in source
    pub version_range: Option<Range>,
    /// Dependency directive type
    pub directive: GoDirective,
    /// Whether this is an indirect dependency (// indirect comment)
    pub indirect: bool,
}

/// Go module directive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoDirective {
    /// Direct dependency in require block
    Require,
    /// Replacement directive
    Replace,
    /// Exclusion directive
    Exclude,
    /// Retraction directive
    Retract,
}

/// Version information from proxy.golang.org.
#[derive(Debug, Clone)]
pub struct GoVersion {
    /// Version string (e.g., "v1.9.1")
    pub version: String,
    /// Publish timestamp, parsed eagerly from the `/@latest` and
    /// `/@v/{version}.info` endpoints' `Time` field.
    ///
    /// Always `None` for versions from `/@v/list` (the `Ch2` path), which
    /// carries no dates — a documented Go-specific limitation, not a bug.
    /// `None` also when the value fails to parse as RFC 3339, degrading
    /// gracefully per [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
    /// Whether this is a pseudo-version
    pub is_pseudo: bool,
    /// Whether this version is retracted
    pub retracted: bool,
}

/// Package metadata from proxy.golang.org.
#[derive(Debug, Clone)]
pub struct GoMetadata {
    /// Module path
    pub module_path: deps_core::PackageName,
    /// Latest stable version
    pub latest_version: String,
    /// Description (if available from go.mod or README)
    pub description: Option<String>,
    /// Repository URL (inferred from module path)
    pub repository: Option<String>,
    /// Documentation URL (pkg.go.dev)
    pub documentation: Option<String>,
}

// NOTE: Cannot use deps_core::impl_dependency! macro because we need to provide custom
// features() implementation (Go modules don't have features like Cargo).
// The macro would provide features() but we need to override it anyway.
impl deps_core::ecosystem::Dependency for GoDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.module_path
    }

    fn name_range(&self) -> Range {
        self.module_path_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        DependencySource::Registry
    }

    fn features(&self) -> &[String] {
        &[]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// NOTE: Cannot use impl_version! macro because GoVersion has custom is_prerelease() logic.
// Go considers pseudo-versions as pre-releases, and has special handling for +incompatible suffix.
impl deps_core::registry::Version for GoVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn removal_status(&self) -> deps_core::RemovalStatus {
        deps_core::RemovalStatus::from_yanked(self.retracted)
    }

    fn published_at(&self) -> Option<deps_core::PublishTime> {
        self.published_at
    }

    fn is_prerelease(&self) -> bool {
        // Go considers pseudo-versions as pre-releases (they're commit-based).
        // Regular pre-releases contain '-' (e.g., v1.0.0-beta.1).
        // BUT: +incompatible suffix is NOT a pre-release indicator.
        self.is_pseudo || (self.version.contains('-') && !self.version.contains("+incompatible"))
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

deps_core::impl_metadata!(GoMetadata {
    name: module_path,
    description: description,
    repository: repository,
    documentation: documentation,
    latest_version: latest_version,
});

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::ecosystem::Dependency;
    use deps_core::registry::{Metadata, Version};
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_go_dependency_trait() {
        let dep = GoDependency {
            module_path: "github.com/gin-gonic/gin".into(),
            module_path_range: Range::new(Position::new(0, 0), Position::new(0, 10)),
            version: Some("v1.9.1".into()),
            version_range: Some(Range::new(Position::new(0, 11), Position::new(0, 17))),
            directive: GoDirective::Require,
            indirect: false,
        };

        assert_eq!(dep.name(), "github.com/gin-gonic/gin");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v1.9.1")
        );
        assert!(matches!(dep.source(), DependencySource::Registry));
        assert_eq!(dep.features().len(), 0);
    }

    #[test]
    fn test_go_version_trait() {
        let version = GoVersion {
            version: "v1.9.1".to_string(),
            published_at: deps_core::PublishTime::parse_rfc3339("2023-01-01T00:00:00Z"),
            is_pseudo: false,
            retracted: false,
        };

        assert_eq!(version.version_string(), "v1.9.1");
        assert!(!version.removal_status().blocks_resolution());
        assert!(!version.is_prerelease());
        assert!(version.is_stable());
        assert_eq!(
            version.published_at(),
            deps_core::PublishTime::parse_rfc3339("2023-01-01T00:00:00Z")
        );
    }

    #[test]
    fn test_pseudo_version_is_prerelease() {
        let version = GoVersion {
            version: "v0.0.0-20191109021931-daa7c04131f5".to_string(),
            published_at: None,
            is_pseudo: true,
            retracted: false,
        };

        assert!(version.is_prerelease());
        assert!(!version.is_stable());
    }

    #[test]
    fn test_retracted_version_is_yanked() {
        let version = GoVersion {
            version: "v1.0.0".to_string(),
            published_at: None,
            is_pseudo: false,
            retracted: true,
        };

        assert!(version.removal_status().blocks_resolution());
        assert!(!version.is_stable());
    }

    #[test]
    fn test_go_metadata_trait() {
        let metadata = GoMetadata {
            module_path: "github.com/gin-gonic/gin".into(),
            latest_version: "v1.9.1".to_string(),
            description: Some("Gin is a HTTP web framework".to_string()),
            repository: Some("https://github.com/gin-gonic/gin".to_string()),
            documentation: Some("https://pkg.go.dev/github.com/gin-gonic/gin".to_string()),
        };

        assert_eq!(metadata.name(), "github.com/gin-gonic/gin");
        assert_eq!(metadata.latest_version(), "v1.9.1");
        assert_eq!(metadata.description(), Some("Gin is a HTTP web framework"));
        assert_eq!(
            metadata.repository(),
            Some("https://github.com/gin-gonic/gin")
        );
        assert_eq!(
            metadata.documentation(),
            Some("https://pkg.go.dev/github.com/gin-gonic/gin")
        );
    }

    #[test]
    fn test_go_directive_equality() {
        assert_eq!(GoDirective::Require, GoDirective::Require);
        assert_ne!(GoDirective::Require, GoDirective::Replace);
    }
}

//! Types for Go module dependency management.

use deps_core::parser::DependencySource;
use std::any::Any;
use tower_lsp_server::ls_types::Range;

/// A dependency from a go.mod file.
#[non_exhaustive]
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
    /// Resolved source (spec 034): `Registry` unless `$GOENV` declares a `GOPROXY`/`GOPRIVATE`
    /// override applicable to this module path.
    pub source: DependencySource,
}

/// Go module directive types.
#[non_exhaustive]
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GoVersion {
    /// Version string (e.g., "v1.9.1")
    pub version: deps_core::ConcreteVersion,
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
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct GoMetadata {
    /// Module path
    pub module_path: deps_core::PackageName,
    /// Latest stable version
    pub latest_version: deps_core::ConcreteVersion,
    /// Description (if available from go.mod or README)
    pub description: Option<String>,
    /// Repository URL (inferred from module path)
    pub repository: Option<String>,
    /// Documentation URL (pkg.go.dev)
    pub documentation: Option<String>,
}

impl GoMetadata {
    /// Constructs a `GoMetadata` from its required fields, with [`Self::description`],
    /// [`Self::repository`], and [`Self::documentation`] left `None` — chain the
    /// corresponding `with_*` setters to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_go::types::GoMetadata;
    ///
    /// let metadata = GoMetadata::new(
    ///     deps_core::PackageName::new("github.com/gin-gonic/gin"),
    ///     "v1.9.1".into(),
    /// )
    /// .with_repository("https://github.com/gin-gonic/gin");
    ///
    /// assert_eq!(metadata.module_path, "github.com/gin-gonic/gin");
    /// ```
    #[must_use]
    pub const fn new(
        module_path: deps_core::PackageName,
        latest_version: deps_core::ConcreteVersion,
    ) -> Self {
        Self {
            module_path,
            latest_version,
            description: None,
            repository: None,
            documentation: None,
        }
    }

    /// Attaches the description. See [`Self::description`].
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Attaches the repository URL. See [`Self::repository`].
    #[must_use]
    pub fn with_repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    /// Attaches the documentation URL. See [`Self::documentation`].
    #[must_use]
    pub fn with_documentation(mut self, documentation: impl Into<String>) -> Self {
        self.documentation = Some(documentation.into());
        self
    }
}

deps_core::impl_dependency!(GoDependency {
    name: module_path,
    name_range: module_path_range,
    version: version,
    version_range: version_range,
    source: source,
});

// NOTE: Cannot use impl_version! macro because GoVersion has custom is_prerelease() logic.
// Go considers pseudo-versions as pre-releases, and has special handling for +incompatible suffix.
impl deps_core::registry::Version for GoVersion {
    fn version_string(&self) -> &deps_core::ConcreteVersion {
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
        self.is_pseudo
            || (self.version.as_str().contains('-')
                && !self.version.as_str().contains("+incompatible"))
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
    use std::assert_matches;
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
            source: DependencySource::Registry,
        };

        assert_eq!(dep.name(), "github.com/gin-gonic/gin");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v1.9.1")
        );
        assert_matches!(dep.source(), DependencySource::Registry);
        assert_eq!(dep.features().len(), 0);
    }

    #[test]
    fn test_go_version_trait() {
        let version = GoVersion {
            version: "v1.9.1".into(),
            published_at: deps_core::PublishTime::parse_rfc3339("2023-01-01T00:00:00Z"),
            is_pseudo: false,
            retracted: false,
        };

        assert_eq!(version.version_string().as_str(), "v1.9.1");
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
            version: "v0.0.0-20191109021931-daa7c04131f5".into(),
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
            version: "v1.0.0".into(),
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
            latest_version: "v1.9.1".into(),
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

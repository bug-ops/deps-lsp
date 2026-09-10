//! Domain types for Dart/Pub dependencies.

use tower_lsp_server::ls_types::Range;

/// A single dependency declaration parsed from a `pubspec.yaml`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartDependency {
    /// Package name.
    pub name: deps_core::PackageName,
    /// Document range of the package name, for hover/diagnostic positioning.
    pub name_range: Range,
    /// Version requirement, if the manifest specifies one.
    pub version_req: Option<deps_core::VersionReq>,
    /// Document range of the version requirement string.
    pub version_range: Option<Range>,
    /// Which `pubspec.yaml` section this dependency was declared under.
    pub section: DependencySection,
    /// Where this dependency resolves from (registry, git, path, etc.).
    pub source: DependencySource,
    /// Dart-specific Git sub-path (e.g., `path: packages/pkg` inside a repo).
    /// Only meaningful when `source` is `DependencySource::Git`.
    pub git_path: Option<String>,
}

/// Which `pubspec.yaml` top-level section a dependency was declared under.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DependencySection {
    /// The `dependencies:` section.
    #[default]
    Dependencies,
    /// The `dev_dependencies:` section.
    DevDependencies,
    /// The `dependency_overrides:` section.
    DependencyOverrides,
}

pub use deps_core::parser::DependencySource;

/// A single published version of a Dart/Pub package.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DartVersion {
    /// The parsed version number.
    pub version: deps_core::ConcreteVersion,
    /// Whether pub.dev has retracted this version.
    pub retracted: bool,
    /// Publish timestamp, parsed eagerly from the API's `published` field.
    ///
    /// `None` when the response omits it or the value fails to parse as
    /// RFC 3339 — degrades gracefully, per
    /// [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
}

/// Package metadata as returned by the pub.dev API.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PackageInfo {
    /// Package name.
    pub name: deps_core::PackageName,
    /// Short package description.
    pub description: Option<String>,
    /// Homepage URL.
    pub homepage: Option<String>,
    /// Source repository URL.
    pub repository: Option<String>,
    /// Documentation URL.
    pub documentation: Option<String>,
    /// Latest published version.
    pub version: deps_core::ConcreteVersion,
    /// SPDX license identifier, if declared.
    pub license: Option<String>,
}

impl PackageInfo {
    /// Constructs a `PackageInfo` from its required fields, with every other field left
    /// `None` — chain the corresponding `with_*` setters to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_dart::types::PackageInfo;
    ///
    /// let info = PackageInfo::new(deps_core::PackageName::new("provider"), "6.1.1".into())
    ///     .with_description("A wrapper around InheritedWidget");
    ///
    /// assert_eq!(info.name, "provider");
    /// ```
    #[must_use]
    pub const fn new(name: deps_core::PackageName, version: deps_core::ConcreteVersion) -> Self {
        Self {
            name,
            description: None,
            homepage: None,
            repository: None,
            documentation: None,
            version,
            license: None,
        }
    }

    /// Attaches a short package description. See [`Self::description`].
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Attaches the homepage URL. See [`Self::homepage`].
    #[must_use]
    pub fn with_homepage(mut self, homepage: impl Into<String>) -> Self {
        self.homepage = Some(homepage.into());
        self
    }

    /// Attaches the source repository URL. See [`Self::repository`].
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

    /// Attaches the SPDX license identifier. See [`Self::license`].
    #[must_use]
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }
}

// deps-core trait implementations

deps_core::impl_dependency!(DartDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
    source: source,
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use tower_lsp_server::ls_types::Position;

    fn test_dep(source: DependencySource) -> DartDependency {
        DartDependency {
            name: "flutter_bloc".into(),
            name_range: Range::new(Position::new(5, 2), Position::new(5, 14)),
            version_req: Some("^8.1.0".into()),
            version_range: Some(Range::new(Position::new(5, 16), Position::new(5, 22))),
            section: DependencySection::Dependencies,
            source,
            git_path: None,
        }
    }

    #[test]
    fn test_dependency_source_variants() {
        assert_matches!(DependencySource::Registry, DependencySource::Registry);
        assert_matches!(
            DependencySource::Git {
                url: "u".into(),
                rev: None
            },
            DependencySource::Git { .. }
        );
        assert_matches!(
            DependencySource::Path { path: "p".into() },
            DependencySource::Path { .. }
        );
        assert_matches!(
            DependencySource::Sdk {
                sdk: "flutter".into()
            },
            DependencySource::Sdk { .. }
        );
    }

    #[test]
    fn test_dependency_section_default() {
        assert_matches!(
            DependencySection::default(),
            DependencySection::Dependencies
        );
    }

    #[test]
    fn test_dependency_trait() {
        use deps_core::Dependency;

        let dep = test_dep(DependencySource::Registry);
        assert_eq!(dep.name(), "flutter_bloc");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("^8.1.0")
        );
        assert!(dep.as_any().is::<DartDependency>());
    }

    #[test]
    fn test_dependency_info_source_registry() {
        use deps_core::Dependency;
        let dep = test_dep(DependencySource::Registry);
        assert!(dep.source().is_registry());
    }

    #[test]
    fn test_dependency_info_source_sdk() {
        use deps_core::Dependency;
        let dep = test_dep(DependencySource::Sdk {
            sdk: "flutter".into(),
        });
        assert!(!dep.source().is_registry());
        assert_matches!(dep.source(), DependencySource::Sdk { sdk } if sdk == "flutter");
    }

    #[test]
    fn test_dependency_info_source_git() {
        use deps_core::Dependency;
        let dep = test_dep(DependencySource::Git {
            url: "https://github.com/test/repo".into(),
            rev: Some("main".into()),
        });
        match dep.source() {
            deps_core::parser::DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/test/repo");
                assert_eq!(rev, Some("main".to_string()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_info_source_path() {
        use deps_core::Dependency;
        let dep = test_dep(DependencySource::Path {
            path: "../local".into(),
        });
        match dep.source() {
            deps_core::parser::DependencySource::Path { path } => {
                assert_eq!(path, "../local");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_version_trait() {
        use deps_core::Version;
        let ver = DartVersion {
            version: "1.0.0".into(),
            retracted: false,
            published_at: Some(deps_core::PublishTime::from_unix_secs(1_704_067_200)),
        };
        assert_eq!(ver.version_string(), "1.0.0");
        assert!(!ver.removal_status().blocks_resolution());
        assert!(ver.features().is_empty());
        assert!(ver.as_any().is::<DartVersion>());
    }

    #[test]
    fn test_version_retracted() {
        use deps_core::Version;
        let ver = DartVersion {
            version: "0.9.0".into(),
            retracted: true,
            published_at: None,
        };
        assert!(ver.removal_status().blocks_resolution());
    }

    #[test]
    fn test_version_is_prerelease() {
        use deps_core::Version;

        let stable = DartVersion {
            version: "1.0.0".into(),
            retracted: false,
            published_at: None,
        };
        let prerelease = DartVersion {
            version: "2.10.0-nullsafety.1".into(),
            retracted: false,
            published_at: None,
        };

        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
        assert!(prerelease.is_prerelease());
        assert!(!prerelease.is_stable());
    }

    #[test]
    fn test_metadata_trait() {
        use deps_core::Metadata;
        let info = PackageInfo {
            name: "provider".into(),
            description: Some("A wrapper around InheritedWidget".into()),
            homepage: Some("https://pub.dev/packages/provider".into()),
            repository: Some("https://github.com/rrousselGit/provider".into()),
            documentation: Some("https://pub.dev/documentation/provider".into()),
            version: "6.1.2".into(),
            license: Some("MIT".into()),
        };
        assert_eq!(info.name(), "provider");
        assert!(info.description().is_some());
        assert_eq!(info.latest_version(), "6.1.2");
        assert!(info.as_any().is::<PackageInfo>());
    }

    #[test]
    fn test_metadata_minimal() {
        use deps_core::Metadata;
        let info = PackageInfo {
            name: "minimal".into(),
            description: None,
            homepage: None,
            repository: None,
            documentation: None,
            version: "0.1.0".into(),
            license: None,
        };
        assert!(info.description().is_none());
        assert!(info.repository().is_none());
        assert!(info.documentation().is_none());
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;
        let dep = DartDependency {
            name: "test".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            section: DependencySection::Dependencies,
            source: DependencySource::Registry,
            git_path: None,
        };
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }
}

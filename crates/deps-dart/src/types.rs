//! Domain types for Dart/Pub dependencies.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartDependency {
    pub name: deps_core::PackageName,
    pub name_range: Range,
    pub version_req: Option<deps_core::VersionReq>,
    pub version_range: Option<Range>,
    pub section: DependencySection,
    pub source: DependencySource,
    /// Dart-specific Git sub-path (e.g., `path: packages/pkg` inside a repo).
    /// Only meaningful when `source` is `DependencySource::Git`.
    pub git_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DependencySection {
    #[default]
    Dependencies,
    DevDependencies,
    DependencyOverrides,
}

pub use deps_core::parser::DependencySource;

#[derive(Debug, Clone)]
pub struct DartVersion {
    pub version: deps_core::ConcreteVersion,
    pub retracted: bool,
    /// Publish timestamp, parsed eagerly from the API's `published` field.
    ///
    /// `None` when the response omits it or the value fails to parse as
    /// RFC 3339 — degrades gracefully, per
    /// [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: deps_core::PackageName,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub version: deps_core::ConcreteVersion,
    pub license: Option<String>,
}

// deps-core trait implementations

impl deps_core::Dependency for DartDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::parser::DependencySource {
        self.source.clone()
    }

    fn features(&self) -> &[String] {
        &[]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

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

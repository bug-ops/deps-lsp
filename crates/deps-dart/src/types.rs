//! Domain types for Dart/Pub dependencies.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DartDependency {
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub section: DependencySection,
    pub source: DependencySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DependencySection {
    #[default]
    Dependencies,
    DevDependencies,
    DependencyOverrides,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DependencySource {
    #[default]
    Hosted,
    Git {
        url: String,
        ref_: Option<String>,
        path: Option<String>,
    },
    Path {
        path: String,
    },
    Sdk {
        sdk: String,
    },
}

#[derive(Debug, Clone)]
pub struct DartVersion {
    pub version: String,
    pub retracted: bool,
    pub published: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub version: String,
    pub license: Option<String>,
}

// deps-core trait implementations

impl DartDependency {
    fn core_source(&self) -> deps_core::parser::DependencySource {
        match &self.source {
            DependencySource::Hosted => deps_core::parser::DependencySource::Registry,
            DependencySource::Git { url, ref_, .. } => deps_core::parser::DependencySource::Git {
                url: url.clone(),
                rev: ref_.clone(),
            },
            DependencySource::Path { path } => {
                deps_core::parser::DependencySource::Path { path: path.clone() }
            }
            DependencySource::Sdk { .. } => deps_core::parser::DependencySource::Registry,
        }
    }
}

impl deps_core::DependencyInfo for DartDependency {
    fn name(&self) -> &str {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&str> {
        self.version_req.as_deref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::parser::DependencySource {
        self.core_source()
    }

    fn features(&self) -> &[String] {
        &[]
    }
}

impl deps_core::Dependency for DartDependency {
    fn name(&self) -> &str {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&str> {
        self.version_req.as_deref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::parser::DependencySource {
        self.core_source()
    }

    fn features(&self) -> &[String] {
        &[]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Version for DartVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.retracted
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for PackageInfo {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.repository.as_deref()
    }

    fn documentation(&self) -> Option<&str> {
        self.documentation.as_deref()
    }

    fn latest_version(&self) -> &str {
        &self.version
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::Position;

    fn test_dep(source: DependencySource) -> DartDependency {
        DartDependency {
            name: "flutter_bloc".into(),
            name_range: Range::new(Position::new(5, 2), Position::new(5, 14)),
            version_req: Some("^8.1.0".into()),
            version_range: Some(Range::new(Position::new(5, 16), Position::new(5, 22))),
            section: DependencySection::Dependencies,
            source,
        }
    }

    #[test]
    fn test_dependency_source_variants() {
        assert!(matches!(DependencySource::Hosted, DependencySource::Hosted));
        assert!(matches!(
            DependencySource::Git {
                url: "u".into(),
                ref_: None,
                path: None
            },
            DependencySource::Git { .. }
        ));
        assert!(matches!(
            DependencySource::Path { path: "p".into() },
            DependencySource::Path { .. }
        ));
        assert!(matches!(
            DependencySource::Sdk {
                sdk: "flutter".into()
            },
            DependencySource::Sdk { .. }
        ));
    }

    #[test]
    fn test_dependency_section_default() {
        assert!(matches!(
            DependencySection::default(),
            DependencySection::Dependencies
        ));
    }

    #[test]
    fn test_dependency_trait() {
        use deps_core::Dependency;

        let dep = test_dep(DependencySource::Hosted);
        assert_eq!(dep.name(), "flutter_bloc");
        assert_eq!(dep.version_requirement(), Some("^8.1.0"));
        assert!(dep.as_any().is::<DartDependency>());
    }

    #[test]
    fn test_dependency_info_source_hosted() {
        use deps_core::DependencyInfo;
        let dep = test_dep(DependencySource::Hosted);
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_info_source_git() {
        use deps_core::DependencyInfo;
        let dep = test_dep(DependencySource::Git {
            url: "https://github.com/test/repo".into(),
            ref_: Some("main".into()),
            path: None,
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
        use deps_core::DependencyInfo;
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
    fn test_dependency_info_source_sdk() {
        use deps_core::DependencyInfo;
        let dep = test_dep(DependencySource::Sdk {
            sdk: "flutter".into(),
        });
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_version_trait() {
        use deps_core::Version;
        let ver = DartVersion {
            version: "1.0.0".into(),
            retracted: false,
            published: Some("2024-01-01".into()),
        };
        assert_eq!(ver.version_string(), "1.0.0");
        assert!(!ver.is_yanked());
        assert!(ver.features().is_empty());
        assert!(ver.as_any().is::<DartVersion>());
    }

    #[test]
    fn test_version_retracted() {
        use deps_core::Version;
        let ver = DartVersion {
            version: "0.9.0".into(),
            retracted: true,
            published: None,
        };
        assert!(ver.is_yanked());
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
            source: DependencySource::Hosted,
        };
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }
}

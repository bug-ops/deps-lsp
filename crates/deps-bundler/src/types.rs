//! Domain types for Bundler dependencies.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

/// Parsed dependency from Gemfile with position tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundlerDependency {
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub group: DependencyGroup,
    pub source: DependencySource,
    pub platforms: Vec<String>,
    pub require: Option<String>,
}

/// Source location of a dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencySource {
    /// Default rubygems.org registry
    Registry,
    /// Git repository
    Git {
        url: String,
        branch: Option<String>,
        tag: Option<String>,
        ref_: Option<String>,
    },
    /// Local filesystem path
    Path { path: String },
    /// GitHub shorthand (e.g., "rails/rails")
    Github {
        repo: String,
        branch: Option<String>,
    },
    /// Custom gem source
    Source { name: String, url: String },
}

/// Gem group classification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DependencyGroup {
    /// No explicit group (runtime dependency)
    #[default]
    Default,
    /// :development group
    Development,
    /// :test group
    Test,
    /// :production group
    Production,
    /// Custom group name
    Custom(String),
}

/// Version information for a gem from rubygems.org.
#[derive(Debug, Clone)]
pub struct BundlerVersion {
    pub number: String,
    pub prerelease: bool,
    pub yanked: bool,
    pub created_at: Option<String>,
    pub platform: String,
}

impl BundlerVersion {
    /// Returns true if this is a stable (non-prerelease) version.
    pub fn is_stable(&self) -> bool {
        !self.prerelease && !self.yanked
    }
}

/// Gem metadata from rubygems.org.
#[derive(Debug, Clone)]
pub struct GemInfo {
    pub name: String,
    pub info: Option<String>,
    pub homepage_uri: Option<String>,
    pub source_code_uri: Option<String>,
    pub documentation_uri: Option<String>,
    pub version: String,
    pub licenses: Vec<String>,
    pub authors: Option<String>,
    pub downloads: u64,
}

// Trait implementations for deps-core integration

impl deps_core::DependencyInfo for BundlerDependency {
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
        match &self.source {
            DependencySource::Registry => deps_core::parser::DependencySource::Registry,
            DependencySource::Git { url, ref_, .. } => deps_core::parser::DependencySource::Git {
                url: url.clone(),
                rev: ref_.clone(),
            },
            DependencySource::Path { path } => {
                deps_core::parser::DependencySource::Path { path: path.clone() }
            }
            DependencySource::Github { repo, .. } => deps_core::parser::DependencySource::Git {
                url: format!("https://github.com/{repo}"),
                rev: None,
            },
            DependencySource::Source { .. } => deps_core::parser::DependencySource::Registry,
        }
    }

    fn features(&self) -> &[String] {
        &[]
    }
}

impl deps_core::Dependency for BundlerDependency {
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
        match &self.source {
            DependencySource::Registry => deps_core::parser::DependencySource::Registry,
            DependencySource::Git { url, ref_, .. } => deps_core::parser::DependencySource::Git {
                url: url.clone(),
                rev: ref_.clone(),
            },
            DependencySource::Path { path } => {
                deps_core::parser::DependencySource::Path { path: path.clone() }
            }
            DependencySource::Github { repo, .. } => deps_core::parser::DependencySource::Git {
                url: format!("https://github.com/{repo}"),
                rev: None,
            },
            DependencySource::Source { .. } => deps_core::parser::DependencySource::Registry,
        }
    }

    fn features(&self) -> &[String] {
        &[]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Version for BundlerVersion {
    fn version_string(&self) -> &str {
        &self.number
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for GemInfo {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.info.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.source_code_uri.as_deref()
    }

    fn documentation(&self) -> Option<&str> {
        self.documentation_uri.as_deref()
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

    fn create_test_dependency(source: DependencySource) -> BundlerDependency {
        BundlerDependency {
            name: "test_gem".into(),
            name_range: Range::new(Position::new(1, 5), Position::new(1, 13)),
            version_req: Some("~> 1.0".into()),
            version_range: Some(Range::new(Position::new(1, 17), Position::new(1, 23))),
            group: DependencyGroup::Default,
            source,
            platforms: vec![],
            require: None,
        }
    }

    #[test]
    fn test_dependency_source_variants() {
        let registry = DependencySource::Registry;
        let git = DependencySource::Git {
            url: "https://github.com/rails/rails".into(),
            branch: Some("main".into()),
            tag: None,
            ref_: None,
        };
        let path = DependencySource::Path {
            path: "../local".into(),
        };
        let github = DependencySource::Github {
            repo: "rails/rails".into(),
            branch: None,
        };
        let source = DependencySource::Source {
            name: "custom".into(),
            url: "https://custom.gem.source".into(),
        };

        assert!(matches!(registry, DependencySource::Registry));
        assert!(matches!(git, DependencySource::Git { .. }));
        assert!(matches!(path, DependencySource::Path { .. }));
        assert!(matches!(github, DependencySource::Github { .. }));
        assert!(matches!(source, DependencySource::Source { .. }));
    }

    #[test]
    fn test_dependency_group_variants() {
        let default = DependencyGroup::Default;
        let dev = DependencyGroup::Development;
        let test = DependencyGroup::Test;
        let prod = DependencyGroup::Production;
        let custom = DependencyGroup::Custom("staging".into());

        assert!(matches!(default, DependencyGroup::Default));
        assert!(matches!(dev, DependencyGroup::Development));
        assert!(matches!(test, DependencyGroup::Test));
        assert!(matches!(prod, DependencyGroup::Production));
        assert!(matches!(custom, DependencyGroup::Custom(_)));
    }

    #[test]
    fn test_dependency_group_default() {
        let group = DependencyGroup::default();
        assert!(matches!(group, DependencyGroup::Default));
    }

    #[test]
    fn test_bundler_version_creation() {
        let version = BundlerVersion {
            number: "7.0.8".into(),
            prerelease: false,
            yanked: false,
            created_at: Some("2023-09-09".into()),
            platform: "ruby".into(),
        };

        assert_eq!(version.number, "7.0.8");
        assert!(!version.yanked);
        assert!(version.is_stable());
    }

    #[test]
    fn test_bundler_version_prerelease() {
        let version = BundlerVersion {
            number: "7.1.0.beta1".into(),
            prerelease: true,
            yanked: false,
            created_at: None,
            platform: "ruby".into(),
        };

        assert!(version.prerelease);
        assert!(!version.is_stable());
    }

    #[test]
    fn test_bundler_version_yanked() {
        let version = BundlerVersion {
            number: "1.0.0".into(),
            prerelease: false,
            yanked: true,
            created_at: None,
            platform: "ruby".into(),
        };

        assert!(version.yanked);
        assert!(!version.is_stable());
    }

    #[test]
    fn test_bundler_dependency_trait() {
        use deps_core::Dependency;

        let dep = BundlerDependency {
            name: "rails".into(),
            name_range: Range::new(Position::new(1, 5), Position::new(1, 10)),
            version_req: Some("~> 7.0".into()),
            version_range: Some(Range::new(Position::new(1, 14), Position::new(1, 20))),
            group: DependencyGroup::Default,
            source: DependencySource::Registry,
            platforms: vec![],
            require: None,
        };

        assert_eq!(dep.name(), "rails");
        assert_eq!(dep.version_requirement(), Some("~> 7.0"));
    }

    #[test]
    fn test_dependency_info_trait_registry() {
        use deps_core::DependencyInfo;

        let dep = create_test_dependency(DependencySource::Registry);
        assert_eq!(dep.name(), "test_gem");
        assert_eq!(dep.name_range().start.line, 1);
        assert_eq!(dep.version_requirement(), Some("~> 1.0"));
        assert!(dep.version_range().is_some());
        assert!(dep.features().is_empty());
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_info_trait_git() {
        use deps_core::DependencyInfo;

        let dep = create_test_dependency(DependencySource::Git {
            url: "https://github.com/rails/rails".into(),
            branch: Some("main".into()),
            tag: None,
            ref_: Some("abc123".into()),
        });

        match dep.source() {
            deps_core::parser::DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/rails/rails");
                assert_eq!(rev, Some("abc123".to_string()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_info_trait_path() {
        use deps_core::DependencyInfo;

        let dep = create_test_dependency(DependencySource::Path {
            path: "../local_gem".into(),
        });

        match dep.source() {
            deps_core::parser::DependencySource::Path { path } => {
                assert_eq!(path, "../local_gem");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_dependency_info_trait_github() {
        use deps_core::DependencyInfo;

        let dep = create_test_dependency(DependencySource::Github {
            repo: "rails/rails".into(),
            branch: Some("main".into()),
        });

        match dep.source() {
            deps_core::parser::DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/rails/rails");
                assert_eq!(rev, None);
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_info_trait_custom_source() {
        use deps_core::DependencyInfo;

        let dep = create_test_dependency(DependencySource::Source {
            name: "private".into(),
            url: "https://gems.example.com".into(),
        });

        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_trait_as_any() {
        use deps_core::Dependency;

        let dep = create_test_dependency(DependencySource::Registry);
        let any = dep.as_any();
        assert!(any.is::<BundlerDependency>());
        assert!(any.downcast_ref::<BundlerDependency>().is_some());
    }

    #[test]
    fn test_dependency_trait_source_conversions() {
        use deps_core::Dependency;

        let sources = vec![
            DependencySource::Registry,
            DependencySource::Git {
                url: "https://github.com/test/repo".into(),
                branch: None,
                tag: Some("v1.0".into()),
                ref_: None,
            },
            DependencySource::Path {
                path: "./local".into(),
            },
            DependencySource::Github {
                repo: "test/repo".into(),
                branch: None,
            },
            DependencySource::Source {
                name: "custom".into(),
                url: "https://custom.example.com".into(),
            },
        ];

        for source in sources {
            let dep = create_test_dependency(source);
            let _ = dep.source();
        }
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;

        let dep = BundlerDependency {
            name: "test".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            group: DependencyGroup::Default,
            source: DependencySource::Registry,
            platforms: vec![],
            require: None,
        };

        assert_eq!(dep.name(), "test");
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }

    #[test]
    fn test_version_trait_implementation() {
        use deps_core::Version;

        let version = BundlerVersion {
            number: "1.2.3".into(),
            prerelease: false,
            yanked: false,
            created_at: Some("2024-01-01".into()),
            platform: "ruby".into(),
        };

        assert_eq!(version.version_string(), "1.2.3");
        assert!(!version.is_yanked());
        assert!(version.features().is_empty());
        assert!(version.as_any().is::<BundlerVersion>());
    }

    #[test]
    fn test_version_trait_yanked() {
        use deps_core::Version;

        let version = BundlerVersion {
            number: "1.0.0".into(),
            prerelease: false,
            yanked: true,
            created_at: None,
            platform: "ruby".into(),
        };

        assert!(version.is_yanked());
    }

    #[test]
    fn test_metadata_trait_full() {
        use deps_core::Metadata;

        let gem = GemInfo {
            name: "rails".into(),
            info: Some("Full-stack web application framework".into()),
            homepage_uri: Some("https://rubyonrails.org".into()),
            source_code_uri: Some("https://github.com/rails/rails".into()),
            documentation_uri: Some("https://api.rubyonrails.org".into()),
            version: "7.0.8".into(),
            licenses: vec!["MIT".into()],
            authors: Some("DHH".into()),
            downloads: 500_000_000,
        };

        assert_eq!(gem.name(), "rails");
        assert_eq!(
            gem.description(),
            Some("Full-stack web application framework")
        );
        assert_eq!(gem.repository(), Some("https://github.com/rails/rails"));
        assert_eq!(gem.documentation(), Some("https://api.rubyonrails.org"));
        assert_eq!(gem.latest_version(), "7.0.8");
        assert!(gem.as_any().is::<GemInfo>());
    }

    #[test]
    fn test_metadata_trait_minimal() {
        use deps_core::Metadata;

        let gem = GemInfo {
            name: "minimal".into(),
            info: None,
            homepage_uri: None,
            source_code_uri: None,
            documentation_uri: None,
            version: "0.1.0".into(),
            licenses: vec![],
            authors: None,
            downloads: 0,
        };

        assert_eq!(gem.name(), "minimal");
        assert!(gem.description().is_none());
        assert!(gem.repository().is_none());
        assert!(gem.documentation().is_none());
        assert_eq!(gem.latest_version(), "0.1.0");
    }

    #[test]
    fn test_gem_info_fields() {
        let gem = GemInfo {
            name: "test".into(),
            info: Some("Test gem".into()),
            homepage_uri: Some("https://example.com".into()),
            source_code_uri: Some("https://github.com/test/test".into()),
            documentation_uri: Some("https://docs.example.com".into()),
            version: "1.0.0".into(),
            licenses: vec!["MIT".into(), "Apache-2.0".into()],
            authors: Some("Test Author".into()),
            downloads: 1000,
        };

        assert_eq!(gem.licenses.len(), 2);
        assert_eq!(gem.authors, Some("Test Author".into()));
        assert_eq!(gem.downloads, 1000);
    }

    #[test]
    fn test_bundler_dependency_clone() {
        let dep = create_test_dependency(DependencySource::Registry);
        let cloned = dep.clone();
        assert_eq!(dep, cloned);
    }

    #[test]
    fn test_bundler_dependency_debug() {
        let dep = create_test_dependency(DependencySource::Registry);
        let debug_str = format!("{:?}", dep);
        assert!(debug_str.contains("test_gem"));
    }
}

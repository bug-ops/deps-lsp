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

        assert!(matches!(registry, DependencySource::Registry));
        assert!(matches!(git, DependencySource::Git { .. }));
        assert!(matches!(path, DependencySource::Path { .. }));
        assert!(matches!(github, DependencySource::Github { .. }));
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
}

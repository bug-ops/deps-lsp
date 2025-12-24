use std::any::Any;
use std::collections::HashMap;
use tower_lsp::lsp_types::Range;

/// Parsed dependency from Cargo.toml with position tracking.
///
/// Stores all information about a dependency declaration, including its name,
/// version requirement, features, and source positions for LSP operations.
/// Positions are critical for features like hover, completion, and inlay hints.
///
/// # Examples
///
/// ```
/// use deps_cargo::types::{ParsedDependency, DependencySource, DependencySection};
/// use tower_lsp::lsp_types::{Position, Range};
///
/// let dep = ParsedDependency {
///     name: "serde".into(),
///     name_range: Range::new(Position::new(5, 0), Position::new(5, 5)),
///     version_req: Some("1.0".into()),
///     version_range: Some(Range::new(Position::new(5, 9), Position::new(5, 14))),
///     features: vec!["derive".into()],
///     features_range: None,
///     source: DependencySource::Registry,
///     workspace_inherited: false,
///     section: DependencySection::Dependencies,
/// };
///
/// assert_eq!(dep.name, "serde");
/// assert!(matches!(dep.source, DependencySource::Registry));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDependency {
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub features: Vec<String>,
    pub features_range: Option<Range>,
    pub source: DependencySource,
    pub workspace_inherited: bool,
    pub section: DependencySection,
}

/// Source location of a dependency.
///
/// Dependencies can come from the crates.io registry, a Git repository,
/// or a local filesystem path. This affects how the LSP server resolves
/// version information and provides completions.
///
/// # Examples
///
/// ```
/// use deps_cargo::types::DependencySource;
///
/// let registry = DependencySource::Registry;
/// let git = DependencySource::Git {
///     url: "https://github.com/serde-rs/serde".into(),
///     rev: Some("v1.0.0".into()),
/// };
/// let path = DependencySource::Path {
///     path: "../local-crate".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum DependencySource {
    /// Dependency from crates.io registry
    Registry,
    /// Dependency from Git repository
    Git { url: String, rev: Option<String> },
    /// Dependency from local filesystem path
    Path { path: String },
}

/// Section in Cargo.toml where a dependency is declared.
///
/// Cargo.toml has four dependency sections with different purposes:
/// - `[dependencies]`: Runtime dependencies
/// - `[dev-dependencies]`: Test and example dependencies
/// - `[build-dependencies]`: Build script dependencies
/// - `[workspace.dependencies]`: Workspace-wide dependency definitions
///
/// # Examples
///
/// ```
/// use deps_cargo::types::DependencySection;
///
/// let section = DependencySection::Dependencies;
/// assert!(matches!(section, DependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DependencySection {
    /// Runtime dependencies (`[dependencies]`)
    Dependencies,
    /// Development dependencies (`[dev-dependencies]`)
    DevDependencies,
    /// Build script dependencies (`[build-dependencies]`)
    BuildDependencies,
    /// Workspace-wide dependency definitions (`[workspace.dependencies]`)
    WorkspaceDependencies,
}

/// Version information for a crate from crates.io.
///
/// Retrieved from the sparse index at `https://index.crates.io/{cr}/{at}/{crate}`.
/// Contains version number, yanked status, and available feature flags.
///
/// # Examples
///
/// ```
/// use deps_cargo::types::CargoVersion;
/// use std::collections::HashMap;
///
/// let version = CargoVersion {
///     num: "1.0.214".into(),
///     yanked: false,
///     features: {
///         let mut f = HashMap::new();
///         f.insert("derive".into(), vec!["serde_derive".into()]);
///         f
///     },
/// };
///
/// assert!(!version.yanked);
/// assert!(version.features.contains_key("derive"));
/// ```
#[derive(Debug, Clone)]
pub struct CargoVersion {
    pub num: String,
    pub yanked: bool,
    pub features: HashMap<String, Vec<String>>,
}

/// Crate metadata from crates.io search API.
///
/// Contains basic information about a crate for display in completion suggestions.
/// Retrieved from `https://crates.io/api/v1/crates?q={query}`.
///
/// # Examples
///
/// ```
/// use deps_cargo::types::CrateInfo;
///
/// let info = CrateInfo {
///     name: "serde".into(),
///     description: Some("A serialization framework".into()),
///     repository: Some("https://github.com/serde-rs/serde".into()),
///     documentation: Some("https://docs.rs/serde".into()),
///     max_version: "1.0.214".into(),
/// };
///
/// assert_eq!(info.name, "serde");
/// ```
#[derive(Debug, Clone)]
pub struct CrateInfo {
    pub name: String,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub max_version: String,
}

// Trait implementations for deps-core integration

impl deps_core::Dependency for ParsedDependency {
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
            DependencySource::Git { url, rev } => deps_core::parser::DependencySource::Git {
                url: url.clone(),
                rev: rev.clone(),
            },
            DependencySource::Path { path } => {
                deps_core::parser::DependencySource::Path { path: path.clone() }
            }
        }
    }

    fn features(&self) -> &[String] {
        &self.features
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Version for CargoVersion {
    fn version_string(&self) -> &str {
        &self.num
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn is_prerelease(&self) -> bool {
        semver::Version::parse(&self.num)
            .map(|v| !v.pre.is_empty())
            .unwrap_or(false)
    }

    fn features(&self) -> Vec<String> {
        self.features.keys().cloned().collect()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for CrateInfo {
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
        &self.max_version
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_source_variants() {
        let registry = DependencySource::Registry;
        let git = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            rev: Some("main".into()),
        };
        let path = DependencySource::Path {
            path: "../local".into(),
        };

        assert!(matches!(registry, DependencySource::Registry));
        assert!(matches!(git, DependencySource::Git { .. }));
        assert!(matches!(path, DependencySource::Path { .. }));
    }

    #[test]
    fn test_dependency_section_variants() {
        let deps = DependencySection::Dependencies;
        let dev_deps = DependencySection::DevDependencies;
        let build_deps = DependencySection::BuildDependencies;
        let workspace_deps = DependencySection::WorkspaceDependencies;

        assert!(matches!(deps, DependencySection::Dependencies));
        assert!(matches!(dev_deps, DependencySection::DevDependencies));
        assert!(matches!(build_deps, DependencySection::BuildDependencies));
        assert!(matches!(
            workspace_deps,
            DependencySection::WorkspaceDependencies
        ));
    }

    #[test]
    fn test_cargo_version_creation() {
        let version = CargoVersion {
            num: "1.0.0".into(),
            yanked: false,
            features: HashMap::new(),
        };

        assert_eq!(version.num, "1.0.0");
        assert!(!version.yanked);
        assert!(version.features.is_empty());
    }

    #[test]
    fn test_cargo_version_is_prerelease() {
        use deps_core::Version;

        let stable = CargoVersion {
            num: "1.0.0".into(),
            yanked: false,
            features: HashMap::new(),
        };
        assert!(!stable.is_prerelease());

        let alpha = CargoVersion {
            num: "1.0.0-alpha.1".into(),
            yanked: false,
            features: HashMap::new(),
        };
        assert!(alpha.is_prerelease());

        let beta = CargoVersion {
            num: "2.0.0-beta.2".into(),
            yanked: false,
            features: HashMap::new(),
        };
        assert!(beta.is_prerelease());

        let rc = CargoVersion {
            num: "3.0.0-rc.1".into(),
            yanked: false,
            features: HashMap::new(),
        };
        assert!(rc.is_prerelease());
    }
}

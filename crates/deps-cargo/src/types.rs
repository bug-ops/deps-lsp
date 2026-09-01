use std::any::Any;
use std::collections::HashMap;
use tower_lsp_server::ls_types::Range;

pub use deps_core::parser::DependencySource;

/// Parsed dependency from Cargo.toml with position tracking.
///
/// Stores all information about a dependency declaration, including its name,
/// version requirement, features, and source positions for LSP operations.
/// Positions are critical for features like hover, completion, and inlay hints.
///
/// # Examples
///
/// ```
/// use deps_cargo::types::{ParsedDependency, DependencySection};
/// use deps_cargo::DependencySource;
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = ParsedDependency {
///     name: "serde".into(),
///     name_range: Range::new(Position::new(5, 0), Position::new(5, 5)),
///     version_req: Some("1.0".into()),
///     version_range: Some(Range::new(Position::new(5, 9), Position::new(5, 14))),
///     features: vec!["derive".into()],
///     features_range: None,
///     source: DependencySource::Registry,
///     section: DependencySection::Dependencies,
/// };
///
/// assert_eq!(dep.name, "serde");
/// assert!(matches!(dep.source, DependencySource::Registry));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDependency {
    pub name: deps_core::PackageName,
    pub name_range: Range,
    pub version_req: Option<deps_core::VersionReq>,
    pub version_range: Option<Range>,
    pub features: Vec<String>,
    pub features_range: Option<Range>,
    pub source: DependencySource,
    pub section: DependencySection,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// Contains version number, yanked status, available feature flags, and
/// publish timestamp.
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
///     published_at: None,
/// };
///
/// assert!(!version.yanked);
/// assert!(version.features.contains_key("derive"));
/// ```
#[derive(Debug, Clone)]
pub struct CargoVersion {
    pub num: deps_core::ConcreteVersion,
    pub yanked: bool,
    pub features: HashMap<String, Vec<String>>,
    /// Publish timestamp, parsed from the sparse index's `pubtime` field.
    ///
    /// `None` when the index entry omits `pubtime` (older cached entries) or
    /// the value fails to parse as RFC 3339 — degrades gracefully, per
    /// [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
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
///     name: deps_core::PackageName::new("serde"),
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
    pub name: deps_core::PackageName,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub max_version: deps_core::ConcreteVersion,
}

// Trait implementations for deps-core integration

impl deps_core::Dependency for ParsedDependency {
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
        &self.features
    }

    fn features_range(&self) -> Option<Range> {
        self.features_range
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Version for CargoVersion {
    fn version_string(&self) -> &deps_core::ConcreteVersion {
        &self.num
    }

    fn removal_status(&self) -> deps_core::RemovalStatus {
        deps_core::RemovalStatus::from_yanked(self.yanked)
    }

    // crates.io enforces valid semver on publish, so `semver::Version::parse`
    // reliably exposes the `pre` component instead of relying on
    // deps-core's default hyphen-substring heuristic (#322). A parse
    // failure (practically unreachable given that enforcement) is treated
    // as not-prerelease, matching the trait's other implementors.
    fn is_prerelease(&self) -> bool {
        semver::Version::parse(self.num.as_str()).is_ok_and(|v| !v.pre.is_empty())
    }

    fn features(&self) -> Vec<String> {
        self.features.keys().cloned().collect()
    }

    fn published_at(&self) -> Option<deps_core::PublishTime> {
        self.published_at
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for CrateInfo {
    fn name(&self) -> &deps_core::PackageName {
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

    fn latest_version(&self) -> &deps_core::ConcreteVersion {
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
        assert!(matches!(
            DependencySource::Registry,
            DependencySource::Registry
        ));
        assert!(matches!(
            DependencySource::Git {
                url: "u".into(),
                rev: None
            },
            DependencySource::Git { .. }
        ));
        assert!(matches!(
            DependencySource::Path { path: "p".into() },
            DependencySource::Path { .. }
        ));
        assert!(matches!(
            DependencySource::Workspace,
            DependencySource::Workspace
        ));
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
            published_at: None,
        };

        assert_eq!(version.num, "1.0.0");
        assert!(!version.yanked);
        assert!(version.features.is_empty());
        assert!(version.published_at.is_none());
    }

    #[test]
    fn test_cargo_version_is_prerelease() {
        use deps_core::Version;

        let stable = CargoVersion {
            num: "1.0.0".into(),
            yanked: false,
            features: HashMap::new(),
            published_at: None,
        };
        let prerelease = CargoVersion {
            num: "1.0.0-alpha.1".into(),
            yanked: false,
            features: HashMap::new(),
            published_at: None,
        };

        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
        assert!(prerelease.is_prerelease());
        assert!(!prerelease.is_stable());
    }
}

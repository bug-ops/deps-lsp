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
/// ```no_run
/// use deps_cargo::DependencySource;
/// use deps_cargo::parse_cargo_toml;
/// use tower_lsp_server::ls_types::Uri;
///
/// let toml = "[dependencies]\nserde = { version = \"1.0\", features = [\"derive\"] }";
/// let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
/// let result = parse_cargo_toml(toml, &uri).unwrap();
/// let dep = &result.dependencies[0];
///
/// assert_eq!(dep.name, "serde");
/// assert!(matches!(dep.source, DependencySource::Registry));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDependency {
    /// The TOML table key: the local import alias when [`Self::package`] is set,
    /// otherwise the actual crate name. Always the position anchor for
    /// [`Self::name_range`], regardless of renaming.
    pub name: deps_core::PackageName,
    /// Document range of the TOML table key, for hover/diagnostic positioning.
    pub name_range: Range,
    /// Version requirement, if the manifest specifies one.
    pub version_req: Option<deps_core::VersionReq>,
    /// Document range of the version requirement string.
    pub version_range: Option<Range>,
    /// Feature flags requested via `features = [...]`.
    pub features: Vec<String>,
    /// Document range of the `features` array, if present.
    pub features_range: Option<Range>,
    /// Where this dependency resolves from (registry, git, path, etc.).
    pub source: DependencySource,
    /// Which `Cargo.toml` section this dependency was declared under.
    pub section: CargoDependencySection,
    /// The real crate name from an explicit `package = "..."` key
    /// ([renaming dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#renaming-dependencies-in-cargotoml)),
    /// when present. `None` for an ordinary, non-renamed dependency, in which
    /// case [`Self::name`] is both the local alias and the registry name.
    ///
    /// Never set when [`Self::source`] is [`DependencySource::Workspace`]: Cargo
    /// silently discards `package` alongside `workspace = true` (the table key is
    /// the only workspace-inheritance lookup key), so honoring it here would
    /// resolve `Dependency::name()` to a value Cargo itself ignores.
    pub package: Option<deps_core::PackageName>,
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
/// use deps_cargo::types::CargoDependencySection;
///
/// let section = CargoDependencySection::Dependencies;
/// assert!(matches!(section, CargoDependencySection::Dependencies));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoDependencySection {
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
/// let mut features = HashMap::new();
/// features.insert("derive".into(), vec!["serde_derive".into()]);
/// let version = CargoVersion::new("1.0.214".into(), false).with_features(features);
///
/// assert!(!version.yanked);
/// assert!(version.features.contains_key("derive"));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CargoVersion {
    /// The parsed version number.
    pub num: deps_core::ConcreteVersion,
    /// Whether this version has been yanked from crates.io.
    pub yanked: bool,
    /// Available feature flags mapped to the other features/deps they enable.
    pub features: HashMap<String, Vec<String>>,
    /// Publish timestamp, parsed from the sparse index's `pubtime` field.
    ///
    /// `None` when the index entry omits `pubtime` (older cached entries) or
    /// the value fails to parse as RFC 3339 — degrades gracefully, per
    /// [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
}

impl CargoVersion {
    /// Constructs a `CargoVersion` from its required fields, with [`Self::features`] left
    /// empty and [`Self::published_at`] left `None` — chain [`Self::with_features`] and/or
    /// [`Self::with_published_at`] to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Arguments
    ///
    /// * `num` - The parsed version number
    /// * `yanked` - Whether this version has been yanked from crates.io
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cargo::types::CargoVersion;
    ///
    /// let version = CargoVersion::new("1.0.214".into(), false);
    /// assert!(!version.yanked);
    /// ```
    #[must_use]
    pub fn new(num: deps_core::ConcreteVersion, yanked: bool) -> Self {
        Self {
            num,
            yanked,
            features: HashMap::new(),
            published_at: None,
        }
    }

    /// Attaches the available feature flags. See [`Self::features`].
    #[must_use]
    pub fn with_features(mut self, features: HashMap<String, Vec<String>>) -> Self {
        self.features = features;
        self
    }

    /// Attaches the publish timestamp. See [`Self::published_at`].
    #[must_use]
    pub const fn with_published_at(mut self, published_at: deps_core::PublishTime) -> Self {
        self.published_at = Some(published_at);
        self
    }
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
/// let info = CrateInfo::new(deps_core::PackageName::new("serde"), "1.0.214".into())
///     .with_description("A serialization framework")
///     .with_repository("https://github.com/serde-rs/serde")
///     .with_documentation("https://docs.rs/serde");
///
/// assert_eq!(info.name, "serde");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// Crate name.
    pub name: deps_core::PackageName,
    /// Short crate description.
    pub description: Option<String>,
    /// Source repository URL.
    pub repository: Option<String>,
    /// Documentation URL.
    pub documentation: Option<String>,
    /// Latest (highest) published version.
    pub max_version: deps_core::ConcreteVersion,
}

impl CrateInfo {
    /// Constructs a `CrateInfo` from its required fields, with [`Self::description`],
    /// [`Self::repository`], and [`Self::documentation`] left `None` — chain the
    /// corresponding `with_*` setters to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_cargo::types::CrateInfo;
    ///
    /// let info = CrateInfo::new(deps_core::PackageName::new("serde"), "1.0.214".into());
    /// assert_eq!(info.name, "serde");
    /// ```
    #[must_use]
    pub const fn new(
        name: deps_core::PackageName,
        max_version: deps_core::ConcreteVersion,
    ) -> Self {
        Self {
            name,
            description: None,
            repository: None,
            documentation: None,
            max_version,
        }
    }

    /// Attaches a short crate description. See [`Self::description`].
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
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
}

// Trait implementations for deps-core integration

// Implemented by hand rather than via `deps_core::impl_dependency!`: `name()` resolves to
// `package.as_ref().unwrap_or(&self.name)` (the `package = "..."` rename, falling back to the
// TOML table key), not a bare field, and `features()`/`features_range()` return real parsed
// data rather than the trait's empty/`None` defaults — neither is expressible through the
// macro's fixed field set. Mirrors `deps-npm`'s identical direct
// `impl deps_core::Dependency for NpmDependency`.
impl deps_core::Dependency for CargoDependency {
    /// Returns the registry lookup name: [`Self::package`] when this dependency was
    /// renamed via `package = "..."`, otherwise the TOML table key.
    fn name(&self) -> &deps_core::PackageName {
        self.package.as_ref().unwrap_or(&self.name)
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

    use std::assert_matches;

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
        assert_matches!(DependencySource::Workspace, DependencySource::Workspace);
    }

    #[test]
    fn test_dependency_section_variants() {
        let deps = CargoDependencySection::Dependencies;
        let dev_deps = CargoDependencySection::DevDependencies;
        let build_deps = CargoDependencySection::BuildDependencies;
        let workspace_deps = CargoDependencySection::WorkspaceDependencies;

        assert_matches!(deps, CargoDependencySection::Dependencies);
        assert_matches!(dev_deps, CargoDependencySection::DevDependencies);
        assert_matches!(build_deps, CargoDependencySection::BuildDependencies);
        assert_matches!(
            workspace_deps,
            CargoDependencySection::WorkspaceDependencies
        );
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

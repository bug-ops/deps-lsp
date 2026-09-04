use std::any::Any;
use tower_lsp_server::ls_types::Range;

/// Parsed dependency from pyproject.toml with position tracking.
///
/// Stores all information about a Python dependency declaration, including its name,
/// version requirement, extras, environment markers, and source positions for LSP operations.
/// Positions are critical for features like hover, completion, and inlay hints.
///
/// # Examples
///
/// ```
/// use deps_pypi::types::{PypiDependency, PypiDependencySection, PypiDependencySource};
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = PypiDependency {
///     name: "requests".into(),
///     name_range: Range::new(Position::new(5, 4), Position::new(5, 12)),
///     version_req: Some(">=2.28.0,<3.0".into()),
///     version_range: Some(Range::new(Position::new(5, 13), Position::new(5, 27))),
///     extras: vec!["security".into()],
///     extras_range: None,
///     markers: Some("python_full_version >= '3.8'".into()),
///     markers_range: None,
///     section: PypiDependencySection::Dependencies,
///     source: PypiDependencySource::Registry,
/// };
///
/// assert_eq!(dep.name, "requests");
/// assert!(matches!(dep.section, PypiDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PypiDependency {
    /// The package name **as produced by the parse path that created this
    /// dependency** — normalization is non-uniform, not a property callers
    /// can rely on directly:
    ///
    /// - PEP 508 string paths (PEP 621 `[project] dependencies`, PEP 735
    ///   dependency groups, `requirements.txt`) — already PEP 503-normalized,
    ///   because `pep508_rs::PackageName` normalizes at construction.
    /// - Poetry table-key paths (`[tool.poetry.dependencies]`,
    ///   `[tool.poetry.group.*.dependencies]`) — the **verbatim** TOML key,
    ///   unnormalized.
    ///
    /// Callers must therefore never assume a normalized name. Apply
    /// [`crate::name::normalize`] (via
    /// `EcosystemFormatter::normalize_package_name`) at lookup time.
    pub name: deps_core::PackageName,
    /// LSP range of the package name
    pub name_range: Range,
    /// PEP 440 version specifier (e.g., ">=2.28.0,<3.0")
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the version specifier
    pub version_range: Option<Range>,
    /// PEP 508 extras (e.g., ["security", "socks"])
    pub extras: Vec<String>,
    /// LSP range of the extras specification
    pub extras_range: Option<Range>,
    /// PEP 508 environment markers (e.g., "python_full_version >= '3.8'"; `pep508_rs`
    /// canonicalizes `python_version` comparisons to `python_full_version` on serialization)
    pub markers: Option<String>,
    /// LSP range of the markers specification
    pub markers_range: Option<Range>,
    /// Section where this dependency is declared
    pub section: PypiDependencySection,
    /// Source of the dependency (PyPI, Git, Path, URL)
    pub source: PypiDependencySource,
}

/// Section in pyproject.toml where a dependency is declared.
///
/// Python projects use different sections for different types of dependencies:
/// - `[project.dependencies]`: Runtime dependencies (PEP 621)
/// - `[project.optional-dependencies.*]`: Optional dependency groups (PEP 621)
/// - `[tool.poetry.dependencies]`: Runtime dependencies (Poetry)
/// - `[tool.poetry.group.*.dependencies]`: Dependency groups (Poetry)
///
/// # Examples
///
/// ```
/// use deps_pypi::types::PypiDependencySection;
///
/// let section = PypiDependencySection::Dependencies;
/// assert!(matches!(section, PypiDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PypiDependencySection {
    /// PEP 517/518 build system requires (`[build-system.requires]`)
    BuildSystem,
    /// PEP 621 runtime dependencies (`[project.dependencies]`)
    Dependencies,
    /// PEP 621 optional dependency group (`[project.optional-dependencies.{group}]`)
    OptionalDependencies { group: String },
    /// PEP 735 dependency group (`[dependency-groups.{group}]`)
    DependencyGroup { group: String },
    /// Poetry runtime dependencies (`[tool.poetry.dependencies]`)
    PoetryDependencies,
    /// Poetry dependency group (`[tool.poetry.group.{group}.dependencies]`)
    PoetryGroup { group: String },
    /// A line in a `requirements.txt`- or `constraints.txt`-format file (pip's
    /// requirements file format). Both file kinds map to this single variant —
    /// nothing downstream distinguishes a constraint from a requirement.
    Requirements,
}

pub use deps_core::parser::DependencySource as PypiDependencySource;

/// Version information for a package from PyPI.
///
/// Retrieved from the PyPI JSON API at `https://pypi.org/pypi/{package}/json`.
/// Contains version number, yanked status, and prerelease detection.
///
/// # Examples
///
/// ```
/// use deps_pypi::types::PypiVersion;
///
/// let version = PypiVersion {
///     version: "2.28.2".into(),
///     yanked: false,
///     published_at: None,
/// };
///
/// assert!(!version.yanked);
/// assert!(!version.is_prerelease());
/// ```
#[derive(Debug, Clone)]
pub struct PypiVersion {
    /// Version string (PEP 440 compliant)
    pub version: deps_core::ConcreteVersion,
    /// Whether this version has been yanked from PyPI
    pub yanked: bool,
    /// Earliest `upload-time` across this version's release files.
    ///
    /// `None` when no file reports one, or every reported value fails to
    /// parse as RFC 3339 — degrades gracefully, per
    /// [US-003](https://github.com/bug-ops/deps-lsp/issues/145).
    pub published_at: Option<deps_core::PublishTime>,
}

impl PypiVersion {
    /// Check if this version is a prerelease (alpha, beta, rc).
    ///
    /// Uses PEP 440 version parsing for accurate prerelease detection.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_pypi::types::PypiVersion;
    ///
    /// let stable = PypiVersion { version: "1.0.0".into(), yanked: false, published_at: None };
    /// let alpha = PypiVersion { version: "1.0.0a1".into(), yanked: false, published_at: None };
    /// let beta = PypiVersion { version: "1.0.0b2".into(), yanked: false, published_at: None };
    /// let rc = PypiVersion { version: "1.0.0rc1".into(), yanked: false, published_at: None };
    ///
    /// assert!(!stable.is_prerelease());
    /// assert!(alpha.is_prerelease());
    /// assert!(beta.is_prerelease());
    /// assert!(rc.is_prerelease());
    /// ```
    ///
    /// Do not rename or remove this method without updating the
    /// `prerelease:` closure in the `impl_version!` call below, which
    /// delegates to it by name and relies on inherent-beats-trait method
    /// resolution to reach it.
    pub fn is_prerelease(&self) -> bool {
        use pep440_rs::Version;
        use std::str::FromStr;

        Version::from_str(self.version.as_str())
            .map(|v| v.is_pre())
            .unwrap_or(false)
    }
}

// Use macro to implement VersionInfo and Version traits. Without an explicit
// `prerelease:` arm, `impl_version!` would fall back to the trait's default
// hyphen-substring heuristic, which is unreachable-shadowing for `PypiVersion`
// once boxed as `dyn deps_core::Version` — its inherent `is_prerelease` above
// is PEP 440-aware and must be the one actually consulted.
//
// `v.is_prerelease()` below resolves to the inherent method (defined above,
// on the concrete `PypiVersion` type) because inherent methods take priority
// over trait methods for the same receiver — this is deliberate delegation,
// not a mistake. If that inherent method is ever renamed or removed, this
// call would silently rebind to the trait method being defined right here,
// causing unbounded recursion; keep the two in sync.
deps_core::impl_version!(PypiVersion {
    version: version,
    status: |v: &PypiVersion| deps_core::RemovalStatus::from_yanked(v.yanked),
    published_at: published_at,
    prerelease: |v: &PypiVersion| v.is_prerelease(),
});

/// Package metadata from PyPI.
///
/// Contains basic information about a PyPI package for display in completion
/// suggestions. Retrieved from `https://pypi.org/pypi/{package}/json`.
///
/// # Examples
///
/// ```
/// use deps_pypi::types::PypiPackage;
///
/// let pkg = PypiPackage {
///     name: deps_core::PackageName::new("requests"),
///     summary: Some("Python HTTP for Humans.".into()),
///     project_urls: vec![
///         ("Homepage".into(), "https://requests.readthedocs.io".into()),
///         ("Repository".into(), "https://github.com/psf/requests".into()),
///     ],
///     latest_version: "2.28.2".into(),
/// };
///
/// assert_eq!(pkg.name, "requests");
/// ```
#[derive(Debug, Clone)]
pub struct PypiPackage {
    /// Package name (canonical form)
    pub name: deps_core::PackageName,
    /// Short package summary/description
    pub summary: Option<String>,
    /// Project URLs (homepage, repository, documentation, etc.)
    pub project_urls: Vec<(String, String)>,
    /// Latest stable version
    pub latest_version: deps_core::ConcreteVersion,
}

// Implement deps_core traits

impl deps_core::Dependency for PypiDependency {
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
        &self.extras
    }

    fn markers(&self) -> Option<&str> {
        self.markers.as_deref()
    }

    fn markers_range(&self) -> Option<Range> {
        self.markers_range
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for PypiPackage {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.project_urls
            .iter()
            .find(|(key, _)| {
                key.eq_ignore_ascii_case("repository")
                    || key.eq_ignore_ascii_case("source")
                    || key.eq_ignore_ascii_case("code")
            })
            .map(|(_, url)| url.as_str())
    }

    fn documentation(&self) -> Option<&str> {
        self.project_urls
            .iter()
            .find(|(key, _)| {
                key.eq_ignore_ascii_case("documentation")
                    || key.eq_ignore_ascii_case("docs")
                    || key.eq_ignore_ascii_case("homepage")
            })
            .map(|(_, url)| url.as_str())
    }

    fn latest_version(&self) -> &deps_core::ConcreteVersion {
        &self.latest_version
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{Metadata, Version};
    use std::assert_matches;
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_pypi_dependency_creation() {
        let dep = PypiDependency {
            name: "flask".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            version_req: Some(">=3.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 6), Position::new(0, 14))),
            extras: vec!["async".into()],
            extras_range: None,
            markers: Some("python_version>='3.9'".into()),
            markers_range: None,
            section: PypiDependencySection::Dependencies,
            source: PypiDependencySource::Registry,
        };

        assert_eq!(dep.name, "flask");
        assert_eq!(dep.version_req, Some(">=3.0.0".into()));
        assert_eq!(dep.extras, vec!["async"]);
    }

    #[test]
    fn test_pypi_dependency_features_maps_to_extras() {
        use deps_core::Dependency;

        let dep = PypiDependency {
            name: "requests".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            extras: vec!["security".into(), "socks".into()],
            extras_range: None,
            markers: None,
            markers_range: None,
            section: PypiDependencySection::Dependencies,
            source: PypiDependencySource::Registry,
        };

        assert_eq!(
            dep.features(),
            &["security".to_string(), "socks".to_string()]
        );
    }

    #[test]
    fn test_dependency_section_variants() {
        let deps = PypiDependencySection::Dependencies;
        let opt_deps = PypiDependencySection::OptionalDependencies {
            group: "dev".into(),
        };
        let dep_group = PypiDependencySection::DependencyGroup {
            group: "dev".into(),
        };
        let poetry_deps = PypiDependencySection::PoetryDependencies;
        let poetry_group = PypiDependencySection::PoetryGroup {
            group: "test".into(),
        };

        assert_matches!(deps, PypiDependencySection::Dependencies);
        assert_matches!(opt_deps, PypiDependencySection::OptionalDependencies { .. });
        assert_matches!(dep_group, PypiDependencySection::DependencyGroup { .. });
        assert_matches!(poetry_deps, PypiDependencySection::PoetryDependencies);
        assert_matches!(poetry_group, PypiDependencySection::PoetryGroup { .. });
    }

    #[test]
    fn test_dependency_source_variants() {
        let registry = PypiDependencySource::Registry;
        let git = PypiDependencySource::Git {
            url: "https://github.com/user/repo.git".into(),
            rev: Some("main".into()),
        };
        let path = PypiDependencySource::Path {
            path: "../local".into(),
        };
        let url = PypiDependencySource::Url {
            url: "https://example.com/package.whl".into(),
        };

        assert!(registry.is_registry());
        assert_matches!(git, PypiDependencySource::Git { .. });
        assert_matches!(path, PypiDependencySource::Path { .. });
        assert!(!url.is_registry());
    }

    #[test]
    fn test_pypi_version_creation() {
        let version = PypiVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
        };

        assert_eq!(version.version, "1.0.0");
        assert!(!version.yanked);
        assert!(!version.is_prerelease());
    }

    #[test]
    fn test_pypi_version_prerelease_detection() {
        let stable = PypiVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
        };
        let alpha = PypiVersion {
            version: "1.0.0a1".into(),
            yanked: false,
            published_at: None,
        };
        let beta = PypiVersion {
            version: "1.0.0b2".into(),
            yanked: false,
            published_at: None,
        };
        let rc = PypiVersion {
            version: "1.0.0rc1".into(),
            yanked: false,
            published_at: None,
        };

        assert!(!stable.is_prerelease());
        assert!(alpha.is_prerelease());
        assert!(beta.is_prerelease());
        assert!(rc.is_prerelease());
    }

    #[test]
    fn test_pypi_version_prerelease_detection_through_version_trait() {
        // Regression test for #322: `impl_version!` must not shadow the
        // PEP 440-aware inherent `is_prerelease` with the deps-core default
        // hyphen-substring heuristic once boxed as `dyn deps_core::Version`.
        let rc: Box<dyn Version> = Box::new(PypiVersion {
            version: "1.0.0rc1".into(),
            yanked: false,
            published_at: None,
        });
        let stable: Box<dyn Version> = Box::new(PypiVersion {
            version: "1.0.0".into(),
            yanked: false,
            published_at: None,
        });

        assert!(rc.is_prerelease());
        assert!(!rc.is_stable());
        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
    }

    #[test]
    fn test_pypi_version_trait() {
        let version = PypiVersion {
            version: "2.28.2".into(),
            yanked: true,
            published_at: None,
        };

        assert_eq!(version.version_string(), "2.28.2");
        assert!(version.removal_status().blocks_resolution());
    }

    #[test]
    fn test_pypi_package_creation() {
        let pkg = PypiPackage {
            name: "requests".into(),
            summary: Some("Python HTTP for Humans.".into()),
            project_urls: vec![
                ("Homepage".into(), "https://requests.readthedocs.io".into()),
                (
                    "Repository".into(),
                    "https://github.com/psf/requests".into(),
                ),
            ],
            latest_version: "2.28.2".into(),
        };

        assert_eq!(pkg.name, "requests");
        assert_eq!(pkg.latest_version, "2.28.2");
    }

    #[test]
    fn test_pypi_package_metadata_trait() {
        let pkg = PypiPackage {
            name: "flask".into(),
            summary: Some("A micro web framework".into()),
            project_urls: vec![
                (
                    "Documentation".into(),
                    "https://flask.palletsprojects.com/".into(),
                ),
                (
                    "Repository".into(),
                    "https://github.com/pallets/flask".into(),
                ),
            ],
            latest_version: "3.0.0".into(),
        };

        assert_eq!(pkg.name(), "flask");
        assert_eq!(pkg.description(), Some("A micro web framework"));
        assert_eq!(pkg.repository(), Some("https://github.com/pallets/flask"));
        assert_eq!(
            pkg.documentation(),
            Some("https://flask.palletsprojects.com/")
        );
        assert_eq!(pkg.latest_version(), "3.0.0");
    }

    #[test]
    fn test_package_url_fallbacks() {
        let pkg = PypiPackage {
            name: "test".into(),
            summary: None,
            project_urls: vec![
                ("Homepage".into(), "https://example.com".into()),
                ("Source".into(), "https://github.com/test/test".into()),
            ],
            latest_version: "1.0.0".into(),
        };

        // Should find "Source" as fallback for repository
        assert_eq!(pkg.repository(), Some("https://github.com/test/test"));
        // Should find "Homepage" as fallback for documentation
        assert_eq!(pkg.documentation(), Some("https://example.com"));
    }
}

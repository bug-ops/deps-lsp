use tower_lsp::lsp_types::Range;

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
/// use tower_lsp::lsp_types::{Position, Range};
///
/// let dep = PypiDependency {
///     name: "requests".into(),
///     name_range: Range::new(Position::new(5, 4), Position::new(5, 12)),
///     version_req: Some(">=2.28.0,<3.0".into()),
///     version_range: Some(Range::new(Position::new(5, 13), Position::new(5, 27))),
///     extras: vec!["security".into()],
///     extras_range: None,
///     markers: Some("python_version>='3.8'".into()),
///     markers_range: None,
///     section: PypiDependencySection::Dependencies,
///     source: PypiDependencySource::PyPI,
/// };
///
/// assert_eq!(dep.name, "requests");
/// assert!(matches!(dep.section, PypiDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PypiDependency {
    /// Package name (normalized to lowercase with underscores replaced by hyphens)
    pub name: String,
    /// LSP range of the package name
    pub name_range: Range,
    /// PEP 440 version specifier (e.g., ">=2.28.0,<3.0")
    pub version_req: Option<String>,
    /// LSP range of the version specifier
    pub version_range: Option<Range>,
    /// PEP 508 extras (e.g., ["security", "socks"])
    pub extras: Vec<String>,
    /// LSP range of the extras specification
    pub extras_range: Option<Range>,
    /// PEP 508 environment markers (e.g., "python_version>='3.8'")
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
}

/// Source location of a Python dependency.
///
/// Python dependencies can come from PyPI, Git repositories, local paths, or direct URLs.
/// This affects how the LSP server resolves version information and provides completions.
///
/// # Examples
///
/// ```
/// use deps_pypi::types::PypiDependencySource;
///
/// let pypi = PypiDependencySource::PyPI;
/// let git = PypiDependencySource::Git {
///     url: "https://github.com/psf/requests.git".into(),
///     rev: Some("v2.28.0".into()),
/// };
/// let path = PypiDependencySource::Path {
///     path: "../local-package".into(),
/// };
/// let url = PypiDependencySource::Url {
///     url: "https://example.com/package.whl".into(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum PypiDependencySource {
    /// Dependency from PyPI registry
    PyPI,
    /// Dependency from Git repository
    Git { url: String, rev: Option<String> },
    /// Dependency from local filesystem path
    Path { path: String },
    /// Dependency from direct URL (wheel or source archive)
    Url { url: String },
}

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
/// };
///
/// assert!(!version.yanked);
/// assert!(!version.is_prerelease());
/// ```
#[derive(Debug, Clone)]
pub struct PypiVersion {
    /// Version string (PEP 440 compliant)
    pub version: String,
    /// Whether this version has been yanked from PyPI
    pub yanked: bool,
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
    /// let stable = PypiVersion { version: "1.0.0".into(), yanked: false };
    /// let alpha = PypiVersion { version: "1.0.0a1".into(), yanked: false };
    /// let beta = PypiVersion { version: "1.0.0b2".into(), yanked: false };
    /// let rc = PypiVersion { version: "1.0.0rc1".into(), yanked: false };
    ///
    /// assert!(!stable.is_prerelease());
    /// assert!(alpha.is_prerelease());
    /// assert!(beta.is_prerelease());
    /// assert!(rc.is_prerelease());
    /// ```
    pub fn is_prerelease(&self) -> bool {
        use pep440_rs::Version;
        use std::str::FromStr;

        Version::from_str(&self.version)
            .map(|v| v.is_pre())
            .unwrap_or(false)
    }
}

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
///     name: "requests".into(),
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
    pub name: String,
    /// Short package summary/description
    pub summary: Option<String>,
    /// Project URLs (homepage, repository, documentation, etc.)
    pub project_urls: Vec<(String, String)>,
    /// Latest stable version
    pub latest_version: String,
}

// Implement deps_core traits

impl deps_core::VersionInfo for PypiVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }
}

impl deps_core::PackageMetadata for PypiPackage {
    fn name(&self) -> &str {
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

    fn latest_version(&self) -> &str {
        &self.latest_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{PackageMetadata, VersionInfo};
    use tower_lsp::lsp_types::Position;

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
            source: PypiDependencySource::PyPI,
        };

        assert_eq!(dep.name, "flask");
        assert_eq!(dep.version_req, Some(">=3.0.0".into()));
        assert_eq!(dep.extras, vec!["async"]);
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

        assert!(matches!(deps, PypiDependencySection::Dependencies));
        assert!(matches!(
            opt_deps,
            PypiDependencySection::OptionalDependencies { .. }
        ));
        assert!(matches!(
            dep_group,
            PypiDependencySection::DependencyGroup { .. }
        ));
        assert!(matches!(
            poetry_deps,
            PypiDependencySection::PoetryDependencies
        ));
        assert!(matches!(
            poetry_group,
            PypiDependencySection::PoetryGroup { .. }
        ));
    }

    #[test]
    fn test_dependency_source_variants() {
        let pypi = PypiDependencySource::PyPI;
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

        assert!(matches!(pypi, PypiDependencySource::PyPI));
        assert!(matches!(git, PypiDependencySource::Git { .. }));
        assert!(matches!(path, PypiDependencySource::Path { .. }));
        assert!(matches!(url, PypiDependencySource::Url { .. }));
    }

    #[test]
    fn test_pypi_version_creation() {
        let version = PypiVersion {
            version: "1.0.0".into(),
            yanked: false,
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
        };
        let alpha = PypiVersion {
            version: "1.0.0a1".into(),
            yanked: false,
        };
        let beta = PypiVersion {
            version: "1.0.0b2".into(),
            yanked: false,
        };
        let rc = PypiVersion {
            version: "1.0.0rc1".into(),
            yanked: false,
        };

        assert!(!stable.is_prerelease());
        assert!(alpha.is_prerelease());
        assert!(beta.is_prerelease());
        assert!(rc.is_prerelease());
    }

    #[test]
    fn test_pypi_version_info_trait() {
        let version = PypiVersion {
            version: "2.28.2".into(),
            yanked: true,
        };

        assert_eq!(version.version_string(), "2.28.2");
        assert!(version.is_yanked());
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

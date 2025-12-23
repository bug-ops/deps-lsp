use tower_lsp::lsp_types::Range;

/// Parsed dependency from package.json with position tracking.
///
/// Stores all information about a dependency declaration, including its name,
/// version requirement, and source positions for LSP operations.
/// Positions are critical for features like hover, completion, and inlay hints.
///
/// # Examples
///
/// ```
/// use deps_npm::types::{NpmDependency, NpmDependencySection};
/// use tower_lsp::lsp_types::{Position, Range};
///
/// let dep = NpmDependency {
///     name: "express".into(),
///     name_range: Range::new(Position::new(5, 4), Position::new(5, 13)),
///     version_req: Some("^4.18.2".into()),
///     version_range: Some(Range::new(Position::new(5, 16), Position::new(5, 25))),
///     section: NpmDependencySection::Dependencies,
/// };
///
/// assert_eq!(dep.name, "express");
/// assert!(matches!(dep.section, NpmDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NpmDependency {
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub section: NpmDependencySection,
}

// Use macro to implement DependencyInfo and Dependency traits
deps_core::impl_dependency!(NpmDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
});

/// Section in package.json where a dependency is declared.
///
/// npm supports multiple dependency sections:
/// - `dependencies`: Production dependencies
/// - `devDependencies`: Development-only dependencies
/// - `peerDependencies`: Peer dependency requirements
/// - `optionalDependencies`: Optional dependencies (install failures ignored)
///
/// # Examples
///
/// ```
/// use deps_npm::types::NpmDependencySection;
///
/// let section = NpmDependencySection::Dependencies;
/// assert!(matches!(section, NpmDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NpmDependencySection {
    /// Production dependencies (`dependencies`)
    Dependencies,
    /// Development dependencies (`devDependencies`)
    DevDependencies,
    /// Peer dependencies (`peerDependencies`)
    PeerDependencies,
    /// Optional dependencies (`optionalDependencies`)
    OptionalDependencies,
}

/// Version information for an npm package.
///
/// Retrieved from the npm registry API at `https://registry.npmjs.org/{package}`.
/// Contains version number and deprecation status.
///
/// # Examples
///
/// ```
/// use deps_npm::types::NpmVersion;
///
/// let version = NpmVersion {
///     version: "4.18.2".into(),
///     deprecated: false,
/// };
///
/// assert!(!version.deprecated);
/// ```
#[derive(Debug, Clone)]
pub struct NpmVersion {
    pub version: String,
    pub deprecated: bool,
}

// Use macro to implement VersionInfo and Version traits
deps_core::impl_version!(NpmVersion {
    version: version,
    yanked: deprecated,
});

/// Package metadata from npm registry.
///
/// Contains basic information about an npm package for display in completion
/// suggestions. Retrieved from `https://registry.npmjs.org/-/v1/search?text={query}`.
///
/// # Examples
///
/// ```
/// use deps_npm::types::NpmPackage;
///
/// let pkg = NpmPackage {
///     name: "express".into(),
///     description: Some("Fast, unopinionated, minimalist web framework".into()),
///     homepage: Some("http://expressjs.com/".into()),
///     repository: Some("expressjs/express".into()),
///     latest_version: "4.18.2".into(),
/// };
///
/// assert_eq!(pkg.name, "express");
/// ```
#[derive(Debug, Clone)]
pub struct NpmPackage {
    pub name: String,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub latest_version: String,
}

// Use macro to implement PackageMetadata and Metadata traits
deps_core::impl_metadata!(NpmPackage {
    name: name,
    description: description,
    repository: repository,
    documentation: homepage,
    latest_version: latest_version,
});

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{PackageMetadata, VersionInfo};
    use tower_lsp::lsp_types::Position;

    #[test]
    fn test_npm_dependency_creation() {
        let dep = NpmDependency {
            name: "react".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            version_req: Some("^18.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 8), Position::new(0, 16))),
            section: NpmDependencySection::Dependencies,
        };

        assert_eq!(dep.name, "react");
        assert_eq!(dep.version_req, Some("^18.0.0".into()));
    }

    #[test]
    fn test_dependency_section_variants() {
        let deps = NpmDependencySection::Dependencies;
        let dev_deps = NpmDependencySection::DevDependencies;
        let peer_deps = NpmDependencySection::PeerDependencies;
        let opt_deps = NpmDependencySection::OptionalDependencies;

        assert!(matches!(deps, NpmDependencySection::Dependencies));
        assert!(matches!(dev_deps, NpmDependencySection::DevDependencies));
        assert!(matches!(peer_deps, NpmDependencySection::PeerDependencies));
        assert!(matches!(
            opt_deps,
            NpmDependencySection::OptionalDependencies
        ));
    }

    #[test]
    fn test_npm_version_creation() {
        let version = NpmVersion {
            version: "1.0.0".into(),
            deprecated: false,
        };

        assert_eq!(version.version, "1.0.0");
        assert!(!version.deprecated);
    }

    #[test]
    fn test_npm_version_info_trait() {
        let version = NpmVersion {
            version: "2.0.0".into(),
            deprecated: true,
        };

        assert_eq!(version.version_string(), "2.0.0");
        assert!(version.is_yanked());
    }

    #[test]
    fn test_npm_package_creation() {
        let pkg = NpmPackage {
            name: "lodash".into(),
            description: Some("Lodash utility library".into()),
            homepage: Some("https://lodash.com/".into()),
            repository: Some("lodash/lodash".into()),
            latest_version: "4.17.21".into(),
        };

        assert_eq!(pkg.name, "lodash");
        assert_eq!(pkg.latest_version, "4.17.21");
    }

    #[test]
    fn test_npm_package_metadata_trait() {
        let pkg = NpmPackage {
            name: "axios".into(),
            description: Some("Promise based HTTP client".into()),
            homepage: Some("https://axios-http.com".into()),
            repository: Some("axios/axios".into()),
            latest_version: "1.6.0".into(),
        };

        assert_eq!(pkg.name(), "axios");
        assert_eq!(pkg.description(), Some("Promise based HTTP client"));
        assert_eq!(pkg.repository(), Some("axios/axios"));
        assert_eq!(pkg.documentation(), Some("https://axios-http.com"));
        assert_eq!(pkg.latest_version(), "1.6.0");
    }
}

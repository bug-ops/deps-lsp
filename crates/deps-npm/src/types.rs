use tower_lsp_server::ls_types::Range;

use crate::catalog::CatalogOrigin;

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
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = NpmDependency {
///     name: "express".into(),
///     name_range: Range::new(Position::new(5, 4), Position::new(5, 13)),
///     version_req: Some("^4.18.2".into()),
///     version_range: Some(Range::new(Position::new(5, 16), Position::new(5, 25))),
///     section: NpmDependencySection::Dependencies,
///     source: deps_core::parser::DependencySource::Registry,
///     catalog: None,
/// };
///
/// assert_eq!(dep.name, "express");
/// assert!(matches!(dep.section, NpmDependencySection::Dependencies));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmDependency {
    pub name: deps_core::PackageName,
    pub name_range: Range,
    pub version_req: Option<deps_core::VersionReq>,
    pub version_range: Option<Range>,
    pub section: NpmDependencySection,
    /// Resolved by `.npmrc` lookup (spec `032-npm-npmrc-registry-support`) — `Registry`
    /// (the public default) unless a `registry=`/`@scope:registry=` entry applies.
    pub source: deps_core::parser::DependencySource,
    /// `Some` when `version_req` (before/after resolution) came from a pnpm
    /// `catalog:`/`catalog:<name>` specifier (spec `046-pnpm-catalogs`); `None` for every
    /// ordinary literal-range dependency.
    pub catalog: Option<CatalogOrigin>,
}

// Implemented by hand rather than via `deps_core::impl_dependency!`: the macro's `source:
// $source:expr` arm substitutes the expression into a generated `fn source(&self)` body, but
// macro hygiene ties a `self` token written at the call site to the call site's own scope
// (module-level, not a method), not to the generated function's `&self` parameter — so
// `self.source.clone()` cannot be passed through the macro at all. Mirrors `deps-cargo`'s
// identical direct `impl deps_core::Dependency for ParsedDependency`.
impl deps_core::Dependency for NpmDependency {
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

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
///     deprecation: None,
///     published_at: None,
/// };
///
/// assert!(!version.deprecated);
/// ```
#[derive(Debug, Clone)]
pub struct NpmVersion {
    pub version: deps_core::ConcreteVersion,
    pub deprecated: bool,
    /// Package-level deprecation payload (issue #205), derived from the packument's
    /// `deprecated` free-text field. `None` whenever `deprecated` is absent, `null`, or
    /// an all-whitespace string — npm's own convention for "un-deprecating" a package is
    /// republishing with an empty `deprecated` string, so that case must not produce a
    /// dangling, information-free diagnostic (see `deprecation_from_message`). Carries no
    /// `replacement`: npm only ever names a successor in free text, and regex-extracting
    /// a package name from registry-controlled prose to rewrite a manifest is a
    /// typosquatting vector — see `NpmFormatter::supports_package_rename`.
    pub deprecation: Option<deps_core::Deprecation>,
    /// Publish timestamp, populated only when `Registry::get_versions_with` is called with
    /// freshness enabled — derived from the full packument's `time` map, never the
    /// abbreviated packument `get_versions` otherwise uses.
    pub published_at: Option<deps_core::PublishTime>,
}

// Use macro to implement VersionInfo and Version traits. `node_semver`
// reliably exposes npm's own prerelease identifiers instead of falling back
// to deps-core's default hyphen-substring heuristic (#322). The registry
// enforces valid semver on publish, so a parse failure here (treated as
// not-prerelease) is practically unreachable.
deps_core::impl_version!(NpmVersion {
    version: version,
    status: |v: &NpmVersion| deps_core::RemovalStatus::from_advisory(v.deprecated),
    published_at: published_at,
    prerelease: |v: &NpmVersion| {
        node_semver::Version::parse(v.version.as_str()).is_ok_and(|parsed| parsed.is_prerelease())
    },
    deprecation: |v: &NpmVersion| v.deprecation.as_ref(),
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
///     name: deps_core::PackageName::new("express"),
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
    pub name: deps_core::PackageName,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub latest_version: deps_core::ConcreteVersion,
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
    use deps_core::{Metadata, Version};
    use std::assert_matches;
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_npm_dependency_creation() {
        let dep = NpmDependency {
            name: "react".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            version_req: Some("^18.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 8), Position::new(0, 16))),
            section: NpmDependencySection::Dependencies,
            source: deps_core::parser::DependencySource::Registry,
            catalog: None,
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

        assert_matches!(deps, NpmDependencySection::Dependencies);
        assert_matches!(dev_deps, NpmDependencySection::DevDependencies);
        assert_matches!(peer_deps, NpmDependencySection::PeerDependencies);
        assert_matches!(opt_deps, NpmDependencySection::OptionalDependencies);
    }

    #[test]
    fn test_npm_version_creation() {
        let version = NpmVersion {
            version: "1.0.0".into(),
            deprecated: false,
            deprecation: None,
            published_at: None,
        };

        assert_eq!(version.version, "1.0.0");
        assert!(!version.deprecated);
    }

    #[test]
    fn test_npm_version_trait() {
        let version = NpmVersion {
            version: "2.0.0".into(),
            deprecated: true,
            deprecation: None,
            published_at: None,
        };

        assert_eq!(version.version_string(), "2.0.0");
        assert_eq!(
            version.removal_status(),
            deps_core::RemovalStatus::AdvisoryDeprecated
        );
        assert!(!version.removal_status().blocks_resolution());
    }

    /// #205: `Version::deprecation()` reads the dedicated field, independent of the
    /// `removal_status`-driving `deprecated` bool.
    #[test]
    fn test_npm_version_deprecation_accessor() {
        let with_payload = NpmVersion {
            version: "2.0.0".into(),
            deprecated: true,
            deprecation: Some(deps_core::Deprecation {
                reason: Some("use foo".to_string()),
                replacement: None,
            }),
            published_at: None,
        };
        assert_eq!(
            with_payload.deprecation().and_then(|d| d.reason.as_deref()),
            Some("use foo")
        );

        let without_payload = NpmVersion {
            version: "1.0.0".into(),
            deprecated: false,
            deprecation: None,
            published_at: None,
        };
        assert!(without_payload.deprecation().is_none());
    }

    #[test]
    fn test_npm_version_is_prerelease() {
        let stable = NpmVersion {
            version: "18.0.0".into(),
            deprecated: false,
            deprecation: None,
            published_at: None,
        };
        let prerelease = NpmVersion {
            version: "18.0.0-beta.1".into(),
            deprecated: false,
            deprecation: None,
            published_at: None,
        };

        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
        assert!(prerelease.is_prerelease());
        assert!(!prerelease.is_stable());
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

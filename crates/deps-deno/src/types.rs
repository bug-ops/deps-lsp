//! Deno-specific dependency, version, and metadata types.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

/// A parsed Deno import, scheme-qualified (D2).
///
/// `name` is `"jsr:@std/fs"` or `"npm:react"` — never the bare form — since
/// [`crate::registry::DenoRegistry`] can only route a lookup to the right registry if the
/// scheme travels with the name.
///
/// # Examples
///
/// ```
/// use deps_deno::types::{DenoDependency, DenoDependencySection};
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = DenoDependency {
///     name: "jsr:@std/fs".into(),
///     name_range: Range::new(Position::new(2, 4), Position::new(2, 15)),
///     version_req: Some("^1.0".into()),
///     version_range: Some(Range::new(Position::new(2, 17), Position::new(2, 21))),
///     section: DenoDependencySection::Imports,
/// };
///
/// assert_eq!(dep.name, "jsr:@std/fs");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenoDependency {
    /// Scheme-qualified package name (`"jsr:@std/fs"`, `"npm:react"`).
    pub name: deps_core::PackageName,
    /// LSP range of `name` within the manifest, including the `scheme:` prefix.
    pub name_range: Range,
    /// Version requirement, if the specifier carried one (`@1.2`, `@^18`).
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of `version_req` within the manifest, if present.
    pub version_range: Option<Range>,
    /// Which section of the manifest this import was declared in.
    pub section: DenoDependencySection,
}

deps_core::impl_dependency!(DenoDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
});

/// Section of a `deno.json` manifest a dependency was declared in.
///
/// Single-variant today (D8): only the `imports` map is parsed in the MVP — `scopes` and
/// `importMap` are out of scope (spec §1). Kept as an enum rather than a unit struct so a
/// future `Scopes` variant slots in without changing every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenoDependencySection {
    /// The `imports` map.
    Imports,
}

/// A JSR package version, from `https://jsr.io/@{scope}/{pkg}/meta.json`.
///
/// `published_at` is populated directly from the same response `get_versions` already
/// fetches (`meta.json`'s per-version `createdAt`) — unlike npm, no extra request is
/// needed for freshness data (D10).
///
/// # Examples
///
/// ```
/// use deps_deno::types::JsrVersion;
///
/// let version = JsrVersion {
///     version: "1.0.24".into(),
///     yanked: false,
///     published_at: None,
/// };
///
/// assert!(!version.yanked);
/// ```
#[derive(Debug, Clone)]
pub struct JsrVersion {
    /// The version string (e.g. `"1.0.24"`).
    pub version: String,
    /// Whether JSR marked this specific version as yanked.
    pub yanked: bool,
    /// When this version was published, parsed from `meta.json`'s `createdAt`.
    pub published_at: Option<deps_core::PublishTime>,
}

// JSR mandates strict semver, so `node_semver` reliably exposes the
// prerelease identifiers instead of falling back to deps-core's default
// hyphen-substring heuristic (#322). A parse failure here (treated as
// not-prerelease) is practically unreachable given that enforcement.
deps_core::impl_version!(JsrVersion {
    version: version,
    status: |v: &JsrVersion| deps_core::RemovalStatus::from_yanked(v.yanked),
    published_at: published_at,
    prerelease: |v: &JsrVersion| {
        node_semver::Version::parse(&v.version).is_ok_and(|parsed| parsed.is_prerelease())
    },
});

/// A JSR package search result, from `https://api.jsr.io/packages?query=`.
///
/// `name` is already scheme-qualified (`"jsr:@scope/pkg"`, per D3) so a completion item
/// built from it inserts a valid Deno specifier rather than a bare JSR package name.
///
/// # Examples
///
/// ```
/// use deps_deno::types::JsrPackage;
///
/// let pkg = JsrPackage {
///     name: "jsr:@std/fs".into(),
///     description: Some("File system utilities".into()),
///     repository: Some("https://github.com/denoland/std".into()),
///     documentation: None,
///     latest_version: "1.0.24".into(),
/// };
///
/// assert_eq!(pkg.name, "jsr:@std/fs");
/// ```
#[derive(Debug, Clone)]
pub struct JsrPackage {
    /// Scheme-qualified package name (`"jsr:@scope/pkg"`).
    pub name: deps_core::PackageName,
    /// Package description, if JSR returned a non-empty one.
    pub description: Option<String>,
    /// Repository URL, derived from the search response's `githubRepository` field.
    pub repository: Option<String>,
    /// Documentation URL. Always `None` today: JSR's search response carries no separate
    /// documentation link distinct from the package's own JSR page (`package_url`).
    pub documentation: Option<String>,
    /// Latest published version string.
    pub latest_version: String,
}

deps_core::impl_metadata!(JsrPackage {
    name: name,
    description: description,
    repository: repository,
    documentation: documentation,
    latest_version: latest_version,
});

/// Wraps a `Box<dyn Metadata>` returned by `deps_npm::NpmRegistry::search`.
///
/// Re-prefixes its [`name`](deps_core::Metadata::name) with the `npm:` scheme (D3) so a
/// completion item built from it inserts a valid Deno specifier rather than a bare npm
/// package name.
///
/// Needed because `Metadata::name` cannot be mutated in place on a `Box<dyn Metadata>` —
/// this forwards every other method to the wrapped value unchanged.
pub struct DenoMetadata {
    name: deps_core::PackageName,
    inner: Box<dyn deps_core::Metadata>,
}

impl DenoMetadata {
    /// Wraps `inner`, overriding its reported name with the already scheme-qualified
    /// `name`.
    #[must_use]
    pub fn new(name: deps_core::PackageName, inner: Box<dyn deps_core::Metadata>) -> Self {
        Self { name, inner }
    }
}

impl deps_core::Metadata for DenoMetadata {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.inner.description()
    }

    fn repository(&self) -> Option<&str> {
        self.inner.repository()
    }

    fn documentation(&self) -> Option<&str> {
        self.inner.documentation()
    }

    fn latest_version(&self) -> &str {
        self.inner.latest_version()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{Metadata, Version};
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_deno_dependency_creation() {
        let dep = DenoDependency {
            name: "jsr:@std/fs".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(Position::new(0, 13), Position::new(0, 17))),
            section: DenoDependencySection::Imports,
        };

        assert_eq!(dep.name, "jsr:@std/fs");
        assert_eq!(dep.version_req, Some("^1.0".into()));
    }

    #[test]
    fn test_jsr_version_trait() {
        let version = JsrVersion {
            version: "1.0.24".into(),
            yanked: true,
            published_at: None,
        };

        assert_eq!(version.version_string(), "1.0.24");
        assert!(version.removal_status().blocks_resolution());
    }

    #[test]
    fn test_jsr_version_is_prerelease() {
        let stable = JsrVersion {
            version: "1.0.24".into(),
            yanked: false,
            published_at: None,
        };
        let prerelease = JsrVersion {
            version: "1.0.24-rc.1".into(),
            yanked: false,
            published_at: None,
        };

        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
        assert!(prerelease.is_prerelease());
        assert!(!prerelease.is_stable());
    }

    #[test]
    fn test_jsr_package_metadata_trait() {
        let pkg = JsrPackage {
            name: "jsr:@std/fs".into(),
            description: Some("File system utilities".into()),
            repository: Some("https://github.com/denoland/std".into()),
            documentation: None,
            latest_version: "1.0.24".into(),
        };

        assert_eq!(pkg.name(), "jsr:@std/fs");
        assert_eq!(pkg.description(), Some("File system utilities"));
        assert_eq!(pkg.repository(), Some("https://github.com/denoland/std"));
        assert_eq!(pkg.documentation(), None);
        assert_eq!(pkg.latest_version(), "1.0.24");
    }

    #[test]
    fn test_deno_metadata_reprefixes_name_and_forwards_everything_else() {
        struct Inner;
        impl Metadata for Inner {
            fn name(&self) -> &deps_core::PackageName {
                static NAME: std::sync::LazyLock<deps_core::PackageName> =
                    std::sync::LazyLock::new(|| deps_core::PackageName::new("react"));
                &NAME
            }
            fn description(&self) -> Option<&str> {
                Some("A JS library")
            }
            fn repository(&self) -> Option<&str> {
                Some("facebook/react")
            }
            fn documentation(&self) -> Option<&str> {
                Some("https://react.dev")
            }
            fn latest_version(&self) -> &'static str {
                "18.3.1"
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let wrapped = DenoMetadata::new(
            deps_core::PackageName::new("npm:react"),
            Box::new(Inner) as Box<dyn Metadata>,
        );

        assert_eq!(wrapped.name(), "npm:react");
        assert_eq!(wrapped.description(), Some("A JS library"));
        assert_eq!(wrapped.repository(), Some("facebook/react"));
        assert_eq!(wrapped.documentation(), Some("https://react.dev"));
        assert_eq!(wrapped.latest_version(), "18.3.1");
    }
}

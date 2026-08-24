use tower_lsp_server::ls_types::Range;

/// Parsed dependency from composer.json with position tracking.
///
/// Stores all information about a dependency declaration, including its name,
/// version requirement, and source positions for LSP operations.
///
/// # Examples
///
/// ```
/// use deps_composer::types::{ComposerDependency, ComposerSection};
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = ComposerDependency {
///     name: "symfony/console".into(),
///     name_range: Range::new(Position::new(3, 4), Position::new(3, 20)),
///     version_req: Some("^6.0".into()),
///     version_range: Some(Range::new(Position::new(3, 23), Position::new(3, 28))),
///     section: ComposerSection::Require,
/// };
///
/// assert_eq!(dep.name, "symfony/console");
/// assert!(matches!(dep.section, ComposerSection::Require));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerDependency {
    pub name: deps_core::PackageName,
    pub name_range: Range,
    pub version_req: Option<deps_core::VersionReq>,
    pub version_range: Option<Range>,
    pub section: ComposerSection,
}

deps_core::impl_dependency!(ComposerDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
});

/// Section in composer.json where a dependency is declared.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerSection;
///
/// let section = ComposerSection::Require;
/// assert!(matches!(section, ComposerSection::Require));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposerSection {
    /// Production dependencies (`require`)
    Require,
    /// Development dependencies (`require-dev`)
    RequireDev,
}

/// Version information for a Packagist package.
///
/// Retrieved from the Packagist v2 API.
/// Contains version number and abandonment status.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerVersion;
///
/// let version = ComposerVersion {
///     version: "6.0.0".into(),
///     version_normalized: "6.0.0.0".into(),
///     abandoned: false,
///     published_at: None,
/// };
///
/// assert!(!version.abandoned);
/// ```
#[derive(Debug, Clone)]
pub struct ComposerVersion {
    pub version: String,
    pub version_normalized: String,
    pub abandoned: bool,
    /// Publish timestamp, parsed from the p2 entry's own `time` field.
    ///
    /// Taken only from the entry itself, never inherited from a previous
    /// minified entry — the Packagist v2 API's field-inheritance scheme does
    /// not apply to `time`, since inheriting it would attribute one
    /// release's publish date to another.
    pub published_at: Option<deps_core::PublishTime>,
}

/// Whether `s` contains Composer's short `-a`/`-b` stability alias (`-a1`,
/// `-b2`, `-a.1`, or a bare `-a`/`-b`), matching `composer/semver`'s
/// `-?(dev|alpha|a|beta|b|RC|rc|patch|p)(\.?\d+)?` grammar for the short
/// forms.
///
/// Checked directly against the raw `version` rather than relying on
/// Packagist's `version_normalized` field (which expands `-a1` to
/// `-alpha1`, already caught by the default heuristic): that field falls
/// back to `version.clone()` when Packagist omits it, which would silently
/// drop this coverage for any entry missing it (#327 M2).
fn has_short_stability_alias(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'-' && matches!(bytes[i + 1], b'a' | b'b' | b'A' | b'B') {
            let after = i + 2;
            let follows_digit_or_end = bytes.get(after).is_none_or(u8::is_ascii_digit);
            let follows_dot_digit = bytes.get(after) == Some(&b'.')
                && bytes.get(after + 1).is_some_and(u8::is_ascii_digit);
            if follows_digit_or_end || follows_dot_digit {
                return true;
            }
        }
        i += 1;
    }
    false
}

// Packagist versions aren't strict semver, so this layers a Composer-specific
// short-stability-alias check on the raw `version` on top of `deps-core`'s
// default hyphen-substring heuristic instead of relying on it alone, which
// misses that gap (#327 M2). The `version_normalized` check is defense in
// depth, not load-bearing: `has_short_stability_alias` already covers the
// short-alias case directly on `version`. No `dev-` branch-alias check here:
// `expand_minified_versions` (`registry.rs`) already filters every
// `dev-`-prefixed version before a `ComposerVersion` is ever constructed, so
// that case never reaches `is_prerelease()` (#327 M1).
deps_core::impl_version!(ComposerVersion {
    version: version,
    yanked: abandoned,
    published_at: published_at,
    prerelease: |v: &ComposerVersion| {
        deps_core::has_default_prerelease_marker(&v.version)
            || deps_core::has_default_prerelease_marker(&v.version_normalized)
            || has_short_stability_alias(&v.version)
    },
});

/// Package metadata from Packagist search.
///
/// Contains basic information about a Packagist package for display in
/// completion suggestions.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerPackage;
///
/// let pkg = ComposerPackage {
///     name: deps_core::PackageName::new("symfony/console"),
///     description: Some("Symfony Console Component".into()),
///     repository: Some("https://github.com/symfony/console".into()),
///     homepage: Some("https://packagist.org/packages/symfony/console".into()),
///     latest_version: "6.0.0".into(),
/// };
///
/// assert_eq!(pkg.name, "symfony/console");
/// ```
#[derive(Debug, Clone)]
pub struct ComposerPackage {
    pub name: deps_core::PackageName,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub latest_version: String,
}

deps_core::impl_metadata!(ComposerPackage {
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
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_composer_dependency_creation() {
        let dep = ComposerDependency {
            name: "symfony/console".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 15)),
            version_req: Some("^6.0".into()),
            version_range: Some(Range::new(Position::new(0, 18), Position::new(0, 22))),
            section: ComposerSection::Require,
        };

        assert_eq!(dep.name, "symfony/console");
        assert_eq!(dep.version_req, Some("^6.0".into()));
        assert!(matches!(dep.section, ComposerSection::Require));
    }

    #[test]
    fn test_composer_section_variants() {
        assert!(matches!(ComposerSection::Require, ComposerSection::Require));
        assert!(matches!(
            ComposerSection::RequireDev,
            ComposerSection::RequireDev
        ));
    }

    #[test]
    fn test_composer_version_trait() {
        let version = ComposerVersion {
            version: "2.0.0".into(),
            version_normalized: "2.0.0.0".into(),
            abandoned: true,
            published_at: None,
        };

        assert_eq!(version.version_string(), "2.0.0");
        assert!(version.is_yanked());
    }

    #[test]
    fn test_composer_version_short_stability_alias_is_prerelease() {
        // Regression test for #327 M2: Composer's short "-a"/"-b" stability
        // aliases, with `version_normalized` present and already expanded to
        // "-alpha"/"-beta" the way Packagist normally returns it.
        let alpha = ComposerVersion {
            version: "1.0.0-a1".into(),
            version_normalized: "1.0.0.0-alpha1".into(),
            abandoned: false,
            published_at: None,
        };
        let beta = ComposerVersion {
            version: "1.0.0-b1".into(),
            version_normalized: "1.0.0.0-beta1".into(),
            abandoned: false,
            published_at: None,
        };
        assert!(alpha.is_prerelease());
        assert!(beta.is_prerelease());
    }

    #[test]
    fn test_composer_version_short_stability_alias_without_normalized_field() {
        // Regression test for #327 M2: when Packagist omits
        // `version_normalized`, `expand_minified_versions` falls back to
        // `version.clone()` (crates/deps-composer/src/registry.rs), so the
        // short-alias check must not depend on `version_normalized` having
        // been expanded — it must catch the alias directly on `version`.
        for (name, is_alias) in [
            ("1.0.0-a1", true),
            ("1.0.0-b2", true),
            ("1.0.0-a", true),
            ("1.0.0-a.1", true),
            ("1.0.0-alpha1", true), // already caught by the default heuristic
            ("1.0.0-abandoned", false),
            ("1.0.0", false),
        ] {
            let version = ComposerVersion {
                version: name.into(),
                version_normalized: name.into(), // no expansion happened
                abandoned: false,
                published_at: None,
            };
            assert_eq!(
                version.is_prerelease(),
                is_alias,
                "{name} prerelease mismatch"
            );
        }
    }

    #[test]
    fn test_composer_version_stable_is_not_prerelease() {
        let version = ComposerVersion {
            version: "6.0.0".into(),
            version_normalized: "6.0.0.0".into(),
            abandoned: false,
            published_at: None,
        };
        assert!(!version.is_prerelease());
    }

    #[test]
    fn test_composer_package_metadata_trait() {
        let pkg = ComposerPackage {
            name: "monolog/monolog".into(),
            description: Some(
                "Sends your logs to files, sockets, inboxes, databases and various web services"
                    .into(),
            ),
            repository: Some("https://github.com/Seldaek/monolog".into()),
            homepage: Some("https://packagist.org/packages/monolog/monolog".into()),
            latest_version: "3.0.0".into(),
        };

        assert_eq!(pkg.name(), "monolog/monolog");
        assert_eq!(pkg.latest_version(), "3.0.0");
        assert_eq!(pkg.repository(), Some("https://github.com/Seldaek/monolog"));
    }
}

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
    pub version: deps_core::ConcreteVersion,
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

/// Whether `s` contains a Composer stability keyword (`alpha`/`a`, `beta`/`b`, `RC`, `dev`)
/// directly adjacent to a numeric run with no separator (e.g. `1.0.0RC1`, `1.0.0a1`,
/// `1.0.0dev`) — `composer/semver`'s modifier grammar makes the `[._-]?` separator before the
/// keyword optional for every recognized word (matching
/// [`crate::formatter::composer_stability_rank`]'s full word list), not just `alpha`/`beta`/
/// `rc`. The hyphenated forms are already caught by
/// [`deps_core::has_default_prerelease_marker`]'s `-rc`/`-alpha`/`-beta`/`-dev` substring
/// checks and [`has_short_stability_alias`]'s hyphenated `-a`/`-b`.
///
/// Covering only three of the six recognized words here left this classifier disagreeing with
/// [`crate::formatter::composer_version_stability_rank`] on bare separator-less short-alias/
/// `dev` forms (`1.0.0a1`, `1.0.0dev`): the rank function ranks them as prerelease (via the
/// same word list `composer_stability_rank` uses), but this function said "not prerelease" —
/// and since `registry.rs`'s `effective_minimum_stability_rank` uses this function for "does
/// the requirement itself pin a prerelease" while the version-side filter uses the rank
/// function, disagreement meant a pin like `1.0.0a1` could never match its own version — the
/// exact #421 S1 failure mode, reintroduced by the original #424 S3 fix instead of being
/// closed by it (critique S2).
///
/// Checked directly on the raw string rather than relying on a hyphen-inserting
/// `version_normalized` to have expanded it: a requirement string has no `version_normalized`
/// at all, and even for a real [`ComposerVersion`], Packagist supplying `version_normalized`
/// is not guaranteed, so classification must not depend on which of the two happens to run
/// first or be present (#424 S3).
///
/// The keyword may also sit directly after a `.`/`_` separator that is itself digit-adjacent
/// (e.g. `2.6.3.alpha`, a live `api-platform/core` tag) — not just directly after a digit —
/// since `composer_stability_rank`'s companion parser (`split_composer_core_and_suffix`)
/// already strips a leading `.`/`_`/`-` separator before reading the qualifier word, so the
/// rank function sees `2.6.3.alpha` as prerelease while this substring scan previously did
/// not, the same #421 S1 failure mode S2 fixed for the hyphen-less case (#424 critique N3).
/// Deliberately excludes `-`: a hyphen-separated qualifier is already covered by
/// [`deps_core::has_default_prerelease_marker`]/[`has_short_stability_alias`] via a different
/// algorithm, so including it here would only duplicate, not extend, coverage.
fn has_separatorless_stability_keyword(s: &str) -> bool {
    let lower = s.to_lowercase();
    let bytes = lower.as_bytes();
    for keyword in ["alpha", "beta", "rc", "dev", "a", "b"] {
        let mut start = 0;
        while let Some(rel) = lower[start..].find(keyword) {
            let idx = start + rel;
            let preceded_ok = idx > 0
                && (bytes[idx - 1].is_ascii_digit()
                    || (matches!(bytes[idx - 1], b'.' | b'_')
                        && idx > 1
                        && bytes[idx - 2].is_ascii_digit()));
            let after = idx + keyword.len();
            let followed_by_digit_or_end = bytes.get(after).is_none_or(u8::is_ascii_digit);
            let followed_by_dot_digit = bytes.get(after) == Some(&b'.')
                && bytes.get(after + 1).is_some_and(u8::is_ascii_digit);
            if preceded_ok && (followed_by_digit_or_end || followed_by_dot_digit) {
                return true;
            }
            start = idx + 1;
        }
    }
    false
}

/// Whether `s` carries any Composer stability marker: `deps-core`'s default hyphen-substring
/// heuristic (`-alpha`, `-beta`, `-rc`, ...), Composer's short `-a`/`-b` alias (see
/// [`has_short_stability_alias`]), or a separator-less keyword suffix (see
/// [`has_separatorless_stability_keyword`]).
///
/// Shared by [`ComposerVersion`]'s `is_prerelease()` (via `impl_version!` below, applied to a
/// concrete version string) and `registry.rs`'s "is this requirement itself prerelease-bearing"
/// check (applied to a requirement string, e.g. an exact `2.0.0-a1` pin) — both sides must use
/// the same predicate, or a requirement naming a short-alias prerelease would be misclassified
/// as stable while the version it pins is correctly classified as unstable, making it
/// impossible to ever satisfy (#421 S1).
pub(crate) fn is_prerelease_marker(s: &str) -> bool {
    deps_core::has_default_prerelease_marker(s)
        || has_short_stability_alias(s)
        || has_separatorless_stability_keyword(s)
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
    status: |v: &ComposerVersion| deps_core::RemovalStatus::from_advisory(v.abandoned),
    published_at: published_at,
    prerelease: |v: &ComposerVersion| {
        is_prerelease_marker(v.version.as_str())
            || deps_core::has_default_prerelease_marker(&v.version_normalized)
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
    pub latest_version: deps_core::ConcreteVersion,
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
        assert_eq!(
            version.removal_status(),
            deps_core::RemovalStatus::AdvisoryDeprecated
        );
        assert!(!version.removal_status().blocks_resolution());
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

    /// #424 S3: a separator-less stability keyword suffix (`1.0.0RC1`, no hyphen before
    /// `RC`) must be classified as prerelease by the primary `is_prerelease_marker` path
    /// alone — without relying on `version_normalized` to have expanded it.
    #[test]
    fn test_is_prerelease_marker_separatorless_suffix() {
        for (s, expected) in [
            ("1.0.0RC1", true),
            ("2.0.0beta3", true),
            ("2.0.0alpha1", true),
            ("1.0.0-RC1", true), // hyphenated form still caught (existing heuristic)
            ("1.0.0", false),
            ("1.0.0-abandoned", false),
        ] {
            assert_eq!(
                is_prerelease_marker(s),
                expected,
                "{s} prerelease-marker mismatch"
            );
        }
    }

    /// #424 critique S2: the short-alias (`a`/`b`) and `dev` separator-less forms must also
    /// be recognized — not just `alpha`/`beta`/`rc` — or this classifier disagrees with
    /// `composer_version_stability_rank` on exactly these forms (see that function's rank
    /// test `test_is_prerelease_marker_separatorless_suffix_agrees_with_rank` below).
    #[test]
    fn test_is_prerelease_marker_separatorless_short_alias_and_dev() {
        for (s, expected) in [
            ("1.0.0a1", true),
            ("1.0.0b1", true),
            ("1.0.0dev", true),
            ("2.0.0A1", true),
            ("2.0.0B2", true),
        ] {
            assert_eq!(
                is_prerelease_marker(s),
                expected,
                "{s} prerelease-marker mismatch"
            );
        }
    }

    /// #424 critique N3: a dot/underscore-separated qualifier (`2.6.3.alpha`, a live
    /// `api-platform/core` tag; `version_normalized: "2.6.3.0-alpha"`) must also be recognized
    /// — the separator before the keyword need not be a bare digit, since
    /// `split_composer_core_and_suffix` (the rank function's own parser) already strips a
    /// leading `.`/`_`/`-` before reading the qualifier word.
    #[test]
    fn test_is_prerelease_marker_dot_underscore_separated_suffix() {
        for (s, expected) in [
            ("2.6.3.alpha", true),
            ("2.6.3_alpha", true),
            ("2.6.3.beta1", true),
            ("2.6.3_dev", true),
            ("2.6.3.a1", true),
            ("2.6.3_b2", true),
            ("2.6.3.rc1", true),
        ] {
            assert_eq!(
                is_prerelease_marker(s),
                expected,
                "{s} prerelease-marker mismatch"
            );
        }
    }

    /// #424 critique S2/N3: `is_prerelease_marker` (substring-scan classifier, used for
    /// requirement strings) and `composer_version_stability_rank` (anchored-parse classifier,
    /// used for candidate versions) must agree on every grammar-valid bare version-shaped
    /// string — a real generated cross-product, not a hand-picked table, so a future addition
    /// to either classifier's word/separator list that misses the other is actually caught,
    /// not just the handful of shapes someone thought to write down.
    ///
    /// Cross product: word (Composer's full recognized set) × separator (the `[._-]?`
    /// grammar's optional-separator axis, including no separator at all) × `v`/`V` prefix ×
    /// numeric suffix shape = 216 grammar-valid forms. Critique N3's first pass covered only
    /// the `-` and `""` separators (the two that already agreed); this covers all four,
    /// closing the gap on the entire `.`/`_` axis (e.g. the live `api-platform/core` tag
    /// `v2.6.3.alpha`) that the narrower table never exercised.
    #[test]
    fn test_is_prerelease_marker_agrees_with_rank_cross_product() {
        let mut mismatches = Vec::new();
        for word in ["alpha", "beta", "rc", "dev", "a", "b"] {
            for sep in ["-", ".", "_", ""] {
                for prefix in ["", "v", "V"] {
                    for suffix in ["", "1", ".1"] {
                        let s = format!("{prefix}2.6.3{sep}{word}{suffix}");
                        let is_prerelease = is_prerelease_marker(&s);
                        let is_stable_rank = crate::formatter::composer_version_stability_rank(&s)
                            == crate::formatter::COMPOSER_STABLE_RANK;
                        if is_prerelease == is_stable_rank {
                            mismatches.push(s);
                        }
                    }
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} / 216 grammar-valid forms disagree between is_prerelease_marker and \
             composer_version_stability_rank: {mismatches:?}",
            mismatches.len()
        );
    }

    /// #424 S3: a `ComposerVersion` whose `version_normalized` was never hyphen-expanded
    /// (mirrors a Packagist response that returns the separator-less form verbatim in both
    /// fields) must still classify as prerelease via the raw `version` alone.
    #[test]
    fn test_composer_version_separatorless_rc_is_prerelease_without_normalized_expansion() {
        let version = ComposerVersion {
            version: "2.0.0RC1".into(),
            version_normalized: "2.0.0RC1".into(),
            abandoned: false,
            published_at: None,
        };
        assert!(version.is_prerelease());
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

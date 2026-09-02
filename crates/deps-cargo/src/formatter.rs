use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy,
};
use deps_core::parser::DependencySource;
use deps_core::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};

/// Maximum crate name length this diagnostic accepts.
///
/// Deliberately stricter than `sparse::is_safe_crate_name`'s 128-byte cap: that
/// predicate only needs to guarantee a name is safe to splice into a sparse-index
/// URL, while this constant approximates crates.io's actual publish-time limit for
/// the "Invalid package name" diagnostic below — a name between 65 and 128 bytes
/// passes the shared URL-safety check but still correctly fails this diagnostic's
/// length check. Do not "fix" the two caps back into lockstep.
const MAX_NAME_LENGTH: usize = 64;

/// Precise semver `VersionReq` matcher, compiled once per dependency by
/// [`CargoFormatter::compile_requirement`].
struct SemverMatcher(semver::VersionReq);

impl RequirementMatcher for SemverMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        version
            .parse::<semver::Version>()
            .ok()
            .map(|v| self.0.matches(&v))
    }
}

pub struct CargoFormatter;

impl PackageNaming for CargoFormatter {
    /// Validates a crate name against crates.io's naming rules.
    ///
    /// crates.io accepts only non-empty names starting with an ASCII letter or `_`,
    /// followed by ASCII alphanumeric characters plus `-`/`_`, up to `MAX_NAME_LENGTH`
    /// characters. The base charset+non-empty check reuses
    /// `sparse::is_safe_crate_name_charset` — the same predicate
    /// `sparse::is_safe_crate_name` builds on for the sparse-index URL-injection
    /// gate — rather than duplicating it. This method deliberately calls the
    /// charset-only variant, not `is_safe_crate_name` itself: that function also
    /// bundles in a 128-byte URL-safety cap unrelated to crates.io's real naming
    /// rules, which would make a charset-valid name over 128 bytes report the wrong
    /// "invalid characters" reason instead of reaching this method's own
    /// `MAX_NAME_LENGTH` check below. The leading-character rule and
    /// `MAX_NAME_LENGTH` are layered on top here because they are specific to this
    /// diagnostic-accuracy question, not to URL-splicing safety (see
    /// `MAX_NAME_LENGTH`'s doc for why the two length caps intentionally differ). A
    /// name that fails this can never resolve on crates.io, so this override lets
    /// the "Invalid package name" diagnostic (deps-core's
    /// `formatter.validate_package_name` gate) surface the accurate reason instead
    /// of the generic "Unknown package" a registry-side lookup failure produces
    /// (#382).
    ///
    /// The charset check (via `sparse::is_safe_crate_name_charset`) and the
    /// leading-character check both run before the length check, so a name that is
    /// both non-ASCII and longer than `MAX_NAME_LENGTH` chars (e.g. a repeated CJK
    /// name) reports the charset violation rather than a misleading "too long" —
    /// the length in bytes of such a name can exceed the limit even when its
    /// character count does not, and vice versa, so the length check counts
    /// `chars()`, not bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, starts with a digit or
    /// `-`, contains a character outside `[A-Za-z0-9_-]` (for example a non-ASCII
    /// name like `"日本語"`), or exceeds `MAX_NAME_LENGTH` characters.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if !crate::sparse::is_safe_crate_name_charset(name) {
            return Err(InvalidPackageName::new(
                "name must contain only ASCII letters, digits, '-', or '_'",
            ));
        }
        if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return Err(InvalidPackageName::new(
                "name must start with an ASCII letter or '_'",
            ));
        }
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(InvalidPackageName::new(format!(
                "name cannot exceed {MAX_NAME_LENGTH} characters"
            )));
        }
        Ok(())
    }
}

impl PackageRendering for CargoFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::crate_url(name.as_str())
    }

    /// Suppresses the hover heading's crates.io link for any source other than plain
    /// [`DependencySource::Registry`] or a verified crates.io mirror (spec FR-014, F2) — a
    /// genuinely different `AlternateRegistry` resolves against a different index entirely,
    /// so [`Self::package_url`]'s crates.io link would point at an unrelated (or simply
    /// nonexistent) public crate once live version data from the real registry renders
    /// beside it. A mirror's crates.io link stays correct: it is crates.io content, just
    /// fetched elsewhere.
    fn suppress_package_url(&self, source: &DependencySource) -> bool {
        !self.source_is_public_registry_content(source)
    }
}

impl RequirementResolution for CargoFormatter {
    /// Compiles `requirement` via `semver::VersionReq`, the same crate `deps-cargo`'s
    /// registry uses for matching — precise range semantics (`^`, `~`, comparator lists),
    /// unlike the default `version_satisfies_requirement` heuristic this method
    /// deliberately does not reuse (see that method's docs).
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }
}

impl DiagnosticMessages for CargoFormatter {}

impl DiagnosticPolicy for CargoFormatter {
    /// `semver::VersionReq::matches` excludes pre-releases unless `requirement` itself pins
    /// to the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics (#299).
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }
}

impl SourcePolicy for CargoFormatter {
    /// Extends the default (crates.io-only) resolvability to a resolved
    /// [`DependencySource::AlternateRegistry`] too — `CargoRegistry` (the value behind
    /// `CargoEcosystem::registry()`) routes that source to the alternate index's own
    /// [`crate::sparse::SparseIndexClient`], so it is exactly as resolvable as a plain
    /// [`DependencySource::Registry`] dependency, just against a different index (spec
    /// FR-016).
    fn can_resolve_source(&self, source: &DependencySource) -> bool {
        matches!(
            source,
            DependencySource::Registry | DependencySource::AlternateRegistry { .. }
        )
    }

    /// A verified crates.io mirror (`AlternateRegistry { mirrors_crates_io: true, .. }`,
    /// spec plan-1b §1.3, F1/F1b) counts as public-registry content alongside plain
    /// [`DependencySource::Registry`] — Cargo verifies per-version checksum equality
    /// against crates.io for a `[source.crates-io] replace-with` mirror, so its content is
    /// exactly as trustworthy as crates.io's own for OSV scanning and hover-link purposes,
    /// even though the fetch itself goes to the mirror's index, not to crates.io.
    fn source_is_public_registry_content(&self, source: &DependencySource) -> bool {
        matches!(
            source,
            DependencySource::Registry
                | DependencySource::AlternateRegistry {
                    mirrors_crates_io: true,
                    ..
                }
        )
    }
}

impl OsvNaming for CargoFormatter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_is_public_registry_content_plain_registry() {
        let formatter = CargoFormatter;
        assert!(formatter.source_is_public_registry_content(&DependencySource::Registry));
    }

    #[test]
    fn test_source_is_public_registry_content_crates_io_mirror() {
        let formatter = CargoFormatter;
        assert!(formatter.source_is_public_registry_content(
            &DependencySource::AlternateRegistry {
                index: "https://mirror.example".into(),
                mirrors_crates_io: true,
            }
        ));
    }

    #[test]
    fn test_source_is_public_registry_content_non_mirror_alternate_is_false() {
        let formatter = CargoFormatter;
        assert!(!formatter.source_is_public_registry_content(
            &DependencySource::AlternateRegistry {
                index: "https://index.mycorp.dev".into(),
                mirrors_crates_io: false,
            }
        ));
    }

    #[test]
    fn test_suppress_package_url_mirror_not_suppressed() {
        let formatter = CargoFormatter;
        assert!(
            !formatter.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "https://mirror.example".into(),
                mirrors_crates_io: true,
            })
        );
    }

    #[test]
    fn test_suppress_package_url_non_mirror_alternate_suppressed() {
        let formatter = CargoFormatter;
        assert!(
            formatter.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "https://index.mycorp.dev".into(),
                mirrors_crates_io: false,
            })
        );
    }

    #[test]
    fn test_format_version() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.0.214")),
            "1.0.214"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("0.1.0")),
            "0.1.0"
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("serde")),
            "https://crates.io/crates/serde"
        );
        assert_eq!(
            formatter.package_url(&PackageName::new("tokio-util")),
            "https://crates.io/crates/tokio-util"
        );
    }

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let formatter = CargoFormatter;
        for name in [
            "serde",
            "tokio-util",
            "my_crate",
            "a",
            "a".repeat(64).as_str(),
        ] {
            assert!(
                formatter.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    #[test]
    fn test_validate_package_name_rejects_empty() {
        let formatter = CargoFormatter;
        assert!(formatter.validate_package_name("").is_err());
    }

    #[test]
    fn test_validate_package_name_rejects_too_long() {
        let formatter = CargoFormatter;
        let too_long = "a".repeat(65);
        assert!(formatter.validate_package_name(&too_long).is_err());
    }

    /// #382 repro: a non-ASCII crate name must be reported as an invalid package
    /// name, not silently forwarded to the registry as an "Unknown package".
    #[test]
    fn test_validate_package_name_rejects_non_ascii() {
        let formatter = CargoFormatter;
        assert!(formatter.validate_package_name("日本語").is_err());
    }

    #[test]
    fn test_validate_package_name_rejects_disallowed_punctuation() {
        let formatter = CargoFormatter;
        for name in ["serde.rs", "serde/util", "serde@1.0", "serde util"] {
            assert!(
                formatter.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    /// crates.io's first-character rule: a digit or `-` can never lead a real
    /// crate name — same "falls through to Unknown package" bug shape as #382,
    /// on a different invalid-name form.
    #[test]
    fn test_validate_package_name_rejects_leading_digit_or_hyphen() {
        let formatter = CargoFormatter;
        for name in ["1abc", "9serde", "-abc"] {
            assert!(
                formatter.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    /// A leading underscore is explicitly allowed, unlike a leading digit or `-`.
    #[test]
    fn test_validate_package_name_accepts_leading_underscore() {
        let formatter = CargoFormatter;
        assert!(formatter.validate_package_name("_private").is_ok());
    }

    /// The charset check must run before the length check: a non-ASCII name whose
    /// *byte* length exceeds 64 (but character count does not) must report the
    /// charset violation, not a misleading "too long" — and vice versa, the length
    /// check must count `chars()`, not bytes, so it doesn't false-positive here.
    #[test]
    fn test_validate_package_name_long_non_ascii_reports_charset_error() {
        let formatter = CargoFormatter;
        let name = "日".repeat(30); // 30 chars, 90 bytes: over the byte cap, under the char cap
        let err = formatter
            .validate_package_name(&name)
            .expect_err("non-ASCII name must be rejected");
        assert!(
            err.reason().contains("ASCII"),
            "expected a charset error, got: {}",
            err.reason()
        );
    }

    /// Regression: `validate_package_name` must use `sparse::is_safe_crate_name_charset`
    /// (charset only), not `sparse::is_safe_crate_name` (charset + a 128-byte
    /// URL-safety cap unrelated to this diagnostic) — a charset-valid name over 128
    /// bytes must reach this method's own `MAX_NAME_LENGTH` check and report "too
    /// long", not the wrong "invalid characters" reason from the bundled-length
    /// predicate.
    #[test]
    fn test_validate_package_name_over_128_bytes_reports_length_error_not_charset() {
        let formatter = CargoFormatter;
        let name = "a".repeat(130);
        let err = formatter
            .validate_package_name(&name)
            .expect_err("over-length name must be rejected");
        assert!(
            err.reason().contains("exceed"),
            "expected a length error, got: {}",
            err.reason()
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("serde")),
            "serde"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("tokio-util")),
            "tokio-util"
        );
    }

    #[test]
    fn test_default_yanked_message() {
        let formatter = CargoFormatter;
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_version_satisfies_requirement() {
        let formatter = CargoFormatter;

        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2.3"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "^1.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "~1.2"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2"));

        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "2.0.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.3"));
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0"))
            .expect("valid semver requirement must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let formatter = CargoFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("not a semver req"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("not-a-version")),
            None
        );
    }

    /// §3.1 worked example: an ordinary comparator-list requirement, which
    /// `version_satisfies_requirement`'s loose heuristic (no `^`/`~` prefix, three dot
    /// segments so `is_partial_version` is false) incorrectly rejects. The precise
    /// `compile_requirement` matcher must accept it.
    #[test]
    fn test_compile_requirement_comparator_list_satisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0, <2.0"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
    }

    /// §3.3 case: `~1.0.999` and latest `1.0.214` share major/minor, so the loose
    /// `is_same_major_minor`-based heuristic (and the removed `status == Outdated` gate)
    /// would treat this as up to date. The precise matcher must reject it — patch `999`
    /// is not published.
    #[test]
    fn test_compile_requirement_tilde_mistyped_patch_is_unsatisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("~1.0.999"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.0.214")),
            Some(false)
        );
    }
}

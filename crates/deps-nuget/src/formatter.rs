//! Version formatting for the NuGet ecosystem.

use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
};
use deps_core::{ConcreteVersion, InvalidPackageName, PackageName, VersionReq};

/// Maximum package ID length NuGet's client-side `PackageIdValidator` accepts.
const MAX_PACKAGE_ID_LENGTH: usize = 100;

/// Whether `name` matches NuGet's package ID rule (`PackageIdValidator.IdRegex` in
/// NuGet.Client: `^\w+([_.-]\w+)*$`, `\w` restricted to ASCII here): one or more ASCII
/// alphanumeric/`_` "words" separated by single `.` or `-` characters, with no leading,
/// trailing, or consecutive `.`/`-`. `_` is itself a `\w` character in .NET regex, not a
/// separator, so it is treated as ordinary word content — `_foo`/`foo__bar`/a bare `_` are
/// all accepted by NuGet's real validator (confirmed live: `_` is a published package id,
/// nuget.org id `_`, #402 critique M1) but were previously rejected here by splitting on `_`
/// as if it were a separator too.
fn is_valid_nuget_id(name: &str) -> bool {
    name.split(['.', '-'])
        .all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// NuGet interval/floating-pattern matcher, compiled once per dependency by
/// [`NuGetFormatter::compile_requirement`] — the range or floating pattern is parsed once
/// here rather than being re-parsed for every candidate version scanned. Always decidable
/// (`Some`) — matching a candidate against an already-parsed range/pattern has no separate
/// "candidate failed to parse" signal, only "range/pattern failed to parse" (already ruled
/// out by `compile_requirement` before this is constructed).
enum NuGetMatcher {
    Range(crate::version::VersionRange),
    Float(crate::version::FloatPattern),
}

impl RequirementMatcher for NuGetMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Some(match self {
            Self::Range(range) => crate::version::range_contains(version, range),
            Self::Float(pattern) => {
                let parsed = crate::version::ParsedVersion::parse(version);
                crate::version::float_matches(version, &parsed, pattern)
            }
        })
    }
}

pub struct NuGetFormatter;

impl PackageNaming for NuGetFormatter {
    /// Lints `name` against NuGet's own `PackageIdValidator` rule (see
    /// `is_valid_nuget_id`), so a structurally invalid package ID is reported as "Invalid
    /// package name" instead of falling through to a registry lookup and rendering the
    /// generic "Registry lookup failed" diagnostic (#402).
    ///
    /// An unresolved MSBuild property reference (e.g. `<PackageReference
    /// Include="$(MyPackageId)" />`) is checked first and always accepted — the same
    /// unresolvable-variable treatment `requirement_is_unresolved` already gives a
    /// `$(...)`-containing *version* string (#402 critique M2): `name` here is not a
    /// concrete package id at all until MSBuild expands the property, so it has no shape to
    /// validate.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, exceeds 100 characters, or contains
    /// a character outside NuGet's `\w+([_.-]\w+)*` shape.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.contains("$(") {
            return Ok(());
        }
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if name.chars().count() > MAX_PACKAGE_ID_LENGTH {
            return Err(InvalidPackageName::new(format!(
                "name cannot exceed {MAX_PACKAGE_ID_LENGTH} characters"
            )));
        }
        if !is_valid_nuget_id(name) {
            return Err(InvalidPackageName::new(
                "name must be ASCII alphanumeric/'_' words separated by single '.' or '-' characters",
            ));
        }
        Ok(())
    }

    /// NuGet package ids are case-insensitive and every V3 API path segment is lowercased.
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }
}

impl PackageRendering for NuGetFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        // NuGet manifests store plain version text; no prefix/wrapping on insert.
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// FR-011 (issue #523, M1): an `AlternateRegistry` dependency (resolved against a private
    /// `NuGet.Config`-declared feed) must not render nuget.org's package-page link alongside
    /// live private-feed data — a nuget.org link next to that would read as confirmation the
    /// link is real, which is worse than showing no link at all. Delegates to
    /// [`SourcePolicy::source_is_public_registry_content`], which is `true` only for plain
    /// `Registry` (the default) — so this suppresses the link for exactly the sources
    /// [`Self::can_resolve_source`] newly opts into resolving.
    fn suppress_package_url(&self, source: &deps_core::parser::DependencySource) -> bool {
        !self.source_is_public_registry_content(source)
    }
}

impl RequirementResolution for NuGetFormatter {
    /// Overridden because the default npm caret/tilde semantics do not apply to NuGet's
    /// interval-notation ranges (`[1.0,2.0)`) and floating patterns (`1.1.*`).
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        if requirement.contains('*') {
            let versions = [version.to_string()];
            return crate::version::resolve_float(&versions, requirement).is_some();
        }
        crate::version::satisfies(version, requirement)
    }

    /// Overridden because a minimum-only range (a bare `Version="1.0.0"`, or its explicit
    /// open-ended-minimum spellings `[1.0.0,)`/`(1.0.0,)`/`[1.0.0,]`) is a floor under
    /// `PackageReference`/`PackageVersion` semantics, not an auto-following range:
    /// `version_satisfies_requirement` accepts any version `>= 1.0.0`, so delegating to it
    /// here would never flag a floor as outdated. `latest` behind the floor is not
    /// "outdated" either (it would read as a downgrade suggestion), so up to date is
    /// `latest <= floor` here, not `latest == floor`. Exact pins, maximums, bounded ranges,
    /// and floating patterns (`1.1.*`) already express the intended forward-compatibility
    /// window, so those keep the general satisfies check.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        let requirement = requirement.as_str();
        if requirement.contains('*') {
            return self.version_satisfies_requirement(latest, requirement);
        }
        match crate::version::compare_minimum_floor(requirement, latest.as_str()) {
            Some(ordering) => ordering != std::cmp::Ordering::Less,
            None => self.version_satisfies_requirement(latest, requirement),
        }
    }

    /// M3: an unexpanded MSBuild property reference (`$(PropertyName)`) inside a version
    /// string — most commonly `[$(MinVersion),$(MaxVersion))`, which parses to a `Bounded`
    /// interval whose min/max both fall back to `0.0.0` (a fail-safe floor, not an error),
    /// but then rejects every real candidate as out of range. A bare `$(X)` (unbracketed) is
    /// already fail-safe via that same floor fallback and needs no guard; the bracketed form
    /// does not. Mirrors Maven's `${property}` / Gradle's `$var`/`${var}` unresolved-variable
    /// guards.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        requirement.as_str().contains("$(")
    }

    /// Uses [`compile_requirement_unless`] (see that function and
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`] for the shared "undecidable" contract).
    ///
    /// The undecidable predicate rejects a syntactically malformed range or floating pattern
    /// (parsing fails) — without this guard, a malformed requirement string would make
    /// `satisfies`/`resolve_float` return `false` for every candidate, producing a false
    /// "unsatisfiable" verdict instead of correctly suppressing the check.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        let requirement = requirement.as_str();
        if requirement.contains('*') {
            compile_requirement_unless(
                requirement,
                |r| crate::version::parse_float(r).is_none(),
                |r| {
                    NuGetMatcher::Float(
                        crate::version::parse_float(&r).expect("validated by undecidable guard"),
                    )
                },
            )
        } else {
            compile_requirement_unless(
                requirement,
                |r| crate::version::parse_range(r).is_none(),
                |r| {
                    NuGetMatcher::Range(
                        crate::version::parse_range(&r).expect("validated by undecidable guard"),
                    )
                },
            )
        }
    }
}

impl DiagnosticMessages for NuGetFormatter {}

impl DiagnosticPolicy for NuGetFormatter {}

impl SourcePolicy for NuGetFormatter {
    /// FR-011 (issue #523): a NuGet dependency resolved against a private `NuGet.Config`
    /// feed is version-resolvable through `NuGetRegistry`'s alternate-feed chain, not just
    /// the default `Registry`/`AlternateRegistry`-excluding set
    /// [`deps_core::parser::DependencySource::is_version_resolvable`] would otherwise answer.
    /// `source_is_public_registry_content` stays at its default (`Registry` only) — an
    /// `AlternateRegistry` dependency is resolvable but is never treated as public-registry
    /// content for OSV/deps.dev/hover-trust-signal purposes (M3: deliberate privacy
    /// protection, since those signals would otherwise send a private package's name to a
    /// public service by default).
    fn can_resolve_source(&self, source: &deps_core::parser::DependencySource) -> bool {
        matches!(
            source,
            deps_core::parser::DependencySource::Registry
                | deps_core::parser::DependencySource::AlternateRegistry { .. }
        )
    }
}

impl OsvNaming for NuGetFormatter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = NuGetFormatter;
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("13.0.3")),
            "13.0.3"
        );
    }

    #[test]
    fn test_package_url() {
        let f = NuGetFormatter;
        assert_eq!(
            f.package_url(&PackageName::new("Newtonsoft.Json")),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
    }

    #[test]
    fn test_version_satisfies_exact_pin() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "[1.0.0]"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_bare_floor() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "1.0.0"));
    }

    #[test]
    fn test_version_satisfies_floating() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.1.5"), "1.1.*"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "1.1.*"));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_outdated() {
        let f = NuGetFormatter;
        // Bare floors are pins under PackageReference: a newer latest is outdated,
        // even though it satisfies the floor (>= 13.0.3).
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("13.0.3"),
            &ConcreteVersion::new("13.0.4")
        ));
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("13.0.3"),
            &ConcreteVersion::new("14.0.0")
        ));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_matches_latest() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("13.0.3"),
            &ConcreteVersion::new("13.0.3")
        ));
    }

    #[test]
    fn test_is_up_to_date_open_ended_minimum_bracket_forms_outdated() {
        let f = NuGetFormatter;
        // Same floor semantics as a bare version, spelled with explicit interval brackets.
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("[13.0.3,)"),
            &ConcreteVersion::new("13.0.4")
        ));
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("(13.0.3,)"),
            &ConcreteVersion::new("13.0.4")
        ));
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("[13.0.3,]"),
            &ConcreteVersion::new("13.0.4")
        ));
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("[13.0.3,)"),
            &ConcreteVersion::new("13.0.3")
        ));
    }

    #[test]
    fn test_is_up_to_date_floor_ahead_of_latest_is_not_outdated() {
        let f = NuGetFormatter;
        // A floor already ahead of the registry's latest (a preview/prerelease pin, or a
        // latest that regressed) must not render a downgrade suggestion.
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("13.0.5"),
            &ConcreteVersion::new("13.0.4")
        ));
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("9.0.0-preview.5"),
            &ConcreteVersion::new("8.0.11")
        ));
        // A prerelease pin genuinely behind a newer stable release is still outdated.
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("9.0.0-preview.5"),
            &ConcreteVersion::new("9.0.0")
        ));
    }

    #[test]
    fn test_is_up_to_date_exact_pin_and_ranges_keep_satisfies_semantics() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("[13.0.3]"),
            &ConcreteVersion::new("13.0.3")
        ));
        assert!(!f.is_requirement_up_to_date(
            &VersionReq::new("[13.0.3]"),
            &ConcreteVersion::new("14.0.0")
        ));
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("[1.0,2.0)"),
            &ConcreteVersion::new("1.5.0")
        ));
        assert!(
            f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), &ConcreteVersion::new("1.1.5"))
        );
        assert!(
            !f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), &ConcreteVersion::new("1.2.0"))
        );
    }

    #[test]
    fn test_normalize_lowercases() {
        let f = NuGetFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("Newtonsoft.Json")),
            "newtonsoft.json"
        );
    }

    #[test]
    fn test_osv_package_name_preserves_case_unlike_normalize_package_name() {
        // OSV's NuGet ecosystem is case-preserving (`Newtonsoft.Json`, verified
        // live — architecture.md §2), unlike `normalize_package_name`'s
        // lowercase internal lookup key. `osv_package_name` has no override
        // here (the default identity impl is already correct for NuGet), so
        // this test is the regression guard: a future "tidy-up" routing it
        // through `normalize_package_name` would silently zero out NuGet OSV
        // scanning, and this is the test that would catch it (critique #10).
        use deps_core::Dependency;
        use deps_core::parser::DependencySource;
        use tower_lsp_server::ls_types::{Position, Range};

        let dep = crate::types::NuGetDependency {
            name: "Newtonsoft.Json".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_requirement: Some("12.0.1".into()),
            version_range: None,
            source: DependencySource::Registry,
        };
        assert_eq!(dep.source(), DependencySource::Registry);

        let f = NuGetFormatter;
        assert_eq!(
            f.osv_package_name(&dep),
            Some("Newtonsoft.Json".to_string())
        );
        assert_ne!(
            f.osv_package_name(&dep).unwrap(),
            f.normalize_package_name(&dep.name)
        );
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_own_parser() {
        // Critic S2 gate: `osv_version_to_native` is identity for NuGet, so
        // the version it hands to `format_version_for_text_edit` must
        // itself satisfy the requirement text that edit produces.
        let f = NuGetFormatter;
        let osv_version = "12.0.1";
        let native = f.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let native = ConcreteVersion::new(native);
        let edit_text = f.format_version_for_text_edit(&native);
        assert!(f.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_compile_requirement_exact_pin_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[13.0.3]"))
            .expect("well-formed exact pin must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("13.0.3")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("13.0.4")),
            Some(false)
        );
    }

    #[test]
    fn test_compile_requirement_range_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .expect("well-formed range must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_floating_pattern_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("1.1.*"))
            .expect("well-formed floating pattern must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.1.5")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.2.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_bare_floor_satisfiable() {
        // A bare version is a minimum-floor requirement under `satisfies` (unlike
        // `is_requirement_up_to_date`'s floor-pin override) — any version `>= floor` counts
        // as a match for the unsatisfiable check.
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("1.0.0"))
            .expect("a bare version is a well-formed minimum floor");
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("0.9.0")), Some(false));
    }

    /// The malformed-requirement guard this formatter's `compile_requirement` adds — the
    /// same class of fix Maven/Gradle carry, but previously untested for NuGet.
    #[test]
    fn test_compile_requirement_malformed_range_returns_none() {
        let f = NuGetFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_malformed_floating_pattern_returns_none() {
        let f = NuGetFormatter;
        // Not a valid interval (contains '*') and not a valid float pattern either
        // (`resolve_float`'s grammar requires a trailing `.*`/`*` segment).
        assert!(f.compile_requirement(&VersionReq::new("1.*.0")).is_none());
    }

    /// M3: a bracketed MSBuild property reference parses as a `Bounded` 0.0.0-0.0.0
    /// interval that rejects every real candidate — must be treated as unresolved, not
    /// checked against `available`.
    #[test]
    fn test_requirement_is_unresolved_bracketed_msbuild_property() {
        let f = NuGetFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("[$(MinVersion),$(MaxVersion))")));
    }

    #[test]
    fn test_requirement_is_unresolved_false_for_ordinary_requirements() {
        let f = NuGetFormatter;
        assert!(!f.requirement_is_unresolved(&VersionReq::new("13.0.3")));
        assert!(!f.requirement_is_unresolved(&VersionReq::new("[1.0,2.0)")));
    }

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let f = NuGetFormatter;
        for name in ["Newtonsoft.Json", "Microsoft.Extensions.Logging", "moq"] {
            assert!(
                f.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402: a structurally invalid NuGet package ID must be reported as an invalid package
    /// name, not forwarded to the registry lookup that produces the misleading generic
    /// diagnostic.
    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let f = NuGetFormatter;
        for name in ["", ".Json", "Json.", "New..Json", "New Json", "日本語"] {
            assert!(
                f.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    /// #402 critique M1: `_` is a `\w` character in NuGet's real `PackageIdValidator.IdRegex`,
    /// not a separator, so a leading/doubled/bare underscore is accepted (confirmed live:
    /// nuget.org publishes a package with id `_`).
    #[test]
    fn test_validate_package_name_accepts_underscore_as_word_character() {
        let f = NuGetFormatter;
        for name in ["_foo", "foo__bar", "_", "foo_bar"] {
            assert!(
                f.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402 critique M2: an unexpanded MSBuild property reference in `Include` (e.g.
    /// `<PackageReference Include="$(MyPackageId)" />`) is not yet a concrete package id and
    /// must not be flagged as an invalid package name.
    #[test]
    fn test_validate_package_name_accepts_unresolved_msbuild_property() {
        let f = NuGetFormatter;
        assert!(f.validate_package_name("$(MyPackageId)").is_ok());
    }

    #[test]
    fn test_validate_package_name_rejects_too_long() {
        let f = NuGetFormatter;
        let too_long = "a".repeat(101);
        assert!(f.validate_package_name(&too_long).is_err());
    }

    // --- SourcePolicy / suppress_package_url (issue #523, M1/FR-011) ---

    #[test]
    fn test_can_resolve_source_includes_alternate_registry() {
        use deps_core::parser::DependencySource;

        let f = NuGetFormatter;
        assert!(f.can_resolve_source(&DependencySource::Registry));
        assert!(f.can_resolve_source(&DependencySource::AlternateRegistry {
            index: "nuget-chain:0".to_string(),
            mirrors_crates_io: false,
        }));
        assert!(!f.can_resolve_source(&DependencySource::CustomRegistry {
            url: "unresolved".to_string(),
        }));
    }

    #[test]
    fn test_suppress_package_url_only_for_non_registry_source() {
        use deps_core::parser::DependencySource;

        let f = NuGetFormatter;
        assert!(!f.suppress_package_url(&DependencySource::Registry));
        assert!(
            f.suppress_package_url(&DependencySource::AlternateRegistry {
                index: "nuget-chain:0".to_string(),
                mirrors_crates_io: false,
            })
        );
    }
}

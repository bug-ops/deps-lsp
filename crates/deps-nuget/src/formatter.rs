//! Version formatting for the NuGet ecosystem.

use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher, compile_requirement_unless};
use deps_core::{PackageName, VersionReq};

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
    fn matches(&self, version: &str) -> Option<bool> {
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

impl EcosystemFormatter for NuGetFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // NuGet manifests store plain version text; no prefix/wrapping on insert.
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// Overridden because the default npm caret/tilde semantics do not apply to NuGet's
    /// interval-notation ranges (`[1.0,2.0)`) and floating patterns (`1.1.*`).
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        if requirement.contains('*') {
            let versions = [version.to_string()];
            return crate::version::resolve_float(&versions, requirement).is_some();
        }
        crate::version::satisfies(version, requirement)
    }

    /// NuGet package ids are case-insensitive and every V3 API path segment is lowercased.
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
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
    fn is_requirement_up_to_date(&self, requirement: &VersionReq, latest: &str) -> bool {
        let requirement = requirement.as_str();
        if requirement.contains('*') {
            return self.version_satisfies_requirement(latest, requirement);
        }
        match crate::version::compare_minimum_floor(requirement, latest) {
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
    /// [`EcosystemFormatter::compile_requirement`] for the shared "undecidable" contract).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = NuGetFormatter;
        assert_eq!(f.format_version_for_text_edit("13.0.3"), "13.0.3");
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
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_bare_floor() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("2.0.0", "1.0.0"));
        assert!(!f.version_satisfies_requirement("0.9.0", "1.0.0"));
    }

    #[test]
    fn test_version_satisfies_floating() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("1.1.5", "1.1.*"));
        assert!(!f.version_satisfies_requirement("1.2.0", "1.1.*"));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_outdated() {
        let f = NuGetFormatter;
        // Bare floors are pins under PackageReference: a newer latest is outdated,
        // even though it satisfies the floor (>= 13.0.3).
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "14.0.0"));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_matches_latest() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "13.0.3"));
    }

    #[test]
    fn test_is_up_to_date_open_ended_minimum_bracket_forms_outdated() {
        let f = NuGetFormatter;
        // Same floor semantics as a bare version, spelled with explicit interval brackets.
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,)"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("(13.0.3,)"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,]"), "13.0.4"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,)"), "13.0.3"));
    }

    #[test]
    fn test_is_up_to_date_floor_ahead_of_latest_is_not_outdated() {
        let f = NuGetFormatter;
        // A floor already ahead of the registry's latest (a preview/prerelease pin, or a
        // latest that regressed) must not render a downgrade suggestion.
        assert!(f.is_requirement_up_to_date(&VersionReq::new("13.0.5"), "13.0.4"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("9.0.0-preview.5"), "8.0.11"));
        // A prerelease pin genuinely behind a newer stable release is still outdated.
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("9.0.0-preview.5"), "9.0.0"));
    }

    #[test]
    fn test_is_up_to_date_exact_pin_and_ranges_keep_satisfies_semantics() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[13.0.3]"), "13.0.3"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3]"), "14.0.0"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[1.0,2.0)"), "1.5.0"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), "1.1.5"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), "1.2.0"));
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
        let edit_text = f.format_version_for_text_edit(&native);
        assert!(f.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_compile_requirement_exact_pin_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[13.0.3]"))
            .expect("well-formed exact pin must compile");
        assert_eq!(matcher.matches("13.0.3"), Some(true));
        assert_eq!(matcher.matches("13.0.4"), Some(false));
    }

    #[test]
    fn test_compile_requirement_range_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .expect("well-formed range must compile");
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_floating_pattern_satisfiable() {
        let f = NuGetFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("1.1.*"))
            .expect("well-formed floating pattern must compile");
        assert_eq!(matcher.matches("1.1.5"), Some(true));
        assert_eq!(matcher.matches("1.2.0"), Some(false));
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
        assert_eq!(matcher.matches("2.0.0"), Some(true));
        assert_eq!(matcher.matches("0.9.0"), Some(false));
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
}

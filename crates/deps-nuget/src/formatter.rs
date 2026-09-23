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

/// [`EcosystemFormatter`](deps_core::lsp_helpers::EcosystemFormatter) implementation for NuGet.
pub struct NuGetFormatter;

impl PackageNaming for NuGetFormatter {
    /// Lints `name` against NuGet's own `PackageIdValidator` rule (see
    /// `is_valid_nuget_id`), so a structurally invalid package ID is reported as "Invalid
    /// package name" instead of falling through to a registry lookup and rendering the
    /// generic "Registry lookup failed" diagnostic (#402).
    ///
    /// An unresolved MSBuild reference (e.g. `<PackageReference Include="$(MyPackageId)" />`,
    /// `Include="%(Identity)"`, or `Include="@(SomeItems)"`) is checked first and always
    /// accepted — the same unresolvable-reference treatment `requirement_is_unresolved` gives
    /// an MSBuild-reference-containing *version* string (#402 critique M2, extended to `%(`/
    /// `@(` by #1355's code-review follow-up): `name` here is not a concrete package id at all
    /// until MSBuild expands the reference, so it has no shape to validate — without this
    /// guard, `%(`/`@(` fell through to `is_valid_nuget_id` and rendered an incorrect
    /// "Invalid package name" diagnostic instead of being silently skipped.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, exceeds 100 characters, or contains
    /// a character outside NuGet's `\w+([_.-]\w+)*` shape.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if crate::parser::is_msbuild_reference(name) {
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

    /// Issue #1347 hardening: an unexpanded MSBuild reference (`$(SomeProperty)`,
    /// `%(MetadataName)`, or `@(ItemList)`) in `current` leaves `current` unchanged instead of
    /// substituting `version`, so hardcoding a literal version over a centrally-managed
    /// reference is structurally impossible even if a future caller reaches this method with
    /// such text. Returning `current` verbatim trips the pre-existing textual no-op guards in
    /// `deps_core::edit::collect_update_candidates`/`plan_vulnerability_fix`.
    ///
    /// Currently defense-in-depth only, not a fix for a reproducible defect: `crate::parser`
    /// already degrades every MSBuild-reference-containing manifest shape to
    /// `version_requirement: None` before either the LSP code-action path or `deps-cli` ever
    /// reaches this method (verified across `.csproj` attribute/child-element form,
    /// `Directory.Packages.props`, `packages.config`, and the bracketed `[$(Min),$(Max))`
    /// form — see `parser::test_unresolved_msbuild_property_degrades_to_none`), so `current`
    /// never actually contains one of these references in production today. This guards
    /// against that parser invariant ever relaxing, at negligible cost. Uses the same
    /// `crate::parser::is_msbuild_reference` predicate as `requirement_is_unresolved` and the
    /// parser's own degrade guards, for consistency (#1355).
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        if crate::parser::is_msbuild_reference(current) {
            return current.to_string();
        }
        self.format_version_for_text_edit(version)
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }
}

impl RequirementResolution for NuGetFormatter {
    /// Overridden because the default npm caret/tilde semantics do not apply to NuGet's
    /// interval-notation ranges (`[1.0,2.0)`) and floating patterns (`1.1.*`).
    ///
    /// Issue #1347 hardening: an unresolved requirement (see
    /// [`Self::requirement_is_unresolved`]) returns `true` (treated as satisfied) rather than
    /// falling into `crate::version::satisfies`, which would otherwise coerce it to a
    /// `0.0.0`-shaped floor matching almost any version — mirrors `MavenFormatter`'s identical
    /// "skip comparison" precedent for its own unresolved-property case, and is what
    /// `deps_core::lsp_helpers::in_use_version`'s `version_matches_requirement` (its
    /// `compile_requirement`-`None` fallback) calls this method for.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        if self.requirement_is_unresolved(&VersionReq::new(requirement)) {
            return true;
        }
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
    ///
    /// Issue #1347 hardening: an unresolved requirement (see
    /// [`Self::requirement_is_unresolved`]) returns `true` (treated as up to date) before
    /// reaching `crate::version::compare_minimum_floor`, which would otherwise coerce it to a
    /// `0.0.0`-shaped floor that every `latest` compares `>=` against — the same
    /// false-"satisfied" coercion [`Self::version_satisfies_requirement`]'s guard above
    /// prevents, needed separately here since this floor branch never calls that method.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        if self.requirement_is_unresolved(requirement) {
            return true;
        }
        let requirement = requirement.as_str();
        if requirement.contains('*') {
            return self.version_satisfies_requirement(latest, requirement);
        }
        match crate::version::compare_minimum_floor(requirement, latest.as_str()) {
            Some(ordering) => ordering != std::cmp::Ordering::Less,
            None => self.version_satisfies_requirement(latest, requirement),
        }
    }

    /// M3: an unexpanded MSBuild reference (`$(PropertyName)`, `%(MetadataName)`, or
    /// `@(ItemList)`) inside a version string — most commonly `[$(MinVersion),$(MaxVersion))`.
    /// `crate::version::parse_range` rejects the bracketed `$(...)` form outright (#821:
    /// its parentheses trip the shared grammar's nested-bracket guard), which
    /// `compile_requirement` alone would already treat as undecidable — but without this
    /// guard, `requirement_status` would classify it as a generic malformed requirement
    /// instead of the more specific `Unresolved` status, losing the "not yet expanded, skip
    /// the check" diagnostic distinction. A bare `$(X)`/`%(X)`/`@(X)` (unbracketed) has no
    /// such bracket to trip a guard and needs this classification too — without it, a bare
    /// `%(Version)`/`@(ItemList)` parses as a bogus bare-floor version and can plan an
    /// incorrect rewrite edit, offer completions, or render a diagnostic (#1355). Uses the
    /// same `crate::parser::is_msbuild_reference` predicate as the parser's own degrade
    /// guards, so a reference recognized at parse time is also recognized here.
    /// Mirrors Maven's `${property}` / Gradle's `$var`/`${var}` unresolved-variable guards.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        crate::parser::is_msbuild_reference(requirement.as_str())
    }

    /// #1370: NuGet has no separate "concrete but undecidable ref" case
    /// [`Self::requirement_is_unresolved`] would need to stay broader than this — an
    /// unexpanded MSBuild reference is the only unresolved shape NuGet has, so both
    /// predicates key off the same `crate::parser::is_msbuild_reference` detector.
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        crate::parser::is_msbuild_reference(requirement.as_str())
    }

    /// Uses [`compile_requirement_unless`] (see that function and
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`] for the shared "undecidable" contract).
    ///
    /// The undecidable predicate rejects a syntactically malformed range or floating pattern
    /// (parsing fails) — without this guard, a malformed requirement string would make
    /// `satisfies`/`resolve_float` return `false` for every candidate, producing a false
    /// "unsatisfiable" verdict instead of correctly suppressing the check.
    ///
    /// Issue #1347 hardening: a bare (unbracketed) `$(SomeProperty)` reference is rejected
    /// outright first, before the undecidable-predicate dispatch below — unlike the bracketed
    /// `[$(Min),$(Max))` form, it has no nested-bracket shape for `parse_range` to trip on
    /// (see [`Self::requirement_is_unresolved`]'s doc), so without this explicit check it
    /// would parse as an ordinary `VersionRange::Minimum` floor and this method would
    /// decisively (and wrongly) report every version as satisfying it. Not a fix for a
    /// reproducible defect, though: `crate::parser` already degrades this input to
    /// `version_requirement: None` before it ever reaches a `VersionReq` this method is called
    /// with (see [`Self::format_version_replacing`]'s doc for the full unreachability
    /// argument), so this guard is defense-in-depth, consistent with the parser's own treatment
    /// of the same input as "no requirement" rather than a real constraint.
    // `compile_requirement_unless`'s contract only invokes the build closure when the
    // undecidable predicate returned `false`, i.e. parsing already succeeded.
    #[allow(clippy::expect_used)]
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        if self.requirement_is_unresolved(requirement) {
            return None;
        }
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

    /// Overridden for the same reason as [`Self::is_requirement_up_to_date`]: a bare or
    /// explicit open-ended-minimum requirement (`1.0.0`, `[1.0.0,)`) is a floor NuGet resolves
    /// to its *lowest* admissible member, not an auto-following range — the base default
    /// (`compile_requirement(..).matches(target)`, true for any version at or above the
    /// floor) would wrongly say "no edit needed" for exactly the shape that needs one, since
    /// leaving the manifest unedited keeps restoring the vulnerable floor version (#1344 C1).
    /// Every other shape (exact pins, bounded/maximum ranges, floating patterns like `1.1.*`)
    /// already expresses a genuine forward-compatibility window, so those keep the base
    /// default via `compile_requirement`.
    fn requirement_already_resolves_to(
        &self,
        requirement: &VersionReq,
        target: &ConcreteVersion,
    ) -> bool {
        let requirement_str = requirement.as_str();
        let is_floor = !requirement_str.contains('*')
            && crate::version::compare_minimum_floor(requirement_str, target.as_str()).is_some();
        if is_floor {
            return false;
        }
        self.compile_requirement(requirement)
            .is_some_and(|matcher| matcher.matches(target) == Some(true))
    }
}

impl DiagnosticMessages for NuGetFormatter {}

impl DiagnosticPolicy for NuGetFormatter {}

impl SourcePolicy for NuGetFormatter {
    /// FR-011 (issue #523): a NuGet dependency resolved against a private `NuGet.Config`
    /// feed is version-resolvable through `NuGetRegistry`'s alternate-feed chain, so widens
    /// [`SourcePolicy::can_resolve_source`] accordingly. `source_is_public_registry_content`
    /// stays at its default (`Registry` only) — an `AlternateRegistry` dependency is
    /// resolvable but is never treated as public-registry content for OSV/deps.dev/hover-
    /// trust-signal purposes (M3: deliberate privacy protection, since those signals would
    /// otherwise send a private package's name to a public service by default).
    fn resolves_alternate_registry(&self) -> bool {
        true
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

    // #758: exact-value `EcosystemFormatter` conformance, replacing
    // test_package_url/test_version_satisfies_exact_pin/test_version_satisfies_bare_floor/
    // test_version_satisfies_floating and the accepts/rejects halves of
    // test_validate_package_name_accepts_valid_names/
    // test_validate_package_name_accepts_underscore_as_word_character/
    // test_validate_package_name_accepts_unresolved_msbuild_property/
    // test_validate_package_name_rejects_invalid_names. Does not cover
    // `is_requirement_up_to_date` (a distinct method from `version_satisfies_requirement`) or
    // the non-literal `test_validate_package_name_rejects_too_long`, which stay hand-written.
    deps_core::formatter_conformance! {
        mod nuget_formatter_conformance;
        build: NuGetFormatter;
        package_url: { "Newtonsoft.Json" => "https://www.nuget.org/packages/Newtonsoft.Json" };
        accepts: [
            "Newtonsoft.Json", "Microsoft.Extensions.Logging", "moq",
            "_foo", "foo__bar", "_", "foo_bar", "$(MyPackageId)", "%(Identity)", "@(SomeItems)",
        ];
        rejects: [ "", ".Json", "Json.", "New..Json", "New Json", "日本語" ];
        version_roundtrip: [
            "1.0.0", "[1.0.0]" => true,
            "1.0.1", "[1.0.0]" => false,
            "2.0.0", "1.0.0" => true,
            "0.9.0", "1.0.0" => false,
            "1.1.5", "1.1.*" => true,
            "1.2.0", "1.1.*" => false
        ];
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

    /// Code-review finding 1: `is_requirement_up_to_date`'s `compare_minimum_floor` branch
    /// never calls `version_satisfies_requirement`, so it needs its own unresolved-requirement
    /// guard — without it, `$(Property)` would coerce to a `0.0.0` floor that every `latest`
    /// compares `>=` against, reporting "up to date" for the wrong reason (right answer,
    /// coincidentally, but via undefined behavior rather than the intended `Unresolved` path).
    #[test]
    fn test_is_up_to_date_unresolved_property_returns_true() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(
            &VersionReq::new("$(SomePackageVersion)"),
            &ConcreteVersion::new("13.0.3")
        ));
    }

    /// Code-review finding 1: `version_satisfies_requirement` is `in_use_version.rs`'s
    /// `version_matches_requirement` fallback whenever `compile_requirement` returns `None` —
    /// now the case for every `$(...)` requirement — so it must not coerce the unparseable core
    /// to a `0.0.0` floor that matches almost any candidate.
    #[test]
    fn test_version_satisfies_requirement_unresolved_property_returns_true() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement(
            &ConcreteVersion::new("13.0.3"),
            "$(SomePackageVersion)"
        ));
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
        use deps_core::position::{Position, Range};

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

    /// #821: `compile_requirement` must classify these as undecidable (no diagnostic), the
    /// same treatment Maven/Gradle already give them, instead of the previous behavior where
    /// `crate::version::parse_range`'s independent, less-hardened grammar silently accepted
    /// them and made every candidate compare as satisfied.
    #[test]
    fn test_compile_requirement_rejects_all_malformed_interval_shapes() {
        let f = NuGetFormatter;
        for malformed in ["[[1.0,2.0)", "[1.0,2.0,3.0]", "(1.0)", "[]", "[1.0,2.0)]"] {
            assert!(
                f.compile_requirement(&VersionReq::new(malformed)).is_none(),
                "expected {malformed:?} to be undecidable"
            );
        }
    }

    #[test]
    fn test_compile_requirement_malformed_floating_pattern_returns_none() {
        let f = NuGetFormatter;
        // Not a valid interval (contains '*') and not a valid float pattern either
        // (`resolve_float`'s grammar requires a trailing `.*`/`*` segment).
        assert!(f.compile_requirement(&VersionReq::new("1.*.0")).is_none());
    }

    /// A bare `$(SomeProperty)` reference previously parsed as an ordinary
    /// `VersionRange::Minimum` floor (no bracket for `parse_range`'s nested-bracket guard to
    /// trip on), so `compile_requirement` would decisively (and wrongly) report every
    /// candidate as satisfying it. See [`NuGetFormatter::compile_requirement`]'s doc for why
    /// this is defense-in-depth rather than a fix for a live code path: were this text ever to
    /// reach `deps-cli update --security-only`'s `requirement_already_admits_fix` gate, it
    /// would rely on exactly this wrong answer — but `version_requirement()` is already `None`
    /// for this input, so that gate is never actually reached with it today.
    #[test]
    fn test_compile_requirement_none_for_unresolved_bare_property() {
        let f = NuGetFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("$(SomePackageVersion)"))
                .is_none()
        );
    }

    /// M3: a bracketed MSBuild property reference must be classified as unresolved, not
    /// left to fall through as a generic malformed/undecidable requirement (#821:
    /// `crate::version::parse_range` now rejects this shape outright via the shared
    /// nested-bracket guard, since it never resolves and should never be checked against
    /// `available`).
    #[test]
    fn test_requirement_is_unresolved_bracketed_msbuild_property() {
        let f = NuGetFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("[$(MinVersion),$(MaxVersion))")));
    }

    /// #1355: `%(Version)` (MSBuild item-metadata syntax) must be classified as unresolved,
    /// the same as `$(PropertyName)` — unlike the bracketed `$(...)` form, a bare `%(...)` has
    /// no bracket to trip `parse_range`'s nested-bracket guard, so without this check it
    /// parses as a bogus bare-floor version and can plan an incorrect rewrite edit.
    #[test]
    fn test_requirement_is_unresolved_msbuild_item_metadata() {
        let f = NuGetFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("%(Version)")));
    }

    /// #1355: `@(ItemList)` (MSBuild item-list reference) must be classified as unresolved
    /// too, the same as `$(PropertyName)`/`%(MetadataName)`.
    #[test]
    fn test_requirement_is_unresolved_msbuild_item_list() {
        let f = NuGetFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("@(PollyVer)")));
    }

    #[test]
    fn test_requirement_is_unresolved_false_for_ordinary_requirements() {
        let f = NuGetFormatter;
        assert!(!f.requirement_is_unresolved(&VersionReq::new("13.0.3")));
        assert!(!f.requirement_is_unresolved(&VersionReq::new("[1.0,2.0)")));
    }

    /// Issue #1347, closing the deps-core mock-fidelity gap: exercises
    /// `deps_core::edit::plan_vulnerability_fix` with the *real* `NuGetFormatter` (not a
    /// hand-rolled mock) and a `NuGetDependency` obtained from the real
    /// `crate::parser::parse_project_file` path, on a vulnerable package whose declared
    /// version is an unexpanded MSBuild property reference.
    ///
    /// Note: on the real `generate_code_actions`/`deps-cli` call graph this scenario is
    /// already unreachable before `plan_vulnerability_fix` is ever called — NuGet's own
    /// parser degrades `$(...)` to `version_requirement: None`
    /// (`test_unresolved_msbuild_property_degrades_to_none` in `parser.rs`), and both
    /// callers bail out on `dep.version_requirement().is_none()` first. This test instead
    /// calls `plan_vulnerability_fix` directly with the raw `$(...)` text as `current` (as a
    /// caller reached some other way would), proving the new guard itself is correct against
    /// the real formatter, independent of that caller-level gate.
    #[test]
    fn test_plan_vulnerability_fix_with_real_formatter_and_parsed_dependency() {
        use deps_core::ParseResult;
        use deps_core::edit::{VulnFixSkip, plan_vulnerability_fix};
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let xml = r#"<Project><ItemGroup><PackageReference Include="AutoMapper" Version="$(AutoMapperVersion)" /></ItemGroup></Project>"#;
        let uri = deps_core::test_util::test_uri("/test/real.csproj");
        let result = crate::parser::parse_project_file(xml, &uri).expect("valid xml");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        assert!(
            dep.version_requirement().is_none(),
            "sanity check: parser must degrade $(...) to None"
        );

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0001".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["1.2.0".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "1.2.0".to_string(),
            });

        let planned = plan_vulnerability_fix(
            *dep,
            deps_core::position::Range::default(),
            "$(AutoMapperVersion)",
            &dv,
            &NuGetFormatter,
        );

        // #1370: `plan_verified_fix`'s central placeholder gate checks `current` directly
        // (independent of `dep.version_requirement()`, which is `None` here) and fires first,
        // via `NuGetFormatter::requirement_is_placeholder`. Before that gate existed,
        // suppression came from `format_version_replacing`'s own `$(` short-circuit instead
        // (`VulnFixSkip::NoOpRewrite`) — still true as defense-in-depth, but no longer the
        // first guard reached.
        assert_eq!(
            planned,
            Err(VulnFixSkip::UnresolvedPlaceholder),
            "the real NuGetFormatter must suppress the fix for an unresolved property reference"
        );
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

    // --- requirement_already_resolves_to (#1344 C1) ---

    #[test]
    fn test_requirement_already_resolves_to_bare_floor_is_false() {
        let f = NuGetFormatter;
        // The base default (`compile_requirement(..).matches(..)`) would say `true` here —
        // any version at or above the floor is a matcher hit — which is exactly the bug: a
        // bare floor never auto-follows forward, so the override must refuse it.
        assert!(!f.requirement_already_resolves_to(
            &VersionReq::new("1.0.0"),
            &ConcreteVersion::new("1.0.2")
        ));
        assert!(!f.requirement_already_resolves_to(
            &VersionReq::new("1.0.0"),
            &ConcreteVersion::new("2.0.0")
        ));
    }

    #[test]
    fn test_requirement_already_resolves_to_open_ended_minimum_bracket_form_is_false() {
        let f = NuGetFormatter;
        // Same floor shape as a bare version, spelled with explicit interval brackets — must
        // classify identically (mirrors `is_requirement_up_to_date`'s own bracket-form tests).
        assert!(!f.requirement_already_resolves_to(
            &VersionReq::new("[1.0.0,)"),
            &ConcreteVersion::new("1.0.2")
        ));
    }

    #[test]
    fn test_requirement_already_resolves_to_exact_pin_is_false() {
        let f = NuGetFormatter;
        // An exact pin's `compile_requirement` matcher already rejects any other version, so
        // this stays `false` via the base default (`compare_minimum_floor` returns `None` for
        // an exact pin, falling through).
        assert!(!f.requirement_already_resolves_to(
            &VersionReq::new("[1.0.0]"),
            &ConcreteVersion::new("1.0.2")
        ));
    }

    #[test]
    fn test_requirement_already_resolves_to_bounded_range_admitting_target_is_true() {
        let f = NuGetFormatter;
        // A bounded range genuinely expresses a forward-compatibility window — the resolver
        // can pick the fix target from within it without any manifest edit.
        assert!(f.requirement_already_resolves_to(
            &VersionReq::new("[1.0.0,2.0.0)"),
            &ConcreteVersion::new("1.0.2")
        ));
    }

    #[test]
    fn test_requirement_already_resolves_to_floating_pattern_admitting_target_is_true() {
        let f = NuGetFormatter;
        assert!(f.requirement_already_resolves_to(
            &VersionReq::new("1.0.*"),
            &ConcreteVersion::new("1.0.2")
        ));
        assert!(!f.requirement_already_resolves_to(
            &VersionReq::new("1.0.*"),
            &ConcreteVersion::new("1.1.0")
        ));
    }

    /// #1344 C1 acceptance criterion: the single most common NuGet declaration form (a bare
    /// floor) must still get its vulnerability quickfix offered end-to-end through
    /// `deps_core::edit::plan_vulnerability_fix` — not just at the `RequirementResolution`
    /// unit level above.
    #[test]
    fn test_plan_vulnerability_fix_bare_floor_still_plans_the_edit() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};
        use deps_core::{ConcreteVersion, Dependency, PackageName};
        use std::sync::Arc;

        let version_range = Range::new(Position::new(0, 30), Position::new(0, 36));
        let dep = crate::types::NuGetDependency {
            name: PackageName::new("Newtonsoft.Json"),
            name_range: Range::default(),
            version_requirement: Some(VersionReq::new("1.0.0")),
            version_range: Some(version_range),
            source: DependencySource::Registry,
        };

        let advisory = Arc::new(
            Advisory::new(
                "GHSA-0000-0000-0000".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["1.0.2".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "1.0.2".to_string(),
            });

        let planned = plan_vulnerability_fix(
            &dep,
            version_range,
            dep.version_requirement().unwrap().as_str(),
            &dv,
            &NuGetFormatter,
        )
        .expect(
            "a bare-floor requirement must not suppress the fix: leaving it unedited keeps \
             restoring the vulnerable floor version",
        );
        assert_eq!(planned.edit.new_text, "1.0.2");
        assert_eq!(planned.target, ConcreteVersion::new("1.0.2"));
    }
}

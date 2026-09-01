//! Version formatting for Gradle ecosystem.

use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher, compile_requirement_unless};
use deps_core::{
    ConcreteVersion, InvalidPackageName, PackageName, VersionReq, is_safe_maven_coordinate_segment,
};

pub struct GradleFormatter;

/// Unresolved Gradle variable reference (`$var`, `${var}`), or an explicit empty
/// version-catalog entry (`[versions] foo = ""`) that a `version.ref` could point at.
fn is_unresolved(requirement: &str) -> bool {
    requirement.is_empty() || requirement.contains('$')
}

/// Strips Gradle's rich-version strict/preferred shorthand
/// (`{strictlyVersion}!!{preferredVersion}`, e.g. the degenerate suffix form `1.2.3!!`
/// or the full infix form `[1.7,1.8[!!1.7.25`), returning only the `strictlyVersion`
/// half. Per Gradle's rich-version semantics, `strictly` is the hard constraint and
/// `preferred` is only a soft conflict-resolution tiebreak among versions that already
/// satisfy it — a version inside the strict range/pin satisfies the requirement
/// regardless of whether it matches the preferred pointer, so every "does this version
/// satisfy the requirement" comparison in [`gradle_version_matches`] and
/// [`GradleFormatter::compile_requirement`] must operate on the `strictlyVersion`
/// constraint alone, never the preference. `requirement` is `trim_end`ed before the
/// marker check: `libs.versions.toml` catalog values reach here un-trimmed
/// (`catalog::extract_version` returns the raw string verbatim), unlike the DSL
/// parsers, which already trim their capture.
fn strip_strict_marker(requirement: &str) -> &str {
    requirement
        .trim_end()
        .split_once("!!")
        .map_or(requirement, |(strictly, _)| strictly.trim_end())
}

/// A `-SNAPSHOT` pin (e.g. `7.0.0-SNAPSHOT`) resolves against Maven Central's snapshot
/// repository, which `deps-maven`'s `MavenCentralRegistry` (reused for Gradle resolution)
/// never queries — release-repo `maven-metadata.xml` never lists snapshot versions, so
/// `available` can never contain one. Treated as always satisfied, like an unresolved
/// variable or `latest.*`.
fn is_snapshot(requirement: &str) -> bool {
    requirement.ends_with("-SNAPSHOT")
}

/// Decides whether `version` satisfies a Gradle `requirement` — shared by
/// `version_satisfies_requirement` and [`GradleFormatter::compile_requirement`]'s matcher,
/// since Gradle has no separate "loose" vs. "precise" comparator to distinguish (mirrors
/// `deps-maven`'s formatter, which shares the same shape for the same reason).
///
/// #249 review (M4, root cause of S1): this function's branch order is a separate copy from
/// `compile_requirement`'s below — the malformed-range guard that function adds ahead of its
/// own copy of this order has no equivalent here (this function has none; a malformed range
/// simply falls through to `crate::range::satisfies`'s fail-closed `false`, which is correct
/// for the "loose satisfies" question this function answers). Reordering the branches here
/// must be checked against `compile_requirement`'s branch order and guard placement too.
fn gradle_version_matches(version: &str, requirement: &str) -> bool {
    // Checked on the raw string *before* stripping the `!!` marker: an unresolved
    // Gradle variable reference can appear in the `strictlyVersion` half (e.g.
    // `${r}!!1.7.25`), and stripping first would discard the `$` along with it,
    // silently treating an unresolved requirement as a concrete one to compare.
    //
    // Deliberate, harmless asymmetry with `compile_requirement` below, which has no
    // equivalent raw-string check: `strip_strict_marker` already returns the
    // `strictlyVersion` half with any `$` intact, so the post-strip `is_unresolved`
    // check a few lines down covers the same case on its own — this raw-string check
    // is pure defense-in-depth for a caller of this loose matcher standalone. Its
    // only observable effect is over-permissive, never under-permissive: a
    // `preferredVersion` half containing an unresolved variable (e.g.
    // `[1.7,1.8[!!${r}`) makes this function report "satisfied" for every version,
    // including ones outside the strict range, whereas `compile_requirement`'s
    // matcher (no raw-string check, and never reached with such a requirement in
    // production since `requirement_is_unsatisfiable` gates on the raw-string
    // `requirement_is_unresolved` first) would correctly reject an out-of-range
    // version. Never produces a false "outdated" badge or a spurious edit, so this
    // is not a bug — just don't "fix" the two functions back into lockstep by
    // deleting this check without checking C3's post-strip coverage still holds.
    if is_unresolved(requirement) {
        return true;
    }
    let requirement = strip_strict_marker(requirement);
    // Unresolved Gradle variable reference (`$var`/`${var}`), or an empty version-catalog
    // entry (`[versions] foo = ""`) — skip comparison. Re-checked post-strip for the
    // degenerate case where the `strictlyVersion` half itself is empty (a malformed
    // bare `"!!"` requirement), which the raw check above does not catch since the raw
    // string is `"!!"`, not empty.
    if is_unresolved(requirement) {
        return true;
    }
    if requirement == "latest" || requirement.starts_with("latest.") {
        return true;
    }
    if is_snapshot(requirement) {
        return true;
    }
    if let Some(prefix) = requirement.strip_suffix('+') {
        return version == prefix.trim_end_matches('.') || version.starts_with(prefix);
    }
    // `]` is included alongside `[`/`(` because Gradle's reversed-bracket exclusive
    // notation (`]1.2,1.5]`) is a leading delimiter in its own right, not just a
    // trailing one.
    if requirement.starts_with(['[', '(', ']']) {
        return crate::range::satisfies(version, requirement);
    }
    version == requirement
}

/// Precise Gradle version/range matcher, compiled once per dependency by
/// [`GradleFormatter::compile_requirement`] — a bracket-interval range is parsed once into a
/// [`deps_maven::interval::VersionRange`] here rather than being re-parsed for every
/// candidate version scanned. `requirement_is_unsatisfiable` already gates on
/// `requirement_is_unresolved` before calling `compile_requirement`, so the unresolved and
/// `latest.*` short-circuits are unreachable from that caller in practice; they stay so this
/// matcher is correct if used standalone.
enum GradleMatcher {
    /// Unresolved `$var`/`${var}`, `latest`/`latest.*`, or a `-SNAPSHOT` pin.
    AlwaysSatisfied,
    /// A dynamic `1.0.+` prefix — the text before the trailing `+`.
    DynamicPrefix(String),
    /// A bracket-interval range, pre-parsed by [`crate::range::parse_range`].
    Range(deps_maven::interval::VersionRange),
    /// A bare exact version.
    Exact(String),
}

impl RequirementMatcher for GradleMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Some(match self {
            Self::AlwaysSatisfied => true,
            Self::DynamicPrefix(prefix) => {
                version == prefix.trim_end_matches('.') || version.starts_with(prefix.as_str())
            }
            Self::Range(range) => deps_maven::interval::contains(version, range),
            Self::Exact(target) => version == target,
        })
    }
}

impl EcosystemFormatter for GradleFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    /// Preserves Gradle's rich-version strict/preferred shorthand
    /// (`{strictlyVersion}!!{preferredVersion}`) when `current` carries it — a bare
    /// `format_version_for_text_edit` replacement would otherwise silently downgrade
    /// a strict constraint to a normal one.
    ///
    /// Only the degenerate suffix form (`1.2.3!!`, no `preferredVersion`) is
    /// rewritten — to `{version}!!` — since the strict pin itself is what "update
    /// version" means to bump there, and there is nothing else in the requirement to
    /// preserve. The full infix form (`[1.7,1.8[!!1.7.25`) is left unchanged rather
    /// than rewriting the `preferredVersion` half: since Gradle's strict constraint
    /// always wins conflict resolution, bumping the preference to a version outside
    /// the hand-written strict range (a likely outcome for "update to latest") would
    /// silently write a no-op edit that *looks* like an update but changes nothing —
    /// worse than the original silently-dropped-marker bug, since the manifest now
    /// reads as though it were updated. There is no single rewrite that is safe in
    /// general without inspecting the strict range's bounds, which is out of scope
    /// here. `current` is `trim`med before the marker check for the same
    /// un-trimmed-catalog-value reason as `strip_strict_marker` above. A no-op
    /// return here is safely excluded from `deps-core`'s `collect_update_all_edits`
    /// ("Update N outdated dependencies" lens) by its own no-op guard.
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        let version = version.as_str();
        let trimmed = current.trim();
        match trimmed.split_once("!!") {
            Some((_, "")) => format!("{version}!!"),
            Some(_) => trimmed.to_string(),
            None => self.format_version_for_text_edit(&ConcreteVersion::new(version)),
        }
    }

    fn package_url(&self, name: &PackageName) -> String {
        deps_maven::registry::package_url(name.as_str())
    }

    /// Validates a Gradle coordinate's `group:artifact` shape and character set.
    ///
    /// Gradle resolves through `deps_maven::MavenCentralRegistry` and shares Maven's
    /// `groupId:artifactId` coordinate shape (see `deps-gradle/src/ecosystem.rs`), so this
    /// mirrors [`deps_maven`]'s `MavenFormatter::validate_package_name` exactly, reusing
    /// [`is_safe_maven_coordinate_segment`] rather than duplicating it — letting the
    /// "Invalid package name" diagnostic surface the accurate reason instead of the
    /// generic "Unknown package" a registry-side rejection produces (#375).
    ///
    /// Unlike Maven's `${property}`-specific `is_unresolved`, this uses Gradle's own
    /// `is_unresolved`, which also short-circuits on an unresolved `$var`/`${var}`
    /// reference or Gradle-catalog-alias placeholder — valid Gradle syntax, not a
    /// malformed coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` has no `:` separator, or if either the
    /// `group` or `artifact` segment fails [`is_safe_maven_coordinate_segment`] — but
    /// never when `name` is unresolved per `is_unresolved`, which is accepted instead.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if is_unresolved(name) {
            return Ok(());
        }
        let Some((group_id, artifact_id)) = name.split_once(':') else {
            return Err(InvalidPackageName::new(
                "coordinate must be in 'group:artifact' form",
            ));
        };
        if !is_safe_maven_coordinate_segment(group_id) {
            return Err(InvalidPackageName::new("group contains invalid characters"));
        }
        if !is_safe_maven_coordinate_segment(artifact_id) {
            return Err(InvalidPackageName::new(
                "artifact contains invalid characters",
            ));
        }
        Ok(())
    }

    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        gradle_version_matches(version, requirement)
    }

    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        is_unresolved(requirement.as_str())
    }

    /// Uses [`compile_requirement_unless`] (see that function and
    /// [`EcosystemFormatter::compile_requirement`] for the shared "undecidable" contract).
    ///
    /// The undecidable predicate rejects a malformed range (leading `[`/`(`/`]` but
    /// `crate::range::parse_range` fails) — checked unconditionally, first, before any
    /// other branch: without this guard ahead of the `AlwaysSatisfied`/dynamic-prefix
    /// short-circuits below, a malformed bracket range that also happens to end in `+`
    /// (e.g. `"[1.0,2.0]+"`) would be misclassified as a dynamic prefix — which decides
    /// `Some(false)` for every real candidate — instead of correctly suppressing the check.
    ///
    /// #249 review (M4): this is a separate branch-order copy from `gradle_version_matches`
    /// above — see the note on that function before reordering either one.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        // `!!` is Gradle's rich-version strict/preferred shorthand (see
        // `gradle_version_matches`/`strip_strict_marker`) — stripped once here, first, so
        // every branch below (the malformed-range guard, dynamic-prefix, range, exact)
        // operates on the `strictlyVersion` spelling underneath without needing its own
        // separate strip. Unlike `gradle_version_matches` (re-derives everything from the raw
        // string on every call), this matcher is pre-parsed once, so the stripped spelling must
        // be what actually gets stored in the `GradleMatcher` variant — storing the unstripped
        // string would make e.g. `Exact` compare against a target that includes `"!!"`.
        let requirement = strip_strict_marker(requirement.as_str());
        compile_requirement_unless(
            requirement,
            |r| r.starts_with(['[', '(', ']']) && crate::range::parse_range(r).is_none(),
            |r| {
                if is_unresolved(&r) || r == "latest" || r.starts_with("latest.") {
                    return GradleMatcher::AlwaysSatisfied;
                }
                if is_snapshot(&r) {
                    return GradleMatcher::AlwaysSatisfied;
                }
                if let Some(prefix) = r.strip_suffix('+') {
                    return GradleMatcher::DynamicPrefix(prefix.to_string());
                }
                // `]` is included alongside `[`/`(` because Gradle's reversed-bracket
                // exclusive notation (`]1.2,1.5]`) is a leading delimiter in its own
                // right, not just a trailing one. The undecidable guard above already
                // ensures `parse_range` succeeds here.
                if r.starts_with(['[', '(', ']'])
                    && let Some(range) = crate::range::parse_range(&r)
                {
                    return GradleMatcher::Range(range);
                }
                GradleMatcher::Exact(r)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::RequirementStatus;

    #[test]
    fn test_format_version() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("3.2.0")),
            "3.2.0"
        );
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("1.0.0-SNAPSHOT")),
            "1.0.0-SNAPSHOT"
        );
    }

    #[test]
    fn test_format_version_replacing_preserves_strict_marker() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("1.2.4"), "1.2.3!!"),
            "1.2.4!!"
        );
    }

    #[test]
    fn test_format_version_replacing_no_marker_stays_plain() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("1.2.4"), "1.2.3"),
            "1.2.4"
        );
    }

    /// M1: a version-catalog entry's raw value is not trimmed by the parser
    /// (unlike the Groovy/Kotlin DSL capture), so trailing whitespace must not
    /// defeat the suffix-marker check.
    #[test]
    fn test_format_version_replacing_preserves_strict_marker_with_trailing_whitespace() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("1.2.4"), "1.2.3!! "),
            "1.2.4!!"
        );
    }

    /// S1/C2: the full `{strictlyVersion}!!{preferredVersion}` shorthand has no
    /// single version to bump to — rewriting the `preferredVersion` half to a value
    /// outside the untouched strict range would write a self-contradictory
    /// constraint (Gradle's strict range always wins, so the bump would silently
    /// have no effect while the manifest reads as updated). Must return the
    /// declared text unchanged rather than destroying the range or writing a
    /// misleading no-op.
    #[test]
    fn test_format_version_replacing_infix_shorthand_is_unchanged() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("9.9.9"), "[1.7, 1.8[!!1.7.25"),
            "[1.7, 1.8[!!1.7.25"
        );
    }

    /// M1: same trailing-whitespace tolerance as the suffix form, for the infix form.
    #[test]
    fn test_format_version_replacing_infix_shorthand_with_trailing_whitespace() {
        let f = GradleFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("9.9.9"), "[1.7,1.8[!!1.7.25 "),
            "[1.7,1.8[!!1.7.25"
        );
    }

    #[test]
    fn test_package_url() {
        let f = GradleFormatter;
        assert_eq!(
            f.package_url(&PackageName::new(
                "org.springframework.boot:spring-boot-starter"
            )),
            "https://central.sonatype.com/artifact/org.springframework.boot/spring-boot-starter"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("3.2.0"), "3.2.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("3.2.0"), "3.1.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("3.2.0"), "3.2.1"));
    }

    #[test]
    fn test_version_satisfies_dynamic_prefix() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "1.0.+"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0"), "1.0.+"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "1.0.+"));
        // Prefix boundary: "2.10.+" must not false-match "2.1.5" via a naive
        // non-dot-anchored prefix check.
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.1.5"), "2.10.+"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.10.5"), "2.10.+"));
    }

    #[test]
    fn test_version_satisfies_latest_selector() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("3.2.0"), "latest.release"));
        assert!(f.version_satisfies_requirement(
            &ConcreteVersion::new("3.2.0-SNAPSHOT"),
            "latest.integration"
        ));
    }

    #[test]
    fn test_version_satisfies_range() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "[1.0,2.0)"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "[1.0,2.0)"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "[1.0.0]"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_reversed_bracket_range() {
        let f = GradleFormatter;
        // `implementation 'com.google.guava:guava:[30.0,31.0['` — Gradle's documented
        // exclusive-upper-bound notation, leading with `[` but trailing with `[` instead of
        // `)`/`]`.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("30.5"), "[30.0,31.0["));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("31.0"), "[30.0,31.0["));
        // Exclusive-lower-bound notation, which leads with `]` rather than `[`/`(`.
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2"), "]1.2,1.5]"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.3"), "]1.2,1.5]"));
    }

    /// S2/C1: the full `{strictlyVersion}!!{preferredVersion}` shorthand matches
    /// against the strict range alone — per Gradle's rich-version semantics,
    /// `strictly` is the hard constraint and `preferred` only breaks ties among
    /// versions that already satisfy it. A version inside the range but different
    /// from the preferred pointer (`1.7.30`) still satisfies the requirement;
    /// only a version genuinely outside the range (`1.8.0`) does not.
    #[test]
    fn test_version_satisfies_strict_range_with_preferred() {
        let f = GradleFormatter;
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("1.7.25"), "[1.7,1.8[!!1.7.25")
        );
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("1.7.30"), "[1.7,1.8[!!1.7.25")
        );
        assert!(
            !f.version_satisfies_requirement(&ConcreteVersion::new("1.8.0"), "[1.7,1.8[!!1.7.25")
        );
    }

    /// C3: an unresolved Gradle variable inside the `strictlyVersion` half must
    /// short-circuit to "satisfied" the same as a bare unresolved variable —
    /// stripping the `!!` marker before checking must never discard the `$`.
    #[test]
    fn test_version_satisfies_unresolved_variable_with_strict_marker() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.7.25"), "${r}!!1.7.25"));
    }

    /// C3: same guarantee when the unresolved variable sits in the
    /// `preferredVersion` half instead — the raw-string check runs before
    /// `strip_strict_marker` discards that half entirely, so it still sees the `$`.
    #[test]
    fn test_version_satisfies_unresolved_variable_in_preferred_half() {
        let f = GradleFormatter;
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("1.7.25"), "[1.7,1.8[!!${r}")
        );
    }

    /// M3: the discriminating case for the raw-string pre-check's documented
    /// asymmetry with `compile_requirement` — `1.7.25` above is inside the strict
    /// range regardless of the pre-check, so it doesn't prove anything on its own.
    /// `1.8.0` is genuinely outside `[1.7,1.8[`; the loose matcher still reports it
    /// as satisfied only because the raw-string pre-check short-circuits before the
    /// range is ever consulted. Deliberately over-permissive and unreachable in
    /// production (see the pre-check's doc comment); this pins the behavior so a
    /// future change to the pre-check doesn't silently alter it.
    #[test]
    fn test_version_satisfies_unresolved_variable_in_preferred_half_over_permissive() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.8.0"), "[1.7,1.8[!!${r}"));
    }

    #[test]
    fn test_version_satisfies_unresolved_bare_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("3.14.0"), "$someVersion"));
    }

    #[test]
    fn test_version_satisfies_unresolved_braced_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("3.14.0"), "${someVersion}"));
    }

    #[test]
    fn test_version_satisfies_unresolved_compound_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("3.14.0"), "1.0.0-$suffix"));
    }

    #[test]
    fn test_validate_package_name_accepts_valid_coordinate() {
        let f = GradleFormatter;
        assert!(f.validate_package_name("com.google.guava:guava").is_ok());
    }

    #[test]
    fn test_validate_package_name_rejects_missing_colon() {
        let f = GradleFormatter;
        assert!(f.validate_package_name("com.google.guava").is_err());
    }

    #[test]
    fn test_validate_package_name_rejects_invalid_group() {
        let f = GradleFormatter;
        assert!(f.validate_package_name("com</group>:guava").is_err());
    }

    #[test]
    fn test_validate_package_name_rejects_invalid_artifact() {
        let f = GradleFormatter;
        assert!(f.validate_package_name("com.google.guava:..").is_err());
    }

    /// Gradle's own `is_unresolved` (unresolved `$var`/`${var}` or catalog-alias
    /// placeholder) is valid Gradle syntax, not a malformed coordinate — must be
    /// accepted, mirroring Maven's `${property}` treatment.
    #[test]
    fn test_validate_package_name_accepts_unresolved_variable() {
        let f = GradleFormatter;
        assert!(f.validate_package_name("$group:guava").is_ok());
        assert!(f.validate_package_name("com.google.guava:${name}").is_ok());
    }

    #[test]
    fn test_normalize_is_identity() {
        let f = GradleFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("com.google.guava:guava")),
            "com.google.guava:guava"
        );
    }

    #[test]
    fn test_requirement_status_unresolved_bare_variable() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("$someVersion"),
                &ConcreteVersion::new("3.14.0")
            ),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_unresolved_braced_variable() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("${someVersion}"),
                &ConcreteVersion::new("3.14.0")
            ),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_unresolved_dangling_catalog_ref() {
        // Synthetic `$alias` produced by `catalog::extract_version` for a `version.ref`
        // missing from `[versions]` — must be treated the same as an unresolved variable.
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(
                &VersionReq::new("$missing"),
                &ConcreteVersion::new("3.14.0")
            ),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_up_to_date() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.2.0"), &ConcreteVersion::new("3.2.0")),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_requirement_status_outdated() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.1.0"), &ConcreteVersion::new("3.2.0")),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_compile_requirement_exact() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("3.2.0"))
            .expect("Gradle requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.2.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.1.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_range() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    /// S2: `requirement_status` must reach `UpToDate` for a strict pin sitting on
    /// the latest version, not stay permanently `Outdated` — the round trip through
    /// `format_version_replacing` (which preserves `!!`) would otherwise leave a
    /// warning the editor can never clear.
    #[test]
    fn test_requirement_status_strict_marker_up_to_date() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("1.2.3!!"), &ConcreteVersion::new("1.2.3")),
            RequirementStatus::UpToDate
        );
    }

    /// C1: matches against the strict range, not the preferred pointer — a
    /// registry that never publishes the exact preferred version must not produce
    /// a false "no published version satisfies this requirement" warning for every
    /// other version genuinely inside the strict range. See
    /// `test_version_satisfies_strict_range_with_preferred`'s doc for why.
    #[test]
    fn test_compile_requirement_strict_range_with_preferred() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.7,1.8[!!1.7.25"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.7.25")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.7.30")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.8.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_malformed_range_returns_none() {
        let f = GradleFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0"))
                .is_none()
        );
    }

    /// #268 rebase re-verification: the malformed-range guard runs on the post-strip
    /// `strictlyVersion` half, same as `crate::range::parse_range` below it — a
    /// missing closing delimiter must still be rejected even with an infix
    /// `!!{preferred}` shorthand attached, not misparsed as valid because the `!!`
    /// suffix confuses the range grammar.
    #[test]
    fn test_compile_requirement_malformed_range_with_preferred_returns_none() {
        let f = GradleFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0!!1.5"))
                .is_none()
        );
    }

    /// S6: mirrors deps-maven's snapshot guard — Gradle resolves through the same
    /// `MavenCentralRegistry`, which never queries the snapshot repository.
    #[test]
    fn test_compile_requirement_snapshot_always_satisfied() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("7.0.0-SNAPSHOT"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("6.9.0")), Some(true));
    }

    #[test]
    fn test_version_satisfies_snapshot() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("6.9.0"), "7.0.0-SNAPSHOT"));
    }

    /// #249 review regression: a malformed bracket range that also happens to end in `+`
    /// must still be rejected (`None`), not misclassified as a dynamic prefix by checking
    /// the `strip_suffix('+')` branch before the malformed-range guard — that would make
    /// every real candidate decide `Some(false)`, a false "unsatisfiable" ERROR for a typo.
    #[test]
    fn test_compile_requirement_malformed_range_rejected_even_with_trailing_plus() {
        let f = GradleFormatter;
        for malformed in ["[1.0,2.0]+", "[1.0,2.+", "(1.0,2.0)+", "]1.0,2.0]+"] {
            assert!(
                f.compile_requirement(&VersionReq::new(malformed)).is_none(),
                "expected None for {malformed:?}"
            );
        }
    }

    #[test]
    fn test_version_satisfies_strict_shorthand() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2.3!!"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.4"), "1.2.3!!"));
    }

    #[test]
    fn test_compile_requirement_strict_shorthand() {
        let f = GradleFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("1.2.3!!")).unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.2.3")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.2.4")), Some(false));
    }

    /// M6: `compile_requirement`'s range-validity guard must strip `!!` the same way
    /// `gradle_version_matches` does — otherwise a valid strict range like
    /// `"[1.0,2.0)!!"` fails `parse_range` (the suffix isn't range grammar) and the
    /// guard wrongly suppresses the diagnostic instead of compiling the matcher.
    #[test]
    fn test_compile_requirement_strict_range() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)!!"))
            .expect("strict range must still compile a matcher");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }
}

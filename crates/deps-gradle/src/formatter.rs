//! Version formatting for Gradle ecosystem.

use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};
use deps_core::{PackageName, VersionReq};

pub struct GradleFormatter;

/// Unresolved Gradle variable reference (`$var`, `${var}`), or an explicit empty
/// version-catalog entry (`[versions] foo = ""`) that a `version.ref` could point at.
fn is_unresolved(requirement: &str) -> bool {
    requirement.is_empty() || requirement.contains('$')
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
    // `!!` is Gradle's `strictly(...)` shorthand (e.g. `1.2.3!!`) — it constrains how
    // Gradle's conflict resolution treats the version, not which version string it names,
    // so matching drops the suffix and compares the version underneath unchanged.
    let requirement = requirement.strip_suffix("!!").unwrap_or(requirement);
    // Unresolved Gradle variable reference (`$var`/`${var}`), or an empty version-catalog
    // entry (`[versions] foo = ""`) — skip comparison
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
    fn matches(&self, version: &str) -> Option<bool> {
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
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        deps_maven::registry::package_url(name.as_str())
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        gradle_version_matches(version, requirement)
    }

    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        is_unresolved(requirement.as_str())
    }

    /// Returns `None` for a malformed range (leading `[`/`(`/`]` but
    /// `crate::range::parse_range` fails) — checked unconditionally, first, before any
    /// other branch: without this guard ahead of the `AlwaysSatisfied`/dynamic-prefix
    /// short-circuits below, a malformed bracket range that also happens to end in `+`
    /// (e.g. `"[1.0,2.0]+"`) would be misclassified as a dynamic prefix — which decides
    /// `Some(false)` for every real candidate — instead of correctly suppressing the check.
    ///
    /// #249 review (M4): this is a separate branch-order copy from `gradle_version_matches`
    /// above — see the note on that function before reordering either one.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        // `!!` is Gradle's `strictly(...)` shorthand (see `gradle_version_matches`) — stripped
        // once here, first, so every branch below (the malformed-range guard, dynamic-prefix,
        // range, exact) operates on the version spelling underneath without needing its own
        // separate strip. Unlike `gradle_version_matches` (re-derives everything from the raw
        // string on every call), this matcher is pre-parsed once, so the stripped spelling must
        // be what actually gets stored in the `GradleMatcher` variant — storing the unstripped
        // string would make e.g. `Exact` compare against a target that includes `"!!"`.
        let requirement = requirement.as_str();
        let requirement = requirement.strip_suffix("!!").unwrap_or(requirement);
        if requirement.starts_with(['[', '(', ']']) && crate::range::parse_range(requirement).is_none()
        {
            return None;
        }
        if is_unresolved(requirement)
            || requirement == "latest"
            || requirement.starts_with("latest.")
        {
            return Some(Box::new(GradleMatcher::AlwaysSatisfied));
        }
        if is_snapshot(requirement) {
            return Some(Box::new(GradleMatcher::AlwaysSatisfied));
        }
        if let Some(prefix) = requirement.strip_suffix('+') {
            return Some(Box::new(GradleMatcher::DynamicPrefix(prefix.to_string())));
        }
        // `]` is included alongside `[`/`(` because Gradle's reversed-bracket exclusive
        // notation (`]1.2,1.5]`) is a leading delimiter in its own right, not just a
        // trailing one.
        if requirement.starts_with(['[', '(', ']']) {
            return crate::range::parse_range(requirement)
                .map(|range| Box::new(GradleMatcher::Range(range)) as Box<dyn RequirementMatcher>);
        }
        Some(Box::new(GradleMatcher::Exact(requirement.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::RequirementStatus;

    #[test]
    fn test_format_version() {
        let f = GradleFormatter;
        assert_eq!(f.format_version_for_text_edit("3.2.0"), "3.2.0");
        assert_eq!(
            f.format_version_for_text_edit("1.0.0-SNAPSHOT"),
            "1.0.0-SNAPSHOT"
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
        assert!(f.version_satisfies_requirement("3.2.0", "3.2.0"));
        assert!(!f.version_satisfies_requirement("3.2.0", "3.1.0"));
        assert!(!f.version_satisfies_requirement("3.2.0", "3.2.1"));
    }

    #[test]
    fn test_version_satisfies_dynamic_prefix() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("1.0.5", "1.0.+"));
        assert!(f.version_satisfies_requirement("1.0", "1.0.+"));
        assert!(!f.version_satisfies_requirement("1.1.0", "1.0.+"));
        // Prefix boundary: "2.10.+" must not false-match "2.1.5" via a naive
        // non-dot-anchored prefix check.
        assert!(!f.version_satisfies_requirement("2.1.5", "2.10.+"));
        assert!(f.version_satisfies_requirement("2.10.5", "2.10.+"));
    }

    #[test]
    fn test_version_satisfies_latest_selector() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.2.0", "latest.release"));
        assert!(f.version_satisfies_requirement("3.2.0-SNAPSHOT", "latest.integration"));
    }

    #[test]
    fn test_version_satisfies_range() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", "[1.0,2.0)"));
        assert!(!f.version_satisfies_requirement("2.0.0", "[1.0,2.0)"));
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_reversed_bracket_range() {
        let f = GradleFormatter;
        // `implementation 'com.google.guava:guava:[30.0,31.0['` — Gradle's documented
        // exclusive-upper-bound notation, leading with `[` but trailing with `[` instead of
        // `)`/`]`.
        assert!(f.version_satisfies_requirement("30.5", "[30.0,31.0["));
        assert!(!f.version_satisfies_requirement("31.0", "[30.0,31.0["));
        // Exclusive-lower-bound notation, which leads with `]` rather than `[`/`(`.
        assert!(!f.version_satisfies_requirement("1.2", "]1.2,1.5]"));
        assert!(f.version_satisfies_requirement("1.3", "]1.2,1.5]"));
    }

    #[test]
    fn test_version_satisfies_unresolved_bare_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "$someVersion"));
    }

    #[test]
    fn test_version_satisfies_unresolved_braced_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "${someVersion}"));
    }

    #[test]
    fn test_version_satisfies_unresolved_compound_variable() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "1.0.0-$suffix"));
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
            f.requirement_status(&VersionReq::new("$someVersion"), "3.14.0"),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_unresolved_braced_variable() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("${someVersion}"), "3.14.0"),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_unresolved_dangling_catalog_ref() {
        // Synthetic `$alias` produced by `catalog::extract_version` for a `version.ref`
        // missing from `[versions]` — must be treated the same as an unresolved variable.
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("$missing"), "3.14.0"),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_up_to_date() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.2.0"), "3.2.0"),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_requirement_status_outdated() {
        let f = GradleFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.1.0"), "3.2.0"),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_compile_requirement_exact() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("3.2.0"))
            .expect("Gradle requirement always compiles");
        assert_eq!(matcher.matches("3.2.0"), Some(true));
        assert_eq!(matcher.matches("3.1.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_range() {
        let f = GradleFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .unwrap();
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_malformed_range_returns_none() {
        let f = GradleFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0"))
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
        assert_eq!(matcher.matches("6.9.0"), Some(true));
    }

    #[test]
    fn test_version_satisfies_snapshot() {
        let f = GradleFormatter;
        assert!(f.version_satisfies_requirement("6.9.0", "7.0.0-SNAPSHOT"));
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
        assert!(f.version_satisfies_requirement("1.2.3", "1.2.3!!"));
        assert!(!f.version_satisfies_requirement("1.2.4", "1.2.3!!"));
    }

    #[test]
    fn test_compile_requirement_strict_shorthand() {
        let f = GradleFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("1.2.3!!")).unwrap();
        assert_eq!(matcher.matches("1.2.3"), Some(true));
        assert_eq!(matcher.matches("1.2.4"), Some(false));
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
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }
}

//! Version formatting for Maven ecosystem.

use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};
use deps_core::{PackageName, VersionReq};

pub struct MavenFormatter;

/// Unexpanded property (missing from `<properties>`).
fn is_unresolved(requirement: &str) -> bool {
    requirement.contains("${")
}

/// Maven's `LATEST`/`RELEASE` metadata keywords (case-sensitive per Maven's own grammar):
/// "resolve to whatever `<latest>`/`<release>` in maven-metadata.xml currently designates".
/// That designation is a side channel [`MavenMatcher`] has no access to (the same
/// `<release>`-side-channel limitation `MavenCentralRegistry::select_latest_matching`
/// documents), so — like an unresolved `${property}` — the requirement can't be checked
/// literally against `available` and must be treated as always satisfied.
fn is_latest_keyword(requirement: &str) -> bool {
    matches!(requirement, "LATEST" | "RELEASE")
}

/// A `-SNAPSHOT` pin (e.g. `7.0.0-SNAPSHOT`) is a normal, common requirement in real dev
/// manifests, but `MavenCentralRegistry` only ever fetches the release-repo
/// `maven-metadata.xml` — which never lists snapshot versions, those live in a separate
/// snapshot repository this registry client doesn't query. `available` can therefore never
/// contain one, so — like `LATEST`/`RELEASE` and an unresolved `${property}` — it must be
/// treated as always satisfied rather than scanned.
fn is_snapshot(requirement: &str) -> bool {
    requirement.ends_with("-SNAPSHOT")
}

/// Precise Maven version/range matcher, compiled once per dependency by
/// [`MavenFormatter::compile_requirement`] — the range union (if any) is parsed once into
/// [`crate::interval::VersionRange`]s here rather than being re-parsed for every candidate
/// version scanned. Deliberately more precise than the loose `version_satisfies_requirement`
/// in two ways it does not need for its own "treat as up to date" question: it recognizes the
/// `LATEST`/`RELEASE` keywords, and its exact-match branch uses qualifier-aware
/// `compare_versions_for_range` instead of raw string equality, so `1.0` correctly matches a
/// published `1.0.0` (equal under Maven's own `ComparableVersion`) rather than reporting a
/// false WARNING.
enum MavenMatcher {
    /// Unresolved `${property}`, `LATEST`/`RELEASE`, or a `-SNAPSHOT` pin — see
    /// [`is_unresolved`], [`is_latest_keyword`], [`is_snapshot`].
    AlwaysSatisfied,
    /// A range/union, pre-parsed by [`crate::range::parse_range`].
    Ranges(Vec<crate::interval::VersionRange>),
    /// A bare "soft" recommended version, compared with qualifier-aware equality.
    Exact(String),
}

impl RequirementMatcher for MavenMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        Some(match self {
            Self::AlwaysSatisfied => true,
            Self::Ranges(ranges) => crate::range::satisfies_ranges(version, ranges),
            Self::Exact(target) => {
                crate::version::compare_versions_for_range(version, target)
                    == std::cmp::Ordering::Equal
            }
        })
    }
}

impl EcosystemFormatter for MavenFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // Maven uses exact versions, no prefix
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    // #249 review (M4): this branch order (unresolved → range → exact) is a separate copy
    // from `compile_requirement`'s below — kept apart deliberately (see `MavenMatcher`'s
    // docs for the two precision differences), but any reordering here must be checked
    // against `compile_requirement`'s malformed-range guard placement too, since S1/S2
    // happened in `deps-gradle` from exactly this kind of drift between two copies.
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // Unresolved properties (missing from <properties>) — skip comparison
        if is_unresolved(requirement) {
            return true;
        }
        if crate::range::is_range(requirement) {
            return crate::range::satisfies(version, requirement);
        }
        version == requirement
    }

    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        is_unresolved(requirement.as_str())
    }

    /// Returns `None` for a malformed range (`is_range` true but `crate::range::parse_range`
    /// fails) — checked unconditionally, first, before any other branch: without this guard
    /// ahead of the `AlwaysSatisfied` short-circuits below, a range that happens to also end
    /// in `-SNAPSHOT` or contain `${` would be misclassified as always-satisfied instead of
    /// rejected, and a fail-closed `false` on every candidate would otherwise produce a false
    /// "unsatisfiable" verdict for a typo instead of correctly suppressing the check.
    ///
    /// #249 review (M4): this is a separate branch-order copy from `version_satisfies_requirement`
    /// above — see the note on that method before reordering either one.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        let requirement = requirement.as_str();
        if crate::range::is_range(requirement) && crate::range::parse_range(requirement).is_none() {
            return None;
        }
        if is_unresolved(requirement) || is_latest_keyword(requirement) || is_snapshot(requirement)
        {
            return Some(Box::new(MavenMatcher::AlwaysSatisfied));
        }
        if crate::range::is_range(requirement) {
            return crate::range::parse_range(requirement).map(|ranges| {
                Box::new(MavenMatcher::Ranges(ranges)) as Box<dyn RequirementMatcher>
            });
        }
        Some(Box::new(MavenMatcher::Exact(requirement.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::lsp_helpers::RequirementStatus;

    #[test]
    fn test_format_version() {
        let f = MavenFormatter;
        assert_eq!(f.format_version_for_text_edit("3.14.0"), "3.14.0");
        assert_eq!(
            f.format_version_for_text_edit("1.0.0-SNAPSHOT"),
            "1.0.0-SNAPSHOT"
        );
    }

    #[test]
    fn test_package_url() {
        let f = MavenFormatter;
        assert_eq!(
            f.package_url(&PackageName::new("org.apache.commons:commons-lang3")),
            "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let f = MavenFormatter;
        assert!(f.version_satisfies_requirement("3.14.0", "3.14.0"));
        assert!(!f.version_satisfies_requirement("3.14.0", "3.13.0"));
        assert!(!f.version_satisfies_requirement("3.14.0", "3.14.1"));
    }

    #[test]
    fn test_version_satisfies_range() {
        let f = MavenFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", "[1.0,2.0)"));
        assert!(!f.version_satisfies_requirement("2.0.0", "[1.0,2.0)"));
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_maven_property() {
        let f = MavenFormatter;
        assert!(f.version_satisfies_requirement("7.1.1", "${woodstoxVersion}"));
        assert!(f.version_satisfies_requirement("2.0.17", "${slf4j.version}"));
        assert!(f.version_satisfies_requirement("1.0.0", "${project.version}"));
    }

    #[test]
    fn test_normalize_is_identity() {
        let f = MavenFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("org.apache.commons:commons-lang3")),
            "org.apache.commons:commons-lang3"
        );
    }

    #[test]
    fn test_requirement_status_unresolved_property() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("${woodstoxVersion}"), "7.1.1"),
            RequirementStatus::Unresolved
        );
        assert_eq!(
            f.requirement_status(&VersionReq::new("${project.version}"), "1.0.0"),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_up_to_date() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.14.0"), "3.14.0"),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_requirement_status_outdated() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status(&VersionReq::new("3.13.0"), "3.14.0"),
            RequirementStatus::Outdated
        );
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_own_parser() {
        // Critic S2 gate: `osv_version_to_native` is identity for Maven (OSV
        // records use Maven's own version syntax verbatim), so the version
        // it hands to `format_version_for_text_edit` must itself satisfy the
        // requirement text that edit produces — proving the default hook is
        // safe for this ecosystem rather than merely assumed so.
        let f = MavenFormatter;
        let osv_version = "1.2.3";
        let native = f.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let edit_text = f.format_version_for_text_edit(&native);
        assert!(f.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_compile_requirement_exact() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("3.14.0"))
            .expect("Maven requirement always compiles");
        assert_eq!(matcher.matches("3.14.0"), Some(true));
        assert_eq!(matcher.matches("3.13.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_range() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("[1.0,2.0)"))
            .unwrap();
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_malformed_range_returns_none() {
        let f = MavenFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0"))
                .is_none()
        );
    }

    /// M2: `<version>1.0</version>` and a published `1.0.0` are equal under Maven's own
    /// `ComparableVersion` (trailing zero segments don't matter) — the exact-match branch
    /// must not fall back to raw string equality and report a false WARNING.
    #[test]
    fn test_compile_requirement_trailing_zero_segments_are_equal() {
        let f = MavenFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("1.0")).unwrap();
        assert_eq!(matcher.matches("1.0.0"), Some(true));
        assert_eq!(matcher.matches("1.1.0"), Some(false));
    }

    /// M2: `LATEST`/`RELEASE` resolve against maven-metadata.xml's `<latest>`/`<release>`
    /// elements, a side channel this matcher has no access to — must be treated as always
    /// satisfied, like an unresolved property, not compared literally against `available`.
    #[test]
    fn test_compile_requirement_latest_keyword_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f.compile_requirement(&VersionReq::new("LATEST")).unwrap();
        assert_eq!(matcher.matches("3.14.0"), Some(true));

        let matcher = f.compile_requirement(&VersionReq::new("RELEASE")).unwrap();
        assert_eq!(matcher.matches("3.14.0"), Some(true));
    }

    /// S6: a `-SNAPSHOT` pin resolves against the snapshot repository, which this registry
    /// never queries — release-repo metadata never lists snapshot versions, so this must be
    /// treated as always satisfied rather than reported unsatisfiable.
    #[test]
    fn test_compile_requirement_snapshot_always_satisfied() {
        let f = MavenFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("7.0.0-SNAPSHOT"))
            .unwrap();
        assert_eq!(matcher.matches("6.9.0"), Some(true));
        assert_eq!(matcher.matches("7.0.0"), Some(true));
    }

    /// #249 review regression: a malformed range that also happens to end in `-SNAPSHOT` or
    /// contain `${` must still be rejected (`None`), not misclassified as always-satisfied by
    /// checking the `AlwaysSatisfied` short-circuits before the malformed-range guard.
    #[test]
    fn test_compile_requirement_malformed_range_rejected_even_with_snapshot_or_property_suffix() {
        let f = MavenFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,2.0-SNAPSHOT"))
                .is_none()
        );
        assert!(
            f.compile_requirement(&VersionReq::new("[1.0,${max}"))
                .is_none()
        );
    }
}

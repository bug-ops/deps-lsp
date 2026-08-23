//! Version formatting for Maven ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;
use deps_core::{PackageName, VersionReq};

pub struct MavenFormatter;

/// Unexpanded property (missing from `<properties>`).
fn is_unresolved(requirement: &str) -> bool {
    requirement.contains("${")
}

impl EcosystemFormatter for MavenFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // Maven uses exact versions, no prefix
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

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
}

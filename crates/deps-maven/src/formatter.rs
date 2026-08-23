//! Version formatting for Maven ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;

pub struct MavenFormatter;

impl EcosystemFormatter for MavenFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // Maven uses exact versions, no prefix
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        crate::registry::package_url(name)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // Unresolved properties (missing from <properties>) — skip comparison
        if self.requirement_is_unresolved(requirement) {
            return true;
        }
        if crate::range::is_range(requirement) {
            return crate::range::satisfies(version, requirement);
        }
        version == requirement
    }

    fn requirement_is_unresolved(&self, requirement: &str) -> bool {
        // Unexpanded property (missing from <properties>)
        requirement.contains("${")
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
            f.package_url("org.apache.commons:commons-lang3"),
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
            f.normalize_package_name("org.apache.commons:commons-lang3"),
            "org.apache.commons:commons-lang3"
        );
    }

    #[test]
    fn test_requirement_status_unresolved_property() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status("${woodstoxVersion}", "7.1.1"),
            RequirementStatus::Unresolved
        );
        assert_eq!(
            f.requirement_status("${project.version}", "1.0.0"),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_up_to_date() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status("3.14.0", "3.14.0"),
            RequirementStatus::UpToDate
        );
    }

    #[test]
    fn test_requirement_status_outdated() {
        let f = MavenFormatter;
        assert_eq!(
            f.requirement_status("3.13.0", "3.14.0"),
            RequirementStatus::Outdated
        );
    }
}

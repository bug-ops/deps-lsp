//! Version formatting for Maven ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;

pub struct MavenFormatter;

impl EcosystemFormatter for MavenFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        // Maven uses exact versions, no prefix
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        crate::registry::package_url(name)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // MVP: exact match only
        version == requirement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = MavenFormatter;
        assert_eq!(f.format_version_for_code_action("3.14.0"), "3.14.0");
        assert_eq!(
            f.format_version_for_code_action("1.0.0-SNAPSHOT"),
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
    fn test_normalize_is_identity() {
        let f = MavenFormatter;
        assert_eq!(
            f.normalize_package_name("org.apache.commons:commons-lang3"),
            "org.apache.commons:commons-lang3"
        );
    }
}

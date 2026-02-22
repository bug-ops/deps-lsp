//! Version formatting for Gradle ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;

pub struct GradleFormatter;

impl EcosystemFormatter for GradleFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        deps_maven::registry::package_url(name)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version == requirement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = GradleFormatter;
        assert_eq!(f.format_version_for_code_action("3.2.0"), "3.2.0");
        assert_eq!(
            f.format_version_for_code_action("1.0.0-SNAPSHOT"),
            "1.0.0-SNAPSHOT"
        );
    }

    #[test]
    fn test_package_url() {
        let f = GradleFormatter;
        assert_eq!(
            f.package_url("org.springframework.boot:spring-boot-starter"),
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
    fn test_normalize_is_identity() {
        let f = GradleFormatter;
        assert_eq!(
            f.normalize_package_name("com.google.guava:guava"),
            "com.google.guava:guava"
        );
    }
}

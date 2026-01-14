use deps_core::lsp_helpers::EcosystemFormatter;

pub struct NpmFormatter;

impl EcosystemFormatter for NpmFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://www.npmjs.com/package/{name}")
    }

    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = NpmFormatter;
        // Version should not include quotes - parser's version_range excludes them
        assert_eq!(
            formatter.format_version_for_code_action("1.0.214"),
            "1.0.214"
        );
        assert_eq!(formatter.format_version_for_code_action("18.3.1"), "18.3.1");
    }

    #[test]
    fn test_package_url() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.package_url("react"),
            "https://www.npmjs.com/package/react"
        );
        assert_eq!(
            formatter.package_url("@types/node"),
            "https://www.npmjs.com/package/@types/node"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.normalize_package_name("react"), "react");
        assert_eq!(
            formatter.normalize_package_name("@types/node"),
            "@types/node"
        );
    }

    #[test]
    fn test_deprecated_messages() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.yanked_message(), "This version is deprecated");
        assert_eq!(formatter.yanked_label(), "*(deprecated)*");
    }

    #[test]
    fn test_version_satisfies_requirement() {
        let formatter = NpmFormatter;

        // Exact match
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));

        // Partial versions
        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        // Caret - allows any version with same major (for major > 0)
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.0"));
        assert!(formatter.version_satisfies_requirement("1.5.0", "^1.2.3"));
        assert!(formatter.version_satisfies_requirement("10.1.3", "^10.1.3")); // Same version
        assert!(formatter.version_satisfies_requirement("10.2.0", "^10.1.3")); // Higher minor

        // Tilde - allows patch changes
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.5", "~1.2"));

        // Should not match
        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
        assert!(!formatter.version_satisfies_requirement("2.0.0", "^1.2.3")); // Different major
    }
}

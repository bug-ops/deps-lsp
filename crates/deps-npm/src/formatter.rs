use deps_core::lsp_helpers::{EcosystemFormatter, is_same_major_minor};

pub struct NpmFormatter;

impl EcosystemFormatter for NpmFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        // Don't add quotes - version_range already excludes them from parser
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://www.npmjs.com/package/{}", name)
    }

    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        let req_normalized = requirement
            .strip_prefix('^')
            .or_else(|| requirement.strip_prefix('~'))
            .unwrap_or(requirement);

        let req_parts: Vec<&str> = req_normalized.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;

        version == requirement
            || (is_partial_version && is_same_major_minor(req_normalized, version))
            || (is_partial_version && version.starts_with(req_normalized))
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

        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
    }
}

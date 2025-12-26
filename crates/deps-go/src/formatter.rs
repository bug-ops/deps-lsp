use deps_core::lsp_helpers::EcosystemFormatter;

/// Formatter for Go module version strings and package URLs.
///
/// Handles Go-specific version formatting:
/// - Versions are unquoted in go.mod (v1.2.3)
/// - Pseudo-versions (v0.0.0-20191109021931-daa7c04131f5)
/// - +incompatible suffix for v2+ modules without /v2 path
pub struct GoFormatter;

impl EcosystemFormatter for GoFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        // Go versions in go.mod are unquoted: v1.2.3
        // Return version as-is since it should already have "v" prefix from registry
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        // Use pkg.go.dev for package documentation
        // URL encode special characters (@ and space)
        let encoded = name.replace('@', "%40").replace(' ', "%20");
        format!("https://pkg.go.dev/{}", encoded)
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        // For Go modules, version matching is typically exact
        // However, we need to handle:
        // 1. Exact match: v1.2.3 == v1.2.3
        // 2. Prefix match for pseudo-versions: v0.0.0-20191109021931-daa7c04131f5 starts with v0.0.0
        // 3. Prefix match for +incompatible: v2.0.0+incompatible starts with v2.0.0

        if version == requirement {
            return true;
        }

        // Handle pseudo-versions and +incompatible suffix
        // Check if version starts with requirement followed by a dot, hyphen, plus, or end
        // This prevents false positives like v1.2.30 matching v1.2.3
        if let Some(suffix) = version.strip_prefix(requirement) {
            return suffix.is_empty()
                || suffix.starts_with('.')
                || suffix.starts_with('-')
                || suffix.starts_with('+');
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version_for_code_action() {
        let formatter = GoFormatter;

        // Standard semantic version
        assert_eq!(formatter.format_version_for_code_action("v1.2.3"), "v1.2.3");

        // Pseudo-version
        assert_eq!(
            formatter.format_version_for_code_action("v0.0.0-20191109021931-daa7c04131f5"),
            "v0.0.0-20191109021931-daa7c04131f5"
        );

        // Version with +incompatible
        assert_eq!(
            formatter.format_version_for_code_action("v2.0.0+incompatible"),
            "v2.0.0+incompatible"
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = GoFormatter;

        // Standard package
        assert_eq!(
            formatter.package_url("github.com/gin-gonic/gin"),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );

        // Package with version path
        assert_eq!(
            formatter.package_url("github.com/go-redis/redis/v8"),
            "https://pkg.go.dev/github.com/go-redis/redis/v8"
        );

        // Standard library package
        assert_eq!(formatter.package_url("fmt"), "https://pkg.go.dev/fmt");

        // Package with @ character (should be URL encoded)
        assert_eq!(
            formatter.package_url("github.com/user@org/package"),
            "https://pkg.go.dev/github.com/user%40org/package"
        );

        // Package with space (should be URL encoded)
        assert_eq!(
            formatter.package_url("github.com/user/pkg name"),
            "https://pkg.go.dev/github.com/user/pkg%20name"
        );
    }

    #[test]
    fn test_version_satisfies_requirement_exact_match() {
        let formatter = GoFormatter;

        // Exact version match
        assert!(formatter.version_satisfies_requirement("v1.2.3", "v1.2.3"));
        assert!(formatter.version_satisfies_requirement("v0.1.0", "v0.1.0"));
    }

    #[test]
    fn test_version_satisfies_requirement_pseudo_version() {
        let formatter = GoFormatter;

        // Pseudo-version prefix match
        assert!(
            formatter.version_satisfies_requirement("v0.0.0-20191109021931-daa7c04131f5", "v0.0.0")
        );

        // Full pseudo-version match
        assert!(formatter.version_satisfies_requirement(
            "v0.0.0-20191109021931-daa7c04131f5",
            "v0.0.0-20191109021931-daa7c04131f5"
        ));
    }

    #[test]
    fn test_version_satisfies_requirement_incompatible() {
        let formatter = GoFormatter;

        // +incompatible suffix handling
        assert!(formatter.version_satisfies_requirement("v2.0.0+incompatible", "v2.0.0"));

        // Exact match with +incompatible
        assert!(
            formatter.version_satisfies_requirement("v2.0.0+incompatible", "v2.0.0+incompatible")
        );
    }

    #[test]
    fn test_version_does_not_satisfy_requirement() {
        let formatter = GoFormatter;

        // Different versions
        assert!(!formatter.version_satisfies_requirement("v1.2.3", "v1.2.4"));
        assert!(!formatter.version_satisfies_requirement("v2.0.0", "v1.0.0"));

        // Partial match that doesn't start with requirement
        assert!(!formatter.version_satisfies_requirement("v1.2.3", "v1.2.3.4"));
    }

    #[test]
    fn test_version_satisfies_requirement_prefix_scenarios() {
        let formatter = GoFormatter;

        // Version is prefix of requirement (should NOT match)
        assert!(!formatter.version_satisfies_requirement("v1.2", "v1.2.3"));

        // Requirement is prefix of version with dot boundary (should match)
        assert!(formatter.version_satisfies_requirement("v1.2.3", "v1.2"));

        // False positive prevention: v1.2.30 should NOT match v1.2.3
        assert!(!formatter.version_satisfies_requirement("v1.2.30", "v1.2.3"));

        // But v1.2.3.1 SHOULD match v1.2.3 (if it has dot boundary)
        assert!(formatter.version_satisfies_requirement("v1.2.3.1", "v1.2.3"));
    }
}

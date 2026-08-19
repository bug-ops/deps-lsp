//! Version formatting for the NuGet ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;

pub struct NuGetFormatter;

impl EcosystemFormatter for NuGetFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // NuGet manifests store plain version text; no prefix/wrapping on insert.
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        crate::registry::package_url(name)
    }

    /// Overridden because the default npm caret/tilde semantics do not apply to NuGet's
    /// interval-notation ranges (`[1.0,2.0)`) and floating patterns (`1.1.*`).
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        if requirement.contains('*') {
            let versions = [version.to_string()];
            return crate::version::resolve_float(&versions, requirement).is_some();
        }
        crate::version::satisfies(version, requirement)
    }

    /// NuGet package ids are case-insensitive and every V3 API path segment is lowercased.
    fn normalize_package_name(&self, name: &str) -> String {
        name.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = NuGetFormatter;
        assert_eq!(f.format_version_for_text_edit("13.0.3"), "13.0.3");
    }

    #[test]
    fn test_package_url() {
        let f = NuGetFormatter;
        assert_eq!(
            f.package_url("Newtonsoft.Json"),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
    }

    #[test]
    fn test_version_satisfies_exact_pin() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_bare_floor() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("2.0.0", "1.0.0"));
        assert!(!f.version_satisfies_requirement("0.9.0", "1.0.0"));
    }

    #[test]
    fn test_version_satisfies_floating() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("1.1.5", "1.1.*"));
        assert!(!f.version_satisfies_requirement("1.2.0", "1.1.*"));
    }

    #[test]
    fn test_normalize_lowercases() {
        let f = NuGetFormatter;
        assert_eq!(
            f.normalize_package_name("Newtonsoft.Json"),
            "newtonsoft.json"
        );
    }
}

//! Version formatting for Bundler ecosystem.

use crate::version::version_matches_requirement;
use deps_core::lsp_helpers::EcosystemFormatter;

/// Formatter for Bundler/Ruby gem versions.
pub struct BundlerFormatter;

impl EcosystemFormatter for BundlerFormatter {
    fn format_version_for_code_action(&self, version: &str) -> String {
        format!("'{version}'")
    }

    fn package_url(&self, name: &str) -> String {
        format!("https://rubygems.org/gems/{name}")
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version_matches_requirement(version, requirement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = BundlerFormatter;
        assert_eq!(formatter.format_version_for_code_action("7.0.8"), "'7.0.8'");
        assert_eq!(formatter.format_version_for_code_action("1.0.0"), "'1.0.0'");
    }

    #[test]
    fn test_package_url() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.package_url("rails"),
            "https://rubygems.org/gems/rails"
        );
        assert_eq!(
            formatter.package_url("nokogiri"),
            "https://rubygems.org/gems/nokogiri"
        );
    }

    #[test]
    fn test_pessimistic_operator() {
        let formatter = BundlerFormatter;

        // ~> 7.0 means >= 7.0, < 8.0
        assert!(formatter.version_satisfies_requirement("7.0.8", "~> 7.0"));
        assert!(formatter.version_satisfies_requirement("7.0.0", "~> 7.0"));
        assert!(formatter.version_satisfies_requirement("7.9.9", "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement("8.0.0", "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement("6.9.9", "~> 7.0"));

        // ~> 1.0.5 means >= 1.0.5, < 1.1.0
        assert!(formatter.version_satisfies_requirement("1.0.5", "~> 1.0.5"));
        assert!(formatter.version_satisfies_requirement("1.0.9", "~> 1.0.5"));
        assert!(!formatter.version_satisfies_requirement("1.1.0", "~> 1.0.5"));
        assert!(!formatter.version_satisfies_requirement("1.0.4", "~> 1.0.5"));
    }

    #[test]
    fn test_comparison_operators() {
        let formatter = BundlerFormatter;

        // >= operator
        assert!(formatter.version_satisfies_requirement("1.5.0", ">= 1.1"));
        assert!(formatter.version_satisfies_requirement("1.1.0", ">= 1.1"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", ">= 1.1"));

        // > operator
        assert!(formatter.version_satisfies_requirement("2.0.0", "> 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "> 1.0"));

        // <= operator
        assert!(formatter.version_satisfies_requirement("1.0.0", "<= 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.1.0", "<= 1.0"));

        // < operator
        assert!(formatter.version_satisfies_requirement("0.9.0", "< 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "< 1.0"));
    }

    #[test]
    fn test_exact_match() {
        let formatter = BundlerFormatter;

        assert!(formatter.version_satisfies_requirement("1.0.0", "= 1.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.1", "= 1.0.0"));

        assert!(formatter.version_satisfies_requirement("1.0.1", "!= 1.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "!= 1.0.0"));
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = BundlerFormatter;
        assert_eq!(formatter.normalize_package_name("rails"), "rails");
        assert_eq!(
            formatter.normalize_package_name("rspec-rails"),
            "rspec-rails"
        );
    }
}

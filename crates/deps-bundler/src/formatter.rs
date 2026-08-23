//! Version formatting for Bundler ecosystem.

use crate::version::version_matches_requirement;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};

/// Rubygems requirement matcher, compiled once per dependency by
/// [`BundlerFormatter::compile_requirement`]. `version_matches_requirement` is a hand-rolled
/// comparator with no external parser to fail on, so this always decides (`Some`).
struct RubygemsMatcher(String);

impl RequirementMatcher for RubygemsMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        Some(version_matches_requirement(version, &self.0))
    }
}

/// A Bundler requirement written as `= X` or bare `X` (no operator) pins a
/// single exact version. RubyGems' `versions.json` endpoint omits yanked
/// entries from the result entirely rather than flagging them — verified
/// live: `rest-client` lists `1.6.9`/`1.6.14` but not the yanked
/// `1.6.10`-`1.6.13`. Every other requirement-shape guard in this codebase
/// (Go pseudo-versions, Composer dev branches) works because the excluded
/// category is detectable from the requirement text; here it isn't — an
/// exact pin that only ever matched a now-yanked version is
/// indistinguishable, from `available` alone, from one that was never
/// published. Per plan §1.3 a yanked-only match counts as satisfied (no
/// diagnostic), so this shape can't be scanned reliably and is suppressed
/// rather than risk a false "no published version satisfies" warning. Wider
/// requirement shapes (`~>`, `>=`, ranges) are left alone: they typically
/// span many versions, so a match existing only among yanked ones is a rare
/// edge case rather than the common one exact pins hit.
fn is_exact_pin(requirement: &str) -> bool {
    let req = requirement.trim();
    if req.is_empty() || req == "*" {
        return false;
    }
    if let Some(rest) = req.strip_prefix('=') {
        return !rest.trim().is_empty();
    }
    !["~>", ">=", ">", "<=", "<", "!="]
        .iter()
        .any(|op| req.starts_with(op))
}

/// Formatter for Bundler/Ruby gem versions.
pub struct BundlerFormatter;

impl EcosystemFormatter for BundlerFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::gem_url(name.as_str())
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version_matches_requirement(version, requirement)
    }

    /// Compiles `requirement` into a `RubygemsMatcher` using the same
    /// `version_matches_requirement` comparator as `version_satisfies_requirement` — Bundler
    /// requirements have no separate "loose" vs. "precise" form to distinguish.
    /// Returns `None` for an exact-pin requirement (see `is_exact_pin`): those can silently
    /// match nothing but a yanked version, which `available` cannot reveal.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        if is_exact_pin(requirement.as_str()) {
            return None;
        }
        Some(Box::new(RubygemsMatcher(requirement.as_str().to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = BundlerFormatter;
        assert_eq!(formatter.format_version_for_text_edit("7.0.8"), "7.0.8");
        assert_eq!(formatter.format_version_for_text_edit("1.0.0"), "1.0.0");
    }

    #[test]
    fn test_package_url() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("rails")),
            "https://rubygems.org/gems/rails"
        );
        assert_eq!(
            formatter.package_url(&PackageName::new("nokogiri")),
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
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("rails")),
            "rails"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("rspec-rails")),
            "rspec-rails"
        );
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = BundlerFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("~> 7.0"))
            .expect("Bundler requirement always compiles");
        assert_eq!(matcher.matches("7.0.8"), Some(true));
        assert_eq!(matcher.matches("8.0.0"), Some(false));
    }

    /// S5 regression: an exact pin can silently only match a yanked (and thus invisible)
    /// version — the whole scan must be suppressed rather than falsely reported unsatisfiable.
    #[test]
    fn test_compile_requirement_bare_exact_pin_returns_none() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("1.6.13"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_equals_prefix_pin_returns_none() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("= 1.6.13"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_wildcard_still_compiles() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("*"))
                .is_some()
        );
    }

    #[test]
    fn test_compile_requirement_range_forms_still_compile() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new(">= 1.1"))
                .is_some()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("!= 1.0.0"))
                .is_some()
        );
    }

    #[test]
    fn test_is_exact_pin() {
        assert!(is_exact_pin("1.6.13"));
        assert!(is_exact_pin("= 1.6.13"));
        assert!(!is_exact_pin("*"));
        assert!(!is_exact_pin(""));
        assert!(!is_exact_pin("~> 7.0"));
        assert!(!is_exact_pin(">= 1.1"));
        assert!(!is_exact_pin("!= 1.0.0"));
    }
}

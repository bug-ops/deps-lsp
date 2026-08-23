//! Version formatting for Dart ecosystem.

use crate::version::version_matches_constraint;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};

/// pub.dev constraint matcher, compiled once per dependency by
/// [`DartFormatter::compile_requirement`]. `version_matches_constraint` is a hand-rolled
/// comparator with no external parser to fail on, so this always decides (`Some`).
struct PubDevMatcher(String);

impl RequirementMatcher for PubDevMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        Some(version_matches_constraint(version, &self.0))
    }
}

pub struct DartFormatter;

impl EcosystemFormatter for DartFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        format!("^{version}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version_matches_constraint(version, requirement)
    }

    /// Compiles `requirement` into a `PubDevMatcher` using the same
    /// `version_matches_constraint` comparator as `version_satisfies_requirement` — Dart
    /// constraints have no separate "loose" vs. "precise" form to distinguish.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(PubDevMatcher(requirement.as_str().to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = DartFormatter;
        assert_eq!(f.format_version_for_text_edit("1.0.0"), "^1.0.0");
        assert_eq!(f.format_version_for_text_edit("6.1.2"), "^6.1.2");
    }

    #[test]
    fn test_package_url() {
        let f = DartFormatter;
        assert_eq!(
            f.package_url(&PackageName::new("provider")),
            "https://pub.dev/packages/provider"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let f = DartFormatter;
        assert!(f.version_satisfies_requirement("1.5.0", "^1.0.0"));
        assert!(!f.version_satisfies_requirement("2.0.0", "^1.0.0"));
    }

    #[test]
    fn test_normalize_is_identity() {
        let f = DartFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("flutter_bloc")),
            "flutter_bloc"
        );
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let f = DartFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .expect("Dart requirement always compiles");
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }
}

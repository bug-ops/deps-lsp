//! Version formatting for Dart ecosystem.

use crate::version::{version_matches_constraint, version_matches_normalized_constraint};
use deps_core::ConcreteVersion;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};
use deps_core::normalize_operator_spacing;

/// Whether `name` is a valid Dart identifier: pub.dev requires every package name to be one,
/// per <https://dart.dev/tools/pub/pubspec#name> — ASCII letters/digits/`_` only, starting
/// with a letter or `_` (never a digit).
fn is_valid_dart_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// pub.dev constraint matcher, compiled once per dependency by
/// [`DartFormatter::compile_requirement`]. Holds the requirement already run through
/// [`normalize_operator_spacing`] so per-candidate matching never re-normalizes or
/// allocates. `version_matches_normalized_constraint` is a hand-rolled comparator with no
/// external parser to fail on, so this always decides (`Some`).
struct PubDevMatcher(String);

impl RequirementMatcher for PubDevMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Some(version_matches_normalized_constraint(version, &self.0))
    }
}

pub struct DartFormatter;

impl EcosystemFormatter for DartFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        format!("^{version}")
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// Lints `name` against pub.dev's rule that every package name must be a valid Dart
    /// identifier (see `is_valid_dart_identifier`), so a structurally invalid name is
    /// reported as "Invalid package name" instead of falling through to a registry lookup
    /// and rendering the generic "Registry lookup failed" diagnostic (#402).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, starts with a digit, or contains a
    /// character other than an ASCII letter, digit, or `_`.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if !is_valid_dart_identifier(name) {
            return Err(InvalidPackageName::new(
                "name must be a valid Dart identifier: only ASCII letters, digits, and '_', not starting with a digit",
            ));
        }
        Ok(())
    }

    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        version_matches_constraint(version, requirement)
    }

    /// Compiles `requirement` into a `PubDevMatcher` using the same comparator as
    /// `version_satisfies_requirement` — Dart constraints have no separate "loose" vs.
    /// "precise" form to distinguish. Spaced-operator normalization runs once here, not
    /// per candidate version.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        let normalized = normalize_operator_spacing(requirement.as_str().trim()).into_owned();
        Some(Box::new(PubDevMatcher(normalized)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = DartFormatter;
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("1.0.0")),
            "^1.0.0"
        );
        assert_eq!(
            f.format_version_for_text_edit(&ConcreteVersion::new("6.1.2")),
            "^6.1.2"
        );
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
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.0.0"));
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
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_spaced_range() {
        let f = DartFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new(">= 1.15.0 < 2.0.0"))
            .expect("Dart requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.15.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.99.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.14.0")),
            Some(false)
        );
    }

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let f = DartFormatter;
        for name in ["provider", "flutter_bloc", "_private", "path9"] {
            assert!(
                f.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402: a structurally invalid Dart package name must be reported as an invalid package
    /// name, not forwarded to the registry lookup that produces the misleading generic
    /// diagnostic.
    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let f = DartFormatter;
        for name in ["", "9path", "my-package", "my package", "日本語"] {
            assert!(
                f.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }
}

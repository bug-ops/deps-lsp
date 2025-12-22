//! Version requirement matching abstractions.
//!
//! Provides traits and implementations for version requirement matching
//! across different package ecosystems (semver, PEP 440, etc.).

use semver::Version;

/// Generic version requirement matcher.
///
/// Each ecosystem implements this to provide version matching logic.
/// Used by handlers to determine if a dependency is up-to-date.
pub trait VersionRequirementMatcher: Send + Sync {
    /// Check if the latest available version satisfies the requirement.
    ///
    /// Returns true if the dependency is "up to date" within its constraint.
    ///
    /// # Examples
    ///
    /// For Cargo/npm (semver):
    /// - `"^1.0.0"` with latest `"1.5.0"` → true (satisfies ^1.0.0)
    /// - `"^1.0.0"` with latest `"2.0.0"` → false (new major version)
    ///
    /// For PyPI (PEP 440):
    /// - `">=8.0"` with latest `"8.3.5"` → true (same major version)
    /// - `">=8.0"` with latest `"9.0.0"` → false (new major version)
    fn is_latest_satisfying(&self, requirement: &str, latest: &str) -> bool;
}

/// Semver-based version matcher for Cargo and npm.
///
/// Uses the semver crate to match version requirements.
/// Handles caret (^) and tilde (~) requirements according to semver semantics.
#[derive(Debug, Clone, Copy)]
pub struct SemverMatcher;

impl VersionRequirementMatcher for SemverMatcher {
    fn is_latest_satisfying(&self, requirement: &str, latest: &str) -> bool {
        use semver::VersionReq;

        // Parse the latest version
        let latest_ver = match latest.parse::<Version>() {
            Ok(v) => v,
            Err(_) => return requirement == latest,
        };

        // Try to parse as a semver requirement (handles ^, ~, =, etc.)
        if let Ok(req) = requirement.parse::<VersionReq>() {
            return req.matches(&latest_ver);
        }

        // If not a valid requirement, try treating it as a caret requirement
        // (Cargo's default: "1.0" means "^1.0")
        if let Ok(req) = format!("^{}", requirement).parse::<VersionReq>() {
            return req.matches(&latest_ver);
        }

        // Fallback: string comparison
        requirement == latest
    }
}

/// PEP 440 version matcher for PyPI dependencies.
///
/// Implements major version comparison strategy:
/// - For versions >= 1.0: compares major version only
/// - For versions 0.x: compares major and minor version
///
/// This matches the typical Python ecosystem convention where breaking
/// changes happen on major version bumps (or minor bumps for 0.x versions).
#[derive(Debug, Clone, Copy)]
pub struct Pep440Matcher;

impl VersionRequirementMatcher for Pep440Matcher {
    fn is_latest_satisfying(&self, requirement: &str, latest: &str) -> bool {
        // Parse the latest version (normalize to three parts if needed)
        let latest_ver = match normalize_and_parse_version(latest) {
            Some(v) => v,
            None => return requirement == latest,
        };

        // Extract the minimum version from the requirement
        // Common patterns: ">=1.0", ">=1.0,<2.0", "~=1.0", "==1.0"
        let min_version = extract_pypi_min_version(requirement);

        let min_ver = match min_version.and_then(|v| normalize_and_parse_version(&v)) {
            Some(v) => v,
            None => return requirement == latest,
        };

        // Check if major versions match (for major version 0, also check minor)
        if min_ver.major == 0 {
            // For 0.x versions, both major and minor must match
            min_ver.major == latest_ver.major && min_ver.minor == latest_ver.minor
        } else {
            // For 1.x+, just major version must match
            min_ver.major == latest_ver.major
        }
    }
}

/// Normalize a version string and parse it as semver.
///
/// Adds missing patch version if needed (e.g., "8.0" → "8.0.0").
///
/// # Examples
///
/// ```
/// # use deps_core::version_matcher::normalize_and_parse_version;
/// assert_eq!(normalize_and_parse_version("1.0.0").unwrap().to_string(), "1.0.0");
/// assert_eq!(normalize_and_parse_version("1.0").unwrap().to_string(), "1.0.0");
/// assert_eq!(normalize_and_parse_version("8").unwrap().to_string(), "8.0.0");
/// ```
pub fn normalize_and_parse_version(version: &str) -> Option<Version> {
    // Try parsing directly first
    if let Ok(v) = version.parse::<Version>() {
        return Some(v);
    }

    // Count dots to see if we need to add patch version
    let dot_count = version.chars().filter(|&c| c == '.').count();

    let normalized = match dot_count {
        0 => format!("{}.0.0", version), // "8" → "8.0.0"
        1 => format!("{}.0", version),   // "8.0" → "8.0.0"
        _ => version.to_string(),
    };

    normalized.parse::<Version>().ok()
}

/// Extract the minimum version number from a PEP 440 version specifier.
///
/// # Examples
///
/// ```
/// # use deps_core::version_matcher::extract_pypi_min_version;
/// assert_eq!(extract_pypi_min_version(">=8.0"), Some("8.0".to_string()));
/// assert_eq!(extract_pypi_min_version(">=1.0,<2.0"), Some("1.0".to_string()));
/// assert_eq!(extract_pypi_min_version("~=1.4.2"), Some("1.4.2".to_string()));
/// assert_eq!(extract_pypi_min_version("==2.0.0"), Some("2.0.0".to_string()));
/// ```
pub fn extract_pypi_min_version(version_req: &str) -> Option<String> {
    // Split by comma and look for >= or ~= or == specifiers
    for part in version_req.split(',') {
        let trimmed = part.trim();

        // Handle different operators
        if let Some(ver) = trimmed.strip_prefix(">=") {
            return Some(ver.trim().to_string());
        }
        if let Some(ver) = trimmed.strip_prefix("~=") {
            return Some(ver.trim().to_string());
        }
        if let Some(ver) = trimmed.strip_prefix("==") {
            return Some(ver.trim().to_string());
        }
        if let Some(ver) = trimmed.strip_prefix('>') {
            // > means strictly greater, but we use this as approximation
            return Some(ver.trim().to_string());
        }
    }

    // If no operator found, try parsing the whole string as a version
    // (handles Poetry's "^1.0" style by stripping the ^)
    let stripped = version_req.trim_start_matches('^').trim_start_matches('~');
    if stripped.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Some(stripped.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_matcher_exact_match() {
        let matcher = SemverMatcher;
        assert!(matcher.is_latest_satisfying("1.0.0", "1.0.0"));
        assert!(matcher.is_latest_satisfying("^1.0.0", "1.0.0"));
        assert!(matcher.is_latest_satisfying("~1.0.0", "1.0.0"));
        assert!(matcher.is_latest_satisfying("=1.0.0", "1.0.0"));
    }

    #[test]
    fn test_semver_matcher_compatible_versions() {
        let matcher = SemverMatcher;
        // Latest version satisfies the requirement (up-to-date)
        assert!(matcher.is_latest_satisfying("1.0.0", "1.0.5")); // ^1.0.0 allows 1.0.5
        assert!(matcher.is_latest_satisfying("^1.0.0", "1.5.0")); // ^1.0.0 allows 1.5.0
        assert!(matcher.is_latest_satisfying("0.1", "0.1.83")); // ^0.1 allows 0.1.83
        assert!(matcher.is_latest_satisfying("1", "1.5.0")); // ^1 allows 1.5.0
    }

    #[test]
    fn test_semver_matcher_incompatible_versions() {
        let matcher = SemverMatcher;
        // Latest version doesn't satisfy requirement (new major available)
        assert!(!matcher.is_latest_satisfying("1.0.0", "2.0.0")); // 2.0.0 breaks ^1.0.0
        assert!(!matcher.is_latest_satisfying("0.1", "0.2.0")); // 0.2.0 breaks ^0.1
        assert!(!matcher.is_latest_satisfying("~1.0.0", "1.1.0")); // ~1.0.0 doesn't allow 1.1.0
    }

    #[test]
    fn test_pep440_matcher_same_major() {
        let matcher = Pep440Matcher;
        // Same major version = up to date
        assert!(matcher.is_latest_satisfying(">=8.0", "8.3.5")); // 8.x matches 8.x
        assert!(matcher.is_latest_satisfying(">=1.0", "1.5.0")); // 1.x matches 1.x
        assert!(matcher.is_latest_satisfying(">=1.0,<2.0", "1.9.0")); // constrained but same major
    }

    #[test]
    fn test_pep440_matcher_new_major() {
        let matcher = Pep440Matcher;
        // New major version available = needs update
        assert!(!matcher.is_latest_satisfying(">=8.0", "9.0.2")); // 8.x vs 9.x
        assert!(!matcher.is_latest_satisfying(">=1.0", "2.0.0")); // 1.x vs 2.x
        assert!(!matcher.is_latest_satisfying(">=4.0,<8.0", "8.0.0")); // 4.x vs 8.x
    }

    #[test]
    fn test_pep440_matcher_zero_version() {
        let matcher = Pep440Matcher;
        // For 0.x versions, minor must also match
        assert!(matcher.is_latest_satisfying(">=0.8", "0.8.5")); // 0.8.x matches 0.8.x
        assert!(!matcher.is_latest_satisfying(">=0.8", "0.9.0")); // 0.8.x vs 0.9.x
    }

    #[test]
    fn test_extract_pypi_min_version() {
        assert_eq!(extract_pypi_min_version(">=8.0"), Some("8.0".to_string()));
        assert_eq!(
            extract_pypi_min_version(">=1.0,<2.0"),
            Some("1.0".to_string())
        );
        assert_eq!(
            extract_pypi_min_version("~=1.4.2"),
            Some("1.4.2".to_string())
        );
        assert_eq!(
            extract_pypi_min_version("==2.0.0"),
            Some("2.0.0".to_string())
        );
        assert_eq!(extract_pypi_min_version("^1.0"), Some("1.0".to_string())); // Poetry style
        assert_eq!(extract_pypi_min_version(">1.0"), Some("1.0".to_string()));
    }

    #[test]
    fn test_normalize_and_parse_version() {
        assert_eq!(
            normalize_and_parse_version("1.0.0").unwrap().to_string(),
            "1.0.0"
        );
        assert_eq!(
            normalize_and_parse_version("1.0").unwrap().to_string(),
            "1.0.0"
        );
        assert_eq!(
            normalize_and_parse_version("8").unwrap().to_string(),
            "8.0.0"
        );
        assert!(normalize_and_parse_version("invalid").is_none());
    }
}

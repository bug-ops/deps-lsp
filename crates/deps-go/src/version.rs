//! Version parsing and module path utilities for Go modules.

use crate::error::{GoError, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use std::cmp::Ordering;

/// Escapes a Go module path for proxy.golang.org API requests.
///
/// Rules:
/// - Uppercase letters → `!lowercase` (e.g., `User` → `!user`)
/// - Special characters percent-encoded (RFC 3986)
///
/// # Examples
///
/// ```
/// use deps_go::escape_module_path;
///
/// assert_eq!(
///     escape_module_path("github.com/User/Repo"),
///     "github.com/!user/!repo"
/// );
/// ```
pub fn escape_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() + 10);

    for c in path.chars() {
        if c.is_uppercase() {
            result.push('!');
            result.push(c.to_ascii_lowercase());
        } else if c.is_ascii_alphanumeric()
            || c == '/'
            || c == '-'
            || c == '.'
            || c == '_'
            || c == '~'
        {
            result.push(c);
        } else {
            // Encode each byte of the UTF-8 representation
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            for &byte in encoded.as_bytes() {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }

    result
}

/// Checks if a version string is a pseudo-version.
///
/// Pseudo-version format: `vX.Y.Z-yyyymmddhhmmss-abcdefabcdef`
///
/// # Examples
///
/// ```
/// use deps_go::is_pseudo_version;
///
/// assert!(is_pseudo_version("v0.0.0-20191109021931-daa7c04131f5"));
/// assert!(!is_pseudo_version("v1.2.3"));
/// ```
pub fn is_pseudo_version(version: &str) -> bool {
    static PSEUDO_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+.*)?$").unwrap()
    });

    PSEUDO_REGEX.is_match(version)
}

/// Extracts the base version from a pseudo-version.
///
/// # Examples
///
/// ```
/// use deps_go::base_version_from_pseudo;
///
/// assert_eq!(
///     base_version_from_pseudo("v1.2.4-0.20191109021931-daa7c04131f5"),
///     Some("v1.2.3".to_string())
/// );
/// ```
pub fn base_version_from_pseudo(pseudo: &str) -> Option<String> {
    if !is_pseudo_version(pseudo) {
        return None;
    }

    let parts: Vec<&str> = pseudo.split('-').collect();
    if parts.len() < 3 {
        return None;
    }

    let version_part = parts[0];
    let pre_release_part = parts[1];

    if pre_release_part.starts_with('0') {
        let semver = version_part.strip_prefix('v')?;
        let mut components: Vec<u32> = semver.split('.').filter_map(|s| s.parse().ok()).collect();
        if components.len() == 3 && components[2] > 0 {
            components[2] -= 1;
            return Some(format!(
                "v{}.{}.{}",
                components[0], components[1], components[2]
            ));
        }
    }

    Some(version_part.to_string())
}

/// Compares two Go versions using semantic versioning rules.
///
/// # Pseudo-version Handling
///
/// Pseudo-versions (e.g., `v0.0.0-20191109021931-daa7c04131f5`) are compared
/// by their base version. For example, `v1.2.4-0.20191109021931-xxx` is treated
/// as being based on `v1.2.3`.
///
/// # Incompatible Suffix
///
/// The `+incompatible` suffix is stripped before comparison.
///
/// # Returns
///
/// - `Ordering::Less` if v1 < v2
/// - `Ordering::Equal` if v1 == v2
/// - `Ordering::Greater` if v1 > v2
///
/// # Examples
///
/// ```
/// use deps_go::compare_versions;
/// use std::cmp::Ordering;
///
/// assert_eq!(compare_versions("v1.0.0", "v2.0.0"), Ordering::Less);
/// assert_eq!(compare_versions("v2.0.0+incompatible", "v2.0.0"), Ordering::Equal);
/// ```
pub fn compare_versions(v1: &str, v2: &str) -> Ordering {
    let clean1 = v1.trim_start_matches('v').replace("+incompatible", "");
    let clean2 = v2.trim_start_matches('v').replace("+incompatible", "");

    let cmp1 = if is_pseudo_version(v1) {
        base_version_from_pseudo(v1).unwrap_or(clean1.clone())
    } else {
        clean1.clone()
    };

    let cmp2 = if is_pseudo_version(v2) {
        base_version_from_pseudo(v2).unwrap_or(clean2.clone())
    } else {
        clean2.clone()
    };

    match (parse_semver(&cmp1), parse_semver(&cmp2)) {
        (Ok(ver1), Ok(ver2)) => ver1.cmp(&ver2),
        _ => v1.cmp(v2),
    }
}

fn parse_semver(version: &str) -> Result<semver::Version> {
    let cleaned = version.trim_start_matches('v');

    let split_at_prerelease = cleaned.split('-').next().unwrap_or(cleaned);

    semver::Version::parse(split_at_prerelease).map_err(|e| GoError::InvalidVersionSpecifier {
        specifier: version.to_string(),
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_module_path() {
        assert_eq!(
            escape_module_path("github.com/User/Repo"),
            "github.com/!user/!repo"
        );
        assert_eq!(
            escape_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
        assert_eq!(
            escape_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_escape_module_path_multiple_uppercase() {
        assert_eq!(
            escape_module_path("github.com/MyUser/MyRepo"),
            "github.com/!my!user/!my!repo"
        );
    }

    #[test]
    fn test_is_pseudo_version() {
        assert!(is_pseudo_version("v0.0.0-20191109021931-daa7c04131f5"));
        assert!(is_pseudo_version("v1.2.4-0.20191109021931-daa7c04131f5"));
        assert!(!is_pseudo_version("v1.2.3"));
        assert!(!is_pseudo_version("v1.2.3-beta.1"));
    }

    #[test]
    fn test_is_pseudo_version_with_incompatible() {
        assert!(is_pseudo_version(
            "v2.0.1-0.20191109021931-daa7c04131f5+incompatible"
        ));
    }

    #[test]
    fn test_base_version_from_pseudo() {
        assert_eq!(
            base_version_from_pseudo("v1.2.4-0.20191109021931-daa7c04131f5"),
            Some("v1.2.3".to_string())
        );
        assert_eq!(
            base_version_from_pseudo("v0.0.0-20191109021931-daa7c04131f5"),
            Some("v0.0.0".to_string())
        );
    }

    #[test]
    fn test_base_version_from_pseudo_invalid() {
        assert_eq!(base_version_from_pseudo("v1.2.3"), None);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("v1.0.0", "v2.0.0"), Ordering::Less);
        assert_eq!(compare_versions("v1.2.3", "v1.2.3"), Ordering::Equal);
        assert_eq!(compare_versions("v2.0.0", "v1.0.0"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_patch() {
        assert_eq!(compare_versions("v1.2.3", "v1.2.4"), Ordering::Less);
        assert_eq!(compare_versions("v1.2.5", "v1.2.4"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_minor() {
        assert_eq!(compare_versions("v1.2.0", "v1.3.0"), Ordering::Less);
        assert_eq!(compare_versions("v1.5.0", "v1.3.0"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_incompatible() {
        assert_eq!(
            compare_versions("v2.0.0+incompatible", "v2.1.0+incompatible"),
            Ordering::Less
        );
    }

    #[test]
    fn test_parse_semver_valid() {
        assert!(parse_semver("1.2.3").is_ok());
        assert!(parse_semver("v1.2.3").is_ok());
    }

    #[test]
    fn test_parse_semver_invalid() {
        assert!(parse_semver("invalid").is_err());
        assert!(parse_semver("v1.2").is_err());
    }

    #[test]
    fn test_pseudo_regex_compiles() {
        let _ = is_pseudo_version("v0.0.0-20191109021931-daa7c04131f5");
    }
}

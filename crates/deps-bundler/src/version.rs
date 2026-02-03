//! Version comparison utilities for Ruby gems.
//!
//! Provides version comparison and requirement matching for Bundler ecosystem.

use std::cmp::Ordering;

/// Compares two version strings numerically.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let a_parts: Vec<u64> = a
        .split('.')
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
        .filter_map(|p| p.parse().ok())
        .collect();
    let b_parts: Vec<u64> = b
        .split('.')
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
        .filter_map(|p| p.parse().ok())
        .collect();

    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let ap = a_parts.get(i).copied().unwrap_or(0);
        let bp = b_parts.get(i).copied().unwrap_or(0);
        match ap.cmp(&bp) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Checks if a version matches the given requirement.
pub fn version_matches_requirement(version: &str, requirement: &str) -> bool {
    let req = requirement.trim();

    // Pessimistic operator (~>)
    if req.starts_with("~>") {
        let req_ver = req.trim_start_matches("~>").trim();
        return matches_pessimistic(version, req_ver);
    }

    // Greater than or equal
    if req.starts_with(">=") {
        let req_ver = req.trim_start_matches(">=").trim();
        return compare_versions(version, req_ver) != Ordering::Less;
    }

    // Greater than
    if req.starts_with('>') && !req.starts_with(">=") {
        let req_ver = req.trim_start_matches('>').trim();
        return compare_versions(version, req_ver) == Ordering::Greater;
    }

    // Less than or equal
    if req.starts_with("<=") {
        let req_ver = req.trim_start_matches("<=").trim();
        return compare_versions(version, req_ver) != Ordering::Greater;
    }

    // Less than
    if req.starts_with('<') && !req.starts_with("<=") {
        let req_ver = req.trim_start_matches('<').trim();
        return compare_versions(version, req_ver) == Ordering::Less;
    }

    // Not equal
    if req.starts_with("!=") {
        let req_ver = req.trim_start_matches("!=").trim();
        return version != req_ver;
    }

    // Exact match
    if let Some(req_ver) = req.strip_prefix('=') {
        return version == req_ver.trim();
    }

    // Default: exact match or prefix match
    version == req || version.starts_with(&format!("{req}."))
}

/// Checks if a version matches a pessimistic requirement (~>).
fn matches_pessimistic(version: &str, requirement: &str) -> bool {
    let req_parts: Vec<&str> = requirement.split('.').collect();
    let ver_parts: Vec<&str> = version.split('.').collect();

    if ver_parts.len() < req_parts.len() {
        return false;
    }

    // All parts except the last must match exactly
    for i in 0..(req_parts.len().saturating_sub(1)) {
        let req_part = req_parts
            .get(i)
            .and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next());
        let ver_part = ver_parts
            .get(i)
            .and_then(|p| p.split(|c: char| !c.is_ascii_digit()).next());
        if req_part != ver_part {
            return false;
        }
    }

    // Last part of version must be >= last part of requirement
    let last_idx = req_parts.len() - 1;
    let req_last: u64 = req_parts[last_idx]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let ver_last: u64 = ver_parts
        .get(last_idx)
        .and_then(|v| v.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);

    ver_last >= req_last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn test_matches_pessimistic() {
        // ~> 1.0 means >= 1.0, < 2.0
        assert!(matches_pessimistic("1.0.5", "1.0"));
        assert!(matches_pessimistic("1.0.0", "1.0"));
        assert!(matches_pessimistic("1.9.9", "1.0"));
        assert!(!matches_pessimistic("2.0.0", "1.0"));

        // ~> 1.0.5 means >= 1.0.5, < 1.1.0
        assert!(matches_pessimistic("1.0.5", "1.0.5"));
        assert!(matches_pessimistic("1.0.9", "1.0.5"));
        assert!(!matches_pessimistic("1.1.0", "1.0.5"));
        assert!(!matches_pessimistic("1.0.4", "1.0.5"));
    }

    #[test]
    fn test_version_matches_requirement() {
        // Pessimistic operator
        assert!(version_matches_requirement("7.0.8", "~> 7.0"));
        assert!(version_matches_requirement("7.0.0", "~> 7.0"));
        assert!(!version_matches_requirement("8.0.0", "~> 7.0"));

        // Greater than or equal
        assert!(version_matches_requirement("1.5.0", ">= 1.1"));
        assert!(version_matches_requirement("1.1.0", ">= 1.1"));
        assert!(!version_matches_requirement("1.0.0", ">= 1.1"));

        // Greater than
        assert!(version_matches_requirement("2.0.0", "> 1.0"));
        assert!(!version_matches_requirement("1.0.0", "> 1.0"));

        // Less than or equal
        assert!(version_matches_requirement("1.0.0", "<= 1.0"));
        assert!(!version_matches_requirement("1.1.0", "<= 1.0"));

        // Less than
        assert!(version_matches_requirement("0.9.0", "< 1.0"));
        assert!(!version_matches_requirement("1.0.0", "< 1.0"));

        // Exact match
        assert!(version_matches_requirement("1.0.0", "= 1.0.0"));
        assert!(!version_matches_requirement("1.0.1", "= 1.0.0"));

        // Not equal
        assert!(version_matches_requirement("1.0.1", "!= 1.0.0"));
        assert!(!version_matches_requirement("1.0.0", "!= 1.0.0"));
    }
}

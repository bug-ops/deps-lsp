//! Version comparison and constraint matching for Dart packages.

use std::cmp::Ordering;

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

/// Checks if a version satisfies a Dart version constraint.
///
/// Supports: ^, >=, >, <=, <, exact, any, and space-separated AND constraints.
pub fn version_matches_constraint(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();

    if constraint.is_empty() || constraint == "any" || constraint == "*" {
        return true;
    }

    // Space-separated constraints are AND logic
    if constraint.contains(' ') && !constraint.starts_with('^') {
        return constraint
            .split_whitespace()
            .all(|c| match_single_constraint(version, c));
    }

    match_single_constraint(version, constraint)
}

fn match_single_constraint(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();

    if constraint.starts_with('^') {
        let req_ver = constraint.trim_start_matches('^');
        return matches_caret(version, req_ver);
    }

    if constraint.starts_with(">=") {
        let req_ver = constraint.trim_start_matches(">=").trim();
        return compare_versions(version, req_ver) != Ordering::Less;
    }

    if constraint.starts_with('>') {
        let req_ver = constraint.trim_start_matches('>').trim();
        return compare_versions(version, req_ver) == Ordering::Greater;
    }

    if constraint.starts_with("<=") {
        let req_ver = constraint.trim_start_matches("<=").trim();
        return compare_versions(version, req_ver) != Ordering::Greater;
    }

    if constraint.starts_with('<') {
        let req_ver = constraint.trim_start_matches('<').trim();
        return compare_versions(version, req_ver) == Ordering::Less;
    }

    // Exact match
    compare_versions(version, constraint) == Ordering::Equal
}

fn matches_caret(version: &str, requirement: &str) -> bool {
    let req_parts: Vec<u64> = requirement
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    let ver_parts: Vec<u64> = version
        .split('.')
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
        .filter_map(|p| p.parse().ok())
        .collect();

    if ver_parts.is_empty() || req_parts.is_empty() {
        return false;
    }

    if compare_versions(version, requirement) == Ordering::Less {
        return false;
    }

    let req_major = req_parts.first().copied().unwrap_or(0);
    let ver_major = ver_parts.first().copied().unwrap_or(0);

    if req_major == 0 {
        // ^0.x.y means >=0.x.y <0.(x+1).0
        let req_minor = req_parts.get(1).copied().unwrap_or(0);
        let ver_minor = ver_parts.get(1).copied().unwrap_or(0);
        ver_major == 0 && ver_minor == req_minor
    } else {
        // ^x.y.z means >=x.y.z <(x+1).0.0
        ver_major == req_major
    }
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
    }

    #[test]
    fn test_caret_constraint() {
        assert!(version_matches_constraint("1.0.0", "^1.0.0"));
        assert!(version_matches_constraint("1.5.0", "^1.0.0"));
        assert!(version_matches_constraint("1.99.99", "^1.0.0"));
        assert!(!version_matches_constraint("2.0.0", "^1.0.0"));
        assert!(!version_matches_constraint("0.9.0", "^1.0.0"));
    }

    #[test]
    fn test_caret_constraint_zero_major() {
        // ^0.1.0 means >=0.1.0 <0.2.0
        assert!(version_matches_constraint("0.1.0", "^0.1.0"));
        assert!(version_matches_constraint("0.1.5", "^0.1.0"));
        assert!(!version_matches_constraint("0.2.0", "^0.1.0"));
        assert!(!version_matches_constraint("0.99.0", "^0.1.0"));
        assert!(!version_matches_constraint("1.0.0", "^0.1.0"));
    }

    #[test]
    fn test_range_constraint() {
        assert!(version_matches_constraint("1.5.0", ">=1.0.0 <2.0.0"));
        assert!(version_matches_constraint("1.0.0", ">=1.0.0 <2.0.0"));
        assert!(!version_matches_constraint("2.0.0", ">=1.0.0 <2.0.0"));
        assert!(!version_matches_constraint("0.9.0", ">=1.0.0 <2.0.0"));
    }

    #[test]
    fn test_exact_constraint() {
        assert!(version_matches_constraint("1.0.0", "1.0.0"));
        assert!(!version_matches_constraint("1.0.1", "1.0.0"));
    }

    #[test]
    fn test_any_constraint() {
        assert!(version_matches_constraint("1.0.0", "any"));
        assert!(version_matches_constraint("99.0.0", "any"));
        assert!(version_matches_constraint("1.0.0", ""));
    }

    #[test]
    fn test_comparison_operators() {
        assert!(version_matches_constraint("1.5.0", ">=1.0.0"));
        assert!(version_matches_constraint("1.0.0", ">=1.0.0"));
        assert!(!version_matches_constraint("0.9.0", ">=1.0.0"));

        assert!(version_matches_constraint("2.0.0", ">1.0.0"));
        assert!(!version_matches_constraint("1.0.0", ">1.0.0"));

        assert!(version_matches_constraint("1.0.0", "<=1.0.0"));
        assert!(!version_matches_constraint("1.1.0", "<=1.0.0"));

        assert!(version_matches_constraint("0.9.0", "<1.0.0"));
        assert!(!version_matches_constraint("1.0.0", "<1.0.0"));
    }
}

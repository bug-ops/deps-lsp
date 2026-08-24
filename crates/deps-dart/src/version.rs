//! Version comparison and constraint matching for Dart packages.

use std::borrow::Cow;
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
    let constraint = normalize_operator_spacing(constraint.trim());
    version_matches_normalized_constraint(version, &constraint)
}

/// Same as [`version_matches_constraint`], but takes a constraint that has already been
/// run through [`normalize_operator_spacing`]. Callers that check many candidate versions
/// against the same constraint (e.g. a compiled [`RequirementMatcher`](deps_core::lsp_helpers::RequirementMatcher))
/// should normalize once and reuse it here instead of re-normalizing per candidate.
pub(crate) fn version_matches_normalized_constraint(version: &str, constraint: &str) -> bool {
    if constraint.is_empty() || constraint == "any" || constraint == "*" {
        return true;
    }

    // Space-separated constraints are AND logic (pub_semver intersects each comparator,
    // including a leading caret comparator combined with further clauses).
    if constraint.contains(' ') {
        return constraint
            .split_whitespace()
            .all(|c| match_single_constraint(version, c));
    }

    match_single_constraint(version, constraint)
}

/// Collapses whitespace between a range operator (`>=`, `<=`, `>`, `<`) and its version
/// number, e.g. `">= 1.15.0 < 2.0.0"` becomes `">=1.15.0 <2.0.0"`. Both forms are valid
/// pubspec constraint syntax, but leaving the space in place would make the later
/// whitespace-based AND split treat the operator and its version as separate clauses.
///
/// Borrows `constraint` unchanged when there is no spaced operator to collapse (the
/// common case) instead of always allocating — [`version_matches_constraint`] (the
/// uncompiled/loose matching path) calls this once per candidate version.
pub(crate) fn normalize_operator_spacing(constraint: &str) -> Cow<'_, str> {
    if !has_spaced_operator(constraint) {
        return Cow::Borrowed(constraint);
    }

    let mut result = String::with_capacity(constraint.len());
    let mut chars = constraint.chars().peekable();
    while let Some(c) = chars.next() {
        result.push(c);
        if c == '>' || c == '<' {
            if chars.peek() == Some(&'=') {
                result.push('=');
                chars.next();
            }
            while chars.peek().is_some_and(|ws| ws.is_whitespace()) {
                chars.next();
            }
        }
    }
    Cow::Owned(result)
}

/// Reports whether `constraint` contains a `>`/`<`/`>=`/`<=` operator immediately
/// followed by whitespace, i.e. whether [`normalize_operator_spacing`] would need to
/// allocate. Pure scan, no allocation, so the common no-op case stays cheap.
fn has_spaced_operator(constraint: &str) -> bool {
    let mut chars = constraint.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '>' || c == '<' {
            if chars.peek() == Some(&'=') {
                chars.next();
            }
            if chars.peek().is_some_and(|ws| ws.is_whitespace()) {
                return true;
            }
        }
    }
    false
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

/// Whether `version` has a semver 2.0.0 prerelease component.
///
/// Pub requires published versions to be strict semver, so any hyphen
/// preceding optional `+build` metadata reliably marks a prerelease —
/// unlike deps-core's default keyword-based heuristic, this also catches
/// conventions not in its fixed list, e.g. Dart's `nullsafety` preview tag
/// (`2.10.0-nullsafety.1`) (#322).
pub fn is_prerelease(version: &str) -> bool {
    version.split('+').next().unwrap_or(version).contains('-')
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
    fn test_is_prerelease() {
        assert!(!is_prerelease("1.0.0"));
        assert!(!is_prerelease("1.0.0+build.1"));
        assert!(is_prerelease("1.0.0-dev.1"));
        // Not in deps-core's default keyword list, but still a valid semver
        // prerelease tag.
        assert!(is_prerelease("2.10.0-nullsafety.1"));
        assert!(is_prerelease("1.0.0-nullsafety.1+build"));
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
    fn test_range_constraint_spaced_operators() {
        assert!(version_matches_constraint("1.15.0", ">= 1.15.0 < 2.0.0"));
        assert!(version_matches_constraint("1.99.0", ">= 1.15.0 < 2.0.0"));
        assert!(!version_matches_constraint("1.14.0", ">= 1.15.0 < 2.0.0"));
        assert!(!version_matches_constraint("2.0.0", ">= 1.15.0 < 2.0.0"));
    }

    #[test]
    fn test_caret_combined_with_spaced_upper_bound() {
        // pub_semver intersects space-separated comparators, so a caret comparator can be
        // combined with a further clause instead of split into garbage input.
        assert!(version_matches_constraint("1.5.0", "^1.0.0 < 2.0.0"));
        assert!(version_matches_constraint("1.99.0", "^1.0.0 < 2.0.0"));
        assert!(!version_matches_constraint("2.0.0", "^1.0.0 < 2.0.0"));
        assert!(!version_matches_constraint("0.9.0", "^1.0.0 < 2.0.0"));
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

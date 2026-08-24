//! Version comparison utilities for Ruby gems.
//!
//! Provides version comparison and requirement matching for Bundler ecosystem.

use std::cmp::Ordering;

/// A single alternating digit/letter run extracted from a version string.
#[derive(Clone, Copy)]
enum Token<'a> {
    /// A run of ASCII digits (e.g. the `10` in `beta10`), or a missing
    /// trailing run, treated as an implicit `0`.
    Numeric(u64),
    /// A run of ASCII letters (e.g. the `beta` in `beta10`).
    Alpha(&'a str),
}

/// Tokenizes `version` into alternating digit/letter runs, skipping
/// separators (`.`, `-`, `+`, ...).
///
/// RubyGems' own prerelease tags can be dot-separated (`3.7.0.pre1`) or
/// glued directly onto the preceding numeric segment (`0.2.19b1`) —
/// scanning the whole string instead of splitting on `.` first handles both
/// shapes uniformly (#323).
fn tokenize(version: &str) -> Vec<Token<'_>> {
    let bytes = version.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i].is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if let Ok(n) = version[start..i].parse::<u64>() {
                tokens.push(Token::Numeric(n));
            }
        } else if bytes[i].is_ascii_alphabetic() {
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            tokens.push(Token::Alpha(&version[start..i]));
        } else {
            i += 1;
        }
    }
    tokens
}

/// Compares two version strings, prerelease-aware.
///
/// Tokenizes both strings into alternating numeric/alpha runs (see
/// `tokenize`) and compares them run-wise: numeric runs compare
/// numerically, so `beta10` sorts after `beta2` rather than before it as a
/// lexicographic compare would; a missing trailing run is treated as an
/// implicit `0`, preserving `"1.0"` == `"1.0.0"`; and an alpha run never
/// outranks a numeric or implicit-zero run at the same position, so
/// `3.7.0` sorts newer than both `3.7.0.pre1` and the glued-tag `0.2.19b1`
/// (#323).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let a_tokens = tokenize(a);
    let b_tokens = tokenize(b);

    let max_len = a_tokens.len().max(b_tokens.len());
    for i in 0..max_len {
        let a_tok = a_tokens.get(i).copied().unwrap_or(Token::Numeric(0));
        let b_tok = b_tokens.get(i).copied().unwrap_or(Token::Numeric(0));

        let ordering = match (a_tok, b_tok) {
            (Token::Numeric(an), Token::Numeric(bn)) => an.cmp(&bn),
            (Token::Numeric(_), Token::Alpha(_)) => Ordering::Greater,
            (Token::Alpha(_), Token::Numeric(_)) => Ordering::Less,
            (Token::Alpha(a_str), Token::Alpha(b_str)) => a_str.cmp(b_str),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Checks if a version matches the given requirement.
pub fn version_matches_requirement(version: &str, requirement: &str) -> bool {
    let req = requirement.trim();

    if req == "*" {
        return true;
    }

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
    fn test_compare_versions_dot_notation_prerelease() {
        // Regression test for #323: a non-numeric trailing segment (RubyGems'
        // dot-notation prerelease tag) must not be silently dropped and tie
        // with the base release.
        assert_eq!(compare_versions("3.7.0", "3.7.0.pre1"), Ordering::Greater);
        assert_eq!(compare_versions("3.7.0.pre1", "3.7.0"), Ordering::Less);
        assert_ne!(compare_versions("3.7.0", "3.7.0.pre1"), Ordering::Equal);

        assert_eq!(compare_versions("3.7.0", "3.7.0.pre2"), Ordering::Greater);
        assert_ne!(compare_versions("3.7.0", "3.7.0.pre2"), Ordering::Equal);

        // pre1 and pre2 must not tie with each other either.
        assert_eq!(compare_versions("3.7.0.pre1", "3.7.0.pre2"), Ordering::Less);
        assert_ne!(
            compare_versions("3.7.0.pre1", "3.7.0.pre2"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_multi_digit_prerelease_ordinal() {
        // Regression test for critic finding S1: a lexicographic tie-break
        // mis-orders multi-digit ordinals ("beta10" < "beta2" as strings).
        // RubyGems compares the numeric run itself, so beta10 > beta2.
        assert_eq!(
            compare_versions("4.0.0.beta10", "4.0.0.beta2"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("4.0.0.beta2", "4.0.0.beta10"),
            Ordering::Less
        );
        assert_eq!(compare_versions("2.0.0.a10", "2.0.0.a9"), Ordering::Greater);
        assert_eq!(
            compare_versions("3.0.0.pre.beta10", "3.0.0.pre.beta2"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_glued_prerelease_tag() {
        // Regression test for critic finding S2: a prerelease tag glued
        // directly onto the trailing numeric segment (no separating dot)
        // must not be silently dropped and tie with the base release.
        assert_eq!(compare_versions("0.2.19", "0.2.19b1"), Ordering::Greater);
        assert_eq!(compare_versions("0.2.19b1", "0.2.19"), Ordering::Less);
        assert_ne!(compare_versions("0.2.19", "0.2.19b1"), Ordering::Equal);

        assert_eq!(compare_versions("0.2.19b1", "0.2.19b2"), Ordering::Less);
        assert_ne!(compare_versions("0.2.19b1", "0.2.19b2"), Ordering::Equal);

        assert_eq!(
            compare_versions("0.11.0pre220", "0.11.0pre229"),
            Ordering::Less
        );

        // Hyphenated tag (not dot- or glue-separated) must also not tie.
        assert_eq!(compare_versions("1.0.0", "1.0.0-beta"), Ordering::Greater);
        assert_ne!(compare_versions("1.0.0", "1.0.0-beta"), Ordering::Equal);
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

        // Wildcard
        assert!(version_matches_requirement("1.0.0", "*"));
        assert!(version_matches_requirement("0.0.1", "*"));
        assert!(version_matches_requirement("99.99.99", "*"));
    }
}

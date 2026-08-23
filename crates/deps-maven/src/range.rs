//! Maven version range parsing and containment ([Maven versioning spec][spec]).
//!
//! # Why this is hand-rolled
//!
//! No maintained Rust crate implements Maven's interval-notation range grammar. Unlike
//! NuGet (`deps-nuget`), Maven ranges may be a top-level comma-separated union of intervals
//! (`(,1.0),(1.2,)`), so this module owns the union-splitting; each individual interval is
//! parsed and matched by [`crate::interval`], shared with `deps-gradle`, which has the same
//! bracket-interval grammar but no top-level union.
//!
//! A bare (non-bracketed) requirement such as `"1.0"` is Maven's "soft" recommended version,
//! not a range, and is intentionally not handled here — see [`is_range`].
//!
//! [spec]: https://maven.apache.org/pom.html#dependency-version-requirement-specification

use crate::interval::{BracketStyle, VersionRange, contains, parse_interval};

/// Splits `s` on commas that are not nested inside a `[`/`(` ... `]`/`)` pair, so a
/// union like `[1.0,2.0),[3.0,4.0)` yields two members while the inner min/max comma of
/// a single member (handled by [`crate::interval::parse_interval`]) is left untouched.
fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Whether `requirement` looks like a Maven range/union, as opposed to a bare "soft"
/// recommended version (which is compared for plain equality by the caller).
pub fn is_range(requirement: &str) -> bool {
    requirement.trim_start().starts_with(['[', '('])
}

/// Parses a Maven range/union `requirement` into its union members, once.
///
/// `requirement` may be a single interval (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`) or a
/// top-level comma union of intervals (`(,1.0),(1.2,)`). Returns `None` if any member fails
/// to parse — a malformed union member indicates the whole `requirement` string is not the
/// range its author intended, so treating it as satisfied by the well-formed members alone
/// would be misleading, not just a missing feature.
///
/// Used by `MavenFormatter::compile_requirement` to parse the requirement once per
/// dependency; the resulting `Vec<VersionRange>` is then tested against each candidate
/// version via `satisfies_ranges` with no re-parsing.
pub(crate) fn parse_range(requirement: &str) -> Option<Vec<VersionRange>> {
    split_top_level(requirement.trim())
        .iter()
        .map(|member| parse_interval(member, BracketStyle::Standard))
        .collect()
}

/// Whether `version` falls inside any member of an already-parsed range union.
pub(crate) fn satisfies_ranges(version: &str, ranges: &[VersionRange]) -> bool {
    ranges.iter().any(|range| contains(version, range))
}

/// Checks whether `version` satisfies a Maven range `requirement`.
///
/// Convenience wrapper around `parse_range` + `satisfies_ranges` for callers that don't
/// need to test more than one candidate against the same requirement (unlike
/// `MavenFormatter::compile_requirement`, which parses once via `parse_range` and reuses it).
pub fn satisfies(version: &str, requirement: &str) -> bool {
    match parse_range(requirement) {
        Some(ranges) => satisfies_ranges(version, &ranges),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_range_detects_brackets() {
        assert!(is_range("[1.0,2.0)"));
        assert!(is_range("(1.0,2.0]"));
        assert!(is_range("  [1.0]"));
        assert!(!is_range("1.0"));
        assert!(!is_range("${property}"));
    }

    #[test]
    fn test_satisfies_bound_with_fewer_segments_than_version() {
        // #182: a bound with fewer segments than the version normalizes its
        // missing trailing segments as zero rather than rejecting the match.
        assert!(satisfies("4.1.0", "[4.0,4.1]"));
        assert!(satisfies("2.0.0", "(,2.0]"));
        assert!(satisfies("1.0.0", "[1.0]"));
        assert!(!satisfies("4.1.0", "[4.0,4.1)"));
        assert!(!satisfies("2.0.0", "(,2.0)"));
    }

    #[test]
    fn test_satisfies_bound_with_more_segments_than_version() {
        // The reverse case must also hold: a version with fewer segments
        // than the bound still matches when the missing segments are zero.
        assert!(satisfies("4.1", "[4.1.0,4.2]"));
        assert!(satisfies("2.0", "(,2.0.0]"));
        assert!(satisfies("1.0", "[1.0.0]"));
        assert!(!satisfies("4.1", "(4.1.0,4.2]"));
    }

    #[test]
    fn test_satisfies_three_way_union() {
        let req = "[1.0,2.0),[3.0,4.0),[5.0,)";
        assert!(satisfies("1.5", req));
        assert!(!satisfies("2.5", req));
        assert!(satisfies("3.5", req));
        assert!(!satisfies("4.5", req));
        assert!(satisfies("9.0", req));
    }

    #[test]
    fn test_satisfies_malformed_union_member_rejects_whole_requirement() {
        // A malformed member must not be silently dropped — the whole requirement is
        // rejected (fail-closed), even though the well-formed member(s) would otherwise
        // have matched.
        assert!(!satisfies("1.5", "[1.0,2.0),[3.0"));
        assert!(!satisfies("1.5", "[1.0,2.0),garbage"));
        assert!(!satisfies("1.5", "[1.0,2.0),"));
        assert!(!satisfies("1.5", ",[1.0,2.0)"));
        // A reversed-bracket (Gradle-only) member must not sneak through Maven's
        // union parsing via a style mixup.
        assert!(!satisfies("1.3", "]1.2,1.5]"));
    }
}

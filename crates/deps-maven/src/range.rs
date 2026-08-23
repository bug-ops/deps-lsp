//! Maven version range parsing and containment ([Maven versioning spec][spec]).
//!
//! # Why this is hand-rolled
//!
//! No maintained Rust crate implements Maven's interval-notation range grammar. Unlike
//! NuGet (`deps-nuget`), Maven ranges may be a top-level comma-separated union of intervals
//! (`(,1.0),(1.2,)`) and every bound is compared with [`crate::version::compare_versions`],
//! which understands Maven's qualifier precedence (`alpha < beta < milestone < rc < snapshot
//! < release < sp`) — plain numeric parsing would misorder bounds like `[1.0-beta,2.0-rc)`.
//!
//! A bare (non-bracketed) requirement such as `"1.0"` is Maven's "soft" recommended version,
//! not a range, and is intentionally not handled here — see [`is_range`].
//!
//! [spec]: https://maven.apache.org/pom.html#dependency-version-requirement-specification

use crate::version::compare_versions;
use std::cmp::Ordering;

/// A single parsed Maven interval, e.g. `[1.0,2.0)` or `[1.0]`.
enum VersionRange {
    /// `[1.0]` — matches only that exact version.
    Exact(String),
    Minimum {
        version: String,
        inclusive: bool,
    },
    Maximum {
        version: String,
        inclusive: bool,
    },
    Bounded {
        min: String,
        min_inclusive: bool,
        max: String,
        max_inclusive: bool,
    },
}

/// Splits `s` on commas that are not nested inside a `[`/`(` ... `]`/`)` pair, so a
/// union like `[1.0,2.0),[3.0,4.0)` yields two members while the inner min/max comma of
/// a single member (handled by [`parse_single_range`]) is left untouched.
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

/// Parses one bracketed interval. Returns `None` for anything that isn't a well-formed
/// `[`/`(` ... `]`/`)` interval: unbalanced brackets, empty bounds on both sides, a stray
/// bracket character nested inside the bounds (e.g. `[[1.0,2.0)`, `[1.0,2.0)]`), a third
/// comma-separated component (`[1.0,2.0,3.0]`), or a no-comma body whose delimiters aren't
/// the matching inclusive pair `[...]` (`[1.0)`, `(1.0]` — Maven has no reversed-bracket
/// exact-pin form). Callers treat an unparseable member as satisfying nothing rather than
/// panicking.
fn parse_single_range(s: &str) -> Option<VersionRange> {
    let s = s.trim();
    let first = s.chars().next()?;
    if first != '[' && first != '(' {
        return None;
    }
    let last = s.chars().next_back()?;
    if last != ']' && last != ')' {
        return None;
    }

    let min_inclusive = first == '[';
    let max_inclusive = last == ']';
    let inner = &s[first.len_utf8()..s.len() - last.len_utf8()];

    if inner.contains(['[', ']', '(', ')']) {
        return None;
    }

    if let Some((lo, hi)) = inner.split_once(',') {
        if hi.contains(',') {
            return None;
        }
        let lo = lo.trim();
        let hi = hi.trim();
        let min = (!lo.is_empty()).then(|| lo.to_string());
        let max = (!hi.is_empty()).then(|| hi.to_string());
        match (min, max) {
            (Some(min), Some(max)) => Some(VersionRange::Bounded {
                min,
                min_inclusive,
                max,
                max_inclusive,
            }),
            (Some(version), None) => Some(VersionRange::Minimum {
                version,
                inclusive: min_inclusive,
            }),
            (None, Some(version)) => Some(VersionRange::Maximum {
                version,
                inclusive: max_inclusive,
            }),
            (None, None) => None,
        }
    } else {
        let inner = inner.trim();
        (!inner.is_empty() && min_inclusive && max_inclusive)
            .then(|| VersionRange::Exact(inner.to_string()))
    }
}

fn satisfies_min(v: &str, min: &str, inclusive: bool) -> bool {
    let ord = compare_versions(v, min);
    if inclusive {
        ord != Ordering::Less
    } else {
        ord == Ordering::Greater
    }
}

fn satisfies_max(v: &str, max: &str, inclusive: bool) -> bool {
    let ord = compare_versions(v, max);
    if inclusive {
        ord != Ordering::Greater
    } else {
        ord == Ordering::Less
    }
}

fn range_contains(version: &str, range: &VersionRange) -> bool {
    match range {
        VersionRange::Exact(target) => compare_versions(version, target) == Ordering::Equal,
        VersionRange::Minimum {
            version: min,
            inclusive,
        } => satisfies_min(version, min, *inclusive),
        VersionRange::Maximum {
            version: max,
            inclusive,
        } => satisfies_max(version, max, *inclusive),
        VersionRange::Bounded {
            min,
            min_inclusive,
            max,
            max_inclusive,
        } => {
            satisfies_min(version, min, *min_inclusive)
                && satisfies_max(version, max, *max_inclusive)
        }
    }
}

/// Whether `requirement` looks like a Maven range/union, as opposed to a bare "soft"
/// recommended version (which is compared for plain equality by the caller).
pub fn is_range(requirement: &str) -> bool {
    requirement.trim_start().starts_with(['[', '('])
}

/// Checks whether `version` satisfies a Maven range `requirement`.
///
/// `requirement` may be a single interval (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`) or a
/// top-level comma union of intervals (`(,1.0),(1.2,)`), which matches if `version` falls
/// inside any member. If any member fails to parse, the whole requirement is rejected and
/// this returns `false` (fail-closed) rather than silently ignoring the bad member — a
/// malformed union member indicates the whole `requirement` string is not the range its
/// author intended, so treating it as satisfied by the well-formed members alone would be
/// misleading, not just a missing feature.
pub fn satisfies(version: &str, requirement: &str) -> bool {
    let mut matched = false;
    for member in split_top_level(requirement.trim()) {
        match parse_single_range(member) {
            Some(range) => matched |= range_contains(version, &range),
            None => return false,
        }
    }
    matched
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
    fn test_satisfies_exact_pin() {
        assert!(satisfies("1.0", "[1.0]"));
        assert!(!satisfies("1.0.1", "[1.0]"));
    }

    #[test]
    fn test_satisfies_bounded_no_comma_vs_with_comma() {
        assert!(satisfies("1.0", "[1.0]"));
        assert!(satisfies("1.0", "[1.0,1.0]"));
        assert!(!satisfies("1.0.1", "[1.0,1.0]"));
    }

    #[test]
    fn test_satisfies_open_ended_minimum() {
        assert!(satisfies("1.5", "[1.5,)"));
        assert!(satisfies("2.0", "[1.5,)"));
        assert!(!satisfies("1.4", "[1.5,)"));
    }

    #[test]
    fn test_satisfies_open_ended_maximum() {
        assert!(satisfies("2.0", "(,2.0]"));
        assert!(!satisfies("2.0.1", "(,2.0]"));
        assert!(satisfies("1.9", "(,2.0)"));
        assert!(!satisfies("2.0", "(,2.0)"));
    }

    #[test]
    fn test_satisfies_bounded_exclusive_inclusive_mix() {
        assert!(satisfies("1.5", "[1.0,2.0)"));
        assert!(!satisfies("2.0", "[1.0,2.0)"));
        assert!(!satisfies("1.0", "(1.0,2.0)"));
        assert!(satisfies("1.0.1", "(1.0,2.0)"));
    }

    #[test]
    fn test_satisfies_whitespace_inside_brackets() {
        assert!(satisfies("1.5", "[ 1.0 , 2.0 )"));
    }

    #[test]
    fn test_satisfies_malformed_brackets_return_false() {
        assert!(!satisfies("1.0", "[1.0,2.0"));
        assert!(!satisfies("1.0", "1.0,2.0)"));
        assert!(!satisfies("1.0", "(,)"));
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
    }

    #[test]
    fn test_satisfies_rejects_mismatched_no_comma_brackets() {
        // A no-comma body is only a valid exact pin when both delimiters are the matching
        // inclusive pair `[...]`; Maven has no reversed-bracket exact-pin notation.
        assert!(!satisfies("1.0", "[1.0)"));
        assert!(!satisfies("1.0", "(1.0]"));
        assert!(!satisfies("1.0", "(1.0)"));
    }

    #[test]
    fn test_satisfies_rejects_stray_nested_brackets() {
        assert!(!satisfies("1.5", "[[1.0,2.0)"));
        assert!(!satisfies("1.5", "[1.0,2.0)]"));
    }

    #[test]
    fn test_satisfies_rejects_extra_component() {
        assert!(!satisfies("1.5", "[1.0,2.0,3.0]"));
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
    fn test_satisfies_qualifier_bearing_bounds() {
        assert!(satisfies("1.0-milestone", "[1.0-beta,2.0-rc)"));
        assert!(!satisfies("1.0-alpha", "[1.0-beta,2.0-rc)"));
        assert!(!satisfies("2.0-rc", "[1.0-beta,2.0-rc)"));
        assert!(satisfies("2.0-milestone", "[1.0-beta,2.0-rc)"));
    }
}

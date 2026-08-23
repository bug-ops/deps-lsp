//! Gradle bracket-interval version range parsing and containment.
//!
//! Gradle's [rich version][spec] grammar shares its bracket-interval syntax
//! (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`) with Maven, but unlike Maven has no top-level
//! comma union — a single interval is the whole requirement, so this is a trimmed copy of
//! `deps_maven::range`'s single-interval parser rather than a shared module. Gradle also
//! documents a reversed-bracket exclusive notation Maven does not have (`]1.2,1.5]` for an
//! exclusive lower bound, `[1.1,2.0[` for an exclusive upper bound), handled here by
//! `parse_single_range`. Dynamic versions (`1.0+`) and `latest.*` selectors are handled
//! directly in `formatter.rs`, not here. Bounds are compared with
//! [`deps_maven::version::compare_versions`], which already knows Maven/Gradle-style
//! qualifier precedence — `deps-gradle` depends on `deps-maven` for registry access, so
//! reusing its comparator avoids a second hand-rolled implementation.
//!
//! [spec]: https://docs.gradle.org/current/userguide/rich_versions.html

use deps_maven::version::compare_versions;
use std::cmp::Ordering;

/// A single parsed Gradle interval, e.g. `[1.0,2.0)` or `[1.0]`.
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

/// Parses one bracketed interval. A leading `[` and trailing `]` are inclusive; a leading
/// `(` and trailing `)` are exclusive; Gradle additionally accepts a leading `]` or trailing
/// `[` as an exclusive bound (`]1.2,1.5]`, `[1.1,2.0[` — Gradle's own reversed-bracket
/// notation, which Maven does not have). Returns `None` for anything else that isn't
/// well-formed: unbalanced/unrecognized delimiters, empty bounds on both sides, a stray
/// bracket character nested inside the bounds (e.g. `[1.0,2.0)]`), a third comma-separated
/// component (`[1.0,2.0,3.0]`), or a no-comma body whose delimiters aren't the matching
/// inclusive pair `[...]` (`[1.0)` — no such thing as an exclusive singleton). Callers treat
/// an unparseable range as satisfying nothing rather than panicking.
fn parse_single_range(s: &str) -> Option<VersionRange> {
    let s = s.trim();
    let first = s.chars().next()?;
    let min_inclusive = match first {
        '[' => true,
        '(' | ']' => false,
        _ => return None,
    };
    let last = s.chars().next_back()?;
    let max_inclusive = match last {
        ']' => true,
        ')' | '[' => false,
        _ => return None,
    };

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

/// Checks whether `version` satisfies a Gradle bracket-interval `requirement`.
///
/// Supports `[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`, and Gradle's reversed-bracket exclusive
/// notation (`]1.2,1.5]`, `[1.1,2.0[`). Returns `false` for an unparseable requirement
/// (unbalanced/unrecognized delimiters, empty bounds, a nested bracket, an extra
/// comma-separated component) rather than panicking.
pub fn satisfies(version: &str, requirement: &str) -> bool {
    match parse_single_range(requirement.trim()) {
        Some(range) => range_contains(version, &range),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satisfies_exact_pin() {
        assert!(satisfies("1.0", "[1.0]"));
        assert!(!satisfies("1.0.1", "[1.0]"));
    }

    #[test]
    fn test_satisfies_bounded() {
        assert!(satisfies("1.5", "[1.0,2.0)"));
        assert!(!satisfies("2.0", "[1.0,2.0)"));
        assert!(!satisfies("1.0", "(1.0,2.0)"));
        assert!(satisfies("1.0.1", "(1.0,2.0)"));
    }

    #[test]
    fn test_satisfies_open_ended() {
        assert!(satisfies("1.5", "[1.5,)"));
        assert!(!satisfies("1.4", "[1.5,)"));
        assert!(satisfies("2.0", "(,2.0]"));
        assert!(!satisfies("2.0.1", "(,2.0]"));
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
    fn test_satisfies_rejects_union_syntax() {
        // Gradle's grammar has no top-level comma union — a Maven-style union string must
        // be rejected outright, not silently parsed as one interval with a corrupted bound.
        assert!(!satisfies("1.5", "[1.0,2.0),[3.0,4.0)"));
        assert!(!satisfies("2.5", "[1.0,2.0),[3.0,4.0)"));
        assert!(!satisfies("3.5", "[1.0,2.0),[3.0,4.0)"));
        assert!(!satisfies("9.9", "[1.0,2.0),[3.0,4.0)"));
    }

    #[test]
    fn test_satisfies_rejects_mismatched_no_comma_brackets() {
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
    fn test_satisfies_reversed_bracket_exclusive_lower() {
        // `]1.2,1.5]`: exclusive lower bound, inclusive upper bound.
        assert!(!satisfies("1.2", "]1.2,1.5]"));
        assert!(satisfies("1.3", "]1.2,1.5]"));
        assert!(satisfies("1.5", "]1.2,1.5]"));
        assert!(!satisfies("1.6", "]1.2,1.5]"));
    }

    #[test]
    fn test_satisfies_reversed_bracket_exclusive_upper() {
        // `[1.1,2.0[`: inclusive lower bound, exclusive upper bound.
        assert!(satisfies("1.1", "[1.1,2.0["));
        assert!(satisfies("1.5", "[1.1,2.0["));
        assert!(!satisfies("2.0", "[1.1,2.0["));
        assert!(!satisfies("1.0", "[1.1,2.0["));
    }
}

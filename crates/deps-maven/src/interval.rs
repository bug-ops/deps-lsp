//! Shared bracket-interval version range parsing, used by both `deps-maven` and
//! `deps-gradle`.
//!
//! Maven and Gradle both express a single version range as a bracket interval
//! (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`). Gradle additionally accepts a
//! reversed-bracket exclusive notation Maven does not have (`]1.2,1.5]` for an
//! exclusive lower bound, `[1.1,2.0[` for an exclusive upper bound) — the only
//! grammar difference between the two, selected via [`BracketStyle`]. What
//! differs between the ecosystems is what wraps a single interval: Maven allows a
//! top-level comma union of intervals (`(,1.0),(1.2,)`), handled by
//! `deps_maven::range`; Gradle has no such union and a single interval is the
//! whole requirement, handled by `deps_gradle::range`. Bounds are compared with
//! `crate::version::compare_versions_for_range`, which understands Maven's qualifier
//! precedence (`alpha < beta < milestone < rc < snapshot < release < sp`) — plain numeric
//! parsing would misorder bounds like `[1.0-beta,2.0-rc)` — and normalizes a missing trailing
//! segment as zero, so a bound and the version it is checked against need not share the same
//! segment count (`[1.0]` matches `1.0.0`).

use crate::version::compare_versions_for_range;
use std::cmp::Ordering;

/// A single parsed bracket interval, e.g. `[1.0,2.0)` or `[1.0]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRange {
    /// `[1.0]` — matches only that exact version.
    Exact(String),
    /// `[1.5,)` / `(1.5,)` — an open-ended lower bound.
    Minimum {
        /// The lower bound version.
        version: String,
        /// Whether `version` itself is included in the range.
        inclusive: bool,
    },
    /// `(,2.0]` / `(,2.0)` — an open-ended upper bound.
    Maximum {
        /// The upper bound version.
        version: String,
        /// Whether `version` itself is included in the range.
        inclusive: bool,
    },
    /// `[1.0,2.0)` — both bounds present.
    Bounded {
        /// The lower bound version.
        min: String,
        /// Whether `min` itself is included in the range.
        min_inclusive: bool,
        /// The upper bound version.
        max: String,
        /// Whether `max` itself is included in the range.
        max_inclusive: bool,
    },
}

/// Selects the delimiter grammar [`parse_interval`] accepts.
///
/// `Standard` is Maven's grammar: `[`/`]` are inclusive, `(`/`)` are
/// exclusive, and no character serves as both an opener and a closer.
/// `AllowReversed` adds Gradle's reversed-bracket exclusive notation on top:
/// a leading `]` or trailing `[` is also accepted as an exclusive bound
/// (`]1.2,1.5]`, `[1.1,2.0[`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BracketStyle {
    /// Maven's grammar: `[`/`]` inclusive, `(`/`)` exclusive only.
    Standard,
    /// `Standard` plus Gradle's reversed-bracket exclusive notation (`]`/`[`).
    AllowReversed,
}

/// Parses one bracketed interval under the given [`BracketStyle`].
///
/// Returns `None` for anything that isn't a well-formed `[`/`(`/`]` ... `]`/`)`/`[`
/// interval: unbalanced delimiters, a single character that cannot serve as both
/// delimiters, empty bounds on both sides, a stray bracket character nested inside
/// the bounds (e.g. `[[1.0,2.0)`, `[1.0,2.0)]`), a third comma-separated component
/// (`[1.0,2.0,3.0]`), or a no-comma body whose delimiters aren't the matching
/// inclusive pair `[...]` (`[1.0)`, `(1.0]` — neither grammar has a reversed-bracket
/// exact-pin form). Callers treat an unparseable interval as satisfying nothing
/// rather than panicking.
pub fn parse_interval(s: &str, style: BracketStyle) -> Option<VersionRange> {
    let s = s.trim();
    let first = s.chars().next()?;
    let min_inclusive = match (first, style) {
        ('[', _) => true,
        ('(', _) => false,
        (']', BracketStyle::AllowReversed) => false,
        _ => return None,
    };
    let last = s.chars().next_back()?;
    let max_inclusive = match (last, style) {
        (']', _) => true,
        (')', _) => false,
        ('[', BracketStyle::AllowReversed) => false,
        _ => return None,
    };

    // A single character cannot be both delimiters; without this the slice below
    // would have start > end (AllowReversed makes `[` and `]` valid on both sides).
    if s.len() < first.len_utf8() + last.len_utf8() {
        return None;
    }

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
    let ord = compare_versions_for_range(v, min);
    if inclusive {
        ord != Ordering::Less
    } else {
        ord == Ordering::Greater
    }
}

fn satisfies_max(v: &str, max: &str, inclusive: bool) -> bool {
    let ord = compare_versions_for_range(v, max);
    if inclusive {
        ord != Ordering::Greater
    } else {
        ord == Ordering::Less
    }
}

/// Whether `version` falls inside the parsed interval `range`.
pub fn contains(version: &str, range: &VersionRange) -> bool {
    match range {
        VersionRange::Exact(target) => {
            compare_versions_for_range(version, target) == Ordering::Equal
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parses(s: &str, style: BracketStyle) -> bool {
        parse_interval(s, style).is_some()
    }

    #[test]
    fn test_satisfies_exact_pin() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[1.0]", style).unwrap();
            assert!(contains("1.0", &range));
            assert!(!contains("1.0.1", &range));
        }
    }

    #[test]
    fn test_satisfies_bounded_no_comma_vs_with_comma() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let exact = parse_interval("[1.0]", style).unwrap();
            let bounded = parse_interval("[1.0,1.0]", style).unwrap();
            assert!(contains("1.0", &exact));
            assert!(contains("1.0", &bounded));
            assert!(!contains("1.0.1", &bounded));
        }
    }

    #[test]
    fn test_satisfies_open_ended_minimum() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[1.5,)", style).unwrap();
            assert!(contains("1.5", &range));
            assert!(contains("2.0", &range));
            assert!(!contains("1.4", &range));
        }
    }

    #[test]
    fn test_satisfies_open_ended_maximum() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let inclusive = parse_interval("(,2.0]", style).unwrap();
            assert!(contains("2.0", &inclusive));
            assert!(!contains("2.0.1", &inclusive));
            let exclusive = parse_interval("(,2.0)", style).unwrap();
            assert!(contains("1.9", &exclusive));
            assert!(!contains("2.0", &exclusive));
        }
    }

    #[test]
    fn test_satisfies_bounded_exclusive_inclusive_mix() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[1.0,2.0)", style).unwrap();
            assert!(contains("1.5", &range));
            assert!(!contains("2.0", &range));
            let range = parse_interval("(1.0,2.0)", style).unwrap();
            assert!(!contains("1.0", &range));
            assert!(contains("1.0.1", &range));
        }
    }

    #[test]
    fn test_satisfies_whitespace_inside_brackets() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[ 1.0 , 2.0 )", style).unwrap();
            assert!(contains("1.5", &range));
        }
    }

    #[test]
    fn test_satisfies_malformed_brackets_return_false() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[1.0,2.0", style));
            assert!(!parses("1.0,2.0)", style));
            assert!(!parses("(,)", style));
        }
    }

    #[test]
    fn test_satisfies_rejects_mismatched_no_comma_brackets() {
        // A no-comma body is only a valid exact pin when both delimiters are the
        // matching inclusive pair `[...]`; neither grammar has a reversed-bracket
        // exact-pin notation.
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[1.0)", style));
            assert!(!parses("(1.0]", style));
            assert!(!parses("(1.0)", style));
        }
    }

    #[test]
    fn test_satisfies_rejects_mismatched_no_comma_reversed_brackets() {
        // M1: the no-comma exact-pin path must reject reversed-bracket delimiters
        // under AllowReversed too — only the matching inclusive pair `[...]` is a
        // valid exact pin.
        assert!(!parses("]1.0[", BracketStyle::AllowReversed));
        assert!(!parses("]1.0]", BracketStyle::AllowReversed));
        assert!(!parses("[1.0[", BracketStyle::AllowReversed));
    }

    #[test]
    fn test_satisfies_rejects_stray_nested_brackets() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[[1.0,2.0)", style));
            assert!(!parses("[1.0,2.0)]", style));
        }
    }

    #[test]
    fn test_satisfies_rejects_extra_component() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[1.0,2.0,3.0]", style));
        }
    }

    #[test]
    fn test_satisfies_qualifier_bearing_bounds() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[1.0-beta,2.0-rc)", style).unwrap();
            assert!(contains("1.0-milestone", &range));
            assert!(!contains("1.0-alpha", &range));
            assert!(!contains("2.0-rc", &range));
            assert!(contains("2.0-milestone", &range));
        }
    }

    #[test]
    fn test_reversed_bracket_accepted_under_allow_reversed() {
        let lower = parse_interval("]1.2,1.5]", BracketStyle::AllowReversed).unwrap();
        assert!(!contains("1.2", &lower));
        assert!(contains("1.3", &lower));
        assert!(contains("1.5", &lower));
        assert!(!contains("1.6", &lower));

        let upper = parse_interval("[1.1,2.0[", BracketStyle::AllowReversed).unwrap();
        assert!(contains("1.1", &upper));
        assert!(contains("1.5", &upper));
        assert!(!contains("2.0", &upper));
        assert!(!contains("1.0", &upper));
    }

    #[test]
    fn test_reversed_bracket_rejected_under_standard() {
        assert!(!parses("]1.2,1.5]", BracketStyle::Standard));
        assert!(!parses("[1.1,2.0[", BracketStyle::Standard));
    }

    #[test]
    fn test_single_delimiter_is_rejected_not_panicking() {
        // #187: a single-character requirement is a char that would need to serve
        // as both the opener and closer; AllowReversed makes `[` and `]` valid on
        // both sides, so without the length guard this panics on a start > end
        // slice instead of returning None.
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[", style));
            assert!(!parses("]", style));
        }
    }
}

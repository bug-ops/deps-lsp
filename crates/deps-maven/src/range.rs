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

use std::cmp::Ordering;

use crate::interval::{BracketStyle, VersionRange, contains, parse_interval};

/// Splits `s` on commas that are not nested inside a `[`/`(` ... `]`/`)` pair, so a
/// union like `[1.0,2.0),[3.0,4.0)` yields two members while the inner min/max comma of
/// a single member (handled by [`crate::interval::parse_interval`]) is left untouched.
// `i`/`start` come from `char_indices()`, always char boundaries.
#[allow(clippy::string_slice)]
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

/// This member's upper edge, if any (`Minimum` has none — it is open-ended above).
///
/// `deps_core::interval::VersionRange` is `#[non_exhaustive]` outside its defining crate, so a
/// wildcard arm is mandatory here even though the four variants above are exhaustive today; a
/// future variant falls back to "no edge", the same as `Minimum`/`Maximum`'s genuinely open
/// side — it simply cannot contribute a gap-detection signal until this match is updated.
fn upper_edge(range: &VersionRange) -> Option<(&str, bool)> {
    match range {
        VersionRange::Exact(v) => Some((v.as_str(), true)),
        VersionRange::Maximum { version, inclusive } => Some((version.as_str(), *inclusive)),
        VersionRange::Bounded {
            max, max_inclusive, ..
        } => Some((max.as_str(), *max_inclusive)),
        // `Minimum` (open-ended above) plus any future variant.
        _ => None,
    }
}

/// This member's lower edge, if any (`Maximum` has none — it is open-ended below). See
/// [`upper_edge`] for why a wildcard arm is required.
fn lower_edge(range: &VersionRange) -> Option<(&str, bool)> {
    match range {
        VersionRange::Exact(v) => Some((v.as_str(), true)),
        VersionRange::Minimum { version, inclusive } => Some((version.as_str(), *inclusive)),
        VersionRange::Bounded {
            min, min_inclusive, ..
        } => Some((min.as_str(), *min_inclusive)),
        // `Maximum` (open-ended below) plus any future variant.
        _ => None,
    }
}

/// Whether `version` lies at or beyond `edge`, the mirror image of `contains`'s own
/// upper-bound check (fails, i.e. "past", exactly where that check would not have matched).
fn is_past(version: &str, edge: (&str, bool)) -> bool {
    let (bound, inclusive) = edge;
    let ord = crate::version::compare_versions_for_range(version, bound);
    if inclusive {
        ord == Ordering::Greater
    } else {
        ord != Ordering::Less
    }
}

/// Whether `version` lies at or before `edge`, the mirror image of `contains`'s own
/// lower-bound check.
fn is_before(version: &str, edge: (&str, bool)) -> bool {
    let (bound, inclusive) = edge;
    let ord = crate::version::compare_versions_for_range(version, bound);
    if inclusive {
        ord == Ordering::Less
    } else {
        ord != Ordering::Greater
    }
}

/// Whether `version` is explicitly excluded by the *shape* of a disjoint multi-range union
/// (issue #1590): not covered by any member, yet sitting in the gap between two of them
/// (past one member's upper edge and before another's lower edge) rather than merely outside
/// the union's overall span.
///
/// `[1.0,1.5),(1.5,2.0)` is Maven's only way to express a `!=`-style exclusion (no literal
/// `!=` operator exists in its grammar), so this is the Maven counterpart of
/// `ComposerMatcher`/`Pep440Matcher`/`RubygemsMatcher`'s `explicitly_excludes` override: a
/// fallback-candidate scan of `available` cannot tell "excluded by a gap" apart from
/// "legitimately above the requirement's ceiling" without asking the matcher directly (#1571).
///
/// M1 (review, tracked for a separate follow-up issue): `parse_interval` never validates
/// `min <= max`, so a degenerate member (`(3.0,3.0)`, `[5.0,3.0]`) can reach here — this fails
/// closed (a spurious `true` only ever makes an offerable fallback edit get rejected, never
/// makes a bad one get approved), so it is left unguarded for this fix.
pub(crate) fn explicitly_excludes(version: &str, ranges: &[VersionRange]) -> bool {
    if satisfies_ranges(version, ranges) {
        return false;
    }
    let past_some_upper = ranges
        .iter()
        .filter_map(upper_edge)
        .any(|e| is_past(version, e));
    let before_some_lower = ranges
        .iter()
        .filter_map(lower_edge)
        .any(|e| is_before(version, e));
    past_some_upper && before_some_lower
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

    fn excludes(version: &str, requirement: &str) -> bool {
        explicitly_excludes(version, &parse_range(requirement).unwrap())
    }

    /// #1590: a disjoint union's punctured point is explicitly excluded, even though it sits
    /// strictly inside the union's overall `[1.0,2.0)` span.
    #[test]
    fn test_explicitly_excludes_detects_disjoint_range_gap() {
        assert!(excludes("1.5.0", "[1.0,1.5),(1.5,2.0)"));
        assert!(!satisfies("1.5.0", "[1.0,1.5),(1.5,2.0)"));
    }

    /// A version outside the union's overall span is merely uncovered, not explicitly
    /// excluded — before the first member's lower bound and after the last member's upper
    /// bound must both stay `false`.
    #[test]
    fn test_explicitly_excludes_false_outside_overall_span() {
        assert!(!excludes("0.5", "[1.0,1.5),(1.5,2.0)"));
        assert!(!excludes("2.5", "[1.0,1.5),(1.5,2.0)"));
    }

    /// A single (non-disjoint) range has no gap to fall into — a candidate above its ceiling
    /// is out of range, not explicitly excluded.
    #[test]
    fn test_explicitly_excludes_false_for_single_range() {
        assert!(!excludes("2.5", "[1.0,2.0)"));
        assert!(!excludes("0.5", "[1.0,2.0)"));
    }

    /// A version actually covered by some member is never "excluded", regardless of how many
    /// disjoint members the union has.
    #[test]
    fn test_explicitly_excludes_false_when_covered() {
        assert!(!excludes("1.2", "[1.0,1.5),(1.5,2.0)"));
        assert!(!excludes("1.8", "[1.0,1.5),(1.5,2.0)"));
    }

    /// The gap can also be punched between two open-ended halves (Maven's only way to express
    /// a whole-line-minus-one-point exclusion), and must account for qualifier-aware/trailing-
    /// zero-segment equality (`1.5` == `1.5.0`) on both edges.
    #[test]
    fn test_explicitly_excludes_open_ended_halves() {
        assert!(excludes("1.5.0", "(,1.5),(1.5,)"));
        assert!(!excludes("1.4", "(,1.5),(1.5,)"));
        assert!(!excludes("1.6", "(,1.5),(1.5,)"));
    }

    /// A union of 3+ disjoint segments punches more than one gap, and each is detected
    /// independently — the algorithm is not hardcoded to a 2-member union.
    #[test]
    fn test_explicitly_excludes_three_way_union_multiple_gaps() {
        let req = "[1.0,2.0),[3.0,4.0),[5.0,6.0)";
        assert!(excludes("2.5", req));
        assert!(excludes("4.5", req));
        assert!(!excludes("0.5", req));
        assert!(!excludes("6.5", req));
        assert!(!excludes("1.5", req));
        assert!(!excludes("3.5", req));
        assert!(!excludes("5.5", req));
    }

    /// Gap detection scans every member's edges independently, so it does not depend on the
    /// union's members appearing in ascending order in the source text.
    #[test]
    fn test_explicitly_excludes_unsorted_segment_order() {
        assert!(excludes("2.5", "[3.0,4.0),[1.0,2.0)"));
        assert!(!excludes("0.5", "[3.0,4.0),[1.0,2.0)"));
        assert!(!excludes("4.5", "[3.0,4.0),[1.0,2.0)"));
    }

    /// Overlapping members leave no true gap — every candidate that would sit "past one
    /// member's upper edge and before another's lower edge" is actually covered by the
    /// overlap, so no version in the combined span is ever flagged as excluded.
    #[test]
    fn test_explicitly_excludes_false_for_overlapping_segments() {
        let req = "[1.0,2.0),(1.5,3.0)";
        for v in ["1.0", "1.5", "1.8", "2.0", "2.5", "2.9"] {
            assert!(satisfies(v, req), "{v} should be covered by the overlap");
            assert!(!excludes(v, req));
        }
    }

    /// An exact-point member (`[1.0]`) has both edges at the same version, so it can be one
    /// side of a gap just like a bounded/open member — the point itself stays covered.
    #[test]
    fn test_explicitly_excludes_exact_point_segment_forms_a_gap() {
        let req = "[1.0],[2.0,3.0)";
        assert!(satisfies("1.0", req));
        assert!(!excludes("1.0", req));
        assert!(excludes("1.5", req));
        assert!(!excludes("0.5", req));
        assert!(!excludes("3.5", req));
    }

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

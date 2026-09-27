//! Bracket-interval version range parsing, used by both `deps-maven` and `deps-gradle`.
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
//!
//! The bracket-interval *grammar* itself (delimiter parsing, the three malformed-input
//! rejection guards) is shared with `deps-nuget` via [`deps_core::interval`] (#821) — this
//! module now only supplies Maven's raw-string bound type and its qualifier-aware comparator.

pub use deps_core::interval::BracketStyle;

/// A single parsed bracket interval, e.g. `[1.0,2.0)` or `[1.0]`, with Maven's raw-string
/// bound representation (comparison happens later, via `compare_versions_for_range`).
pub type VersionRange = deps_core::interval::VersionRange<String>;

/// Parses one bracketed interval under the given [`BracketStyle`].
///
/// See [`deps_core::interval::parse_interval`] for the exact grammar and rejection rules,
/// including the `min <= max` bounded-range validation (#1595), which uses
/// `compare_versions_for_range` so a qualifier-bearing bound (`[1.0-beta,1.0-alpha)`) is
/// validated with Maven's own precedence, not raw string ordering.
pub fn parse_interval(s: &str, style: BracketStyle) -> Option<VersionRange> {
    deps_core::interval::parse_interval(
        s,
        style,
        |bound| Some(bound.to_string()),
        |a, b| crate::version::compare_versions_for_range(a, b),
    )
}

/// Whether `version` falls inside the parsed interval `range`.
pub fn contains(version: &str, range: &VersionRange) -> bool {
    deps_core::interval::contains(version, range, |a, b| {
        crate::version::compare_versions_for_range(a, b)
    })
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

    /// #1595: `min <= max` validation uses qualifier-aware comparison, not raw string
    /// ordering. Under Maven's precedence `snapshot` (rank 4) sorts below `release`/`""`
    /// (rank 5), even though `"release" < "snapshot"` lexically — the opposite order. So
    /// `[1.0-snapshot,1.0-release)` is a valid (non-inverted) range, while
    /// `[1.0-release,1.0-snapshot)` — which a raw string comparison would accept, since
    /// `"release" < "snapshot"` lexically — is actually inverted under qualifier precedence
    /// and parses to `Empty`, admitting no version.
    #[test]
    fn test_inverted_qualifier_bearing_bounds_is_empty() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let valid = parse_interval("[1.0-snapshot,1.0-release)", style).unwrap();
            assert_ne!(valid, VersionRange::Empty, "style={style:?}");
            let inverted = parse_interval("[1.0-release,1.0-snapshot)", style).unwrap();
            assert_eq!(inverted, VersionRange::Empty, "style={style:?}");
        }
    }

    /// #1595: a degenerate bounded range parses to `Empty` (well-formed, unsatisfiable), not
    /// `None` (malformed syntax) — `Empty` still admits no candidate.
    #[test]
    fn test_degenerate_bounded_range_is_empty() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let inverted = parse_interval("[5.0,3.0]", style).unwrap();
            assert_eq!(inverted, VersionRange::Empty, "style={style:?}");
            let zero_width_exclusive = parse_interval("(3.0,3.0)", style).unwrap();
            assert_eq!(zero_width_exclusive, VersionRange::Empty, "style={style:?}");
            assert!(!contains("3.0", &inverted));
        }
    }

    /// #1595 M3: Maven's qualifier ordering is non-transitive with a plain trailing-segment
    /// comparison — an unrecognized qualifier (`jre`) ranks above every known one, including
    /// the release rank, so `1.0-jre` sorts above `1.0`. `[1.0-jre,1.0]` is therefore
    /// genuinely inverted and correctly parses to `Empty`, matching real Maven semantics, not
    /// a false positive from the new guard.
    #[test]
    fn test_unrecognized_qualifier_above_release_is_empty() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_interval("[1.0-jre,1.0]", style).unwrap();
            assert_eq!(range, VersionRange::Empty, "style={style:?}");
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

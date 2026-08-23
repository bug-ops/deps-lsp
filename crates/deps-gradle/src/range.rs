//! Gradle bracket-interval version range parsing and containment.
//!
//! Gradle's [rich version][spec] grammar shares its bracket-interval syntax
//! (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`) with Maven, but unlike Maven has no top-level
//! comma union — a single interval is the whole requirement. Both grammars are handled by
//! the shared single-interval parser in [`deps_maven::interval`]; the only divergence is
//! Gradle's reversed-bracket exclusive notation (`]1.2,1.5]` for an exclusive lower bound,
//! `[1.1,2.0[` for an exclusive upper bound), selected here via
//! `deps_maven::interval::BracketStyle::AllowReversed`. Dynamic versions (`1.0+`) and
//! `latest.*` selectors are handled directly in `formatter.rs`, not here.
//!
//! [spec]: https://docs.gradle.org/current/userguide/rich_versions.html

use deps_maven::interval::{BracketStyle, VersionRange, contains, parse_interval};

/// Parses a Gradle bracket-interval `requirement`, once.
///
/// Supports `[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`, and Gradle's reversed-bracket exclusive
/// notation (`]1.2,1.5]`, `[1.1,2.0[`). Returns `None` for an unparseable requirement
/// (unbalanced/unrecognized delimiters, empty bounds, a nested bracket, an extra
/// comma-separated component) rather than panicking.
///
/// Used by `GradleFormatter::compile_requirement` to parse the requirement once per
/// dependency; the resulting `VersionRange` is then tested against each candidate version
/// via `contains` with no re-parsing.
pub(crate) fn parse_range(requirement: &str) -> Option<VersionRange> {
    parse_interval(requirement.trim(), BracketStyle::AllowReversed)
}

/// Checks whether `version` satisfies a Gradle bracket-interval `requirement`.
///
/// Convenience wrapper around `parse_range` + [`contains`] for callers that don't need to
/// test more than one candidate against the same requirement.
pub fn satisfies(version: &str, requirement: &str) -> bool {
    match parse_range(requirement) {
        Some(range) => contains(version, &range),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satisfies_bound_digit_count_normalization() {
        // #182 fix propagated through the shared parser: missing trailing
        // segments normalize as zero.
        assert!(satisfies("1.5", "]1.2,1.5.0]"));
        assert!(!satisfies("2.0.0", "[1.1,2.0["));
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

    #[test]
    fn test_satisfies_single_delimiter_does_not_panic() {
        // #187: a single-character requirement must be rejected, not panic on a
        // start > end slice (AllowReversed makes `[`/`]` valid on both sides).
        assert!(!satisfies("1.0", "["));
        assert!(!satisfies("1.0", "]"));
    }
}

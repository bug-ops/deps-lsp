//! Shared bracket-interval version-range grammar (#821).
//!
//! Maven, Gradle, and NuGet all express a single version range as a bracket interval
//! (`[1.0,2.0)`, `[1.0]`, `[1.5,)`, `(,2.0]`); Gradle additionally accepts a reversed-bracket
//! exclusive notation Maven/NuGet do not have (`]1.2,1.5]` for an exclusive lower bound,
//! `[1.1,2.0[` for an exclusive upper bound), selected via [`crate::interval::BracketStyle`].
//! This grammar used to be implemented twice: once (hardened, with three rejection guards for
//! malformed input) in `deps-maven`, reused by `deps-gradle`, and once (independently, missing
//! all three guards) in `deps-nuget` — which let `deps-nuget` silently accept malformed ranges
//! (`[[1.0,2.0)`, `[1.0,2.0,3.0]`, `(1.0)`, `[]`) that Maven/Gradle correctly rejected. This
//! module is the single implementation both grammars route through.
//!
//! What stays ecosystem-specific, and deliberately does **not** live here, is bound *parsing*
//! and *comparison*: Maven's bounds carry qualifier precedence (`alpha < beta < milestone < rc
//! < snapshot < release < sp`), NuGet's carry SemVer2 prerelease precedence with
//! case-insensitive labels, and both normalize a missing trailing segment as zero.
//! [`crate::interval::VersionRange`] is therefore generic over the ecosystem's own bound type
//! `V`; [`crate::interval::parse_interval`] takes a `parse_bound` closure to turn a bound
//! substring into `V`, and [`crate::interval::contains`] takes a `cmp` closure to compare a
//! candidate against a bound. See each item's own doc for the exact signature.

use std::cmp::Ordering;

/// A single parsed bracket interval, e.g. `[1.0,2.0)` or `[1.0]`.
///
/// Generic over the ecosystem-specific bound type `V` (e.g. a raw version string for
/// Maven/Gradle, or an already-parsed `ParsedVersion` for NuGet).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRange<V> {
    /// `[1.0]` — matches only that exact version.
    Exact(V),
    /// `[1.5,)` / `(1.5,)` — an open-ended lower bound.
    Minimum {
        /// The lower bound.
        version: V,
        /// Whether `version` itself is included in the range.
        inclusive: bool,
    },
    /// `(,2.0]` / `(,2.0)` — an open-ended upper bound.
    Maximum {
        /// The upper bound.
        version: V,
        /// Whether `version` itself is included in the range.
        inclusive: bool,
    },
    /// `[1.0,2.0)` — both bounds present.
    Bounded {
        /// The lower bound.
        min: V,
        /// Whether `min` itself is included in the range.
        min_inclusive: bool,
        /// The upper bound.
        max: V,
        /// Whether `max` itself is included in the range.
        max_inclusive: bool,
    },
}

/// Selects the delimiter grammar [`parse_interval`] accepts.
///
/// `Standard` is Maven's/NuGet's grammar: `[`/`]` are inclusive, `(`/`)` are exclusive, and no
/// character serves as both an opener and a closer. `AllowReversed` adds Gradle's
/// reversed-bracket exclusive notation on top: a leading `]` or trailing `[` is also accepted
/// as an exclusive bound (`]1.2,1.5]`, `[1.1,2.0[`).
///
/// **Exhaustive** (issue #769): a 2-variant grammar selector fixed by `parse_interval`'s call
/// sites — a third grammar would change the calling convention there too, not slot into an
/// existing wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BracketStyle {
    /// Maven's/NuGet's grammar: `[`/`]` inclusive, `(`/`)` exclusive only.
    Standard,
    /// `Standard` plus Gradle's reversed-bracket exclusive notation (`]`/`[`).
    AllowReversed,
}

/// Outcome of parsing one side of a bracket interval's bound, distinguishing "no bound"
/// (an open-ended range) from a parse failure (reject the whole interval) — a plain
/// `Option<Option<V>>` cannot express this three-way split without clippy flagging it.
enum ParsedBound<V> {
    /// The bound substring was empty — an open-ended minimum/maximum.
    Open,
    /// `parse_bound` accepted the bound substring.
    Value(V),
    /// `parse_bound` rejected a non-empty bound substring.
    Invalid,
}

/// Parses `s` as a bound, distinguishing "no bound" (empty string) from a parse failure.
fn parse_bound_side<V>(s: &str, parse_bound: &impl Fn(&str) -> Option<V>) -> ParsedBound<V> {
    if s.is_empty() {
        ParsedBound::Open
    } else {
        match parse_bound(s) {
            Some(v) => ParsedBound::Value(v),
            None => ParsedBound::Invalid,
        }
    }
}

/// Parses one bracketed interval under the given [`BracketStyle`], turning each bound
/// substring into `V` via `parse_bound`.
///
/// Returns `None` for anything that isn't a well-formed `[`/`(`/`]` ... `]`/`)`/`[` interval:
/// unbalanced delimiters, a single character that cannot serve as both delimiters, empty
/// bounds on both sides, a stray bracket character nested inside the bounds (e.g.
/// `[[1.0,2.0)`, `[1.0,2.0)]`), a third comma-separated component (`[1.0,2.0,3.0]`), a
/// no-comma body whose delimiters aren't the matching inclusive pair `[...]` (`[1.0)`,
/// `(1.0]`, `(1.0)` — neither grammar has a reversed-bracket exact-pin form), or a bound
/// substring `parse_bound` itself rejects. Callers treat an unparseable interval as satisfying
/// nothing rather than panicking.
///
/// # Examples
///
/// ```
/// use deps_core::interval::{BracketStyle, VersionRange, parse_interval};
///
/// let range = parse_interval("[1.0,2.0)", BracketStyle::Standard, |b| Some(b.to_string()));
/// assert_eq!(
///     range,
///     Some(VersionRange::Bounded {
///         min: "1.0".to_string(),
///         min_inclusive: true,
///         max: "2.0".to_string(),
///         max_inclusive: false,
///     })
/// );
///
/// // Malformed shapes are rejected, not silently accepted.
/// assert_eq!(parse_interval::<String>("[1.0,2.0,3.0]", BracketStyle::Standard, |b| Some(b.to_string())), None);
/// assert_eq!(parse_interval::<String>("(1.0)", BracketStyle::Standard, |b| Some(b.to_string())), None);
/// ```
// `first`/`last` are `chars()` ends sliced at `len_utf8`, and the explicit length guard
// above prevents `start > end`, so the slice bound is always a char boundary.
#[allow(clippy::string_slice)]
pub fn parse_interval<V>(
    s: &str,
    style: BracketStyle,
    parse_bound: impl Fn(&str) -> Option<V>,
) -> Option<VersionRange<V>> {
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
        let min = parse_bound_side(lo.trim(), &parse_bound);
        let max = parse_bound_side(hi.trim(), &parse_bound);
        match (min, max) {
            (ParsedBound::Invalid, _) | (_, ParsedBound::Invalid) => None,
            (ParsedBound::Value(min), ParsedBound::Value(max)) => Some(VersionRange::Bounded {
                min,
                min_inclusive,
                max,
                max_inclusive,
            }),
            (ParsedBound::Value(version), ParsedBound::Open) => Some(VersionRange::Minimum {
                version,
                inclusive: min_inclusive,
            }),
            (ParsedBound::Open, ParsedBound::Value(version)) => Some(VersionRange::Maximum {
                version,
                inclusive: max_inclusive,
            }),
            (ParsedBound::Open, ParsedBound::Open) => None,
        }
    } else {
        let inner = inner.trim();
        if inner.is_empty() || !min_inclusive || !max_inclusive {
            return None;
        }
        parse_bound(inner).map(VersionRange::Exact)
    }
}

fn satisfies_min<Q: ?Sized, V>(
    v: &Q,
    min: &V,
    inclusive: bool,
    cmp: &impl Fn(&Q, &V) -> Ordering,
) -> bool {
    let ord = cmp(v, min);
    if inclusive {
        ord != Ordering::Less
    } else {
        ord == Ordering::Greater
    }
}

fn satisfies_max<Q: ?Sized, V>(
    v: &Q,
    max: &V,
    inclusive: bool,
    cmp: &impl Fn(&Q, &V) -> Ordering,
) -> bool {
    let ord = cmp(v, max);
    if inclusive {
        ord != Ordering::Greater
    } else {
        ord == Ordering::Less
    }
}

/// Whether `v` falls inside the parsed interval `range`, comparing via `cmp`.
///
/// `Q` (the candidate's type) and `V` (the range's bound type) are independent: a caller may
/// compare a raw `&str` candidate against `VersionRange<String>` bounds without allocating
/// (Maven/Gradle), or a pre-parsed candidate against pre-parsed bounds of the same type
/// (NuGet).
///
/// # Examples
///
/// ```
/// use deps_core::interval::{BracketStyle, contains, parse_interval};
///
/// let range = parse_interval("[1.0,2.0)", BracketStyle::Standard, |b| Some(b.to_string())).unwrap();
/// let cmp = |a: &str, b: &String| a.cmp(b.as_str());
/// assert!(contains("1.5", &range, cmp));
/// assert!(!contains("2.0", &range, cmp));
/// ```
pub fn contains<Q: ?Sized, V>(
    v: &Q,
    range: &VersionRange<V>,
    cmp: impl Fn(&Q, &V) -> Ordering,
) -> bool {
    match range {
        VersionRange::Exact(target) => cmp(v, target) == Ordering::Equal,
        VersionRange::Minimum { version, inclusive } => satisfies_min(v, version, *inclusive, &cmp),
        VersionRange::Maximum { version, inclusive } => satisfies_max(v, version, *inclusive, &cmp),
        VersionRange::Bounded {
            min,
            min_inclusive,
            max,
            max_inclusive,
        } => {
            satisfies_min(v, min, *min_inclusive, &cmp)
                && satisfies_max(v, max, *max_inclusive, &cmp)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str, style: BracketStyle) -> Option<VersionRange<String>> {
        parse_interval(s, style, |b| Some(b.to_string()))
    }

    fn parses(s: &str, style: BracketStyle) -> bool {
        parse_str(s, style).is_some()
    }

    fn str_cmp<S: AsRef<str>>(a: &str, b: &S) -> Ordering {
        a.cmp(b.as_ref())
    }

    fn contains_str(v: &str, range: &VersionRange<String>) -> bool {
        contains(v, range, str_cmp)
    }

    #[test]
    fn test_satisfies_exact_pin() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_str("[1.0]", style).unwrap();
            assert!(contains_str("1.0", &range));
            assert!(!contains_str("1.0.1", &range));
        }
    }

    #[test]
    fn test_satisfies_bounded_exclusive_inclusive_mix() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_str("[1.0,2.0)", style).unwrap();
            assert!(contains_str("1.5", &range));
            assert!(!contains_str("2.0", &range));
        }
    }

    #[test]
    fn test_satisfies_open_ended_minimum_and_maximum() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let min = parse_str("[1.5,)", style).unwrap();
            assert!(contains_str("2.0", &min));
            assert!(!contains_str("1.4", &min));

            let max = parse_str("(,2.0]", style).unwrap();
            assert!(contains_str("2.0", &max));
            assert!(!contains_str("2.0.1", &max));
        }
    }

    #[test]
    fn test_satisfies_whitespace_inside_brackets() {
        let range = parse_str("[ 1.0 , 2.0 )", BracketStyle::Standard).unwrap();
        assert!(contains_str("1.5", &range));
    }

    #[test]
    fn test_reversed_bracket_accepted_under_allow_reversed_only() {
        assert!(parses("]1.2,1.5]", BracketStyle::AllowReversed));
        assert!(!parses("]1.2,1.5]", BracketStyle::Standard));
        assert!(parses("[1.1,2.0[", BracketStyle::AllowReversed));
        assert!(!parses("[1.1,2.0[", BracketStyle::Standard));
    }

    #[test]
    fn test_single_delimiter_is_rejected_not_panicking() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(!parses("[", style));
            assert!(!parses("]", style));
        }
    }

    /// #821 conformance: the malformed shapes NuGet's independent, less-hardened
    /// implementation used to silently accept — this is the shared, ecosystem-agnostic
    /// grammar every ecosystem (Maven, Gradle, NuGet) now routes through, so a shape rejected
    /// here is rejected everywhere.
    #[test]
    fn test_conformance_rejects_all_malformed_shapes() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            // Nested/stray bracket characters.
            assert!(!parses("[[1.0,2.0)", style), "style={style:?}");
            assert!(!parses("[1.0,2.0)]", style), "style={style:?}");
            // A third comma-separated component.
            assert!(!parses("[1.0,2.0,3.0]", style), "style={style:?}");
            // A no-comma body is only a valid exact pin as the matching inclusive pair
            // `[...]` — neither grammar has a reversed-bracket exact-pin form.
            assert!(!parses("(1.0)", style), "style={style:?}");
            assert!(!parses("[1.0)", style), "style={style:?}");
            assert!(!parses("(1.0]", style), "style={style:?}");
            // Empty exact pin.
            assert!(!parses("[]", style), "style={style:?}");
        }
    }

    #[test]
    fn test_conformance_accepts_well_formed_shapes() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert!(parses("[1.0]", style), "style={style:?}");
            assert!(parses("[1.0,2.0)", style), "style={style:?}");
        }
    }

    /// A bound `parse_bound` itself rejects must reject the whole interval, not fall back to
    /// treating it as an open bound.
    #[test]
    fn test_unparseable_bound_rejects_whole_interval() {
        let parse_u32 = |b: &str| b.parse::<u32>().ok();
        assert_eq!(
            parse_interval("[1,not-a-number)", BracketStyle::Standard, parse_u32),
            None
        );
        assert_eq!(
            parse_interval("[not-a-number]", BracketStyle::Standard, parse_u32),
            None
        );
    }

    #[test]
    fn test_contains_with_independent_candidate_and_bound_types() {
        // The candidate type `Q` need not match the bound type `V` — here a `u32` candidate
        // is compared against `String`-typed bounds via a custom `cmp`.
        let range = parse_str("[1,10)", BracketStyle::Standard).unwrap();
        let cmp = |a: &u32, b: &String| a.cmp(&b.parse::<u32>().unwrap());
        assert!(contains(&5u32, &range, cmp));
        assert!(!contains(&10u32, &range, cmp));
    }
}

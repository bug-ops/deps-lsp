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
    /// A syntactically well-formed bounded interval that can never be satisfied by any
    /// version: `min > max` (`[5.0,3.0]`), or `min == max` with either bound exclusive
    /// (`(3.0,3.0)`, `[3.0,3.0)`) — see #1595. Distinct from [`parse_interval`] returning
    /// `None` (malformed syntax): a malformed member invalidates a whole union for callers
    /// like Maven's, while `Empty` is a well-formed member that legitimately contributes
    /// nothing — [`contains`] reports `false` for every candidate, so a requirement made up
    /// entirely of `Empty` members is correctly reported as unsatisfiable rather than
    /// undecidable, and an `Empty` member alongside valid ones in a union does not corrupt
    /// gap detection over the valid members with a fabricated edge.
    Empty,
}

impl<V> VersionRange<V> {
    /// This range's upper edge, if any — `(bound, inclusive)`. `Minimum` (open-ended above)
    /// and `Empty` (admits nothing) have none.
    ///
    /// Shared edge accessor for union-gap detection (`deps-maven`'s disjoint-range-union check,
    /// `deps-composer`'s OR-alternation check, #1610): both derive a member's edges through this
    /// method instead of independently re-matching `VersionRange`'s variants.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interval::VersionRange;
    ///
    /// let bounded = VersionRange::Bounded {
    ///     min: "1.0".to_string(),
    ///     min_inclusive: true,
    ///     max: "2.0".to_string(),
    ///     max_inclusive: false,
    /// };
    /// assert_eq!(bounded.upper_edge(), Some((&"2.0".to_string(), false)));
    ///
    /// let minimum = VersionRange::Minimum {
    ///     version: "1.5".to_string(),
    ///     inclusive: true,
    /// };
    /// assert_eq!(minimum.upper_edge(), None);
    /// ```
    pub fn upper_edge(&self) -> Option<(&V, bool)> {
        match self {
            Self::Exact(v) => Some((v, true)),
            Self::Maximum { version, inclusive } => Some((version, *inclusive)),
            Self::Bounded {
                max, max_inclusive, ..
            } => Some((max, *max_inclusive)),
            Self::Minimum { .. } | Self::Empty => None,
        }
    }

    /// This range's lower edge, if any — `(bound, inclusive)`. `Maximum` (open-ended below)
    /// and `Empty` (admits nothing) have none. See [`Self::upper_edge`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::interval::VersionRange;
    ///
    /// let bounded = VersionRange::Bounded {
    ///     min: "1.0".to_string(),
    ///     min_inclusive: true,
    ///     max: "2.0".to_string(),
    ///     max_inclusive: false,
    /// };
    /// assert_eq!(bounded.lower_edge(), Some((&"1.0".to_string(), true)));
    ///
    /// let maximum = VersionRange::Maximum {
    ///     version: "2.0".to_string(),
    ///     inclusive: false,
    /// };
    /// assert_eq!(maximum.lower_edge(), None);
    /// ```
    pub fn lower_edge(&self) -> Option<(&V, bool)> {
        match self {
            Self::Exact(v) => Some((v, true)),
            Self::Minimum { version, inclusive } => Some((version, *inclusive)),
            Self::Bounded {
                min, min_inclusive, ..
            } => Some((min, *min_inclusive)),
            Self::Maximum { .. } | Self::Empty => None,
        }
    }
}

/// Builds the [`VersionRange::Bounded`]/[`VersionRange::Empty`] shape from a min/max edge pair,
/// applying the same unsatisfiable-shape detection [`parse_interval`] uses for a syntactic
/// bracket interval (#1595: `min > max`, or `min == max` with either edge exclusive, collapses
/// to [`VersionRange::Empty`] rather than a literal `Bounded` shape that admits nothing).
fn bounded_or_empty<V>(
    min: V,
    min_inclusive: bool,
    max: V,
    max_inclusive: bool,
    cmp_bound: impl Fn(&V, &V) -> Ordering,
) -> VersionRange<V> {
    let ord = cmp_bound(&min, &max);
    let unsatisfiable =
        ord == Ordering::Greater || (ord == Ordering::Equal && !(min_inclusive && max_inclusive));
    if unsatisfiable {
        VersionRange::Empty
    } else {
        VersionRange::Bounded {
            min,
            min_inclusive,
            max,
            max_inclusive,
        }
    }
}

/// Builds a [`VersionRange`] from a min/max edge pair derived independently of bracket syntax.
///
/// Intended for a caller like Composer's per-`||`-branch bound, AND-intersected clause by
/// clause (#1610) — reuses [`parse_interval`]'s own unsatisfiable-shape detection (via the same
/// internal helper) rather than re-deriving it.
///
/// Returns `None` only when both edges are absent: "no constraint at all" (open on both sides)
/// has no `VersionRange` shape to express it as — bracket syntax has no such form either (see
/// [`parse_interval`]'s `(ParsedBound::Open, ParsedBound::Open) => None` case) — so the caller
/// decides what an edge-less bound means for its own use case.
///
/// # Examples
///
/// ```
/// use deps_core::interval::{VersionRange, range_from_edges};
///
/// let cmp = |a: &String, b: &String| a.cmp(b);
/// let range = range_from_edges(Some(("1.0".to_string(), true)), Some(("2.0".to_string(), false)), cmp);
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
/// // Both edges absent has no `VersionRange` shape.
/// assert_eq!(range_from_edges::<String>(None, None, cmp), None);
/// ```
pub fn range_from_edges<V>(
    min: Option<(V, bool)>,
    max: Option<(V, bool)>,
    cmp_bound: impl Fn(&V, &V) -> Ordering,
) -> Option<VersionRange<V>> {
    match (min, max) {
        (Some((min, min_inclusive)), Some((max, max_inclusive))) => Some(bounded_or_empty(
            min,
            min_inclusive,
            max,
            max_inclusive,
            cmp_bound,
        )),
        (Some((version, inclusive)), None) => Some(VersionRange::Minimum { version, inclusive }),
        (None, Some((version, inclusive))) => Some(VersionRange::Maximum { version, inclusive }),
        (None, None) => None,
    }
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
/// substring `parse_bound` itself rejects. Callers treat an unparseable interval as
/// satisfying nothing rather than panicking.
///
/// Returns `Some(VersionRange::Empty)` — not `None` — for a bounded range that parses
/// syntactically but can never be satisfied: `min > max` per `cmp_bound` (`[5.0,3.0]`), or
/// `min == max` with either bound exclusive (`(3.0,3.0)`, `[3.0,3.0)`) — see #1595 and
/// [`VersionRange::Empty`]'s own doc for why this must not be conflated with the malformed-
/// syntax `None` case.
///
/// # Examples
///
/// ```
/// use deps_core::interval::{BracketStyle, VersionRange, parse_interval};
///
/// let cmp = |a: &String, b: &String| a.cmp(b);
///
/// let range = parse_interval("[1.0,2.0)", BracketStyle::Standard, |b| Some(b.to_string()), cmp);
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
/// assert_eq!(parse_interval::<String>("[1.0,2.0,3.0]", BracketStyle::Standard, |b| Some(b.to_string()), cmp), None);
/// assert_eq!(parse_interval::<String>("(1.0)", BracketStyle::Standard, |b| Some(b.to_string()), cmp), None);
///
/// // An inverted or zero-width-exclusive bounded range parses to `Empty`, not `None`.
/// assert_eq!(parse_interval::<String>("[5.0,3.0]", BracketStyle::Standard, |b| Some(b.to_string()), cmp), Some(VersionRange::Empty));
/// assert_eq!(parse_interval::<String>("(3.0,3.0)", BracketStyle::Standard, |b| Some(b.to_string()), cmp), Some(VersionRange::Empty));
///
/// // A zero-width range with both bounds inclusive is a valid single-point match.
/// assert!(parse_interval::<String>("[3.0,3.0]", BracketStyle::Standard, |b| Some(b.to_string()), cmp).is_some_and(|r| r != VersionRange::Empty));
/// ```
#[expect(
    clippy::string_slice,
    reason = "first/last are chars() ends sliced at len_utf8, and the explicit length guard \
              above prevents start > end, so the slice bound is always a char boundary"
)]
pub fn parse_interval<V>(
    s: &str,
    style: BracketStyle,
    parse_bound: impl Fn(&str) -> Option<V>,
    cmp_bound: impl Fn(&V, &V) -> Ordering,
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
            (ParsedBound::Value(min), ParsedBound::Value(max)) => Some(bounded_or_empty(
                min,
                min_inclusive,
                max,
                max_inclusive,
                cmp_bound,
            )),
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
/// let range = parse_interval("[1.0,2.0)", BracketStyle::Standard, |b| Some(b.to_string()), |a, b| a.cmp(b)).unwrap();
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
        // A well-formed but unsatisfiable range admits nothing — see `VersionRange::Empty`.
        VersionRange::Empty => false,
    }
}

/// Whether an upper-bounded member admits some value at or above `candidate`.
///
/// `upper_edge` is `(bound, inclusive)`, or `None` for open-ended-above. `None` always
/// answers `true`: "no known upper edge" means "assume unbounded", the safe default for a
/// member whose shape [`union_gap_excludes`]'s caller could not characterize (mirrors
/// `deps-maven`'s own `upper_edge`/`lower_edge` wildcard-arm convention of contributing no
/// edge for an unrecognized/degenerate shape rather than guessing one).
pub fn admits_at_or_above<Q: ?Sized, V: ?Sized>(
    candidate: &Q,
    upper_edge: Option<(&V, bool)>,
    cmp: impl Fn(&Q, &V) -> Ordering,
) -> bool {
    match upper_edge {
        None => true,
        Some((bound, inclusive)) => {
            let ord = cmp(candidate, bound);
            if inclusive {
                ord != Ordering::Greater
            } else {
                ord == Ordering::Less
            }
        }
    }
}

/// Whether a lower-bounded member admits some value at or below `candidate`.
///
/// `lower_edge` is `(bound, inclusive)`, or `None` for open-ended-below. See
/// [`admits_at_or_above`]'s doc for why `None` always answers `true`.
pub fn admits_at_or_below<Q: ?Sized, V: ?Sized>(
    candidate: &Q,
    lower_edge: Option<(&V, bool)>,
    cmp: impl Fn(&Q, &V) -> Ordering,
) -> bool {
    match lower_edge {
        None => true,
        Some((bound, inclusive)) => {
            let ord = cmp(candidate, bound);
            if inclusive {
                ord != Ordering::Less
            } else {
                ord == Ordering::Greater
            }
        }
    }
}

/// Whether a candidate not covered by any union member is explicitly excluded by the shape.
///
/// "The shape" means: sitting past one member's admitted span and before another's, with
/// nothing in between (#1601, generalizing Maven's disjoint-range-union gap detection from
/// #1590/#1594 to any union representation).
///
/// This is deliberately representation-agnostic — `M` may be a bracket interval
/// (`deps-maven`/`deps-composer`, whose members expose literal string edges via
/// [`admits_at_or_above`]/[`admits_at_or_below`]) or an opaque range object with no exposed
/// bound values (`deps-npm`'s `node_semver::Range`, whose members answer the same two
/// questions by probing `Range::allows_any` instead). Only the answers to three yes/no
/// questions per member are needed: does it cover `candidate` already, does it admit
/// something at or above `candidate`, and does it admit something at or below `candidate`.
///
/// A member that cannot answer these precisely for some clause shape should just answer
/// `true` for the two `admits_at_or_*` questions (see [`admits_at_or_above`]'s doc) — that
/// only means a real gap through that member goes undetected, never that a covered candidate
/// is misreported as excluded.
///
/// # Examples
///
/// ```
/// use deps_core::interval::union_gap_excludes;
///
/// // Two disjoint half-lines with a punctured point at 5, mirroring a Maven
/// // `(,5),(5,)`-style union or a Composer/npm `||`-alternation with the same shape.
/// let members = [(0, 5), (5, 10)]; // (lower, upper), both bounds exclusive
/// let excludes = |candidate: i32| {
///     union_gap_excludes(
///         &members,
///         |&(lo, hi)| candidate > lo && candidate < hi,
///         |&(_, hi)| candidate < hi,
///         |&(lo, _)| candidate > lo,
///     )
/// };
/// assert!(excludes(5));
/// assert!(!excludes(3));
/// assert!(!excludes(7));
/// assert!(!excludes(-1));
/// assert!(!excludes(11));
/// ```
pub fn union_gap_excludes<M>(
    members: &[M],
    covers: impl Fn(&M) -> bool,
    admits_at_or_above: impl Fn(&M) -> bool,
    admits_at_or_below: impl Fn(&M) -> bool,
) -> bool {
    if members.iter().any(&covers) {
        return false;
    }
    let past_some_upper = members.iter().any(|m| !admits_at_or_above(m));
    let before_some_lower = members.iter().any(|m| !admits_at_or_below(m));
    past_some_upper && before_some_lower
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str, style: BracketStyle) -> Option<VersionRange<String>> {
        parse_interval(s, style, |b| Some(b.to_string()), |a, b| a.cmp(b))
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
        let cmp_u32 = |a: &u32, b: &u32| a.cmp(b);
        assert_eq!(
            parse_interval(
                "[1,not-a-number)",
                BracketStyle::Standard,
                parse_u32,
                cmp_u32
            ),
            None
        );
        assert_eq!(
            parse_interval("[not-a-number]", BracketStyle::Standard, parse_u32, cmp_u32),
            None
        );
    }

    /// #1595: a bounded range that can never be satisfied — inverted bounds, or a
    /// zero-width range with either bound exclusive — parses to `Empty`, not `None`: it is
    /// well-formed syntax, just an unsatisfiable one (see `VersionRange::Empty`'s doc for why
    /// this must stay distinct from a malformed-syntax rejection).
    #[test]
    fn test_bounded_range_min_greater_than_max_is_empty() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            assert_eq!(
                parse_str("[5.0,3.0]", style),
                Some(VersionRange::Empty),
                "style={style:?}"
            );
            assert_eq!(
                parse_str("(5.0,3.0)", style),
                Some(VersionRange::Empty),
                "style={style:?}"
            );
        }
    }

    #[test]
    fn test_bounded_range_zero_width_exclusive_is_empty() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            for s in ["(3.0,3.0)", "[3.0,3.0)", "(3.0,3.0]"] {
                assert_eq!(
                    parse_str(s, style),
                    Some(VersionRange::Empty),
                    "style={style:?}"
                );
            }
        }
    }

    /// An `Empty` range admits no candidate, unlike an unparseable `None` interval which the
    /// caller must handle separately (e.g. Maven's whole-union rejection).
    #[test]
    fn test_empty_range_contains_nothing() {
        let range: VersionRange<String> = VersionRange::Empty;
        assert!(!contains_str("3.0", &range));
        assert!(!contains_str("0.0", &range));
    }

    #[test]
    fn test_bounded_range_zero_width_inclusive_is_a_valid_single_point() {
        for style in [BracketStyle::Standard, BracketStyle::AllowReversed] {
            let range = parse_str("[3.0,3.0]", style).unwrap();
            assert!(contains_str("3.0", &range));
            assert!(!contains_str("2.9", &range));
        }
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

    fn str_ord(a: &str, b: &str) -> Ordering {
        a.cmp(b)
    }

    #[test]
    fn test_admits_at_or_above_none_edge_is_always_true() {
        assert!(admits_at_or_above("999", None::<(&str, bool)>, str_ord));
    }

    #[test]
    fn test_admits_at_or_above_respects_inclusivity() {
        let bound = "5";
        assert!(admits_at_or_above("5", Some((bound, true)), str_ord));
        assert!(!admits_at_or_above("5", Some((bound, false)), str_ord));
        assert!(admits_at_or_above("4", Some((bound, true)), str_ord));
        assert!(!admits_at_or_above("6", Some((bound, true)), str_ord));
    }

    #[test]
    fn test_admits_at_or_below_none_edge_is_always_true() {
        assert!(admits_at_or_below("0", None::<(&str, bool)>, str_ord));
    }

    #[test]
    fn test_admits_at_or_below_respects_inclusivity() {
        let bound = "5";
        assert!(admits_at_or_below("5", Some((bound, true)), str_ord));
        assert!(!admits_at_or_below("5", Some((bound, false)), str_ord));
        assert!(admits_at_or_below("6", Some((bound, true)), str_ord));
        assert!(!admits_at_or_below("4", Some((bound, true)), str_ord));
    }

    /// Mirrors Maven's #1590 disjoint-range-union gap test, but through the
    /// representation-agnostic union primitive instead of `deps-maven`'s own edge extraction.
    #[test]
    fn test_union_gap_excludes_disjoint_members() {
        let members: Vec<(i32, i32)> = vec![(0, 5), (5, 10)]; // exclusive both ends
        let excludes = |candidate: i32| {
            union_gap_excludes(
                &members,
                |&(lo, hi)| candidate > lo && candidate < hi,
                |&(_, hi)| candidate < hi,
                |&(lo, _)| candidate > lo,
            )
        };
        assert!(excludes(5));
        assert!(!excludes(3));
        assert!(!excludes(7));
        assert!(!excludes(-1));
        assert!(!excludes(11));
    }

    /// A single member alone has no "other side" to sandwich a candidate against, so it can
    /// never trigger a gap exclusion by itself, even if it is entirely below or above the
    /// candidate.
    #[test]
    fn test_union_gap_excludes_single_member_never_excludes() {
        let members: Vec<(i32, i32)> = vec![(0, 5)];
        assert!(!union_gap_excludes(
            &members,
            |&(lo, hi)| 7 > lo && 7 < hi,
            |&(_, hi)| 7 < hi,
            |&(lo, _)| 7 > lo,
        ));
    }

    /// A member reporting "unknown" (always answering `true` for both admits-questions, per
    /// [`admits_at_or_above`]'s doc) never itself contributes a false gap, even sitting
    /// between two other real members.
    #[test]
    fn test_union_gap_excludes_unknown_member_contributes_nothing() {
        #[derive(Clone, Copy)]
        enum Member {
            Bounded(i32, i32),
            Unknown,
        }
        let members = [
            Member::Bounded(0, 5),
            Member::Unknown,
            Member::Bounded(5, 10),
        ];
        let covers = |m: &Member| matches!(m, Member::Bounded(lo, hi) if 5 > *lo && 5 < *hi);
        let above = |m: &Member| match m {
            Member::Bounded(_, hi) => 5 < *hi,
            Member::Unknown => true,
        };
        let below = |m: &Member| match m {
            Member::Bounded(lo, _) => 5 > *lo,
            Member::Unknown => true,
        };
        assert!(union_gap_excludes(&members, covers, above, below));
    }

    #[test]
    fn test_upper_edge_lower_edge_per_variant() {
        let bounded = parse_str("[1.0,2.0)", BracketStyle::Standard).unwrap();
        assert_eq!(bounded.upper_edge(), Some((&"2.0".to_string(), false)));
        assert_eq!(bounded.lower_edge(), Some((&"1.0".to_string(), true)));

        let min = parse_str("[1.5,)", BracketStyle::Standard).unwrap();
        assert_eq!(min.upper_edge(), None);
        assert_eq!(min.lower_edge(), Some((&"1.5".to_string(), true)));

        let max = parse_str("(,2.0]", BracketStyle::Standard).unwrap();
        assert_eq!(max.upper_edge(), Some((&"2.0".to_string(), true)));
        assert_eq!(max.lower_edge(), None);

        let exact = parse_str("[1.0]", BracketStyle::Standard).unwrap();
        assert_eq!(exact.upper_edge(), Some((&"1.0".to_string(), true)));
        assert_eq!(exact.lower_edge(), Some((&"1.0".to_string(), true)));

        let empty: VersionRange<String> = VersionRange::Empty;
        assert_eq!(empty.upper_edge(), None);
        assert_eq!(empty.lower_edge(), None);
    }

    #[test]
    fn test_range_from_edges_builds_expected_shapes() {
        let cmp = |a: &String, b: &String| a.cmp(b);
        let v = |s: &str| (s.to_string(), true);

        assert_eq!(
            range_from_edges(Some(v("1.0")), Some(("2.0".to_string(), false)), cmp),
            Some(VersionRange::Bounded {
                min: "1.0".to_string(),
                min_inclusive: true,
                max: "2.0".to_string(),
                max_inclusive: false,
            })
        );
        assert_eq!(
            range_from_edges(Some(v("1.5")), None, cmp),
            Some(VersionRange::Minimum {
                version: "1.5".to_string(),
                inclusive: true,
            })
        );
        assert_eq!(
            range_from_edges(None, Some(v("2.0")), cmp),
            Some(VersionRange::Maximum {
                version: "2.0".to_string(),
                inclusive: true,
            })
        );
        assert_eq!(range_from_edges::<String>(None, None, cmp), None);
    }

    /// #1595 parity: `range_from_edges` must apply the same unsatisfiable-shape detection
    /// `parse_interval` does for a syntactic bracket interval.
    #[test]
    fn test_range_from_edges_unsatisfiable_shapes_are_empty() {
        let cmp = |a: &String, b: &String| a.cmp(b);
        assert_eq!(
            range_from_edges(
                Some(("5.0".to_string(), true)),
                Some(("3.0".to_string(), true)),
                cmp
            ),
            Some(VersionRange::Empty)
        );
        assert_eq!(
            range_from_edges(
                Some(("3.0".to_string(), false)),
                Some(("3.0".to_string(), true)),
                cmp
            ),
            Some(VersionRange::Empty)
        );
    }

    /// A candidate covered by any member is never excluded, regardless of how many other
    /// members would otherwise box it in.
    #[test]
    fn test_union_gap_excludes_false_when_covered() {
        let members: Vec<(i32, i32)> = vec![(0, 5), (4, 10)];
        assert!(!union_gap_excludes(
            &members,
            |&(lo, hi)| 4 >= lo && 4 <= hi,
            |&(_, hi)| 4 < hi,
            |&(lo, _)| 4 > lo,
        ));
    }
}

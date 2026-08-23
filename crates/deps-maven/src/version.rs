//! Maven version comparison and pre-release detection.

use std::cmp::Ordering;

/// Detects if a Maven version string is a pre-release.
///
/// A version is a pre-release when any of its segments is a qualifier that
/// ranks below the release qualifier in `qualifier_rank` (`alpha`, `beta`,
/// `milestone`/`M`, `rc`/`cr`, `snapshot`, ...) — the same table
/// [`compare_versions`] uses for ordering, so this can never disagree with
/// the comparator about whether a version is a base release or a
/// pre-release.
pub fn is_prerelease(version: &str) -> bool {
    split_version(version).iter().any(|segment| {
        if is_numeric_segment(segment) {
            return false;
        }
        let tokens = tokenize_qualifier(segment);
        let Some(QualToken::Alpha(prefix)) = tokens.first() else {
            return false;
        };
        let has_numeric_suffix = matches!(tokens.get(1), Some(QualToken::Digits(_)));
        qualifier_rank(&normalize_qualifier(prefix, has_numeric_suffix)) < qualifier_rank("")
    })
}

/// Compares two Maven version strings by dot/dash-separated segment.
///
/// This is a total order (antisymmetric, transitive, and consistent with equality — verified by
/// `test_compare_versions_total_order_invariants`), so it is safe to use as a `sort_by`
/// comparator, e.g. sorting `maven-metadata.xml`'s version list in
/// `crate::registry::parse_metadata_xml`. Each segment is classified as purely numeric (all
/// ASCII digits) or a non-numeric qualifier. A numeric segment always outranks a non-numeric
/// qualifier at the same position, which keeps legacy Maven identifiers such as Guava's bare
/// `r03`..`r09` release tags below properly-formed numeric releases (e.g. `33.7.1-jre`). A
/// missing segment (the shorter version ran out of components) is ranked against a non-numeric
/// qualifier at that position by the same Maven qualifier precedence used for two real
/// qualifiers (see `compare_qualifiers`): a version's own trailing dash-qualifier that ranks
/// below release (e.g. `-RC1`, `-SNAPSHOT`) sorts below its base release (`6.1.0-RC1` < `6.1.0`),
/// while one that ranks above release (e.g. `-sp`, or an unrecognized vendor suffix) sorts above
/// it. Two numeric segments compare by magnitude (leading zeros ignored, no size limit); two real
/// non-numeric segments are ranked by Maven qualifier precedence (see `compare_qualifiers`).
///
/// Note this does *not* treat a missing segment as equal to a present-but-zero one (`1.0` and
/// `1.0.0` compare unequal here) — doing so would break the total order, since the zero-valued
/// segment and the missing one can each compare differently against a qualifier at that position
/// depending on which side of the pair supplies it. Range/interval bound matching, which does
/// want that normalization (`[1.0]` should match `1.0.0`), uses the dedicated pairwise
/// `compare_versions_for_range` instead.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let a_parts = split_version(a);
    let b_parts = split_version(b);

    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let ap = a_parts.get(i).map_or("", |s| s.as_str());
        let bp = b_parts.get(i).map_or("", |s| s.as_str());

        let ord = compare_segment(ap, bp);
        if ord != Ordering::Equal {
            return ord;
        }
    }

    Ordering::Equal
}

/// Compares two Maven version strings for range/interval bound matching only.
///
/// Unlike [`compare_versions`], a missing trailing segment (the shorter version ran out of
/// components) normalizes as equal to a present-but-zero numeric segment at that position, per
/// Maven's `IntItem.compareTo(null)` rule (the same rule [`compare_qualifiers`] already applies
/// one level down, to qualifier-token digit runs): `1.0` == `1.0.0` == `1.0.0.0`. This is what
/// lets a range bound with a different segment count than the version being checked still match
/// correctly (`[1.0]` contains `1.0.0`; `[4.0,4.1]` contains `4.1.0`).
///
/// # Not a total order
///
/// This function is **not** transitive and must never be used as a `sort_by` comparator: because
/// [`split_version`] flattens `.`/`-` into one flat segment list, a zero-valued segment and an
/// absent one can each compare differently against a same-position qualifier depending on which
/// version supplies it, producing ordering cycles (e.g. `1.0.0 > 1.0-jre`, `1.0-jre > 1.0`, but
/// `1.0 == 1.0.0`). It is safe only for the pairwise range-containment checks in
/// `crate::interval`, which never sort — see [`compare_versions`] for the total-order sorting
/// comparator.
pub(crate) fn compare_versions_for_range(a: &str, b: &str) -> Ordering {
    let a_parts = split_version(a);
    let b_parts = split_version(b);

    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let ap = a_parts.get(i).map(String::as_str);
        let bp = b_parts.get(i).map(String::as_str);

        let ord = compare_segment_for_range(ap, bp);
        if ord != Ordering::Equal {
            return ord;
        }
    }

    Ordering::Equal
}

fn split_version(v: &str) -> Vec<String> {
    v.split(['.', '-'])
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Compares a single dot/dash-separated version segment.
///
/// A purely numeric segment always outranks a non-numeric one: legacy Maven
/// qualifiers such as Guava's bare `r03`..`r09` identifiers must sort below
/// properly-formed numeric releases (e.g. `33.7.1-jre`), not above them via a
/// raw ASCII string comparison (`'r' > '3'`). When neither segment is
/// numeric, they are ranked as Maven qualifiers; see [`compare_qualifiers`].
fn compare_segment(a: &str, b: &str) -> Ordering {
    match (is_numeric_segment(a), is_numeric_segment(b)) {
        (true, true) => compare_numeric_segments(a, b),
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => compare_qualifiers(a, b),
    }
}

/// Compares a single dot/dash-separated version segment for
/// [`compare_versions_for_range`]; `None` means the shorter version ran out
/// of components at this position.
///
/// When both segments are present, this defers to [`compare_segment`].
/// When one side is missing, it applies Maven's `IntItem.compareTo(null)`
/// rule: a present numeric segment that is all zeros (e.g. the third
/// component of `1.0.0` vs `1.0`) is equivalent to a missing one, so the
/// segments compare equal; any other numeric segment outranks the missing
/// one. A present non-numeric qualifier is instead compared against the
/// empty qualifier via [`compare_qualifiers`], preserving Maven qualifier
/// precedence at a missing segment (e.g. `6.1.0-RC1` < `6.1.0`).
fn compare_segment_for_range(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => compare_segment(a, b),
        (Some(a), None) if is_numeric_segment(a) => {
            if is_zero_digits(a) {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Some(a), None) => compare_qualifiers(a, ""),
        (None, Some(_)) => compare_segment_for_range(b, a).reverse(),
        (None, None) => Ordering::Equal,
    }
}

/// A segment is numeric only if every byte is an ASCII digit; classifying by
/// character class (rather than `str::parse::<u64>` success) means a segment
/// with more than 20 digits is still treated as numeric instead of silently
/// falling through to the non-numeric branch.
fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Compares two all-digit segments by magnitude, ignoring leading zeros.
///
/// Digit strings of equal length compare identically whether by numeric
/// value or by lexicographic byte order, so this avoids parsing into a
/// fixed-width integer type and has no size limit.
fn compare_numeric_segments(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two non-numeric qualifier segments using Maven's
/// `ComparableVersion` precedence: `alpha < beta < milestone < rc/cr <
/// snapshot < (release, i.e. "", "ga", "final") < sp`, case-insensitively.
///
/// A missing segment is compared against `""` — padded by [`compare_versions`] itself when the
/// other version simply runs out of components, or passed explicitly by
/// [`compare_segment_for_range`] when the present side is a non-numeric qualifier
/// (`split_version` never yields empty segments itself); `""` represents "no further
/// qualifier", i.e. the release rank: a dash-qualifier segment ranking below release (`alpha`,
/// `beta`, `milestone`, `rc`/`cr`, `snapshot`, e.g. `RC1` or `SNAPSHOT`) sorts below the base
/// release it is compared against, while one ranking above release (`sp`, or any unrecognized
/// qualifier such as a vendor suffix) sorts above it — the same per-token rank comparison used
/// for two real qualifiers, not a special case.
///
/// Both segments are tokenized into maximal alpha/digit runs (see
/// [`tokenize_qualifier`]) and compared positionally, token by token,
/// returning the first non-equal ordering — matching Maven's
/// `ComparableVersion`, which splits a qualifier on every alpha/digit
/// transition rather than just the trailing one (e.g. `rc1a` becomes `rc`,
/// `1`, `a`), so a leading unrecognized run like `a` in `rc1a` never
/// overrides the qualifier rank carried by the leading `rc` token. Each
/// position is compared as follows:
/// - alpha vs alpha: ranked by Maven qualifier precedence (see
///   [`qualifier_rank`]); segments that are not recognized qualifier words
///   rank above every known qualifier, including `sp`, matching
///   `ComparableVersion`, which compares an unrecognized qualifier's index
///   (`QUALIFIERS.size()`) as a string against the known indices, so it
///   always sorts last.
/// - digits vs digits: compared numerically rather than lexicographically
///   (e.g. `M2` vs `M10`, `alpha9` vs `alpha15`).
/// - digits vs alpha at the same position: digits always outrank alpha,
///   mirroring the numeric-outranks-non-numeric rule [`compare_segment`]
///   applies at the top level.
/// - alpha vs a missing token (one side ran out): ranked against the empty
///   qualifier, same as the alpha-vs-alpha case with `""` on the missing
///   side.
/// - digits vs a missing token: a present-but-zero digit run (e.g. `r0` vs
///   `r`) is treated as equivalent to a missing one, mirroring Maven's
///   `IntItem.compareTo(null)`, which returns `0` for a zero-valued item
///   compared against an absent one; any other digit run outranks a missing
///   token.
fn compare_qualifiers(a: &str, b: &str) -> Ordering {
    let a_tokens = tokenize_qualifier(a);
    let b_tokens = tokenize_qualifier(b);
    let max_len = a_tokens.len().max(b_tokens.len());

    for i in 0..max_len {
        let ord = compare_qualifier_tokens(
            a_tokens.get(i),
            a_tokens.get(i + 1),
            b_tokens.get(i),
            b_tokens.get(i + 1),
        );
        if ord != Ordering::Equal {
            return ord;
        }
    }

    Ordering::Equal
}

/// Compares a single positional pair of qualifier tokens; `a_next`/`b_next`
/// are the tokens immediately following each, needed to decide
/// `has_numeric_suffix` when normalizing an `Alpha` token.
fn compare_qualifier_tokens(
    a: Option<&QualToken<'_>>,
    a_next: Option<&QualToken<'_>>,
    b: Option<&QualToken<'_>>,
    b_next: Option<&QualToken<'_>>,
) -> Ordering {
    match (a, b) {
        (Some(QualToken::Alpha(p)), Some(QualToken::Alpha(q))) => {
            let a_norm = normalize_qualifier(p, matches!(a_next, Some(QualToken::Digits(_))));
            let b_norm = normalize_qualifier(q, matches!(b_next, Some(QualToken::Digits(_))));
            qualifier_rank(&a_norm)
                .cmp(&qualifier_rank(&b_norm))
                .then_with(|| a_norm.cmp(&b_norm))
        }
        (Some(QualToken::Digits(p)), Some(QualToken::Digits(q))) => compare_numeric_segments(p, q),
        (Some(QualToken::Digits(_)), Some(QualToken::Alpha(_))) => Ordering::Greater,
        (Some(QualToken::Alpha(_)), Some(QualToken::Digits(_))) => Ordering::Less,
        (Some(QualToken::Alpha(p)), None) => {
            let a_norm = normalize_qualifier(p, matches!(a_next, Some(QualToken::Digits(_))));
            qualifier_rank(&a_norm).cmp(&qualifier_rank(""))
        }
        (None, Some(QualToken::Alpha(q))) => {
            let b_norm = normalize_qualifier(q, matches!(b_next, Some(QualToken::Digits(_))));
            qualifier_rank("").cmp(&qualifier_rank(&b_norm))
        }
        (Some(QualToken::Digits(p)), None) => {
            if is_zero_digits(p) {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (None, Some(QualToken::Digits(q))) => {
            if is_zero_digits(q) {
                Ordering::Equal
            } else {
                Ordering::Less
            }
        }
        (None, None) => Ordering::Equal,
    }
}

/// Whether a digit string's value is zero (all-zero, including `"0"`,
/// `"00"`, or empty — the latter cannot occur from [`tokenize_qualifier`]
/// but is handled the same way for safety).
fn is_zero_digits(digits: &str) -> bool {
    digits.bytes().all(|b| b == b'0')
}

/// A maximal alpha or digit run produced by [`tokenize_qualifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualToken<'a> {
    Alpha(&'a str),
    Digits(&'a str),
}

/// Splits a qualifier into maximal alternating alpha/digit runs, at every
/// ASCII-digit/non-digit boundary (e.g. `"rc1a"` -> `[Alpha("rc"),
/// Digits("1"), Alpha("a")]`, `"M10"` -> `[Alpha("M"), Digits("10")]`,
/// `"beta"` -> `[Alpha("beta")]`). Either kind may appear first; only called
/// on segments already known to be non-numeric, so the result is never
/// empty. Mirrors Maven's `ComparableVersion` tokenizer, which splits a
/// qualifier on every alpha/digit transition, not just the trailing one.
fn tokenize_qualifier(s: &str) -> Vec<QualToken<'_>> {
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        let is_digit = bytes[start].is_ascii_digit();
        let end = bytes[start..]
            .iter()
            .position(|b| b.is_ascii_digit() != is_digit)
            .map_or(bytes.len(), |i| start + i);
        let run = &s[start..end];
        tokens.push(if is_digit {
            QualToken::Digits(run)
        } else {
            QualToken::Alpha(run)
        });
        start = end;
    }
    tokens
}

/// Lowercases a qualifier prefix and resolves it to Maven's canonical
/// qualifier name, applying the aliases from `ComparableVersion`: `cr` ->
/// `rc` and `ga`/`final`/`release` -> the empty (release) qualifier
/// unconditionally, plus the single-letter `a` -> `alpha`, `b` -> `beta`,
/// `m` -> `milestone` aliases — but only when `has_numeric_suffix` is set
/// (i.e. the prefix was glued to a trailing number, e.g. `M2`). A bare `1.0-m`
/// with no digit after it stays an unrecognized qualifier, matching Maven's
/// tokenizer, which only folds a single letter into its word alias when it
/// is immediately followed by a digit.
fn normalize_qualifier(prefix: &str, has_numeric_suffix: bool) -> String {
    let lower = prefix.to_ascii_lowercase();
    if has_numeric_suffix && lower.len() == 1 {
        match lower.as_str() {
            "a" => return "alpha".to_string(),
            "b" => return "beta".to_string(),
            "m" => return "milestone".to_string(),
            _ => {}
        }
    }
    match lower.as_str() {
        "cr" => "rc".to_string(),
        "ga" | "final" | "release" => String::new(),
        _ => lower,
    }
}

/// Ranks a normalized qualifier per Maven's `ComparableVersion.QUALIFIERS`
/// table (`alpha, beta, milestone, rc, snapshot, "", sp`). An unrecognized
/// qualifier ranks above all of them, including `sp`: `ComparableVersion`
/// compares an unknown qualifier's index (`QUALIFIERS.size()`, i.e. one past
/// `sp`) as a string against the known single-digit indices, so it always
/// sorts last.
fn qualifier_rank(qualifier: &str) -> u8 {
    match qualifier {
        "alpha" => 0,
        "beta" => 1,
        "milestone" => 2,
        "rc" => 3,
        "snapshot" => 4,
        "" => 5,
        "sp" => 6,
        _ => 7,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prerelease_detection() {
        assert!(is_prerelease("1.0.0-SNAPSHOT"));
        assert!(is_prerelease("1.0.0-alpha"));
        assert!(is_prerelease("1.0.0-ALPHA"));
        assert!(is_prerelease("1.0.0-beta"));
        assert!(is_prerelease("1.0.0-rc1"));
        assert!(is_prerelease("1.0.0-RC1"));
        assert!(is_prerelease("2.0.0-M1"));
        assert!(is_prerelease("2.0.0-M10"));
        assert!(is_prerelease("1.0.0-rc1a"));
    }

    #[test]
    fn test_stable_versions() {
        assert!(!is_prerelease("1.0.0"));
        assert!(!is_prerelease("3.14.0"));
        assert!(!is_prerelease("1.2.3.Final"));
        assert!(!is_prerelease("2.0.RELEASE"));
    }

    #[test]
    fn test_version_comparison() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("10.0.0", "9.0.0"), Ordering::Greater);
    }

    #[test]
    fn test_exact_match() {
        assert_eq!(compare_versions("3.14.0", "3.14.0"), Ordering::Equal);
    }

    #[test]
    fn test_numeric_release_outranks_bare_qualifier() {
        // Guava scenario: r03-r09 are legacy bare qualifiers that must not
        // outrank properly-formed numeric releases.
        assert_eq!(compare_versions("33.7.1-jre", "r09"), Ordering::Greater);
        assert_eq!(compare_versions("r09", "33.7.1-jre"), Ordering::Less);
        assert_eq!(compare_versions("14.0", "r09"), Ordering::Greater);
    }

    #[test]
    fn test_bare_qualifiers_ordered_relative_to_each_other() {
        assert_eq!(compare_versions("r09", "r03"), Ordering::Greater);
        assert_eq!(compare_versions("r03", "r09"), Ordering::Less);
        assert_eq!(compare_versions("r05", "r05"), Ordering::Equal);
        // "r0" has a present-but-zero numeric suffix, equivalent to a
        // missing one, matching Maven's IntItem.compareTo(null).
        assert_eq!(compare_versions("r0", "r"), Ordering::Equal);
        assert_eq!(compare_versions("r00", "r"), Ordering::Equal);
        assert_eq!(compare_versions("r1", "r"), Ordering::Greater);
    }

    #[test]
    fn test_numeric_segment_outranks_qualifier_mid_version() {
        // "1.0-final" has a non-numeric third segment; a numeric segment at
        // the same position must still outrank it.
        assert_eq!(compare_versions("1.0.1", "1.0-final"), Ordering::Greater);
    }

    #[test]
    fn test_prerelease_sorts_below_own_base_release() {
        // junit-jupiter maven-metadata.xml case. "M1" < "RC1" here follows
        // the milestone < rc qualifier rank, not coincidental ASCII order;
        // both real qualifiers sort below the missing-segment base release.
        assert_eq!(compare_versions("6.1.0-M1", "6.1.0-RC1"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0-RC1", "6.1.0"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0-M1", "6.1.0"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0", "6.1.0-RC1"), Ordering::Greater);
    }

    #[test]
    fn test_prerelease_sort_matches_junit_jupiter_metadata_order() {
        // Real maven-metadata.xml version list order for junit-jupiter: both
        // qualifiers sort below the base release via `.sort_by`, not just in
        // isolated two-way comparisons.
        let mut versions = vec!["6.1.0", "6.1.0-M1", "6.1.0-RC1"];
        versions.sort_by(|a, b| compare_versions(a, b));
        assert_eq!(versions, vec!["6.1.0-M1", "6.1.0-RC1", "6.1.0"]);
    }

    #[test]
    fn test_prerelease_ordering_independent_of_segment_count() {
        // "1.0-SNAPSHOT" vs "1.0" (padding) must agree with the already
        // component-count-matched "1.0-SNAPSHOT" vs "1.0.0" comparison.
        assert_eq!(compare_versions("1.0-SNAPSHOT", "1.0"), Ordering::Less);
        assert_eq!(compare_versions("1.0-SNAPSHOT", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn test_numeric_segment_beyond_u64_range() {
        // A 20-digit segment overflows u64::MAX (20 digits) but must still be
        // classified and compared as numeric, not fall through to the
        // non-numeric lexicographic branch.
        assert_eq!(
            compare_versions("1.99999999999999999999", "1.2"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("1.100000000000000000000", "1.99999999999999999999"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("1.007", "1.07"), Ordering::Equal);
    }

    #[test]
    fn test_glued_numeric_qualifier_compares_numerically() {
        // #130: a letter prefix glued directly to a multi-digit number must
        // compare the numeric suffix by magnitude, not by raw ASCII bytes.
        assert_eq!(compare_versions("6.1.0-M2", "6.1.0-M10"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0-M10", "6.1.0-M2"), Ordering::Greater);
        assert_eq!(compare_versions("6.1.0-RC2", "6.1.0-RC10"), Ordering::Less);
        assert_eq!(
            compare_versions("1.0.alpha9", "1.0.alpha15"),
            Ordering::Less
        );
    }

    #[test]
    fn test_vaadin_alpha_sequence_orders_numerically() {
        // Vaadin publishes .alpha1..alpha15 in one maven-metadata.xml; under
        // lexicographic comparison alpha9 > alpha15, which is wrong.
        assert_eq!(
            compare_versions("1.0.alpha9", "1.0.alpha15"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("1.0.alpha15", "1.0.alpha1"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_qualifier_precedence_table() {
        // #131: rc/cr outranks beta, beta is below milestone/M, matching
        // Maven's ComparableVersion.QUALIFIERS precedence.
        assert_eq!(compare_versions("1.0-RC1", "1.0-beta"), Ordering::Greater);
        assert_eq!(compare_versions("1.0-beta", "1.0-M1"), Ordering::Less);
        assert_eq!(compare_versions("1.0-rc1", "1.0-RC1"), Ordering::Equal);
    }

    #[test]
    fn test_qualifier_precedence_full_chain() {
        // alpha < beta < milestone < rc < snapshot < release < sp, with `cr`
        // aliased to `rc` and `ga`/`final` aliased to the release qualifier.
        assert_eq!(compare_versions("9.9-alpha", "9.9-beta"), Ordering::Less);
        assert_eq!(
            compare_versions("9.9-beta", "9.9-milestone"),
            Ordering::Less
        );
        assert_eq!(compare_versions("9.9-milestone", "9.9-rc"), Ordering::Less);
        assert_eq!(compare_versions("9.9-rc", "9.9-cr"), Ordering::Equal);
        assert_eq!(compare_versions("9.9-rc", "9.9-snapshot"), Ordering::Less);
        assert_eq!(compare_versions("9.9-snapshot", "9.9-ga"), Ordering::Less);
        assert_eq!(compare_versions("9.9-ga", "9.9-final"), Ordering::Equal);
        assert_eq!(compare_versions("9.9-ga", "9.9-sp"), Ordering::Less);
    }

    #[test]
    fn test_unknown_qualifier_ranks_above_release_and_sp() {
        // Matches Maven: an unrecognized qualifier's index compares as the
        // string "7-word" against the known single-digit indices, so it
        // always sorts after every known qualifier, sp included.
        assert_eq!(compare_versions("9.9-ga", "9.9-vaadin"), Ordering::Less);
        assert_eq!(compare_versions("9.9-vaadin", "9.9-sp"), Ordering::Greater);
        assert_eq!(compare_versions("9.9-foo", "9.9-vaadin"), Ordering::Less);
    }

    #[test]
    fn test_single_letter_qualifier_aliases_gated_on_trailing_digit() {
        // Maven aliases a/b/m to alpha/beta/milestone only when the letter
        // is immediately followed by a digit (the same alpha/digit token
        // boundary #130 already computes); a bare letter with no digit stays
        // an unrecognized qualifier instead of silently matching the word.
        assert_eq!(compare_versions("1.0-a1", "1.0-alpha1"), Ordering::Equal);
        assert_eq!(compare_versions("1.0-a1", "1.0-beta1"), Ordering::Less);
        assert_eq!(compare_versions("1.0-b1", "1.0-beta1"), Ordering::Equal);
        assert_eq!(
            compare_versions("1.0-m1", "1.0-milestone1"),
            Ordering::Equal
        );
        assert_eq!(
            compare_versions("1.0-m", "1.0-milestone"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_non_trailing_digit_run_uses_leading_qualifier_prefix() {
        // The qualifier tokenizer splits on every alpha/digit transition, not
        // just the trailing one, so "rc1a" becomes ["rc", "1", "a"] and is
        // ranked by its leading "rc" token, not treated as one unrecognized
        // unit.
        assert_eq!(compare_versions("1.0-rc1a", "1.0-rc"), Ordering::Greater);
        assert_eq!(compare_versions("1.0-rc1a", "1.0-sp"), Ordering::Less);
        assert_eq!(compare_versions("1.0-rc1a", "1.0-rc1"), Ordering::Greater);
        assert_eq!(
            compare_versions("1.0-alpha2beta", "1.0-alpha2"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions("1.0-alpha2beta", "1.0-alpha3"),
            Ordering::Less
        );
        // Mismatched token kind at the same position: digits always outrank
        // alpha, mirroring the top-level numeric-outranks-non-numeric rule.
        assert_eq!(
            compare_versions("1.0-2beta", "1.0-beta2"),
            Ordering::Greater
        );
        assert_eq!(compare_versions("1.0-beta2", "1.0-2beta"), Ordering::Less);
        // Deeper chain: exercises numeric comparison at token index 3.
        assert_eq!(compare_versions("1.0-rc1a2", "1.0-rc1a10"), Ordering::Less);
    }

    #[test]
    fn test_qualifier_missing_segment_ranked_by_token_rank_not_shortcut() {
        // A missing segment pads to rank(""), the same per-token rank used
        // for two real qualifiers: only qualifiers below release rank
        // (alpha/beta/milestone/rc/snapshot) lose to the missing segment.
        // `sp` and unrecognized qualifiers rank above release, so they
        // outrank a missing segment too — there is no blanket rule that a
        // missing segment always outranks every real qualifier.
        assert_eq!(compare_versions("1.0-sp", "1.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0-ga", "1.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0-vaadin", "1.0"), Ordering::Greater);
        assert_eq!(compare_versions("9.9", "9.9-vaadin"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_for_range_normalizes_trailing_zero_segments() {
        // #182, range/interval bound matching only: a missing trailing segment
        // normalizes as equal to a zero-valued numeric segment, matching
        // Maven's IntItem.compareTo(null). compare_versions itself must NOT do
        // this — see test_compare_versions_does_not_normalize_trailing_zero_segments
        // and test_compare_versions_total_order_invariants (C1 regression).
        assert_eq!(compare_versions_for_range("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions_for_range("1.0.0", "1.0"), Ordering::Equal);
        assert_eq!(
            compare_versions_for_range("1.0", "1.0.0.0"),
            Ordering::Equal
        );
        assert_eq!(compare_versions_for_range("1", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions_for_range("1.0.00", "1.0"), Ordering::Equal);
        assert_eq!(
            compare_versions_for_range("1.0.1", "1.0"),
            Ordering::Greater
        );
        assert_eq!(compare_versions_for_range("1.0", "1.0.1"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_for_range_normalization_does_not_affect_qualifiers() {
        // A missing segment must still lose to a present non-numeric
        // qualifier per Maven qualifier precedence, not be swallowed by the
        // zero-normalization rule (#182).
        assert_eq!(
            compare_versions_for_range("6.1.0-RC1", "6.1.0"),
            Ordering::Less
        );
        assert_eq!(
            compare_versions_for_range("1.0-sp", "1.0"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions_for_range("1.0.0-SNAPSHOT", "1.0"),
            Ordering::Less
        );
    }

    #[test]
    fn test_compare_versions_does_not_normalize_trailing_zero_segments() {
        // compare_versions must stay a total order for sort_by callers
        // (crate::registry::parse_metadata_xml). Unlike
        // compare_versions_for_range, a missing trailing segment is ranked as
        // an empty qualifier here, not treated as equal to a zero-valued
        // numeric one.
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_total_order_invariants() {
        // C1 regression guard: a version corpus mixing segment-count spellings
        // of the same release with a same-base above-release qualifier used to
        // produce ordering cycles (1.0.0 > 1.0-jre, 1.0-jre > 1.0, 1.0 == 1.0.0)
        // once compare_versions treated a missing segment as zero. Antisymmetry,
        // transitivity of `<`, and equal-substitution must all hold, or
        // `Vec::sort_by` panics ("does not correctly implement a total order")
        // on realistic maven-metadata.xml version lists (crate::registry).
        let corpus = [
            "1.0",
            "1.0.0",
            "1.0.0.0",
            "1.0-jre",
            "1.0-android",
            "1.0-sp",
            "1.0-RC1",
            "1.0-SNAPSHOT",
            "1.0.1",
            "1.1",
            "1.1.0",
            "2.0",
        ];
        for &a in &corpus {
            for &b in &corpus {
                assert_eq!(
                    compare_versions(a, b),
                    compare_versions(b, a).reverse(),
                    "antisymmetry: compare({a}, {b}) vs compare({b}, {a})"
                );
                for &c in &corpus {
                    if compare_versions(a, b) == Ordering::Less
                        && compare_versions(b, c) == Ordering::Less
                    {
                        assert_eq!(
                            compare_versions(a, c),
                            Ordering::Less,
                            "transitivity: {a} < {b} < {c} but not {a} < {c}"
                        );
                    }
                    if compare_versions(a, b) == Ordering::Equal {
                        assert_eq!(
                            compare_versions(a, c),
                            compare_versions(b, c),
                            "equal-substitution: {a} == {b} but compare({a},{c}) != compare({b},{c})"
                        );
                    }
                }
            }
        }
    }
}

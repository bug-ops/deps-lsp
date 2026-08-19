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
        let (prefix, suffix) = split_trailing_digits(segment);
        qualifier_rank(&normalize_qualifier(prefix, suffix.is_some())) < qualifier_rank("")
    })
}

/// Compares two Maven version strings by dot/dash-separated segment.
///
/// Each segment is classified as purely numeric (all ASCII digits) or a
/// non-numeric qualifier. A numeric segment always outranks a non-numeric
/// qualifier at the same position, which keeps legacy Maven identifiers such
/// as Guava's bare `r03`..`r09` release tags below properly-formed numeric
/// releases (e.g. `33.7.1-jre`). A missing segment (the shorter version ran
/// out of components) outranks a non-numeric qualifier at that position, so
/// a version's own trailing dash-qualifier (e.g. `-RC1`, `-SNAPSHOT`) sorts
/// below its base release (`6.1.0-RC1` < `6.1.0`). Two numeric segments
/// compare by magnitude (leading zeros ignored, no size limit); two real
/// non-numeric segments are ranked by Maven qualifier precedence (see
/// `compare_qualifiers`).
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
/// A missing segment is padded to `""` by [`compare_versions`] (`split_version`
/// never yields empty segments itself) and represents "no further
/// qualifier", so it outranks every real qualifier: a dash-qualifier segment
/// like `RC1` or `SNAPSHOT` sorts below the base release it padded against.
///
/// Segments that are not recognized qualifier words rank above every known
/// qualifier, including `sp` — matching `ComparableVersion`, which compares
/// an unrecognized qualifier's index (`QUALIFIERS.size()`) as a string
/// against the known indices, so it always sorts last. When both sides share
/// the same normalized prefix and end in a glued numeric suffix (e.g. `M2`
/// vs `M10`, `alpha9` vs `alpha15`), the suffix is compared numerically
/// rather than lexicographically. A present-but-zero suffix (e.g. `r0` vs
/// `r`) is treated as equivalent to a missing one, mirroring Maven's
/// `IntItem.compareTo(null)`, which returns `0` for a zero-valued item
/// compared against an absent one.
fn compare_qualifiers(a: &str, b: &str) -> Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }

    let (a_prefix, a_suffix) = split_trailing_digits(a);
    let (b_prefix, b_suffix) = split_trailing_digits(b);
    let a_norm = normalize_qualifier(a_prefix, a_suffix.is_some());
    let b_norm = normalize_qualifier(b_prefix, b_suffix.is_some());

    qualifier_rank(&a_norm)
        .cmp(&qualifier_rank(&b_norm))
        .then_with(|| {
            if a_norm != b_norm {
                return a_norm.cmp(&b_norm);
            }
            match (a_suffix, b_suffix) {
                (Some(an), Some(bn)) => compare_numeric_segments(an, bn),
                (Some(an), None) => {
                    if is_zero_digits(an) {
                        Ordering::Equal
                    } else {
                        Ordering::Greater
                    }
                }
                (None, Some(bn)) => {
                    if is_zero_digits(bn) {
                        Ordering::Equal
                    } else {
                        Ordering::Less
                    }
                }
                (None, None) => Ordering::Equal,
            }
        })
}

/// Whether a digit string's value is zero (all-zero, including `"0"`,
/// `"00"`, or empty — the latter cannot occur from [`split_trailing_digits`]
/// but is handled the same way for safety).
fn is_zero_digits(digits: &str) -> bool {
    digits.bytes().all(|b| b == b'0')
}

/// Splits a qualifier into its leading prefix and a trailing run of ASCII
/// digits, if any (e.g. `"M10"` -> `("M", Some("10"))`, `"beta"` -> `("beta",
/// None)`). Only called on segments already known to be non-numeric, so the
/// prefix returned is never empty.
fn split_trailing_digits(s: &str) -> (&str, Option<&str>) {
    let prefix_len = s
        .bytes()
        .rposition(|b| !b.is_ascii_digit())
        .map_or(0, |i| i + 1);
    if prefix_len == s.len() {
        (s, None)
    } else {
        (&s[..prefix_len], Some(&s[prefix_len..]))
    }
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
        // is immediately followed by a digit (the same split_trailing_digits
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
    fn test_digit_not_at_trailing_position_falls_through_to_unknown() {
        // split_trailing_digits only peels a run of digits at the very end;
        // "rc1a" doesn't end in a digit, so it is not recognized as `rc`
        // plus a numeric suffix and ranks as an unrecognized qualifier
        // (above every known qualifier, sp included) rather than as `rc`.
        assert_eq!(compare_versions("1.0-rc1a", "1.0-rc"), Ordering::Greater);
        assert_eq!(compare_versions("1.0-rc1a", "1.0-sp"), Ordering::Greater);
    }
}

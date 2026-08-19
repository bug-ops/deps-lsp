//! Maven version comparison and pre-release detection.

use std::cmp::Ordering;

/// Detects if a Maven version string is a pre-release.
///
/// Maven pre-release qualifiers: SNAPSHOT, alpha, beta, rc, M (milestone).
pub fn is_prerelease(version: &str) -> bool {
    let v = version.to_uppercase();
    v.contains("-SNAPSHOT")
        || v.contains("-ALPHA")
        || v.contains("-BETA")
        || v.contains("-RC")
        || v.contains(".RC")
        || contains_milestone_qualifier(&v)
}

fn contains_milestone_qualifier(upper: &str) -> bool {
    // Match -M followed by digits: e.g. -M1, -M2, -M10
    let bytes = upper.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'-' && bytes[i + 1] == b'M' {
            let rest = &upper[i + 2..];
            if rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    false
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
/// compare by magnitude (leading zeros ignored, no size limit); two
/// non-numeric segments compare lexicographically.
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
/// numeric, an empty segment (produced by padding a shorter version out to
/// the longer one's length — `split_version` never yields empty segments
/// itself) represents "no further qualifier" and outranks a real qualifier,
/// so a dash-qualifier segment like `RC1` or `SNAPSHOT` sorts below the base
/// release it padded against. Two real qualifiers fall back to lexicographic
/// order, which still ranks `r09 > r08 > ... > r03` correctly relative to
/// each other.
fn compare_segment(a: &str, b: &str) -> Ordering {
    match (is_numeric_segment(a), is_numeric_segment(b)) {
        (true, true) => compare_numeric_segments(a, b),
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => match (a.is_empty(), b.is_empty()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => a.cmp(b),
        },
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
    }

    #[test]
    fn test_numeric_segment_outranks_qualifier_mid_version() {
        // "1.0-final" has a non-numeric third segment; a numeric segment at
        // the same position must still outrank it.
        assert_eq!(compare_versions("1.0.1", "1.0-final"), Ordering::Greater);
    }

    #[test]
    fn test_prerelease_sorts_below_own_base_release() {
        // junit-jupiter maven-metadata.xml case. "M1" < "RC1" here is ASCII
        // ('M' < 'R'), not a maintained alpha/beta/milestone/rc rank table;
        // both real qualifiers sort below the missing-segment base release.
        assert_eq!(compare_versions("6.1.0-M1", "6.1.0-RC1"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0-RC1", "6.1.0"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0-M1", "6.1.0"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0", "6.1.0-RC1"), Ordering::Greater);
    }

    #[test]
    fn test_prerelease_sort_matches_junit_jupiter_metadata_order() {
        // Real maven-metadata.xml version list order for junit-jupiter:
        // both qualifiers sort below the base release via `.sort_by`, not
        // just in isolated two-way comparisons ("M1" < "RC1" is coincidental
        // ASCII order, not a semantic qualifier rank).
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
}

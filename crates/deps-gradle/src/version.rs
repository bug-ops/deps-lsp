//! Gradle version ordering for plain numeric versions.

use std::cmp::Ordering;

/// Orders two Gradle versions made only of dot-separated decimal segments, or `None`.
///
/// The answer is `Some` only when a differing numeric segment decides it, or both versions are
/// numerically identical. Any non-numeric part (qualifiers, `-`, `+`, ranges), or equal leading
/// segments with different lengths (where Gradle and Maven disagree about `1.0` versus
/// `1.0.0`), gives `None`.
///
/// # Examples
///
/// ```
/// use deps_gradle::version::try_compare_versions;
/// use std::cmp::Ordering;
///
/// assert_eq!(try_compare_versions("1.10", "1.9"), Some(Ordering::Greater));
/// assert_eq!(try_compare_versions("1.0", "1.0.0"), None);
/// ```
#[must_use]
pub fn try_compare_versions(a: &str, b: &str) -> Option<Ordering> {
    let a = numeric_segments(a)?;
    let b = numeric_segments(b)?;
    if let Some(decided) = a
        .iter()
        .zip(&b)
        .map(|(x, y)| compare_digits(x, y))
        .find(|ordering| ordering.is_ne())
    {
        return Some(decided);
    }
    (a.len() == b.len()).then_some(Ordering::Equal)
}

fn numeric_segments(version: &str) -> Option<Vec<&str>> {
    version
        .split('.')
        .map(|segment| {
            (!segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit())).then_some(segment)
        })
        .collect()
}

/// Compares two digit strings numerically without a width limit.
fn compare_digits(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decisive_numeric_segment_orders() {
        assert_eq!(try_compare_versions("1.10", "1.9"), Some(Ordering::Greater));
        assert_eq!(
            try_compare_versions("2.0.0", "10.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            try_compare_versions("1.2.3", "1.2.3"),
            Some(Ordering::Equal)
        );
        assert_eq!(try_compare_versions("1.02", "1.2"), Some(Ordering::Equal));
        assert_eq!(
            try_compare_versions("1.99999999999999999999999", "1.2"),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn test_different_lengths_with_an_equal_prefix_are_not_covered() {
        assert_eq!(try_compare_versions("1.0", "1.0.0"), None);
        assert_eq!(try_compare_versions("1.0.0", "1.0"), None);
        assert_eq!(
            try_compare_versions("1.1", "1.0.0"),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn test_non_numeric_input_is_not_covered() {
        for bad in [
            "1.0-rc1",
            "1.0.RELEASE",
            "1.+",
            "[1.0,2.0)",
            "",
            "1..2",
            "1.0-SNAPSHOT",
        ] {
            assert_eq!(try_compare_versions(bad, "1.0"), None, "{bad}");
            assert_eq!(try_compare_versions("1.0", bad), None, "{bad}");
        }
    }
}

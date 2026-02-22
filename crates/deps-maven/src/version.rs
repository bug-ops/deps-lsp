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

/// Compares two Maven version strings.
///
/// Splits on `.` and `-`, compares numeric segments numerically,
/// string segments lexicographically.
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

fn compare_segment(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(an), Ok(bn)) => an.cmp(&bn),
        _ => a.cmp(b),
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
}

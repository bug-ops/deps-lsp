//! Version comparison and constraint matching for Dart packages.

use deps_core::normalize_operator_spacing;
use std::cmp::Ordering;

/// A single dot-separated SemVer 2.0.0 prerelease identifier (semver spec §11).
///
/// A purely numeric identifier compares numerically and always sorts below an
/// alphanumeric one; alphanumeric identifiers compare lexically by ASCII byte value
/// (case-sensitive — unlike NuGet's case-folded prerelease scheme, plain SemVer 2.0.0
/// does not fold case). Declaring `Numeric` before `AlphaNumeric` makes the derived
/// `Ord` rank every numeric identifier below every alphanumeric one, matching the spec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PrereleaseIdentifier {
    Numeric(u64),
    AlphaNumeric(String),
}

impl PrereleaseIdentifier {
    fn parse(s: &str) -> Self {
        if !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = s.parse::<u64>()
        {
            return Self::Numeric(n);
        }
        Self::AlphaNumeric(s.to_string())
    }
}

/// Splits `version` into its bare numeric-dot core and, if present, its raw prerelease
/// suffix. Build metadata (after `+`) is discarded first; the prerelease suffix is
/// everything after the first `-` that follows.
fn split_core_and_prerelease(version: &str) -> (&str, Option<&str>) {
    let without_build = version.split('+').next().unwrap_or(version);
    match without_build.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (without_build, None),
    }
}

/// Parses a bare numeric-dot core string into its components, leniently taking each
/// dot-separated segment's leading digit run (defaulting to `0` for a non-numeric segment).
fn parse_core_parts(core: &str) -> Vec<u64> {
    core.split('.')
        .map(|s| {
            s.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap_or(0)
        })
        .collect()
}

/// Compares two Dart version strings.
///
/// Numeric core components are compared first (a missing trailing component is treated as
/// `0`, so `"1.0"` and `"1.0.0"` compare equal), then SemVer 2.0.0 prerelease precedence
/// (spec §11) applies: a version with no prerelease outranks one with a prerelease of the
/// same core, and two prereleases are compared identifier-by-identifier, with a longer
/// identifier list outranking a shared-prefix shorter one. Build metadata (`+...`) is
/// ignored.
///
/// # Examples
///
/// ```
/// use deps_dart::version::compare_versions;
/// use std::cmp::Ordering;
///
/// assert_eq!(compare_versions("2.0.0", "2.0.0-beta1"), Ordering::Greater);
/// assert_eq!(compare_versions("2.0.0-alpha", "2.0.0-beta"), Ordering::Less);
/// assert_eq!(compare_versions("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
/// ```
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (a_core, a_pre) = split_core_and_prerelease(a);
    let (b_core, b_pre) = split_core_and_prerelease(b);

    let a_core_parts = parse_core_parts(a_core);
    let b_core_parts = parse_core_parts(b_core);

    let max_len = a_core_parts.len().max(b_core_parts.len());
    for i in 0..max_len {
        let ap = a_core_parts.get(i).copied().unwrap_or(0);
        let bp = b_core_parts.get(i).copied().unwrap_or(0);
        match ap.cmp(&bp) {
            Ordering::Equal => {}
            other => return other,
        }
    }

    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a_pre), Some(b_pre)) => {
            let a_ids: Vec<PrereleaseIdentifier> =
                a_pre.split('.').map(PrereleaseIdentifier::parse).collect();
            let b_ids: Vec<PrereleaseIdentifier> =
                b_pre.split('.').map(PrereleaseIdentifier::parse).collect();
            a_ids.cmp(&b_ids)
        }
    }
}

/// Checks if a version satisfies a Dart version constraint.
///
/// Supports: ^, >=, >, <=, <, exact, any, and space-separated AND constraints.
pub fn version_matches_constraint(version: &str, constraint: &str) -> bool {
    let constraint = normalize_operator_spacing(constraint.trim());
    version_matches_normalized_constraint(version, &constraint)
}

/// Same as [`version_matches_constraint`], but takes a constraint that has already been
/// run through [`normalize_operator_spacing`]. Callers that check many candidate versions
/// against the same constraint (e.g. a compiled [`RequirementMatcher`](deps_core::lsp_helpers::RequirementMatcher))
/// should normalize once and reuse it here instead of re-normalizing per candidate.
pub(crate) fn version_matches_normalized_constraint(version: &str, constraint: &str) -> bool {
    if constraint.is_empty() || constraint == "any" || constraint == "*" {
        return true;
    }

    // Space-separated constraints are AND logic (pub_semver intersects each comparator,
    // including a leading caret comparator combined with further clauses).
    if constraint.contains(' ') {
        return constraint
            .split_whitespace()
            .all(|c| match_single_constraint(version, c));
    }

    match_single_constraint(version, constraint)
}

fn match_single_constraint(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();

    if constraint.starts_with('^') {
        let req_ver = constraint.trim_start_matches('^');
        return matches_caret(version, req_ver);
    }

    if constraint.starts_with(">=") {
        let req_ver = constraint.trim_start_matches(">=").trim();
        return compare_versions(version, req_ver) != Ordering::Less;
    }

    if constraint.starts_with('>') {
        let req_ver = constraint.trim_start_matches('>').trim();
        return compare_versions(version, req_ver) == Ordering::Greater;
    }

    if constraint.starts_with("<=") {
        let req_ver = constraint.trim_start_matches("<=").trim();
        return compare_versions(version, req_ver) != Ordering::Greater;
    }

    if constraint.starts_with('<') {
        let req_ver = constraint.trim_start_matches('<').trim();
        return compare_versions(version, req_ver) == Ordering::Less;
    }

    // Exact match
    compare_versions(version, constraint) == Ordering::Equal
}

fn matches_caret(version: &str, requirement: &str) -> bool {
    // Same leading-digit-run extraction as `ver_parts` below, so a requirement segment with
    // a stray suffix (e.g. `"0-beta"`) zeroes to `0` instead of being dropped and shifting
    // every later segment's index.
    let req_parts: Vec<u64> = requirement
        .split('.')
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
        .filter_map(|p| p.parse().ok())
        .collect();
    let ver_parts: Vec<u64> = version
        .split('.')
        .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
        .filter_map(|p| p.parse().ok())
        .collect();

    if ver_parts.is_empty() || req_parts.is_empty() {
        return false;
    }

    if compare_versions(version, requirement) == Ordering::Less {
        return false;
    }

    let req_major = req_parts.first().copied().unwrap_or(0);
    let ver_major = ver_parts.first().copied().unwrap_or(0);

    if req_major == 0 {
        // ^0.x.y means >=0.x.y <0.(x+1).0
        let req_minor = req_parts.get(1).copied().unwrap_or(0);
        let ver_minor = ver_parts.get(1).copied().unwrap_or(0);
        ver_major == 0 && ver_minor == req_minor
    } else {
        // ^x.y.z means >=x.y.z <(x+1).0.0
        ver_major == req_major
    }
}

/// Whether `version` has a semver 2.0.0 prerelease component.
///
/// Pub requires published versions to be strict semver, so any hyphen
/// preceding optional `+build` metadata reliably marks a prerelease —
/// unlike deps-core's default keyword-based heuristic, this also catches
/// conventions not in its fixed list, e.g. Dart's `nullsafety` preview tag
/// (`2.10.0-nullsafety.1`) (#322).
pub fn is_prerelease(version: &str) -> bool {
    version.split('+').next().unwrap_or(version).contains('-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0"), Ordering::Equal);
    }

    /// Regression test for #418: a prerelease/qualifier suffix must not be silently
    /// truncated and tie with its stable counterpart.
    #[test]
    fn test_compare_versions_prerelease_vs_stable() {
        assert_eq!(compare_versions("2.0.0", "2.0.0-beta1"), Ordering::Greater);
        assert_eq!(compare_versions("2.0.0-beta1", "2.0.0"), Ordering::Less);
        assert_ne!(compare_versions("2.0.0", "2.0.0-beta1"), Ordering::Equal);
        assert_ne!(
            compare_versions("2.10.0-nullsafety.1", "2.10.0"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_prerelease_identifier_ordering() {
        // Numeric identifiers always outrank below alphanumeric ones.
        assert_eq!(compare_versions("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
        // Alphanumeric identifiers compare lexically, case-sensitively.
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-beta"),
            Ordering::Less
        );
        // A numeric identifier compares numerically, not lexically.
        assert_eq!(
            compare_versions("1.0.0-alpha.2", "1.0.0-alpha.10"),
            Ordering::Less
        );
        // More prerelease fields outrank fewer when the shared prefix is equal.
        assert_eq!(
            compare_versions("1.0.0-alpha.1", "1.0.0-alpha"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_build_metadata_ignored() {
        assert_eq!(
            compare_versions("1.0.0+build1", "1.0.0+build2"),
            Ordering::Equal
        );
        assert_eq!(
            compare_versions("1.0.0-beta+build1", "1.0.0-beta+build2"),
            Ordering::Equal
        );
    }

    /// Regression test for #418: sorting a version list must move every prerelease
    /// below its own base release, not tie with it.
    #[test]
    fn test_compare_versions_sorts_prerelease_below_stable() {
        let mut versions = vec!["2.0.0-beta1", "2.0.0", "2.0.0-alpha"];
        versions.sort_by(|a, b| compare_versions(a, b));
        assert_eq!(versions, vec!["2.0.0-alpha", "2.0.0-beta1", "2.0.0"]);
    }

    #[test]
    fn test_is_prerelease() {
        assert!(!is_prerelease("1.0.0"));
        assert!(!is_prerelease("1.0.0+build.1"));
        assert!(is_prerelease("1.0.0-dev.1"));
        // Not in deps-core's default keyword list, but still a valid semver
        // prerelease tag.
        assert!(is_prerelease("2.10.0-nullsafety.1"));
        assert!(is_prerelease("1.0.0-nullsafety.1+build"));
    }

    #[test]
    fn test_caret_constraint() {
        assert!(version_matches_constraint("1.0.0", "^1.0.0"));
        assert!(version_matches_constraint("1.5.0", "^1.0.0"));
        assert!(version_matches_constraint("1.99.99", "^1.0.0"));
        assert!(!version_matches_constraint("2.0.0", "^1.0.0"));
        assert!(!version_matches_constraint("0.9.0", "^1.0.0"));
    }

    /// Regression test for impl-critic M4/#418: a prerelease of the caret floor must not
    /// satisfy the constraint — pub_semver agrees `^1.0.0` excludes `1.0.0-beta`. Before the
    /// #418 fix, `compare_versions("1.0.0-beta", "1.0.0")` wrongly returned `Equal`, so the
    /// `Less`-rejection in `matches_caret` never triggered for this case.
    #[test]
    fn test_caret_constraint_excludes_own_floor_prerelease() {
        assert!(!version_matches_constraint("1.0.0-beta", "^1.0.0"));
    }

    #[test]
    fn test_caret_constraint_zero_major() {
        // ^0.1.0 means >=0.1.0 <0.2.0
        assert!(version_matches_constraint("0.1.0", "^0.1.0"));
        assert!(version_matches_constraint("0.1.5", "^0.1.0"));
        assert!(!version_matches_constraint("0.2.0", "^0.1.0"));
        assert!(!version_matches_constraint("0.99.0", "^0.1.0"));
        assert!(!version_matches_constraint("1.0.0", "^0.1.0"));
    }

    #[test]
    fn test_range_constraint() {
        assert!(version_matches_constraint("1.5.0", ">=1.0.0 <2.0.0"));
        assert!(version_matches_constraint("1.0.0", ">=1.0.0 <2.0.0"));
        assert!(!version_matches_constraint("2.0.0", ">=1.0.0 <2.0.0"));
        assert!(!version_matches_constraint("0.9.0", ">=1.0.0 <2.0.0"));
    }

    #[test]
    fn test_range_constraint_spaced_operators() {
        assert!(version_matches_constraint("1.15.0", ">= 1.15.0 < 2.0.0"));
        assert!(version_matches_constraint("1.99.0", ">= 1.15.0 < 2.0.0"));
        assert!(!version_matches_constraint("1.14.0", ">= 1.15.0 < 2.0.0"));
        assert!(!version_matches_constraint("2.0.0", ">= 1.15.0 < 2.0.0"));
    }

    #[test]
    fn test_caret_combined_with_spaced_upper_bound() {
        // pub_semver intersects space-separated comparators, so a caret comparator can be
        // combined with a further clause instead of split into garbage input.
        assert!(version_matches_constraint("1.5.0", "^1.0.0 < 2.0.0"));
        assert!(version_matches_constraint("1.99.0", "^1.0.0 < 2.0.0"));
        assert!(!version_matches_constraint("2.0.0", "^1.0.0 < 2.0.0"));
        assert!(!version_matches_constraint("0.9.0", "^1.0.0 < 2.0.0"));
    }

    #[test]
    fn test_exact_constraint() {
        assert!(version_matches_constraint("1.0.0", "1.0.0"));
        assert!(!version_matches_constraint("1.0.1", "1.0.0"));
    }

    #[test]
    fn test_any_constraint() {
        assert!(version_matches_constraint("1.0.0", "any"));
        assert!(version_matches_constraint("99.0.0", "any"));
        assert!(version_matches_constraint("1.0.0", ""));
    }

    #[test]
    fn test_comparison_operators() {
        assert!(version_matches_constraint("1.5.0", ">=1.0.0"));
        assert!(version_matches_constraint("1.0.0", ">=1.0.0"));
        assert!(!version_matches_constraint("0.9.0", ">=1.0.0"));

        assert!(version_matches_constraint("2.0.0", ">1.0.0"));
        assert!(!version_matches_constraint("1.0.0", ">1.0.0"));

        assert!(version_matches_constraint("1.0.0", "<=1.0.0"));
        assert!(!version_matches_constraint("1.1.0", "<=1.0.0"));

        assert!(version_matches_constraint("0.9.0", "<1.0.0"));
        assert!(!version_matches_constraint("1.0.0", "<1.0.0"));
    }
}

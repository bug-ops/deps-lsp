//! NuGet version comparison, prerelease detection, and range/floating syntax.
//!
//! # Why this is hand-rolled
//!
//! No maintained Rust crate implements NuGet's versioning scheme. NuGet versions are
//! `Major.Minor.Patch[.Revision]` (1–4 numeric components, `Major` required) with SemVer2
//! prerelease precedence and case-insensitive prerelease label comparison; the workspace's
//! `semver` crate rejects both `1.2.3.4` (too many components) and `1.2` (too few) outright, so
//! it cannot parse the common NuGet forms. `deps-maven` set the precedent for a crate-local
//! hand-rolled comparator under the same constraint (no maintained crate for Maven's scheme).

use std::cmp::Ordering;

/// A single dot-separated prerelease identifier, per SemVer2 precedence rules:
/// numeric identifiers compare numerically and always sort below alphanumeric ones;
/// alphanumeric identifiers compare lexically. NuGet's twist: alphanumeric identifiers
/// compare case-insensitively (`1.0.0-Alpha == 1.0.0-alpha`), so they are lowercased at parse
/// time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PrereleaseSegment {
    Numeric(u64),
    Alphanumeric(String),
}

impl PrereleaseSegment {
    fn parse(s: &str) -> Self {
        if !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && let Ok(n) = s.parse::<u64>()
        {
            return Self::Numeric(n);
        }
        Self::Alphanumeric(s.to_lowercase())
    }
}

impl Ord for PrereleaseSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Alphanumeric(a), Self::Alphanumeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Alphanumeric(_)) => Ordering::Less,
            (Self::Alphanumeric(_), Self::Numeric(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PrereleaseSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A parsed NuGet version: 4 numeric components (missing = 0) plus SemVer2 prerelease
/// segments. Build metadata is stripped during parsing and never retained — it is never
/// compared, and nothing in this crate round-trips a version string back from its parsed
/// form.
///
/// Kept crate-private so it cannot collide with the registry-facing `NuGetVersion` in
/// `types.rs` — this mirrors the `deps-maven` module split.
#[derive(Debug, Clone)]
pub(crate) struct ParsedVersion {
    major: u64,
    minor: u64,
    patch: u64,
    revision: u64,
    pre: Vec<PrereleaseSegment>,
}

impl ParsedVersion {
    pub(crate) fn parse(version: &str) -> Self {
        let version = version.trim();
        // Build metadata (after '+') is discarded — never compared, never retained.
        let core_and_pre = version.split('+').next().unwrap_or(version);
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((a, b)) => (a, Some(b)),
            None => (core_and_pre, None),
        };

        let mut parts = core.split('.').map(|s| s.parse::<u64>().unwrap_or(0));
        let major = parts.next().unwrap_or(0);
        let minor = parts.next().unwrap_or(0);
        let patch = parts.next().unwrap_or(0);
        let revision = parts.next().unwrap_or(0);

        let pre = pre
            .map(|p| p.split('.').map(PrereleaseSegment::parse).collect())
            .unwrap_or_default();

        Self {
            major,
            minor,
            patch,
            revision,
            pre,
        }
    }
}

fn compare_pre(a: &[PrereleaseSegment], b: &[PrereleaseSegment]) -> Ordering {
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = x.cmp(y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    // A larger set of prerelease fields has higher precedence when all preceding
    // identifiers are equal (SemVer2 rule).
    a.len().cmp(&b.len())
}

fn compare_parsed(a: &ParsedVersion, b: &ParsedVersion) -> Ordering {
    a.major
        .cmp(&b.major)
        .then_with(|| a.minor.cmp(&b.minor))
        .then_with(|| a.patch.cmp(&b.patch))
        .then_with(|| a.revision.cmp(&b.revision))
        .then_with(|| match (a.pre.is_empty(), b.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            // No prerelease has higher precedence than any prerelease of the same core.
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_pre(&a.pre, &b.pre),
        })
}

/// Compares two NuGet version strings.
///
/// 4 numeric components (missing components treated as 0), then SemVer2 prerelease
/// precedence with case-insensitive prerelease label comparison. Build metadata is ignored.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    compare_parsed(&ParsedVersion::parse(a), &ParsedVersion::parse(b))
}

/// Detects whether a NuGet version string is a prerelease version.
///
/// NuGet's rule is **structural**, not keyword-based: any version with a `-` suffix after
/// the numeric core is a prerelease, regardless of the label used. This must not be
/// confused with `deps_core::registry::Version`'s defaulted keyword-sniff implementation,
/// which recognizes only `-alpha|-beta|-rc|-dev|-pre|-snapshot|-canary|-nightly` — standard
/// .NET labels like `-rtm`, `-servicing.23`, `-CI-*`, and `-final` all match none of those
/// keywords and would be misreported as stable. See the `NuGetVersion` hand-written
/// `Version` impl in `types.rs`, which delegates here instead of using `impl_version!`.
pub fn is_prerelease(version: &str) -> bool {
    let without_build = version.split('+').next().unwrap_or(version);
    without_build.contains('-')
}

/// A parsed interval-notation version range (spec §2).
enum VersionRange {
    Exact(ParsedVersion),
    Minimum {
        version: ParsedVersion,
        inclusive: bool,
    },
    Maximum {
        version: ParsedVersion,
        inclusive: bool,
    },
    Bounded {
        min: ParsedVersion,
        min_inclusive: bool,
        max: ParsedVersion,
        max_inclusive: bool,
    },
}

fn parse_range(range: &str) -> Option<VersionRange> {
    let range = range.trim();
    if range.is_empty() {
        return None;
    }

    let first = range.chars().next()?;
    if first != '[' && first != '(' {
        // Bare version is a floor (minimum, inclusive) under PackageReference.
        return Some(VersionRange::Minimum {
            version: ParsedVersion::parse(range),
            inclusive: true,
        });
    }

    let last = range.chars().next_back()?;
    if last != ']' && last != ')' {
        return None;
    }

    let min_inclusive = first == '[';
    let max_inclusive = last == ']';
    let inner = &range[first.len_utf8()..range.len() - last.len_utf8()];

    if let Some((lo, hi)) = inner.split_once(',') {
        let lo = lo.trim();
        let hi = hi.trim();
        let min = (!lo.is_empty()).then(|| ParsedVersion::parse(lo));
        let max = (!hi.is_empty()).then(|| ParsedVersion::parse(hi));
        match (min, max) {
            (Some(min), Some(max)) => Some(VersionRange::Bounded {
                min,
                min_inclusive,
                max,
                max_inclusive,
            }),
            (Some(version), None) => Some(VersionRange::Minimum {
                version,
                inclusive: min_inclusive,
            }),
            (None, Some(version)) => Some(VersionRange::Maximum {
                version,
                inclusive: max_inclusive,
            }),
            (None, None) => None,
        }
    } else {
        // No comma inside brackets: exact pin, e.g. "[1.0]" == 1.0.
        Some(VersionRange::Exact(ParsedVersion::parse(inner.trim())))
    }
}

fn satisfies_min(v: &ParsedVersion, min: &ParsedVersion, inclusive: bool) -> bool {
    let ord = compare_parsed(v, min);
    if inclusive {
        ord != Ordering::Less
    } else {
        ord == Ordering::Greater
    }
}

fn satisfies_max(v: &ParsedVersion, max: &ParsedVersion, inclusive: bool) -> bool {
    let ord = compare_parsed(v, max);
    if inclusive {
        ord != Ordering::Greater
    } else {
        ord == Ordering::Less
    }
}

/// Checks whether `version` satisfies a NuGet interval-notation `range` (spec §2).
///
/// Supports bare floors (`1.0`), exact pins (`[1.0]`), open/closed minimums and maximums
/// (`[1.0,)`, `(,1.0]`, ...), and bounded intervals (`[1.0,2.0)`, ...). Returns `false` for
/// unparseable ranges rather than panicking.
pub fn satisfies(version: &str, range: &str) -> bool {
    let Some(parsed_range) = parse_range(range) else {
        return false;
    };
    let v = ParsedVersion::parse(version);

    match parsed_range {
        VersionRange::Exact(target) => compare_parsed(&v, &target) == Ordering::Equal,
        VersionRange::Minimum { version, inclusive } => satisfies_min(&v, &version, inclusive),
        VersionRange::Maximum { version, inclusive } => satisfies_max(&v, &version, inclusive),
        VersionRange::Bounded {
            min,
            min_inclusive,
            max,
            max_inclusive,
        } => satisfies_min(&v, &min, min_inclusive) && satisfies_max(&v, &max, max_inclusive),
    }
}

/// A parsed floating-version pattern (spec §2).
enum FloatPattern {
    /// `*` (stable only) or `*-*` (including prerelease).
    Any { include_prerelease: bool },
    /// `1.1.*` (stable only) or `1.1.*-*` (including prerelease); `prefix` is the
    /// dot-separated numeric prefix (e.g. `"1.1"`).
    NumericPrefix {
        prefix: String,
        include_prerelease: bool,
    },
    /// `1.2.0-rc.*`: matches the stable version `1.2.0` itself, or any prerelease whose
    /// numeric core is `1.2.0` and whose prerelease label starts with `rc`.
    PrereleaseLabelPrefix {
        stable_prefix: String,
        label_prefix: String,
    },
}

fn parse_float(pattern: &str) -> Option<FloatPattern> {
    let pattern = pattern.trim();
    if pattern == "*" {
        return Some(FloatPattern::Any {
            include_prerelease: false,
        });
    }
    if pattern == "*-*" {
        return Some(FloatPattern::Any {
            include_prerelease: true,
        });
    }

    if let Some(prefix) = pattern.strip_suffix(".*-*") {
        return Some(FloatPattern::NumericPrefix {
            prefix: prefix.to_string(),
            include_prerelease: true,
        });
    }

    if let Some(prefix) = pattern.strip_suffix(".*") {
        if let Some((stable, label)) = prefix.split_once('-') {
            return Some(FloatPattern::PrereleaseLabelPrefix {
                stable_prefix: stable.to_string(),
                label_prefix: label.to_string(),
            });
        }
        return Some(FloatPattern::NumericPrefix {
            prefix: prefix.to_string(),
            include_prerelease: false,
        });
    }

    None
}

/// Returns true if `version`'s numeric core has `prefix` as an exact dot-separated
/// component prefix (e.g. `"1.1"` matches `"1.1.5"` but not `"1.10"`).
fn numeric_prefix_matches(version: &str, prefix: &str) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let core_parts: Vec<&str> = core.split('.').collect();
    let prefix_parts: Vec<&str> = prefix.split('.').collect();
    if prefix_parts.len() > core_parts.len() {
        return false;
    }
    core_parts
        .iter()
        .zip(prefix_parts.iter())
        .all(|(c, p)| c == p)
}

/// Returns true if `version`'s numeric core exactly equals `stable_prefix`'s numeric core.
fn stable_core_matches(version: &str, stable_prefix: &str) -> bool {
    let v = ParsedVersion::parse(version);
    let s = ParsedVersion::parse(stable_prefix);
    v.major == s.major && v.minor == s.minor && v.patch == s.patch && v.revision == s.revision
}

/// Returns true if `version`'s prerelease label starts with `label_prefix`, case-insensitively.
fn prerelease_label_starts_with(version: &str, label_prefix: &str) -> bool {
    let Some((_, pre)) = version.split_once('-') else {
        return false;
    };
    let pre = pre.split('+').next().unwrap_or(pre);
    pre.to_lowercase().starts_with(&label_prefix.to_lowercase())
}

/// Resolves a floating-version pattern (`*`, `1.1.*`, `*-*`, `1.2.0-rc.*`, ...) against a
/// list of available versions, returning the highest matching version.
///
/// Prerelease versions are excluded unless the pattern is itself prerelease-bearing
/// (`*-*`, `*.-*`) or the prerelease-label-prefix form is used. Returns `None` if the
/// pattern cannot be parsed or no version matches.
pub fn resolve_float<'a>(versions: &'a [String], pattern: &str) -> Option<&'a str> {
    let float = parse_float(pattern)?;
    let mut best: Option<(&'a str, ParsedVersion)> = None;

    for v in versions {
        let parsed = ParsedVersion::parse(v);
        let matches = match &float {
            FloatPattern::Any { include_prerelease } => {
                *include_prerelease || parsed.pre.is_empty()
            }
            FloatPattern::NumericPrefix {
                prefix,
                include_prerelease,
            } => {
                (*include_prerelease || parsed.pre.is_empty()) && numeric_prefix_matches(v, prefix)
            }
            FloatPattern::PrereleaseLabelPrefix {
                stable_prefix,
                label_prefix,
            } => {
                stable_core_matches(v, stable_prefix)
                    && (parsed.pre.is_empty() || prerelease_label_starts_with(v, label_prefix))
            }
        };
        if !matches {
            continue;
        }

        let is_better = best.as_ref().is_none_or(|(_, best_parsed)| {
            compare_parsed(&parsed, best_parsed) == Ordering::Greater
        });
        if is_better {
            best = Some((v.as_str(), parsed));
        }
    }

    best.map(|(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions_basic() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("10.0.0", "9.0.0"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_missing_components_are_zero() {
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1", "1.0.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.2", "1.2.0.1"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_four_component() {
        assert_eq!(compare_versions("1.0.0.1", "1.0.0.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0.10", "1.0.0.9"), Ordering::Greater);
    }

    #[test]
    fn test_compare_versions_stable_beats_prerelease() {
        assert_eq!(compare_versions("1.0.0", "1.0.0-rc"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-rc", "1.0.0"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_prerelease_case_insensitive() {
        assert_eq!(
            compare_versions("1.0.0-Alpha", "1.0.0-alpha"),
            Ordering::Equal
        );
        assert_eq!(
            compare_versions("1.0.0-RC.1", "1.0.0-rc.1"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_prerelease_numeric_vs_alphanumeric() {
        // Numeric identifiers always have lower precedence than alphanumeric ones.
        assert_eq!(compare_versions("1.0.0-1", "1.0.0-alpha"), Ordering::Less);
    }

    #[test]
    fn test_compare_versions_prerelease_more_fields_higher_precedence() {
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
            compare_versions("1.0.0-rc+build1", "1.0.0-rc+build2"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_is_prerelease_dotnet_labels() {
        // Real .NET prerelease labels that the shared keyword sniff in
        // deps_core::registry::Version::is_prerelease (-alpha|-beta|-rc|-dev|-pre|-snapshot|
        // -canary|-nightly) would all misclassify as stable.
        assert!(is_prerelease("13.0.0-rtm"));
        assert!(is_prerelease("8.0.0-servicing.23"));
        assert!(is_prerelease("1.0.0-CI-20240101"));
        assert!(is_prerelease("6.0.0-final"));
        assert!(is_prerelease("7.0.0-preview.1"));
    }

    #[test]
    fn test_is_prerelease_stable() {
        assert!(!is_prerelease("1.0.0"));
        assert!(!is_prerelease("13.0.0"));
        assert!(!is_prerelease("1.0.0.5"));
    }

    #[test]
    fn test_is_prerelease_ignores_build_metadata() {
        assert!(!is_prerelease("1.0.0+build-with-dash"));
        assert!(is_prerelease("1.0.0-rc+build"));
    }

    #[test]
    fn test_satisfies_bare_is_minimum_inclusive() {
        assert!(satisfies("1.0.0", "1.0"));
        assert!(satisfies("2.0.0", "1.0"));
        assert!(!satisfies("0.9.0", "1.0"));
    }

    #[test]
    fn test_satisfies_exact_pin() {
        assert!(satisfies("1.0.0", "[1.0]"));
        assert!(satisfies("1.0", "[1.0.0]"));
        assert!(!satisfies("1.0.1", "[1.0]"));
    }

    #[test]
    fn test_satisfies_open_minimum() {
        assert!(satisfies("1.0.0", "[1.0,)"));
        assert!(satisfies("1.5.0", "[1.0,)"));
        assert!(!satisfies("0.9.0", "[1.0,)"));

        assert!(satisfies("1.0.1", "(1.0,)"));
        assert!(!satisfies("1.0.0", "(1.0,)"));
    }

    #[test]
    fn test_satisfies_open_maximum() {
        assert!(satisfies("1.0.0", "(,1.0]"));
        assert!(!satisfies("1.0.1", "(,1.0]"));

        assert!(satisfies("0.9.0", "(,1.0)"));
        assert!(!satisfies("1.0.0", "(,1.0)"));
    }

    #[test]
    fn test_satisfies_bounded() {
        assert!(satisfies("1.5.0", "[1.0,2.0]"));
        assert!(satisfies("2.0.0", "[1.0,2.0]"));
        assert!(!satisfies("2.0.0", "[1.0,2.0)"));
        assert!(!satisfies("1.0.0", "(1.0,2.0)"));
        assert!(satisfies("1.0.1", "(1.0,2.0)"));
        assert!(!satisfies("1.0.0", "(1.0,2.0]"));
        assert!(satisfies("1.0.1", "(1.0,2.0]"));
    }

    #[test]
    fn test_satisfies_malformed_range_returns_false() {
        assert!(!satisfies("1.0.0", ""));
        assert!(!satisfies("1.0.0", "[1.0"));
        assert!(!satisfies("1.0.0", "(,)"));
    }

    #[test]
    fn test_resolve_float_any_stable_only() {
        let versions: Vec<String> = ["1.0.0", "2.0.0-rc", "1.5.0"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "*"), Some("1.5.0"));
    }

    #[test]
    fn test_resolve_float_any_including_prerelease() {
        let versions: Vec<String> = ["1.0.0", "2.0.0-rc", "1.5.0"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "*-*"), Some("2.0.0-rc"));
    }

    #[test]
    fn test_resolve_float_numeric_prefix_stable() {
        let versions: Vec<String> = ["1.1.0", "1.1.5", "1.2.0", "1.1.9-beta"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "1.1.*"), Some("1.1.5"));
    }

    #[test]
    fn test_resolve_float_numeric_prefix_including_prerelease() {
        let versions: Vec<String> = ["1.1.0", "1.1.5", "1.1.9-beta"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "1.1.*-*"), Some("1.1.9-beta"));
    }

    #[test]
    fn test_resolve_float_prerelease_label_prefix_stable_wins() {
        let versions: Vec<String> = ["1.2.0-rc.1", "1.2.0-rc.2", "1.2.0"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "1.2.0-rc.*"), Some("1.2.0"));
    }

    #[test]
    fn test_resolve_float_prerelease_label_prefix_no_stable() {
        let versions: Vec<String> = ["1.2.0-rc.1", "1.2.0-rc.2", "1.2.0-beta"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(resolve_float(&versions, "1.2.0-rc.*"), Some("1.2.0-rc.2"));
    }

    #[test]
    fn test_resolve_float_no_match_returns_none() {
        let versions: Vec<String> = vec!["2.0.0".to_string()];
        assert_eq!(resolve_float(&versions, "1.1.*"), None);
    }

    #[test]
    fn test_resolve_float_invalid_pattern_returns_none() {
        let versions: Vec<String> = vec!["1.0.0".to_string()];
        assert_eq!(resolve_float(&versions, "not-a-pattern"), None);
    }
}

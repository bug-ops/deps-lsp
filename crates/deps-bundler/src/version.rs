//! Version comparison utilities for Ruby gems.
//!
//! Provides version comparison and requirement matching for Bundler ecosystem,
//! ported directly from RubyGems' own `Gem::Version#<=>`,
//! `Gem::Version#canonical_segments`, `#release`, and `#bump` so that
//! ordering and `~>` requirement matching match `Gem::Version`/
//! `Gem::Requirement` exactly, including prerelease-vs-prerelease
//! tie-breaking and pessimistic-operator ceiling rules (#323, #327).

use std::cmp::Ordering;

/// A single alternating digit/letter run extracted from a version string.
///
/// Mirrors the segments produced by `Gem::Version#segments`
/// (`version.scan(/[0-9]+|[a-z]+/i)`): a numeric run is kept as its raw digit
/// string rather than parsed into a fixed-width integer, so an arbitrarily
/// long digit run (e.g. 20+ digits) is never silently dropped on overflow
/// (#327 M8).
#[derive(Clone, Debug)]
enum Token {
    /// A run of ASCII digits, compared as an arbitrary-precision
    /// non-negative integer via [`cmp_digits`].
    Numeric(String),
    /// A run of ASCII letters, compared case-sensitively like Ruby's default
    /// string `<=>`.
    Alpha(String),
}

impl Token {
    /// Whether this token is a numeric run whose value is zero.
    fn is_zero(&self) -> bool {
        matches!(self, Self::Numeric(s) if is_zero_digits(s))
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => cmp_digits(a, b) == Ordering::Equal,
            (Self::Alpha(a), Self::Alpha(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Token {}

/// Whether every character of a digit run is `0`.
fn is_zero_digits(s: &str) -> bool {
    s.bytes().all(|b| b == b'0')
}

/// Compares two non-negative digit strings as arbitrary-precision integers.
///
/// Leading zeros are stripped first, so the comparison never overflows a
/// fixed-width type regardless of how many digits either run has (#327 M8).
fn cmp_digits(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Tokenizes `version` into alternating digit/letter runs, skipping
/// separators (`.`, `+`, ...).
///
/// A literal `-` is first rewritten to `.pre.`, mirroring
/// `Gem::Version#initialize`'s `@version.gsub!("-", ".pre.")` — RubyGems
/// treats a hyphenated suffix as an implicit `pre` segment, so `1.0.0-1`
/// tokenizes identically to `1.0.0.pre.1` and sorts as a prerelease of
/// `1.0.0` rather than above it (#327 M7).
///
/// RubyGems' own prerelease tags can be dot-separated (`3.7.0.pre1`) or
/// glued directly onto the preceding numeric segment (`0.2.19b1`) —
/// scanning the whole string instead of splitting on `.` first handles both
/// shapes uniformly (#323).
fn tokenize(version: &str) -> Vec<Token> {
    let normalized = version.replace('-', ".pre.");
    let bytes = normalized.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i].is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            tokens.push(Token::Numeric(normalized[start..i].to_string()));
        } else if bytes[i].is_ascii_alphabetic() {
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            tokens.push(Token::Alpha(normalized[start..i].to_string()));
        } else {
            i += 1;
        }
    }
    tokens
}

/// Ports `Gem::Version#canonical_segments`: strips the trailing zero
/// segments that RubyGems considers redundant before comparing.
///
/// Two passes, applied in the same order RubyGems applies them:
/// 1. Trailing `Numeric(0)` segments are dropped from the very end of the
///    version (`"1.0.0"` canonicalizes to `[1]`), always leaving at least
///    one segment.
/// 2. For a prerelease version (one containing any alpha segment), the run
///    of `Numeric(0)` segments immediately preceding the *first* alpha
///    segment is also dropped (`"3.0.pre"` canonicalizes to `[3, "pre"]`).
///
/// Without step 2, a padded comparison would compare the implicit zero
/// before a short prerelease tag against the zero before a longer one
/// positionally, rather than comparing the tags themselves — the root cause
/// of `"3.0.0.beta"` sorting on the wrong side of `"3.0.pre"` (#327 M6).
fn canonical_segments(version: &str) -> Vec<Token> {
    let mut tokens = tokenize(version);
    let prerelease = tokens.iter().any(|t| matches!(t, Token::Alpha(_)));

    while tokens.len() > 1 && tokens.last().is_some_and(Token::is_zero) {
        tokens.pop();
    }

    if prerelease
        && let Some(first_alpha) = tokens.iter().position(|t| matches!(t, Token::Alpha(_)))
    {
        let mut start = first_alpha;
        while start > 0 && tokens[start - 1].is_zero() {
            start -= 1;
        }
        tokens.drain(start..first_alpha);
    }

    tokens
}

/// Compares two version strings, prerelease-aware.
///
/// Ports `Gem::Version#<=>` over the canonical segment lists produced by
/// `canonical_segments`: shared positions compare numerically or
/// alphabetically depending on token kind (an alpha segment always sorts
/// below a numeric one at the same position), and once one side runs out of
/// segments, the other side's first decisive trailing segment settles the
/// result — an extra alpha segment means that side is a prerelease of the
/// other (sorts lower), an extra nonzero numeric segment means it is more
/// precise (sorts higher), and trailing zero segments are equivalent to not
/// being there at all.
///
/// # Examples
///
/// ```
/// use deps_bundler::version::compare_versions;
/// use std::cmp::Ordering;
///
/// assert_eq!(compare_versions("1.0.1", "1.0.0"), Ordering::Greater);
/// assert_eq!(compare_versions("1.0.0", "1.0.0"), Ordering::Equal);
///
/// // A dot-notation prerelease tag sorts below its own base release.
/// assert_eq!(compare_versions("1.0.0", "1.0.0.pre1"), Ordering::Greater);
///
/// // RubyGems rewrites a hyphenated suffix as an implicit prerelease tag,
/// // so it sorts below the release too, not above it.
/// assert_eq!(compare_versions("1.0.0", "1.0.0-1"), Ordering::Greater);
/// ```
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let lhs = canonical_segments(a);
    let rhs = canonical_segments(b);

    if lhs == rhs {
        return Ordering::Equal;
    }

    let limit = lhs.len().min(rhs.len());
    for i in 0..limit {
        let ordering = match (&lhs[i], &rhs[i]) {
            (Token::Numeric(x), Token::Numeric(y)) => cmp_digits(x, y),
            (Token::Alpha(x), Token::Alpha(y)) => x.cmp(y),
            (Token::Alpha(_), Token::Numeric(_)) => Ordering::Less,
            (Token::Numeric(_), Token::Alpha(_)) => Ordering::Greater,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if lhs.len() <= rhs.len() {
        for token in &rhs[limit..] {
            match token {
                Token::Alpha(_) => return Ordering::Greater,
                Token::Numeric(n) if !is_zero_digits(n) => return Ordering::Less,
                _ => {}
            }
        }
    } else {
        for token in &lhs[limit..] {
            match token {
                Token::Alpha(_) => return Ordering::Less,
                Token::Numeric(n) if !is_zero_digits(n) => return Ordering::Greater,
                _ => {}
            }
        }
    }
    Ordering::Equal
}

/// Checks if a version matches the given requirement.
pub fn version_matches_requirement(version: &str, requirement: &str) -> bool {
    let req = requirement.trim();

    if req == "*" {
        return true;
    }

    // Pessimistic operator (~>)
    if req.starts_with("~>") {
        let req_ver = req.trim_start_matches("~>").trim();
        return matches_pessimistic(version, req_ver);
    }

    // Greater than or equal
    if req.starts_with(">=") {
        let req_ver = req.trim_start_matches(">=").trim();
        return compare_versions(version, req_ver) != Ordering::Less;
    }

    // Greater than
    if req.starts_with('>') && !req.starts_with(">=") {
        let req_ver = req.trim_start_matches('>').trim();
        return compare_versions(version, req_ver) == Ordering::Greater;
    }

    // Less than or equal
    if req.starts_with("<=") {
        let req_ver = req.trim_start_matches("<=").trim();
        return compare_versions(version, req_ver) != Ordering::Greater;
    }

    // Less than
    if req.starts_with('<') && !req.starts_with("<=") {
        let req_ver = req.trim_start_matches('<').trim();
        return compare_versions(version, req_ver) == Ordering::Less;
    }

    // Not equal
    if req.starts_with("!=") {
        let req_ver = req.trim_start_matches("!=").trim();
        return version != req_ver;
    }

    // Exact match
    if let Some(req_ver) = req.strip_prefix('=') {
        return version == req_ver.trim();
    }

    // Default: exact match or prefix match
    version == req || version.starts_with(&format!("{req}."))
}

/// Joins a token slice back into a dot-separated version string.
fn join_tokens(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(|t| match t {
            Token::Numeric(s) | Token::Alpha(s) => s.as_str(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Increments a non-negative decimal digit string by one.
///
/// Works on the raw digit string rather than a fixed-width integer, so an
/// arbitrarily long digit run increments correctly instead of overflowing
/// (#327 C3 — the same silent-drop failure class M8 removed from the
/// tokenizer, previously reintroduced here via `parse::<u64>()`).
fn increment_digits(digits: &str) -> String {
    let mut bytes = digits.as_bytes().to_vec();
    let mut i = bytes.len();
    loop {
        if i == 0 {
            bytes.insert(0, b'1');
            break;
        }
        i -= 1;
        if bytes[i] == b'9' {
            bytes[i] = b'0';
        } else {
            bytes[i] += 1;
            break;
        }
    }
    String::from_utf8(bytes).expect("incrementing ASCII digits stays valid UTF-8")
}

/// Ports `Gem::Version#release`: the numeric prefix before the first
/// prerelease tag, as a dot-joined string. A version with no prerelease tag
/// is returned unchanged (re-joined from its own tokens).
fn release_string(version: &str) -> String {
    let tokens = tokenize(version);
    let end = tokens
        .iter()
        .position(|t| matches!(t, Token::Alpha(_)))
        .unwrap_or(tokens.len());
    join_tokens(&tokens[..end])
}

/// Ports `Gem::Version#bump`: the exclusive upper bound for a `~>`
/// requirement, as a dot-joined string.
///
/// Truncates at the first prerelease tag (same as [`release_string`]), drops
/// one more trailing segment if more than one remains, then increments the
/// new last segment — e.g. `bump_string("3.7.0")` is `"3.8"` and
/// `bump_string("3.7")` is `"4"`. Returns `None` only if the requirement has
/// no numeric segment to increment at all (a malformed requirement).
fn bump_string(requirement: &str) -> Option<String> {
    let tokens = tokenize(requirement);
    let end = tokens
        .iter()
        .position(|t| matches!(t, Token::Alpha(_)))
        .unwrap_or(tokens.len());
    let mut segments = tokens[..end].to_vec();
    if segments.len() > 1 {
        segments.pop();
    }
    match segments.last_mut()? {
        Token::Numeric(s) => *s = increment_digits(s),
        Token::Alpha(_) => unreachable!("segments before the first alpha token contain no alpha"),
    }
    Some(join_tokens(&segments))
}

/// Checks if a version matches a pessimistic requirement (`~>`).
///
/// Ports RubyGems' own pessimistic-operator check
/// (`Gem::Requirement::OPS["~>"]`): `version >= requirement` and
/// `version.release < requirement.bump`, via [`release_string`] and
/// [`bump_string`] — e.g. `~> 3.7.0` is `>= 3.7.0, < 3.8`, and `~> 3.7` is
/// `>= 3.7, < 4`.
///
/// Comparing against the version's *release* (not the raw version) means a
/// prerelease of the ceiling correctly falls outside the range — e.g.
/// `3.8.0.pre1` does not satisfy `~> 3.7.0`, since its release `3.8.0` is
/// not less than the ceiling `3.8` (#327 C1). Building the ceiling via
/// [`bump_string`] instead of bumping a dot-separated substring means a
/// requirement with its own prerelease tag bumps correctly instead of
/// ignoring the tag or silently matching nothing (#327 C2).
fn matches_pessimistic(version: &str, requirement: &str) -> bool {
    if compare_versions(version, requirement) == Ordering::Less {
        return false;
    }

    let Some(ceiling) = bump_string(requirement) else {
        return false;
    };

    compare_versions(&release_string(version), &ceiling) == Ordering::Less
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
        assert_eq!(compare_versions("1.0", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_dot_notation_prerelease() {
        // Regression test for #323: a non-numeric trailing segment (RubyGems'
        // dot-notation prerelease tag) must not be silently dropped and tie
        // with the base release.
        assert_eq!(compare_versions("3.7.0", "3.7.0.pre1"), Ordering::Greater);
        assert_eq!(compare_versions("3.7.0.pre1", "3.7.0"), Ordering::Less);
        assert_ne!(compare_versions("3.7.0", "3.7.0.pre1"), Ordering::Equal);

        assert_eq!(compare_versions("3.7.0", "3.7.0.pre2"), Ordering::Greater);
        assert_ne!(compare_versions("3.7.0", "3.7.0.pre2"), Ordering::Equal);

        // pre1 and pre2 must not tie with each other either.
        assert_eq!(compare_versions("3.7.0.pre1", "3.7.0.pre2"), Ordering::Less);
        assert_ne!(
            compare_versions("3.7.0.pre1", "3.7.0.pre2"),
            Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_multi_digit_prerelease_ordinal() {
        // Regression test for critic finding S1: a lexicographic tie-break
        // mis-orders multi-digit ordinals ("beta10" < "beta2" as strings).
        // RubyGems compares the numeric run itself, so beta10 > beta2.
        assert_eq!(
            compare_versions("4.0.0.beta10", "4.0.0.beta2"),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions("4.0.0.beta2", "4.0.0.beta10"),
            Ordering::Less
        );
        assert_eq!(compare_versions("2.0.0.a10", "2.0.0.a9"), Ordering::Greater);
        assert_eq!(
            compare_versions("3.0.0.pre.beta10", "3.0.0.pre.beta2"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_compare_versions_glued_prerelease_tag() {
        // Regression test for critic finding S2: a prerelease tag glued
        // directly onto the trailing numeric segment (no separating dot)
        // must not be silently dropped and tie with the base release.
        assert_eq!(compare_versions("0.2.19", "0.2.19b1"), Ordering::Greater);
        assert_eq!(compare_versions("0.2.19b1", "0.2.19"), Ordering::Less);
        assert_ne!(compare_versions("0.2.19", "0.2.19b1"), Ordering::Equal);

        assert_eq!(compare_versions("0.2.19b1", "0.2.19b2"), Ordering::Less);
        assert_ne!(compare_versions("0.2.19b1", "0.2.19b2"), Ordering::Equal);

        assert_eq!(
            compare_versions("0.11.0pre220", "0.11.0pre229"),
            Ordering::Less
        );

        // Hyphenated tag (not dot- or glue-separated) must also not tie.
        assert_eq!(compare_versions("1.0.0", "1.0.0-beta"), Ordering::Greater);
        assert_ne!(compare_versions("1.0.0", "1.0.0-beta"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_trailing_zero_before_prerelease_tag() {
        // Regression test for #327 M6: a padded, position-by-position
        // compare gets this backwards (treats an implicit zero segment as
        // outranking the other side's tag). RubyGems collapses the zero
        // segment(s) immediately before the first prerelease tag, so this
        // reduces to comparing "beta" against "pre" directly, and
        // "beta" < "pre" alphabetically.
        assert_eq!(compare_versions("3.0.0.beta", "3.0.pre"), Ordering::Less);
        assert_eq!(compare_versions("3.0.pre", "3.0.0.beta"), Ordering::Greater);
        assert_ne!(compare_versions("3.0.0.beta", "3.0.pre"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_hyphen_is_implicit_pre() {
        // Regression test for #327 M7: RubyGems rewrites "1.0.0-1" to
        // "1.0.0.pre.1" internally, so it must sort as a prerelease of
        // "1.0.0" (below it), not above it as a naive numeric-outranks-alpha
        // compare against a bare hyphen-skipped "1" would produce.
        assert_eq!(compare_versions("1.0.0-1", "1.0.0"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0-1"), Ordering::Greater);
        assert_ne!(compare_versions("1.0.0-1", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn test_compare_versions_oversized_digit_run() {
        // Regression test for #327 M8: a 20+ digit numeric segment must not
        // silently overflow a fixed-width parse and get dropped, which would
        // falsely tie it with a version lacking that segment entirely.
        let huge = "1.0.0.100000000000000000000";
        assert_ne!(compare_versions("1.0.0", huge), Ordering::Equal);
        assert_eq!(compare_versions("1.0.0", huge), Ordering::Less);
        assert_eq!(compare_versions(huge, "1.0.0"), Ordering::Greater);

        // Arbitrary-precision ordering, not a fixed-width overflow: a
        // 21-digit run must outrank a 20-digit run regardless of the u64
        // range boundary sitting between them.
        assert_eq!(
            compare_versions("1.0.100000000000000000000", "1.0.99999999999999999999"),
            Ordering::Greater
        );
    }

    #[test]
    fn test_matches_pessimistic() {
        // ~> 1.0 means >= 1.0, < 2.0
        assert!(matches_pessimistic("1.0.5", "1.0"));
        assert!(matches_pessimistic("1.0.0", "1.0"));
        assert!(matches_pessimistic("1.9.9", "1.0"));
        assert!(!matches_pessimistic("2.0.0", "1.0"));

        // ~> 1.0.5 means >= 1.0.5, < 1.1.0
        assert!(matches_pessimistic("1.0.5", "1.0.5"));
        assert!(matches_pessimistic("1.0.9", "1.0.5"));
        assert!(!matches_pessimistic("1.1.0", "1.0.5"));
        assert!(!matches_pessimistic("1.0.4", "1.0.5"));
    }

    #[test]
    fn test_matches_pessimistic_prerelease_below_floor() {
        // Regression test for #327 M1: matches_pessimistic used to compute
        // the last-segment comparison from the requirement's precision only,
        // silently dropping any version segment past that precision — so
        // "3.7.0.pre1" (a prerelease below 3.7.0) was wrongly treated as
        // satisfying "~> 3.7.0".
        assert!(!matches_pessimistic("3.7.0.pre1", "3.7.0"));
        assert!(!matches_pessimistic("3.7.0.pre1", "3.7"));
        assert!(matches_pessimistic("3.7.1", "3.7.0"));
    }

    #[test]
    fn test_matches_pessimistic_prerelease_above_ceiling() {
        // Regression test for critic finding C1: the ceiling comparison
        // used to run against the raw version instead of its release, so a
        // prerelease *of* the ceiling version wrongly satisfied the
        // requirement (RubyGems compares `version.release < requirement.bump`).
        assert!(!matches_pessimistic("3.8.0.pre1", "3.7.0"));
        assert!(!matches_pessimistic("4.0.0.beta1", "3.7"));
        assert!(!matches_pessimistic("2.0.0.rc1", "1.9"));
    }

    #[test]
    fn test_matches_pessimistic_requirement_with_prerelease_tag() {
        // Regression test for critic finding C2: the ceiling used to bump
        // the second-to-last dot-separated *string* part of the
        // requirement, ignoring any prerelease tag in the requirement
        // itself. Gem::Version#bump truncates at the requirement's own
        // first alpha segment before bumping, so a requirement tag must not
        // change the ceiling's precision or make the requirement
        // unsatisfiable.
        assert!(matches_pessimistic("1.5.0", "1.0.pre"));
        assert!(!matches_pessimistic("2.0.0", "1.0.pre"));

        assert!(matches_pessimistic("1.0.5", "1.0.0.rc1"));
        assert!(!matches_pessimistic("1.1.0", "1.0.0.rc1"));

        assert!(matches_pessimistic("0.1.2", "0.0.rc1"));
        assert!(!matches_pessimistic("1.0.0", "0.0.rc1"));

        // These used to match nothing at all: the requirement's second-to-last
        // *string* part ("b"/"pre") has no digit prefix, so the old
        // `parse::<u64>()` silently failed the whole match.
        assert!(matches_pessimistic("2.5.0", "2.b.1"));
        assert!(!matches_pessimistic("3.0.0", "2.b.1"));

        assert!(matches_pessimistic("1.5.0", "1.pre.2"));
        assert!(!matches_pessimistic("2.0.0", "1.pre.2"));
    }

    #[test]
    fn test_matches_pessimistic_oversized_digit_run() {
        // Regression test for critic finding C3: matches_pessimistic still
        // called parse::<u64>() to build the ceiling, reintroducing the
        // exact silent-drop-on-overflow bug M8 removed from the tokenizer —
        // a 20+ digit segment in the requirement made the whole match
        // silently fail instead of comparing on its real value.
        assert!(matches_pessimistic(
            "1.100000000000000000000.5",
            "1.100000000000000000000.0"
        ));
        assert!(matches_pessimistic(
            "18446744073709551615.0.1",
            "18446744073709551615.0.0"
        ));
    }

    #[test]
    fn test_version_matches_requirement() {
        // Pessimistic operator
        assert!(version_matches_requirement("7.0.8", "~> 7.0"));
        assert!(version_matches_requirement("7.0.0", "~> 7.0"));
        assert!(!version_matches_requirement("8.0.0", "~> 7.0"));

        // Greater than or equal
        assert!(version_matches_requirement("1.5.0", ">= 1.1"));
        assert!(version_matches_requirement("1.1.0", ">= 1.1"));
        assert!(!version_matches_requirement("1.0.0", ">= 1.1"));

        // Greater than
        assert!(version_matches_requirement("2.0.0", "> 1.0"));
        assert!(!version_matches_requirement("1.0.0", "> 1.0"));

        // Less than or equal
        assert!(version_matches_requirement("1.0.0", "<= 1.0"));
        assert!(!version_matches_requirement("1.1.0", "<= 1.0"));

        // Less than
        assert!(version_matches_requirement("0.9.0", "< 1.0"));
        assert!(!version_matches_requirement("1.0.0", "< 1.0"));

        // Exact match
        assert!(version_matches_requirement("1.0.0", "= 1.0.0"));
        assert!(!version_matches_requirement("1.0.1", "= 1.0.0"));

        // Not equal
        assert!(version_matches_requirement("1.0.1", "!= 1.0.0"));
        assert!(!version_matches_requirement("1.0.0", "!= 1.0.0"));

        // Wildcard
        assert!(version_matches_requirement("1.0.0", "*"));
        assert!(version_matches_requirement("0.0.1", "*"));
        assert!(version_matches_requirement("99.99.99", "*"));
    }
}

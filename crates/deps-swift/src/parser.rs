//! Package.swift parser using regex-based approach.
//!
//! Parses .package() declarations using regular expressions after stripping
//! comments to avoid false positives. Byte offsets are preserved during
//! comment stripping for accurate LSP position tracking.

use crate::types::SwiftDependency;
use deps_core::Result;
use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
use deps_core::parser::DependencySource;
use regex::Regex;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::{Range, Uri};

/// Result of parsing a Package.swift file.
#[non_exhaustive]
#[derive(Debug)]
pub struct SwiftParseResult {
    /// Dependencies found in the `Package.swift` manifest.
    pub dependencies: Vec<SwiftDependency>,
    /// URI of the manifest this result was parsed from.
    pub uri: Uri,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

deps_core::impl_parse_result!(
    SwiftParseResult,
    SwiftDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

// Regex patterns for various .package() call forms.
// All use (?s) DOTALL flag to handle multiline calls.

// Compile-time-constant patterns; a malformed literal is a build-visible programmer error,
// not attacker-influenceable input.
#[allow(clippy::expect_used)]
static RE_URL_FROM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*from\s*:\s*"([^"]+)"\s*\)"#)
        .expect("RE_URL_FROM")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_UP_TO_NEXT_MAJOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMajor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_UP_TO_NEXT_MAJOR")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_UP_TO_NEXT_MINOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMinor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_UP_TO_NEXT_MINOR")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_EXACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.exact\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_EXACT")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_RANGE_HALF_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\.\.<\s*"([^"]+)"\s*\)"#,
    )
    .expect("RE_URL_RANGE_HALF_OPEN")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_RANGE_CLOSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\.\.\.\s*"([^"]+)"\s*\)"#,
    )
    .expect("RE_URL_RANGE_CLOSED")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.branch\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_BRANCH")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_URL_REVISION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.revision\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_REVISION")
});

// Same guarantee as RE_URL_FROM above.
#[allow(clippy::expect_used)]
static RE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\.package\s*\(\s*path\s*:\s*"([^"]+)"\s*\)"#).expect("RE_PATH")
});

/// Converts a `github.com` Git URL to an `owner/repo` identity string.
///
/// Accepts HTTPS/SSH URL forms (`https://github.com/owner/repo`, `git@github.com:owner/repo`)
/// and strips a trailing `.git` suffix (before or after a trailing slash). Returns `None` for
/// any URL whose host is not GitHub's (a self-hosted git server, GitLab, or any other host —
/// #979: this crate's registry backend only resolves GitHub `owner/repo` identities via the
/// GitHub API, so silently mapping a non-GitHub URL onto an `owner/repo` pair would query an
/// unrelated, attacker-nameable GitHub repository with the user's `GITHUB_TOKEN` attached).
pub fn url_to_identity(url: &str) -> Option<String> {
    let parsed = parse_git_url(url)?;
    let host = parsed.host_str()?;
    if !crate::is_github_host(host) {
        return None;
    }

    let trimmed = parsed.path().trim_end_matches('/');
    let path = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if let [owner, repo] = parts.as_slice() {
        Some(format!("{owner}/{repo}"))
    } else {
        None
    }
}

/// Normalizes an SSH-style Git URL (`git@host:owner/repo[.git]`) to an `https://` URL and
/// parses it, so every caller that needs a dependency URL's host handles both URL shapes
/// the same way.
///
/// Shared by [`url_to_identity`] above and `formatter::is_non_github_registry_url` (#983
/// critic S2): both need "what host does this dependency URL point at," and deriving that
/// twice — once here, once in the formatter — let the formatter's copy silently miss the
/// SSH shape (`Url::parse` fails outright on a raw `git@host:path` string with no scheme).
/// Sharing this step means the two call sites can no longer drift on which URL shapes they
/// recognize.
pub(crate) fn parse_git_url(url: &str) -> Option<reqwest::Url> {
    // Normalize SSH-style URLs (git@host:owner/repo[.git]) to an https URL so the rest of
    // this function only ever deals with one shape.
    let normalized = if let Some(rest) = url.strip_prefix("git@") {
        let (host, path) = rest.split_once(':')?;
        format!("https://{host}/{path}")
    } else {
        url.to_string()
    };

    // `reqwest::Url` re-exports `url::Url` — reuse it rather than adding a second URL-parsing
    // dependency (`deps-swift` already depends on `reqwest`, and `formatter::osv_package_name`
    // parses the same way).
    reqwest::Url::parse(&normalized).ok()
}

/// Resolves the display name and [`DependencySource`] for a registry-form (`from:`,
/// `.upToNextMajor`, `.upToNextMinor`, `.exact`, `..<`, `...`) dependency URL.
///
/// A GitHub URL resolves to [`DependencySource::Registry`] under its `owner/repo` identity,
/// enabling GitHub-tags version resolution. Any other host (#979) still keeps the dependency
/// visible — matching the `.branch`/`.revision` forms below — as [`DependencySource::Git`]
/// with the raw URL as its name, so it renders in hover/document-link/inlay-hint output
/// instead of silently vanishing, while never being queried against GitHub
/// (`EcosystemFormatter::can_resolve_source` defaults to `Registry`-only, which this crate
/// does not override).
fn resolve_registry_source(url_str: &str) -> (String, DependencySource) {
    match url_to_identity(url_str) {
        Some(identity) => (identity, DependencySource::Registry),
        None => (
            url_str.to_string(),
            DependencySource::Git {
                url: url_str.to_string(),
                rev: None,
            },
        ),
    }
}

/// Strips comments from Package.swift content, replacing comment characters
/// with spaces to preserve byte offsets for accurate position tracking.
///
/// Handles:
/// - `//` line comments (not inside string literals)
/// - `/* ... */` block comments (not nested)
///
/// Thin wrapper over the shared [`deps_core::quote_scan::blank_comments`] (#1022) — kept
/// as its own named function so its callers and the offset-preservation contract below
/// stay stable regardless of where the scan itself lives.
fn strip_comments(content: &str) -> String {
    deps_core::quote_scan::blank_comments(content, deps_core::quote_scan::ScanSyntax::Swift)
}

/// Computes the next major version string for `upToNextMajor` requirements.
fn next_major(version: &str) -> String {
    let parts: Vec<&str> = version.split('.').collect();
    let major: u64 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    format!("{}", major + 1)
}

/// Computes the next minor version string for `upToNextMinor` requirements.
fn next_minor(major: &str, minor: &str) -> String {
    let minor_num: u64 = minor.parse().unwrap_or(0);
    format!("{major}.{}.0", minor_num + 1)
}

/// Parses a Package.swift file and returns all dependencies with LSP positions.
///
/// Uses regex matching after stripping comments. Byte offsets are preserved
/// throughout so LSP positions are computed correctly.
///
/// # Errors
///
/// Infallible by construction: unrecognized lines are skipped rather than erroring.
/// Returns [`Result`] only to match the shared parser signature every ecosystem implements.
// Every capture-group slice below (`url.start()..url.end()`, etc.) uses regex match offsets,
// always char boundaries; offsets taken on `stripped` are valid in `content` too because
// `strip_comments` overwrites byte-for-byte (length- and boundary-preserving). Group 0
// always exists on a successful match and every numbered group in these patterns is
// mandatory (never `?`-optional), so `cap.get(N).unwrap()` is always `Some`.
#[allow(clippy::string_slice, clippy::unwrap_used)]
pub fn parse_package_swift(content: &str, uri: &Uri) -> Result<SwiftParseResult> {
    let stripped = strip_comments(content);
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    // Captures `content`/`line_table` so call sites only pass byte start/end offsets.
    let make_range = |start: usize, end: usize| -> Range {
        byte_span_to_range(content, &line_table, start, end)
    };

    // Find the byte offset of a capture within the stripped content
    // and map back to original content for position calculation.
    // Since stripping only replaces with spaces (same byte length), offsets match.

    let mut matched_ranges: Vec<std::ops::Range<usize>> = Vec::new();
    // Shared across all 9 pin-form passes below (#796) — the ceiling is per-document, not
    // per-form.
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    // Track which byte ranges have already been matched to avoid double-parsing
    let is_already_matched = |start: usize, end: usize, matched: &[std::ops::Range<usize>]| {
        matched.iter().any(|r| r.start <= start && end <= r.end)
    };

    // 1. .package(url: "...", .upToNextMajor(from: "..."))
    for cap in RE_URL_UP_TO_NEXT_MAJOR.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let ver = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let ver_str = &content[ver.start()..ver.end()];

        let parts: Vec<&str> = ver_str.splitn(3, '.').collect();
        let major = parts.first().copied().unwrap_or("0");
        let version_req = format!(">={ver_str}, <{}.0.0", next_major(major));

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(ver.start(), ver.end())),
            version_literal: Some(ver_str.to_string()),
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 2. .package(url: "...", .upToNextMinor(from: "..."))
    for cap in RE_URL_UP_TO_NEXT_MINOR.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let ver = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let ver_str = &content[ver.start()..ver.end()];

        let parts: Vec<&str> = ver_str.splitn(3, '.').collect();
        let major = parts.first().copied().unwrap_or("0");
        let minor = parts.get(1).copied().unwrap_or("0");
        let version_req = format!(">={ver_str}, <{}", next_minor(major, minor));

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(ver.start(), ver.end())),
            version_literal: Some(ver_str.to_string()),
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 3. .package(url: "...", .exact("..."))
    for cap in RE_URL_EXACT.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let ver = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let ver_str = &content[ver.start()..ver.end()];

        let version_req = format!("={ver_str}");

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(ver.start(), ver.end())),
            version_literal: Some(ver_str.to_string()),
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 4. .package(url: "...", "lower"..<"upper")
    for cap in RE_URL_RANGE_HALF_OPEN.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let lower = cap.get(2).unwrap();
        let upper = cap.get(3).unwrap();

        let url_str = &content[url.start()..url.end()];
        let lower_str = &content[lower.start()..lower.end()];
        let upper_str = &content[upper.start()..upper.end()];

        let version_req = format!(">={lower_str}, <{upper_str}");

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(lower.start(), lower.end())),
            // Deliberately `None`, unlike every other registry form: `version_range` spans
            // only the lower bound of a two-literal range, so reporting it as the literal
            // would let the guard pass and the edit rewrite the lower bound alone,
            // inverting the range (e.g. `"1.0.0"..<"2.0.0"` -> `"3.5.0"..<"2.0.0"`) — SwiftPM
            // traps on `lowerBound > upperBound`, corrupting the whole manifest (#367 C1).
            // `None` keeps this form fail-closed, matching pre-fix behavior.
            version_literal: None,
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 5. .package(url: "...", "lower"..."upper")
    for cap in RE_URL_RANGE_CLOSED.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let lower = cap.get(2).unwrap();
        let upper = cap.get(3).unwrap();

        let url_str = &content[url.start()..url.end()];
        let lower_str = &content[lower.start()..lower.end()];
        let upper_str = &content[upper.start()..upper.end()];

        let version_req = format!(">={lower_str}, <={upper_str}");

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(lower.start(), lower.end())),
            // See the half-open range form above (#367 C1): `version_range` spans only
            // the lower bound, so reporting it as the literal would let the guard rewrite
            // the lower bound alone and invert the range.
            version_literal: None,
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 6. .package(url: "...", from: "...")
    for cap in RE_URL_FROM.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let ver = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let ver_str = &content[ver.start()..ver.end()];

        let version_req = format!(">={ver_str}, <{}.0.0", next_major(ver_str));

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        let (name, source) = resolve_registry_source(url_str);
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req.into()),
            version_range: Some(make_range(ver.start(), ver.end())),
            version_literal: Some(ver_str.to_string()),
            url: url_str.to_string(),
            source,
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 7. .package(url: "...", .branch("..."))
    for cap in RE_URL_BRANCH.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let branch = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let branch_str = &content[branch.start()..branch.end()];

        let identity = url_to_identity(url_str).unwrap_or_else(|| url_str.to_string());

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        dependencies.push(SwiftDependency {
            name: identity.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: None,
            version_range: None,
            version_literal: None,
            url: url_str.to_string(),
            source: DependencySource::Git {
                url: url_str.to_string(),
                rev: Some(branch_str.to_string()),
            },
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 8. .package(url: "...", .revision("..."))
    for cap in RE_URL_REVISION.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let url = cap.get(1).unwrap();
        let rev = cap.get(2).unwrap();

        let url_str = &content[url.start()..url.end()];
        let rev_str = &content[rev.start()..rev.end()];

        let identity = url_to_identity(url_str).unwrap_or_else(|| url_str.to_string());

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        dependencies.push(SwiftDependency {
            name: identity.into(),
            name_range: make_range(url.start(), url.end()),
            version_req: None,
            version_range: None,
            version_literal: None,
            url: url_str.to_string(),
            source: DependencySource::Git {
                url: url_str.to_string(),
                rev: Some(rev_str.to_string()),
            },
        });
        matched_ranges.push(full.start()..full.end());
    }

    // 9. .package(path: "...")
    for cap in RE_PATH.captures_iter(&stripped) {
        let full = cap.get(0).unwrap();
        if is_already_matched(full.start(), full.end(), &matched_ranges) {
            continue;
        }
        let path = cap.get(1).unwrap();
        let path_str = &content[path.start()..path.end()];

        let name = std::path::Path::new(path_str)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path_str)
            .to_string();

        if !budget.allow() {
            matched_ranges.push(full.start()..full.end());
            continue;
        }
        dependencies.push(SwiftDependency {
            name: name.into(),
            name_range: make_range(path.start(), path.end()),
            version_req: None,
            version_range: None,
            version_literal: None,
            url: String::new(),
            source: DependencySource::Path {
                path: path_str.to_string(),
            },
        });
        matched_ranges.push(full.start()..full.end());
    }

    Ok(SwiftParseResult {
        dependencies,
        uri: uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::Dependency;
    use std::assert_matches;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/Package.swift")
    }

    #[test]
    fn test_url_to_identity_https() {
        assert_eq!(
            url_to_identity("https://github.com/apple/swift-nio.git"),
            Some("apple/swift-nio".into())
        );
    }

    /// Regression for #979 critic M1: a trailing slash after `.git` (a valid, if unusual,
    /// clone URL) must not defeat the `.git`-suffix strip and leave it stuck onto `repo`.
    #[test]
    fn test_url_to_identity_git_suffix_with_trailing_slash() {
        assert_eq!(
            url_to_identity("https://github.com/apple/swift-nio.git/"),
            Some("apple/swift-nio".into())
        );
    }

    #[test]
    fn test_url_to_identity_no_git_suffix() {
        assert_eq!(
            url_to_identity("https://github.com/vapor/vapor"),
            Some("vapor/vapor".into())
        );
    }

    #[test]
    fn test_url_to_identity_ssh() {
        assert_eq!(
            url_to_identity("git@github.com:apple/swift-log.git"),
            Some("apple/swift-log".into())
        );
    }

    #[test]
    fn test_parse_from() {
        let content = r#"
let package = Package(
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
    ]
)
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "apple/swift-nio");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(">=2.40.0, <3.0.0")
        );
        assert!(dep.version_range().is_some());
    }

    #[test]
    fn test_parse_up_to_next_major() {
        let content = r#"
.package(url: "https://github.com/apple/swift-log", .upToNextMajor(from: "1.5.0"))
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "apple/swift-log");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(">=1.5.0, <2.0.0")
        );
    }

    #[test]
    fn test_parse_up_to_next_minor() {
        let content = r#"
.package(url: "https://github.com/apple/swift-metrics", .upToNextMinor(from: "2.3.0"))
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(">=2.3.0, <2.4.0")
        );
    }

    #[test]
    fn test_parse_exact() {
        let content = r#".package(url: "https://github.com/apple/swift-crypto", .exact("3.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some("=3.0.0")
        );
    }

    #[test]
    fn test_parse_range_half_open() {
        let content = r#".package(url: "https://github.com/foo/bar", "1.0.0"..<"2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.0.0, <2.0.0")
        );
    }

    #[test]
    fn test_parse_range_closed() {
        let content = r#".package(url: "https://github.com/baz/qux", "1.0.0"..."1.9.9")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.0.0, <=1.9.9")
        );
    }

    #[test]
    fn test_parse_branch() {
        let content = r#".package(url: "https://github.com/dev/tool", .branch("main"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.version_requirement(), None);
        assert_matches!(dep.source(), DependencySource::Git { .. });
    }

    #[test]
    fn test_parse_revision() {
        let content = r#".package(url: "https://github.com/dev/debug", .revision("abc123"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source(),
            DependencySource::Git { .. }
        );
    }

    #[test]
    fn test_parse_path() {
        let content = r#".package(path: "../LocalPackage")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].source(),
            DependencySource::Path { .. }
        );
        assert_eq!(result.dependencies[0].name(), "LocalPackage");
    }

    #[test]
    fn test_strip_line_comments() {
        let content = r#"
// .package(url: "https://github.com/old/dep", from: "1.0.0")
.package(url: "https://github.com/real/dep", from: "3.0.0")
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "real/dep");
    }

    #[test]
    fn test_strip_block_comments() {
        let content = r#"
/* .package(url: "https://github.com/removed/dep", from: "2.0.0") */
.package(url: "https://github.com/real/dep", from: "3.0.0")
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "real/dep");
    }

    #[test]
    fn test_multiline_package() {
        let content = r#"
.package(
    url: "https://github.com/apple/swift-nio.git",
    from: "2.40.0"
)
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "apple/swift-nio");
    }

    #[test]
    fn test_multiple_dependencies() {
        let content = r#"
.package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0"),
.package(url: "https://github.com/vapor/vapor", from: "4.89.0"),
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
    }

    #[test]
    fn test_empty_content() {
        let result = parse_package_swift("", &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_next_major() {
        assert_eq!(next_major("2"), "3");
        assert_eq!(next_major("2.40.0"), "3");
        assert_eq!(next_major("0"), "1");
    }

    #[test]
    fn test_next_minor() {
        assert_eq!(next_minor("2", "3"), "2.4.0");
        assert_eq!(next_minor("1", "4"), "1.5.0");
    }

    // --- url_to_identity edge cases ---

    #[test]
    fn test_url_to_identity_single_segment_returns_none() {
        // URL with only one path segment cannot produce owner/repo
        assert_eq!(url_to_identity("https://github.com/singlerepo"), None);
    }

    #[test]
    fn test_url_to_identity_non_github_host_returns_none() {
        // #979: a non-GitHub host must never be coerced into a GitHub owner/repo
        // identity — this crate's registry only resolves GitHub `owner/repo` pairs via
        // the GitHub API, so doing so would query an unrelated, attacker-nameable
        // GitHub repository with the user's GITHUB_TOKEN attached.
        assert_eq!(url_to_identity("https://gitlab.com/myorg/myrepo"), None);
    }

    #[test]
    fn test_url_to_identity_self_hosted_git_returns_none() {
        assert_eq!(
            url_to_identity("https://git.example.internal/myorg/myrepo.git"),
            None
        );
    }

    #[test]
    fn test_url_to_identity_ssh_non_github_host_returns_none() {
        assert_eq!(url_to_identity("git@gitlab.com:myorg/myrepo.git"), None);
    }

    #[test]
    fn test_url_to_identity_www_github_host() {
        assert_eq!(
            url_to_identity("https://www.github.com/apple/swift-nio.git"),
            Some("apple/swift-nio".into())
        );
    }

    #[test]
    fn test_url_to_identity_uppercase_github_host() {
        assert_eq!(
            url_to_identity("https://GitHub.com/apple/swift-nio.git"),
            Some("apple/swift-nio".into())
        );
    }

    #[test]
    fn test_url_to_identity_lookalike_host_suffix_returns_none() {
        // A host that merely ends with "github.com" is not GitHub.
        assert_eq!(
            url_to_identity("https://github.com.evil.example/owner/repo"),
            None
        );
    }

    #[test]
    fn test_url_to_identity_userinfo_spoof_returns_none() {
        // The real host here is "evil.example" — "github.com" is just userinfo, a
        // classic URL-confusion trick. Must resolve by the real (parsed) host only.
        assert_eq!(
            url_to_identity("https://github.com@evil.example/owner/repo"),
            None
        );
    }

    #[test]
    fn test_url_to_identity_ssh_no_git_suffix() {
        // SSH URL without .git extension
        assert_eq!(
            url_to_identity("git@github.com:apple/swift-log"),
            Some("apple/swift-log".into())
        );
    }

    #[test]
    fn test_url_to_identity_empty_string() {
        assert_eq!(url_to_identity(""), None);
    }

    // --- strip_comments edge cases ---

    #[test]
    fn test_comment_inside_string_not_stripped() {
        // A "//" inside a string literal must NOT be treated as a comment
        let content = r#".package(url: "https://github.com/foo/bar", from: "1.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        // The URL contains "://" which should not confuse the comment stripper
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "foo/bar");
    }

    #[test]
    fn test_escaped_quote_inside_string() {
        // Escaped quote inside string should not end the string
        // This is an edge case — Package.swift doesn't typically use escapes in URLs,
        // but the stripper must handle them without panicking.
        let content = "let s = \"hello \\\"world\\\"\"\n.package(url: \"https://github.com/a/b\", from: \"1.0.0\")";
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "a/b");
    }

    #[test]
    fn test_block_comment_multiline_stripped() {
        let content = "/*\n.package(url: \"https://github.com/removed/pkg\", from: \"1.0.0\")\n*/\n.package(url: \"https://github.com/real/pkg\", from: \"2.0.0\")";
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "real/pkg");
    }

    // --- parser: registry-form dependencies with no GitHub identity fall back to a
    // non-resolvable Git source instead of vanishing (#979 critic S1) ---

    /// Asserts the shared #979 fallback shape: the dependency stays visible under the raw
    /// URL as its name, tagged `DependencySource::Git` (never queried against GitHub, since
    /// `EcosystemFormatter::can_resolve_source` defaults to `Registry`-only), but the
    /// version requirement declared in the manifest is still preserved for display.
    fn assert_git_fallback(dep: &SwiftDependency, url_str: &str) {
        assert_eq!(dep.name(), url_str);
        assert_matches!(dep.source(), DependencySource::Git { .. });
    }

    #[test]
    fn test_parse_from_non_identity_url_falls_back_to_git_source() {
        let content = r#".package(url: "https://example.com/onlyone", from: "1.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.0.0, <2.0.0")
        );
    }

    #[test]
    fn test_parse_exact_non_identity_url_falls_back_to_git_source() {
        let content = r#".package(url: "https://example.com/onlyone", .exact("2.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
    }

    #[test]
    fn test_parse_range_half_open_non_identity_falls_back_to_git_source() {
        let content = r#".package(url: "https://example.com/onlyone", "1.0.0"..<"2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
    }

    #[test]
    fn test_parse_range_closed_non_identity_falls_back_to_git_source() {
        let content = r#".package(url: "https://example.com/onlyone", "1.0.0"..."2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
    }

    #[test]
    fn test_parse_up_to_next_major_non_identity_falls_back_to_git_source() {
        let content =
            r#".package(url: "https://example.com/onlyone", .upToNextMajor(from: "1.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
    }

    #[test]
    fn test_parse_up_to_next_minor_non_identity_falls_back_to_git_source() {
        let content =
            r#".package(url: "https://example.com/onlyone", .upToNextMinor(from: "1.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://example.com/onlyone");
    }

    /// Regression for #979: a registry-form (`from:`) dependency declared against a
    /// non-GitHub host (here GitLab) must never be resolved into a `Dependency` whose
    /// identity is queried against an unrelated GitHub repository — it stays visible as a
    /// non-resolvable `Git`-sourced dependency under its raw URL instead.
    #[test]
    fn test_parse_from_non_github_host_falls_back_to_git_source() {
        let content = r#".package(url: "https://gitlab.com/myorg/myrepo", from: "1.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_git_fallback(&result.dependencies[0], "https://gitlab.com/myorg/myrepo");
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.0.0, <2.0.0")
        );
    }

    // --- branch/revision fallback to raw URL when no identity ---

    #[test]
    fn test_parse_branch_non_identity_url_uses_raw() {
        // Branch deps fall back to raw URL string when url_to_identity returns None
        let content = r#".package(url: "https://example.com/onlyone", .branch("main"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        // name falls back to the raw URL
        assert_eq!(result.dependencies[0].name(), "https://example.com/onlyone");
    }

    #[test]
    fn test_parse_revision_non_identity_url_uses_raw() {
        let content = r#".package(url: "https://example.com/onlyone", .revision("abc123"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "https://example.com/onlyone");
    }

    /// Regression for #979: a `.branch(...)` dependency on a non-GitHub host must fall
    /// back to the raw URL for display, never a fabricated `owner/repo` GitHub identity.
    /// These forms carry `DependencySource::Git`, so they were never registry-resolvable
    /// via GitHub regardless — this only guards the display/lockfile-matching identity.
    #[test]
    fn test_parse_branch_non_github_host_uses_raw_url() {
        let content = r#".package(url: "https://gitlab.com/myorg/myrepo", .branch("main"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name(),
            "https://gitlab.com/myorg/myrepo"
        );
    }

    // --- path: nested directory name extraction ---

    #[test]
    fn test_parse_path_nested() {
        let content = r#".package(path: "../Packages/MyLib")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "MyLib");
    }

    #[test]
    fn test_parse_path_absolute() {
        let content = r#".package(path: "/Users/dev/my-package")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "my-package");
    }

    // --- multiline for all patterns ---

    #[test]
    fn test_multiline_up_to_next_major() {
        let content = r#"
.package(
    url: "https://github.com/apple/swift-log",
    .upToNextMajor(from: "1.5.0")
)
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some(">=1.5.0, <2.0.0")
        );
    }

    #[test]
    fn test_multiline_exact() {
        let content = r#"
.package(
    url: "https://github.com/apple/swift-crypto",
    .exact("3.0.0")
)
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some("=3.0.0")
        );
    }

    // --- version range position tracking ---

    #[test]
    fn test_version_range_present_for_registry_deps() {
        let content = r#".package(url: "https://github.com/foo/bar", from: "1.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert!(result.dependencies[0].version_range().is_some());
    }

    #[test]
    fn test_version_range_absent_for_branch_deps() {
        let content = r#".package(url: "https://github.com/foo/bar", .branch("main"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert!(result.dependencies[0].version_range().is_none());
    }

    #[test]
    fn test_version_range_absent_for_path_deps() {
        let content = r#".package(path: "../MyLib")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert!(result.dependencies[0].version_range().is_none());
    }

    // --- version_literal / literal-span guard (#367) ---

    /// Slices `content` over a single-line LSP `Range` — mirrors
    /// `deps_core::lsp_helpers`'s private `slice_for_range`, reimplemented here since
    /// that helper isn't public. Every fixture below is single-line ASCII, so character
    /// offsets equal byte offsets.
    #[allow(clippy::string_slice)] // single-line ASCII fixture
    fn slice(content: &str, range: Range) -> &str {
        assert_eq!(
            range.start.line, range.end.line,
            "fixture must be single-line"
        );
        let line = content.lines().nth(range.start.line as usize).unwrap();
        &line[range.start.character as usize..range.end.character as usize]
    }

    /// Regression for #367: `deps-swift`'s registry-form dependencies all synthesize a
    /// `version_req` comparator string that never equals the bare literal `version_range`
    /// spans (e.g. `.exact("4.50.0")` -> requirement `"=4.50.0"`, range `"4.50.0"`). The
    /// literal-span guard in `generate_code_actions`/`collect_update_all_edits` must
    /// instead compare against `version_literal()`, which this test proves equals exactly
    /// what `version_range()` slices to, for every **single-literal** registry-form
    /// syntax (`.upToNextMajor`, `.upToNextMinor`, `.exact`, `from:`). The two-literal
    /// range forms (`..<`/`...`) are deliberately excluded — see
    /// `test_version_literal_is_none_for_range_forms` below (#367 C1).
    #[test]
    fn test_version_literal_matches_version_range_slice_for_every_registry_syntax() {
        let cases: &[(&str, &str)] = &[
            (
                r#".package(url: "https://github.com/apple/swift-log", .upToNextMajor(from: "1.5.0"))"#,
                "1.5.0",
            ),
            (
                r#".package(url: "https://github.com/apple/swift-metrics", .upToNextMinor(from: "2.3.0"))"#,
                "2.3.0",
            ),
            (
                r#".package(url: "https://github.com/apple/swift-crypto", .exact("3.0.0"))"#,
                "3.0.0",
            ),
            (
                r#".package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0")"#,
                "2.40.0",
            ),
        ];

        for (content, expected_literal) in cases {
            let result = parse_package_swift(content, &test_uri()).unwrap();
            assert_eq!(result.dependencies.len(), 1, "fixture: {content}");
            let dep = &result.dependencies[0];

            assert_eq!(
                dep.version_literal(),
                Some(*expected_literal),
                "fixture: {content}"
            );

            let version_range = dep
                .version_range()
                .expect("registry dep has a version_range");
            let slice = slice(content, version_range);
            assert_eq!(
                slice,
                dep.version_literal().unwrap(),
                "version_range must slice to exactly version_literal: {content}"
            );
            assert_ne!(
                slice,
                dep.version_requirement().unwrap().as_str(),
                "the synthesized version_req must diverge from the bare literal, or this \
                 fixture no longer exercises the bug #367 fixed: {content}"
            );
        }
    }

    /// Regression for #367 critic finding C1: `version_range` for a `..<`/`...` range
    /// dependency spans only the *lower* bound literal — reporting that as
    /// `version_literal` would let the literal-span guard pass and rewrite the lower
    /// bound alone, inverting the range (e.g. `"1.0.0"..<"2.0.0"` ->
    /// `"3.5.0"..<"2.0.0"`), which traps SwiftPM. `version_literal` must stay `None` for
    /// both range forms so the guard keeps failing closed, exactly as it did before
    /// `version_literal` existed.
    #[test]
    fn test_version_literal_is_none_for_range_forms() {
        for content in [
            r#".package(url: "https://github.com/foo/bar", "1.0.0"..<"2.0.0")"#,
            r#".package(url: "https://github.com/baz/qux", "1.0.0"..."1.9.9")"#,
        ] {
            let result = parse_package_swift(content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(dep.version_literal(), None, "{content}");
            // Still a registry dep with a version_range to (safely) decline to edit.
            assert!(dep.version_range().is_some(), "{content}");
            assert!(dep.version_requirement().is_some(), "{content}");
        }
    }

    #[test]
    fn test_version_literal_absent_for_branch_revision_path_deps() {
        for content in [
            r#".package(url: "https://github.com/dev/tool", .branch("main"))"#,
            r#".package(url: "https://github.com/dev/debug", .revision("abc123"))"#,
            r#".package(path: "../MyLib")"#,
        ] {
            let result = parse_package_swift(content, &test_uri()).unwrap();
            assert_eq!(result.dependencies[0].version_literal(), None, "{content}");
        }
    }
}

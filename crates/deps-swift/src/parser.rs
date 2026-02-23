//! Package.swift parser using regex-based approach.
//!
//! Parses .package() declarations using regular expressions after stripping
//! comments to avoid false positives. Byte offsets are preserved during
//! comment stripping for accurate LSP position tracking.

use crate::error::Result;
use crate::types::{SwiftDependency, SwiftParseResult};
use deps_core::lsp_helpers::LineOffsetTable;
use deps_core::parser::DependencySource;
use regex::Regex;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::{Range, Uri};

// Regex patterns for various .package() call forms.
// All use (?s) DOTALL flag to handle multiline calls.

static RE_URL_FROM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*from\s*:\s*"([^"]+)"\s*\)"#)
        .expect("RE_URL_FROM")
});

static RE_URL_UP_TO_NEXT_MAJOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMajor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_UP_TO_NEXT_MAJOR")
});

static RE_URL_UP_TO_NEXT_MINOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.upToNextMinor\s*\(\s*from\s*:\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_UP_TO_NEXT_MINOR")
});

static RE_URL_EXACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.exact\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_EXACT")
});

static RE_URL_RANGE_HALF_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\.\.<\s*"([^"]+)"\s*\)"#,
    )
    .expect("RE_URL_RANGE_HALF_OPEN")
});

static RE_URL_RANGE_CLOSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\.\.\.\s*"([^"]+)"\s*\)"#,
    )
    .expect("RE_URL_RANGE_CLOSED")
});

static RE_URL_BRANCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.branch\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_BRANCH")
});

static RE_URL_REVISION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)\.package\s*\(\s*url\s*:\s*"([^"]+)"\s*,\s*\.revision\s*\(\s*"([^"]+)"\s*\)\s*\)"#,
    )
    .expect("RE_URL_REVISION")
});

static RE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)\.package\s*\(\s*path\s*:\s*"([^"]+)"\s*\)"#).expect("RE_PATH")
});

/// Converts a GitHub or generic Git URL to `owner/repo` identity string.
///
/// Strips trailing `.git` and extracts the last two path segments.
pub fn url_to_identity(url: &str) -> Option<String> {
    // Handle SSH-style URLs: git@github.com:user/repo.git
    let url = if let Some(rest) = url.strip_prefix("git@") {
        // Replace first ':' with '/' to normalize
        if let Some(colon_pos) = rest.find(':') {
            let host = &rest[..colon_pos];
            let path = &rest[colon_pos + 1..];
            format!("https://{host}/{path}")
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    };

    // Strip trailing .git
    let url = url.strip_suffix(".git").unwrap_or(&url);

    // Extract last two path segments (owner/repo)
    let parts: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        let owner = parts[parts.len() - 2];
        let repo = parts[parts.len() - 1];
        // Filter out protocol parts like "https:" or "github.com"
        if owner.contains(':') || owner.contains('.') {
            return None;
        }
        Some(format!("{owner}/{repo}"))
    } else {
        None
    }
}

/// Strips comments from Package.swift content, replacing comment characters
/// with spaces to preserve byte offsets for accurate position tracking.
///
/// Handles:
/// - `//` line comments (not inside string literals)
/// - `/* ... */` block comments (not nested)
fn strip_comments(content: &str) -> String {
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut result: Vec<u8> = bytes.to_vec();

    let mut i = 0;
    let mut in_string = false;

    while i < len {
        if in_string {
            if bytes[i] == b'\\' && i + 1 < len {
                i += 2;
            } else if bytes[i] == b'"' {
                in_string = false;
                i += 1;
            } else {
                i += 1;
            }
        } else if bytes[i] == b'"' {
            in_string = true;
            i += 1;
        } else if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            // Line comment: replace until newline
            while i < len && bytes[i] != b'\n' {
                result[i] = b' ';
                i += 1;
            }
        } else if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            // Block comment: replace until */
            result[i] = b' ';
            result[i + 1] = b' ';
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] != b'\n' {
                    result[i] = b' ';
                }
                i += 1;
            }
            if i + 1 < len {
                result[i] = b' ';
                result[i + 1] = b' ';
                i += 2;
            }
        } else {
            i += 1;
        }
    }

    // The only non-ASCII bytes in comments are preserved as-is (replaced with spaces),
    // so the resulting bytes are valid UTF-8.
    String::from_utf8(result).unwrap_or_else(|_| content.to_string())
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
pub fn parse_package_swift(content: &str, uri: &Uri) -> Result<SwiftParseResult> {
    let stripped = strip_comments(content);
    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    // Helper to make Range from byte start/end offsets in original content
    let make_range = |start: usize, end: usize| -> Range {
        let start_pos = line_table.byte_offset_to_position(content, start);
        let end_pos = line_table.byte_offset_to_position(content, end);
        Range::new(start_pos, end_pos)
    };

    // Find the byte offset of a capture within the stripped content
    // and map back to original content for position calculation.
    // Since stripping only replaces with spaces (same byte length), offsets match.

    let mut matched_ranges: Vec<std::ops::Range<usize>> = Vec::new();

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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let parts: Vec<&str> = ver_str.splitn(3, '.').collect();
        let major = parts.first().copied().unwrap_or("0");
        let version_req = format!(">={ver_str}, <{}.0.0", next_major(major));

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(ver.start(), ver.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let parts: Vec<&str> = ver_str.splitn(3, '.').collect();
        let major = parts.first().copied().unwrap_or("0");
        let minor = parts.get(1).copied().unwrap_or("0");
        let version_req = format!(">={ver_str}, <{}", next_minor(major, minor));

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(ver.start(), ver.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let version_req = format!("={ver_str}");

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(ver.start(), ver.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let version_req = format!(">={lower_str}, <{upper_str}");

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(lower.start(), lower.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let version_req = format!(">={lower_str}, <={upper_str}");

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(lower.start(), lower.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        let Some(identity) = url_to_identity(url_str) else {
            matched_ranges.push(full.start()..full.end());
            continue;
        };

        let version_req = format!(">={ver_str}, <{}.0.0", next_major(ver_str));

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: Some(version_req),
            version_range: Some(make_range(ver.start(), ver.end())),
            url: url_str.to_string(),
            source: DependencySource::Registry,
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

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: None,
            version_range: None,
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

        dependencies.push(SwiftDependency {
            name: identity,
            name_range: make_range(url.start(), url.end()),
            version_req: None,
            version_range: None,
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

        dependencies.push(SwiftDependency {
            name,
            name_range: make_range(path.start(), path.end()),
            version_req: None,
            version_range: None,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::Dependency;

    fn test_uri() -> Uri {
        Uri::from_file_path("/test/Package.swift").unwrap()
    }

    #[test]
    fn test_url_to_identity_https() {
        assert_eq!(
            url_to_identity("https://github.com/apple/swift-nio.git"),
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
        assert_eq!(dep.version_requirement(), Some(">=2.40.0, <3.0.0"));
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
        assert_eq!(dep.version_requirement(), Some(">=1.5.0, <2.0.0"));
    }

    #[test]
    fn test_parse_up_to_next_minor() {
        let content = r#"
.package(url: "https://github.com/apple/swift-metrics", .upToNextMinor(from: "2.3.0"))
"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.version_requirement(), Some(">=2.3.0, <2.4.0"));
    }

    #[test]
    fn test_parse_exact() {
        let content = r#".package(url: "https://github.com/apple/swift-crypto", .exact("3.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_requirement(), Some("=3.0.0"));
    }

    #[test]
    fn test_parse_range_half_open() {
        let content = r#".package(url: "https://github.com/foo/bar", "1.0.0"..<"2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].version_requirement(),
            Some(">=1.0.0, <2.0.0")
        );
    }

    #[test]
    fn test_parse_range_closed() {
        let content = r#".package(url: "https://github.com/baz/qux", "1.0.0"..."1.9.9")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].version_requirement(),
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
        assert!(matches!(dep.source(), DependencySource::Git { .. }));
    }

    #[test]
    fn test_parse_revision() {
        let content = r#".package(url: "https://github.com/dev/debug", .revision("abc123"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source(),
            DependencySource::Git { .. }
        ));
    }

    #[test]
    fn test_parse_path() {
        let content = r#".package(path: "../LocalPackage")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source(),
            DependencySource::Path { .. }
        ));
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
    fn test_url_to_identity_non_github_host() {
        // Non-github hosts should work as long as path has two segments
        assert_eq!(
            url_to_identity("https://gitlab.com/myorg/myrepo"),
            Some("myorg/myrepo".into())
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

    // --- parser: non-identity URLs should be skipped (not panic) ---

    #[test]
    fn test_parse_from_non_identity_url_skipped() {
        // URL that cannot produce owner/repo identity → dependency is skipped
        let content = r#".package(url: "https://example.com/onlyone", from: "1.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_exact_non_identity_url_skipped() {
        let content = r#".package(url: "https://example.com/onlyone", .exact("2.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_range_half_open_non_identity_skipped() {
        let content = r#".package(url: "https://example.com/onlyone", "1.0.0"..<"2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_range_closed_non_identity_skipped() {
        let content = r#".package(url: "https://example.com/onlyone", "1.0.0"..."2.0.0")"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_up_to_next_major_non_identity_skipped() {
        let content =
            r#".package(url: "https://example.com/onlyone", .upToNextMajor(from: "1.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_up_to_next_minor_non_identity_skipped() {
        let content =
            r#".package(url: "https://example.com/onlyone", .upToNextMinor(from: "1.0.0"))"#;
        let result = parse_package_swift(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
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
            result.dependencies[0].version_requirement(),
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
        assert_eq!(result.dependencies[0].version_requirement(), Some("=3.0.0"));
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
}

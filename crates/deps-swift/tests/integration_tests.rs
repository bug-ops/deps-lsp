//! Integration tests using fixture files.

// #689: workspace-level `clippy::unwrap_used` (moved from a per-crate lib.rs attribute)
// now reaches this integration test's separate crate root. `clippy.toml`'s
// `allow-unwrap-in-tests` already exempts `#[test]` functions, so this covers only the
// non-`#[test]` helper (`fixture_uri`/`load_fixture`) calling `unwrap()` on a known-good path.
#![allow(clippy::unwrap_used)]

use deps_core::Dependency;
use deps_core::lsp_helpers::LineOffsetTable;
use deps_swift::parse_package_swift;
use url::Url;

/// Slices `content` at a dependency's `version_range`, the same LSP `Range` the client would
/// use to place a rewrite — proves the range points at the literal text it claims to, not
/// just that some range exists.
// `position_to_byte_offset` returns char-boundary offsets by construction (same guarantee
// `parse_package_swift` itself relies on for its own slicing).
#[allow(clippy::string_slice, clippy::unwrap_used)]
fn version_range_text<'a>(content: &'a str, dep: &dyn Dependency) -> &'a str {
    let range = dep.version_range().unwrap();
    let table = LineOffsetTable::new(content);
    let start = table.position_to_byte_offset(content, range.start);
    let end = table.position_to_byte_offset(content, range.end);
    &content[start..end]
}

fn fixture_uri(name: &str) -> Url {
    #[cfg(windows)]
    let path = format!("C:/test/{name}");
    #[cfg(not(windows))]
    let path = format!("/test/{name}");
    Url::from_file_path(path).unwrap()
}

fn load_fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"))
}

/// `.product(name:, package:)` entries inside `targets:` must never be mistaken for a
/// `.package()` dependency declaration — only the latter is matched.
#[test]
fn test_fixture_simple() {
    let content = load_fixture("simple.swift");
    let result = parse_package_swift(&content, &fixture_uri("simple.swift")).unwrap();

    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(result.dependencies[0].name().as_str(), "apple/swift-nio");
    assert_eq!(result.dependencies[1].name().as_str(), "vapor/vapor");
}

/// Exercises all 9 `.package()` forms mixed in one manifest: `from`, `.upToNextMajor`,
/// `.upToNextMinor`, `.exact`, half-open range, closed range, `.branch`, `.revision`, `path:`.
#[test]
fn test_fixture_complex() {
    let content = load_fixture("complex.swift");
    let result = parse_package_swift(&content, &fixture_uri("complex.swift")).unwrap();

    assert_eq!(result.dependencies.len(), 9);

    let by_name: std::collections::HashMap<&str, &deps_swift::SwiftDependency> = result
        .dependencies
        .iter()
        .map(|d| (d.name().as_str(), d))
        .collect();

    // `from`/`.upToNextMajor`/`.upToNextMinor`/`.exact`/half-open/closed range all produce a
    // `version_requirement` and a `version_range` that slices exactly the version literal
    // that requirement was derived from (the half-open/closed forms only the lower bound —
    // see parser.rs's `#367 C1` comments on those two forms).
    for (name, expected_req, expected_literal) in [
        ("apple/swift-nio", ">=2.40.0, <3.0.0", "2.40.0"),
        ("apple/swift-log", ">=1.5.0, <2.0.0", "1.5.0"),
        ("apple/swift-metrics", ">=2.3.0, <2.4.0", "2.3.0"),
        ("apple/swift-crypto", "=3.0.0", "3.0.0"),
        ("foo/bar", ">=1.0.0, <2.0.0", "1.0.0"),
        ("baz/qux", ">=1.0.0, <=1.9.9", "1.0.0"),
    ] {
        let dep: &&deps_swift::SwiftDependency = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(expected_req),
            "{name} version_requirement"
        );
        assert_eq!(
            version_range_text(&content, *dep),
            expected_literal,
            "{name} version_range should slice its own version literal"
        );
    }

    // `.branch`/`.revision`/`path:` pin to a non-version coordinate, so neither a
    // `version_requirement` nor a `version_range` exists.
    for name in ["dev/tool", "dev/debug", "LocalPackage"] {
        let dep = by_name
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert!(
            dep.version_requirement().is_none(),
            "{name} should have no version_requirement"
        );
        assert!(
            dep.version_range().is_none(),
            "{name} should have no version_range"
        );
    }
}

/// A `.package()` call inside a `//` line comment or a `/* ... */` block comment must not be
/// parsed as a real dependency declaration.
#[test]
fn test_fixture_commented() {
    let content = load_fixture("commented.swift");
    let result = parse_package_swift(&content, &fixture_uri("commented.swift")).unwrap();

    assert_eq!(result.dependencies.len(), 1);
    assert_eq!(result.dependencies[0].name().as_str(), "real/dep");
    assert_eq!(
        result.dependencies[0]
            .version_requirement()
            .map(deps_core::VersionReq::as_str),
        Some(">=3.0.0, <4.0.0")
    );
}

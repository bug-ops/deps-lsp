//! composer.json parser with position tracking.
//!
//! Parses composer.json files and extracts dependency information with precise
//! source positions for LSP operations. Platform packages (php, ext-*, lib-*)
//! are filtered out as they are not Packagist packages.

use crate::types::{ComposerDependency, ComposerSection};
use deps_core::Result;
use deps_core::lsp_helpers::LineOffsetTable;
use serde_json::Value;
use std::any::Any;
use tower_lsp_server::ls_types::{Range, Uri};

/// Result of parsing a composer.json file.
///
/// Contains all non-platform dependencies found in the file with their positions.
#[derive(Debug)]
pub struct ComposerParseResult {
    pub dependencies: Vec<ComposerDependency>,
    pub uri: Uri,
    /// Raw value of the manifest's own top-level `minimum-stability` field (e.g. `"beta"`),
    /// if present — Composer's project-wide default stability floor, one of `dev`, `alpha`,
    /// `beta`, `RC`, `stable` (case-insensitive). `None` when the field is absent, which
    /// Composer itself treats as `stable` (#424).
    ///
    /// Consumers rank this word (`registry.rs`'s crate-private stability ranking) rather than
    /// comparing it as a string — stored raw here rather than pre-ranked so a caller with no
    /// interest in stability filtering (e.g. a future manifest-summary feature) is not forced
    /// to depend on that ranking.
    pub minimum_stability: Option<String>,
}

impl deps_core::ParseResult for ComposerParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Returns true if the package is a platform requirement (not a Packagist package).
///
/// Platform packages include:
/// - `php`, and its variants `php-64bit`, `php-ipv6`, `php-zts`, `php-debug` — PHP version
///   requirements
/// - `hhvm` — HHVM version requirement
/// - `composer` — the Composer CLI version itself
/// - `ext-*` — PHP extensions
/// - `lib-*` — PHP libraries
/// - `composer-plugin-api`, `composer-runtime-api` — Composer's own virtual packages
///
/// Mirrors Composer's `PlatformRepository` package set (#402 critique S1: an incomplete list
/// here previously let a real platform requirement like `composer-plugin-api` — present in
/// essentially every Composer plugin's `composer.json` — reach the Packagist-shaped
/// `vendor/package` name validator and get flagged "Invalid package name"; M6: `composer`
/// itself was still missing from the set).
///
/// Every platform package name is a single bare token with no `/` — a real Packagist package
/// always has a `vendor/package` shape — so any name containing `/` returns `false`
/// immediately, before the prefix checks below. Without this guard, `starts_with("php-")` (and
/// `ext-`/`lib-`) would also match a real package merely because its *vendor* happens to start
/// with that prefix (e.g. `php-di/php-di`, `php-amqplib/php-amqplib`, `ext-mongo/whatever`),
/// silently dropping it from the dependency list entirely — no diagnostic, hover, inlay hint,
/// or code lens — rather than validating it as a normal dependency (#402 critique C2).
pub fn is_platform_package(name: &str) -> bool {
    if name.contains('/') {
        return false;
    }
    name == "php"
        || name.starts_with("php-")
        || name == "hhvm"
        || name == "composer"
        || name.starts_with("ext-")
        || name.starts_with("lib-")
        || name == "composer-plugin-api"
        || name == "composer-runtime-api"
}

/// Parses a composer.json file and extracts all non-platform dependencies with positions.
///
/// Handles `require` and `require-dev` sections.
/// Platform packages (php, ext-*, lib-*) are silently filtered out.
///
/// # Errors
///
/// Returns an error if JSON parsing fails.
///
/// # Examples
///
/// ```no_run
/// use deps_composer::parser::parse_composer_json;
/// use tower_lsp_server::ls_types::Uri;
///
/// let json = r#"{
///   "require": {
///     "symfony/console": "^6.0"
///   }
/// }"#;
/// let uri = Uri::from_file_path("/project/composer.json").unwrap();
///
/// let result = parse_composer_json(json, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "symfony/console");
/// ```
pub fn parse_composer_json(content: &str, uri: &Uri) -> Result<ComposerParseResult> {
    let root: Value = deps_core::parse_json_checked(content.as_bytes())?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    // Parse each section, scoping position search to that section's own byte range (see
    // `deps_core::parser::find_json_section_byte_range`) so a name repeated across sections
    // (e.g. also present in `require-dev`) does not have both occurrences resolve to the
    // same, monotonically-advancing search cursor position — `serde_json::Map` iteration
    // order (alphabetical without `preserve_order`) cannot be relied on to match source-text
    // order (#610).
    const SECTIONS: [(&str, ComposerSection); 2] = [
        ("require", ComposerSection::Require),
        ("require-dev", ComposerSection::RequireDev),
    ];

    for (key, section) in SECTIONS {
        if let Some(deps) = root.get(key).and_then(|v| v.as_object()) {
            // Fall back to the whole-file range (pre-fix behavior) if the section's own
            // bounds cannot be located — never drop a section's dependencies over this.
            let section_range = deps_core::parser::find_json_section_byte_range(content, key)
                .unwrap_or_else(|| {
                    tracing::debug!(
                        section = key,
                        "section byte range not found, falling back to whole-file position search"
                    );
                    (0, content.len())
                });
            dependencies.extend(parse_section(
                content,
                deps,
                section,
                section_range,
                &line_table,
            ));
        }
    }

    let minimum_stability = root
        .get("minimum-stability")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Ok(ComposerParseResult {
        dependencies,
        uri: uri.clone(),
        minimum_stability,
    })
}

/// Parses a single dependency section and extracts positions, filtering platform packages.
///
/// `section_range` bounds the search performed by `find_positions` to this section's own
/// `{...}` byte range, so a name that also appears in another section (e.g. `require` and
/// `require-dev`) does not resolve to that other section's occurrence.
fn parse_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: ComposerSection,
    section_range: (usize, usize),
    line_table: &LineOffsetTable,
) -> Vec<ComposerDependency> {
    let mut result = Vec::new();

    for (name, value) in deps {
        if is_platform_package(name) {
            continue;
        }

        let version_req = value.as_str().map(String::from);
        let (name_range, version_range) = find_positions(
            content,
            name,
            version_req.as_ref(),
            section_range,
            line_table,
        );

        result.push(ComposerDependency {
            name: name.clone().into(),
            name_range,
            version_req: version_req.map(Into::into),
            version_range,
            section,
        });
    }

    result
}

/// Finds the byte positions of a dependency name and version in the source text.
///
/// Searches for the dependency as a JSON key-value pair within `section_range` (the
/// enclosing section's own `{...}` byte range) to avoid false matches both from unrelated
/// text elsewhere in the file and from the same name declared in a *different* dependency
/// section.
fn find_positions(
    content: &str,
    name: &str,
    version_req: Option<&String>,
    section_range: (usize, usize),
    line_table: &LineOffsetTable,
) -> (Range, Option<Range>) {
    let mut name_range = Range::default();
    let mut version_range = None;

    let name_pattern = format!("\"{name}\"");
    let (range_start, range_end) = section_range;
    let section_content = &content[range_start..range_end];

    let mut search_start = 0;
    while let Some(rel_idx) = section_content[search_start..].find(&name_pattern) {
        let name_start_idx = range_start + search_start + rel_idx;
        let after_name = &content[name_start_idx + name_pattern.len()..range_end];
        let trimmed = after_name.trim_start();

        if !trimmed.starts_with(':') {
            search_start = (name_start_idx + name_pattern.len()) - range_start;
            continue;
        }

        let name_start = line_table.byte_offset_to_position(content, name_start_idx + 1);
        let name_end = line_table.byte_offset_to_position(content, name_start_idx + 1 + name.len());
        name_range = Range::new(name_start, name_end);

        if let Some(version) = version_req {
            let version_search = format!("\"{version}\"");
            let colon_offset =
                name_start_idx + name_pattern.len() + (after_name.len() - trimmed.len());
            let after_colon = &content[colon_offset..];

            // Limit search to the next 100 chars to stay within this key-value pair, and
            // never past the enclosing section's own end — otherwise a version search
            // starting near a section boundary could bleed into the next section's text.
            // Round down to a char boundary since `version.len()` is a byte count that
            // can land mid-character when the source contains multi-byte UTF-8.
            let search_limit = after_colon.floor_char_boundary(
                after_colon
                    .len()
                    .min(100 + version.len())
                    .min(range_end.saturating_sub(colon_offset)),
            );
            let search_area = &after_colon[..search_limit];

            if let Some(ver_rel_idx) = search_area.find(&version_search) {
                let version_start_idx = colon_offset + ver_rel_idx + 1;
                let version_start = line_table.byte_offset_to_position(content, version_start_idx);
                let version_end =
                    line_table.byte_offset_to_position(content, version_start_idx + version.len());
                version_range = Some(Range::new(version_start, version_end));
            }
        }

        break;
    }

    (name_range, version_range)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/composer.json")
    }

    #[test]
    fn test_parse_require() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0",
    "monolog/monolog": "^3.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        // JSON object iteration order is not guaranteed, so find by name
        let symfony = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .expect("symfony/console not found");
        assert_eq!(symfony.version_req, Some("^6.0".into()));
        assert_matches!(symfony.section, ComposerSection::Require);

        let monolog = result
            .dependencies
            .iter()
            .find(|d| d.name == "monolog/monolog")
            .expect("monolog/monolog not found");
        assert_eq!(monolog.version_req, Some("^3.0".into()));
    }

    #[test]
    fn test_parse_require_dev() {
        let json = r#"{
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(result.dependencies[0].section, ComposerSection::RequireDev);
    }

    #[test]
    fn test_filter_platform_packages() {
        let json = r#"{
  "require": {
    "php": ">=8.1",
    "ext-mbstring": "*",
    "lib-xml": "*",
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "symfony/console");
    }

    #[test]
    fn test_is_platform_package() {
        assert!(is_platform_package("php"));
        assert!(is_platform_package("ext-mbstring"));
        assert!(is_platform_package("ext-json"));
        assert!(is_platform_package("lib-xml"));
        assert!(!is_platform_package("symfony/console"));
        assert!(!is_platform_package("monolog/monolog"));
        assert!(!is_platform_package("extended/package")); // not ext- prefix
    }

    /// #402 critique S1: the platform-package set previously covered only `php`/`ext-*`/
    /// `lib-*`, so a real requirement like `composer-plugin-api` fell through to the
    /// Packagist-shaped `vendor/package` name validator and was flagged "Invalid package
    /// name" instead of being silently filtered like the other platform packages.
    #[test]
    fn test_is_platform_package_covers_full_composer_platform_set() {
        for name in [
            "php-64bit",
            "php-ipv6",
            "php-zts",
            "php-debug",
            "hhvm",
            "composer",
            "composer-plugin-api",
            "composer-runtime-api",
        ] {
            assert!(
                is_platform_package(name),
                "expected {name:?} to be recognized as a platform package"
            );
        }
    }

    /// #402 critique C2: a real Packagist package under a vendor whose name happens to start
    /// with a platform prefix (`php-di/php-di`, `php-amqplib/php-amqplib`,
    /// `ext-mongo/whatever`, `lib-xml/whatever`) must not be misclassified as a platform
    /// package — that would silently drop it from the dependency list entirely, with no
    /// diagnostic, hover, inlay hint, or code lens, rather than validating it normally.
    #[test]
    fn test_is_platform_package_does_not_swallow_real_packages_with_platform_like_vendors() {
        for name in [
            "php-di/php-di",
            "php-amqplib/php-amqplib",
            "php-debugbar/php-debugbar",
            "php-ffmpeg/php-ffmpeg",
            "ext-mongo/whatever",
            "lib-xml/whatever",
            "hhvm/whatever",
            "composer/whatever",
        ] {
            assert!(
                !is_platform_package(name),
                "expected {name:?} to NOT be recognized as a platform package"
            );
        }
    }

    #[test]
    fn test_parse_both_sections() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let require_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, ComposerSection::Require))
            .count();
        let dev_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, ComposerSection::RequireDev))
            .count();

        assert_eq!(require_count, 1);
        assert_eq!(dev_count, 1);
    }

    /// #424: `minimum-stability` is parsed from the manifest root when present.
    #[test]
    fn test_parse_minimum_stability_present() {
        let json = r#"{
  "minimum-stability": "beta",
  "require": {
    "symfony/console": "^6.0"
  }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.minimum_stability.as_deref(), Some("beta"));
    }

    /// #424: a manifest with no `minimum-stability` field parses to `None`, not a fabricated
    /// `"stable"` — the stable default is applied by the registry ranking, not the parser.
    #[test]
    fn test_parse_minimum_stability_absent() {
        let json = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.minimum_stability, None);
    }

    #[test]
    fn test_parse_empty() {
        let json = r#"{"name": "vendor/project"}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_composer_json("{invalid json}", &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `composer.json` must be rejected by the
        // depth guard rather than handed to `serde_json::from_str`. Reported
        // as `DepsError::Json`, the same variant a genuinely malformed
        // `composer.json` produces (unified via `deps_core::parse_json_checked`).
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_composer_json(&json, &test_uri());
        assert_matches!(result, Err(deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_parse_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"require": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let result = parse_composer_json(&json, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_position_tracking() {
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name_range.start.line, 2);
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 2);
    }

    #[test]
    fn test_parse_empty_require() {
        let json = r#"{"require": {}}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    /// Regression test for https://github.com/bug-ops/deps-lsp/issues/84
    ///
    /// `serde_json::Map` iterates alphabetically without the `preserve_order` feature:
    /// guzzlehttp/guzzle → laravel/framework → symfony/console. The parser's original
    /// implementation searched for each dependency's position using a single
    /// monotonically-advancing cursor in that iteration order, so laravel/framework (file
    /// line 2) was searched for only after the cursor had already advanced past line 3,
    /// leaving its name_range and version_range at (0,0)→(0,0). Fixed by scoping each
    /// section's search to its own byte range (see `find_positions`), independent of
    /// iteration order — the same fix later generalized for the cross-section case in #610.
    #[test]
    fn test_position_tracking_out_of_alphabetical_order() {
        let json = r#"{
    "require": {
        "laravel/framework": "^10.0",
        "guzzlehttp/guzzle": "^7.5",
        "symfony/console": "~6.0"
    }
}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        for dep in &result.dependencies {
            // Every dependency must have a valid (non-zero) name position.
            assert!(
                dep.name_range.start.line > 0,
                "name_range for '{}' is at line 0 — position tracking regressed",
                dep.name
            );
            assert!(
                dep.version_range.is_some(),
                "version_range for '{}' is missing",
                dep.name
            );
        }

        let laravel = result
            .dependencies
            .iter()
            .find(|d| d.name == "laravel/framework")
            .unwrap();
        assert_eq!(laravel.name_range.start.line, 2);

        let guzzle = result
            .dependencies
            .iter()
            .find(|d| d.name == "guzzlehttp/guzzle")
            .unwrap();
        assert_eq!(guzzle.name_range.start.line, 3);

        let symfony = result
            .dependencies
            .iter()
            .find(|d| d.name == "symfony/console")
            .unwrap();
        assert_eq!(symfony.name_range.start.line, 4);
    }

    #[test]
    fn test_find_positions_no_panic_on_multibyte_utf8_boundary() {
        // The search window is `100 + version.len()` bytes after the colon. Placing a
        // 2-byte UTF-8 character ('é') to straddle that exact byte offset used to panic
        // when the raw offset was used to slice the string directly (issue #245, same
        // pattern as #230 in deps-npm).
        let name = "vendor/pkg";
        let version = "1.0.0".to_string();
        let padding = "a".repeat(103);
        let content = format!("\"{name}\":{padding}é more text \"{version}\" end");

        let line_table = LineOffsetTable::new(&content);
        let (name_range, version_range) = find_positions(
            &content,
            name,
            Some(&version),
            (0, content.len()),
            &line_table,
        );

        assert_eq!(name_range.start.line, 0);
        // The multibyte character falls right at the truncated search boundary, so the
        // version string (placed after it) is outside the search window and not found.
        assert!(version_range.is_none());
    }

    #[test]
    fn test_find_positions_finds_version_when_multibyte_char_is_further_out() {
        // Same truncation boundary as above, but this time the version sits well inside
        // the truncated window while the 2-byte UTF-8 character ('é') straddles the exact
        // raw byte offset (107) that used to be sliced naively. Confirms the fix does not
        // just avoid panicking but still returns the correct, real match.
        let name = "vendor/pkg";
        let version = "1.0.0-x".to_string(); // 7 bytes -> raw window limit = 100 + 7 = 107
        let quoted_version = format!("\"{version}\"");
        let padding = "a".repeat(95);
        let content = format!("\"{name}\": {quoted_version}{padding}é end");

        let line_table = LineOffsetTable::new(&content);
        let (name_range, version_range) = find_positions(
            &content,
            name,
            Some(&version),
            (0, content.len()),
            &line_table,
        );

        assert_eq!(name_range.start.line, 0);
        let version_range = version_range.expect("version should still be found after truncation");
        assert_eq!(version_range.start.line, 0);

        // Version content starts right after the opening quote; everything before it is
        // ASCII, so byte offset and UTF-16 character offset coincide.
        let expected_start = content.find(&quoted_version).unwrap() + 1;
        assert_eq!(version_range.start.character, expected_start as u32);
    }

    #[test]
    fn test_parse_composer_json_no_panic_with_multibyte_field_after_dependency() {
        // Public-API-level regression test for issue #245: an ordinary manifest where a
        // later top-level field (`description`) contains multi-byte UTF-8 can still land
        // the search-window offset for an *earlier* dependency's version mid-character.
        // This reaches the panic through `parse_composer_json`, the only entry point the
        // LSP layer actually calls, rather than the private `find_positions` helper.
        let json = r#"{
  "require": {
    "symfony/console": "^6.0"
  },
  "authors": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "description": "Gestão de projetos"
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let symfony = &result.dependencies[0];
        assert_eq!(symfony.name, "symfony/console");
        assert_eq!(symfony.version_req, Some("^6.0".into()));
        assert!(symfony.version_range.is_some());
    }

    // --- #610: duplicate dependency names across sections ---

    #[test]
    fn test_duplicate_name_across_require_and_require_dev() {
        // #610, same bug class as npm's #605: "vendor/pkg" appears in both `require` and
        // `require-dev`, with keys not in source-text order relative to each section's
        // start. The old implementation threaded a single, monotonically-advancing
        // `search_start` cursor across `serde_json::Map` iteration, so it could skip past —
        // or land on — the wrong occurrence whenever `Map` iteration order didn't match
        // source-text order. The fix no longer depends on `Map` iteration order at all: each
        // section's own byte range is located up front, and every entry's position is
        // searched fresh within it. Each occurrence must resolve to its own section's
        // position.
        let json = r#"{
  "require": {
    "zzz/other": "^1.0",
    "vendor/pkg": "^2.0"
  },
  "require-dev": {
    "vendor/pkg": "^9.9",
    "aaa/other": "^1.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);

        let require_pkg = result
            .dependencies
            .iter()
            .find(|d| d.name == "vendor/pkg" && matches!(d.section, ComposerSection::Require))
            .expect("vendor/pkg in require");
        let dev_pkg = result
            .dependencies
            .iter()
            .find(|d| d.name == "vendor/pkg" && matches!(d.section, ComposerSection::RequireDev))
            .expect("vendor/pkg in require-dev");

        assert_eq!(require_pkg.version_req, Some("^2.0".into()));
        assert_eq!(dev_pkg.version_req, Some("^9.9".into()));

        assert_eq!(require_pkg.name_range.start.line, 3);
        assert_eq!(dev_pkg.name_range.start.line, 6);

        let require_version = require_pkg
            .version_range
            .expect("require vendor/pkg version_range");
        let dev_version = dev_pkg
            .version_range
            .expect("require-dev vendor/pkg version_range");
        assert_eq!(require_version.start.line, 3);
        assert_eq!(dev_version.start.line, 6);
    }
}

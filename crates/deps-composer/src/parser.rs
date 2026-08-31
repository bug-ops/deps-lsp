//! composer.json parser with position tracking.
//!
//! Parses composer.json files and extracts dependency information with precise
//! source positions for LSP operations. Platform packages (php, ext-*, lib-*)
//! are filtered out as they are not Packagist packages.

use crate::types::{ComposerDependency, ComposerSection};
use deps_core::Result;
use serde_json::Value;
use std::any::Any;
use tower_lsp_server::ls_types::{Position, Range, Uri};

/// Line offset table for O(log n) position lookups.
struct LineOffsetTable {
    offsets: Vec<usize>,
}

impl LineOffsetTable {
    fn new(content: &str) -> Self {
        let mut offsets = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                offsets.push(i + 1);
            }
        }
        Self { offsets }
    }

    /// Converts byte offset to LSP Position using UTF-16 code unit counting.
    fn position_from_offset(&self, content: &str, offset: usize) -> Position {
        let line = match self.offsets.binary_search(&offset) {
            Ok(line) => line,
            Err(line) => line.saturating_sub(1),
        };
        let line_start = self.offsets[line];
        let character = content[line_start..offset]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();
        Position::new(line as u32, character)
    }
}

/// Result of parsing a composer.json file.
///
/// Contains all non-platform dependencies found in the file with their positions.
#[derive(Debug)]
pub struct ComposerParseResult {
    pub dependencies: Vec<ComposerDependency>,
    pub uri: Uri,
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
/// - `php` — PHP version requirement
/// - `ext-*` — PHP extensions
/// - `lib-*` — PHP libraries
pub fn is_platform_package(name: &str) -> bool {
    name == "php" || name.starts_with("ext-") || name.starts_with("lib-")
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
    let root: Value = serde_json::from_str(content)?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    if let Some(deps) = root.get("require").and_then(|v| v.as_object()) {
        dependencies.extend(parse_section(
            content,
            deps,
            ComposerSection::Require,
            &line_table,
        ));
    }

    if let Some(deps) = root.get("require-dev").and_then(|v| v.as_object()) {
        dependencies.extend(parse_section(
            content,
            deps,
            ComposerSection::RequireDev,
            &line_table,
        ));
    }

    Ok(ComposerParseResult {
        dependencies,
        uri: uri.clone(),
    })
}

/// Parses a single dependency section and extracts positions, filtering platform packages.
///
/// Uses `search_start` to scope position lookups to the current section,
/// preventing false matches when the same package name appears in multiple sections.
fn parse_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: ComposerSection,
    line_table: &LineOffsetTable,
) -> Vec<ComposerDependency> {
    let mut result = Vec::new();
    let mut search_start = 0;

    for (name, value) in deps {
        if is_platform_package(name) {
            continue;
        }

        let version_req = value.as_str().map(String::from);
        let (name_range, version_range, new_offset) = find_positions(
            content,
            name,
            version_req.as_ref(),
            line_table,
            search_start,
        );

        search_start = new_offset;

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
/// Returns `(name_range, version_range, new_search_offset)` where `new_search_offset`
/// is advanced past the current match to avoid false matches in subsequent lookups.
fn find_positions(
    content: &str,
    name: &str,
    version_req: Option<&String>,
    line_table: &LineOffsetTable,
    search_from: usize,
) -> (Range, Option<Range>, usize) {
    let mut name_range = Range::default();
    let mut version_range = None;

    let name_pattern = format!("\"{name}\"");
    let mut search_start = search_from;

    while let Some(rel_idx) = content[search_start..].find(&name_pattern) {
        let name_start_idx = search_start + rel_idx;
        let after_name = &content[name_start_idx + name_pattern.len()..];
        let trimmed = after_name.trim_start();

        if !trimmed.starts_with(':') {
            search_start = name_start_idx + name_pattern.len();
            continue;
        }

        let name_start = line_table.position_from_offset(content, name_start_idx + 1);
        let name_end = line_table.position_from_offset(content, name_start_idx + 1 + name.len());
        name_range = Range::new(name_start, name_end);

        if let Some(version) = version_req {
            let version_search = format!("\"{version}\"");
            let colon_offset =
                name_start_idx + name_pattern.len() + (after_name.len() - trimmed.len());
            let after_colon = &content[colon_offset..];

            // Limit search to the next 100 chars to stay within this key-value pair.
            // Round down to a char boundary since `version.len()` is a byte count that
            // can land mid-character when the source contains multi-byte UTF-8.
            let search_limit =
                after_colon.floor_char_boundary(after_colon.len().min(100 + version.len()));
            let search_area = &after_colon[..search_limit];

            if let Some(ver_rel_idx) = search_area.find(&version_search) {
                let version_start_idx = colon_offset + ver_rel_idx + 1;
                let version_start = line_table.position_from_offset(content, version_start_idx);
                let version_end =
                    line_table.position_from_offset(content, version_start_idx + version.len());
                version_range = Some(Range::new(version_start, version_end));
            }
        }

        return (
            name_range,
            version_range,
            name_start_idx + name_pattern.len(),
        );
    }

    (name_range, version_range, search_start)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches!(symfony.section, ComposerSection::Require));

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
        assert!(matches!(
            result.dependencies[0].section,
            ComposerSection::RequireDev
        ));
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

    #[test]
    fn test_parse_empty() {
        let json = r#"{"name": "vendor/project"}"#;
        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_composer_json("{invalid json}", &test_uri());
        assert!(matches!(result, Err(deps_core::DepsError::Json(_))));
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
    /// BTreeMap iterates alphabetically: guzzlehttp/guzzle → laravel/framework →
    /// symfony/console. Without preserve_order, laravel/framework (file line 2) was
    /// searched after search_start had advanced past line 3, so its name_range and
    /// version_range were left at (0,0)→(0,0).
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
        let (name_range, version_range, _) =
            find_positions(&content, name, Some(&version), &line_table, 0);

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
        let (name_range, version_range, _) =
            find_positions(&content, name, Some(&version), &line_table, 0);

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
}

//! composer.json parser with position tracking.
//!
//! Parses composer.json files and extracts dependency information with precise
//! source positions for LSP operations. Platform packages (php, ext-*, lib-*)
//! are filtered out as they are not Packagist packages.

use crate::types::{ComposerDependency, ComposerSection};
use deps_core::Result;
use deps_core::json_ast::{JsonAst, JsonSection};
use deps_core::lsp_helpers::LineOffsetTable;
use serde_json::Value;
use std::any::Any;
use tower_lsp_server::ls_types::Uri;

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
    let ast = JsonAst::parse(content);
    if ast.is_none() {
        tracing::warn!(
            "jsonc-parser failed to parse composer.json content serde_json already accepted; \
             dependency positions will default to (0,0)"
        );
    }
    let mut dependencies = Vec::new();

    // Parse each section, reading each entry's position directly from the AST (#613) — the
    // AST's own `Object::properties` only ever lists a given object's *direct* children, so a
    // name repeated across sections (e.g. also present in `require-dev`) or nested inside an
    // unrelated value never gets confused with the real top-level occurrence, independent of
    // `serde_json::Map` iteration order (#610).
    const SECTIONS: [(&str, ComposerSection); 2] = [
        ("require", ComposerSection::Require),
        ("require-dev", ComposerSection::RequireDev),
    ];

    for (key, section) in SECTIONS {
        if let Some(deps) = root.get(key).and_then(|v| v.as_object()) {
            let positions = ast.as_ref().and_then(|ast| ast.section(key));
            dependencies.extend(parse_section(
                content,
                deps,
                section,
                positions.as_ref(),
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
/// `positions` is this section's own direct properties, pre-indexed by name (see
/// [`JsonAst::section`]) — `None` when the AST parse degraded (see [`parse_composer_json`]),
/// in which case every dependency falls back to a default, zero position rather than being
/// dropped.
fn parse_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: ComposerSection,
    positions: Option<&JsonSection<'_>>,
    line_table: &LineOffsetTable,
) -> Vec<ComposerDependency> {
    let mut result = Vec::new();

    for (name, value) in deps {
        if is_platform_package(name) {
            continue;
        }

        let version_req = value.as_str().map(String::from);
        let (name_range, version_range) = positions
            .and_then(|s| s.position(name, content, line_table))
            .unwrap_or_default();

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

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;
    use tower_lsp_server::ls_types::Range;

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
    /// leaving its name_range and version_range at (0,0)→(0,0). Positions now come from an
    /// AST index keyed by name (#613), independent of `serde_json::Map` iteration order
    /// entirely — the same fix later generalized for the cross-section case in #610.
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
    fn test_parse_composer_json_no_panic_with_multibyte_field_after_dependency() {
        // Public-API-level regression test for issue #245: an ordinary manifest where a
        // later top-level field (`description`) contains multi-byte UTF-8 must not upset
        // position tracking for an *earlier* dependency. AST-derived positions (#613) make
        // this structurally impossible (no byte-offset search window to straddle), but the
        // regression test stays as end-to-end coverage through the only entry point the LSP
        // layer actually calls.
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
        // start. The original implementation threaded a single, monotonically-advancing
        // `search_start` cursor across `serde_json::Map` iteration, so it could skip past —
        // or land on — the wrong occurrence whenever `Map` iteration order didn't match
        // source-text order. Positions now come from a per-section AST index (#613), so each
        // occurrence resolves to its own section's node directly, independent of both
        // `Map` iteration order and source-text order entirely.
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

    // --- #613: AST-based position recovery edge cases ---

    /// A dependency's value can itself be a nested object containing a key with the same
    /// name as a real top-level dependency in this section (e.g. a malformed/unusual
    /// manifest). A text-based scanner finds the nested occurrence first; the AST only
    /// ever indexes a section's own *direct* properties, so the real top-level occurrence's
    /// position is never stolen by one nested inside a sibling's value.
    #[test]
    fn test_nested_object_value_with_colliding_key_resolves_to_top_level_position() {
        let json = r#"{
  "require": {
    "a/b": {
      "c/d": "0.0.1"
    },
    "c/d": "^2.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let c_d = result
            .dependencies
            .iter()
            .find(|d| d.name == "c/d")
            .expect("c/d");
        assert_eq!(c_d.version_req, Some("^2.0".into()));
        // The real top-level "c/d" is on line 5, not line 3 (nested inside "a/b"'s value).
        assert_eq!(c_d.name_range.start.line, 5);
        let version_range = c_d.version_range.expect("c/d version_range");
        assert_eq!(version_range.start.line, 5);
    }

    /// JSON permits (if unusual) a duplicate top-level key; `serde_json::Map` keeps only the
    /// *last* occurrence's value (last-key-wins during deserialization, `preserve_order` or
    /// not). The AST lookup must resolve the identically-named "require" key the same way —
    /// the last one — not the first, or the surviving dependency's position silently defaults
    /// to `Range::default()` whenever the two sections don't share every name.
    #[test]
    fn test_duplicate_top_level_section_key_resolves_to_last_occurrence() {
        let json = r#"{
  "require": {
    "only-in-first": "^1.0"
  },
  "require": {
    "vendor/pkg": "^2.0"
  }
}"#;

        let result = parse_composer_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let pkg = &result.dependencies[0];
        assert_eq!(pkg.name, "vendor/pkg");
        assert_eq!(pkg.version_req, Some("^2.0".into()));
        assert_ne!(pkg.name_range, Range::default());
        assert_eq!(pkg.name_range.start.line, 5);
        assert!(pkg.version_range.is_some());
    }

    /// M6(c): when the AST parse degrades (e.g. a future `jsonc-parser` disagreement with
    /// `serde_json` on content this crate's own `parse_composer_json` never actually
    /// produces — see [`JsonAst::parse`]'s doc), `positions: None` must still yield a
    /// dependency entry with a default, zero position rather than dropping it or panicking.
    #[test]
    fn test_parse_section_with_no_ast_positions_falls_back_to_default_range() {
        let mut deps = serde_json::Map::new();
        deps.insert("vendor/pkg".to_string(), Value::String("^1.0".into()));
        let content = r#"{"require": {"vendor/pkg": "^1.0"}}"#;
        let line_table = LineOffsetTable::new(content);

        let result = parse_section(content, &deps, ComposerSection::Require, None, &line_table);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "vendor/pkg");
        assert_eq!(result[0].name_range, Range::default());
        assert!(result[0].version_range.is_none());
    }
}

//! package.json parser with position tracking.
//!
//! Parses package.json files and extracts dependency information with precise
//! source positions for LSP operations.

use crate::config::{NpmConfig, NpmParseContext, NpmRegistryIndex};
use crate::types::{NpmDependency, NpmDependencySection};
use deps_core::Result;
use deps_core::lsp_helpers::LineOffsetTable;
use serde_json::Value;
use std::any::Any;
use tower_lsp_server::ls_types::{Range, Uri};

/// Result of parsing a package.json file.
///
/// Contains all dependencies found in the file with their positions.
#[derive(Debug)]
pub struct NpmParseResult {
    pub dependencies: Vec<NpmDependency>,
    pub uri: Uri,
    /// Every `.npmrc`-resolved alternate registry this parse's dependencies reference,
    /// deduplicated (spec FR-002–004) — fed to `NpmRegistry::register_alternate` by
    /// `NpmEcosystem::parse_manifest`, the one place a per-document `.npmrc` resolution and
    /// the long-lived shared router meet. Empty for a workspace declaring no `.npmrc`
    /// (NFR-005: zero regression).
    pub resolved_registries: Vec<NpmRegistryIndex>,
}

impl deps_core::ParseResult for NpmParseResult {
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

/// Parses a package.json file and extracts all dependencies with positions.
///
/// Handles all dependency sections:
/// - `dependencies`
/// - `devDependencies`
/// - `peerDependencies`
/// - `optionalDependencies`
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - File is not a valid package.json structure
///
/// # Examples
///
/// ```no_run
/// use deps_npm::parser::parse_package_json;
/// use tower_lsp_server::ls_types::Uri;
///
/// let json = r#"{
///   "dependencies": {
///     "express": "^4.18.2"
///   }
/// }"#;
/// let uri = Uri::from_file_path("/project/package.json").unwrap();
///
/// let result = parse_package_json(json, &uri).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "express");
/// ```
pub fn parse_package_json(content: &str, uri: &Uri) -> Result<NpmParseResult> {
    parse_package_json_with_context(content, uri, &NpmParseContext::default())
}

/// [`parse_package_json`], but threading `ctx` through to `.npmrc` registry resolution.
///
/// Spec FR-002–FR-008 — the real entry point; [`parse_package_json`] delegates here with a
/// fresh, default context, mirroring
/// `deps_cargo::parser::parse_cargo_toml_with_context`'s pattern.
///
/// # Errors
///
/// Same as [`parse_package_json`].
pub fn parse_package_json_with_context(
    content: &str,
    uri: &Uri,
    ctx: &NpmParseContext,
) -> Result<NpmParseResult> {
    let root: Value = deps_core::parse_json_checked(content.as_bytes())?;

    // Build line offset table once for O(log n) position lookups
    let line_table = LineOffsetTable::new(content);

    let mut dependencies = Vec::new();

    // Parse each dependency section
    if let Some(deps) = root.get("dependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::Dependencies,
            &line_table,
        ));
    }

    if let Some(deps) = root.get("devDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::DevDependencies,
            &line_table,
        ));
    }

    if let Some(deps) = root.get("peerDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::PeerDependencies,
            &line_table,
        ));
    }

    if let Some(deps) = root.get("optionalDependencies").and_then(|v| v.as_object()) {
        dependencies.extend(parse_dependency_section(
            content,
            deps,
            NpmDependencySection::OptionalDependencies,
            &line_table,
        ));
    }

    // FR-002: a non-`file:` URI (or one `Uri::to_file_path` cannot resolve) has no directory to
    // walk `.npmrc`/pnpm-workspace discovery from — falls back to the empty `NpmConfig`, which
    // resolves every dependency to `DependencySource::Registry` (NFR-005: byte-identical to
    // pre-feature behavior), rather than failing the whole parse. Also the manifest directory
    // spec 046's catalog resolution walks up from (S3: `None` here is what makes a non-`file:`
    // URI land on `CatalogOutcome::NoWorkspaceFile` rather than skipping resolution).
    //
    // Implementation-critique S2: `Uri::to_file_path` does **not** check the URI's scheme (its
    // own doc says so) — it just decodes whatever path component is present. Left unguarded,
    // `untitled:package.json` (VS Code's untitled-buffer form, path "package.json") would
    // resolve `manifest_dir` to a *relative* path, and `find_workspace_file`/`.npmrc` discovery
    // would then probe the LSP server process's own CWD instead of the workspace the document
    // notionally belongs to; a `vscode-vfs://`/`vscode-remote://` URI whose path happens to
    // mirror a real local path could likewise resolve against an unrelated local
    // `pnpm-workspace.yaml`/`.npmrc`. Both `.npmrc` registry resolution and the catalog gate
    // share this one `manifest_dir`, so gating it once here closes both: require the `file`
    // scheme (case-insensitive per RFC 3986) and an absolute resulting directory.
    let manifest_dir = uri
        .scheme()
        .as_str()
        .eq_ignore_ascii_case("file")
        .then(|| uri.to_file_path())
        .flatten()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .filter(|dir| dir.is_absolute());

    let npm_config: NpmConfig = manifest_dir
        .as_deref()
        .map(|dir| crate::config::resolve(dir, &ctx.config_cache, &ctx.policy))
        .unwrap_or_default();

    for dep in &mut dependencies {
        dep.source = npm_config.resolve_source_for(&dep.name);
    }

    // Spec 046 FR-001/NFR-002: cheap fast-path — a non-pnpm manifest pays one string check per
    // dependency and zero filesystem calls. `apply` runs unconditionally once this fires (the
    // module's totality invariant), never short-circuited by `load` returning `None`.
    if dependencies.iter().any(|dep| {
        dep.version_req
            .as_ref()
            .is_some_and(|req| req.as_str().starts_with("catalog:"))
    }) {
        let workspace_config = crate::catalog::load(manifest_dir.as_deref(), &ctx.workspace_cache);
        crate::catalog::apply(&mut dependencies, workspace_config.as_deref());
    }

    Ok(NpmParseResult {
        dependencies,
        uri: uri.clone(),
        resolved_registries: npm_config.resolved_registries(),
    })
}

/// Parses a single dependency section and extracts positions.
fn parse_dependency_section(
    content: &str,
    deps: &serde_json::Map<String, Value>,
    section: NpmDependencySection,
    line_table: &LineOffsetTable,
) -> Vec<NpmDependency> {
    let mut result = Vec::new();

    for (name, value) in deps {
        let version_req = value.as_str().map(String::from);

        // Calculate positions for name and version
        let (name_range, version_range) =
            find_dependency_positions(content, name, version_req.as_ref(), line_table);

        result.push(NpmDependency {
            name: name.clone().into(),
            name_range,
            version_req: version_req.map(Into::into),
            version_range,
            section,
            // Overwritten by `parse_package_json_with_context` once `.npmrc` resolution has
            // run; `Registry` here is the correct value for a manifest with no `.npmrc` at
            // all (NFR-005) and for `parse_dependency_section`'s own unit tests, which do
            // not go through that resolution step.
            source: deps_core::parser::DependencySource::Registry,
            // Overwritten by `parse_package_json_with_context`'s catalog post-pass when the
            // `catalog:` gate fires; `None` here is correct for both a non-pnpm manifest and
            // for this function's own unit tests.
            catalog: None,
        });
    }

    result
}

/// Finds the position of a dependency name and version in the source text.
///
/// Searches for the dependency as a JSON key-value pair to avoid false matches
/// when the name appears elsewhere in the file (e.g., in scripts).
fn find_dependency_positions(
    content: &str,
    name: &str,
    version_req: Option<&String>,
    line_table: &LineOffsetTable,
) -> (Range, Option<Range>) {
    let mut name_range = Range::default();
    let mut version_range = None;

    let name_pattern = format!("\"{name}\"");

    // Find all occurrences of the name pattern and check which one is a dependency key
    let mut search_start = 0;
    while let Some(rel_idx) = content[search_start..].find(&name_pattern) {
        let name_start_idx = search_start + rel_idx;
        let after_name = &content[name_start_idx + name_pattern.len()..];

        // Check if this is a JSON key (followed by optional whitespace and colon)
        let trimmed = after_name.trim_start();
        if !trimmed.starts_with(':') {
            // Not a key, continue searching
            search_start = name_start_idx + name_pattern.len();
            continue;
        }

        // Found a valid key, calculate position
        let name_start = line_table.byte_offset_to_position(content, name_start_idx + 1);
        let name_end = line_table.byte_offset_to_position(content, name_start_idx + 1 + name.len());
        name_range = Range::new(name_start, name_end);

        // Find version position (after the colon)
        if let Some(version) = version_req {
            let version_search = format!("\"{version}\"");
            // Search for version only in the portion after the colon
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
                let version_start = line_table.byte_offset_to_position(content, version_start_idx);
                let version_end =
                    line_table.byte_offset_to_position(content, version_start_idx + version.len());
                version_range = Some(Range::new(version_start, version_end));
            }
        }

        // Found valid dependency, stop searching
        break;
    }

    (name_range, version_range)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/test/package.json")
    }

    #[test]
    fn test_parse_simple_dependencies() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let express = &result.dependencies[0];
        assert_eq!(express.name, "express");
        assert_eq!(express.version_req, Some("^4.18.2".into()));
        assert!(matches!(
            express.section,
            NpmDependencySection::Dependencies
        ));

        let lodash = &result.dependencies[1];
        assert_eq!(lodash.name, "lodash");
        assert_eq!(lodash.version_req, Some("^4.17.21".into()));
    }

    #[test]
    fn test_parse_dev_dependencies() {
        let json = r#"{
  "devDependencies": {
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        assert!(
            result
                .dependencies
                .iter()
                .all(|d| matches!(d.section, NpmDependencySection::DevDependencies))
        );
    }

    #[test]
    fn test_parse_peer_dependencies() {
        let json = r#"{
  "peerDependencies": {
    "react": "^18.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].section,
            NpmDependencySection::PeerDependencies
        ));
    }

    #[test]
    fn test_parse_optional_dependencies() {
        let json = r#"{
  "optionalDependencies": {
    "fsevents": "^2.3.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].section,
            NpmDependencySection::OptionalDependencies
        ));
    }

    #[test]
    fn test_parse_multiple_sections() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let deps_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, NpmDependencySection::Dependencies))
            .count();
        let dev_deps_count = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.section, NpmDependencySection::DevDependencies))
            .count();

        assert_eq!(deps_count, 1);
        assert_eq!(dev_deps_count, 1);
    }

    #[test]
    fn test_parse_empty_dependencies() {
        let json = r#"{
  "dependencies": {}
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_no_dependencies() {
        let json = r#"{
  "name": "my-package",
  "version": "1.0.0"
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = "{ invalid json }";
        let result = parse_package_json(json, &test_uri());
        assert!(matches!(result, Err(deps_core::DepsError::Json(_))));
    }

    #[test]
    fn test_parse_deeply_nested_json_rejected_before_parse() {
        // #430: a deeply nested `package.json` must be rejected by the depth
        // guard rather than handed to `serde_json::from_str`. Reported as
        // `DepsError::Json`, the same variant a genuinely malformed
        // `package.json` produces (unified via `deps_core::parse_json_checked`).
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        let result = parse_package_json(&json, &test_uri());
        assert!(matches!(result, Err(deps_core::DepsError::Json(_))));
    }

    #[test]
    fn test_parse_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"dependencies": {{}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        let result = parse_package_json(&json, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_position_calculation() {
        let json = r#"{
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        let express = &result.dependencies[0];

        // Name should be on line 2 (0-indexed: line 2)
        assert_eq!(express.name_range.start.line, 2);

        // Version should also be on line 2
        if let Some(version_range) = express.version_range {
            assert_eq!(version_range.start.line, 2);
        }
    }

    #[test]
    fn test_line_offset_table() {
        let content = "line0\nline1\nline2";
        let table = LineOffsetTable::new(content);

        let pos0 = table.byte_offset_to_position(content, 0);
        assert_eq!(pos0.line, 0);
        assert_eq!(pos0.character, 0);

        let pos6 = table.byte_offset_to_position(content, 6);
        assert_eq!(pos6.line, 1);
        assert_eq!(pos6.character, 0);

        let pos12 = table.byte_offset_to_position(content, 12);
        assert_eq!(pos12.line, 2);
        assert_eq!(pos12.character, 0);
    }

    #[test]
    fn test_line_offset_table_utf16() {
        // Test UTF-16 character counting (LSP requirement)
        // "hello 世界" where 世界 are multi-byte Unicode characters
        let content = "hello 世界\nworld";
        let table = LineOffsetTable::new(content);

        // Byte offset for "world" is 16 (6 bytes "hello " + 6 bytes "世界" + 1 byte "\n" + 3 bytes "wor")
        // But we need UTF-16 character count for LSP
        let world_offset = content.find("world").unwrap();
        let pos = table.byte_offset_to_position(content, world_offset);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);

        // Test character position within a line with multi-byte chars
        // "hello " = 6 UTF-16 code units
        let world_char_offset = content.find('世').unwrap();
        let pos = table.byte_offset_to_position(content, world_char_offset);
        assert_eq!(pos.line, 0);
        assert_eq!(pos.character, 6); // "hello " = 6 UTF-16 code units
    }

    #[test]
    fn test_line_offset_table_emoji() {
        // Test with emoji (4-byte UTF-8, 2 UTF-16 code units)
        let content = "test 🚀 rocket\nline2";
        let table = LineOffsetTable::new(content);

        // Find position of "rocket"
        let rocket_offset = content.find("rocket").unwrap();
        let pos = table.byte_offset_to_position(content, rocket_offset);
        assert_eq!(pos.line, 0);
        // "test " = 5, "🚀" = 2 UTF-16 code units, " " = 1 => total 8
        assert_eq!(pos.character, 8);
    }

    #[test]
    fn test_dependency_with_git_url() {
        let json = r#"{
  "dependencies": {
    "my-lib": "git+https://github.com/user/repo.git"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "my-lib");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("git+https://github.com/user/repo.git".into())
        );
    }

    #[test]
    fn test_dependency_with_file_path() {
        let json = r#"{
  "dependencies": {
    "local-pkg": "file:../local-package"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "local-pkg");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("file:../local-package".into())
        );
    }

    #[test]
    fn test_scoped_package() {
        let json = r#"{
  "devDependencies": {
    "@vitest/coverage-v8": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "@vitest/coverage-v8");
        assert_eq!(result.dependencies[0].version_req, Some("^3.1.4".into()));
        assert!(result.dependencies[0].version_range.is_some());
    }

    #[test]
    fn test_package_name_in_scripts_not_confused() {
        // Regression test: "vitest" appears in scripts as a value,
        // but should only be found as a dependency key
        let json = r#"{
  "scripts": {
    "test": "vitest",
    "coverage": "vitest run --coverage"
  },
  "devDependencies": {
    "vitest": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let vitest = &result.dependencies[0];
        assert_eq!(vitest.name, "vitest");
        assert_eq!(vitest.version_req, Some("^3.1.4".into()));
        // Verify version_range is found (this was the bug)
        assert!(
            vitest.version_range.is_some(),
            "vitest should have a version_range"
        );
        // Verify position is in devDependencies, not scripts
        // devDependencies starts at line 6
        assert!(
            vitest.name_range.start.line >= 5,
            "vitest should be found in devDependencies, not scripts"
        );
    }

    #[test]
    fn test_multiple_packages_same_version() {
        // Both packages have the same version - each should have distinct positions
        let json = r#"{
  "devDependencies": {
    "@vitest/coverage-v8": "^3.1.4",
    "vitest": "^3.1.4"
  }
}"#;

        let result = parse_package_json(json, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        // Find both dependencies
        let coverage = result
            .dependencies
            .iter()
            .find(|d| d.name == "@vitest/coverage-v8")
            .expect("@vitest/coverage-v8 should be parsed");
        let vitest = result
            .dependencies
            .iter()
            .find(|d| d.name == "vitest")
            .expect("vitest should be parsed");

        // Both should have version ranges
        assert!(
            coverage.version_range.is_some(),
            "@vitest/coverage-v8 should have version_range"
        );
        assert!(
            vitest.version_range.is_some(),
            "vitest should have version_range"
        );

        // Positions should be different
        let coverage_pos = coverage.version_range.unwrap();
        let vitest_pos = vitest.version_range.unwrap();
        assert_ne!(
            coverage_pos.start.line, vitest_pos.start.line,
            "version positions should be on different lines"
        );
    }

    #[test]
    fn test_find_dependency_positions_no_panic_on_multibyte_utf8_boundary() {
        // The search window is `100 + version.len()` bytes after the colon. Placing a
        // 2-byte UTF-8 character ('é') to straddle that exact byte offset used to panic
        // when the raw offset was used to slice the string directly (issue #230).
        let name = "pkg";
        let version = "1.0.0".to_string();
        let padding = "a".repeat(103);
        let content = format!("\"{name}\":{padding}é more text \"{version}\" end");

        let line_table = LineOffsetTable::new(&content);
        let (name_range, version_range) =
            find_dependency_positions(&content, name, Some(&version), &line_table);

        assert_eq!(name_range.start.line, 0);
        // The multibyte character falls right at the truncated search boundary, so the
        // version string (placed after it) is outside the search window and not found.
        assert!(version_range.is_none());
    }

    #[test]
    fn test_find_dependency_positions_finds_version_when_multibyte_char_is_further_out() {
        // Same truncation boundary as above, but this time the version sits well inside
        // the truncated window while the 2-byte UTF-8 character ('é') straddles the exact
        // raw byte offset (107) that used to be sliced naively. Confirms the fix does not
        // just avoid panicking but still returns the correct, real match.
        let name = "pkg";
        let version = "1.0.0-x".to_string(); // 7 bytes -> raw window limit = 100 + 7 = 107
        let quoted_version = format!("\"{version}\"");
        let padding = "a".repeat(95);
        let content = format!("\"{name}\": {quoted_version}{padding}é end");

        let line_table = LineOffsetTable::new(&content);
        let (name_range, version_range) =
            find_dependency_positions(&content, name, Some(&version), &line_table);

        assert_eq!(name_range.start.line, 0);
        let version_range = version_range.expect("version should still be found after truncation");
        assert_eq!(version_range.start.line, 0);

        // Version content starts right after the opening quote; everything before it is
        // ASCII, so byte offset and UTF-16 character offset coincide.
        let expected_start = content.find(&quoted_version).unwrap() + 1;
        assert_eq!(version_range.start.character, expected_start as u32);
    }

    // --- `.npmrc` registry resolution (spec FR-002–FR-008, FR-010) ---

    fn all_policy() -> crate::config::NpmParseContext {
        crate::config::NpmParseContext {
            policy: std::sync::Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
                deps_core::net_policy::WorkspaceRegistryAccess::All,
            )),
            config_cache: std::sync::Arc::new(crate::config::NpmConfigCache::new()),
            workspace_cache: std::sync::Arc::new(crate::catalog::PnpmWorkspaceCache::new()),
        }
    }

    /// FR-003 end-to-end (M7): a top-level `registry=` override rewrites every unscoped
    /// dependency, and leaves a scoped dependency with its own `@scope:registry` entry alone.
    #[test]
    fn test_parse_with_context_top_level_override_and_scope_override_coexist() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://npm.mycorp.example\n@myorg:registry=https://npm.pkg.github.com\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2", "@myorg/internal-lib": "^2.0.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let express = result
            .dependencies
            .iter()
            .find(|d| d.name == "express")
            .unwrap();
        assert_eq!(
            express.source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: "https://npm.mycorp.example".to_string(),
                mirrors_crates_io: false,
            }
        );

        let scoped = result
            .dependencies
            .iter()
            .find(|d| d.name == "@myorg/internal-lib")
            .unwrap();
        assert_eq!(
            scoped.source,
            deps_core::parser::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            }
        );

        assert_eq!(result.resolved_registries.len(), 2);
    }

    /// FR-006/US-004/SC-004: the npm form of issue #248 — a misconfigured `@scope:registry=`
    /// fails closed to `CustomRegistry`, never falling back to `Registry` (the public
    /// registry).
    #[test]
    fn test_parse_with_context_invalid_scope_registry_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "@myorg:registry=not-a-valid-url\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"@myorg/internal-lib": "^2.0.0"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        );
        assert!(!result.dependencies[0].source.is_version_resolvable());
        assert!(result.resolved_registries.is_empty());
    }

    /// NFR-005: no `.npmrc` at any tier is byte-identical to pre-feature behavior — every
    /// dependency resolves to the plain public registry.
    #[test]
    fn test_parse_with_context_no_npmrc_resolves_to_public_registry() {
        let root = tempfile::tempdir().unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(
            result.dependencies[0].source,
            deps_core::parser::DependencySource::Registry
        );
        assert!(result.resolved_registries.is_empty());
    }

    /// FR-008: a workspace-declared index blocked by the default `public_only` policy fails
    /// closed to `CustomRegistry`, same shape as an invalid URL.
    #[test]
    fn test_parse_with_context_policy_blocked_registry_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join(".npmrc"),
            "registry=https://169.254.169.254\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let ctx = NpmParseContext::default(); // default policy is `public_only`
        let result = parse_package_json_with_context(json, &uri, &ctx).unwrap();

        assert!(matches!(
            &result.dependencies[0].source,
            deps_core::parser::DependencySource::CustomRegistry { .. }
        ));
    }

    // --- pnpm catalogs (spec 046) ---

    /// S3 regression: a manifest URI with no filesystem path at all (e.g. a bare virtual-host
    /// URI with nothing after the authority) has no directory to search for
    /// `pnpm-workspace.yaml` from — `Uri::to_file_path` returns `None` for it (verified by the
    /// `assert!` below, so this test fails loudly rather than silently degrading into an
    /// ordinary no-workspace-file case if a future `Uri` version starts resolving it). The
    /// catalog post-pass must still land this on `CatalogOutcome::NoWorkspaceFile` — never
    /// leave the raw `catalog:` specifier in `version_req`, which would re-arm the destructive
    /// "Update all outdated dependencies" rewrite (spec §6's totality invariant).
    #[test]
    fn test_parse_with_context_uri_with_no_file_path_catalog_dep_has_no_requirement() {
        let uri: Uri = "vscode-vfs://host"
            .parse()
            .expect("a non-file scheme must still parse as a valid Uri");
        assert!(
            uri.to_file_path().is_none(),
            "test premise: this Uri must not resolve to any filesystem path"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert!(matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        ));
    }

    /// A companion regression for a virtual-filesystem URI that *does* carry a path
    /// component (`Uri::to_file_path` resolves it to `Some`, since — per its own doc — it
    /// never checks the scheme). Implementation-critique S2: without the `scheme() == "file"`
    /// guard added to `manifest_dir`'s computation, this would walk up to 64 real ancestors of
    /// `/nonexistent-mount/repo` on *this* machine's filesystem — a `vscode-vfs://`/
    /// `vscode-remote://` path that happens to mirror a real local path could then silently
    /// resolve against an unrelated local `pnpm-workspace.yaml`/`.npmrc`. With the guard, the
    /// non-`file` scheme collapses `manifest_dir` to `None` directly, with no filesystem probe
    /// at all — deterministic, not merely "happens not to exist on this machine".
    #[test]
    fn test_parse_with_context_virtual_fs_uri_scheme_guard_skips_filesystem_probe_entirely() {
        let uri: Uri = "vscode-vfs://host/nonexistent-mount/repo/package.json"
            .parse()
            .expect("a non-file scheme must still parse as a valid Uri");

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert!(matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        ));
    }

    /// S2 regression: `Uri::to_file_path` does not check scheme, so an `untitled:` URI (VS
    /// Code's unsaved-buffer form, e.g. `untitled:package.json`) resolves to the *relative*
    /// path `"package.json"`. Unguarded, `.parent()` of that is the empty relative path `""`,
    /// and `find_workspace_file`/`.npmrc` discovery would then probe the **LSP server
    /// process's own current working directory** instead of failing closed. The `is_absolute()`
    /// filter must reject this before any ancestor walk starts.
    #[test]
    fn test_parse_with_context_untitled_scheme_relative_path_does_not_probe_process_cwd() {
        let uri: Uri = "untitled:package.json"
            .parse()
            .expect("untitled: must still parse as a valid Uri");
        assert_eq!(
            uri.to_file_path().as_deref(),
            Some(std::path::Path::new("package.json")),
            "test premise: to_file_path resolves this to a relative path, not None"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert!(matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        ));
        // The same guard protects `.npmrc` registry resolution, sharing `manifest_dir`.
        assert_eq!(react.source, deps_core::parser::DependencySource::Registry);
    }

    /// S2 regression, absolute-path form: a `file:` URI whose path is written relative (not
    /// RFC 3986-conformant for `file:`, but not rejected by a generic URI parser either) must
    /// not resolve `manifest_dir` to a relative directory either — the `is_absolute()` filter
    /// applies regardless of scheme.
    #[test]
    fn test_parse_with_context_file_scheme_relative_path_is_rejected() {
        let uri: Uri = "file:relative/path/package.json"
            .parse()
            .expect("a relative-looking file: URI must still parse as a valid Uri");
        assert!(
            uri.to_file_path().is_some_and(|p| p.is_relative()),
            "test premise: to_file_path resolves this to a relative path"
        );

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        let react = &result.dependencies[0];
        assert_eq!(react.version_req, None);
        assert!(matches!(
            react.catalog.as_ref().map(|origin| &origin.outcome),
            Some(crate::catalog::CatalogOutcome::NoWorkspaceFile)
        ));
    }

    #[test]
    fn test_parse_with_context_default_catalog_resolves_end_to_end() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let json = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(result.dependencies[0].version_req, Some("^18.3.0".into()));
    }

    /// Pinning regression for the `Resolved` catalog path's protection documented in
    /// `catalog.rs`'s module doc: with `version_requirement()` now `Some("^18.3.0")` (not
    /// `None` — the totality invariant doesn't cover this path) and a newer registry version
    /// cached, `collect_update_all_edits` must still produce **no edit** for this dependency,
    /// because `literal_span_matches` rejects the manifest's still-`"catalog:"` `version_range`
    /// slice against the resolved requirement. This holds only because `NpmDependency` does
    /// not override `version_literal()` — if that ever changes, this test must fail.
    #[test]
    fn test_resolved_catalog_dependency_blocks_update_all_rewrite() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let content = r#"{"dependencies": {"react": "catalog:"}}"#;
        let result = parse_package_json_with_context(content, &uri, &all_policy()).unwrap();
        assert_eq!(result.dependencies[0].version_req, Some("^18.3.0".into()));

        let mut cached = std::collections::HashMap::new();
        cached.insert(
            deps_core::PackageName::new("react"),
            deps_core::lsp_helpers::PackageVersions::latest_only("19.0.0"),
        );
        let resolved = std::collections::HashMap::new();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = deps_core::lsp_helpers::collect_update_all_edits(
            &result,
            content,
            versions,
            &crate::formatter::NpmFormatter,
        );

        assert!(
            edits.is_empty(),
            "a catalog-resolved dependency must never be rewritten by \"Update all outdated \
             dependencies\": {edits:?}"
        );
    }

    #[test]
    fn test_parse_with_context_no_catalog_dependency_skips_workspace_lookup() {
        // FR-008/NFR-002: no `catalog:`-prefixed value anywhere in the manifest, so the
        // gate never fires — a bogus/nonexistent workspace path must not affect the result.
        let uri = Uri::from_file_path("/nonexistent/path/package.json").unwrap();
        let json = r#"{"dependencies": {"express": "^4.18.2"}}"#;
        let result = parse_package_json_with_context(json, &uri, &all_policy()).unwrap();

        assert_eq!(result.dependencies[0].version_req, Some("^4.18.2".into()));
        assert!(result.dependencies[0].catalog.is_none());
    }
}

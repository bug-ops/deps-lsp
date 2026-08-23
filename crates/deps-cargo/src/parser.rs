//! Cargo.toml parser with position tracking.
//!
//! Parses Cargo.toml files using toml-span to preserve formatting and extract
//! precise LSP positions for every dependency field. Critical for features like
//! hover, completion, and inlay hints.
//!
//! # Key Features
//!
//! - Position-preserving parsing via toml-span spans
//! - Handles all dependency formats: inline, table, workspace inheritance
//! - Extracts dependencies from all sections: dependencies, dev-dependencies, build-dependencies
//! - Converts byte offsets to LSP Position (line, UTF-16 character)
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::parse_cargo_toml;
//! use tower_lsp_server::ls_types::Uri;
//!
//! let toml = r#"
//! [dependencies]
//! serde = "1.0"
//! "#;
//!
//! let url = Uri::from_file_path("/test/Cargo.toml").unwrap();
//! let result = parse_cargo_toml(toml, &url).unwrap();
//! assert_eq!(result.dependencies.len(), 1);
//! assert_eq!(result.dependencies[0].name, "serde");
//! ```

use crate::error::{CargoError, Result};
use crate::types::{DependencySection, DependencySource, ParsedDependency};
use std::any::Any;
use std::path::PathBuf;
use toml_span::value::{Table, Value};
use tower_lsp_server::ls_types::{Range, Uri};

pub use deps_core::lsp_helpers::LineOffsetTable;

/// Result of parsing a Cargo.toml file.
///
/// Contains all extracted dependencies with their positions, plus optional
/// workspace root information for resolving inherited dependencies.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// All dependencies found in the file
    pub dependencies: Vec<ParsedDependency>,
    /// Workspace root path if this is a workspace member
    pub workspace_root: Option<PathBuf>,
    /// Document URI
    pub uri: Uri,
}

/// Parses a Cargo.toml file and extracts all dependencies with positions.
///
/// # Errors
///
/// Returns an error if:
/// - TOML syntax is invalid
/// - File path cannot be converted from URL
///
/// # Examples
///
/// ```no_run
/// use deps_cargo::parse_cargo_toml;
/// use tower_lsp_server::ls_types::Uri;
///
/// let toml = r#"
/// [dependencies]
/// serde = "1.0"
/// tokio = { version = "1.0", features = ["full"] }
/// "#;
///
/// let url = Uri::from_file_path("/test/Cargo.toml").unwrap();
/// let result = parse_cargo_toml(toml, &url).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
/// ```
pub fn parse_cargo_toml(content: &str, doc_uri: &Uri) -> Result<ParseResult> {
    if let Err(depth) =
        deps_core::check_toml_nesting_depth(content, deps_core::MAX_TOML_NESTING_DEPTH)
    {
        return Err(CargoError::TomlParseError {
            message: format!(
                "array/table nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_TOML_NESTING_DEPTH
            ),
        });
    }

    let doc = toml_span::parse(content).map_err(|e| CargoError::TomlParseError {
        message: e.to_string(),
    })?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    let root_table = doc.as_table().ok_or_else(|| CargoError::TomlParseError {
        message: "root is not a table".into(),
    })?;

    if let Some(deps_val) = get_val(root_table, "dependencies")
        && let Some(deps) = deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            deps,
            content,
            &line_table,
            DependencySection::Dependencies,
        ));
    }

    if let Some(dev_deps_val) = get_val(root_table, "dev-dependencies")
        && let Some(dev_deps) = dev_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            dev_deps,
            content,
            &line_table,
            DependencySection::DevDependencies,
        ));
    }

    if let Some(build_deps_val) = get_val(root_table, "build-dependencies")
        && let Some(build_deps) = build_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            build_deps,
            content,
            &line_table,
            DependencySection::BuildDependencies,
        ));
    }

    // Parse workspace dependencies (for workspace root Cargo.toml)
    if let Some(workspace_val) = get_val(root_table, "workspace")
        && let Some(workspace_table) = workspace_val.as_table()
        && let Some(workspace_deps_val) = get_val(workspace_table, "dependencies")
        && let Some(workspace_deps) = workspace_deps_val.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            workspace_deps,
            content,
            &line_table,
            DependencySection::WorkspaceDependencies,
        ));
    }

    let workspace_root = find_workspace_root(doc_uri)?;

    Ok(ParseResult {
        dependencies,
        workspace_root,
        uri: doc_uri.clone(),
    })
}

fn get_val<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Value<'a>> {
    table.get(key)
}

/// Parses a single dependency section (dependencies, dev-dependencies, or build-dependencies).
fn parse_dependencies_section(
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    section: DependencySection,
) -> Vec<ParsedDependency> {
    let mut deps = Vec::new();

    for (key, value) in table {
        let name = key.name.to_string();
        let name_range = span_to_range(content, line_table, key.span);

        let mut dep = ParsedDependency {
            name: name.into(),
            name_range,
            version_req: None,
            version_range: None,
            features: Vec::new(),
            features_range: None,
            source: DependencySource::Registry,
            section,
        };

        if let Some(s) = value.as_str() {
            // Simple string version: serde = "1.0"
            dep.version_req = Some(s.into());
            dep.version_range = Some(span_to_range(content, line_table, value.span));
        } else if let Some(t) = value.as_table() {
            // Inline table or full table: serde = { version = "1.0" }
            parse_table_dependency(&mut dep, t, content, line_table);
        } else {
            continue;
        }

        deps.push(dep);
    }

    deps
}

/// Parses a table (inline or full) dependency entry.
fn parse_table_dependency(
    dep: &mut ParsedDependency,
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
) {
    for (key, value) in table {
        match key.name.as_ref() {
            "version" => {
                if let Some(s) = value.as_str() {
                    dep.version_req = Some(s.into());
                    dep.version_range = Some(span_to_range(content, line_table, value.span));
                }
            }
            "features" => {
                if let Some(arr) = value.as_array() {
                    dep.features = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    dep.features_range = Some(span_to_range(content, line_table, value.span));
                }
            }
            "workspace" if value.as_bool() == Some(true) => {
                dep.source = DependencySource::Workspace;
            }
            "workspace" => {}
            "git" => {
                if let Some(url) = value.as_str() {
                    dep.source = DependencySource::Git {
                        url: url.to_string(),
                        rev: None,
                    };
                }
            }
            "path" => {
                if let Some(path) = value.as_str() {
                    dep.source = DependencySource::Path {
                        path: path.to_string(),
                    };
                }
            }
            // `registry = "my-corp"` names an alternative registry defined in
            // `.cargo/config.toml`, not crates.io. deps-cargo has no client
            // for it, so it must not stay classified as the plain `Registry`
            // source: `CustomRegistry` opts it out of version-resolution
            // diagnostics that would otherwise silently check it against
            // crates.io's unrelated package of the same name (#248, known
            // limitation until private-registry client support exists).
            // `"crates-io"` is Cargo's reserved alias for the *public*
            // registry (not a custom one) and must stay classified as
            // `Registry`.
            "registry" => {
                if let Some(name) = value.as_str()
                    && name != "crates-io"
                {
                    dep.source = DependencySource::CustomRegistry {
                        url: name.to_string(),
                    };
                }
            }
            // `registry-index = "<url>"` is the direct-URL spelling of the
            // same concept as `registry` above. Cargo's built-in public
            // index URLs must stay classified as `Registry`; any other URL
            // names a private index this LSP has no client for.
            "registry-index" => {
                if let Some(url) = value.as_str()
                    && !is_public_crates_io_index(url)
                {
                    dep.source = DependencySource::CustomRegistry {
                        url: url.to_string(),
                    };
                }
            }
            _ => {}
        }
    }
}

/// Returns true if `url` is one of Cargo's built-in public crates.io index URLs
/// (the git index or the sparse index), as opposed to a private registry index.
fn is_public_crates_io_index(url: &str) -> bool {
    matches!(
        url,
        "https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/"
    )
}

/// Converts toml-span byte offsets to LSP Range using pre-computed line table.
fn span_to_range(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Range {
    let start = line_table.byte_offset_to_position(content, span.start);
    let end = line_table.byte_offset_to_position(content, span.end);
    Range::new(start, end)
}

/// Finds the workspace root by walking up the directory tree.
///
/// Looks for a Cargo.toml file with a [workspace] section.
fn find_workspace_root(doc_uri: &Uri) -> Result<Option<PathBuf>> {
    let path = doc_uri
        .to_file_path()
        .ok_or_else(|| CargoError::invalid_uri(format!("{doc_uri:?}")))?;

    let mut current = path.parent();

    while let Some(dir) = current {
        let workspace_toml = dir.join("Cargo.toml");

        if workspace_toml.exists()
            && let Ok(content) = std::fs::read_to_string(&workspace_toml)
        {
            if deps_core::check_toml_nesting_depth(&content, deps_core::MAX_TOML_NESTING_DEPTH)
                .is_err()
            {
                tracing::warn!(
                    path = %workspace_toml.display(),
                    "skipping ancestor Cargo.toml during workspace root discovery: nesting depth exceeds maximum"
                );
            } else if let Ok(doc) = toml_span::parse(&content)
                && doc
                    .as_table()
                    .and_then(|t| get_val(t, "workspace"))
                    .is_some()
            {
                return Ok(Some(dir.to_path_buf()));
            }
        }

        current = dir.parent();
    }

    Ok(None)
}

/// Parser for Cargo.toml manifests implementing the deps-core traits.
pub struct CargoParser;

// Implement new ParseResult trait for trait object support
impl deps_core::ParseResult for ParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.workspace_root.as_deref()
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_url() -> Uri {
        #[cfg(windows)]
        let path = "C:/test/Cargo.toml";
        #[cfg(not(windows))]
        let path = "/test/Cargo.toml";
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_cargo_toml_rejects_excessive_nesting() {
        // Well past MAX_TOML_NESTING_DEPTH (64) but far below the depth
        // that would actually overflow the stack, so the guard is what's
        // being exercised here, not the crash itself.
        let content = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        let result = parse_cargo_toml(&content, &test_url());
        assert!(matches!(result, Err(CargoError::TomlParseError { .. })));
    }

    #[test]
    fn test_parse_inline_dependency() {
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "serde");
        assert_eq!(result.dependencies[0].version_req, Some("1.0".into()));
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Registry
        ));
    }

    #[test]
    fn test_parse_table_dependency() {
        let toml = r#"[dependencies]
serde = { version = "1.0", features = ["derive"] }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("1.0".into()));
        assert_eq!(result.dependencies[0].features, vec!["derive"]);
    }

    #[test]
    fn test_parse_workspace_inheritance() {
        let toml = r"[dependencies]
serde = { workspace = true }";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Workspace
        ));
    }

    #[test]
    fn test_parse_git_dependency() {
        let toml = r#"[dependencies]
tower-lsp = { git = "https://github.com/ebkalderon/tower-lsp", branch = "main" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Git { .. }
        ));
    }

    #[test]
    fn test_parse_path_dependency() {
        let toml = r#"[dependencies]
local = { path = "../local" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(matches!(
            result.dependencies[0].source,
            DependencySource::Path { .. }
        ));
    }

    #[test]
    fn test_parse_custom_registry_dependency() {
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry = "my-corp" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => assert_eq!(url, "my-corp"),
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(!result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_parse_registry_crates_io_alias_stays_registry() {
        let toml = r#"[dependencies]
serde = { version = "1.0", registry = "crates-io" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
        assert!(result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_parse_registry_index_custom_url() {
        let toml = r#"[dependencies]
internal-crate = { version = "1.0", registry-index = "https://gitlab.mycorp.com/registry-index" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://gitlab.mycorp.com/registry-index");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
        assert!(!result.dependencies[0].source.is_version_resolvable());
    }

    #[test]
    fn test_parse_registry_index_public_crates_io_stays_registry() {
        let toml = r#"[dependencies]
serde = { version = "1.0", registry-index = "https://github.com/rust-lang/crates.io-index" }
serde_json = { version = "1.0", registry-index = "sparse+https://index.crates.io/" }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            assert_eq!(dep.source, DependencySource::Registry);
        }
    }

    #[test]
    fn test_parse_multiple_sections() {
        let toml = r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
insta = "1.0"

[build-dependencies]
cc = "1.0"
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 3);

        assert!(matches!(
            result.dependencies[0].section,
            DependencySection::Dependencies
        ));
        assert!(matches!(
            result.dependencies[1].section,
            DependencySection::DevDependencies
        ));
        assert!(matches!(
            result.dependencies[2].section,
            DependencySection::BuildDependencies
        ));
    }

    #[test]
    fn test_line_offset_table() {
        let content = "abc\ndef";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }

    #[test]
    fn test_line_offset_table_unicode() {
        let content = "hello 世界\nworld";
        let table = LineOffsetTable::new(content);
        let world_offset = content.find("world").unwrap();
        let pos = table.byte_offset_to_position(content, world_offset);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }

    #[test]
    fn test_malformed_toml() {
        let toml = r#"[dependencies
serde = "1.0"#;
        let result = parse_cargo_toml(toml, &test_url());
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_dependencies() {
        let toml = r"[dependencies]";
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 0);
    }

    #[test]
    fn test_position_tracking() {
        let toml = r#"[dependencies]
serde = "1.0""#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.name, "serde");
        assert_eq!(dep.version_req, Some("1.0".into()));

        // Verify name_range is on line 1 (after [dependencies])
        assert_eq!(dep.name_range.start.line, 1);
        // serde starts at column 0 on that line
        assert_eq!(dep.name_range.start.character, 0);
        // Verify end position is after "serde" (5 characters)
        assert_eq!(dep.name_range.end.character, 5);
    }

    #[test]
    fn test_name_range_tracking() {
        let toml = r#"[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();

        for dep in &result.dependencies {
            // All dependencies should have non-default name ranges
            let is_default = dep.name_range.start.line == 0
                && dep.name_range.start.character == 0
                && dep.name_range.end.line == 0
                && dep.name_range.end.character == 0;
            assert!(
                !is_default,
                "name_range should not be default for {}",
                dep.name
            );
        }
    }

    #[test]
    fn test_parse_workspace_dependencies() {
        let toml = r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        for dep in &result.dependencies {
            assert!(matches!(
                dep.section,
                DependencySection::WorkspaceDependencies
            ));
        }

        let serde = result.dependencies.iter().find(|d| d.name == "serde");
        assert!(serde.is_some());
        let serde = serde.unwrap();
        assert_eq!(serde.version_req, Some("1.0".into()));
        // version_range should be set for inlay hints
        assert!(
            serde.version_range.is_some(),
            "version_range should be set for serde"
        );

        let tokio = result.dependencies.iter().find(|d| d.name == "tokio");
        assert!(tokio.is_some());
        let tokio = tokio.unwrap();
        assert_eq!(tokio.version_req, Some("1.0".into()));
        assert_eq!(tokio.features, vec!["full"]);
        // version_range should be set for inlay hints
        assert!(
            tokio.version_range.is_some(),
            "version_range should be set for tokio"
        );
    }

    #[test]
    fn test_parse_workspace_and_regular_dependencies() {
        let toml = r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
serde = "1.0"

[dependencies]
tokio = "1.0"
"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let serde = result.dependencies.iter().find(|d| d.name == "serde");
        assert!(serde.is_some());
        assert!(matches!(
            serde.unwrap().section,
            DependencySection::WorkspaceDependencies
        ));

        let tokio = result.dependencies.iter().find(|d| d.name == "tokio");
        assert!(tokio.is_some());
        assert!(matches!(
            tokio.unwrap().section,
            DependencySection::Dependencies
        ));
    }

    #[test]
    fn test_find_workspace_root_skips_over_depth_ancestor() {
        // Directory layout:
        //   <root>/workspace/Cargo.toml        - valid, has [workspace]
        //   <root>/workspace/mid/Cargo.toml     - malicious: over MAX_TOML_NESTING_DEPTH
        //   <root>/workspace/mid/pkg/Cargo.toml - the file actually opened
        // find_workspace_root must skip the malicious ancestor (log + continue)
        // rather than failing the whole parse, and still find the valid
        // workspace root further up.
        let root = tempfile::tempdir().unwrap();
        let workspace_dir = root.path().join("workspace");
        let mid_dir = workspace_dir.join("mid");
        let pkg_dir = mid_dir.join("pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        std::fs::write(
            workspace_dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"mid/pkg\"]\n",
        )
        .unwrap();

        let malicious = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        std::fs::write(mid_dir.join("Cargo.toml"), malicious).unwrap();

        let opened_content = "[dependencies]\nserde = \"1.0\"\n";
        let opened_path = pkg_dir.join("Cargo.toml");
        std::fs::write(&opened_path, opened_content).unwrap();

        let doc_uri = Uri::from_file_path(&opened_path).unwrap();
        let result = parse_cargo_toml(opened_content, &doc_uri).unwrap();

        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.workspace_root, Some(workspace_dir));
    }
}

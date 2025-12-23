//! Cargo.toml parser with position tracking.
//!
//! Parses Cargo.toml files using toml_edit to preserve formatting and extract
//! precise LSP positions for every dependency field. Critical for features like
//! hover, completion, and inlay hints.
//!
//! # Key Features
//!
//! - Position-preserving parsing via toml_edit spans
//! - Handles all dependency formats: inline, table, workspace inheritance
//! - Extracts dependencies from all sections: dependencies, dev-dependencies, build-dependencies
//! - Converts byte offsets to LSP Position (line, UTF-16 character)
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::parse_cargo_toml;
//! use tower_lsp::lsp_types::Url;
//!
//! let toml = r#"
//! [dependencies]
//! serde = "1.0"
//! "#;
//!
//! let url = Url::parse("file:///test/Cargo.toml").unwrap();
//! let result = parse_cargo_toml(toml, &url).unwrap();
//! assert_eq!(result.dependencies.len(), 1);
//! assert_eq!(result.dependencies[0].name, "serde");
//! ```

use crate::error::{CargoError, Result};
use crate::types::{DependencySection, DependencySource, ParsedDependency};
use std::any::Any;
use std::path::PathBuf;
use toml_edit::{Document, DocumentMut, Item, Table, Value};
use tower_lsp::lsp_types::{Position, Range, Url};

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
    pub uri: Url,
}

/// Pre-computed line start byte offsets for O(1) position lookups.
struct LineOffsetTable {
    line_starts: Vec<usize>,
}

impl LineOffsetTable {
    fn new(content: &str) -> Self {
        let mut line_starts = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                line_starts.push(i + 1);
            }
        }
        Self { line_starts }
    }

    fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts[line];

        let character = content[line_start..offset]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();

        Position::new(line as u32, character)
    }
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
/// use tower_lsp::lsp_types::Url;
///
/// let toml = r#"
/// [dependencies]
/// serde = "1.0"
/// tokio = { version = "1.0", features = ["full"] }
/// "#;
///
/// let url = Url::parse("file:///test/Cargo.toml").unwrap();
/// let result = parse_cargo_toml(toml, &url).unwrap();
/// assert_eq!(result.dependencies.len(), 2);
/// ```
pub fn parse_cargo_toml(content: &str, doc_uri: &Url) -> Result<ParseResult> {
    // Use Document (not DocumentMut) to preserve span information
    let doc: Document<&str> =
        Document::parse(content).map_err(|e| CargoError::TomlParseError { source: e })?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();

    if let Some(deps_item) = doc.get("dependencies")
        && let Some(deps) = deps_item.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            deps,
            content,
            &line_table,
            DependencySection::Dependencies,
        )?);
    }

    if let Some(dev_deps_item) = doc.get("dev-dependencies")
        && let Some(dev_deps) = dev_deps_item.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            dev_deps,
            content,
            &line_table,
            DependencySection::DevDependencies,
        )?);
    }

    if let Some(build_deps_item) = doc.get("build-dependencies")
        && let Some(build_deps) = build_deps_item.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            build_deps,
            content,
            &line_table,
            DependencySection::BuildDependencies,
        )?);
    }

    // Parse workspace dependencies (for workspace root Cargo.toml)
    if let Some(workspace_item) = doc.get("workspace")
        && let Some(workspace_table) = workspace_item.as_table()
        && let Some(workspace_deps_item) = workspace_table.get("dependencies")
        && let Some(workspace_deps) = workspace_deps_item.as_table()
    {
        dependencies.extend(parse_dependencies_section(
            workspace_deps,
            content,
            &line_table,
            DependencySection::WorkspaceDependencies,
        )?);
    }

    let workspace_root = find_workspace_root(doc_uri)?;

    Ok(ParseResult {
        dependencies,
        workspace_root,
        uri: doc_uri.clone(),
    })
}

/// Parses a single dependency section (dependencies, dev-dependencies, or build-dependencies).
fn parse_dependencies_section(
    table: &Table,
    content: &str,
    line_table: &LineOffsetTable,
    section: DependencySection,
) -> Result<Vec<ParsedDependency>> {
    let mut deps = Vec::new();

    for (key, value) in table.iter() {
        let name = key.to_string();

        let name_range = compute_name_range_from_value(content, line_table, &name, value);

        let mut dep = ParsedDependency {
            name,
            name_range,
            version_req: None,
            version_range: None,
            features: Vec::new(),
            features_range: None,
            source: DependencySource::Registry,
            workspace_inherited: false,
            section,
        };

        match value {
            Item::Value(Value::String(s)) => {
                dep.version_req = Some(s.value().to_string());
                if let Some(span) = s.span() {
                    dep.version_range = Some(span_to_range_with_table(
                        content, line_table, span.start, span.end,
                    ));
                }
            }
            Item::Value(Value::InlineTable(t)) => {
                parse_inline_table_dependency(&mut dep, t, content, line_table)?;
            }
            Item::Table(t) => {
                parse_table_dependency(&mut dep, t, content, line_table)?;
            }
            _ => continue,
        }

        deps.push(dep);
    }

    Ok(deps)
}

/// Computes the name range by searching backwards from the value position.
fn compute_name_range_from_value(
    content: &str,
    line_table: &LineOffsetTable,
    name: &str,
    value: &Item,
) -> Range {
    let value_span = match value {
        Item::Value(v) => v.span(),
        Item::Table(t) => t.span(),
        _ => None,
    };

    if let Some(span) = value_span {
        let search_start = span.start.saturating_sub(name.len() + 100);
        let search_end = span.start;

        if search_start < content.len() && search_end <= content.len() {
            let search_slice = &content[search_start..search_end];

            if let Some(pos) = search_slice.rfind(name) {
                let name_start = search_start + pos;
                let name_end = name_start + name.len();

                if name_end <= search_end && name_start < content.len() && name_end <= content.len()
                {
                    return span_to_range_with_table(content, line_table, name_start, name_end);
                }
            }
        }
    } else {
        // Fallback: search for the name in the entire content
        if let Some(pos) = content.find(name) {
            let name_start = pos;
            let name_end = pos + name.len();
            if name_end <= content.len() {
                return span_to_range_with_table(content, line_table, name_start, name_end);
            }
        }
    }

    Range::default()
}

/// Parses an inline table dependency.
fn parse_inline_table_dependency(
    dep: &mut ParsedDependency,
    table: &toml_edit::InlineTable,
    content: &str,
    line_table: &LineOffsetTable,
) -> Result<()> {
    for (key, value) in table.iter() {
        match key {
            "version" => {
                if let Some(s) = value.as_str() {
                    dep.version_req = Some(s.to_string());
                    if let Some(span) = value.span() {
                        dep.version_range = Some(span_to_range_with_table(
                            content, line_table, span.start, span.end,
                        ));
                    }
                }
            }
            "features" => {
                if let Some(arr) = value.as_array() {
                    dep.features = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    if let Some(span) = value.span() {
                        dep.features_range = Some(span_to_range_with_table(
                            content, line_table, span.start, span.end,
                        ));
                    }
                }
            }
            "workspace" if value.as_bool() == Some(true) => {
                dep.workspace_inherited = true;
            }
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
            _ => {}
        }
    }

    Ok(())
}

/// Parses a full table dependency.
fn parse_table_dependency(
    dep: &mut ParsedDependency,
    table: &Table,
    content: &str,
    line_table: &LineOffsetTable,
) -> Result<()> {
    for (key, item) in table.iter() {
        let Item::Value(value) = item else {
            continue;
        };

        match key {
            "version" => {
                if let Some(s) = value.as_str() {
                    dep.version_req = Some(s.to_string());
                    if let Some(span) = value.span() {
                        dep.version_range = Some(span_to_range_with_table(
                            content, line_table, span.start, span.end,
                        ));
                    }
                }
            }
            "features" => {
                if let Some(arr) = value.as_array() {
                    dep.features = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    if let Some(span) = value.span() {
                        dep.features_range = Some(span_to_range_with_table(
                            content, line_table, span.start, span.end,
                        ));
                    }
                }
            }
            "workspace" if value.as_bool() == Some(true) => {
                dep.workspace_inherited = true;
            }
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
            _ => {}
        }
    }

    Ok(())
}

/// Converts toml_edit byte offsets to LSP Range using pre-computed line table.
fn span_to_range_with_table(
    content: &str,
    line_table: &LineOffsetTable,
    start: usize,
    end: usize,
) -> Range {
    let start_pos = line_table.byte_offset_to_position(content, start);
    let end_pos = line_table.byte_offset_to_position(content, end);
    Range::new(start_pos, end_pos)
}

/// Finds the workspace root by walking up the directory tree.
///
/// Looks for a Cargo.toml file with a [workspace] section.
fn find_workspace_root(doc_uri: &Url) -> Result<Option<PathBuf>> {
    let path = doc_uri
        .to_file_path()
        .map_err(|_| CargoError::invalid_uri(doc_uri.to_string()))?;

    let mut current = path.parent();

    while let Some(dir) = current {
        let workspace_toml = dir.join("Cargo.toml");

        if workspace_toml.exists()
            && let Ok(content) = std::fs::read_to_string(&workspace_toml)
            && let Ok(doc) = content.parse::<DocumentMut>()
            && doc.get("workspace").is_some()
        {
            return Ok(Some(dir.to_path_buf()));
        }

        current = dir.parent();
    }

    Ok(None)
}

/// Parser for Cargo.toml manifests implementing the deps-core traits.
pub struct CargoParser;

impl deps_core::ManifestParser for CargoParser {
    type Dependency = ParsedDependency;
    type ParseResult = ParseResult;

    fn parse(&self, content: &str, doc_uri: &Url) -> deps_core::Result<Self::ParseResult> {
        parse_cargo_toml(content, doc_uri).map_err(Into::into)
    }
}

// Implement DependencyInfo trait for ParsedDependency
impl deps_core::DependencyInfo for ParsedDependency {
    fn name(&self) -> &str {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&str> {
        self.version_req.as_deref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::DependencySource {
        match &self.source {
            DependencySource::Registry => deps_core::DependencySource::Registry,
            DependencySource::Git { url, rev } => deps_core::DependencySource::Git {
                url: url.clone(),
                rev: rev.clone(),
            },
            DependencySource::Path { path } => {
                deps_core::DependencySource::Path { path: path.clone() }
            }
        }
    }

    fn features(&self) -> &[String] {
        &self.features
    }
}

// Implement ParseResultInfo trait for ParseResult (legacy)
impl deps_core::ParseResultInfo for ParseResult {
    type Dependency = ParsedDependency;

    fn dependencies(&self) -> &[Self::Dependency] {
        &self.dependencies
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.workspace_root.as_deref()
    }
}

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

    fn uri(&self) -> &Url {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_url() -> Url {
        #[cfg(windows)]
        let url = "file:///C:/test/Cargo.toml";
        #[cfg(not(windows))]
        let url = "file:///test/Cargo.toml";
        Url::parse(url).unwrap()
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
        let toml = r#"[dependencies]
serde = { workspace = true }"#;
        let result = parse_cargo_toml(toml, &test_url()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].workspace_inherited);
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
        let toml = r#"[dependencies]"#;
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
}

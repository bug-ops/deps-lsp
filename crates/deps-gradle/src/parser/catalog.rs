//! Parser for Gradle Version Catalog (gradle/libs.versions.toml).
//!
//! Handles [versions], [libraries] sections with position tracking via toml_edit spans.

use crate::error::{GradleError, Result};
use crate::parser::{GradleParseResult, LineOffsetTable};
use crate::types::GradleDependency;
use std::collections::HashMap;
use toml_edit::DocumentMut;
use tower_lsp_server::ls_types::{Range, Uri};

pub fn parse_version_catalog(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let doc: DocumentMut =
        content
            .parse()
            .map_err(|e: toml_edit::TomlError| GradleError::ParseError {
                message: e.to_string(),
            })?;

    let line_table = LineOffsetTable::new(content);
    let mut version_refs: HashMap<String, String> = HashMap::new();

    // Collect [versions] section: key -> version string
    if let Some(versions_item) = doc.get("versions")
        && let Some(versions_table) = versions_item.as_table()
    {
        for (key, item) in versions_table {
            if let Some(ver_str) = item.as_str() {
                version_refs.insert(key.to_string(), ver_str.to_string());
            }
        }
    }

    let mut dependencies = Vec::new();

    // Parse [libraries] section
    let Some(libs_item) = doc.get("libraries") else {
        return Ok(GradleParseResult {
            dependencies,
            uri: uri.clone(),
        });
    };
    let Some(libs_table) = libs_item.as_table() else {
        return Ok(GradleParseResult {
            dependencies,
            uri: uri.clone(),
        });
    };

    for (_alias, item) in libs_table {
        let Some(dep) = parse_library_entry(item, content, &line_table, &version_refs) else {
            continue;
        };
        dependencies.push(dep);
    }

    Ok(GradleParseResult {
        dependencies,
        uri: uri.clone(),
    })
}

fn parse_library_entry(
    item: &toml_edit::Item,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> Option<GradleDependency> {
    if let Some(inline) = item.as_inline_table() {
        return parse_from_inline(inline, content, line_table, version_refs);
    }
    if let Some(table) = item.as_table() {
        return parse_from_table(table, content, line_table, version_refs);
    }
    None
}

fn parse_from_inline(
    table: &toml_edit::InlineTable,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> Option<GradleDependency> {
    let (group_id, artifact_id, name, name_range) =
        extract_coordinates_inline(table, content, line_table)?;
    let (version_req, version_range) =
        extract_version_inline(table, content, line_table, version_refs);

    Some(GradleDependency {
        group_id,
        artifact_id,
        name,
        name_range,
        version_req,
        version_range,
        configuration: String::new(),
    })
}

fn parse_from_table(
    table: &toml_edit::Table,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> Option<GradleDependency> {
    let (group_id, artifact_id, name, name_range) =
        extract_coordinates_table(table, content, line_table)?;
    let (version_req, version_range) =
        extract_version_table(table, content, line_table, version_refs);

    Some(GradleDependency {
        group_id,
        artifact_id,
        name,
        name_range,
        version_req,
        version_range,
        configuration: String::new(),
    })
}

fn extract_coordinates_inline(
    table: &toml_edit::InlineTable,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<(String, String, String, Range)> {
    if let Some(module_val) = table.get("module") {
        let module_str = module_val.as_str()?;
        let name_range = span_to_range(content, line_table, module_val.span());
        let (g, a) = module_str.split_once(':')?;
        return Some((
            g.to_string(),
            a.to_string(),
            module_str.to_string(),
            name_range,
        ));
    }
    let group_val = table.get("group")?;
    let name_val = table.get("name")?;
    let g = group_val.as_str()?.to_string();
    let a = name_val.as_str()?.to_string();
    let name_str = format!("{g}:{a}");
    let name_range = span_to_range(content, line_table, name_val.span());
    Some((g, a, name_str, name_range))
}

fn extract_coordinates_table(
    table: &toml_edit::Table,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<(String, String, String, Range)> {
    if let Some(module_item) = table.get("module") {
        let module_str = module_item.as_str()?;
        let name_range = span_to_range(content, line_table, module_item.span());
        let (g, a) = module_str.split_once(':')?;
        return Some((
            g.to_string(),
            a.to_string(),
            module_str.to_string(),
            name_range,
        ));
    }
    let group_item = table.get("group")?;
    let name_item = table.get("name")?;
    let g = group_item.as_str()?.to_string();
    let a = name_item.as_str()?.to_string();
    let name_str = format!("{g}:{a}");
    let name_range = span_to_range(content, line_table, name_item.span());
    Some((g, a, name_str, name_range))
}

fn extract_version_inline(
    table: &toml_edit::InlineTable,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> (Option<String>, Option<Range>) {
    let Some(version_val) = table.get("version") else {
        return (None, None);
    };

    if let Some(ver_str) = version_val.as_str() {
        let range = span_to_range(content, line_table, version_val.span());
        return (Some(ver_str.to_string()), Some(range));
    }

    if let Some(version_table) = version_val.as_inline_table()
        && let Some(ref_val) = version_table.get("ref")
        && let Some(ref_key) = ref_val.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range(content, line_table, ref_val.span());
        return (resolved, Some(range));
    }

    (None, None)
}

fn extract_version_table(
    table: &toml_edit::Table,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> (Option<String>, Option<Range>) {
    let Some(version_item) = table.get("version") else {
        return (None, None);
    };

    if let Some(ver_str) = version_item.as_str() {
        let range = span_to_range(content, line_table, version_item.span());
        return (Some(ver_str.to_string()), Some(range));
    }

    if let Some(version_table) = version_item.as_table()
        && let Some(ref_item) = version_table.get("ref")
        && let Some(ref_key) = ref_item.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range(content, line_table, ref_item.span());
        return (resolved, Some(range));
    }

    if let Some(version_table) = version_item.as_inline_table()
        && let Some(ref_val) = version_table.get("ref")
        && let Some(ref_key) = ref_val.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range(content, line_table, ref_val.span());
        return (resolved, Some(range));
    }

    (None, None)
}

fn span_to_range(
    content: &str,
    line_table: &LineOffsetTable,
    span: Option<std::ops::Range<usize>>,
) -> Range {
    let Some(span) = span else {
        return Range::default();
    };
    let (start_off, end_off) = strip_quotes(content, span.start, span.end);
    let start = line_table.byte_offset_to_position(content, start_off);
    let end = line_table.byte_offset_to_position(content, end_off);
    Range::new(start, end)
}

/// If the byte range in `content` is a quoted string, returns the inner range (excluding quotes).
fn strip_quotes(content: &str, start: usize, end: usize) -> (usize, usize) {
    if start >= content.len() || end > content.len() || start >= end {
        return (start, end);
    }
    let slice = &content[start..end];
    if (slice.starts_with('"') && slice.ends_with('"'))
        || (slice.starts_with('\'') && slice.ends_with('\''))
    {
        (start + 1, end - 1)
    } else {
        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri() -> Uri {
        Uri::from_file_path("/project/gradle/libs.versions.toml").unwrap()
    }

    #[test]
    fn test_parse_simple_catalog() {
        let content = r#"[versions]
spring = "3.2.0"
guava = "33.0.0-jre"

[libraries]
spring-boot = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring" }
guava = { module = "com.google.guava:guava", version.ref = "guava" }
"#;
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let spring = result
            .dependencies
            .iter()
            .find(|d| d.name == "org.springframework.boot:spring-boot-starter")
            .unwrap();
        assert_eq!(spring.version_req, Some("3.2.0".into()));
        assert_eq!(spring.group_id, "org.springframework.boot");
        assert_eq!(spring.artifact_id, "spring-boot-starter");
    }

    #[test]
    fn test_parse_inline_version() {
        let content = "[libraries]\njunit = { module = \"junit:junit\", version = \"4.13.2\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("4.13.2".into()));
    }

    #[test]
    fn test_parse_group_name_format() {
        let content = "[libraries]\ncommons = { group = \"org.apache.commons\", name = \"commons-lang3\", version = \"3.14.0\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.apache.commons:commons-lang3"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.14.0".into()));
    }

    #[test]
    fn test_parse_no_version() {
        let content = "[libraries]\nspring-bom = { module = \"org.springframework.boot:spring-boot-dependencies\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_parse_empty_catalog() {
        let content = "[versions]\n[libraries]\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_parse_invalid_toml() {
        let content = "[libraries\nbad toml";
        let result = parse_version_catalog(content, &make_uri());
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_libraries_section() {
        let content = "[versions]\nspring = \"3.2.0\"\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_strip_quotes() {
        let content = "\"hello\"";
        let (s, e) = strip_quotes(content, 0, content.len());
        assert_eq!(&content[s..e], "hello");

        let content = "plain";
        let (s, e) = strip_quotes(content, 0, content.len());
        assert_eq!(&content[s..e], "plain");
    }

    #[test]
    fn test_unresolved_version_ref() {
        let content = "[libraries]\nspring-boot = { module = \"org.springframework.boot:spring-boot-starter\", version.ref = \"missing\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }
}

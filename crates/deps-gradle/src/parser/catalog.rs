//! Parser for Gradle Version Catalog (gradle/libs.versions.toml).
//!
//! Handles \[versions\], \[libraries\] sections with position tracking via toml_edit spans.

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
    let hint_line = name_range.start.line;
    let (version_req, version_range) =
        extract_version_inline(table, content, line_table, version_refs, hint_line);

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
    let hint_line = name_range.start.line;
    let (version_req, version_range) =
        extract_version_table(table, content, line_table, version_refs, hint_line);

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
    let parent_span = table.span();
    if let Some(module_val) = table.get("module") {
        let module_str = module_val.as_str()?;
        let name_range = span_to_range_or_fallback(
            content,
            line_table,
            module_val.span(),
            parent_span,
            "module",
            module_str,
        );
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
    let name_range = span_to_range_or_fallback(
        content,
        line_table,
        name_val.span(),
        parent_span,
        "name",
        &a,
    );
    Some((g, a, name_str, name_range))
}

fn extract_coordinates_table(
    table: &toml_edit::Table,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<(String, String, String, Range)> {
    let parent_span = table.span();
    if let Some(module_item) = table.get("module") {
        let module_str = module_item.as_str()?;
        let name_range = span_to_range_or_fallback(
            content,
            line_table,
            module_item.span(),
            parent_span,
            "module",
            module_str,
        );
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
    let name_range = span_to_range_or_fallback(
        content,
        line_table,
        name_item.span(),
        parent_span,
        "name",
        &a,
    );
    Some((g, a, name_str, name_range))
}

fn extract_version_inline(
    table: &toml_edit::InlineTable,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
    hint_line: u32,
) -> (Option<String>, Option<Range>) {
    let Some(version_val) = table.get("version") else {
        return (None, None);
    };

    if let Some(ver_str) = version_val.as_str() {
        let range = span_to_range_with_hint(
            content,
            line_table,
            version_val.span(),
            "version",
            ver_str,
            hint_line,
        );
        return (Some(ver_str.to_string()), Some(range));
    }

    if let Some(version_table) = version_val.as_inline_table()
        && let Some(ref_val) = version_table.get("ref")
        && let Some(ref_key) = ref_val.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range_with_hint(
            content,
            line_table,
            ref_val.span(),
            "ref",
            ref_key,
            hint_line,
        );
        return (resolved, Some(range));
    }

    (None, None)
}

fn extract_version_table(
    table: &toml_edit::Table,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
    hint_line: u32,
) -> (Option<String>, Option<Range>) {
    let Some(version_item) = table.get("version") else {
        return (None, None);
    };

    if let Some(ver_str) = version_item.as_str() {
        let range = span_to_range_with_hint(
            content,
            line_table,
            version_item.span(),
            "version",
            ver_str,
            hint_line,
        );
        return (Some(ver_str.to_string()), Some(range));
    }

    if let Some(version_table) = version_item.as_table()
        && let Some(ref_item) = version_table.get("ref")
        && let Some(ref_key) = ref_item.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range_with_hint(
            content,
            line_table,
            ref_item.span(),
            "ref",
            ref_key,
            hint_line,
        );
        return (resolved, Some(range));
    }

    if let Some(version_table) = version_item.as_inline_table()
        && let Some(ref_val) = version_table.get("ref")
        && let Some(ref_key) = ref_val.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range_with_hint(
            content,
            line_table,
            ref_val.span(),
            "ref",
            ref_key,
            hint_line,
        );
        return (resolved, Some(range));
    }

    (None, None)
}

fn span_to_range_or_fallback(
    content: &str,
    line_table: &LineOffsetTable,
    span: Option<std::ops::Range<usize>>,
    _parent_span: Option<std::ops::Range<usize>>,
    key: &str,
    value: &str,
) -> Range {
    if span.is_some() {
        return span_to_range(content, line_table, span);
    }
    find_value_in_content(content, line_table, key, value)
}

fn span_to_range_with_hint(
    content: &str,
    line_table: &LineOffsetTable,
    span: Option<std::ops::Range<usize>>,
    key: &str,
    value: &str,
    hint_line: u32,
) -> Range {
    if span.is_some() {
        return span_to_range(content, line_table, span);
    }
    find_value_on_line(content, line_table, key, value, hint_line)
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

/// Find the first occurrence of a quoted value by key in the entire content.
/// Used for unique values like module/name coordinates.
fn find_value_in_content(
    content: &str,
    line_table: &LineOffsetTable,
    key: &str,
    value: &str,
) -> Range {
    let needle = format!("\"{value}\"");
    let mut search_from = 0;
    while let Some(key_pos) = content[search_from..].find(key) {
        let abs_key = search_from + key_pos;
        let after_key = &content[abs_key..];
        let line_end = after_key.find('\n').unwrap_or(after_key.len());
        if let Some(val_offset) = after_key[..line_end].find(&needle) {
            let abs_start = abs_key + val_offset + 1;
            let abs_end = abs_start + value.len();
            let start = line_table.byte_offset_to_position(content, abs_start);
            let end = line_table.byte_offset_to_position(content, abs_end);
            return Range::new(start, end);
        }
        search_from = abs_key + key.len();
    }
    Range::default()
}

/// Find the range of a quoted value on a specific line by text search.
/// `hint_line` constrains the search to a specific 0-based line number.
fn find_value_on_line(
    content: &str,
    line_table: &LineOffsetTable,
    key: &str,
    value: &str,
    hint_line: u32,
) -> Range {
    let line_start = line_table.line_start_offset(hint_line);
    let line_end = line_table.line_end_offset(content, hint_line);
    let line_slice = &content[line_start..line_end];
    let needle = format!("\"{value}\"");
    if let Some(key_pos) = line_slice.find(key)
        && let Some(val_offset) = line_slice[key_pos..].find(&needle)
    {
        let abs_start = line_start + key_pos + val_offset + 1;
        let abs_end = abs_start + value.len();
        let start = line_table.byte_offset_to_position(content, abs_start);
        let end = line_table.byte_offset_to_position(content, abs_end);
        return Range::new(start, end);
    }
    Range::default()
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
    fn test_version_ref_position_tracking() {
        let content = r#"[versions]
spring = "3.2.0"

[libraries]
spring-boot = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring" }
"#;
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        let dep = &result.dependencies[0];

        // name_range should point to the module value on line 4
        assert_eq!(dep.name_range.start.line, 4);
        assert!(dep.name_range.start.character > 0);

        // version_range should also be on line 4, not line 0
        let vr = dep.version_range.as_ref().unwrap();
        assert_eq!(vr.start.line, 4);
        assert!(vr.start.character > 0);
    }

    #[test]
    fn test_duplicate_version_ref_different_lines() {
        let content = r#"[versions]
hilt = "2.50"

[libraries]
hilt-android = { group = "com.google.dagger", name = "hilt-android", version.ref = "hilt" }
hilt-compiler = { group = "com.google.dagger", name = "hilt-compiler", version.ref = "hilt" }
"#;
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let d0 = &result.dependencies[0];
        let d1 = &result.dependencies[1];
        let vr0 = d0.version_range.as_ref().unwrap();
        let vr1 = d1.version_range.as_ref().unwrap();

        // Each dependency's version range must be on its own line
        assert_ne!(vr0.start.line, vr1.start.line);
        assert_eq!(vr0.start.line, d0.name_range.start.line);
        assert_eq!(vr1.start.line, d1.name_range.start.line);
    }

    #[test]
    fn test_unresolved_version_ref() {
        let content = "[libraries]\nspring-boot = { module = \"org.springframework.boot:spring-boot-starter\", version.ref = \"missing\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }
}

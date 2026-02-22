//! Parser for Gradle Version Catalog (gradle/libs.versions.toml).
//!
//! Handles \[versions\], \[libraries\] sections with position tracking via toml-span.

use crate::error::{GradleError, Result};
use crate::parser::{GradleParseResult, LineOffsetTable};
use crate::types::GradleDependency;
use std::collections::HashMap;
use toml_span::value::{Table, Value};
use tower_lsp_server::ls_types::{Range, Uri};

pub fn parse_version_catalog(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let doc = toml_span::parse(content).map_err(|e| GradleError::ParseError {
        message: e.to_string(),
    })?;

    let line_table = LineOffsetTable::new(content);
    let mut version_refs: HashMap<String, String> = HashMap::new();

    // Collect [versions] section: key -> version string
    if let Some(versions_table) = doc.as_table().and_then(|t| get_table_val(t, "versions"))
        && let Some(t) = versions_table.as_table()
    {
        for (key, item) in t {
            if let Some(ver_str) = item.as_str() {
                version_refs.insert(key.name.to_string(), ver_str.to_string());
            }
        }
    }

    let mut dependencies = Vec::new();

    let Some(libs_table) = doc
        .as_table()
        .and_then(|t| get_table_val(t, "libraries"))
        .and_then(|v| v.as_table())
    else {
        return Ok(GradleParseResult {
            dependencies,
            uri: uri.clone(),
        });
    };

    for item in libs_table.values() {
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

fn get_table_val<'a>(table: &'a Table<'a>, key: &str) -> Option<&'a Value<'a>> {
    table.get(key)
}

fn parse_library_entry(
    item: &Value<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> Option<GradleDependency> {
    let table = item.as_table()?;
    let (group_id, artifact_id, name, name_range) =
        extract_coordinates(table, content, line_table)?;
    let (version_req, version_range) = extract_version(table, content, line_table, version_refs);

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

fn extract_coordinates<'a>(
    table: &'a Table<'a>,
    content: &str,
    line_table: &LineOffsetTable,
) -> Option<(String, String, String, Range)> {
    if let Some(module_val) = get_table_val(table, "module") {
        let module_str = module_val.as_str()?;
        let name_range = span_to_range(content, line_table, module_val.span);
        let (g, a) = module_str.split_once(':')?;
        return Some((
            g.to_string(),
            a.to_string(),
            module_str.to_string(),
            name_range,
        ));
    }
    let group_val = get_table_val(table, "group")?;
    let name_val = get_table_val(table, "name")?;
    let g = group_val.as_str()?.to_string();
    let a = name_val.as_str()?.to_string();
    let name_str = format!("{g}:{a}");
    let name_range = span_to_range(content, line_table, name_val.span);
    Some((g, a, name_str, name_range))
}

fn extract_version(
    table: &Table<'_>,
    content: &str,
    line_table: &LineOffsetTable,
    version_refs: &HashMap<String, String>,
) -> (Option<String>, Option<Range>) {
    let Some(version_val) = get_table_val(table, "version") else {
        return (None, None);
    };

    if let Some(ver_str) = version_val.as_str() {
        let range = span_to_range(content, line_table, version_val.span);
        return (Some(ver_str.to_string()), Some(range));
    }

    // version.ref = "alias" — toml-span represents dotted keys as nested tables
    if let Some(version_table) = version_val.as_table()
        && let Some(ref_val) = get_table_val(version_table, "ref")
        && let Some(ref_key) = ref_val.as_str()
    {
        let resolved = version_refs.get(ref_key).cloned();
        let range = span_to_range(content, line_table, ref_val.span);
        return (resolved, Some(range));
    }

    (None, None)
}

fn span_to_range(content: &str, line_table: &LineOffsetTable, span: toml_span::Span) -> Range {
    // toml-span string spans already exclude surrounding quotes
    let start = line_table.byte_offset_to_position(content, span.start);
    let end = line_table.byte_offset_to_position(content, span.end);
    Range::new(start, end)
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
        // toml-span handles quote stripping internally; this test verifies that
        // string values returned via as_str() don't include surrounding quotes.
        let content = "[libraries]\njunit = { module = \"junit:junit\", version = \"4.13.2\" }\n";
        let result = parse_version_catalog(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("4.13.2".to_string())
        );
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

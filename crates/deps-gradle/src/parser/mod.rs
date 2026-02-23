//! Gradle manifest parser dispatcher.
//!
//! Routes parsing to the appropriate module based on file extension/name.

pub mod catalog;
pub mod groovy;
pub mod kotlin;
pub mod properties;
pub mod settings;

use crate::error::Result;
use crate::types::GradleDependency;
use std::any::Any;
use std::collections::HashMap;
use tower_lsp_server::ls_types::{Position, Range, Uri};

pub use deps_core::lsp_helpers::LineOffsetTable;

pub struct GradleParseResult {
    pub dependencies: Vec<GradleDependency>,
    pub uri: Uri,
}

/// Resolves `$var` and `${var}` references in dependency versions using the given properties map.
///
/// If a version is a variable reference and the variable is found in `properties`,
/// the version is replaced with the resolved value. The version_range is kept as-is
/// (pointing to the variable reference in source).
pub fn resolve_variables(deps: &mut [GradleDependency], properties: &HashMap<String, String>) {
    for dep in deps.iter_mut() {
        if let Some(ref ver) = dep.version_req
            && let Some(resolved) = resolve_variable_ref(ver, properties)
        {
            dep.version_req = Some(resolved);
        }
    }
}

/// Returns the resolved value if `value` is a `$name` or `${name}` reference. Returns `None` otherwise.
fn resolve_variable_ref(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let trimmed = value.trim();
    if let Some(name) = trimmed.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        properties.get(name).cloned()
    } else if let Some(name) = trimmed.strip_prefix('$') {
        properties.get(name).cloned()
    } else {
        None
    }
}

pub fn parse_gradle(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let path = uri.path().to_string();
    let mut result = if path.ends_with("libs.versions.toml") {
        catalog::parse_version_catalog(content, uri)?
    } else if path.ends_with("settings.gradle.kts") || path.ends_with("settings.gradle") {
        settings::parse_settings(content, uri)?
    } else if path.ends_with(".gradle.kts") {
        kotlin::parse_kotlin_dsl(content, uri)?
    } else if path.ends_with(".gradle") {
        groovy::parse_groovy_dsl(content, uri)?
    } else {
        return Ok(GradleParseResult {
            dependencies: vec![],
            uri: uri.clone(),
        });
    };

    // Resolve variable references for build files (not catalogs or settings)
    if (path.ends_with("build.gradle.kts") || path.ends_with("build.gradle"))
        && let Some(dir) = std::path::Path::new(&path).parent()
    {
        let props = properties::load_gradle_properties(dir);
        if !props.is_empty() {
            resolve_variables(&mut result.dependencies, &props);
        }
    }

    Ok(result)
}

impl deps_core::ParseResult for GradleParseResult {
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

/// Returns the number of UTF-16 code units in `s`.
pub(crate) fn utf16_len(s: &str) -> usize {
    s.chars().map(|c| c.len_utf16()).sum()
}

/// Finds the LSP range of `"group_id:artifact_id"` within `line`.
pub(crate) fn find_name_range(
    line: &str,
    line_idx: u32,
    group_id: &str,
    artifact_id: &str,
) -> Range {
    let search = format!("{group_id}:{artifact_id}");
    if let Some(col) = line.find(&search) {
        let col_u32 = utf16_len(&line[..col]) as u32;
        let end_u32 = col_u32 + utf16_len(&search) as u32;
        Range::new(
            Position::new(line_idx, col_u32),
            Position::new(line_idx, end_u32),
        )
    } else {
        Range::default()
    }
}

/// Finds the LSP range of `version` in `line` after the second `:`.
pub(crate) fn find_version_range(line: &str, line_idx: u32, version: &str) -> Range {
    let second_colon = line
        .char_indices()
        .filter(|(_, c)| *c == ':')
        .nth(1)
        .map(|(i, _)| i);

    if let Some(colon_pos) = second_colon {
        let after_colon = &line[colon_pos + 1..];
        if let Some(rel) = after_colon.find(version) {
            let abs_start = colon_pos + 1 + rel;
            let col_start = utf16_len(&line[..abs_start]) as u32;
            let col_end = col_start + utf16_len(version) as u32;
            return Range::new(
                Position::new(line_idx, col_start),
                Position::new(line_idx, col_end),
            );
        }
    }
    Range::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri(path: &str) -> Uri {
        Uri::from_file_path(path).unwrap()
    }

    #[test]
    fn test_dispatch_catalog() {
        let content = "[versions]\nspring = \"3.2.0\"\n\n[libraries]\nspring-boot = { module = \"org.springframework.boot:spring-boot-starter\", version.ref = \"spring\" }\n";
        let uri = make_uri("/project/gradle/libs.versions.toml");
        let result = parse_gradle(content, &uri).unwrap();
        assert!(!result.dependencies.is_empty());
    }

    #[test]
    fn test_dispatch_kotlin() {
        let content = "dependencies {\n    implementation(\"org.springframework.boot:spring-boot-starter:3.2.0\")\n}\n";
        let uri = make_uri("/project/build.gradle.kts");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_groovy() {
        let content = "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'\n}\n";
        let uri = make_uri("/project/build.gradle");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_settings_gradle() {
        let content = "pluginManagement {\n    plugins {\n        id \"org.jetbrains.kotlin.jvm\" version \"2.1.10\"\n    }\n}\n";
        let uri = make_uri("/project/settings.gradle");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_settings_gradle_kts() {
        let content = "pluginManagement {\n    plugins {\n        id(\"org.springframework.boot\") version \"3.2.0\"\n    }\n}\n";
        let uri = make_uri("/project/settings.gradle.kts");
        let result = parse_gradle(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_dispatch_unknown() {
        let uri = make_uri("/project/something.xml");
        let result = parse_gradle("", &uri).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_resolve_variables_dollar_brace() {
        let props: HashMap<String, String> =
            [("kotlinVersion".to_string(), "2.1.10".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "org.jetbrains.kotlin".into(),
            artifact_id: "kotlin-stdlib".into(),
            name: "org.jetbrains.kotlin:kotlin-stdlib".into(),
            name_range: Range::default(),
            version_req: Some("${kotlinVersion}".into()),
            version_range: None,
            configuration: "implementation".into(),
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("2.1.10".into()));
    }

    #[test]
    fn test_resolve_variables_dollar_plain() {
        let props: HashMap<String, String> =
            [("springVersion".to_string(), "3.2.0".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "org.springframework.boot".into(),
            artifact_id: "spring-boot-starter".into(),
            name: "org.springframework.boot:spring-boot-starter".into(),
            name_range: Range::default(),
            version_req: Some("$springVersion".into()),
            version_range: None,
            configuration: "implementation".into(),
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_resolve_variables_not_found_keeps_raw() {
        let props: HashMap<String, String> = HashMap::new();
        let mut deps = vec![GradleDependency {
            group_id: "com.example".into(),
            artifact_id: "lib".into(),
            name: "com.example:lib".into(),
            name_range: Range::default(),
            version_req: Some("$unknownVar".into()),
            version_range: None,
            configuration: "implementation".into(),
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("$unknownVar".into()));
    }

    #[test]
    fn test_resolve_variables_literal_version_unchanged() {
        let props: HashMap<String, String> = [("v".to_string(), "9.9.9".to_string())].into();
        let mut deps = vec![GradleDependency {
            group_id: "com.example".into(),
            artifact_id: "lib".into(),
            name: "com.example:lib".into(),
            name_range: Range::default(),
            version_req: Some("1.2.3".into()),
            version_range: None,
            configuration: "implementation".into(),
        }];
        resolve_variables(&mut deps, &props);
        assert_eq!(deps[0].version_req, Some("1.2.3".into()));
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let uri = make_uri("/project/build.gradle");
        let result = parse_gradle("", &uri).unwrap();
        assert!(result.dependencies().is_empty());
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<GradleParseResult>());
    }

    #[test]
    fn test_line_offset_table() {
        let content = "line0\nline1\nline2";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 6);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);

        let pos = table.byte_offset_to_position(content, 8);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 2);
    }

    #[test]
    fn test_find_name_range() {
        let line = "    implementation(\"com.example:lib:1.0.0\")";
        let range = find_name_range(line, 5, "com.example", "lib");
        assert_eq!(range.start.line, 5);
        assert!(range.start.character > 0);
    }

    #[test]
    fn test_find_version_range() {
        let line = "    implementation(\"com.example:lib:1.0.0\")";
        let range = find_version_range(line, 5, "1.0.0");
        assert_eq!(range.start.line, 5);
        // "1.0.0" is 5 chars, end = start + 5
        assert_eq!(range.end.character - range.start.character, 5);
    }

    #[test]
    fn test_utf16_len_ascii() {
        assert_eq!(utf16_len("hello"), 5);
    }
}

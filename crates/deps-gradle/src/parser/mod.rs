//! Gradle manifest parser dispatcher.
//!
//! Routes parsing to the appropriate module based on file extension/name.

pub mod catalog;
pub mod groovy;
pub mod kotlin;

use crate::error::Result;
use crate::types::GradleDependency;
use std::any::Any;
use tower_lsp_server::ls_types::{Position, Range, Uri};

pub use deps_core::lsp_helpers::LineOffsetTable;

pub struct GradleParseResult {
    pub dependencies: Vec<GradleDependency>,
    pub uri: Uri,
}

pub fn parse_gradle(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let path = uri.path().to_string();
    if path.ends_with("libs.versions.toml") {
        catalog::parse_version_catalog(content, uri)
    } else if path.ends_with(".gradle.kts") {
        kotlin::parse_kotlin_dsl(content, uri)
    } else if path.ends_with(".gradle") {
        groovy::parse_groovy_dsl(content, uri)
    } else {
        Ok(GradleParseResult {
            dependencies: vec![],
            uri: uri.clone(),
        })
    }
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
    fn test_dispatch_unknown() {
        let uri = make_uri("/project/settings.gradle");
        let result = parse_gradle("", &uri).unwrap();
        assert!(result.dependencies.is_empty());
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

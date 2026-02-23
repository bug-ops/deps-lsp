//! Parser for settings.gradle and settings.gradle.kts files.
//!
//! Extracts plugin declarations from `pluginManagement { plugins { } }` blocks.

use crate::error::Result;
use crate::parser::{GradleParseResult, utf16_len};
use crate::types::GradleDependency;
use regex::Regex;
use std::sync::OnceLock;
use tower_lsp_server::ls_types::{Position, Range, Uri};

/// Matches: id "plugin.id" version "1.0.0" (Groovy) or id("plugin.id") version "1.0.0" (Kotlin DSL)
static RE_PLUGIN: OnceLock<Regex> = OnceLock::new();

fn re_plugin() -> &'static Regex {
    RE_PLUGIN.get_or_init(|| {
        Regex::new(r#"id\s*\(?\s*['"]([^'"]+)['"]\s*\)?\s+version\s+['"]([^'"]+)['"]"#).unwrap()
    })
}

/// Finds the LSP range of `plugin_id` within `line`.
fn find_plugin_name_range(line: &str, line_idx: u32, plugin_id: &str) -> Range {
    if let Some(col) = line.find(plugin_id) {
        let col_u32 = utf16_len(&line[..col]) as u32;
        let end_u32 = col_u32 + utf16_len(plugin_id) as u32;
        Range::new(
            Position::new(line_idx, col_u32),
            Position::new(line_idx, end_u32),
        )
    } else {
        Range::default()
    }
}

/// Finds the LSP range of `version` in `line` after the `version` keyword.
fn find_plugin_version_range(line: &str, line_idx: u32, version: &str) -> Range {
    // Find "version" keyword, then locate the version string after it
    if let Some(kw_pos) = line.find("version") {
        let after_kw = &line[kw_pos + "version".len()..];
        if let Some(rel) = after_kw.find(version) {
            let abs_start = kw_pos + "version".len() + rel;
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

/// Parses `pluginManagement { plugins { ... } }` blocks from settings.gradle / settings.gradle.kts.
pub fn parse_settings(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();
    let mut brace_depth: i32 = 0;
    let mut in_plugin_management = false;
    let mut pm_depth: i32 = 0;
    let mut in_plugins = false;
    let mut plugins_depth: i32 = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Detect pluginManagement { entry
        if !in_plugin_management && trimmed.starts_with("pluginManagement") && trimmed.contains('{')
        {
            in_plugin_management = true;
            pm_depth = brace_depth + 1;
        }

        // Detect plugins { entry inside pluginManagement
        if in_plugin_management
            && !in_plugins
            && trimmed.starts_with("plugins")
            && trimmed.contains('{')
        {
            in_plugins = true;
            plugins_depth = brace_depth + 1;
        }

        // Count braces
        for ch in line.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if in_plugins && brace_depth < plugins_depth {
                        in_plugins = false;
                    }
                    if in_plugin_management && brace_depth < pm_depth {
                        in_plugin_management = false;
                    }
                }
                _ => {}
            }
        }

        if !in_plugins {
            continue;
        }

        let line_u32 = line_idx as u32;

        for caps in re_plugin().captures_iter(line) {
            let plugin_id = caps.get(1).map_or("", |m| m.as_str()).to_string();
            let version = caps.get(2).map_or("", |m| m.as_str()).trim().to_string();

            // Convention: pluginId -> group = pluginId, artifact = pluginId.gradle.plugin
            let artifact_id = format!("{plugin_id}.gradle.plugin");
            let name = format!("{plugin_id}:{artifact_id}");

            let name_range = find_plugin_name_range(line, line_u32, &plugin_id);
            let version_range = find_plugin_version_range(line, line_u32, &version);

            dependencies.push(GradleDependency {
                group_id: plugin_id,
                artifact_id,
                name,
                name_range,
                version_req: Some(version),
                version_range: Some(version_range),
                configuration: "plugin".to_string(),
            });
        }
    }

    Ok(GradleParseResult {
        dependencies,
        uri: uri.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri(name: &str) -> Uri {
        Uri::from_file_path(format!("/project/{name}")).unwrap()
    }

    #[test]
    fn test_parse_groovy_plugin() {
        let content = r#"pluginManagement {
    plugins {
        id "org.jetbrains.kotlin.jvm" version "2.1.10"
        id 'com.google.devtools.ksp' version '2.1.10-1.0.31'
    }
}
"#;
        let result = parse_settings(content, &make_uri("settings.gradle")).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let dep = &result.dependencies[0];
        assert_eq!(dep.group_id, "org.jetbrains.kotlin.jvm");
        assert_eq!(dep.artifact_id, "org.jetbrains.kotlin.jvm.gradle.plugin");
        assert_eq!(
            dep.name,
            "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin"
        );
        assert_eq!(dep.version_req, Some("2.1.10".into()));
        assert_eq!(dep.configuration, "plugin");

        let dep2 = &result.dependencies[1];
        assert_eq!(dep2.group_id, "com.google.devtools.ksp");
        assert_eq!(dep2.version_req, Some("2.1.10-1.0.31".into()));
    }

    #[test]
    fn test_parse_kotlin_dsl_plugin() {
        let content = r#"pluginManagement {
    plugins {
        id("org.springframework.boot") version "3.2.0"
    }
}
"#;
        let result = parse_settings(content, &make_uri("settings.gradle.kts")).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].group_id, "org.springframework.boot");
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_no_plugin_management_block() {
        let content = "rootProject.name = \"my-project\"\n";
        let result = parse_settings(content, &make_uri("settings.gradle")).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_plugin_without_version_skipped() {
        let content = r#"pluginManagement {
    plugins {
        id "org.jetbrains.kotlin.jvm"
    }
}
"#;
        let result = parse_settings(content, &make_uri("settings.gradle")).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = r#"pluginManagement {
    plugins {
        id "org.jetbrains.kotlin.jvm" version "2.1.10"
    }
}
"#;
        let result = parse_settings(content, &make_uri("settings.gradle")).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name_range.start.line, 2);
        assert!(dep.version_range.is_some());
        let vr = dep.version_range.unwrap();
        assert_eq!(vr.start.line, 2);
    }

    #[test]
    fn test_empty_content() {
        let result = parse_settings("", &make_uri("settings.gradle")).unwrap();
        assert!(result.dependencies.is_empty());
    }
}

//! Parser for settings.gradle and settings.gradle.kts files.
//!
//! Extracts plugin declarations from `pluginManagement { plugins { } }` blocks.

use crate::parser::{GradleParseResult, LineOffsetTable, SourceLine};
use crate::types::GradleDependency;
use deps_core::Result;
use regex::Regex;
use std::sync::LazyLock;
use url::Url;

/// Matches: id "plugin.id" version "1.0.0" (Groovy) or id("plugin.id") version "1.0.0" (Kotlin DSL)
// Compile-time-constant pattern; a malformed literal is a build-visible programmer error,
// not attacker-influenceable input.
#[allow(clippy::expect_used)]
static RE_PLUGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"id\s*\(?\s*['"]([^'"]+)['"]\s*\)?\s+version\s+['"]([^'"]+)['"]"#)
        .expect("RE_PLUGIN")
});

/// Parses `pluginManagement { plugins { ... } }` blocks from settings.gradle / settings.gradle.kts.
///
/// # Errors
///
/// Infallible by construction: unrecognized lines are skipped rather than erroring.
/// Returns [`Result`] only to match the shared parser signature every ecosystem implements.
pub fn parse_settings(content: &str, uri: &Url) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();
    let line_table = LineOffsetTable::new(content);
    let mut brace_depth: i32 = 0;
    let mut in_plugin_management = false;
    let mut pm_depth: i32 = 0;
    let mut in_plugins = false;
    let mut plugins_depth: i32 = 0;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if !in_plugin_management && trimmed.starts_with("pluginManagement") && trimmed.contains('{')
        {
            in_plugin_management = true;
            pm_depth = brace_depth + 1;
        }

        if in_plugin_management
            && !in_plugins
            && trimmed.starts_with("plugins")
            && trimmed.contains('{')
        {
            in_plugins = true;
            plugins_depth = brace_depth + 1;
        }

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

        let src = SourceLine::new(&line_table, content, line_idx, line);

        for caps in RE_PLUGIN.captures_iter(line) {
            if !budget.allow() {
                continue;
            }
            let (id_start, plugin_id) = caps.get(1).map_or((0, ""), |m| (m.start(), m.as_str()));
            let (version_start, raw_version) =
                caps.get(2).map_or((0, ""), |m| (m.start(), m.as_str()));
            let version = raw_version.trim();
            let leading_ws = raw_version.len() - raw_version.trim_start().len();

            // Convention: pluginId -> group = pluginId, artifact = pluginId.gradle.plugin
            let artifact_id = format!("{plugin_id}.gradle.plugin");
            let name = format!("{plugin_id}:{artifact_id}");

            let name_range = src.range_of(id_start, plugin_id);
            let version_range = src.range_of(version_start + leading_ws, version);

            dependencies.push(GradleDependency {
                group_id: plugin_id.to_string(),
                artifact_id,
                name: name.into(),
                name_range,
                version_req: Some(version.to_string().into()),
                version_range: Some(version_range),
                configuration: "plugin".to_string(),
                source: deps_core::parser::DependencySource::Registry,
            });
        }
    }

    Ok(GradleParseResult {
        dependencies,
        uri: uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_uri(name: &str) -> Url {
        deps_core::test_util::test_uri(&format!("/project/{name}"))
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

    /// #1701: one huge non-ASCII line with thousands of plugins must report exact UTF-16
    /// columns for both the plugin id and the version.
    #[test]
    fn test_single_long_line_utf16_columns() {
        const N: usize = 5000;
        let filler = "/*\u{1F600}\u{65E5}*/ ";
        let units = |s: &str| u32::try_from(s.encode_utf16().count()).unwrap();
        let mut body = String::from("        ");
        let mut expected = Vec::with_capacity(N);
        let mut col = units(&body);
        for i in 0..N {
            let id = format!("org.p{i}");
            let version = format!("1.{i}");
            let before_id = format!("{filler}id(\"");
            let between = "\") version \"";
            col += units(&before_id);
            let id_range = (col, col + units(&id));
            col += units(&id) + units(between);
            expected.push((id_range, (col, col + units(&version))));
            col += units(&version) + 1;
            body.push_str(&format!("{before_id}{id}{between}{version}\""));
        }
        let content = format!("pluginManagement {{\n    plugins {{\n{body}\n    }}\n}}\n");

        let result = parse_settings(&content, &make_uri("settings.gradle.kts")).unwrap();

        assert_eq!(result.dependencies.len(), N);
        let got: Vec<_> = result
            .dependencies
            .iter()
            .map(|d| {
                let v = d.version_range.unwrap();
                (
                    (d.name_range.start.character, d.name_range.end.character),
                    (v.start.character, v.end.character),
                )
            })
            .collect();
        assert_eq!(got, expected);
    }

    /// A shorter id sharing a prefix with an earlier one, and an identical version, must map
    /// to its own span rather than the first plugin's.
    #[test]
    fn test_prefix_sharing_ids_get_own_ranges() {
        let line = r#"        id("org.a.b") version "1.0"; id("org.a") version "1.0""#;
        let content = format!("pluginManagement {{\n    plugins {{\n{line}\n    }}\n}}\n");
        let result = parse_settings(&content, &make_uri("settings.gradle.kts")).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        let second = &result.dependencies[1];
        let id_col = u32::try_from(line.rfind("org.a\"").unwrap()).unwrap();
        assert_eq!(second.name_range.start.character, id_col);
        assert_eq!(second.name_range.end.character, id_col + 5);
        let ver_col = u32::try_from(line.rfind("1.0").unwrap()).unwrap();
        assert_eq!(second.version_range.unwrap().start.character, ver_col);
    }
}

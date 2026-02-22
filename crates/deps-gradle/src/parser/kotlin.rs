//! Parser for Gradle Kotlin DSL (build.gradle.kts).
//!
//! Regex-based extraction of dependency declarations from dependencies { } blocks.

use crate::error::Result;
use crate::parser::{GradleParseResult, find_name_range, find_version_range};
use crate::types::GradleDependency;
use regex::Regex;
use std::sync::OnceLock;
use tower_lsp_server::ls_types::Uri;

/// Matches: implementation("group:artifact:version")
static RE_WITH_VERSION: OnceLock<Regex> = OnceLock::new();
/// Matches: implementation("group:artifact") — no version
static RE_NO_VERSION: OnceLock<Regex> = OnceLock::new();

const CONFIGURATIONS: &[&str] = &[
    "implementation",
    "api",
    "compileOnly",
    "runtimeOnly",
    "testImplementation",
    "testRuntimeOnly",
    "annotationProcessor",
    "kapt",
    "classpath",
    "ksp",
    "testCompileOnly",
];

fn re_with_version() -> &'static Regex {
    RE_WITH_VERSION
        .get_or_init(|| Regex::new(r#"(\w+)\(\s*"([^:"\s]+):([^:"\s]+):([^"]+)"\s*\)"#).unwrap())
}

fn re_no_version() -> &'static Regex {
    RE_NO_VERSION.get_or_init(|| Regex::new(r#"(\w+)\(\s*"([^:"\s]+):([^:"\s"]+)"\s*\)"#).unwrap())
}

pub fn parse_kotlin_dsl(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();

    // Track brace depth to detect dependencies { } block
    let mut brace_depth: i32 = 0;
    let mut in_dependencies_block = false;
    let mut deps_brace_depth: i32 = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Detect entry into dependencies { block
        if !in_dependencies_block
            && (trimmed == "dependencies {" || trimmed.starts_with("dependencies {"))
        {
            in_dependencies_block = true;
            deps_brace_depth = brace_depth + 1;
        }

        // Count braces
        for ch in line.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if in_dependencies_block && brace_depth < deps_brace_depth {
                        in_dependencies_block = false;
                    }
                }
                _ => {}
            }
        }

        if !in_dependencies_block && !line.trim_start().starts_with("dependencies") {
            continue;
        }

        let line_u32 = line_idx as u32;

        // Try pattern with version first
        for caps in re_with_version().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }

            let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
            let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
            let version = caps.get(4).map_or("", |m| m.as_str()).trim().to_string();
            let name = format!("{group_id}:{artifact_id}");

            // name_range covers the full "group:artifact" portion of the string
            let name_range = find_name_range(line, line_u32, &group_id, &artifact_id);
            let version_range = find_version_range(line, line_u32, &version);

            dependencies.push(GradleDependency {
                group_id,
                artifact_id,
                name,
                name_range,
                version_req: Some(version),
                version_range: Some(version_range),
                configuration: config.to_string(),
            });
        }

        // Try pattern without version (only if no versioned match on this line)
        // Avoid double-matching lines that were already caught above
        let already_matched: Vec<_> = re_with_version()
            .captures_iter(line)
            .filter_map(|c| {
                let config = c.get(1)?.as_str();
                CONFIGURATIONS
                    .contains(&config)
                    .then_some(c.get(0)?.start())
            })
            .collect();

        for caps in re_no_version().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }
            // Skip if this match overlaps with a versioned match
            let match_start = caps.get(0).map_or(0, |m| m.start());
            if already_matched.contains(&match_start) {
                continue;
            }

            let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
            let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
            let name = format!("{group_id}:{artifact_id}");
            let name_range = find_name_range(line, line_u32, &group_id, &artifact_id);

            dependencies.push(GradleDependency {
                group_id,
                artifact_id,
                name,
                name_range,
                version_req: None,
                version_range: None,
                configuration: config.to_string(),
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

    fn make_uri() -> Uri {
        Uri::from_file_path("/project/build.gradle.kts").unwrap()
    }

    #[test]
    fn test_parse_simple_kotlin() {
        let content = r#"dependencies {
    implementation("org.springframework.boot:spring-boot-starter:3.2.0")
    testImplementation("junit:junit:4.13.2")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let spring = &result.dependencies[0];
        assert_eq!(spring.name, "org.springframework.boot:spring-boot-starter");
        assert_eq!(spring.version_req, Some("3.2.0".into()));
        assert_eq!(spring.configuration, "implementation");

        let junit = &result.dependencies[1];
        assert_eq!(junit.name, "junit:junit");
        assert_eq!(junit.configuration, "testImplementation");
    }

    #[test]
    fn test_parse_no_version() {
        let content = r#"dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_ignore_non_dependency_configurations() {
        let content = r#"dependencies {
    implementation("a:b:1.0")
    unknown("c:d:2.0")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "a:b");
    }

    #[test]
    fn test_parse_multiple_configurations() {
        let content = r#"dependencies {
    api("com.google.guava:guava:33.0.0-jre")
    compileOnly("org.projectlombok:lombok:1.18.30")
    runtimeOnly("mysql:mysql-connector-java:8.0.33")
    kapt("com.google.dagger:dagger-compiler:2.51")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);
        assert_eq!(result.dependencies[0].configuration, "api");
        assert_eq!(result.dependencies[1].configuration, "compileOnly");
        assert_eq!(result.dependencies[2].configuration, "runtimeOnly");
        assert_eq!(result.dependencies[3].configuration, "kapt");
    }

    #[test]
    fn test_empty_dependencies_block() {
        let content = "dependencies {\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_no_dependencies_block() {
        let content = "plugins {\n    id(\"java\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = "dependencies {\n    implementation(\"com.example:lib:1.0.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        // name_range should be on line 1
        assert_eq!(dep.name_range.start.line, 1);
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 1);
    }
}

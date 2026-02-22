//! Parser for Gradle Groovy DSL (build.gradle).
//!
//! Regex-based extraction of dependency declarations from dependencies { } blocks.

use crate::error::Result;
use crate::parser::{GradleParseResult, find_name_range, find_version_range};
use crate::types::GradleDependency;
use regex::Regex;
use std::sync::OnceLock;
use tower_lsp_server::ls_types::Uri;

/// Matches: implementation('group:artifact:version') or implementation("group:artifact:version")
static RE_WITH_PARENS: OnceLock<Regex> = OnceLock::new();
/// Matches: implementation 'group:artifact:version' or implementation "group:artifact:version"
static RE_WITHOUT_PARENS: OnceLock<Regex> = OnceLock::new();
/// Matches: implementation 'group:artifact' or implementation "group:artifact" (no version)
static RE_NO_VERSION_WITHOUT_PARENS: OnceLock<Regex> = OnceLock::new();
/// Matches: implementation('group:artifact') (no version, with parens)
static RE_NO_VERSION_WITH_PARENS: OnceLock<Regex> = OnceLock::new();

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
    "compile",
    "testCompile",
    "provided",
];

fn re_with_parens() -> &'static Regex {
    RE_WITH_PARENS.get_or_init(|| {
        Regex::new(r#"(\w+)\(\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)"#).unwrap()
    })
}

fn re_without_parens() -> &'static Regex {
    RE_WITHOUT_PARENS
        .get_or_init(|| Regex::new(r#"(\w+)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]"#).unwrap())
}

fn re_no_version_without_parens() -> &'static Regex {
    RE_NO_VERSION_WITHOUT_PARENS
        .get_or_init(|| Regex::new(r#"(\w+)\s+['"]([^:'"]+):([^:'"]+)['"]"#).unwrap())
}

fn re_no_version_with_parens() -> &'static Regex {
    RE_NO_VERSION_WITH_PARENS
        .get_or_init(|| Regex::new(r#"(\w+)\(\s*['"]([^:'"]+):([^:'"]+)['"]\s*\)"#).unwrap())
}

pub fn parse_groovy_dsl(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();

    let mut brace_depth: i32 = 0;
    let mut in_dependencies_block = false;
    let mut deps_brace_depth: i32 = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if !in_dependencies_block
            && (trimmed == "dependencies {" || trimmed.starts_with("dependencies {"))
        {
            in_dependencies_block = true;
            deps_brace_depth = brace_depth + 1;
        }

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
        let mut matched_positions: Vec<usize> = Vec::new();

        // Pattern 1: with parens and version
        for caps in re_with_parens().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }
            let start = caps.get(0).map_or(0, |m| m.start());
            matched_positions.push(start);

            let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
            let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
            let version = caps.get(4).map_or("", |m| m.as_str()).trim().to_string();
            let name = format!("{group_id}:{artifact_id}");

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

        // Pattern 2: without parens and with version
        for caps in re_without_parens().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }
            let start = caps.get(0).map_or(0, |m| m.start());
            if matched_positions.contains(&start) {
                continue;
            }
            matched_positions.push(start);

            let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
            let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
            let version = caps.get(4).map_or("", |m| m.as_str()).trim().to_string();
            let name = format!("{group_id}:{artifact_id}");

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

        // Pattern 3: with parens, no version
        for caps in re_no_version_with_parens().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }
            let start = caps.get(0).map_or(0, |m| m.start());
            if matched_positions.contains(&start) {
                continue;
            }
            matched_positions.push(start);

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

        // Pattern 4: without parens, no version
        for caps in re_no_version_without_parens().captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !CONFIGURATIONS.contains(&config) {
                continue;
            }
            let start = caps.get(0).map_or(0, |m| m.start());
            if matched_positions.contains(&start) {
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
        Uri::from_file_path("/project/build.gradle").unwrap()
    }

    #[test]
    fn test_parse_single_quotes() {
        let content = "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-starter"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_parse_double_quotes() {
        let content =
            "dependencies {\n    implementation \"com.google.guava:guava:33.0.0-jre\"\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "com.google.guava:guava");
        assert_eq!(
            result.dependencies[0].version_req,
            Some("33.0.0-jre".into())
        );
    }

    #[test]
    fn test_parse_with_parens() {
        let content = "dependencies {\n    implementation('junit:junit:4.13.2')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
    }

    #[test]
    fn test_parse_multiple_configurations() {
        let content = "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'\n    testImplementation 'junit:junit:4.13.2'\n    compileOnly 'org.projectlombok:lombok:1.18.30'\n    runtimeOnly 'mysql:mysql-connector-java:8.0.33'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);
        assert_eq!(result.dependencies[1].configuration, "testImplementation");
        assert_eq!(result.dependencies[2].configuration, "compileOnly");
    }

    #[test]
    fn test_ignore_unknown_configurations() {
        let content = "dependencies {\n    implementation 'a:b:1.0'\n    unknown 'c:d:2.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_parse_no_version() {
        let content = "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_empty_block() {
        let content = "dependencies {\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = "dependencies {\n    implementation 'com.example:lib:1.0.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name_range.start.line, 1);
        assert!(dep.version_range.is_some());
    }

    #[test]
    fn test_no_dependencies_block() {
        let content = "apply plugin: 'java'\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }
}

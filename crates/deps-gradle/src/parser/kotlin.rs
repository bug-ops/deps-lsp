//! Parser for Gradle Kotlin DSL (build.gradle.kts).
//!
//! Regex-based extraction of dependency declarations from dependencies { } blocks.

use crate::parser::{
    GradleParseResult, build_dependency, is_dependency_configuration, opens_dependencies_block,
};
use deps_core::Result;
use regex::Regex;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

/// Matches: implementation("group:artifact:version")
/// (optional whitespace between the configuration word and the opening paren)
static RE_WITH_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*"([^:"\s]+):([^:"\s]+):([^"]+)"\s*\)"#).expect("RE_WITH_VERSION")
});
/// Matches: implementation("group:artifact") — no version
/// (optional whitespace between the configuration word and the opening paren)
static RE_NO_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*"([^:"\s]+):([^:"\s]+)"\s*\)"#).expect("RE_NO_VERSION")
});
/// Matches: implementation(platform("group:artifact:version")) / enforcedPlatform(...)
static RE_PLATFORM_WITH_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*"([^:"\s]+):([^:"\s]+):([^"]+)"\s*\)\s*\)"#)
        .expect("RE_PLATFORM_WITH_VERSION")
});
/// Matches: implementation(platform("group:artifact")) — no version
static RE_PLATFORM_NO_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*"([^:"\s]+):([^:"\s]+)"\s*\)\s*\)"#,
    )
    .expect("RE_PLATFORM_NO_VERSION")
});

pub fn parse_kotlin_dsl(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();

    // Track brace depth to detect dependencies { } block
    let mut brace_depth: i32 = 0;
    let mut in_dependencies_block = false;
    let mut deps_brace_depth: i32 = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Detect entry into dependencies { block
        if !in_dependencies_block && opens_dependencies_block(trimmed) {
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

        if !in_dependencies_block && !opens_dependencies_block(trimmed) {
            continue;
        }

        let line_u32 = line_idx as u32;

        // Try pattern with version first
        for caps in RE_WITH_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            dependencies.push(build_dependency(&caps, line, line_u32, true, config));
        }

        // Try pattern without version (only if no versioned match on this line)
        // Avoid double-matching lines that were already caught above
        let already_matched: Vec<_> = RE_WITH_VERSION
            .captures_iter(line)
            .filter_map(|c| {
                let config = c.get(1)?.as_str();
                is_dependency_configuration(config).then_some(c.get(0)?.start())
            })
            .collect();

        for caps in RE_NO_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            // Skip if this match overlaps with a versioned match
            let match_start = caps.get(0).map_or(0, |m| m.start());
            if already_matched.contains(&match_start) {
                continue;
            }
            dependencies.push(build_dependency(&caps, line, line_u32, false, config));
        }

        // Same as above, for platform()/enforcedPlatform()-wrapped BOM coordinates
        let already_matched_platform: Vec<_> = RE_PLATFORM_WITH_VERSION
            .captures_iter(line)
            .filter_map(|c| {
                let config = c.get(1)?.as_str();
                is_dependency_configuration(config).then_some(c.get(0)?.start())
            })
            .collect();

        for caps in RE_PLATFORM_WITH_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            dependencies.push(build_dependency(&caps, line, line_u32, true, config));
        }

        for caps in RE_PLATFORM_NO_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            let match_start = caps.get(0).map_or(0, |m| m.start());
            if already_matched_platform.contains(&match_start) {
                continue;
            }
            dependencies.push(build_dependency(&caps, line, line_u32, false, config));
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
        deps_core::test_util::test_uri("/project/build.gradle.kts")
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
    fn test_parse_bare_annotation_processor() {
        // Bare (no variant prefix) form of a CONFIGURATION_SUFFIXES entry.
        let content = "dependencies {\n    annotationProcessor(\"com.example:foo:1.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "annotationProcessor");
    }

    #[test]
    fn test_parse_legacy_configurations() {
        // Kotlin DSL scripts migrated from (or targeting) pre-Gradle-7 builds
        // can still use the legacy `compile`/`testCompile`/`provided` words —
        // Gradle parses them regardless of DSL, so they must be recognized
        // here just as they are in groovy.rs.
        let content = r#"dependencies {
    compile("org.springframework.boot:spring-boot-starter:3.2.0")
    testCompile("junit:junit:4.13.2")
    provided("javax.servlet:javax.servlet-api:4.0.1")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_eq!(result.dependencies[0].configuration, "compile");
        assert_eq!(result.dependencies[1].configuration, "testCompile");
        assert_eq!(result.dependencies[2].configuration, "provided");
    }

    #[test]
    fn test_parse_legacy_configuration_no_version() {
        let content = "dependencies {\n    provided(\"javax.servlet:javax.servlet-api\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "provided");
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_parse_legacy_configuration_platform() {
        let content = "dependencies {\n    compile(platform(\"org.springframework.boot:spring-boot-dependencies:3.2.0\"))\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "compile");
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
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
    fn test_parse_with_parens_whitespace_no_version() {
        let content = "dependencies {\n    implementation (\"junit:junit\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_parse_with_parens_whitespace_with_version() {
        let content = "dependencies {\n    implementation (\"junit:junit:4.13.2\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert_eq!(result.dependencies[0].version_req, Some("4.13.2".into()));
    }

    #[test]
    fn test_parse_with_parens_multiple_spaces_and_tab() {
        let content = "dependencies {\n    implementation   (\"junit:junit:4.13.2\")\n    api\t(\"a:b:1.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert_eq!(result.dependencies[1].name, "a:b");
    }

    #[test]
    fn test_parse_test_implementation_with_parens_whitespace() {
        let content = "dependencies {\n    testImplementation (\"junit:junit:4.13.2\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "testImplementation");
    }

    #[test]
    fn test_parens_whitespace_no_false_positive_on_nested_calls() {
        // platform()/enforcedPlatform() BOM wrappers are surfaced as dependencies.
        // Other nested-call forms (project/module refs, catalog accessors) are not
        // plain "group:artifact[:version]" string literals, so they must stay
        // unparsed even with whitespace before the parens.
        let content = r#"dependencies {
    implementation (platform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
    implementation (project(":core"))
    implementation (libs.junit)
    implementation (kotlin("stdlib"))
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_platform_with_version() {
        let content = r#"dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
        assert_eq!(result.dependencies[0].configuration, "implementation");
    }

    #[test]
    fn test_platform_no_version() {
        let content = r#"dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies"))
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_enforced_platform_with_version() {
        let content = r#"dependencies {
    implementation(enforcedPlatform("org.springframework.boot:spring-boot-dependencies:3.2.0"))
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_platform_whitespace_before_parens() {
        let content =
            "dependencies {\n    implementation (platform(\"junit:junit-bom:5.10.0\"))\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit-bom");
        assert_eq!(result.dependencies[0].version_req, Some("5.10.0".into()));
    }

    #[test]
    fn test_parse_modern_configurations() {
        // #627: androidTestImplementation, debugImplementation, compileOnlyApi,
        // and testFixturesImplementation were missing from the whitelist and
        // parsed to zero results.
        let content = r#"dependencies {
    androidTestImplementation("a:b:1.0")
    debugImplementation("c:d:2.0")
    compileOnlyApi("e:f:3.0")
    testFixturesImplementation("g:h:4.0")
}
"#;
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 4);
        assert_eq!(
            result.dependencies[0].configuration,
            "androidTestImplementation"
        );
        assert_eq!(result.dependencies[1].configuration, "debugImplementation");
        assert_eq!(result.dependencies[2].configuration, "compileOnlyApi");
        assert_eq!(
            result.dependencies[3].configuration,
            "testFixturesImplementation"
        );
    }

    #[test]
    fn test_same_line_dependencies_distinct_version_ranges() {
        // #628: three dependencies sharing an identical version string on
        // one line must each resolve to their own position, not collapse to
        // the first dependency's position.
        let content = "dependencies {\n    implementation(\"com.example:foo:1.0.0\"); implementation(\"com.example:bar:1.0.0\"); implementation(\"com.example:baz:1.0.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        let ranges: Vec<_> = result
            .dependencies
            .iter()
            .map(|d| d.version_range.expect("version_range"))
            .collect();
        assert_ne!(ranges[0], ranges[1]);
        assert_ne!(ranges[1], ranges[2]);
        assert_ne!(ranges[0], ranges[2]);
        assert!(ranges[1].start.character > ranges[0].start.character);
        assert!(ranges[2].start.character > ranges[1].start.character);
    }

    #[test]
    fn test_same_line_duplicate_coordinate_distinct_name_ranges() {
        // Regression for the S1 gap found in review of #628: two
        // dependencies with an *identical coordinate* (not just the same
        // version) on one line must each get their own name_range, since
        // name_range uniquely keys OSV/diagnostic lookups.
        let content = "dependencies {\n    implementation(\"com.example:lib:1.0.0\"); testImplementation(\"com.example:lib:1.0.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        let first = result.dependencies[0].name_range;
        let second = result.dependencies[1].name_range;
        assert_ne!(first, second);
        assert!(second.start.character > first.start.character);
    }

    #[test]
    fn test_dependencies_info_block_not_scanned() {
        // #629: `dependenciesInfo { }` (Android Gradle Plugin block) must not
        // be mistaken for the `dependencies { }` block due to a prefix match.
        // The dependency call must be on the SAME line as the block opener —
        // a multi-line form doesn't discriminate old vs. new guard code,
        // since the old guard only checked the continuation line's prefix.
        let content = "dependenciesInfo { compile(\"com.example:foo:1.0.0\") }\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_dependencies_block_tolerates_extra_whitespace_before_brace() {
        // S2: the block-open guard must not regress `dependencies` followed
        // by more than one space/tab before `{`.
        let content = "dependencies  {\n    implementation(\"a:b:1.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let content_tab = "dependencies\t{\n    implementation(\"a:b:1.0\")\n}\n";
        let result_tab = parse_kotlin_dsl(content_tab, &make_uri()).unwrap();
        assert_eq!(result_tab.dependencies.len(), 1);
    }

    #[test]
    fn test_parse_kapt_ksp_prefix_variants() {
        // S3: kapt/ksp follow a prefix convention (word + capitalized
        // variant), not the suffix convention used by Implementation/Api.
        let content = "dependencies {\n    kaptTest(\"a:b:1.0\")\n    kaptAndroidTest(\"c:d:2.0\")\n    kspDebug(\"e:f:3.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_eq!(result.dependencies[0].configuration, "kaptTest");
        assert_eq!(result.dependencies[1].configuration, "kaptAndroidTest");
        assert_eq!(result.dependencies[2].configuration, "kspDebug");
    }

    #[test]
    fn test_suffix_matching_accepts_near_miss_configuration_name() {
        // Documents a known, accepted tradeoff of suffix-based matching
        // (#627): a name ending in a recognized suffix is treated as a
        // dependency configuration even if it isn't a real Gradle one. Risk
        // is bounded — a coordinate-shaped string literal is still required,
        // and Gradle itself would reject an actually-unknown configuration.
        let content = "dependencies {\n    someRandomApi(\"a:b:1.0\")\n}\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "someRandomApi");
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

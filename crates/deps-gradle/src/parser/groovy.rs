//! Parser for Gradle Groovy DSL (build.gradle).
//!
//! Regex-based extraction of dependency declarations from dependencies { } blocks.

use crate::parser::{
    GradleParseResult, build_dependency, is_dependency_configuration, opens_dependencies_block,
};
use crate::types::GradleDependency;
use deps_core::Result;
use regex::Regex;
use std::sync::LazyLock;
use tower_lsp_server::ls_types::Uri;

/// Matches: implementation('group:artifact:version') or implementation("group:artifact:version")
/// (optional whitespace between the configuration word and the opening paren)
static RE_WITH_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)"#).expect("RE_WITH_PARENS")
});
/// Matches: implementation 'group:artifact:version' or implementation "group:artifact:version"
static RE_WITHOUT_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]"#).expect("RE_WITHOUT_PARENS")
});
/// Matches: implementation 'group:artifact' or implementation "group:artifact" (no version)
static RE_NO_VERSION_WITHOUT_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s+['"]([^:'"]+):([^:'"]+)['"]"#).expect("RE_NO_VERSION_WITHOUT_PARENS")
});
/// Matches: implementation('group:artifact') (no version, with parens)
/// (optional whitespace between the configuration word and the opening paren)
static RE_NO_VERSION_WITH_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*['"]([^:'"]+):([^:'"]+)['"]\s*\)"#)
        .expect("RE_NO_VERSION_WITH_PARENS")
});
/// Matches: implementation(platform('group:artifact:version')) / enforcedPlatform(...)
static RE_PLATFORM_WITH_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)\s*\)"#,
    )
    .expect("RE_PLATFORM_WITH_PARENS")
});
/// Matches: implementation platform('group:artifact:version') (no parens around the configuration call)
static RE_PLATFORM_WITHOUT_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(\w+)\s+(?:platform|enforcedPlatform)\s*\(\s*['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\s*\)"#,
    )
    .expect("RE_PLATFORM_WITHOUT_PARENS")
});
/// Same as RE_PLATFORM_WITH_PARENS, no version
static RE_PLATFORM_NO_VERSION_WITH_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*['"]([^:'"]+):([^:'"]+)['"]\s*\)\s*\)"#)
        .expect("RE_PLATFORM_NO_VERSION_WITH_PARENS")
});
/// Same as RE_PLATFORM_WITHOUT_PARENS, no version
static RE_PLATFORM_NO_VERSION_WITHOUT_PARENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s+(?:platform|enforcedPlatform)\s*\(\s*['"]([^:'"]+):([^:'"]+)['"]\s*\)"#)
        .expect("RE_PLATFORM_NO_VERSION_WITHOUT_PARENS")
});

/// Runs `re` over `line`, filters matches to known dependency configurations, dedups
/// against `matched_positions` (shared across all patterns tried on this
/// line), and pushes a [`GradleDependency`] for each surviving match.
///
/// All eight Groovy DSL regex variants (with/without parens, with/without
/// version, plain/platform-wrapped) share identical capture group indices —
/// 1: configuration, 2: group id, 3: artifact id, 4: version (when present) —
/// so `has_version` alone distinguishes the two capture shapes.
fn extract_matches(
    re: &Regex,
    line: &str,
    line_u32: u32,
    has_version: bool,
    matched_positions: &mut Vec<usize>,
    dependencies: &mut Vec<GradleDependency>,
) {
    for caps in re.captures_iter(line) {
        let config = caps.get(1).map_or("", |m| m.as_str());
        if !is_dependency_configuration(config) {
            continue;
        }
        let start = caps.get(0).map_or(0, |m| m.start());
        if matched_positions.contains(&start) {
            continue;
        }
        matched_positions.push(start);

        dependencies.push(build_dependency(&caps, line, line_u32, has_version, config));
    }
}

pub fn parse_groovy_dsl(content: &str, uri: &Uri) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();

    let mut brace_depth: i32 = 0;
    let mut in_dependencies_block = false;
    let mut deps_brace_depth: i32 = 0;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        if !in_dependencies_block && opens_dependencies_block(trimmed) {
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

        if !in_dependencies_block && !opens_dependencies_block(trimmed) {
            continue;
        }

        let line_u32 = line_idx as u32;
        let mut matched_positions: Vec<usize> = Vec::new();

        // Pattern 1: with parens and version
        extract_matches(
            &RE_WITH_PARENS,
            line,
            line_u32,
            true,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 2: without parens and with version
        extract_matches(
            &RE_WITHOUT_PARENS,
            line,
            line_u32,
            true,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 3: with parens, no version
        extract_matches(
            &RE_NO_VERSION_WITH_PARENS,
            line,
            line_u32,
            false,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 4: without parens, no version
        extract_matches(
            &RE_NO_VERSION_WITHOUT_PARENS,
            line,
            line_u32,
            false,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 5: platform()/enforcedPlatform()-wrapped BOM coordinate, with parens, with version
        extract_matches(
            &RE_PLATFORM_WITH_PARENS,
            line,
            line_u32,
            true,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 6: same, without parens around the configuration call
        extract_matches(
            &RE_PLATFORM_WITHOUT_PARENS,
            line,
            line_u32,
            true,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 7: platform()/enforcedPlatform()-wrapped BOM coordinate, with parens, no version
        extract_matches(
            &RE_PLATFORM_NO_VERSION_WITH_PARENS,
            line,
            line_u32,
            false,
            &mut matched_positions,
            &mut dependencies,
        );

        // Pattern 8: same, without parens around the configuration call
        extract_matches(
            &RE_PLATFORM_NO_VERSION_WITHOUT_PARENS,
            line,
            line_u32,
            false,
            &mut matched_positions,
            &mut dependencies,
        );
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
        deps_core::test_util::test_uri("/project/build.gradle")
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
    fn test_parse_bare_annotation_processor() {
        // Bare (no variant prefix) form of a CONFIGURATION_SUFFIXES entry.
        let content = "dependencies {\n    annotationProcessor 'com.example:foo:1.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "annotationProcessor");
    }

    #[test]
    fn test_parse_legacy_configurations() {
        // compile/testCompile/provided predate #625's unification but were
        // never covered by a dedicated test; guard the shared CONFIGURATIONS
        // list now that both DSLs read from it.
        let content = "dependencies {\n    compile 'org.springframework.boot:spring-boot-starter:3.2.0'\n    testCompile 'junit:junit:4.13.2'\n    provided 'javax.servlet:javax.servlet-api:4.0.1'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 3);
        assert_eq!(result.dependencies[0].configuration, "compile");
        assert_eq!(result.dependencies[1].configuration, "testCompile");
        assert_eq!(result.dependencies[2].configuration, "provided");
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
    fn test_parse_no_version_with_parens() {
        let content = "dependencies {\n    implementation('com.example:lib')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name, "com.example:lib");
        assert!(dep.version_req.is_none());
        assert!(dep.version_range.is_none());
        assert_eq!(dep.name_range.start.line, 1);
        assert_eq!(dep.name_range.start.character, 20);
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

    #[test]
    fn test_parse_with_parens_whitespace_no_version() {
        let content = "dependencies {\n    implementation ('junit:junit')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_parse_with_parens_whitespace_with_version() {
        let content = "dependencies {\n    implementation ('junit:junit:4.13.2')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "junit:junit");
        assert_eq!(result.dependencies[0].version_req, Some("4.13.2".into()));
    }

    #[test]
    fn test_platform_bare_call_with_version() {
        let content = "dependencies {\n    implementation platform('org.springframework.boot:spring-boot-dependencies:3.2.0')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
        assert_eq!(result.dependencies[0].configuration, "implementation");
    }

    #[test]
    fn test_platform_with_parens_with_version() {
        let content = "dependencies {\n    implementation(platform('org.springframework.boot:spring-boot-dependencies:3.2.0'))\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_enforced_platform_bare_call() {
        let content = "dependencies {\n    implementation enforcedPlatform('org.springframework.boot:spring-boot-dependencies:3.2.0')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }

    #[test]
    fn test_platform_no_version_with_parens() {
        let content = "dependencies {\n    implementation(platform('org.springframework.boot:spring-boot-dependencies'))\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_platform_no_version_bare_call() {
        let content = "dependencies {\n    implementation platform('org.springframework.boot:spring-boot-dependencies')\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_parse_modern_configurations() {
        // #627: androidTestImplementation, debugImplementation, compileOnlyApi,
        // and testFixturesImplementation were missing from the whitelist and
        // parsed to zero results.
        let content = "dependencies {\n    androidTestImplementation 'a:b:1.0'\n    debugImplementation 'c:d:2.0'\n    compileOnlyApi 'e:f:3.0'\n    testFixturesImplementation 'g:h:4.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
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
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
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
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
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
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_dependencies_block_tolerates_extra_whitespace_before_brace() {
        // S2: the block-open guard must not regress `dependencies` followed
        // by more than one space/tab before `{`.
        let content = "dependencies  {\n    implementation 'a:b:1.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);

        let content_tab = "dependencies\t{\n    implementation 'a:b:1.0'\n}\n";
        let result_tab = parse_groovy_dsl(content_tab, &make_uri()).unwrap();
        assert_eq!(result_tab.dependencies.len(), 1);
    }

    #[test]
    fn test_parse_kapt_ksp_prefix_variants() {
        // S3: kapt/ksp follow a prefix convention (word + capitalized
        // variant), not the suffix convention used by Implementation/Api.
        let content = "dependencies {\n    kaptTest 'a:b:1.0'\n    kaptAndroidTest 'c:d:2.0'\n    kspDebug 'e:f:3.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
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
        let content = "dependencies {\n    someRandomApi 'a:b:1.0'\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].configuration, "someRandomApi");
    }

    #[test]
    fn test_platform_double_quotes() {
        let content = "dependencies {\n    implementation platform(\"org.springframework.boot:spring-boot-dependencies:3.2.0\")\n}\n";
        let result = parse_groovy_dsl(content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(
            result.dependencies[0].name,
            "org.springframework.boot:spring-boot-dependencies"
        );
        assert_eq!(result.dependencies[0].version_req, Some("3.2.0".into()));
    }
}

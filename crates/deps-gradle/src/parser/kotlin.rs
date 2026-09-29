//! Parser for Gradle Kotlin DSL (build.gradle.kts).
//!
//! Regex-based extraction of dependency declarations from dependencies { } blocks.

use crate::parser::{
    GradleParseResult, LineOffsetTable, SourceLine, build_dependency, is_dependency_configuration,
    opens_dependencies_block,
};
use deps_core::Result;
use regex::Regex;
use std::sync::LazyLock;
use url::Url;

/// Matches: implementation("group:artifact:version")
/// (optional whitespace between the configuration word and the opening paren)
// Compile-time-constant pattern; a malformed literal is a build-visible programmer error,
// not attacker-influenceable input.
#[allow(clippy::expect_used)]
static RE_WITH_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*"([^:"\s]+):([^:"\s]+):([^"]+)"\s*\)"#).expect("RE_WITH_VERSION")
});
/// Matches: implementation("group:artifact") — no version
/// (optional whitespace between the configuration word and the opening paren)
// Same guarantee as RE_WITH_VERSION above.
#[allow(clippy::expect_used)]
static RE_NO_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*"([^:"\s]+):([^:"\s]+)"\s*\)"#).expect("RE_NO_VERSION")
});
/// Matches: implementation(platform("group:artifact:version")) / enforcedPlatform(...)
// Same guarantee as RE_WITH_VERSION above.
#[allow(clippy::expect_used)]
static RE_PLATFORM_WITH_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*"([^:"\s]+):([^:"\s]+):([^"]+)"\s*\)\s*\)"#)
        .expect("RE_PLATFORM_WITH_VERSION")
});
/// Matches: implementation(platform("group:artifact")) — no version
// Same guarantee as RE_WITH_VERSION above.
#[allow(clippy::expect_used)]
static RE_PLATFORM_NO_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(\w+)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*"([^:"\s]+):([^:"\s]+)"\s*\)\s*\)"#,
    )
    .expect("RE_PLATFORM_NO_VERSION")
});

/// Start offsets (as unit spans) of dependency-configuration matches of `re` on `line`.
fn claimed_starts(re: &Regex, line: &str) -> deps_core::MatchedSpans {
    let mut spans = deps_core::MatchedSpans::default();
    for caps in re.captures_iter(line) {
        let is_dependency = caps
            .get(1)
            .is_some_and(|config| is_dependency_configuration(config.as_str()));
        if let (true, Some(m)) = (is_dependency, caps.get(0)) {
            spans.insert_point(m.start());
        }
    }
    spans
}

/// Parses a Kotlin-DSL `build.gradle.kts` file into a [`GradleParseResult`].
///
/// Always succeeds: unrecognized lines are simply skipped. Returns [`Result`]
/// only to match the shared parser signature every ecosystem implements.
///
/// # Errors
///
/// Infallible by construction: this function never returns `Err`.
pub fn parse_kotlin_dsl(content: &str, uri: &Url) -> Result<GradleParseResult> {
    let mut dependencies = Vec::new();
    let line_table = LineOffsetTable::new(content);

    let mut brace_depth: i32 = 0;
    let mut in_dependencies_block = false;
    let mut deps_brace_depth: i32 = 0;
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

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

        let src = SourceLine::new(&line_table, content, line_idx, line);

        for caps in RE_WITH_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            if !budget.allow() {
                continue;
            }
            dependencies.push(build_dependency(&caps, &src, true, config));
        }

        // Only match a versionless coordinate if this line has no versioned match already.
        let already_matched = claimed_starts(&RE_WITH_VERSION, line);

        for caps in RE_NO_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            let match_start = caps.get(0).map_or(0, |m| m.start());
            if already_matched.contains_point(match_start) {
                continue;
            }
            if !budget.allow() {
                continue;
            }
            dependencies.push(build_dependency(&caps, &src, false, config));
        }

        // Same as above, for platform()/enforcedPlatform()-wrapped BOM coordinates
        let already_matched_platform = claimed_starts(&RE_PLATFORM_WITH_VERSION, line);

        for caps in RE_PLATFORM_WITH_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            if !budget.allow() {
                continue;
            }
            dependencies.push(build_dependency(&caps, &src, true, config));
        }

        for caps in RE_PLATFORM_NO_VERSION.captures_iter(line) {
            let config = caps.get(1).map_or("", |m| m.as_str());
            if !is_dependency_configuration(config) {
                continue;
            }
            let match_start = caps.get(0).map_or(0, |m| m.start());
            if already_matched_platform.contains_point(match_start) {
                continue;
            }
            if !budget.allow() {
                continue;
            }
            dependencies.push(build_dependency(&caps, &src, false, config));
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

    fn make_uri() -> Url {
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
        assert_eq!(dep.name_range.start.line, 1);
        assert!(dep.version_range.is_some());
        assert_eq!(dep.version_range.unwrap().start.line, 1);
    }

    #[test]
    fn test_versioned_and_versionless_flood_on_one_line_is_linear() {
        let filler = "api(\"g:a:1\")\n".repeat(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
        let flood = r#"api("g:a:1")api("g:a")"#.repeat(100_000);
        let content = format!("dependencies {{\n{filler}{flood}\n}}\n");
        let start = std::time::Instant::now();
        let result = parse_kotlin_dsl(&content, &make_uri()).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(
            result.dependencies.len(),
            deps_core::MAX_DEPENDENCIES_PER_DOCUMENT
        );
    }

    #[test]
    fn test_versionless_after_multibyte_prefix_keeps_utf16_columns() {
        let line = r#"val s = "é😀"; implementation("g:a")"#;
        let content = format!("dependencies {{\n{line}\n}}\n");
        let result = parse_kotlin_dsl(&content, &make_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let byte = line.find("g:a").unwrap();
        let expected = u32::try_from(line.get(..byte).unwrap().encode_utf16().count()).unwrap();
        assert_eq!(result.dependencies[0].name_range.start.character, expected);
    }

    /// #1701: one huge non-ASCII line with thousands of matches must report exact UTF-16
    /// columns (an astral char counts as 2 units, a CJK char as 1).
    #[test]
    fn test_single_long_line_utf16_columns() {
        const N: usize = 5000;
        let filler = "/*\u{1F600}\u{65E5}*/ ";
        let head = "implementation(\"";
        let units = |s: &str| u32::try_from(s.encode_utf16().count()).unwrap();
        let mut line = String::from("dependencies { ");
        let mut expected = Vec::with_capacity(N);
        let mut col = units(&line);
        for i in 0..N {
            let name = format!("g{i}:a{i}");
            let coord = if i % 2 == 0 {
                name.clone()
            } else {
                format!("{name}:1.{i}")
            };
            col += units(filler) + units(head);
            expected.push((col, col + units(&name)));
            col += units(&coord) + 2;
            line.push_str(&format!("{filler}{head}{coord}\")"));
        }
        line.push_str(" }\n");

        let result = parse_kotlin_dsl(&line, &make_uri()).unwrap();

        assert_eq!(result.dependencies.len(), N);
        let mut got: Vec<_> = result
            .dependencies
            .iter()
            .map(|d| (d.name_range.start.character, d.name_range.end.character))
            .collect();
        got.sort_unstable();
        assert_eq!(got, expected);
    }

    /// Mixed ASCII / non-ASCII / CRLF lines each get columns relative to their own line.
    #[test]
    fn test_mixed_ascii_and_non_ascii_lines() {
        let content = "dependencies {\r\n    implementation(\"a:b:1\")\r\n    /*\u{1F600}*/ implementation(\"c:d:2\")\r\n    implementation(\"e:f:3\")\r\n}\r\n";
        let result = parse_kotlin_dsl(content, &make_uri()).unwrap();
        let got: Vec<_> = result
            .dependencies
            .iter()
            .map(|d| {
                let v = d.version_range.unwrap();
                (
                    d.name_range.start.line,
                    d.name_range.start.character,
                    v.start.character,
                )
            })
            .collect();
        assert_eq!(got, [(1, 20, 24), (2, 27, 31), (3, 20, 24)]);
    }
}

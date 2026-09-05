//! Gradle manifest parser dispatcher.
//!
//! Routes parsing to the appropriate module based on file extension/name.

pub mod catalog;
pub mod groovy;
pub mod kotlin;
pub mod properties;
pub mod settings;

use crate::types::GradleDependency;
use deps_core::Result;
use regex::Captures;
use std::any::Any;
use std::collections::HashMap;
use tower_lsp_server::ls_types::{Position, Range, Uri};

pub use deps_core::lsp_helpers::LineOffsetTable;

/// Configuration words that follow neither the suffix convention
/// ([`CONFIGURATION_SUFFIXES`]) nor the prefix convention
/// ([`CONFIGURATION_PREFIXES`]) and must be matched literally.
///
/// Includes the pre-Gradle-7 legacy configurations `compile`, `testCompile`,
/// and `provided`: Gradle still parses them regardless of which DSL a build
/// script uses, so a `build.gradle.kts` migrated from an old `build.gradle`
/// (or targeting a project not yet updated) can legitimately contain them.
/// Restricting recognition to one DSL would be silent drift, not an
/// intentional scoping decision. `classpath` has no variant form at all.
const CONFIGURATION_LITERALS: &[&str] = &["classpath", "compile", "testCompile", "provided"];

/// `(bare, suffix)` pairs for configuration base words that Gradle core
/// plugins (`java`, `java-library`) and common first-party plugins (Android
/// Gradle Plugin, `java-test-fixtures`) combine with an arbitrary
/// variant/source-set prefix, e.g. `debugImplementation`,
/// `androidTestImplementation`, `testFixturesImplementation` — and
/// `compileOnlyApi`, matched by the `Api` suffix.
///
/// `bare` is the word used with no prefix (`implementation`); `suffix` is the
/// same word capitalized, as it appears after a prefix. A literal whitelist
/// can't keep up with plugin-registered configurations following this
/// convention (arbitrary build types/flavors in Android, custom source
/// sets), so membership is decided by suffix instead — safe because Gradle
/// itself treats any name ending in one of these words as that kind of
/// configuration.
const CONFIGURATION_SUFFIXES: &[(&str, &str)] = &[
    ("implementation", "Implementation"),
    ("api", "Api"),
    ("compileOnly", "CompileOnly"),
    ("runtimeOnly", "RuntimeOnly"),
    ("annotationProcessor", "AnnotationProcessor"),
];

/// Kotlin annotation-processing plugin configurations (`kapt`, KSP's `ksp`)
/// follow a *prefix* convention instead: bare for the main source set, or
/// `<word><Variant>` for others — e.g. `kaptTest`, `kaptAndroidTest`,
/// `kspDebug`, `kspCommonMainMetadata`. [`CONFIGURATION_SUFFIXES`] can't
/// express this since the variant comes after the word, not before it.
const CONFIGURATION_PREFIXES: &[&str] = &["kapt", "ksp"];

/// Returns whether `config` is a recognized Gradle dependency configuration
/// word: a legacy literal ([`CONFIGURATION_LITERALS`]), a name ending in one
/// of [`CONFIGURATION_SUFFIXES`]'s base words, or a name starting with one of
/// [`CONFIGURATION_PREFIXES`]'s words followed by a capitalized variant.
pub(crate) fn is_dependency_configuration(config: &str) -> bool {
    CONFIGURATION_LITERALS.contains(&config)
        || CONFIGURATION_SUFFIXES
            .iter()
            .any(|(bare, suffix)| config == *bare || config.ends_with(suffix))
        || CONFIGURATION_PREFIXES.iter().any(|prefix| {
            config == *prefix
                || config
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
        })
}

/// Returns whether `trimmed` (a line with surrounding whitespace stripped)
/// opens a Gradle `dependencies { }` block.
///
/// Requires the brace to follow the `dependencies` keyword (any amount of
/// whitespace, including none, in between) so that unrelated blocks whose
/// name merely starts with the word — e.g. Android's `dependenciesInfo { }`
/// — aren't mistaken for it.
pub(crate) fn opens_dependencies_block(trimmed: &str) -> bool {
    trimmed
        .strip_prefix("dependencies")
        .is_some_and(|rest| rest.trim_start().starts_with('{'))
}

/// Builds a [`GradleDependency`] from a regex match's captures.
///
/// All Groovy and Kotlin DSL regex variants share identical capture group
/// indices — 1: configuration, 2: group id, 3: artifact id, 4: version (when
/// present) — so `has_version` alone distinguishes the two capture shapes.
pub(crate) fn build_dependency(
    caps: &Captures<'_>,
    line: &str,
    line_idx: u32,
    has_version: bool,
    config: &str,
) -> GradleDependency {
    debug_assert_eq!(
        caps.len(),
        if has_version { 5 } else { 4 },
        "regex capture count must match has_version so group 4 (version) is only read when present"
    );

    let match_start = caps.get(0).map_or(0, |m| m.start());
    let group_id = caps.get(2).map_or("", |m| m.as_str()).to_string();
    let artifact_id = caps.get(3).map_or("", |m| m.as_str()).to_string();
    let name = format!("{group_id}:{artifact_id}");
    let name_range = find_name_range(line, line_idx, match_start, &group_id, &artifact_id);

    let (version_req, version_range) = if has_version {
        let version = caps.get(4).map_or("", |m| m.as_str()).trim().to_string();
        let version_range = find_version_range(line, line_idx, match_start, &version);
        (Some(version.into()), Some(version_range))
    } else {
        (None, None)
    };

    GradleDependency {
        group_id,
        artifact_id,
        name: name.into(),
        name_range,
        version_req,
        version_range,
        configuration: config.to_string(),
    }
}

#[derive(Debug)]
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
            && let Some(resolved) = resolve_variable_ref(ver.as_str(), properties)
        {
            dep.version_req = Some(resolved.into());
        }
    }
}

/// Returns the resolved value if `value` is a `$name` or `${name}` reference. Returns `None` otherwise.
fn resolve_variable_ref(value: &str, properties: &HashMap<String, String>) -> Option<String> {
    let trimmed = value.trim();
    if let Some(name) = trimmed.strip_circumfix("${", '}') {
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

/// Finds the LSP range of `"group_id:artifact_id"` within the dependency
/// declaration's own match span (`line[match_start..]`), not the whole line.
///
/// Scoping to `match_start` matters when two dependencies share an identical
/// coordinate on one line — e.g.
/// `implementation("a:b:1.0.0"); testImplementation("a:b:1.0.0")` — so the
/// second dependency's range isn't mis-attributed to the first's position.
pub(crate) fn find_name_range(
    line: &str,
    line_idx: u32,
    match_start: usize,
    group_id: &str,
    artifact_id: &str,
) -> Range {
    let scoped = &line[match_start..];
    let search = format!("{group_id}:{artifact_id}");
    if let Some(rel) = scoped.find(&search) {
        let abs_start = match_start + rel;
        let col_u32 = utf16_len(&line[..abs_start]) as u32;
        let end_u32 = col_u32 + utf16_len(&search) as u32;
        Range::new(
            Position::new(line_idx, col_u32),
            Position::new(line_idx, end_u32),
        )
    } else {
        Range::default()
    }
}

/// Finds the LSP range of `version` after the second `:` within the
/// dependency declaration's own match span (`line[match_start..]`), not the
/// whole line.
///
/// Scoping to `match_start` matters when two dependencies share the same
/// version string on one line — e.g.
/// `implementation("a:b:1.0.0"); implementation("c:d:1.0.0")` — so the
/// second dependency's range isn't mis-attributed to the first's position.
pub(crate) fn find_version_range(
    line: &str,
    line_idx: u32,
    match_start: usize,
    version: &str,
) -> Range {
    let scoped = &line[match_start..];
    let second_colon = scoped
        .char_indices()
        .filter(|(_, c)| *c == ':')
        .nth(1)
        .map(|(i, _)| i);

    if let Some(colon_pos) = second_colon {
        let after_colon = &scoped[colon_pos + 1..];
        if let Some(rel) = after_colon.find(version) {
            let abs_start = match_start + colon_pos + 1 + rel;
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
        deps_core::test_util::test_uri(path)
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
        let range = find_name_range(line, 5, 0, "com.example", "lib");
        assert_eq!(range.start.line, 5);
        assert!(range.start.character > 0);
    }

    #[test]
    fn test_find_name_range_scoped_to_match_start() {
        // Two dependencies with an identical coordinate on one line: scoping
        // the search to the second dependency's match_start must not return
        // the first dependency's name_range.
        let line = "implementation(\"a:b:1.0.0\"); testImplementation(\"a:b:1.0.0\")";
        let second_match_start = line.rfind("testImplementation").unwrap();
        let range = find_name_range(line, 0, second_match_start, "a", "b");
        let first_range = find_name_range(line, 0, 0, "a", "b");
        assert_ne!(range.start.character, first_range.start.character);
        assert!(range.start.character > second_match_start as u32);
    }

    #[test]
    fn test_is_dependency_configuration_kapt_ksp_prefix_variants() {
        for config in [
            "kapt",
            "kaptTest",
            "kaptAndroidTest",
            "ksp",
            "kspDebug",
            "kspCommonMainMetadata",
        ] {
            assert!(
                is_dependency_configuration(config),
                "{config} should be recognized"
            );
        }
        // "kaptx" has no capitalized variant boundary after the prefix.
        assert!(!is_dependency_configuration("kaptx"));
    }

    #[test]
    fn test_is_dependency_configuration_suffix_near_miss_is_accepted() {
        // Known, documented tradeoff of suffix-matching: any name ending in
        // a recognized suffix is accepted even if it isn't a real Gradle
        // configuration, since a coordinate-shaped string literal argument
        // is still required and Gradle itself would reject the unknown name.
        assert!(is_dependency_configuration("someRandomApi"));
        assert!(is_dependency_configuration("myOwnImplementation"));
    }

    #[test]
    fn test_opens_dependencies_block_tolerates_extra_whitespace() {
        assert!(opens_dependencies_block("dependencies  {"));
        assert!(opens_dependencies_block("dependencies\t{"));
        assert!(opens_dependencies_block("dependencies {"));
        assert!(opens_dependencies_block("dependencies{"));
        assert!(!opens_dependencies_block("dependenciesInfo {"));
        assert!(!opens_dependencies_block("dependenciesInfo{"));
    }

    #[test]
    fn test_find_version_range() {
        let line = "    implementation(\"com.example:lib:1.0.0\")";
        let range = find_version_range(line, 5, 0, "1.0.0");
        assert_eq!(range.start.line, 5);
        // "1.0.0" is 5 chars, end = start + 5
        assert_eq!(range.end.character - range.start.character, 5);
    }

    #[test]
    fn test_find_version_range_scoped_to_match_start() {
        // Two dependencies sharing the same version on one line: scoping the
        // search to the second dependency's match_start must not return the
        // first dependency's colon/version position.
        let line = "implementation(\"a:b:1.0.0\"); implementation(\"c:d:1.0.0\")";
        let second_match_start = line.rfind("implementation").unwrap();
        let range = find_version_range(line, 0, second_match_start, "1.0.0");
        let first_range = find_version_range(line, 0, 0, "1.0.0");
        assert_ne!(range.start.character, first_range.start.character);
        assert!(range.start.character > second_match_start as u32);
    }

    #[test]
    fn test_utf16_len_ascii() {
        assert_eq!(utf16_len("hello"), 5);
    }
}

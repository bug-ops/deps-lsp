//! Integration tests for deps-gradle parsers using fixture files.

use deps_gradle::parser::{GradleParseResult, parse_gradle};
use tower_lsp_server::ls_types::Uri;

fn make_uri(path: &str) -> Uri {
    Uri::from_file_path(path).unwrap()
}

// --- Version Catalog ---

#[test]
fn test_catalog_fixture() {
    let content = include_str!("fixtures/libs.versions.toml");
    let uri = make_uri("/project/gradle/libs.versions.toml");
    let result = parse_gradle(content, &uri).unwrap();

    // Should parse all library entries except spring-bom (no version)
    assert!(result.dependencies.len() >= 6);

    let spring = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.springframework.boot:spring-boot-starter")
        .expect("spring-boot-starter not found");
    assert_eq!(spring.version_req, Some("3.2.0".into()));
    assert_eq!(spring.group_id, "org.springframework.boot");

    let guava = result
        .dependencies
        .iter()
        .find(|d| d.name == "com.google.guava:guava")
        .expect("guava not found");
    assert_eq!(guava.version_req, Some("33.0.0-jre".into()));

    // group/name format
    let commons = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.apache.commons:commons-lang3")
        .expect("commons-lang3 not found");
    assert_eq!(commons.version_req, Some("3.14.0".into()));

    // inline version
    let jackson = result
        .dependencies
        .iter()
        .find(|d| d.name == "com.fasterxml.jackson.core:jackson-databind")
        .expect("jackson-databind not found");
    assert_eq!(jackson.version_req, Some("2.16.1".into()));
}

#[test]
fn test_catalog_name_ranges_set() {
    let content = include_str!("fixtures/libs.versions.toml");
    let uri = make_uri("/project/gradle/libs.versions.toml");
    let result = parse_gradle(content, &uri).unwrap();

    // All parsed dependencies must have a non-empty name
    for dep in &result.dependencies {
        assert!(!dep.name.is_empty(), "Dependency has empty name");
        assert!(
            !dep.group_id.is_empty() && !dep.artifact_id.is_empty(),
            "Dependency {} has empty group_id or artifact_id",
            dep.name
        );
    }
}

// --- Kotlin DSL ---

#[test]
fn test_kotlin_fixture() {
    let content = include_str!("fixtures/build.gradle.kts");
    let uri = make_uri("/project/build.gradle.kts");
    let result = parse_gradle(content, &uri).unwrap();

    assert!(!result.dependencies.is_empty());

    let spring = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.springframework.boot:spring-boot-starter")
        .expect("spring-boot-starter not found");
    assert_eq!(spring.version_req, Some("3.2.0".into()));
    assert_eq!(spring.configuration, "implementation");

    let guava = result
        .dependencies
        .iter()
        .find(|d| d.name == "com.google.guava:guava")
        .expect("guava not found");
    assert_eq!(guava.configuration, "api");

    let junit = result
        .dependencies
        .iter()
        .find(|d| d.name == "junit:junit")
        .expect("junit not found");
    assert_eq!(junit.configuration, "testImplementation");

    // Entry without version
    let launcher = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.junit.platform:junit-platform-launcher");
    if let Some(dep) = launcher {
        assert!(dep.version_req.is_none());
    }
}

#[test]
fn test_kotlin_position_tracking() {
    let content = include_str!("fixtures/build.gradle.kts");
    let uri = make_uri("/project/build.gradle.kts");
    let result = parse_gradle(content, &uri).unwrap();

    for dep in &result.dependencies {
        if dep.version_req.is_some() {
            assert!(
                dep.version_range.is_some(),
                "Missing version_range for {} with version {:?}",
                dep.name,
                dep.version_req
            );
        }
    }
}

// --- Groovy DSL ---

#[test]
fn test_groovy_fixture() {
    let content = include_str!("fixtures/build.gradle");
    let uri = make_uri("/project/build.gradle");
    let result = parse_gradle(content, &uri).unwrap();

    assert!(!result.dependencies.is_empty());

    let spring = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.springframework.boot:spring-boot-starter")
        .expect("spring-boot-starter not found");
    assert_eq!(spring.version_req, Some("3.2.0".into()));

    let guava = result
        .dependencies
        .iter()
        .find(|d| d.name == "com.google.guava:guava")
        .expect("guava not found");
    assert_eq!(guava.version_req, Some("33.0.0-jre".into()));

    // With parens
    let mockito = result
        .dependencies
        .iter()
        .find(|d| d.name == "org.mockito:mockito-core")
        .expect("mockito-core not found");
    assert_eq!(mockito.version_req, Some("5.8.0".into()));
}

#[test]
fn test_groovy_single_and_double_quotes() {
    let content = "dependencies {\n    implementation 'a:b:1.0'\n    api \"c:d:2.0\"\n}\n";
    let uri = make_uri("/project/build.gradle");
    let result = parse_gradle(content, &uri).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(result.dependencies[0].version_req, Some("1.0".into()));
    assert_eq!(result.dependencies[1].version_req, Some("2.0".into()));
}

#[test]
fn test_groovy_position_tracking() {
    let content = include_str!("fixtures/build.gradle");
    let uri = make_uri("/project/build.gradle");
    let result = parse_gradle(content, &uri).unwrap();

    for dep in &result.dependencies {
        if dep.version_req.is_some() {
            assert!(
                dep.version_range.is_some(),
                "Missing version_range for {} with version {:?}",
                dep.name,
                dep.version_req
            );
        }
    }
}

// --- ParseResult trait ---

#[test]
fn test_parse_result_trait() {
    use deps_core::ParseResult;

    let content = "dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n";
    let uri = make_uri("/project/build.gradle");
    let result = parse_gradle(content, &uri).unwrap();

    assert_eq!(result.dependencies().len(), 1);
    assert!(result.workspace_root().is_none());
    assert_eq!(result.uri(), &uri);
    assert!(result.as_any().is::<GradleParseResult>());
}

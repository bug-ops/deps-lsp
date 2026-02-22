//! Integration tests using fixture files.

use deps_maven::parse_pom_xml;
use tower_lsp_server::ls_types::Uri;

fn fixture_uri(name: &str) -> Uri {
    #[cfg(windows)]
    let path = format!("C:/test/{name}");
    #[cfg(not(windows))]
    let path = format!("/test/{name}");
    Uri::from_file_path(path).unwrap()
}

fn load_fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"))
}

#[test]
fn test_fixture_simple_pom() {
    let content = load_fixture("simple_pom.xml");
    let result = parse_pom_xml(&content, &fixture_uri("simple_pom.xml")).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(
        result.dependencies[0].name,
        "org.apache.commons:commons-lang3"
    );
    assert_eq!(result.dependencies[1].name, "junit:junit");
}

#[test]
fn test_fixture_complex_pom() {
    use deps_maven::MavenScope;

    let content = load_fixture("complex_pom.xml");
    let result = parse_pom_xml(&content, &fixture_uri("complex_pom.xml")).unwrap();

    // 6 regular deps + 1 from dependencyManagement + 2 plugins
    assert!(result.dependencies.len() >= 8);

    // Properties parsed
    assert_eq!(
        result.properties.get("java.version"),
        Some(&"17".to_string())
    );
    assert_eq!(
        result.properties.get("spring.version"),
        Some(&"3.2.0".to_string())
    );

    // Scope variety
    let scopes: Vec<_> = result.dependencies.iter().map(|d| &d.scope).collect();
    assert!(scopes.iter().any(|s| matches!(s, MavenScope::Test)));
    assert!(scopes.iter().any(|s| matches!(s, MavenScope::Runtime)));
    assert!(scopes.iter().any(|s| matches!(s, MavenScope::Provided)));
    assert!(scopes.iter().any(|s| matches!(s, MavenScope::Import)));
}

#[test]
fn test_fixture_minimal_pom() {
    let content = load_fixture("minimal_pom.xml");
    let result = parse_pom_xml(&content, &fixture_uri("minimal_pom.xml")).unwrap();
    assert!(result.dependencies.is_empty());
}

#[test]
fn test_fixture_property_versions() {
    let content = load_fixture("property_versions.xml");
    let result = parse_pom_xml(&content, &fixture_uri("property_versions.xml")).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    // Property references stored as-is
    assert_eq!(
        result.dependencies[0].version_req,
        Some("${commons.version}".into())
    );
    assert_eq!(
        result.dependencies[1].version_req,
        Some("${guava.version}".into())
    );
}

#[test]
fn test_fixture_scoped_deps() {
    use deps_maven::MavenScope;

    let content = load_fixture("scoped_deps.xml");
    let result = parse_pom_xml(&content, &fixture_uri("scoped_deps.xml")).unwrap();
    assert_eq!(result.dependencies.len(), 5);

    let by_scope: std::collections::HashMap<String, _> = result
        .dependencies
        .iter()
        .map(|d| (d.artifact_id.clone(), &d.scope))
        .collect();

    assert!(matches!(by_scope["commons-lang3"], MavenScope::Compile));
    assert!(matches!(by_scope["junit"], MavenScope::Test));
    assert!(matches!(by_scope["logback-classic"], MavenScope::Runtime));
    assert!(matches!(
        by_scope["javax.servlet-api"],
        MavenScope::Provided
    ));
    assert!(matches!(by_scope["tools"], MavenScope::System));
}

#[test]
fn test_fixture_namespaced_pom() {
    let content = load_fixture("namespaced_pom.xml");
    let result = parse_pom_xml(&content, &fixture_uri("namespaced_pom.xml")).unwrap();
    assert_eq!(result.dependencies.len(), 1);
    assert_eq!(
        result.dependencies[0].name,
        "org.apache.commons:commons-lang3"
    );
}

#[test]
fn test_fixture_malformed_pom() {
    let content = load_fixture("malformed_pom.xml");
    let result = parse_pom_xml(&content, &fixture_uri("malformed_pom.xml"));
    assert!(result.is_err());
}

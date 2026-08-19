//! Integration tests using fixture files.

use deps_core::lockfile::LockFileProvider;
use deps_nuget::{
    NuGetLockParser, parse_directory_packages_props, parse_packages_config, parse_project_file,
};
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
fn test_fixture_simple_csproj() {
    let content = load_fixture("simple.csproj");
    let result = parse_project_file(&content, &fixture_uri("simple.csproj")).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(result.dependencies[0].name, "Newtonsoft.Json");
    assert_eq!(
        result.dependencies[0].version_requirement,
        Some("13.0.3".into())
    );
    assert_eq!(result.dependencies[1].name, "Serilog");
    assert_eq!(
        result.dependencies[1].version_requirement,
        Some("3.1.1".into())
    );
}

#[test]
fn test_fixture_child_element_csproj() {
    let content = load_fixture("child_element.csproj");
    let result = parse_project_file(&content, &fixture_uri("child_element.csproj")).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    assert_eq!(
        result.dependencies[0].version_requirement,
        Some("3.1.1".into())
    );
    assert_eq!(
        result.dependencies[1].version_requirement,
        Some("5.0.1".into())
    );
}

#[test]
fn test_fixture_central_package_management_csproj() {
    let content = load_fixture("central_package_management.csproj");
    let result =
        parse_project_file(&content, &fixture_uri("central_package_management.csproj")).unwrap();
    assert_eq!(result.dependencies.len(), 2);
    for dep in &result.dependencies {
        assert!(dep.version_requirement.is_none());
        assert!(dep.version_range.is_none());
    }
}

#[test]
fn test_fixture_complex_csproj() {
    let content = load_fixture("complex.csproj");
    let result = parse_project_file(&content, &fixture_uri("complex.csproj")).unwrap();
    assert_eq!(result.dependencies.len(), 6);

    let by_name: std::collections::HashMap<&str, &deps_nuget::NuGetDependency> = result
        .dependencies
        .iter()
        .map(|d| (d.name.as_str(), d))
        .collect();

    assert_eq!(
        by_name["Newtonsoft.Json"].version_requirement,
        Some("13.0.3".into())
    );
    assert_eq!(by_name["Serilog"].version_requirement, Some("3.1.1".into()));
    // Central package management: no version at all.
    assert!(by_name["MyCompany.Shared"].version_requirement.is_none());
    // Unresolvable MSBuild property expression degrades to None.
    assert!(by_name["AutoMapper"].version_requirement.is_none());
    // Condition attribute containing a literal `Version="` must not confuse the parser.
    assert_eq!(
        by_name["System.Text.Json"].version_requirement,
        Some("8.0.5".into())
    );
    // Single-quoted attributes.
    assert_eq!(by_name["Polly"].version_requirement, Some("8.4.1".into()));
}

#[test]
fn test_fixture_malformed_csproj_errors() {
    let content = load_fixture("malformed.csproj");
    let result = parse_project_file(&content, &fixture_uri("malformed.csproj"));
    assert!(result.is_err());
}

#[test]
fn test_fixture_directory_packages_props() {
    let content = load_fixture("Directory.Packages.props");
    let result =
        parse_directory_packages_props(&content, &fixture_uri("Directory.Packages.props")).unwrap();
    assert_eq!(result.dependencies.len(), 3);
    assert_eq!(result.dependencies[0].name, "Newtonsoft.Json");
    assert_eq!(
        result.dependencies[0].version_requirement,
        Some("13.0.3".into())
    );
}

#[test]
fn test_fixture_packages_config_normalizes_exact_pin() {
    let content = load_fixture("packages.config");
    let result = parse_packages_config(&content, &fixture_uri("packages.config")).unwrap();
    assert_eq!(result.dependencies.len(), 3);
    for dep in &result.dependencies {
        let req = dep.version_requirement.as_deref().unwrap();
        assert!(
            req.starts_with('[') && req.ends_with(']'),
            "expected bracketed exact pin for {}, got {req}",
            dep.name
        );
    }
}

#[tokio::test]
async fn test_fixture_packages_lock_json() {
    let tmp = tempfile::tempdir().unwrap();
    let content = load_fixture("packages.lock.json");
    let lock_path = tmp.path().join("packages.lock.json");
    tokio::fs::write(&lock_path, &content).await.unwrap();

    let parser = NuGetLockParser;
    let resolved = parser.parse_lockfile(&lock_path).await.unwrap();

    // MyCompany.Shared ("type": "Project", no "resolved") must be skipped, not abort parsing.
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved.get_version("Newtonsoft.Json"), Some("13.0.3"));
    assert_eq!(resolved.get_version("Serilog"), Some("3.1.1"));
    assert!(resolved.get("MyCompany.Shared").is_none());
}

#[test]
fn test_parse_result_trait() {
    use deps_core::ParseResult;

    let content = load_fixture("simple.csproj");
    let result = parse_project_file(&content, &fixture_uri("simple.csproj")).unwrap();

    assert_eq!(result.dependencies().len(), 2);
    assert!(result.workspace_root().is_none());
    assert!(result.as_any().is::<deps_nuget::NuGetParseResult>());
}

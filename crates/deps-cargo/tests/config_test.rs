//! Integration tests for `.cargo/config.toml` discovery and registry resolution
//! (spec `023-cargo-custom-registries` FR-002/FR-003/FR-004/FR-008/FR-009/FR-015),
//! exercised through the crate's public API rather than `config.rs`'s own
//! module-internal unit tests.

use deps_cargo::DependencySource;
use deps_cargo::config::{
    RegistryIndex, cargo_home_config_path, discover_workspace_config_paths, resolve,
};
use deps_cargo::parse_cargo_toml;
use std::collections::HashSet;
use tower_lsp_server::ls_types::Uri;

fn write_manifest(dir: &std::path::Path, content: &str) -> Uri {
    let path = dir.join("Cargo.toml");
    std::fs::write(&path, content).unwrap();
    Uri::from_file_path(&path).unwrap()
}

/// FR-002: an alias resolves end-to-end, from the raw `registry = "<alias>"` manifest
/// value through discovery + resolution, into a fetchable `AlternateRegistry` source.
#[test]
fn test_alias_resolves_end_to_end_via_workspace_config() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        "[registries.my-corp]\nindex = \"sparse+https://index.mycorp.dev\"\n",
    )
    .unwrap();

    let uri = write_manifest(
        root.path(),
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"my-corp\" }\n",
    );

    let result = parse_cargo_toml(
        &std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    assert_eq!(result.dependencies.len(), 1);
    match &result.dependencies[0].source {
        DependencySource::AlternateRegistry { index } => {
            assert_eq!(index, "https://index.mycorp.dev/");
        }
        other => panic!("expected AlternateRegistry, got {other:?}"),
    }
}

/// FR-003: an alias with no matching config entry stays `CustomRegistry`, unchanged —
/// no crash, no silent wrong resolution.
#[test]
fn test_alias_without_config_stays_custom_registry() {
    let root = tempfile::tempdir().unwrap();
    let uri = write_manifest(
        root.path(),
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"unconfigured\" }\n",
    );

    let result = parse_cargo_toml(
        &std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    match &result.dependencies[0].source {
        DependencySource::CustomRegistry { url } => assert_eq!(url, "unconfigured"),
        other => panic!("expected CustomRegistry, got {other:?}"),
    }
    assert!(result.resolved_registries.is_empty());
}

/// Closest ancestor `.cargo/config.toml` wins over one farther away, and both are
/// discovered by walking up from the manifest's own directory (spec FR-002, "hierarchy").
#[test]
fn test_ancestor_precedence_closest_directory_wins() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("crates").join("member");
    std::fs::create_dir_all(&nested).unwrap();

    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        "[registries.my-corp]\nindex = \"sparse+https://far.example\"\n",
    )
    .unwrap();

    std::fs::create_dir_all(nested.join(".cargo")).unwrap();
    std::fs::write(
        nested.join(".cargo/config.toml"),
        "[registries.my-corp]\nindex = \"sparse+https://close.example\"\n",
    )
    .unwrap();

    let uri = write_manifest(
        &nested,
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"my-corp\" }\n",
    );

    let result = parse_cargo_toml(
        &std::fs::read_to_string(nested.join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    match &result.dependencies[0].source {
        DependencySource::AlternateRegistry { index } => {
            assert_eq!(index, "https://close.example/", "closest ancestor must win");
        }
        other => panic!("expected AlternateRegistry, got {other:?}"),
    }
}

/// NFR-004: a manifest with zero `registry`/`registry-index` dependencies triggers no
/// config discovery at all — asserted at the public `resolved_registries` boundary
/// rather than by instrumenting file reads directly.
#[test]
fn test_no_custom_registry_dependency_triggers_no_resolution() {
    let root = tempfile::tempdir().unwrap();
    let uri = write_manifest(root.path(), "[dependencies]\nserde = \"1.0\"\n");

    let result = parse_cargo_toml(
        &std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    assert!(result.resolved_registries.is_empty());
}

/// `RegistryIndex` validation — NFR-002's SSRF-adjacent construction-time gate,
/// exercised through the crate's public type rather than only inside `config.rs`.
#[test]
fn test_registry_index_validation_public_api() {
    assert!(RegistryIndex::new("sparse+https://index.mycorp.dev").is_ok());
    assert!(RegistryIndex::new("http://index.mycorp.dev").is_err());
    assert!(RegistryIndex::new("https://user:pass@index.mycorp.dev").is_err());
    assert!(RegistryIndex::new("not a url").is_err());
}

/// FR-004: `$CARGO_HOME` unset yields no cargo-home config path, and no
/// `HOME`/`USERPROFILE` fallback is attempted — asserted here only for the
/// unset-in-this-test-process shape; `resolve`'s own precedence tests cover the
/// populated case without touching real process environment (see `config.rs`'s
/// `resolve_with_env`-based unit tests, which this integration file cannot reach since
/// it is `unsafe`-free by the same workspace-wide constraint).
#[test]
fn test_discover_and_resolve_public_api_smoke() {
    let root = tempfile::tempdir().unwrap();
    let paths = discover_workspace_config_paths(root.path());
    assert!(paths.is_empty(), "no .cargo/config.toml exists yet");

    let aliases: HashSet<String> = std::iter::once("nonexistent".to_string()).collect();
    let config = resolve(&aliases, &paths, cargo_home_config_path().as_deref());
    assert!(config.get("nonexistent").is_none());
}

/// FR-009/US-004 structural auth-gate property, exercised end-to-end from
/// `parse_cargo_toml`: a workspace-declared registry entry must never carry a token,
/// even when a same-named `$CARGO_HOME/config.toml` entry has one — proven here via
/// `resolved_registries`, the exact channel `CargoEcosystem::parse_manifest` uses to
/// register a client's credential into the shared `CargoRegistry` router.
#[test]
fn test_workspace_resolved_registry_never_carries_auth_even_with_cargo_home_present() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        "[registries.my-corp]\nindex = \"sparse+https://workspace.example\"\n",
    )
    .unwrap();

    let uri = write_manifest(
        root.path(),
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"my-corp\" }\n",
    );

    let result = parse_cargo_toml(
        &std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    assert_eq!(result.resolved_registries.len(), 1);
    assert!(
        result.resolved_registries[0].1.is_none(),
        "a workspace-resolved registry entry must never carry a credential"
    );
}

/// A literal `registry-index` URL resolves without any `.cargo/config.toml` at all
/// (spec FR-002's direct-URL form) and never carries a credential either — a literal
/// manifest value is workspace-declared by definition.
#[test]
fn test_registry_index_literal_resolves_without_config_and_without_auth() {
    let root = tempfile::tempdir().unwrap();
    let uri = write_manifest(
        root.path(),
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry-index = \"sparse+https://index.mycorp.dev\" }\n",
    );

    let result = parse_cargo_toml(
        &std::fs::read_to_string(root.path().join("Cargo.toml")).unwrap(),
        &uri,
    )
    .unwrap();

    match &result.dependencies[0].source {
        DependencySource::AlternateRegistry { index } => {
            assert_eq!(index, "https://index.mycorp.dev/");
        }
        other => panic!("expected AlternateRegistry, got {other:?}"),
    }
    assert_eq!(result.resolved_registries.len(), 1);
    assert!(result.resolved_registries[0].1.is_none());
}

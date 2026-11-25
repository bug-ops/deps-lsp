//! #2151: any `*.versions.toml` routes to Gradle, and Gradle's pattern stays disjoint from every
//! other ecosystem's (registration debug-asserts it, so building the registry is itself a check).
//! Fixtures use `plugins.versions.toml`, a name no `libs`-specific rule can satisfy.

#![cfg(all(feature = "cargo", feature = "gradle", feature = "pypi"))]
#![expect(clippy::expect_used, reason = "test code")]

use std::sync::Arc;

use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

fn registry() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    register_ecosystems(&registry, Arc::new(HttpCache::new()), &runtime);
    registry
}

fn routed(registry: &EcosystemRegistry, filename: &str) -> Option<EcosystemId> {
    registry
        .for_filename(filename)
        .map(|ecosystem| ecosystem.ecosystem_id())
}

#[test]
fn for_filename_routes_every_versions_toml_to_gradle() {
    let registry = registry();
    for name in [
        "libs.versions.toml",
        "plugins.versions.toml",
        "testlibs.versions.toml",
        "deps.versions.toml",
    ] {
        assert_eq!(routed(&registry, name), Some(EcosystemId::Gradle), "{name}");
    }
}

#[test]
fn for_filename_does_not_route_near_misses_to_gradle() {
    let registry = registry();
    for name in [
        "plugins.version.toml",
        "plugins.versions.tom",
        "versions.toml",
    ] {
        assert_ne!(routed(&registry, name), Some(EcosystemId::Gradle), "{name}");
    }
}

#[test]
fn for_filename_keeps_other_ecosystems_routing() {
    let registry = registry();
    assert_eq!(routed(&registry, "Cargo.toml"), Some(EcosystemId::Cargo));
    assert_eq!(
        routed(&registry, "requirements-dev.txt"),
        Some(EcosystemId::Pypi)
    );
}

const SETTINGS_DECLARING: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";

fn declared_catalog(settings: Option<&str>) -> (tempfile::TempDir, url::Url) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical root");
    std::fs::create_dir_all(root.join("gradle")).expect("gradle dir");
    if let Some(settings) = settings {
        std::fs::write(root.join("settings.gradle.kts"), settings).expect("settings");
    }
    let catalog = root.join("gradle/deps.toml");
    std::fs::write(&catalog, "[libraries]\n").expect("catalog");
    let uri = url::Url::from_file_path(catalog).expect("file url");
    (dir, uri)
}

#[test]
fn for_uri_blocking_routes_a_settings_declared_catalog_to_gradle() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let registry = registry();
    let (_dir, uri) = declared_catalog(Some(SETTINGS_DECLARING));

    assert!(registry.for_uri(&uri).is_none(), "for_uri stays pure");
    assert_eq!(
        registry
            .for_uri_blocking(&uri)
            .map(|ecosystem| ecosystem.ecosystem_id()),
        Some(EcosystemId::Gradle)
    );
}

#[test]
fn for_uri_blocking_leaves_an_undeclared_toml_unrouted() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let registry = registry();
    let (_dir, uri) = declared_catalog(None);

    assert!(registry.for_uri_blocking(&uri).is_none());
}

#[test]
fn for_uri_blocking_keeps_static_routing_for_cargo_and_pypi() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let registry = registry();
    let root = tempfile::tempdir().expect("tempdir");
    for (name, id) in [
        ("Cargo.toml", EcosystemId::Cargo),
        ("requirements.txt", EcosystemId::Pypi),
    ] {
        let uri = url::Url::from_file_path(root.path().join(name)).expect("file url");
        assert_eq!(
            registry
                .for_uri_blocking(&uri)
                .map(|ecosystem| ecosystem.ecosystem_id()),
            Some(id),
            "{name}"
        );
    }
}

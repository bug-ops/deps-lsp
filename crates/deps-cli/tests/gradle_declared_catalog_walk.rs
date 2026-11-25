//! #2161: the CLI walk routes a `*.toml` that `settings.gradle.kts` declares as a version catalog
//! to Gradle, and leaves an undeclared `*.toml` unrouted.
#![cfg(feature = "gradle")]

use std::sync::Arc;

use deps_cli::walk::{GitignorePolicy, SymlinkPolicy, walk};
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

const SETTINGS: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";

fn registry() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    register_ecosystems(&registry, Arc::new(HttpCache::new()), &runtime);
    registry
}

#[test]
fn walk_routes_a_settings_declared_catalog_to_gradle() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS).unwrap();
    std::fs::write(root.join("gradle/deps.toml"), "[libraries]\n").unwrap();
    std::fs::write(root.join("other.toml"), "[libraries]\n").unwrap();

    let outcome = walk(
        std::slice::from_ref(&root),
        &registry(),
        GitignorePolicy::Ignore,
        SymlinkPolicy::Skip,
    );

    let routed = |name: &str| {
        outcome
            .manifests()
            .iter()
            .find(|manifest| manifest.path.file_name().is_some_and(|n| n == name))
            .map(|manifest| manifest.ecosystem.ecosystem_id())
    };
    assert_eq!(routed("deps.toml"), Some(EcosystemId::Gradle));
    assert_eq!(
        routed("other.toml"),
        None,
        "an undeclared toml is not a manifest"
    );
}

#[test]
fn walk_of_an_explicit_declared_catalog_path_routes_it_to_gradle() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS).unwrap();
    let catalog = root.join("gradle/deps.toml");
    std::fs::write(&catalog, "[libraries]\n").unwrap();

    let outcome = walk(
        &[catalog],
        &registry(),
        GitignorePolicy::Ignore,
        SymlinkPolicy::Skip,
    );

    assert_eq!(outcome.manifests().len(), 1);
    assert_eq!(
        outcome.manifests()[0].ecosystem.ecosystem_id(),
        EcosystemId::Gradle
    );
    assert!(outcome.unrecognized_explicit_paths().is_empty());
}

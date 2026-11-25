//! #2151: any `*.versions.toml` routes to Gradle, and Gradle's pattern stays disjoint from every
//! other ecosystem's (registration debug-asserts it, so building the registry is itself a check).
//! Fixtures use `plugins.versions.toml`, a name no `libs`-specific rule can satisfy.

#![cfg(all(feature = "cargo", feature = "gradle", feature = "pypi"))]

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

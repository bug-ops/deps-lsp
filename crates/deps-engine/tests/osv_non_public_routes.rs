//! #1917 opt-in guard: only npm, Deno, Go, PyPI and NuGet may route a non-public registry as an
//! unverified mirror, and each opting-in ecosystem must map to an OSV ecosystem.
//!
//! Cross-ecosystem behavioral checks run against every registered ecosystem's own typed
//! formatter through `Ecosystem::probe_non_public_route` and
//! `Ecosystem::probe_route_non_public_routes`, fed real dependencies built through
//! `ProbeDependency` (#1977, #1999):
//!
//! - a `CustomRegistry` source (a route every hop of which was rejected) is reported as an
//!   unverified mirror by Go alone, so a new ecosystem silently opting in fails the test;
//! - an `AlternateRegistry { mirrors_public_registry: false }` source (GitLab includes, Swift
//!   swizzled sources, Cargo alias registries, NuGet feeds, ...) stays
//!   [`NonPublicRoute::Private`] in every ecosystem.
//!
//! - the full opt-in set is derived from behavior: an ecosystem opts in when the `CustomRegistry`
//!   probe or any `ProbeDependency::route_probes` dependency (the registry, index and feed routes
//!   that no source can express) reports an unverified mirror. The derived set is compared with a
//!   literal list, so a new opt-in, or an ecosystem losing every opt-in route, fails the test, and every member must map
//!   to an OSV ecosystem.

#![cfg(all(
    feature = "cargo",
    feature = "npm",
    feature = "pypi",
    feature = "go",
    feature = "bundler",
    feature = "dart",
    feature = "maven",
    feature = "composer",
    feature = "gradle",
    feature = "swift",
    feature = "nuget",
    feature = "deno",
    feature = "github-actions",
    feature = "gitlab-ci",
))]

use std::sync::Arc;

use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::osv::NonPublicRoute;
use deps_core::parser::DependencySource;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemId, EcosystemRegistry, HttpCache, PackageName};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

fn registered_ecosystems() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    register_ecosystems(&registry, Arc::new(HttpCache::new()), &runtime);
    registry
}

fn route_for(
    registry: &EcosystemRegistry,
    id: EcosystemId,
    source: &DependencySource,
) -> NonPublicRoute {
    registry
        .get(id)
        .unwrap_or_else(|| panic!("{id:?} is not registered by register_ecosystems"))
        .probe_non_public_route(PackageName::new("probe"), source.clone())
}

fn custom_registry_source() -> DependencySource {
    DependencySource::CustomRegistry {
        url: "https://proxy.corp.example".into(),
    }
}

fn opts_in_as_unverified_mirror(registry: &EcosystemRegistry, id: EcosystemId) -> bool {
    let ecosystem = registry
        .get(id)
        .unwrap_or_else(|| panic!("{id:?} is not registered by register_ecosystems"));
    route_for(registry, id, &custom_registry_source()) == NonPublicRoute::UnverifiedMirror
        || ecosystem
            .probe_route_non_public_routes(PackageName::new("probe"))
            .contains(&NonPublicRoute::UnverifiedMirror)
}

#[test]
fn the_derived_unverified_mirror_opt_ins_are_exactly_the_known_set_and_map_to_osv() {
    let registry = registered_ecosystems();
    let derived: Vec<EcosystemId> = EcosystemId::ALL
        .iter()
        .copied()
        .filter(|&id| opts_in_as_unverified_mirror(&registry, id))
        .collect();
    assert_eq!(
        derived,
        [
            EcosystemId::Npm,
            EcosystemId::Pypi,
            EcosystemId::Go,
            EcosystemId::NuGet,
            EcosystemId::Deno,
        ]
    );
    for id in derived {
        assert!(
            id.osv_ecosystem().is_some(),
            "{id:?} reports an unverified mirror but has no OSV ecosystem"
        );
    }
}

#[test]
fn only_go_reports_a_rejected_custom_registry_as_an_unverified_mirror() {
    let source = custom_registry_source();
    let registry = registered_ecosystems();
    let opted_in: Vec<EcosystemId> = EcosystemId::ALL
        .iter()
        .copied()
        .filter(|&id| route_for(&registry, id, &source) == NonPublicRoute::UnverifiedMirror)
        .collect();
    assert_eq!(opted_in, [EcosystemId::Go]);
}

#[test]
fn a_private_alternate_registry_stays_silent_in_every_ecosystem() {
    let source = DependencySource::AlternateRegistry {
        index: "https://registry.corp.example/index".into(),
        mirrors_public_registry: false,
    };
    let registry = registered_ecosystems();
    for &id in EcosystemId::ALL {
        assert_eq!(
            route_for(&registry, id, &source),
            NonPublicRoute::Private,
            "{id:?} must not report a private alternate registry as an unverified mirror"
        );
    }
}

//! #1917 opt-in guard: only npm, Deno, Go, PyPI and NuGet may route a non-public registry as an
//! unverified mirror, and each opting-in ecosystem must map to an OSV ecosystem.
//!
//! Two cross-ecosystem behavioral checks run against every registered ecosystem's own typed
//! formatter through `Ecosystem::probe_non_public_route`,
//! fed a real dependency built through `ProbeDependency` (#1977):
//!
//! - a `CustomRegistry` source (a route every hop of which was rejected) is reported as an
//!   unverified mirror by Go alone, so a new ecosystem silently opting in fails the test;
//! - an `AlternateRegistry { mirrors_public_registry: false }` source (GitLab includes, Swift
//!   swizzled sources, Cargo alias registries, NuGet feeds, ...) stays
//!   [`NonPublicRoute::Private`] in every ecosystem.
//!
//! The probe sets only the source; npm, Deno, PyPI and NuGet also opt in through registry or
//! index routes that no source can express, which their own crates test.

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

use deps_core::net_policy::{ProcessEnv, RegistryEnvironment};
use deps_core::osv::NonPublicRoute;
use deps_core::parser::DependencySource;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemId, EcosystemRegistry, HttpCache, PackageName};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

/// Ecosystems that override `deps_core::lsp_helpers::DependencyFormatter::non_public_route` to
/// report an unverified mirror.
const UNVERIFIED_MIRROR_OPT_INS: [EcosystemId; 5] = [
    EcosystemId::Go,
    EcosystemId::Npm,
    EcosystemId::Deno,
    EcosystemId::Pypi,
    EcosystemId::NuGet,
];

fn registered_ecosystems() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&ProcessEnv),
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

#[test]
fn every_unverified_mirror_opt_in_has_an_osv_mapping() {
    for id in UNVERIFIED_MIRROR_OPT_INS {
        assert!(
            id.osv_ecosystem().is_some(),
            "{id:?} reports an unverified mirror but has no OSV ecosystem"
        );
    }
}

#[test]
fn only_go_reports_a_rejected_custom_registry_as_an_unverified_mirror() {
    let source = DependencySource::CustomRegistry {
        url: "https://proxy.corp.example".into(),
    };
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

//! #1917 opt-in guard: across every registered ecosystem, only npm and Go may mark a non-public
//! route as an unverified mirror, and each opting-in ecosystem must map to an OSV ecosystem.
//!
//! GitLab includes, Swift swizzled sources, Cargo alias registries, Deno and NuGet feeds all
//! carry `AlternateRegistry { mirrors_public_registry: false }` and must stay silent.

#![cfg(all(
    feature = "cargo",
    feature = "npm",
    feature = "pypi",
    feature = "go",
    feature = "bundler",
    feature = "dart",
    feature = "maven",
    feature = "gradle",
    feature = "swift",
    feature = "composer",
    feature = "nuget",
    feature = "github-actions",
    feature = "gitlab-ci",
    feature = "deno"
))]
// #689: `clippy.toml`'s `allow-unwrap-in-tests` covers the `#[test]` function, not the helper.
#![allow(clippy::unwrap_used)]

use std::any::Any;
use std::sync::Arc;

use deps_core::net_policy::{ProcessEnv, RegistryEnvironment};
use deps_core::osv::NonPublicRoute;
use deps_core::parser::DependencySource;
use deps_core::policy_config::PolicyConfig;
use deps_core::position::Range;
use deps_core::{Dependency, EcosystemId, EcosystemRegistry, HttpCache, PackageName, VersionReq};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

/// Ecosystems known to override [`deps_core::lsp_helpers::OsvNaming::non_public_route`] by
/// inspecting their own dependency type (npm, PyPI, NuGet), which a synthetic probe cannot
/// trigger. Probe-visible overrides are derived from the registered formatters instead (see
/// `every_probe_visible_unverified_route_has_an_osv_mapping`); this list only covers the rest.
const DOWNCAST_OPT_INS: [EcosystemId; 3] =
    [EcosystemId::Npm, EcosystemId::Pypi, EcosystemId::NuGet];

struct RouteDep {
    name: PackageName,
    source: DependencySource,
}

impl Dependency for RouteDep {
    fn name(&self) -> &PackageName {
        &self.name
    }
    fn name_range(&self) -> Range {
        Range::default()
    }
    fn version_requirement(&self) -> Option<&VersionReq> {
        None
    }
    fn version_range(&self) -> Option<Range> {
        None
    }
    fn source(&self) -> DependencySource {
        self.source.clone()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn route_of(
    id: EcosystemId,
    registry: &EcosystemRegistry,
    source: DependencySource,
) -> NonPublicRoute {
    let ecosystem = registry.get(id).unwrap();
    let dep = RouteDep {
        name: PackageName::new("example"),
        source,
    };
    ecosystem.formatter().non_public_route(&dep)
}

fn registered() -> EcosystemRegistry {
    let registry = EcosystemRegistry::new();
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&ProcessEnv),
    );
    register_ecosystems(&registry, Arc::new(HttpCache::new()), &runtime);
    registry
}

#[test]
fn alternate_registries_stay_silent_in_every_ecosystem() {
    let registry = registered();
    for id in registry.ecosystem_ids() {
        let route = route_of(
            id,
            &registry,
            DependencySource::AlternateRegistry {
                index: "https://mirror.example".into(),
                mirrors_public_registry: false,
            },
        );
        assert_eq!(
            route,
            NonPublicRoute::Private,
            "{id:?}: an alternate registry must stay silent"
        );
    }
}

/// Derives the opted-in set from the real formatters: any ecosystem that reports an unverified
/// mirror for a probe route must map to an OSV ecosystem, or the skip could never have been a scan.
#[test]
fn every_probe_visible_unverified_route_has_an_osv_mapping() {
    let registry = registered();
    let probe_visible: Vec<EcosystemId> = registry
        .ecosystem_ids()
        .into_iter()
        .filter(|id| {
            route_of(
                *id,
                &registry,
                DependencySource::CustomRegistry {
                    url: "https://broken.example".into(),
                },
            ) == NonPublicRoute::UnverifiedMirror
        })
        .collect();
    assert_eq!(probe_visible, [EcosystemId::Go]);
    for id in probe_visible.into_iter().chain(DOWNCAST_OPT_INS) {
        assert!(
            id.osv_ecosystem().is_some(),
            "{id:?} reports an unverified mirror but has no OSV ecosystem"
        );
    }
}

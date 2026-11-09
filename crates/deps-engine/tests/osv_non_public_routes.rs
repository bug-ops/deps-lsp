//! #1917 opt-in guard: only npm, Deno, Go, PyPI and NuGet may route a non-public registry as an
//! unverified mirror, and each opting-in ecosystem must map to an OSV ecosystem.
//!
//! The opt-in list below is static and hard-coded. The earlier cross-ecosystem probe, which
//! walked every registered formatter with a synthetic dependency, is gone because
//! `non_public_route` now reads the ecosystem's own typed dependency. That also dropped the
//! cross-ecosystem check that GitLab includes, Swift swizzled sources, Cargo alias registries
//! and NuGet feeds (`AlternateRegistry { mirrors_public_registry: false }`) stay silent; only
//! deps-go, deps-npm, deps-deno, deps-pypi and deps-nuget keep their own `non_public_route`
//! tests, so Cargo, GitLab CI and Swift have no equivalent test. Tracked in #1977.

use deps_core::EcosystemId;

/// Ecosystems that override `deps_core::lsp_helpers::DependencyFormatter::non_public_route` to
/// report an unverified mirror.
const UNVERIFIED_MIRROR_OPT_INS: [EcosystemId; 5] = [
    EcosystemId::Go,
    EcosystemId::Npm,
    EcosystemId::Deno,
    EcosystemId::Pypi,
    EcosystemId::NuGet,
];

#[test]
fn every_unverified_mirror_opt_in_has_an_osv_mapping() {
    for id in UNVERIFIED_MIRROR_OPT_INS {
        assert!(
            id.osv_ecosystem().is_some(),
            "{id:?} reports an unverified mirror but has no OSV ecosystem"
        );
    }
}

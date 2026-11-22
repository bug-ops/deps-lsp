//! Acceptance tests for #575 / spec 044: the constructor-only `deps-precommit` crate wires the
//! pre-commit flavor of the git-tags ecosystem into manifest routing, and shares one registry
//! with GitHub Actions when both are enabled.

use std::sync::Arc;

use deps_core::{
    Ecosystem, EcosystemBase, EcosystemId, EcosystemRegistry, HttpCache, ParseResult,
    parse_manifest_blocking,
};
use deps_github_actions::{GithubActionsEcosystem, GithubActionsRegistry};

const CONFIG: &str = "repos:\n  - repo: https://github.com/psf/black\n    rev: 24.1.0\n    hooks:\n      - id: black\n";

fn standalone() -> Arc<dyn Ecosystem> {
    Arc::new(deps_precommit::standalone(Arc::new(HttpCache::new())))
}

#[test]
fn standalone_reports_the_pre_commit_ecosystem_id() {
    assert_eq!(standalone().ecosystem_id(), EcosystemId::PreCommit);
}

#[test]
fn ecosystem_over_a_shared_registry_reports_the_pre_commit_id() {
    let registry = Arc::new(GithubActionsRegistry::new(Arc::new(HttpCache::new())));
    let eco = deps_precommit::ecosystem(registry);
    assert_eq!(eco.ecosystem_id(), EcosystemId::PreCommit);
}

#[test]
fn registry_routes_both_config_filenames_to_pre_commit() {
    let registry = EcosystemRegistry::new();
    registry.register(standalone());

    for filename in [".pre-commit-config.yaml", ".pre-commit-config.yml"] {
        let routed = registry.for_filename(filename).expect(filename);
        assert_eq!(routed.ecosystem_id(), EcosystemId::PreCommit, "{filename}");
    }
}

#[test]
fn registry_routes_nested_config_path_to_pre_commit() {
    let registry = EcosystemRegistry::new();
    registry.register(standalone());
    let uri = deps_core::test_util::test_uri("/repo/sub/project/.pre-commit-config.yaml");

    let routed = registry.for_uri(&uri).expect("routed by basename");

    assert_eq!(routed.ecosystem_id(), EcosystemId::PreCommit);
}

#[test]
fn registering_both_flavors_keeps_workflow_and_precommit_routing_apart() {
    let shared = Arc::new(GithubActionsRegistry::new(Arc::new(HttpCache::new())));
    let registry = EcosystemRegistry::new();
    registry.register(Arc::new(GithubActionsEcosystem::with_registry(
        Arc::clone(&shared),
        deps_github_actions::GitTagsFlavor::Actions,
    )));
    registry.register(Arc::new(deps_precommit::ecosystem(shared)));

    let workflow = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
    let config = deps_core::test_util::test_uri("/repo/.pre-commit-config.yaml");

    assert_eq!(
        registry
            .for_uri(&workflow)
            .expect("workflow")
            .ecosystem_id(),
        EcosystemId::GithubActions
    );
    assert_eq!(
        registry.for_uri(&config).expect("config").ecosystem_id(),
        EcosystemId::PreCommit
    );
}

#[tokio::test]
async fn standalone_parses_a_pre_commit_config_fixture() {
    let uri = deps_core::test_util::test_uri("/repo/.pre-commit-config.yaml");

    let manifest = parse_manifest_blocking(&standalone(), CONFIG, &uri)
        .await
        .expect("fixture parses");

    assert_eq!(manifest.ecosystem_id(), EcosystemId::PreCommit);
    let deps = ParseResult::dependencies(&*manifest);
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name().as_str(), "psf/black");
}

#[test]
fn pre_commit_ecosystem_id_is_the_documented_wire_name() {
    assert_eq!(EcosystemId::PreCommit.id(), "pre-commit");
}

#[test]
fn pre_commit_has_no_osv_ecosystem() {
    assert!(EcosystemId::PreCommit.osv_ecosystem().is_none());
}

//! #1917 end to end: which dependencies whose registry route is not public content are reported
//! as `UnverifiedRegistrySource` (npm top-level `registry=`, Go with every hop rejected) and
//! which stay silent (scoped npm registries, `GOPRIVATE`, VCS and path forks).
//!
//! Drives the real npm and Go parsers and formatters through `build_scan_targets`.

#![cfg(all(feature = "npm", feature = "go"))]
// #689: `clippy.toml`'s `allow-unwrap-in-tests` covers the `#[test]` function, not the setup
// helpers, which unwrap known-good temp-directory I/O.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use deps_core::lsp_helpers::DependencyFormatter;
use deps_core::net_policy::{MapEnv, RegistryAccessPolicy};
use deps_core::osv::{ScanOutcome, SkipReason, vuln_key_for};
use deps_core::test_util::stub_document_with;
use deps_core::{EcosystemId, TypedParseResult};
use deps_engine::classify::osv::build_scan_targets;
use deps_go::config::{GoEnvCache, GoParseContext, GoProcessEnv};
use deps_go::{GoFormatter, parse_go_mod_with_context};
use deps_npm::{NpmFormatter, parse_package_json_with_context};
use url::Url;

/// What the OSV target builder did with one dependency.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Scanned,
    Skipped(SkipReason),
}

fn verdicts<P, F>(parse_result: P, formatter: F, ecosystem: EcosystemId) -> HashMap<String, Verdict>
where
    P: TypedParseResult + 'static,
    F: DependencyFormatter<Dep = P::Dep> + 'static,
{
    let document = stub_document_with(parse_result, formatter, ecosystem);
    let (targets, skipped) = build_scan_targets(
        document.as_ref(),
        &HashMap::new(),
        &HashMap::new(),
        ecosystem,
    );
    let mut verdicts = HashMap::new();
    document.for_each_formatted_dependency(&mut |bound| {
        let dep = bound.dependency();
        let key = vuln_key_for(dep, None, bound.formatter());
        let verdict = match skipped.get(&key) {
            Some(ScanOutcome::Skipped(reason)) => Verdict::Skipped(*reason),
            Some(other) => panic!("unexpected pre-scan outcome {other:?}"),
            None => {
                assert!(
                    !targets.is_empty(),
                    "{} neither skipped nor targeted",
                    dep.name().as_str()
                );
                Verdict::Scanned
            }
        };
        verdicts.insert(dep.name().as_str().to_owned(), verdict);
    });
    verdicts
}

fn npm_verdicts(npmrc: Option<&str>, package_json: &str) -> HashMap<String, Verdict> {
    let dir = tempfile::tempdir().unwrap();
    if let Some(npmrc) = npmrc {
        std::fs::write(dir.path().join(".npmrc"), npmrc).unwrap();
    }
    let uri = Url::from_file_path(dir.path().join("package.json")).unwrap();
    let result =
        parse_package_json_with_context(package_json, &uri, &deps_npm::NpmParseContext::default())
            .unwrap();
    verdicts(result, NpmFormatter, EcosystemId::Npm)
}

const NPM_MANIFEST: &str = r#"{"dependencies": {
    "lodash": "4.17.15",
    "@types/node": "20.0.0",
    "@myorg/lib": "1.0.0"
}}"#;

fn go_verdicts(env: &MapEnv, go_mod: &str) -> HashMap<String, Verdict> {
    let ctx = GoParseContext::new(
        Arc::new(RegistryAccessPolicy::default()),
        Arc::new(GoEnvCache::new()),
        None,
        Arc::new(GoProcessEnv::from_env(env)),
    );
    let dir = tempfile::tempdir().unwrap();
    let uri = Url::from_file_path(dir.path().join("go.mod")).unwrap();
    let result = parse_go_mod_with_context(go_mod, &uri, &ctx).unwrap();
    verdicts(result, GoFormatter, EcosystemId::Go)
}

const GO_MOD: &str =
    "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n";
const GIN: &str = "github.com/gin-gonic/gin";

#[test]
fn npm_top_level_registry_reports_unscoped_and_unmatched_scoped_names() {
    let verdicts = npm_verdicts(
        Some(
            "registry=https://registry.npmmirror.com/\n@myorg:registry=https://npm.corp.example/\n",
        ),
        NPM_MANIFEST,
    );
    let unverified = Verdict::Skipped(SkipReason::UnverifiedRegistrySource);
    assert_eq!(verdicts["lodash"], unverified);
    assert_eq!(verdicts["@types/node"], unverified);
    assert_eq!(
        verdicts["@myorg/lib"],
        Verdict::Skipped(SkipReason::NonRegistrySource),
        "a scope entry is a private registry by convention and stays silent"
    );
}

#[test]
fn npm_without_npmrc_is_scanned() {
    let verdicts = npm_verdicts(None, NPM_MANIFEST);
    assert_eq!(verdicts["lodash"], Verdict::Scanned);
    assert_eq!(verdicts["@types/node"], Verdict::Scanned);
}

#[test]
fn npm_explicit_public_registry_is_scanned() {
    for npmrc in [
        "registry=https://registry.npmjs.org/\n",
        "registry=https://registry.npmjs.org\n",
    ] {
        let verdicts = npm_verdicts(Some(npmrc), NPM_MANIFEST);
        assert_eq!(verdicts["lodash"], Verdict::Scanned, "{npmrc:?} (#1953)");
        assert_eq!(
            verdicts["@types/node"],
            Verdict::Scanned,
            "{npmrc:?} (#1953)"
        );
    }
}

#[test]
fn npm_public_registry_lookalikes_are_still_reported() {
    for npmrc in [
        "registry=https://registry.npmjs.org/?x=1\n",
        "registry=http://registry.npmjs.org/\n",
        "registry=https://user:pw@registry.npmjs.org/\n",
    ] {
        let verdicts = npm_verdicts(Some(npmrc), r#"{"dependencies": {"lodash": "4.17.15"}}"#);
        assert_eq!(
            verdicts["lodash"],
            Verdict::Skipped(SkipReason::UnverifiedRegistrySource),
            "{npmrc:?}"
        );
    }
}

#[test]
fn npm_peer_dependencies_are_exempt_from_lock_coverage_gaps() {
    use deps_core::osv::LockResolution;

    let dir = tempfile::tempdir().unwrap();
    let uri = Url::from_file_path(dir.path().join("package.json")).unwrap();
    let result = parse_package_json_with_context(
        r#"{"peerDependencies": {"react": "^18.0.0"}, "dependencies": {"lodash": "4.17.15"}}"#,
        &uri,
        &deps_npm::NpmParseContext::default(),
    )
    .unwrap();
    let document = stub_document_with(result, NpmFormatter, EcosystemId::Npm);
    let resolution = |name: &str| {
        let mut resolution = None;
        document.for_each_formatted_dependency(&mut |bound| {
            if bound.dependency().name().as_str() == name {
                resolution = Some(bound.lock_resolution());
            }
        });
        resolution.unwrap()
    };
    assert_eq!(resolution("react"), LockResolution::NotLocked);
    assert_eq!(resolution("lodash"), LockResolution::Expected);
}

#[test]
fn npm_invalid_top_level_registry_is_reported() {
    let verdicts = npm_verdicts(
        Some("registry=${DEPS_LSP_TEST_UNDEFINED_REGISTRY}\n"),
        r#"{"dependencies": {"lodash": "4.17.15"}}"#,
    );
    assert_eq!(
        verdicts["lodash"],
        Verdict::Skipped(SkipReason::UnverifiedRegistrySource)
    );
}

#[test]
fn npm_non_registry_specifiers_stay_silent() {
    let verdicts = npm_verdicts(
        Some("registry=https://registry.npmmirror.com/\n"),
        r#"{"dependencies": {"forked": "git+https://example.com/forked.git"}}"#,
    );
    assert_eq!(
        verdicts["forked"],
        Verdict::Skipped(SkipReason::NonRegistrySource)
    );
}

#[test]
fn go_direct_proxy_is_scanned() {
    for goproxy in ["direct", "off", "https://proxy.golang.org,direct"] {
        let env = MapEnv::new().with_var("GOPROXY", goproxy);
        assert_eq!(
            go_verdicts(&env, GO_MOD)[GIN],
            Verdict::Scanned,
            "GOPROXY={goproxy} must still reach OSV (#1914)"
        );
    }
}

#[test]
fn go_proxy_with_every_hop_rejected_is_reported() {
    let env = MapEnv::new().with_var("GOPROXY", "https://user:token@proxy.corp.example");
    assert_eq!(
        go_verdicts(&env, GO_MOD)[GIN],
        Verdict::Skipped(SkipReason::UnverifiedRegistrySource)
    );
}

#[test]
fn go_nosumdb_only_module_with_every_hop_rejected_is_reported() {
    let env = MapEnv::new()
        .with_var("GOPROXY", "https://user:token@proxy.corp.example")
        .with_var("GONOSUMDB", "github.com/gin-gonic");
    assert_eq!(
        go_verdicts(&env, GO_MOD)[GIN],
        Verdict::Skipped(SkipReason::UnverifiedRegistrySource),
        "routing fails closed before the checksum-database check"
    );
}

#[test]
fn go_private_modules_stay_silent() {
    for env in [
        MapEnv::new().with_var("GOPRIVATE", "github.com/gin-gonic"),
        MapEnv::new()
            .with_var("GOPROXY", "direct")
            .with_var("GOPRIVATE", "github.com/gin-gonic"),
        MapEnv::new()
            .with_var("GOPROXY", "direct")
            .with_var("GONOSUMDB", "github.com/gin-gonic"),
        MapEnv::new()
            .with_var("GOPROXY", "direct")
            .with_var("GOSUMDB", "off"),
    ] {
        assert_eq!(
            go_verdicts(&env, GO_MOD)[GIN],
            Verdict::Skipped(SkipReason::NonRegistrySource)
        );
    }
}

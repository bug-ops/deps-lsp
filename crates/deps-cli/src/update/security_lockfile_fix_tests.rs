//! `plan_security_updates` records the lock-file evidence (#2110, #2109) on a
//! `RequiresLockfileUpdate` item, driven through a real npm ecosystem against `mockito`
//! registry and OSV servers.

#![expect(clippy::expect_used, reason = "test code")]

#[path = "../../tests/native_advisory/mod.rs"]
mod native_advisory;

use std::assert_matches;
use std::sync::Arc;

use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::{FetchTimeout, PolicyConfig};
use deps_core::{ConcreteVersion, EcosystemId, EcosystemRegistry, FreshnessSettings, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use native_advisory::{AdvisoryFixture, DAY, now_secs, osv_with_advisory, rfc3339};

use super::Outcome;
use super::ignore::IgnoreRules;
use super::security::plan_security_updates;
use crate::analyze::{AnalysisScope, analyze_manifest};
use crate::report::CheckContext;

const MANIFEST: &str = r#"{"dependencies": {"widget": "^1.0.0"}}"#;
const LOCK: &str = r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"widget":"^1.0.0"}},"node_modules/widget":{"version":"1.0.0","resolved":"https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"}}}"#;

/// `(version, age in seconds)`, oldest first; the newest entry is `latest`.
const VERSIONS: &[(&str, i64)] = &[("1.0.0", 100 * DAY), ("1.0.1", 20 * DAY), ("1.0.2", DAY)];

async fn lockfile_only_item(freshness_enabled: bool) -> super::PlannedUpdateItem {
    let mut registry = mockito::Server::new_async().await;
    let entries: Vec<String> = VERSIONS
        .iter()
        .map(|(version, _)| format!(r#""{version}":{{}}"#))
        .collect();
    let abbreviated = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body(format!(
            r#"{{"dist-tags":{{"latest":"1.0.2"}},"versions":{{{}}}}}"#,
            entries.join(",")
        ))
        .expect_at_least(0)
        .create_async()
        .await;
    let times: Vec<String> = VERSIONS
        .iter()
        .map(|(version, age)| format!(r#""{version}":"{}""#, rfc3339(now_secs() - age)))
        .collect();
    let full = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(format!(r#"{{"time":{{{}}}}}"#, times.join(",")))
        .expect_at_least(0)
        .create_async()
        .await;
    let (osv, _osv_mocks) = osv_with_advisory(&AdvisoryFixture {
        ecosystem: "npm",
        package: "widget",
        range_type: "SEMVER",
        vulnerable: "1.0.0",
        fixed: "1.0.1",
    })
    .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::write(root.join(".npmrc"), "").expect("npmrc");
    std::fs::write(root.join("package-lock.json"), LOCK).expect("lock");
    let manifest = root.join("package.json");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let mut policy = PolicyConfig::default();
    policy.freshness.enabled = freshness_enabled;
    let base = url::Url::parse(&registry.url()).expect("mock url");
    let runtime =
        EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&MapEnv::new()))
            .with_npm_public_base_for_test(base);
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let ecosystems = EcosystemRegistry::new();
    let _ = register_ecosystems(&ecosystems, Arc::clone(&cache), &runtime);
    let ecosystem = ecosystems.get(EcosystemId::Npm).expect("npm registered");
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
        policy,
    };

    let analysis = analyze_manifest(
        &ecosystem,
        &manifest,
        MANIFEST,
        &ctx,
        AnalysisScope::vulnerabilities_only(),
    )
    .await
    .expect("analyze_manifest");
    let freshness: FreshnessSettings = ctx.policy.freshness.to_freshness();
    let plan = plan_security_updates(
        &analysis,
        ecosystem.as_ref(),
        &ctx.osv,
        &[],
        &IgnoreRules::empty(),
        freshness,
        FetchTimeout::try_from_secs(30).expect("timeout"),
    )
    .await;
    drop((abbreviated, full));
    plan.items
        .into_iter()
        .find(|item| matches!(item.outcome, Outcome::RequiresLockfileUpdate { .. }))
        .expect("a lock-file-only item")
}

#[tokio::test]
async fn test_plan_security_updates_records_the_cooldown_held_versions_and_ecosystem() {
    let item = lockfile_only_item(true).await;

    assert_eq!(
        item.lockfile_fix.cooldown_held,
        vec![ConcreteVersion::from("1.0.2")]
    );
    assert_matches!(
        item.outcome,
        Outcome::RequiresLockfileUpdate {
            ecosystem: EcosystemId::Npm,
            ..
        }
    );
}

#[tokio::test]
async fn test_plan_security_updates_records_no_held_versions_when_freshness_is_disabled() {
    let item = lockfile_only_item(false).await;

    assert!(item.lockfile_fix.cooldown_held.is_empty());
}

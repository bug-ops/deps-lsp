//! #2041 / spec 099 acceptance: npm's native `min-release-age` through the real `deps-cli`
//! pipeline (`check_manifest`, `plan_updates`) against a `mockito` registry reached through a
//! workspace `.npmrc`, with freshness left disabled so publish times exist only because a
//! native window asked for them.
//!
//! Explain-only: a held `latest` is never written, the skip carries the same note `check`
//! prints (FR-016), and a project without a window is unaffected.
//!
//! Advisories are not covered here: OSV is never asked about a package fetched through a
//! `.npmrc`-overridden registry, and this harness can only reach a mock registry that way. The
//! advisory and security-fix paths read the window through the same `NativeGate` sinks the Cargo
//! suite (`native_cooldown_cli.rs`) already exercises.

#![cfg(feature = "npm")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::exit::update_exit_code;
use deps_cli::report::{CheckContext, check_manifest};
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::{Outcome, SkipReason, UpdatePlan, plan_updates};
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::{PolicyConfig, RegistriesConfig, WorkspaceRegistriesSetting};
use deps_core::{Ecosystem, EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

const DAY: i64 = 86_400;
const MANIFEST: &str = r#"{"dependencies": {"widget": "1.0.0"}}"#;
const WINDOW_7D: &str = "min-release-age=7\n";
const NOTE: &str = "excluded by npm min-release-age = 7 days";

fn now_secs() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits")
}

fn rfc3339(epoch: i64) -> String {
    let (days, rem) = (epoch.div_euclid(DAY), epoch.rem_euclid(DAY));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

struct Fixture {
    _registry: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    _dir: tempfile::TempDir,
    manifest: PathBuf,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
}

async fn fixture(npmrc_extra: &str, latest_age: i64) -> Fixture {
    let mut registry = mockito::Server::new_async().await;
    let abbreviated = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body(r#"{"dist-tags":{"latest":"1.1.0"},"versions":{"1.0.0":{},"1.1.0":{}}}"#)
        .expect_at_least(0)
        .create_async()
        .await;
    let full = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(format!(
            r#"{{"time":{{"1.0.0":"{}","1.1.0":"{}"}}}}"#,
            rfc3339(now_secs() - 100 * DAY),
            rfc3339(now_secs() - latest_age)
        ))
        .expect_at_least(0)
        .create_async()
        .await;
    let mut osv = mockito::Server::new_async().await;
    let osv_mock = osv
        .mock("POST", "/v1/querybatch")
        .with_status(200)
        .with_body(r#"{"results":[{"vulns":[]}]}"#)
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::write(
        root.join(".npmrc"),
        format!("registry={}/\n{npmrc_extra}", registry.url()),
    )
    .expect("npmrc");
    std::fs::write(root.join("package-lock.json"), "{}").expect("lock");
    let manifest = root.join("package.json");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let policy = PolicyConfig {
        registries: RegistriesConfig::new()
            .with_workspace_registries(WorkspaceRegistriesSetting::All),
        ..PolicyConfig::default()
    };
    let host = registry.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let runtime = EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&env));
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
    Fixture {
        _registry: registry,
        _osv: osv,
        _mocks: vec![abbreviated, full, osv_mock],
        _dir: dir,
        manifest,
        ctx,
        ecosystem,
    }
}

impl Fixture {
    async fn check_messages(&self) -> Vec<String> {
        check_manifest(
            &self.ecosystem,
            &self.manifest,
            &self.manifest,
            MANIFEST,
            &self.ctx,
        )
        .await
        .expect("check_manifest")
        .findings
        .into_iter()
        .map(|finding| finding.message)
        .collect()
    }

    async fn update_plan(&self) -> UpdatePlan {
        let analysis = analyze_manifest(
            &self.ecosystem,
            &self.manifest,
            MANIFEST,
            &self.ctx,
            AnalysisScope::update_default(),
        )
        .await
        .expect("analyze_manifest");
        let reparse = deps_core::edit::EcosystemReparse {
            ecosystem: &self.ecosystem,
            uri: &analysis.uri,
        };
        plan_updates(
            &analysis,
            MANIFEST,
            &reparse,
            &[],
            &IgnoreRules::empty(),
            self.ctx.policy.freshness.to_freshness(),
            analysis.now,
        )
    }
}

fn applied(plan: &UpdatePlan) -> Vec<String> {
    plan.items
        .iter()
        .filter_map(|item| match &item.outcome {
            Outcome::Applied { target, .. } => Some(target.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

fn held_items(plan: &UpdatePlan) -> usize {
    plan.items
        .iter()
        .filter(|item| {
            matches!(
                item.outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinNativeCooldown,
                    ..
                }
            )
        })
        .count()
}

#[tokio::test]
async fn check_names_the_npm_window_with_freshness_disabled() {
    let fx = fixture(WINDOW_7D, 3 * DAY).await;
    let messages = fx.check_messages().await;
    let held: Vec<_> = messages.iter().filter(|m| m.contains(NOTE)).collect();
    assert_eq!(held.len(), 1, "{messages:?}");
    assert!(
        held[0].contains("1.1.0") && held[0].contains("eligible in"),
        "{held:?}"
    );
}

#[tokio::test]
async fn update_skips_the_held_latest_with_exit_zero() {
    let fx = fixture(WINDOW_7D, 3 * DAY).await;
    let plan = fx.update_plan().await;
    assert!(applied(&plan).is_empty(), "{:#?}", plan.items);
    assert_eq!(held_items(&plan), 1, "{:#?}", plan.items);
    let run = deps_cli::update::UpdateRun {
        plan,
        lockfile: deps_cli::update::regen::LockfileOutcome::NotApplicable(
            deps_cli::update::regen::NotApplicableReason::NothingApplied,
        ),
    };
    assert_eq!(update_exit_code(&run), 0);
}

#[tokio::test]
async fn update_applies_a_latest_published_beyond_the_window() {
    let fx = fixture(WINDOW_7D, 8 * DAY).await;
    let plan = fx.update_plan().await;
    assert_eq!(applied(&plan), ["1.1.0"], "{:#?}", plan.items);
    assert_eq!(held_items(&plan), 0);
}

#[tokio::test]
async fn without_a_window_nothing_is_held() {
    let fx = fixture("", 3 * DAY).await;
    assert!(
        fx.check_messages()
            .await
            .iter()
            .all(|message| !message.contains("excluded by"))
    );
    assert_eq!(applied(&fx.update_plan().await), ["1.1.0"]);
}

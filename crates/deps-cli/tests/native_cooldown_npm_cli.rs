//! #2041 / spec 099 acceptance: npm's native `min-release-age` through the real `deps-cli`
//! pipeline (`check_manifest`, `plan_updates`) against a `mockito` registry reached through a
//! workspace `.npmrc`, with freshness left disabled so publish times exist only because a
//! native window asked for them.
//!
//! Explain-only: a held `latest` is never written, the skip carries the same note `check`
//! prints (FR-016), and a project without a window is unaffected.
//!
//! The advisory and security-fix scenarios reach the mock registry through
//! `EcosystemRuntime::with_npm_public_base_for_test` instead, so the package counts as public
//! and OSV is asked about it.

#![cfg(feature = "npm")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::exit::update_exit_code;
use deps_cli::report::{CheckContext, check_manifest};
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::security::plan_security_updates;
use deps_cli::update::{Outcome, SkipReason, UpdatePlan, plan_updates};
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::{
    FetchTimeout, PolicyConfig, RegistriesConfig, WorkspaceRegistriesSetting,
};
use deps_core::{Ecosystem, EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use native_advisory::{ADVISORY, AdvisoryFixture, DAY, now_secs, osv_with_advisory, rfc3339};

mod native_advisory;

const MANIFEST: &str = r#"{"dependencies": {"widget": "1.0.0"}}"#;
const WINDOW_7D: &str = "min-release-age=7\n";
const NOTE: &str = "excluded by npm min-release-age = 7 days";

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

// ---- advisories: the registry is the public tier, so OSV is asked -------------------------

/// `(version, age in seconds, deprecated)`, oldest first; the newest entry is `latest`.
type PublicVersions<'a> = &'a [(&'a str, i64, bool)];

async fn public_fixture(npmrc: &str, versions: PublicVersions<'_>, fixed: &str) -> Fixture {
    let mut registry = mockito::Server::new_async().await;
    let latest = versions.last().expect("a version").0;
    let entries: Vec<String> = versions
        .iter()
        .map(|(version, _, deprecated)| {
            let body = if *deprecated {
                r#"{"deprecated":"use a newer release"}"#
            } else {
                "{}"
            };
            format!(r#""{version}":{body}"#)
        })
        .collect();
    let abbreviated = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body(format!(
            r#"{{"dist-tags":{{"latest":"{latest}"}},"versions":{{{}}}}}"#,
            entries.join(",")
        ))
        .expect_at_least(0)
        .create_async()
        .await;
    let times: Vec<String> = versions
        .iter()
        .map(|(version, age, _)| format!(r#""{version}":"{}""#, rfc3339(now_secs() - age)))
        .collect();
    let full = registry
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(format!(r#"{{"time":{{{}}}}}"#, times.join(",")))
        .expect_at_least(0)
        .create_async()
        .await;
    let (osv, mut mocks) = osv_with_advisory(&AdvisoryFixture {
        ecosystem: "npm",
        package: "widget",
        range_type: "SEMVER",
        vulnerable: "1.0.0",
        fixed,
    })
    .await;
    mocks.extend([abbreviated, full]);

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::write(root.join(".npmrc"), npmrc).expect("npmrc");
    std::fs::write(root.join("package-lock.json"), "{}").expect("lock");
    let manifest = root.join("package.json");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let mut policy = PolicyConfig::default();
    policy.freshness.enabled = false;
    let env = MapEnv::new();
    let base = url::Url::parse(&registry.url()).expect("mock url");
    let runtime = EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&env))
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
    Fixture {
        _registry: registry,
        _osv: osv,
        _mocks: mocks,
        _dir: dir,
        manifest,
        ctx,
        ecosystem,
    }
}

impl Fixture {
    async fn security_plan(&self) -> UpdatePlan {
        let analysis = analyze_manifest(
            &self.ecosystem,
            &self.manifest,
            MANIFEST,
            &self.ctx,
            AnalysisScope::vulnerabilities_only(),
        )
        .await
        .expect("analyze_manifest");
        plan_security_updates(
            &analysis,
            self.ecosystem.as_ref(),
            &self.ctx.osv,
            &[],
            &IgnoreRules::empty(),
            self.ctx.policy.freshness.to_freshness(),
            FetchTimeout::try_from_secs(30).expect("timeout"),
        )
        .await
    }
}

const FIXABLE: PublicVersions<'static> = &[("1.0.0", 100 * DAY, false), ("1.0.1", 3 * DAY, false)];

#[tokio::test]
async fn security_fix_inside_the_window_is_applied_and_annotated() {
    let held = public_fixture(WINDOW_7D, FIXABLE, "1.0.1").await;
    let plain = public_fixture("", FIXABLE, "1.0.1").await;
    let (h, p) = (held.security_plan().await, plain.security_plan().await);
    assert_eq!(applied(&p), ["1.0.1"], "control: {:#?}", p.items);
    assert_eq!(applied(&h), ["1.0.1"], "{:#?}", h.items);
    assert!(
        h.items[0]
            .reason()
            .contains("inside npm min-release-age = 7 days"),
        "{}",
        h.items[0].reason()
    );
    assert!(
        !p.items[0].reason().contains("inside"),
        "{}",
        p.items[0].reason()
    );
}

#[tokio::test]
async fn check_reports_the_advisory_identically_with_and_without_a_window() {
    let held = public_fixture(WINDOW_7D, FIXABLE, "1.0.1").await;
    let none = public_fixture("", FIXABLE, "1.0.1").await;
    let pick = |messages: Vec<String>| {
        messages
            .into_iter()
            .filter(|message| message.contains(ADVISORY))
            .collect::<Vec<_>>()
    };
    let (h, n) = (
        pick(held.check_messages().await),
        pick(none.check_messages().await),
    );
    assert!(!n.is_empty(), "control: the advisory is reported");
    assert_eq!(h, n);
}

/// `1.0.1` fixes the advisory but is deprecated; `1.0.2` is `latest`, one day old.
const DEPRECATED_FIX: PublicVersions<'static> = &[
    ("1.0.0", 100 * DAY, false),
    ("1.0.1", 50 * DAY, true),
    ("1.0.2", DAY, false),
];

#[tokio::test]
async fn deprecated_fix_steers_past_a_fresh_latest_only_when_publish_times_are_known() {
    let unknown = public_fixture("", DEPRECATED_FIX, "1.0.1").await;
    let known = public_fixture(WINDOW_7D, DEPRECATED_FIX, "1.0.1").await;
    assert_eq!(
        applied(&unknown.security_plan().await),
        ["1.0.2"],
        "control: without publish times the fresh latest is an acceptable steer target"
    );
    assert_eq!(
        applied(&known.security_plan().await),
        ["1.0.1"],
        "the window asks for publish times, so the one-day-old latest is not used"
    );
}

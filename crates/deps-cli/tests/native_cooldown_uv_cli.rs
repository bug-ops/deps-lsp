//! #2042 / spec 099 acceptance: uv's `exclude-newer` window through the real `deps-cli` pipeline
//! (`check_manifest`, `plan_updates`) with a `mockito` PEP 691 index bound to the dependency
//! through `[tool.uv.sources]`.
//!
//! Explain-only: a natively held `latest` is never written; the update is skipped as
//! `WithinNativeCooldown` (exit 0) with the same note `check` prints.

#![cfg(feature = "pypi")]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

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

const NOTE: &str = "excluded by uv exclude-newer = 7 days";

struct Fixture {
    _index: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    _dir: tempfile::TempDir,
    manifest: PathBuf,
    content: String,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
}

async fn fixture(tool_uv: &str) -> Fixture {
    let mut index = mockito::Server::new_async().await;
    let body = format!(
        r#"{{"meta":{{"api-version":"1.4"}},"name":"requests","versions":["2.31.0","2.32.0"],"files":[
        {{"filename":"requests-2.31.0.tar.gz","yanked":false,"upload-time":"{}"}},
        {{"filename":"requests-2.32.0.tar.gz","yanked":false,"upload-time":"{}"}}]}}"#,
        rfc3339(now_secs() - 100 * DAY),
        rfc3339(now_secs() - 3 * DAY),
    );
    let index_mock = index
        .mock("GET", "/simple/requests/")
        .with_status(200)
        .with_header("content-type", "application/vnd.pypi.simple.v1+json")
        .with_body(body)
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
    let content = format!(
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n{tool_uv}\n\n[tool.uv.sources]\nrequests = {{ index = \"mock\" }}\n\n[[tool.uv.index]]\nname = \"mock\"\nurl = \"{}/simple\"\nexplicit = true\n",
        index.url()
    );
    let manifest = root.join("pyproject.toml");
    std::fs::write(&manifest, &content).expect("manifest");
    std::fs::write(
        root.join("uv.lock"),
        "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
    )
    .expect("lock");

    let policy = PolicyConfig {
        registries: RegistriesConfig::new()
            .with_workspace_registries(WorkspaceRegistriesSetting::All),
        ..PolicyConfig::default()
    };
    let host = index.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let runtime = EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&env));
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);
    let ecosystem = registry.get(EcosystemId::Pypi).expect("pypi registered");
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
        policy,
    };
    Fixture {
        _index: index,
        _osv: osv,
        _mocks: vec![index_mock, osv_mock],
        _dir: dir,
        manifest,
        content,
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
            &self.content,
            &self.ctx,
        )
        .await
        .expect("check_manifest")
        .findings
        .into_iter()
        .map(|f| f.message)
        .collect()
    }

    async fn update_plan(&self) -> UpdatePlan {
        let analysis = analyze_manifest(
            &self.ecosystem,
            &self.manifest,
            &self.content,
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
            &self.content,
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
        .filter_map(|i| match &i.outcome {
            Outcome::Applied { target, .. } => Some(target.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn check_names_the_uv_source_and_remaining_time() {
    let fx = fixture("exclude-newer = \"7 days\"").await;
    let messages = fx.check_messages().await;
    let held: Vec<_> = messages.iter().filter(|m| m.contains(NOTE)).collect();
    assert_eq!(held.len(), 1, "{messages:?}");
    assert!(
        held[0].contains("2.32.0") && held[0].contains("eligible in"),
        "{held:?}"
    );
}

#[tokio::test]
async fn update_skips_the_held_latest_as_within_native_cooldown_and_exits_zero() {
    let fx = fixture("exclude-newer = \"7 days\"").await;
    let plan = fx.update_plan().await;
    assert!(applied(&plan).is_empty(), "{:#?}", plan.items);
    let skipped: Vec<_> = plan
        .items
        .iter()
        .filter(|i| {
            matches!(
                i.outcome,
                Outcome::Skipped {
                    reason: SkipReason::WithinNativeCooldown,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(skipped.len(), 1, "{:#?}", plan.items);
    assert!(
        skipped[0].reason().contains(NOTE),
        "{}",
        skipped[0].reason()
    );
    let run = deps_cli::update::UpdateRun {
        plan,
        lockfile: deps_cli::update::regen::LockfileOutcome::NotApplicable(
            deps_cli::update::regen::NotApplicableReason::NothingApplied,
        ),
    };
    assert_eq!(update_exit_code(&run), 0);
}

#[tokio::test]
async fn without_uv_config_the_latest_is_applied_and_check_has_no_note() {
    let fx = fixture("# nothing configured").await;
    assert_eq!(applied(&fx.update_plan().await), ["2.32.0"]);
    assert!(
        fx.check_messages()
            .await
            .iter()
            .all(|m| !m.contains("excluded by"))
    );
}

// ---- advisories: the index is the public tier, so OSV is asked ------------------------------

async fn public_fixture(tool_uv: &str) -> Fixture {
    let mut index = mockito::Server::new_async().await;
    let body = format!(
        r#"{{"meta":{{"api-version":"1.4"}},"name":"requests","versions":["2.31.0","2.32.0"],"files":[
        {{"filename":"requests-2.31.0.tar.gz","yanked":false,"upload-time":"{}"}},
        {{"filename":"requests-2.32.0.tar.gz","yanked":false,"upload-time":"{}"}}]}}"#,
        rfc3339(now_secs() - 100 * DAY),
        rfc3339(now_secs() - 3 * DAY),
    );
    let index_mock = index
        .mock("GET", "/simple/requests/")
        .with_status(200)
        .with_header("content-type", "application/vnd.pypi.simple.v1+json")
        .with_body(body)
        .expect_at_least(0)
        .create_async()
        .await;
    let (osv, mut mocks) = osv_with_advisory(&AdvisoryFixture {
        ecosystem: "PyPI",
        package: "requests",
        range_type: "ECOSYSTEM",
        vulnerable: "2.31.0",
        fixed: "2.32.0",
    })
    .await;
    mocks.push(index_mock);

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let content = format!(
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n\n[tool.uv]\n{tool_uv}\n"
    );
    let manifest = root.join("pyproject.toml");
    std::fs::write(&manifest, &content).expect("manifest");
    std::fs::write(
        root.join("uv.lock"),
        "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
    )
    .expect("lock");

    let policy = PolicyConfig::default();
    let base = url::Url::parse(&format!("{}/simple", index.url())).expect("mock url");
    let runtime =
        EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&MapEnv::new()))
            .with_pypi_public_base_for_test(base);
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);
    let ecosystem = registry.get(EcosystemId::Pypi).expect("pypi registered");
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
        policy,
    };
    Fixture {
        _index: index,
        _osv: osv,
        _mocks: mocks,
        _dir: dir,
        manifest,
        content,
        ctx,
        ecosystem,
    }
}

impl Fixture {
    async fn security_plan(&self) -> UpdatePlan {
        let analysis = analyze_manifest(
            &self.ecosystem,
            &self.manifest,
            &self.content,
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

#[tokio::test]
async fn security_fix_inside_the_window_is_applied_and_annotated() {
    let held = public_fixture("exclude-newer = \"7 days\"").await;
    let plain = public_fixture("# nothing configured").await;
    let (h, p) = (held.security_plan().await, plain.security_plan().await);
    assert_eq!(applied(&p), ["2.32.0"], "control: {:#?}", p.items);
    assert_eq!(applied(&h), ["2.32.0"], "{:#?}", h.items);
    assert!(
        h.items[0]
            .reason()
            .contains("inside uv exclude-newer = 7 days"),
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
    let held = public_fixture("exclude-newer = \"7 days\"").await;
    let none = public_fixture("# nothing configured").await;
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

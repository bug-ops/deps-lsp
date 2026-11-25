//! Acceptance tests (tester-owned) for #2190: `check` judges "outdated" against the newest
//! version eligible under the freshness cooldown or Cargo's native window, and `update` proposes
//! it under a native hold. Real pipeline, `mockito` sparse index and OSV.

#![cfg(feature = "cargo")]
#![expect(clippy::expect_used, reason = "test code")]

use std::path::PathBuf;
use std::sync::Arc;

use deps_cli::analyze::{AnalysisScope, analyze_manifest};
use deps_cli::report::{CheckContext, check_manifest};
use deps_cli::update::ignore::IgnoreRules;
use deps_cli::update::{Outcome, plan_updates};
use deps_core::lsp_helpers::exemption::OperatorExemptions;
use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::{PolicyConfig, RegistriesConfig, WorkspaceRegistriesSetting};
use deps_core::{Ecosystem, EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

const DAY: i64 = 86_400;
const NATIVE_7D: &str = "[registry]\nglobal-min-publish-age = \"7 days\"\n";
const OUTDATED: &str = "Newer version available";

fn pubtime(age_secs: i64) -> String {
    let epoch = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits")
        - age_secs;
    let (days, rem) = (epoch.div_euclid(DAY), epoch.rem_euclid(DAY));
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
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
    manifest: PathBuf,
    content: String,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
    _dir: tempfile::TempDir,
    _index: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
}

/// `rmcp = "=<in_use>"` locked at `in_use`; `versions` is `(version, age in days)`, newest first.
async fn fixture(cargo_config: &str, in_use: &str, versions: &[(&str, i64)]) -> Fixture {
    let mut index = mockito::Server::new_async().await;
    let lines = versions
        .iter()
        .map(|(v, days)| {
            format!(
                r#"{{"name":"rmcp","vers":"{v}","yanked":false,"features":{{}},"deps":[],"pubtime":"{}"}}"#,
                pubtime(days * DAY)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut mocks = vec![
        index
            .mock("GET", "/rm/cp/rmcp")
            .with_body(lines)
            .expect_at_least(0)
            .create_async()
            .await,
    ];
    let mut osv = mockito::Server::new_async().await;
    mocks.push(
        osv.mock("POST", "/v1/querybatch")
            .with_body_from_request(|request| {
                let body: serde_json::Value =
                    serde_json::from_slice(request.body().expect("body")).expect("batch json");
                let queries = body
                    .get("queries")
                    .and_then(serde_json::Value::as_array)
                    .expect("queries")
                    .len();
                let results = vec![serde_json::json!({"vulns": []}); queries];
                serde_json::json!({ "results": results })
                    .to_string()
                    .into_bytes()
            })
            .expect_at_least(0)
            .create_async()
            .await,
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::create_dir_all(root.join(".cargo")).expect("cargo dir");
    std::fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+{}\"\n{cargo_config}",
            index.url()
        ),
    )
    .expect("config");
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 4\n\n[[package]]\nname = \"rmcp\"\nversion = \"{in_use}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ),
    )
    .expect("lock");
    let content = format!(
        "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"={in_use}\"\n"
    );
    let manifest = root.join("Cargo.toml");
    std::fs::write(&manifest, &content).expect("manifest");

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
    let ecosystem = registry.get(EcosystemId::Cargo).expect("cargo registered");
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::for_test(Arc::clone(&cache), osv.url())),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        advisory_exemptions: Arc::new(OperatorExemptions::none()),
        policy,
    };
    Fixture {
        manifest,
        content,
        ctx,
        ecosystem,
        _dir: dir,
        _index: index,
        _osv: osv,
        _mocks: mocks,
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

    async fn applied_updates(&self) -> Vec<String> {
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
        .items
        .iter()
        .filter_map(|i| match &i.outcome {
            Outcome::Applied { target, .. } => Some(target.as_str().to_owned()),
            _ => None,
        })
        .collect()
    }
}

/// `(cargo config, age of the held latest in days)`: the freshness cooldown, then the native window.
const HOLDS: [(&str, i64); 2] = [("", 1), (NATIVE_7D, 5)];

#[tokio::test]
async fn check_with_nothing_eligible_newer_reports_no_outdated_finding() {
    for (config, latest_age) in HOLDS {
        let fx = fixture(config, "3.8.0", &[("3.9.0", latest_age), ("3.8.0", 100)]).await;

        let messages = fx.check_messages().await;

        assert!(
            messages.iter().all(|m| !m.contains(OUTDATED)),
            "config {config:?}: {messages:?}"
        );
    }
}

#[tokio::test]
async fn check_with_an_eligible_newer_version_names_it_before_the_held_latest() {
    for (config, latest_age) in HOLDS {
        let versions = [("3.9.0", latest_age), ("3.8.0", 50), ("3.7.0", 100)];
        let fx = fixture(config, "3.7.0", &versions).await;

        let messages = fx.check_messages().await;

        assert!(
            messages
                .iter()
                .any(|m| m.starts_with("Newer version available: 3.8.0 (3.9.0")),
            "config {config:?}: {messages:?}"
        );
    }
}

#[tokio::test]
async fn update_under_a_native_hold_proposes_the_newest_eligible_version() {
    let versions = [("3.9.0", 5), ("3.8.0", 50), ("3.7.0", 100)];
    let fx = fixture(NATIVE_7D, "3.7.0", &versions).await;

    assert_eq!(fx.applied_updates().await, ["3.8.0"]);
}

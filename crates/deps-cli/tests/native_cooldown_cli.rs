//! #1982 / spec 099 Phase 1 acceptance: Cargo's native `min-publish-age` window through the real
//! `deps-cli` pipeline (`check_manifest`, `analyze_manifest`, `plan_updates`,
//! `plan_security_updates`) with a `mockito` sparse index (reached through
//! `[source.crates-io] replace-with`) and a counting `mockito` OSV server.
//!
//! Explain-only (user decision C1(ii)): a natively held `latest` is never written; the update is
//! skipped as `WithinNativeCooldown` (exit 0) with the same note `check` prints (FR-016); a
//! valid spec-075 fallback still applies exactly as before the feature; the vulnerability fix is
//! kept and annotated; the OSV request count never changes (NFR-004).

#![cfg(feature = "cargo")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    FetchTimeout, NativeCooldownMode, PolicyConfig, RegistriesConfig, WorkspaceRegistriesSetting,
};
use deps_core::{Ecosystem, EcosystemId, EcosystemRegistry, HttpCache};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use serde_json::json;

const DAY: i64 = 86_400;
const MANIFEST: &str =
    "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"=3.8.0\"\n";
const WINDOW_7D: &str = "[registry]\nglobal-min-publish-age = \"7 days\"\n";
const NOTE: &str = "excluded by cargo registry.global-min-publish-age = 7 days";
const ADVISORY: &str = "RUSTSEC-2026-0001";

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
    let days = epoch.div_euclid(DAY);
    let rem = epoch.rem_euclid(DAY);
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

struct Advisory {
    introduced: &'static str,
    fixed: Option<&'static str>,
    /// When set, OSV reports the advisory only for queries of exactly this version.
    only_version: Option<&'static str>,
}

struct Setup {
    cargo_config: Option<&'static str>,
    /// `(version, age in seconds)`, newest first.
    versions: Vec<(&'static str, i64)>,
    advisory: Option<Advisory>,
    honor: NativeCooldownMode,
}

impl Setup {
    fn new(cargo_config: Option<&'static str>, versions: &[(&'static str, i64)]) -> Self {
        Self {
            cargo_config,
            versions: versions.to_vec(),
            advisory: None,
            honor: NativeCooldownMode::Honor,
        }
    }

    fn latest_age(cargo_config: Option<&'static str>, age: i64) -> Self {
        Self::new(cargo_config, &[("3.9.0", age), ("3.8.0", 100 * DAY)])
    }
}

struct Fixture {
    _index: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    _dir: tempfile::TempDir,
    manifest: PathBuf,
    ctx: CheckContext,
    ecosystem: Arc<dyn Ecosystem>,
    osv_hits: Arc<AtomicUsize>,
}

async fn fixture(setup: Setup) -> Fixture {
    let mut index = mockito::Server::new_async().await;
    let lines = setup
        .versions
        .iter()
        .map(|(v, age)| {
            format!(
                r#"{{"name":"rmcp","vers":"{v}","yanked":false,"features":{{}},"deps":[],"pubtime":"{}"}}"#,
                rfc3339(now_secs() - age)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let index_mock = index
        .mock("GET", "/rm/cp/rmcp")
        .with_status(200)
        .with_body(lines)
        .expect_at_least(0)
        .create_async()
        .await;

    let mut osv = mockito::Server::new_async().await;
    let osv_hits = Arc::new(AtomicUsize::new(0));
    let mut mocks = vec![index_mock];
    let vulns = if setup.advisory.is_some() {
        format!(r#"{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z"}}"#)
    } else {
        String::new()
    };
    let hits = Arc::clone(&osv_hits);
    let only_version = setup.advisory.as_ref().and_then(|a| a.only_version);
    mocks.push(
        osv.mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body_from_request(move |request| {
                hits.fetch_add(1, Ordering::SeqCst);
                let body: serde_json::Value =
                    serde_json::from_slice(request.body().expect("body")).expect("batch json");
                let results = body
                    .get("queries")
                    .and_then(serde_json::Value::as_array)
                    .expect("queries")
                    .iter()
                    .map(|q| {
                        let hit = only_version.is_none_or(|v| q.get("version") == Some(&json!(v)));
                        let list = if hit { vulns.as_str() } else { "" };
                        format!(r#"{{"vulns":[{list}]}}"#)
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#"{{"results":[{results}]}}"#).into_bytes()
            })
            .expect_at_least(0)
            .create_async()
            .await,
    );
    if let Some(advisory) = &setup.advisory {
        let hits = Arc::clone(&osv_hits);
        let fixed = advisory
            .fixed
            .map(|f| format!(r#",{{"fixed":"{f}"}}"#))
            .unwrap_or_default();
        let introduced = advisory.introduced;
        mocks.push(
            osv.mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
                .with_status(200)
                .with_body_from_request(move |_| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    format!(
                        r#"{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z","summary":"s",
                        "affected":[{{"package":{{"name":"rmcp","ecosystem":"crates.io"}},
                        "ranges":[{{"type":"SEMVER","events":[{{"introduced":"{introduced}"}}{fixed}]}}]}}]}}"#
                    )
                    .into_bytes()
                })
                .expect_at_least(0)
                .create_async()
                .await,
        );
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::create_dir_all(root.join(".cargo")).expect("cargo dir");
    std::fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+{}\"\n{}",
            index.url(),
            setup.cargo_config.unwrap_or_default()
        ),
    )
    .expect("config");
    std::fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"rmcp\"\nversion = \"3.8.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .expect("lock");
    let manifest = root.join("Cargo.toml");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let mut policy = PolicyConfig {
        registries: RegistriesConfig::new()
            .with_workspace_registries(WorkspaceRegistriesSetting::All),
        ..PolicyConfig::default()
    };
    policy.freshness.honor_native_cooldown = setup.honor;
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
        _index: index,
        _osv: osv,
        _mocks: mocks,
        _dir: dir,
        manifest,
        ctx,
        ecosystem,
        osv_hits,
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
        .map(|f| f.message)
        .collect()
    }

    async fn analyze(&self, scope: AnalysisScope) -> deps_cli::analyze::ManifestAnalysis {
        analyze_manifest(&self.ecosystem, &self.manifest, MANIFEST, &self.ctx, scope)
            .await
            .expect("analyze_manifest")
    }

    async fn update_plan(&self) -> UpdatePlan {
        let analysis = self.analyze(AnalysisScope::update_default()).await;
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

    async fn security_plan(&self) -> UpdatePlan {
        let analysis = self.analyze(AnalysisScope::vulnerabilities_only()).await;
        plan_security_updates(
            &analysis,
            self.ecosystem.as_ref(),
            &self.ctx.osv,
            &[],
            &IgnoreRules::empty(),
            FetchTimeout::try_from_secs(30).expect("timeout"),
        )
        .await
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

fn within_native(plan: &UpdatePlan) -> Vec<&deps_cli::update::PlannedUpdateItem> {
    plan.items
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
        .collect()
}

#[tokio::test]
async fn check_outdated_finding_names_the_native_source_and_remaining_time() {
    let fx = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    let messages = fx.check_messages().await;
    let held: Vec<_> = messages.iter().filter(|m| m.contains(NOTE)).collect();
    assert_eq!(held.len(), 1, "{messages:?}");
    assert!(
        held[0].contains("3.9.0") && held[0].contains("eligible in"),
        "{held:?}"
    );
}

#[tokio::test]
async fn check_without_native_config_has_no_note() {
    let fx = fixture(Setup::latest_age(None, 3 * DAY)).await;
    assert!(
        fx.check_messages()
            .await
            .iter()
            .all(|m| !m.contains("excluded by"))
    );
}

#[tokio::test]
async fn update_skips_held_latest_as_within_native_cooldown_with_the_same_note_and_exit_zero() {
    let fx = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    let plan = fx.update_plan().await;
    assert!(applied(&plan).is_empty(), "{:#?}", plan.items);
    let skipped = within_native(&plan);
    assert_eq!(skipped.len(), 1, "{:#?}", plan.items);
    assert!(
        skipped[0].reason().contains(NOTE),
        "{}",
        skipped[0].reason()
    );
    assert_eq!(update_exit_code(&plan), 0);

    let check = fx.check_messages().await;
    assert!(
        check.iter().any(|m| m.contains(NOTE)),
        "FR-016: both interfaces explain with the same source label"
    );
}

#[tokio::test]
async fn update_without_native_config_applies_the_latest() {
    let fx = fixture(Setup::latest_age(None, 3 * DAY)).await;
    assert_eq!(applied(&fx.update_plan().await), ["3.9.0"]);
}

#[tokio::test]
async fn update_applies_latest_published_beyond_the_window() {
    let control = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    assert!(
        applied(&control.update_plan().await).is_empty(),
        "control: inside the window nothing is applied"
    );
    let fx = fixture(Setup::latest_age(Some(WINDOW_7D), 8 * DAY)).await;
    let plan = fx.update_plan().await;
    assert_eq!(applied(&plan), ["3.9.0"]);
    assert!(within_native(&plan).is_empty());
}

#[tokio::test]
async fn opt_out_update_and_check_match_a_project_without_native_config() {
    let mut off = Setup::latest_age(Some(WINDOW_7D), 3 * DAY);
    off.honor = NativeCooldownMode::Ignore;
    let off = fixture(off).await;
    let none = fixture(Setup::latest_age(None, 3 * DAY)).await;
    let on = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    assert_ne!(
        on.check_messages().await,
        none.check_messages().await,
        "control: the window changes check output when honored"
    );
    assert_eq!(off.check_messages().await, none.check_messages().await);
    assert_eq!(
        applied(&off.update_plan().await),
        applied(&none.update_plan().await)
    );
}

#[tokio::test]
async fn fetch_output_carries_publish_times_aligned_with_the_version_list() {
    let fx = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    let analysis = fx.analyze(AnalysisScope::update_default()).await;
    let (_, versions) = analysis.cached_versions.iter().next().expect("one package");
    assert_eq!(versions.publish_times.len(), versions.available.len());
    assert!(versions.publish_times.iter().all(Option::is_some));
}

// ---- security-only: the fix is kept and annotated ------------------------------------------

#[tokio::test]
async fn security_only_applies_the_fix_inside_the_window_and_annotates_the_reason() {
    let mut held = Setup::latest_age(Some(WINDOW_7D), 3 * DAY);
    held.advisory = Some(Advisory {
        introduced: "0",
        fixed: Some("3.9.0"),
        only_version: Some("3.8.0"),
    });
    let held = fixture(held).await;
    let mut plain = Setup::latest_age(None, 3 * DAY);
    plain.advisory = Some(Advisory {
        introduced: "0",
        fixed: Some("3.9.0"),
        only_version: Some("3.8.0"),
    });
    let plain = fixture(plain).await;

    let (h, p) = (held.security_plan().await, plain.security_plan().await);
    assert_eq!(
        applied(&h),
        applied(&p),
        "target never changes because of the window"
    );
    assert_eq!(applied(&h), ["3.9.0"], "{:#?}", h.items);
    assert_eq!(h.items[0].advisory_ids, p.items[0].advisory_ids);
    assert!(
        h.items[0]
            .reason()
            .contains("inside cargo registry.global-min-publish-age = 7 days"),
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
    let advisory = || Advisory {
        introduced: "0",
        fixed: Some("3.9.0"),
        only_version: Some("3.8.0"),
    };
    let mut held = Setup::latest_age(Some(WINDOW_7D), 3 * DAY);
    held.advisory = Some(advisory());
    let mut none = Setup::latest_age(None, 3 * DAY);
    none.advisory = Some(advisory());
    let (held, none) = (fixture(held).await, fixture(none).await);
    let pick = |ms: Vec<String>| {
        ms.into_iter()
            .filter(|m| m.contains(ADVISORY))
            .collect::<Vec<_>>()
    };
    let (h, n) = (
        pick(held.check_messages().await),
        pick(none.check_messages().await),
    );
    assert!(!n.is_empty());
    assert_eq!(h, n);
}

// ---- NativeHeld + spec-075 fallback, OSV request parity ------------------------------------

/// `4.0.0` (1 day old, a major bump so the fallback edit cannot admit it) is flagged and natively held; `3.8.5` is the cooldown-cleared fallback.
fn flagged_latest_setup(config: Option<&'static str>) -> Setup {
    let mut s = Setup::new(
        config,
        &[("4.0.0", DAY), ("3.8.5", 30 * DAY), ("3.8.0", 100 * DAY)],
    );
    s.advisory = Some(Advisory {
        introduced: "4.0.0",
        fixed: None,
        only_version: Some("4.0.0"),
    });
    s
}

#[tokio::test]
async fn flagged_and_held_latest_still_applies_the_valid_fallback_exactly_as_before() {
    let held = fixture(flagged_latest_setup(Some(WINDOW_7D))).await;
    let none = fixture(flagged_latest_setup(None)).await;
    let (h, n) = (held.update_plan().await, none.update_plan().await);
    assert!(
        !applied(&n).is_empty(),
        "control: fallback applies pre-feature: {:#?}",
        n.items
    );
    assert_eq!(applied(&h), applied(&n));
    assert!(within_native(&h).is_empty(), "{:#?}", h.items);
}

#[tokio::test]
async fn native_window_adds_no_osv_request_in_the_fallback_round() {
    let held = fixture(flagged_latest_setup(Some(WINDOW_7D))).await;
    let none = fixture(flagged_latest_setup(None)).await;
    held.update_plan().await;
    none.update_plan().await;
    let (h, n) = (
        held.osv_hits.load(Ordering::SeqCst),
        none.osv_hits.load(Ordering::SeqCst),
    );
    assert!(n > 0, "control must reach OSV");
    assert_eq!(h, n);
}

#[tokio::test]
async fn native_window_adds_no_osv_request_for_a_plain_held_latest() {
    let held = fixture(Setup::latest_age(Some(WINDOW_7D), 3 * DAY)).await;
    let none = fixture(Setup::latest_age(None, 3 * DAY)).await;
    held.update_plan().await;
    none.update_plan().await;
    assert_eq!(
        held.osv_hits.load(Ordering::SeqCst),
        none.osv_hits.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn hostile_maximum_window_keeps_advisories_and_writes_no_default_edit() {
    let hostile = Some("[registry]\nglobal-min-publish-age = \"999999999 months\"\n");
    let mut held = Setup::latest_age(hostile, 400 * DAY);
    held.advisory = Some(Advisory {
        introduced: "0",
        fixed: Some("3.9.0"),
        only_version: Some("3.8.0"),
    });
    let held = fixture(held).await;
    assert!(applied(&held.update_plan().await).is_empty());
    assert!(
        held.check_messages()
            .await
            .iter()
            .any(|m| m.contains(ADVISORY)),
        "the advisory is never suppressed"
    );
    assert_eq!(applied(&held.security_plan().await), ["3.9.0"]);
}

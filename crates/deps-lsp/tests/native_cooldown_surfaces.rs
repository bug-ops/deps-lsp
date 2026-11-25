//! #1982 / spec 099 Phase 1 acceptance: Cargo's native `min-publish-age` window through the real
//! LSP handlers (hover, diagnostics, code actions, code lens), with a `mockito` sparse index
//! reached through `[source.crates-io] replace-with` and a counting `mockito` OSV server.
//!
//! Behaviour under test is explain-only (user decision C1(ii)): a held `latest` is named in hover
//! and the outdated diagnostic, no sink writes it, advisories are never suppressed, and the
//! vulnerability fix for the true latest stays listed and annotated. Publish times are set
//! relative to the real clock (production stamps `VersionData::now` from it), with margins of
//! hours around day-sized windows.

#![cfg(feature = "cargo")]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_core::osv::OsvClient;
use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, handle_document_open};
use deps_lsp::handlers::code_actions::handle_code_actions;
use deps_lsp::handlers::code_lens::handle_code_lens;
use deps_lsp::handlers::diagnostics::handle_diagnostics;
use deps_lsp::handlers::hover::handle_hover;
use deps_lsp::lsp_types_interop::to_lsp_uri;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower_lsp_server::ls_types::Uri;
use tower_lsp_server::{Client, LspService};

const DAY: i64 = 86_400;
const HOUR: i64 = 3_600;
const MANIFEST: &str =
    "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"=3.8.0\"\n";
const DEP_LINE: u32 = 5;
const WINDOW_7D: &str = "[registry]\nglobal-min-publish-age = \"7 days\"\n";
const HELD_NOTE: &str = "excluded by cargo registry.global-min-publish-age = 7 days";
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
        rem / HOUR,
        rem % HOUR / 60,
        rem % 60
    )
}

fn index_line(version: &str, age_secs: i64) -> String {
    format!(
        r#"{{"name":"rmcp","vers":"{version}","yanked":false,"features":{{}},"deps":[],"pubtime":"{}"}}"#,
        rfc3339(now_secs() - age_secs)
    )
}

fn lock(versions: &[&str]) -> String {
    let mut out = String::from("version = 4\n");
    for v in versions {
        out.push_str(&format!(
            "\n[[package]]\nname = \"rmcp\"\nversion = \"{v}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ));
    }
    out
}

struct Setup {
    cargo_config: Option<String>,
    /// `(version, age in seconds)`, newest first.
    versions: Vec<(&'static str, i64)>,
    lock: Vec<&'static str>,
    settings: Value,
    advisory_fixed_in: Option<&'static str>,
}

impl Setup {
    /// `3.9.0` published `latest_age` ago, `3.8.0` 100 days ago, lock `3.8.0`.
    fn new(cargo_config: Option<&str>, latest_age: i64) -> Self {
        Self {
            cargo_config: cargo_config.map(str::to_owned),
            versions: vec![("3.9.0", latest_age), ("3.8.0", 100 * DAY)],
            lock: vec!["3.8.0"],
            settings: json!({}),
            advisory_fixed_in: None,
        }
    }

    fn settings(mut self, settings: Value) -> Self {
        self.settings = settings;
        self
    }

    fn advisory(mut self, fixed_in: &'static str) -> Self {
        self.advisory_fixed_in = Some(fixed_in);
        self
    }

    fn lock(mut self, lock: &[&'static str]) -> Self {
        self.lock = lock.to_vec();
        self
    }
}

struct Fixture {
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
    client: Client,
    uri: Uri,
    index_hits: Arc<AtomicUsize>,
    osv_hits: Arc<AtomicUsize>,
    server: mockito::ServerGuard,
    _service: LspService<Backend>,
    _dir: tempfile::TempDir,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
}

fn settings_json(extra: Value, vulnerabilities: bool) -> Value {
    let mut base = json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": {"vulnerabilities_enabled": vulnerabilities},
    });
    let object = base.as_object_mut().expect("settings object");
    for (k, v) in extra.as_object().expect("settings object") {
        object.insert(k.clone(), v.clone());
    }
    base
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear fixture: index and OSV mocks, repository files, state, document open"
)]
async fn fixture(setup: Setup) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let index_hits = Arc::new(AtomicUsize::new(0));
    let lines = setup
        .versions
        .iter()
        .map(|(v, age)| index_line(v, *age))
        .collect::<Vec<_>>()
        .join("\n");
    let hits = Arc::clone(&index_hits);
    let index_mock = server
        .mock("GET", "/rm/cp/rmcp")
        .with_status(200)
        .with_body_from_request(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            lines.clone().into_bytes()
        })
        .expect_at_least(0)
        .create_async()
        .await;

    let mut osv = mockito::Server::new_async().await;
    let osv_hits = Arc::new(AtomicUsize::new(0));
    let mut mocks = vec![index_mock];
    if let Some(fixed) = setup.advisory_fixed_in {
        let hits = Arc::clone(&osv_hits);
        mocks.push(
            osv.mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body_from_request(move |request| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let body: Value =
                        serde_json::from_slice(request.body().expect("body")).expect("batch json");
                    let results = body
                        .get("queries")
                        .and_then(Value::as_array)
                        .expect("queries")
                        .iter()
                        .map(|q| {
                            let in_use = q.get("version") == Some(&json!("3.8.0"));
                            let list = if in_use {
                                format!(
                                    r#"{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z"}}"#
                                )
                            } else {
                                String::new()
                            };
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
        let hits = Arc::clone(&osv_hits);
        mocks.push(
            osv.mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
                .with_status(200)
                .with_body_from_request(move |_| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    format!(
                        r#"{{"id":"{ADVISORY}","modified":"2026-01-01T00:00:00Z","summary":"s",
                        "affected":[{{"package":{{"name":"rmcp","ecosystem":"crates.io"}},
                        "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
                    )
                    .into_bytes()
                })
                .expect_at_least(0)
                .create_async()
                .await,
        );
    } else {
        mocks.push(
            osv.mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body_from_request({
                    let hits = Arc::clone(&osv_hits);
                    move |_| {
                        hits.fetch_add(1, Ordering::SeqCst);
                        br#"{"results":[{"vulns":[]}]}"#.to_vec()
                    }
                })
                .expect_at_least(0)
                .create_async()
                .await,
        );
    }

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let mirror = format!(
        "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+{}\"\n",
        server.url()
    );
    std::fs::create_dir_all(root.join(".cargo")).expect("cargo dir");
    std::fs::write(
        root.join(".cargo/config.toml"),
        format!("{mirror}{}", setup.cargo_config.unwrap_or_default()),
    )
    .expect("config");
    std::fs::write(root.join("Cargo.lock"), lock(&setup.lock)).expect("lock");
    let path = root.join("Cargo.toml");
    std::fs::write(&path, MANIFEST).expect("manifest");

    let host = server.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let mut state = ServerState::from_env_source(&env);
    state.osv = Arc::new(OsvClient::for_test(Arc::clone(&state.cache), osv.url()));
    let state = Arc::new(state);
    state
        .cache
        .set_registry_policy(deps_core::policy_config::WorkspaceRegistriesSetting::All.to_policy());
    let vulnerabilities = setup.advisory_fixed_in.is_some();
    let config: DepsConfig =
        serde_json::from_value(settings_json(setup.settings, vulnerabilities)).expect("config");
    state
        .native_cooldown
        .set(config.policy.freshness.honor_native_cooldown);
    let config = Arc::new(RwLock::new(config));

    let slot = std::sync::Mutex::new(None);
    let (service, _socket) = LspService::new(|client| {
        *slot.lock().expect("slot") = Some(client.clone());
        Backend::new(client)
    });
    let client = slot.into_inner().expect("slot").expect("client");
    let uri = to_lsp_uri(&url::Url::from_file_path(&path).expect("file url"));
    let opened = handle_document_open(
        uri.clone(),
        MANIFEST.to_owned(),
        Some(1),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    .expect("document opens");
    assert!(opened);
    tokio::time::timeout(Duration::from_secs(10), async {
        while !state
            .with_document(&uri, |doc| {
                matches!(
                    doc.loading_state(),
                    deps_core::LoadingState::Loaded | deps_core::LoadingState::Failed
                )
            })
            .unwrap_or(false)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("load settles");

    let fx = Fixture {
        state,
        config,
        client,
        uri,
        index_hits,
        osv_hits,
        server,
        _service: service,
        _dir: dir,
        _osv: osv,
        _mocks: mocks,
    };
    if vulnerabilities {
        fx.wait_for_advisory().await;
    }
    fx
}

impl Fixture {
    /// OSV phase B commits after the document reports `Loaded`, so diagnostics read straight
    /// after the open can predate the advisory (#2094); poll, bounded, until it is published.
    async fn wait_for_advisory(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while advisory_diagnostics(&self.diagnostics().await).is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the OSV advisory diagnostic is published");
    }

    async fn hover(&self) -> String {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
            "position": {"line": DEP_LINE, "character": 2},
        }))
        .expect("hover params");
        let hover = handle_hover(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        serde_json::to_string(&hover.expect("hover")).expect("serialize")
    }

    async fn diagnostics(&self) -> Vec<Value> {
        handle_diagnostics(
            Arc::clone(&self.state),
            &self.uri,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .iter()
        .map(|d| serde_json::to_value(d).expect("diagnostic"))
        .collect()
    }

    async fn lens_titles(&self) -> Vec<String> {
        let params = serde_json::from_value(json!({"textDocument": {"uri": self.uri.as_str()}}))
            .expect("lens params");
        handle_code_lens(
            Arc::clone(&self.state),
            params,
            true,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .iter()
        .filter_map(|l| l.command.as_ref().map(|c| c.title.clone()))
        .collect()
    }

    async fn action_titles(&self) -> Vec<String> {
        let diagnostics = self.diagnostics().await;
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
            "range": {"start": {"line": DEP_LINE, "character": 10}, "end": {"line": DEP_LINE, "character": 10}},
            "context": {"diagnostics": diagnostics},
        }))
        .expect("action params");
        handle_code_actions(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .iter()
        .filter_map(|a| {
            serde_json::to_value(a)
                .ok()?
                .get("title")?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
    }

    /// Every user-visible surface, for byte-identical comparisons.
    async fn surfaces(&self) -> String {
        format!(
            "{}\n{:?}\n{:?}\n{:?}",
            self.hover().await,
            self.diagnostics().await,
            self.lens_titles().await,
            self.action_titles().await
        )
    }
}

fn messages(diagnostics: &[Value]) -> Vec<String> {
    diagnostics
        .iter()
        .filter_map(|d| d.get("message")?.as_str().map(str::to_owned))
        .collect()
}

fn advisory_diagnostics(diagnostics: &[Value]) -> Vec<Value> {
    diagnostics
        .iter()
        .filter(|d| d.to_string().contains(ADVISORY))
        .cloned()
        .collect()
}

fn updates_to(titles: &[String], version: &str) -> Vec<String> {
    titles
        .iter()
        .filter(|t| t.contains(version))
        .cloned()
        .collect()
}

// ---- US-001 / SC-001 -----------------------------------------------------------------------

#[tokio::test]
async fn baseline_without_native_config_offers_the_update_and_no_note() {
    let fx = fixture(Setup::new(None, 3 * DAY)).await;
    assert!(!fx.hover().await.contains("excluded by"));
    assert!(
        messages(&fx.diagnostics().await)
            .iter()
            .all(|m| !m.contains("excluded by"))
    );
    assert_eq!(fx.lens_titles().await, ["Update 1 outdated dependency"]);
    assert!(!updates_to(&fx.action_titles().await, "3.9.0").is_empty());
}

#[tokio::test]
async fn hover_names_the_window_and_remaining_time_and_keeps_the_true_latest() {
    let fx = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    let hover = fx.hover().await;
    assert!(hover.contains(HELD_NOTE), "{hover}");
    assert!(hover.contains("eligible in"), "{hover}");
    assert!(hover.contains("**Latest**: `3.9.0`"), "{hover}");
}

#[tokio::test]
async fn outdated_diagnostic_names_the_native_source_and_keeps_its_kind_and_range() {
    // 3.8.5 gives the held 3.9.0 an eligible stand-in, so the diagnostic still has a subject.
    let with_eligible = |config| {
        let mut setup = Setup::new(config, 3 * DAY);
        setup.versions.insert(1, ("3.8.5", 50 * DAY));
        setup
    };
    let held = fixture(with_eligible(Some(WINDOW_7D))).await;
    let plain = fixture(with_eligible(None)).await;
    let held_diags = held.diagnostics().await;
    let plain_diags = plain.diagnostics().await;
    assert_eq!(held_diags.len(), plain_diags.len());
    let (h, p) = (&held_diags[0], &plain_diags[0]);
    assert_eq!(h["range"], p["range"]);
    assert_eq!(h["severity"], p["severity"]);
    assert_eq!(h["code"], p["code"]);
    let msg = h["message"].as_str().expect("message");
    assert!(
        msg.contains("3.8.5")
            && msg.contains("3.9.0")
            && msg.contains(HELD_NOTE)
            && msg.contains("eligible in"),
        "{msg}"
    );
}

#[tokio::test]
async fn held_latest_is_offered_by_no_action_and_no_lens() {
    let fx = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    assert!(fx.lens_titles().await.is_empty());
    let actions = fx.action_titles().await;
    assert!(updates_to(&actions, "3.9.0").is_empty(), "{actions:?}");
    assert!(
        actions.iter().all(|t| !t.contains("Update to")),
        "no update action to any version because of the window: {actions:?}"
    );
}

#[tokio::test]
async fn latest_published_beyond_the_window_is_eligible_and_unannotated() {
    let fx = fixture(Setup::new(Some(WINDOW_7D), 7 * DAY + 2 * HOUR)).await;
    assert!(!fx.hover().await.contains("excluded by"));
    assert_eq!(fx.lens_titles().await, ["Update 1 outdated dependency"]);
    assert!(!updates_to(&fx.action_titles().await, "3.9.0").is_empty());
}

#[tokio::test]
async fn latest_inside_the_window_by_a_margin_is_held() {
    let fx = fixture(Setup::new(Some(WINDOW_7D), 7 * DAY - 2 * HOUR)).await;
    assert!(fx.hover().await.contains(HELD_NOTE));
    assert!(fx.lens_titles().await.is_empty());
}

// ---- FR-006 lock exemption -----------------------------------------------------------------

#[tokio::test]
async fn transitive_duplicate_lock_entry_keeps_the_version_eligible() {
    let control = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    assert!(
        control.hover().await.contains(HELD_NOTE),
        "control: held with a plain lock"
    );
    let fx = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY).lock(&["3.8.0", "3.9.0"])).await;
    assert!(!fx.hover().await.contains("excluded by"));
    assert!(
        messages(&fx.diagnostics().await)
            .iter()
            .all(|m| !m.contains("excluded by"))
    );
}

// ---- opt-out, no-config identity, hostile and malformed config -----------------------------

#[tokio::test]
async fn opt_out_output_is_byte_identical_to_a_project_without_native_config() {
    let off = fixture(
        Setup::new(Some(WINDOW_7D), 3 * DAY)
            .settings(json!({"freshness": {"honor_native_cooldown": false}})),
    )
    .await;
    let none = fixture(Setup::new(None, 3 * DAY)).await;
    assert_eq!(off.surfaces().await, none.surfaces().await);
}

#[tokio::test]
async fn incompatible_publish_age_allow_output_is_byte_identical_to_no_native_config() {
    let cfg = format!("{WINDOW_7D}[resolver]\nincompatible-publish-age = \"allow\"\n");
    let allow = fixture(Setup::new(Some(&cfg), 3 * DAY)).await;
    let none = fixture(Setup::new(None, 3 * DAY)).await;
    let valid = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    assert_ne!(
        valid.surfaces().await,
        none.surfaces().await,
        "control: a valid window must change the output"
    );
    assert_eq!(allow.surfaces().await, none.surfaces().await);
}

#[tokio::test]
async fn malformed_window_output_is_byte_identical_to_no_native_config() {
    let bad = fixture(Setup::new(
        Some("[registry]\nglobal-min-publish-age = \"7 fortnights\"\n"),
        3 * DAY,
    ))
    .await;
    let none = fixture(Setup::new(None, 3 * DAY)).await;
    let valid = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    assert_ne!(
        valid.surfaces().await,
        none.surfaces().await,
        "control: a valid window must change the output"
    );
    assert_eq!(bad.surfaces().await, none.surfaces().await);
}

#[tokio::test]
async fn native_window_is_honored_even_when_freshness_is_disabled() {
    let fx = fixture(
        Setup::new(Some(WINDOW_7D), 3 * DAY).settings(json!({"freshness": {"enabled": false}})),
    )
    .await;
    assert!(fx.hover().await.contains(HELD_NOTE));
    assert!(fx.lens_titles().await.is_empty());
}

#[tokio::test]
async fn native_window_and_registry_fetch_count_is_not_increased() {
    let held = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    let none = fixture(Setup::new(None, 3 * DAY)).await;
    held.surfaces().await;
    none.surfaces().await;
    assert_eq!(
        held.index_hits.load(Ordering::SeqCst),
        none.index_hits.load(Ordering::SeqCst),
        "the window adds no registry request"
    );
}

// ---- US-005 / FR-011 / FR-012 / SC-004: advisories stay visible ----------------------------

fn fix_titles(titles: &[String]) -> Vec<String> {
    titles
        .iter()
        .filter(|t| t.contains(ADVISORY))
        .cloned()
        .collect()
}

#[tokio::test]
async fn vulnerability_diagnostic_is_identical_with_and_without_a_window() {
    let held = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY).advisory("3.9.0")).await;
    let none = fixture(Setup::new(None, 3 * DAY).advisory("3.9.0")).await;
    let (h, n) = (
        advisory_diagnostics(&held.diagnostics().await),
        advisory_diagnostics(&none.diagnostics().await),
    );
    assert!(!n.is_empty(), "control run must report the advisory");
    assert_eq!(h, n);
}

#[tokio::test]
async fn vulnerability_fix_is_listed_with_its_target_and_annotated_with_the_window() {
    let held = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY).advisory("3.9.0")).await;
    let none = fixture(Setup::new(None, 3 * DAY).advisory("3.9.0")).await;
    let plain = fix_titles(&none.action_titles().await);
    assert_eq!(plain.len(), 1, "{plain:?}");
    assert!(!plain[0].contains("inside"), "{plain:?}");

    let annotated = fix_titles(&held.action_titles().await);
    assert_eq!(annotated.len(), 1, "{annotated:?}");
    assert!(annotated[0].contains("Update to 3.9.0"), "{annotated:?}");
    assert!(
        annotated[0].contains(&format!("fixes {ADVISORY}")),
        "{annotated:?}"
    );
    assert!(
        annotated[0].contains(&format!("inside {HELD_NOTE_SOURCE}")),
        "{annotated:?}"
    );
}

const HELD_NOTE_SOURCE: &str = "cargo registry.global-min-publish-age = 7 days";

#[tokio::test]
async fn vulnerability_fix_is_not_annotated_once_the_window_has_passed() {
    let fx = fixture(Setup::new(Some(WINDOW_7D), 7 * DAY + 2 * HOUR).advisory("3.9.0")).await;
    let titles = fix_titles(&fx.action_titles().await);
    assert_eq!(titles.len(), 1, "{titles:?}");
    assert!(!titles[0].contains("inside"), "{titles:?}");
}

#[tokio::test]
async fn hostile_maximum_window_suppresses_no_advisory_and_writes_no_edit() {
    let hostile = "[registry]\nglobal-min-publish-age = \"999999999 months\"\n";
    let held = fixture(Setup::new(Some(hostile), 400 * DAY).advisory("3.9.0")).await;
    let none = fixture(Setup::new(None, 400 * DAY).advisory("3.9.0")).await;
    assert_eq!(
        advisory_diagnostics(&held.diagnostics().await),
        advisory_diagnostics(&none.diagnostics().await)
    );
    assert!(
        held.lens_titles().await.is_empty(),
        "no bulk edit under a hostile window"
    );
    let fixes = fix_titles(&held.action_titles().await);
    assert_eq!(fixes.len(), 1, "the advisory fix stays listed: {fixes:?}");
    assert!(fixes[0].contains("Update to 3.9.0"), "{fixes:?}");
}

/// NFR-004 / SC-005: the window adds no OSV request.
#[tokio::test]
async fn native_window_sends_exactly_as_many_osv_requests_as_no_window() {
    let held = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY).advisory("3.9.0")).await;
    let none = fixture(Setup::new(None, 3 * DAY).advisory("3.9.0")).await;
    held.surfaces().await;
    none.surfaces().await;
    let (h, n) = (
        held.osv_hits.load(Ordering::SeqCst),
        none.osv_hits.load(Ordering::SeqCst),
    );
    assert!(n > 0, "control run must reach OSV");
    assert_eq!(h, n);
}

// ---- S1: release published after the cached fetch ------------------------------------------

/// The cache was fetched while only `3.9.0` (held) was newest; a `3.9.1` published since then
/// appears in the live list the code-action path fetches. It is inside the window too, so no
/// plain update to either version may be offered, and hover must explain the displayed latest.
#[tokio::test]
async fn release_published_after_the_fetch_is_gated_on_its_live_publish_time() {
    let mut fx = fixture(Setup::new(Some(WINDOW_7D), 3 * DAY)).await;
    let before = fx.index_hits.load(Ordering::SeqCst);
    fx.server.reset();
    let newer = [
        index_line("3.9.1", 30 * 60),
        index_line("3.9.0", 3 * DAY),
        index_line("3.8.0", 100 * DAY),
    ]
    .join("\n");
    let _m = fx
        .server
        .mock("GET", "/rm/cp/rmcp")
        .with_status(200)
        .with_body(newer)
        .expect_at_least(0)
        .create_async()
        .await;

    let actions = fx.action_titles().await;
    assert!(
        fx.index_hits.load(Ordering::SeqCst) >= before,
        "sanity: counter is monotonic"
    );
    assert!(
        fx.hover().await.contains(HELD_NOTE),
        "hover explains the held latest"
    );
    assert!(updates_to(&actions, "3.9.1").is_empty(), "{actions:?}");
    assert!(updates_to(&actions, "3.9.0").is_empty(), "{actions:?}");
    assert!(
        actions.iter().all(|t| !t.contains("preferred")),
        "nothing is marked preferred because of the window: {actions:?}"
    );
}

// ---- FR-013: configuration surface ---------------------------------------------------------

#[test]
fn honor_native_cooldown_defaults_to_honor_and_parses_false_as_ignore() {
    use deps_core::policy_config::NativeCooldownMode;
    let default: DepsConfig = serde_json::from_value(json!({})).expect("default");
    assert_eq!(
        default.policy.freshness.honor_native_cooldown,
        NativeCooldownMode::Honor
    );
    let off: DepsConfig =
        serde_json::from_value(json!({"freshness": {"honor_native_cooldown": false}}))
            .expect("off");
    assert_eq!(
        off.policy.freshness.honor_native_cooldown,
        NativeCooldownMode::Ignore
    );
    let on: DepsConfig =
        serde_json::from_value(json!({"freshness": {"honor_native_cooldown": true}})).expect("on");
    assert_eq!(
        on.policy.freshness.honor_native_cooldown,
        NativeCooldownMode::Honor
    );
}

#[test]
fn honor_native_cooldown_rejects_a_non_boolean_value() {
    let bad = serde_json::from_value::<DepsConfig>(
        json!({"freshness": {"honor_native_cooldown": "yes"}}),
    );
    assert!(bad.is_err());
}

//! Acceptance tests (tester-owned) for #2191 and the LSP half of #2190: the default 3-day
//! freshness cooldown gates the LSP update lens and update actions, and the outdated diagnostic
//! is judged against the newest eligible version. Real handlers, `mockito` sparse index and OSV.

#![cfg(feature = "cargo")]
#![expect(clippy::expect_used, reason = "test code")]

use std::sync::Arc;
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_core::osv::OsvClient;
use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, handle_document_open};
use deps_lsp::handlers::code_actions::handle_code_actions;
use deps_lsp::handlers::code_lens::handle_code_lens;
use deps_lsp::handlers::diagnostics::handle_diagnostics;
use deps_lsp::lsp_types_interop::to_lsp_uri;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower_lsp_server::ls_types::Uri;
use tower_lsp_server::{Client, LspService};

const DAY: i64 = 86_400;
const DEP_LINE: u32 = 5;
const ADVISORY: &str = "RUSTSEC-2026-0001";
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
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
    client: Client,
    uri: Uri,
    _service: LspService<Backend>,
    _dir: tempfile::TempDir,
    _index: mockito::ServerGuard,
    _osv: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
}

/// `rmcp = "=<in_use>"` locked at `in_use`; `versions` is `(version, age in days)`, newest first.
/// With `fixed_in`, OSV flags exactly the in-use version.
#[expect(
    clippy::too_many_lines,
    reason = "one linear fixture: mocks, files, document open"
)]
async fn fixture(
    in_use: &'static str,
    versions: &[(&str, i64)],
    fixed_in: Option<&'static str>,
) -> Fixture {
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
            .with_body_from_request(move |request| {
                let body: Value =
                    serde_json::from_slice(request.body().expect("body")).expect("batch json");
                let results = body
                    .get("queries")
                    .and_then(Value::as_array)
                    .expect("queries")
                    .iter()
                    .map(|q| {
                        if fixed_in.is_some() && q.get("version") == Some(&json!(in_use)) {
                            json!({"vulns": [{"id": ADVISORY, "modified": "2026-01-01T00:00:00Z"}]})
                        } else {
                            json!({"vulns": []})
                        }
                    })
                    .collect::<Vec<_>>();
                json!({ "results": results }).to_string().into_bytes()
            })
            .expect_at_least(0)
            .create_async()
            .await,
    );
    if let Some(fixed) = fixed_in {
        mocks.push(
            osv.mock("GET", format!("/v1/vulns/{ADVISORY}").as_str())
                .with_body(
                    json!({
                        "id": ADVISORY, "modified": "2026-01-01T00:00:00Z", "summary": "s",
                        "affected": [{
                            "package": {"name": "rmcp", "ecosystem": "crates.io"},
                            "ranges": [{"type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": fixed}]}]
                        }]
                    })
                    .to_string(),
                )
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
            "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+{}\"\n",
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
    let manifest = format!(
        "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"={in_use}\"\n"
    );
    let path = root.join("Cargo.toml");
    std::fs::write(&path, &manifest).expect("manifest");

    let host = index.host_with_port();
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
    let config: DepsConfig = serde_json::from_value(json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": {"vulnerabilities_enabled": fixed_in.is_some()},
    }))
    .expect("config");
    let config = Arc::new(RwLock::new(config));

    let slot = std::sync::Mutex::new(None);
    let (service, _socket) = LspService::new(|client| {
        *slot.lock().expect("slot") = Some(client.clone());
        Backend::new(client)
    });
    let client = slot.into_inner().expect("slot").expect("client");
    let uri = to_lsp_uri(&url::Url::from_file_path(&path).expect("file url"));
    handle_document_open(
        uri.clone(),
        manifest,
        Some(1),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    .expect("document opens");
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
        _service: service,
        _dir: dir,
        _index: index,
        _osv: osv,
        _mocks: mocks,
    };
    if fixed_in.is_some() {
        // OSV phase B commits after the document reports `Loaded`.
        tokio::time::timeout(Duration::from_secs(10), async {
            while !fx.messages().await.iter().any(|m| m.contains(ADVISORY)) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the advisory diagnostic is published");
    }
    fx
}

impl Fixture {
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

    async fn messages(&self) -> Vec<String> {
        self.diagnostics()
            .await
            .iter()
            .filter_map(|d| d.get("message")?.as_str().map(str::to_owned))
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
        .into_iter()
        .filter_map(|l| l.command.map(|c| c.title))
        .collect()
    }

    async fn action_titles(&self) -> Vec<String> {
        let diagnostics = self.diagnostics().await;
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri.as_str()},
            "range": {"start": {"line": DEP_LINE, "character": 10},
                      "end": {"line": DEP_LINE, "character": 10}},
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
}

// #2191
#[tokio::test]
async fn latest_inside_the_freshness_cooldown_is_written_by_no_lens_and_no_update_action() {
    let fx = fixture("3.8.0", &[("3.9.0", 1), ("3.8.0", 100)], None).await;

    let lenses = fx.lens_titles().await;
    assert!(lenses.is_empty(), "{lenses:?}");
    let actions = fx.action_titles().await;
    assert!(actions.iter().all(|t| !t.contains("3.9.0")), "{actions:?}");
}

// #2191
#[tokio::test]
async fn security_fix_to_a_held_version_stays_offered_and_names_the_cooldown() {
    let fx = fixture("3.8.0", &[("3.9.0", 1), ("3.8.0", 100)], Some("3.9.0")).await;

    let actions = fx.action_titles().await;
    assert!(
        actions
            .iter()
            .any(|t| t.contains("3.9.0") && t.contains("inside the release cooldown")),
        "{actions:?}"
    );
}

// #2190
#[tokio::test]
async fn held_latest_with_nothing_eligible_newer_has_no_outdated_diagnostic() {
    let fx = fixture("3.8.0", &[("3.9.0", 1), ("3.8.0", 100)], None).await;

    let messages = fx.messages().await;
    assert!(
        messages.iter().all(|m| !m.contains(OUTDATED)),
        "{messages:?}"
    );
}

// #2190
#[tokio::test]
async fn held_latest_with_an_eligible_newer_version_names_that_version() {
    let fx = fixture(
        "3.7.0",
        &[("3.9.0", 1), ("3.8.0", 50), ("3.7.0", 100)],
        None,
    )
    .await;

    let messages = fx.messages().await;
    assert!(
        messages
            .iter()
            .any(|m| m.starts_with("Newer version available: 3.8.0 (3.9.0")),
        "{messages:?}"
    );
}

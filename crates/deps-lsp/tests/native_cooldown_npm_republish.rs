//! #2041 / spec 099 FR-015 (impl-critic question): when a native window is already active and a
//! watched config file changes the window's value (`.npmrc`, `pnpm-workspace.yaml`,
//! `bunfig.toml`), the diagnostics of the open `package.json` are republished with the new
//! window, without reopening the document.
//!
//! The fixture captures the `textDocument/publishDiagnostics` notifications the server sends.

#![cfg(feature = "npm")]
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_lsp::Backend;
use deps_lsp::document::ServerState;
use serde_json::{Value, json};
use tower::Service;
use tower_lsp_server::jsonrpc::Request;
use tower_lsp_server::{LanguageServer, LspService};

const DAY: i64 = 86_400;
const MANIFEST: &str = "{\n  \"dependencies\": {\n    \"widget\": \"1.0.0\"\n  }\n}\n";

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
    service: LspService<Backend>,
    root: std::path::PathBuf,
    registry_line: String,
    published: Arc<Mutex<Vec<String>>>,
    _drain: tokio::task::JoinHandle<()>,
    _server: mockito::ServerGuard,
    _dir: tempfile::TempDir,
    _mocks: Vec<mockito::Mock>,
}

fn settings() -> Value {
    json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": {"vulnerabilities_enabled": false},
        "freshness": {"enabled": false, "honor_native_cooldown": true},
    })
}

/// A repository whose `latest` (1.1.0) is three days old, with `npmrc_extra` appended to its
/// `.npmrc` and `files` written at its root.
async fn fixture(npmrc_extra: &str, files: &[(&str, &str)]) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body(r#"{"dist-tags":{"latest":"1.1.0"},"versions":{"1.0.0":{},"1.1.0":{}}}"#)
        .expect_at_least(0)
        .create_async()
        .await;
    let full = server
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(format!(
            r#"{{"time":{{"1.0.0":"{}","1.1.0":"{}"}}}}"#,
            rfc3339(now_secs() - 100 * DAY),
            rfc3339(now_secs() - 3 * DAY)
        ))
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let registry_line = format!("registry={}/\n", server.url());
    std::fs::write(root.join(".npmrc"), format!("{registry_line}{npmrc_extra}")).expect("npmrc");
    for (name, content) in files {
        std::fs::write(root.join(name), content).expect("config file");
    }
    let manifest = root.join("package.json");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let host = server.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let state = ServerState::from_env_source(&env);
    let (mut service, socket) = LspService::new(|client| Backend::with_state(client, state));
    let (mut requests, mut responses) = socket.split();
    let published = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&published);
    let drain = tokio::spawn(async move {
        while let Some(request) = futures::StreamExt::next(&mut requests).await {
            if request.method() == "textDocument/publishDiagnostics" {
                let text = request.params().map(Value::to_string).unwrap_or_default();
                sink.lock().expect("sink").push(text);
            }
            if let (_, Some(id), _) = request.into_parts() {
                let reply = tower_lsp_server::jsonrpc::Response::from_parts(id, Ok(Value::Null));
                if futures::SinkExt::send(&mut responses, reply).await.is_err() {
                    break;
                }
            }
        }
    });

    let uri = url::Url::from_file_path(&manifest)
        .expect("file url")
        .to_string();
    // Through the service, so the server counts as initialized and its notifications reach the
    // socket (calling the handlers directly bypasses that state machine).
    let initialize = Request::build("initialize")
        .id(1_i64)
        .params(json!({
            "processId": null,
            "rootUri": url::Url::from_file_path(&root).expect("root url").to_string(),
            "capabilities": {},
            "initializationOptions": settings(),
        }))
        .finish();
    let response = service.call(initialize).await.expect("initialize");
    assert!(response.is_some_and(|r| r.is_ok()));
    service
        .call(Request::build("initialized").params(json!({})).finish())
        .await
        .expect("initialized");
    let backend = service.inner();
    backend
        .did_open(
            serde_json::from_value(json!({"textDocument": {
                "uri": uri, "languageId": "json", "version": 1, "text": MANIFEST}}))
            .expect("did_open params"),
        )
        .await;
    Fixture {
        service,
        root,
        registry_line,
        published,
        _drain: drain,
        _server: server,
        _dir: dir,
        _mocks: vec![abbreviated, full],
    }
}

impl Fixture {
    async fn watched_file_changed(&self, file: &str) {
        self.service
            .inner()
            .did_change_watched_files(
                serde_json::from_value(json!({"changes": [{
                    "uri": url::Url::from_file_path(self.root.join(file)).expect("url").to_string(),
                    "type": 2,
                }]}))
                .expect("watched files params"),
            )
            .await;
    }

    /// Waits until some published diagnostics contain `needle`.
    async fn hover_loaded(&self) {
        for _ in 0..100 {
            let params = serde_json::from_value(json!({
                "textDocument": {"uri": url::Url::from_file_path(self.root.join("package.json")).expect("url").to_string()},
                "position": {"line": 2, "character": 6},
            }))
            .expect("hover params");
            let hover = self.service.inner().hover(params).await.expect("hover rpc");
            if hover.is_some_and(|h| {
                serde_json::to_string(&h)
                    .expect("json")
                    .contains("**Latest**")
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("document never loaded");
    }

    async fn published_with(&self, needle: &str) {
        for _ in 0..100 {
            if self
                .published
                .lock()
                .expect("sink")
                .iter()
                .any(|text| text.contains(needle))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "no diagnostics containing {needle:?}; published: {:#?}",
            self.published.lock().expect("sink")
        );
    }
}

async fn edit_changes_the_published_window(
    fx: &Fixture,
    file: &str,
    content: &str,
    before: &str,
    after: &str,
) {
    fx.hover_loaded().await;
    fx.published_with(before).await;
    std::fs::write(fx.root.join(file), content).expect("edit");
    fx.watched_file_changed(file).await;
    fx.published_with(after).await;
}

#[tokio::test]
async fn npmrc_edit_republishes_the_new_window() {
    let fx = fixture("min-release-age=7\n", &[("package-lock.json", "{}")]).await;
    let edited = format!("{}min-release-age=14\n", fx.registry_line);
    edit_changes_the_published_window(
        &fx,
        ".npmrc",
        &edited,
        "npm min-release-age = 7 days",
        "npm min-release-age = 14 days",
    )
    .await;
}

#[tokio::test]
async fn pnpm_workspace_edit_republishes_the_new_window() {
    let fx = fixture(
        "",
        &[
            ("pnpm-workspace.yaml", "minimumReleaseAge: 10080\n"),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ],
    )
    .await;
    edit_changes_the_published_window(
        &fx,
        "pnpm-workspace.yaml",
        "minimumReleaseAge: 20160\n",
        "pnpm minimumReleaseAge = 10080 minutes",
        "pnpm minimumReleaseAge = 20160 minutes",
    )
    .await;
}

#[tokio::test]
async fn bunfig_edit_republishes_the_new_window() {
    let fx = fixture(
        "",
        &[
            ("bunfig.toml", "[install]\nminimumReleaseAge = 604800\n"),
            ("bun.lock", ""),
        ],
    )
    .await;
    edit_changes_the_published_window(
        &fx,
        "bunfig.toml",
        "[install]\nminimumReleaseAge = 1209600\n",
        "bun minimumReleaseAge = 604800 seconds",
        "bun minimumReleaseAge = 1209600 seconds",
    )
    .await;
}

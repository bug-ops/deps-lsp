//! #1982 / spec 099 FR-013, FR-015 at integration level: the real `LanguageServer` notifications
//! (`workspace/didChangeConfiguration`, `workspace/didChangeWatchedFiles`) re-evaluate an already
//! open Cargo manifest's native `min-publish-age` window without reopening it.
//!
//! The fixture builds a `Backend` over a pre-built `ServerState` (`Backend::with_state`) whose
//! registry is a `mockito` sparse index reached through `[source.crates-io] replace-with`.

#![cfg(feature = "cargo")]
#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_lsp::Backend;
use deps_lsp::document::ServerState;
use serde_json::{Value, json};
use tower_lsp_server::{LanguageServer, LspService};

const DAY: i64 = 86_400;
const MANIFEST: &str =
    "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nrmcp = \"=3.8.0\"\n";
const MIRROR_HEAD: &str = "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\n";
const HELD: &str = "excluded by cargo registry.global-min-publish-age = 7 days";

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

fn settings(honor: bool) -> Value {
    json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": {"vulnerabilities_enabled": false},
        "freshness": {"honor_native_cooldown": honor},
    })
}

struct Fixture {
    service: LspService<Backend>,
    uri: String,
    cargo_config: PathBuf,
    mirror: String,
    _drain: tokio::task::JoinHandle<()>,
    _server: mockito::ServerGuard,
    _mock: mockito::Mock,
    _dir: tempfile::TempDir,
}

async fn fixture(initial_config: &str) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let lines = [("3.9.0", 3 * DAY), ("3.8.0", 100 * DAY)]
        .iter()
        .map(|(v, age)| {
            format!(
                r#"{{"name":"rmcp","vers":"{v}","yanked":false,"features":{{}},"deps":[],"pubtime":"{}"}}"#,
                rfc3339(now_secs() - age)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mock = server
        .mock("GET", "/rm/cp/rmcp")
        .with_status(200)
        .with_body(lines)
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let mirror = format!("{MIRROR_HEAD}registry = \"sparse+{}\"\n", server.url());
    std::fs::create_dir_all(root.join(".cargo")).expect("cargo dir");
    let cargo_config = root.join(".cargo/config.toml");
    std::fs::write(&cargo_config, format!("{mirror}{initial_config}")).expect("config");
    std::fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"rmcp\"\nversion = \"3.8.0\"\nsource = \"registry+https://index.crates.io/\"\n",
    )
    .expect("lock");
    let manifest = root.join("Cargo.toml");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

    let host = server.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let state = ServerState::from_env_source(&env);
    let (service, socket) = LspService::new(|client| Backend::with_state(client, state));
    // The server awaits replies to its own requests (progress, registrations); answer them all.
    let (mut requests, mut responses) = socket.split();
    let drain = tokio::spawn(async move {
        while let Some(request) = futures::StreamExt::next(&mut requests).await {
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

    let backend = service.inner();
    backend
        .initialize(
            serde_json::from_value(json!({
                "processId": null,
                "rootUri": url::Url::from_file_path(&root).expect("root url").to_string(),
                "capabilities": {},
                "initializationOptions": settings(true),
            }))
            .expect("initialize params"),
        )
        .await
        .expect("initialize");
    backend
        .initialized(serde_json::from_value(json!({})).expect("initialized params"))
        .await;
    backend
        .did_open(
            serde_json::from_value(json!({"textDocument": {
                "uri": uri, "languageId": "toml", "version": 1, "text": MANIFEST}}))
            .expect("did_open params"),
        )
        .await;

    Fixture {
        service,
        uri,
        cargo_config,
        mirror,
        _drain: drain,
        _server: server,
        _mock: mock,
        _dir: dir,
    }
}

impl Fixture {
    async fn hover(&self) -> String {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri},
            "position": {"line": 5, "character": 2},
        }))
        .expect("hover params");
        let hover = self.service.inner().hover(params).await.expect("hover rpc");
        hover.map_or_else(String::new, |h| {
            serde_json::to_string(&h).expect("serialize")
        })
    }

    /// Polls hover until `done` holds for it, or panics with the last hover text.
    async fn hover_until(&self, what: &str, done: impl Fn(&str) -> bool) {
        let mut last = String::new();
        for _ in 0..100 {
            last = self.hover().await;
            if last.contains("**Latest**") && done(&last) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for: {what}; last hover: {last}");
    }

    async fn configure(&self, honor: bool) {
        self.service
            .inner()
            .did_change_configuration(
                serde_json::from_value(json!({"settings": settings(honor)}))
                    .expect("configuration params"),
            )
            .await;
    }
}

#[tokio::test]
async fn honor_toggle_via_did_change_configuration_applies_to_an_open_document() {
    let fx = fixture("[registry]\nglobal-min-publish-age = \"7 days\"\n").await;
    fx.hover_until("initial held callout", |h| h.contains(HELD))
        .await;

    fx.configure(false).await;
    fx.hover_until("callout gone after opt-out", |h| !h.contains("excluded by"))
        .await;

    fx.configure(true).await;
    fx.hover_until("callout back after re-enabling", |h| h.contains(HELD))
        .await;
}

#[tokio::test]
async fn editing_cargo_config_toml_refetches_the_window_for_an_open_document() {
    let fx = fixture("[registry]\nglobal-min-publish-age = \"7 days\"\n").await;
    fx.hover_until("initial held callout", |h| h.contains(HELD))
        .await;

    std::fs::write(
        &fx.cargo_config,
        format!("{}[registry]\nglobal-min-publish-age = \"0\"\n", fx.mirror),
    )
    .expect("rewrite config");
    fx.service
        .inner()
        .did_change_watched_files(
            serde_json::from_value(json!({"changes": [{
                "uri": url::Url::from_file_path(&fx.cargo_config).expect("url").to_string(),
                "type": 2,
            }]}))
            .expect("watched files params"),
        )
        .await;
    fx.hover_until("callout gone after the window was removed", |h| {
        !h.contains("excluded by")
    })
    .await;

    std::fs::write(
        &fx.cargo_config,
        format!(
            "{}[registry]\nglobal-min-publish-age = \"7 days\"\n",
            fx.mirror
        ),
    )
    .expect("restore config");
    fx.service
        .inner()
        .did_change_watched_files(
            serde_json::from_value(json!({"changes": [{
                "uri": url::Url::from_file_path(&fx.cargo_config).expect("url").to_string(),
                "type": 2,
            }]}))
            .expect("watched files params"),
        )
        .await;
    fx.hover_until("callout back after the window returned", |h| {
        h.contains(HELD)
    })
    .await;
}

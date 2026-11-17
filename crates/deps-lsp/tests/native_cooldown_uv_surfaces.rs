//! #2042 / spec 099 acceptance: uv's `exclude-newer` window through the real `LanguageServer`
//! (hover, `didChangeConfiguration`, `didChangeWatchedFiles`), with a `mockito` PEP 691 index
//! bound to the dependency through `[tool.uv.sources]`.
//!
//! Publish times are relative to the real clock with hour-sized margins around day-sized windows.

#![cfg(feature = "pypi")]
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use deps_core::net_policy::{MapEnv, PRIVATE_REGISTRY_HOSTS_ENV};
use deps_lsp::Backend;
use deps_lsp::document::ServerState;
use serde_json::{Value, json};
use tower_lsp_server::{LanguageServer, LspService};

const DAY: i64 = 86_400;
const DEP_LINE: u32 = 3;
const HELD: &str = "excluded by uv exclude-newer = 7 days";

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

fn manifest(tool_uv: &str, index_url: &str) -> String {
    format!(
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2.0\"]\n\n[tool.uv]\n{tool_uv}\n\n[tool.uv.sources]\nrequests = {{ index = \"mock\" }}\n\n[[tool.uv.index]]\nname = \"mock\"\nurl = \"{index_url}/simple\"\nexplicit = true\n"
    )
}

struct Fixture {
    service: LspService<Backend>,
    uri: String,
    root: PathBuf,
    hits: Arc<AtomicUsize>,
    _drain: tokio::task::JoinHandle<()>,
    _server: mockito::ServerGuard,
    _mock: mockito::Mock,
    _dir: tempfile::TempDir,
}

async fn fixture(tool_uv: &str) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let body = format!(
        r#"{{"meta":{{"api-version":"1.4"}},"name":"requests","versions":["2.31.0","2.32.0"],"files":[
        {{"filename":"requests-2.31.0.tar.gz","yanked":false,"upload-time":"{}"}},
        {{"filename":"requests-2.32.0.tar.gz","yanked":false,"upload-time":"{}"}}]}}"#,
        rfc3339(now_secs() - 100 * DAY),
        rfc3339(now_secs() - 3 * DAY),
    );
    let mock = server
        .mock("GET", "/simple/requests/")
        .with_status(200)
        .with_header("content-type", "application/vnd.pypi.simple.v1+json")
        .with_body_from_request(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            body.clone().into_bytes()
        })
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    let content = manifest(tool_uv, &server.url());
    std::fs::write(root.join("pyproject.toml"), &content).expect("manifest");
    std::fs::write(
        root.join("uv.lock"),
        "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
    )
    .expect("lock");

    let host = server.host_with_port();
    let env = MapEnv::new().with_var(
        PRIVATE_REGISTRY_HOSTS_ENV,
        host.split(':').next().expect("host"),
    );
    let state = ServerState::from_env_source(&env);
    let (service, socket) = LspService::new(|client| Backend::with_state(client, state));
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
    let uri = url::Url::from_file_path(root.join("pyproject.toml"))
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
                "uri": uri, "languageId": "toml", "version": 1, "text": content}}))
            .expect("did_open params"),
        )
        .await;

    Fixture {
        service,
        uri,
        root,
        hits,
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
            "position": {"line": DEP_LINE, "character": 18},
        }))
        .expect("hover params");
        let hover = self.service.inner().hover(params).await.expect("hover rpc");
        hover.map_or_else(String::new, |h| {
            serde_json::to_string(&h).expect("serialize")
        })
    }

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
async fn held_latest_is_explained_in_hover() {
    let fx = fixture("exclude-newer = \"7 days\"").await;
    fx.hover_until("held callout", |h| h.contains(HELD)).await;
}

#[tokio::test]
async fn without_uv_config_hover_has_no_native_note() {
    let fx = fixture("# nothing configured").await;
    fx.hover_until("latest rendered", |h| !h.contains("excluded by"))
        .await;
}

#[tokio::test]
async fn honor_toggle_applies_to_an_open_document() {
    let fx = fixture("exclude-newer = \"7 days\"").await;
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
async fn adding_uv_toml_applies_the_window_to_an_open_document() {
    let fx = fixture("# nothing configured").await;
    fx.hover_until("latest rendered", |h| !h.contains("excluded by"))
        .await;

    let uv_toml = fx.root.join("uv.toml");
    std::fs::write(&uv_toml, "exclude-newer = \"7 days\"\n").expect("uv.toml");
    fx.service
        .inner()
        .did_change_watched_files(
            serde_json::from_value(json!({"changes": [{
                "uri": url::Url::from_file_path(&uv_toml).expect("url").to_string(),
                "type": 1,
            }]}))
            .expect("watched files params"),
        )
        .await;
    fx.hover_until("callout after uv.toml appears", |h| h.contains(HELD))
        .await;

    std::fs::write(&uv_toml, "exclude-newer = \"0 days\"\n").expect("uv.toml");
    fx.service
        .inner()
        .did_change_watched_files(
            serde_json::from_value(json!({"changes": [{
                "uri": url::Url::from_file_path(&uv_toml).expect("url").to_string(),
                "type": 2,
            }]}))
            .expect("watched files params"),
        )
        .await;
    fx.hover_until("callout gone after the window is switched off", |h| {
        !h.contains("excluded by")
    })
    .await;
}

#[tokio::test]
async fn adding_uv_toml_sends_no_registry_request() {
    let fx = fixture("# nothing configured").await;
    fx.hover_until("latest rendered", |h| !h.contains("excluded by"))
        .await;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let before = fx.hits.load(Ordering::SeqCst);

    let uv_toml = fx.root.join("uv.toml");
    std::fs::write(&uv_toml, "exclude-newer = \"7 days\"\n").expect("uv.toml");
    fx.service
        .inner()
        .did_change_watched_files(
            serde_json::from_value(json!({"changes": [{
                "uri": url::Url::from_file_path(&uv_toml).expect("url").to_string(),
                "type": 1,
            }]}))
            .expect("watched files params"),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        fx.hits.load(Ordering::SeqCst),
        before,
        "a window change must not refetch the registry"
    );
}

//! #2041 / spec 099 acceptance: npm, pnpm and Bun release-age windows through the real
//! `LanguageServer` (hover, `didChangeConfiguration`, `didChangeWatchedFiles`), with a `mockito`
//! packument reached through a `.npmrc` `registry=` declaration.
//!
//! Covers: a held `latest` is explained with freshness disabled and no freshness text leaks
//! (N-M3/D2), the opt-out and no-native-config request shape is exactly today's (byte-identical
//! contract), pnpm and Bun windows, and a window added later through the Ignore-to-Honor toggle or
//! a watched file (`bunfig.toml`, N-M7) refetching publish times.
//!
//! Written tests-first against plans `20-24-32-architect` / `20-32-28-architect`. Publish times
//! are relative to the real clock with hour-sized margins around day-sized windows.

#![cfg(feature = "npm")]
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
const MANIFEST: &str = "{\n  \"dependencies\": {\n    \"widget\": \"^1.0.0\"\n  }\n}\n";
const DEP_LINE: u32 = 2;
const FRESHNESS_WORDS: [&str; 2] = ["recently published", "published "];

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

/// Native configuration files written next to the manifest.
#[derive(Default)]
struct Repo {
    npmrc_extra: &'static str,
    pnpm_workspace: Option<&'static str>,
    bunfig: Option<&'static str>,
    lock_file: Option<&'static str>,
}

struct Fixture {
    service: LspService<Backend>,
    uri: String,
    abbreviated_hits: Arc<AtomicUsize>,
    full_hits: Arc<AtomicUsize>,
    root: PathBuf,
    _drain: tokio::task::JoinHandle<()>,
    _server: mockito::ServerGuard,
    _dir: tempfile::TempDir,
    _mocks: Vec<mockito::Mock>,
}

fn settings(honor: bool) -> Value {
    json!({
        "registries": {"workspace_registries": "all"},
        "supply_chain": {"enabled": false},
        "typosquat": {"enabled": false},
        "gossip": {"enabled": false},
        "diagnostics": {"vulnerabilities_enabled": false},
        "freshness": {"enabled": false, "honor_native_cooldown": honor},
    })
}

async fn fixture(repo: Repo, honor: bool) -> Fixture {
    let mut server = mockito::Server::new_async().await;
    let abbreviated_hits = Arc::new(AtomicUsize::new(0));
    let full_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&abbreviated_hits);
    let abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body_from_request(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            br#"{"dist-tags":{"latest":"1.1.0"},"versions":{"1.0.0":{},"1.1.0":{}}}"#.to_vec()
        })
        .expect_at_least(0)
        .create_async()
        .await;
    let hits = Arc::clone(&full_hits);
    let full_body = format!(
        r#"{{"dist-tags":{{"latest":"1.1.0"}},"time":{{"1.0.0":"{}","1.1.0":"{}"}},"versions":{{"1.0.0":{{}},"1.1.0":{{}}}}}}"#,
        rfc3339(now_secs() - 100 * DAY),
        rfc3339(now_secs() - DAY)
    );
    let full = server
        .mock("GET", "/widget")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body_from_request(move |_| {
            hits.fetch_add(1, Ordering::SeqCst);
            full_body.clone().into_bytes()
        })
        .expect_at_least(0)
        .create_async()
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path().canonicalize().expect("canonical");
    std::fs::write(
        root.join(".npmrc"),
        format!("registry={}/\n{}", server.url(), repo.npmrc_extra),
    )
    .expect("npmrc");
    if let Some(content) = repo.pnpm_workspace {
        std::fs::write(root.join("pnpm-workspace.yaml"), content).expect("workspace");
    }
    if let Some(content) = repo.bunfig {
        std::fs::write(root.join("bunfig.toml"), content).expect("bunfig");
    }
    if let Some(name) = repo.lock_file {
        std::fs::write(root.join(name), "").expect("lock");
    }
    let manifest = root.join("package.json");
    std::fs::write(&manifest, MANIFEST).expect("manifest");

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
                "initializationOptions": settings(honor),
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
                "uri": uri, "languageId": "json", "version": 1, "text": MANIFEST}}))
            .expect("did_open params"),
        )
        .await;

    Fixture {
        service,
        uri,
        abbreviated_hits,
        full_hits,
        root,
        _drain: drain,
        _server: server,
        _dir: dir,
        _mocks: vec![abbreviated, full],
    }
}

impl Fixture {
    async fn hover(&self) -> String {
        let params = serde_json::from_value(json!({
            "textDocument": {"uri": self.uri},
            "position": {"line": DEP_LINE, "character": 6},
        }))
        .expect("hover params");
        let hover = self.service.inner().hover(params).await.expect("hover rpc");
        hover.map_or_else(String::new, |h| {
            serde_json::to_string(&h).expect("serialize")
        })
    }

    /// Polls hover until the loaded hover (it names the latest version) satisfies `done`.
    async fn hover_until(&self, what: &str, done: impl Fn(&str) -> bool) -> String {
        let mut last = String::new();
        for _ in 0..100 {
            last = self.hover().await;
            if last.contains("**Latest**") && done(&last) {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for: {what}; last hover: {last}");
    }

    async fn loaded_hover(&self) -> String {
        self.hover_until("loaded hover", |_| true).await
    }

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

    async fn configure(&self, honor: bool) {
        self.service
            .inner()
            .did_change_configuration(
                serde_json::from_value(json!({"settings": settings(honor)}))
                    .expect("configuration params"),
            )
            .await;
    }

    fn full_requests(&self) -> usize {
        self.full_hits.load(Ordering::SeqCst)
    }

    fn abbreviated_requests(&self) -> usize {
        self.abbreviated_hits.load(Ordering::SeqCst)
    }
}

fn assert_no_freshness_text(hover: &str) {
    for word in FRESHNESS_WORDS {
        assert!(
            !hover.contains(word),
            "freshness is disabled: hover must not contain {word:?}: {hover}"
        );
    }
}

fn npm(extra: &'static str) -> Repo {
    Repo {
        npmrc_extra: extra,
        lock_file: Some("package-lock.json"),
        ..Repo::default()
    }
}

#[tokio::test]
async fn npm_window_explains_the_held_latest_with_freshness_disabled() {
    let fx = fixture(npm("min-release-age=7\n"), true).await;
    let hover = fx
        .hover_until("held callout", |h| h.contains("excluded by"))
        .await;
    assert!(hover.contains("min-release-age = 7 days"), "{hover}");
    assert_no_freshness_text(&hover);
    assert!(
        fx.full_requests() >= 1,
        "native demand fetches publish times"
    );
}

#[tokio::test]
async fn pnpm_window_explains_the_held_latest() {
    let fx = fixture(
        Repo {
            pnpm_workspace: Some("minimumReleaseAge: 10080\n"),
            lock_file: Some("pnpm-lock.yaml"),
            ..Repo::default()
        },
        true,
    )
    .await;
    let hover = fx
        .hover_until("held callout", |h| h.contains("excluded by"))
        .await;
    assert!(
        hover.contains("minimumReleaseAge = 10080 minutes"),
        "{hover}"
    );
    assert_no_freshness_text(&hover);
}

#[tokio::test]
async fn bun_window_explains_the_held_latest() {
    let fx = fixture(
        Repo {
            bunfig: Some("[install]\nminimumReleaseAge = 604800\n"),
            lock_file: Some("bun.lock"),
            ..Repo::default()
        },
        true,
    )
    .await;
    let hover = fx
        .hover_until("held callout", |h| h.contains("excluded by"))
        .await;
    assert!(
        hover.contains("minimumReleaseAge = 604800 seconds"),
        "{hover}"
    );
    assert_no_freshness_text(&hover);
}

#[tokio::test]
async fn no_native_config_issues_no_full_packument_request_and_shows_no_hold() {
    let fx = fixture(
        Repo {
            lock_file: Some("package-lock.json"),
            ..Repo::default()
        },
        true,
    )
    .await;
    let hover = fx.loaded_hover().await;
    assert!(!hover.contains("excluded by"), "{hover}");
    assert_no_freshness_text(&hover);
    assert_eq!(fx.full_requests(), 0, "request shape must equal today's");
    assert!(fx.abbreviated_requests() >= 1);
}

#[tokio::test]
async fn opt_out_ignores_the_window_and_issues_no_full_packument_request() {
    let fx = fixture(npm("min-release-age=7\n"), false).await;
    let hover = fx.loaded_hover().await;
    assert!(!hover.contains("excluded by"), "{hover}");
    assert_eq!(
        fx.full_requests(),
        0,
        "honor_native_cooldown = false must cost nothing extra"
    );
}

#[tokio::test]
async fn exempt_dependency_is_never_held() {
    let fx = fixture(
        npm("min-release-age=7\nmin-release-age-exclude=widget\n"),
        true,
    )
    .await;
    let hover = fx.loaded_hover().await;
    assert!(!hover.contains("excluded by"), "{hover}");
}

#[tokio::test]
async fn enabling_honor_after_opt_out_refetches_publish_times_and_holds() {
    let fx = fixture(npm("min-release-age=7\n"), false).await;
    assert!(!fx.loaded_hover().await.contains("excluded by"));
    assert_eq!(fx.full_requests(), 0);

    fx.configure(true).await;
    let hover = fx
        .hover_until("callout after re-enabling", |h| h.contains("excluded by"))
        .await;
    assert!(
        fx.full_requests() >= 1,
        "Ignore -> Honor must upgrade the refetch (N-M7)"
    );
    assert_no_freshness_text(&hover);
}

#[tokio::test]
async fn window_added_through_bunfig_after_open_refetches_publish_times_and_holds() {
    let fx = fixture(
        Repo {
            lock_file: Some("bun.lock"),
            ..Repo::default()
        },
        true,
    )
    .await;
    assert!(!fx.loaded_hover().await.contains("excluded by"));
    assert_eq!(fx.full_requests(), 0);

    std::fs::write(
        fx.root.join("bunfig.toml"),
        "[install]\nminimumReleaseAge = 604800\n",
    )
    .expect("bunfig");
    fx.watched_file_changed("bunfig.toml").await;
    let hover = fx
        .hover_until("callout after bunfig edit", |h| h.contains("excluded by"))
        .await;
    assert!(
        fx.full_requests() >= 1,
        "demand rise must refetch with times"
    );
    assert_no_freshness_text(&hover);
}

#[tokio::test]
async fn window_removed_from_bunfig_clears_the_callout() {
    let fx = fixture(
        Repo {
            bunfig: Some("[install]\nminimumReleaseAge = 604800\n"),
            lock_file: Some("bun.lock"),
            ..Repo::default()
        },
        true,
    )
    .await;
    fx.hover_until("initial callout", |h| h.contains("excluded by"))
        .await;

    std::fs::write(fx.root.join("bunfig.toml"), "[install]\nexact = true\n").expect("bunfig");
    fx.watched_file_changed("bunfig.toml").await;
    fx.hover_until("callout gone", |h| !h.contains("excluded by"))
        .await;
}

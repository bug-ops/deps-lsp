//! End-to-end check of spec 097 FR-012 (#1955): once a registry fetch ends in a failure, the
//! outcome is already committed when the server asks the client for `workspace/inlayHint/refresh`,
//! so the `textDocument/inlayHint` request served at refresh time carries the `⚠` marker.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use crate::server::Backend;
use futures::{SinkExt as _, StreamExt as _};
use std::time::Duration;
use tower_lsp_server::jsonrpc::{Request, Response};
use tower_lsp_server::ls_types::{
    ClientCapabilities, DidOpenTextDocumentParams, InitializeParams, InlayHintLabel,
    InlayHintParams, InlayHintWorkspaceClientCapabilities, Position, Range, TextDocumentIdentifier,
    TextDocumentItem, Uri, WorkspaceClientCapabilities,
};

const MANIFEST: &str = r#"{"dependencies": {"@acme-corp/secretpkg": "^1.0.0"}}"#;
const LOCKFILE: &str = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"@acme-corp/secretpkg": "^1.0.0"}},
    "node_modules/@acme-corp/secretpkg": {"version": "1.0.0"}
  }
}"#;
const REFRESH_METHOD: &str = "workspace/inlayHint/refresh";
const DEADLINE: Duration = Duration::from_secs(30);

async fn labels(backend: &Backend, uri: &Uri) -> Vec<String> {
    use tower_lsp_server::LanguageServer as _;
    let hints = backend
        .inlay_hint(InlayHintParams {
            work_done_progress_params: Default::default(),
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            range: Range::new(Position::new(0, 0), Position::new(10, 0)),
        })
        .await
        .unwrap()
        .unwrap_or_default();
    hints
        .into_iter()
        .map(|hint| match hint.label {
            InlayHintLabel::String(text) => text,
            InlayHintLabel::LabelParts(_) => panic!("expected string label"),
        })
        .collect()
}

/// A manifest plus the files its registry routing needs, written into one temp directory.
struct Scenario<'a> {
    files: Vec<(&'a str, &'a str)>,
    manifest_name: &'a str,
    manifest: &'a str,
    language_id: &'a str,
}

fn npm_scenario(npmrc: &str) -> Scenario<'_> {
    Scenario {
        files: vec![(".npmrc", npmrc), ("package-lock.json", LOCKFILE)],
        manifest_name: "package.json",
        manifest: MANIFEST,
        language_id: "json",
    }
}

/// Opens `scenario`, then answers the server's client requests and returns the labels served
/// at the *first* `workspace/inlayHint/refresh`, or the last labels seen on timeout. Taking the
/// first refresh pins the ordering: the fetch outcome must be recorded before the refresh is
/// requested, so a refresh that raced ahead of it cannot be masked by a later one. Config goes
/// through `initialize` rather than `didChangeConfiguration`: the latter schedules a debounced
/// reparse whose own (legitimate) refresh lands before a slow fetch, e.g. Windows' ~1 s refused
/// connect, and would be taken as the first refresh.
async fn labels_served_at_refresh(scenario: &Scenario<'_>) -> Vec<String> {
    use tower::Service as _;
    use tower_lsp_server::LanguageServer as _;
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in &scenario.files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let manifest = dir.path().join(scenario.manifest_name);
    std::fs::write(&manifest, scenario.manifest).unwrap();
    let uri = Uri::from_file_path(&manifest).unwrap();

    let (mut service, mut socket) = tower_lsp_server::LspService::build(Backend::new).finish();
    let capabilities = ClientCapabilities {
        workspace: Some(WorkspaceClientCapabilities {
            inlay_hint: Some(InlayHintWorkspaceClientCapabilities {
                refresh_support: Some(true),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let init = Request::build("initialize")
        .id(1_i64)
        .params(
            serde_json::to_value(InitializeParams {
                capabilities,
                initialization_options: Some(
                    serde_json::json!({ "registries": { "workspace_registries": "all" } }),
                ),
                ..Default::default()
            })
            .unwrap(),
        )
        .finish();
    assert!(
        service
            .call(init)
            .await
            .unwrap()
            .is_some_and(|response| response.is_ok())
    );
    let backend = service.inner();
    assert!(backend.state().inlay_hint_refresh_supported());
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: scenario.language_id.to_string(),
                version: 1,
                text: scenario.manifest.to_string(),
            },
        })
        .await;

    let mut last = labels(backend, &uri).await;
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while let Ok(Some(request)) = tokio::time::timeout_at(deadline, socket.next()).await {
        let Some(id) = request.id().cloned() else {
            continue;
        };
        socket
            .send(Response::from_ok(id, serde_json::Value::Null))
            .await
            .unwrap();
        if request.method() != REFRESH_METHOD {
            continue;
        }
        last = labels(backend, &uri).await;
        break;
    }
    last
}

#[tokio::test]
async fn test_registry_http_failure_is_visible_at_inlay_refresh() {
    let mut registry = mockito::Server::new_async().await;
    let _mock = registry
        .mock("GET", "/@acme-corp/secretpkg")
        .with_status(500)
        .expect_at_least(1)
        .create_async()
        .await;
    assert_eq!(
        labels_served_at_refresh(&npm_scenario(&format!(
            "@acme-corp:registry={}\n",
            registry.url()
        )))
        .await,
        vec!["⚠ 1.0.0"]
    );
}

#[tokio::test]
async fn test_registry_transport_failure_is_visible_at_inlay_refresh() {
    assert_eq!(
        labels_served_at_refresh(&npm_scenario("@acme-corp:registry=http://127.0.0.1:9\n")).await,
        vec!["⚠ 1.0.0"]
    );
}

/// A Cargo alternate registry records the 404 as a lookup miss (unlike npm's `.npmrc` route),
/// rendered as the neutral `ℹ` marker.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn test_registry_lookup_miss_is_visible_at_inlay_refresh() {
    let mut index = mockito::Server::new_async().await;
    let _mock = index
        .mock("GET", "/mo/ck/mockdep")
        .with_status(404)
        .expect_at_least(1)
        .create_async()
        .await;
    let cargo_config = format!("[registries.corp]\nindex = \"sparse+{}/\"\n", index.url());
    let manifest = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                    mockdep = { version = \"1.0\", registry = \"corp\" }\n";
    let lockfile = format!(
        "version = 3\n\n[[package]]\nname = \"mockdep\"\nversion = \"1.0.0\"\nsource = \"sparse+{}/\"\n",
        index.url()
    );
    let scenario = Scenario {
        files: vec![
            (".cargo/config.toml", cargo_config.as_str()),
            ("Cargo.lock", lockfile.as_str()),
        ],
        manifest_name: "Cargo.toml",
        manifest,
        language_id: "toml",
    };
    assert_eq!(labels_served_at_refresh(&scenario).await, vec!["ℹ 1.0.0"]);
}

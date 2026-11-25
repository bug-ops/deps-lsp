//! #2166: a `didChange` carrying an older document version must never overwrite a newer commit,
//! whatever order the parses finish in, and a superseded edit is not reported as a dropped one.
#![cfg(feature = "npm")]
#![expect(clippy::unwrap_used, reason = "test code")]

mod log_capture;

use std::assert_matches;
use std::sync::Arc;
use std::task::Poll;

use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, handle_document_change, handle_document_open};
use deps_lsp::lsp_types_interop::to_lsp_uri;
use tokio::sync::RwLock;
use tower::Service as _;
use tower_lsp_server::LanguageServer as _;
use tower_lsp_server::LspService;
use tower_lsp_server::ls_types::{
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, InitializeParams,
    TextDocumentContentChangeEvent, TextDocumentItem, Uri, VersionedTextDocumentIdentifier,
};

fn manifest(express: u32) -> String {
    format!(r#"{{"dependencies": {{"express": "^4.{express}.0"}}}}"#)
}

struct Harness {
    _dir: tempfile::TempDir,
    uri: Uri,
    state: Arc<ServerState>,
    client: tower_lsp_server::Client,
    config: Arc<RwLock<DepsConfig>>,
}

async fn opened_at_v1() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("package.json");
    std::fs::write(&path, manifest(1)).unwrap();
    let slot = std::sync::Mutex::new(None);
    let (_service, _socket) = LspService::new(|client| {
        *slot.lock().unwrap() = Some(client.clone());
        Backend::new(client)
    });
    let h = Harness {
        uri: to_lsp_uri(&url::Url::from_file_path(&path).unwrap()),
        _dir: dir,
        state: Arc::new(ServerState::new()),
        client: slot.into_inner().unwrap().unwrap(),
        config: Arc::new(RwLock::new(DepsConfig::default())),
    };
    handle_document_open(
        h.uri.clone(),
        manifest(1),
        Some(1),
        Arc::clone(&h.state),
        h.client.clone(),
        Arc::clone(&h.config),
    )
    .await
    .unwrap();
    h.state.cancel_background_task(&h.uri).await;
    h
}

impl Harness {
    /// Applies a change and reports whether it committed (returned a follow-up task).
    async fn change(&self, express: u32, version: Option<i32>) -> bool {
        let task = handle_document_change(
            self.uri.clone(),
            manifest(express),
            version,
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .unwrap();
        task.inspect(tokio::task::JoinHandle::abort).is_some()
    }

    fn content(&self) -> String {
        self.state.get_document(&self.uri).unwrap().content.clone()
    }

    fn version(&self) -> Option<i32> {
        self.state.get_document(&self.uri).unwrap().version
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn did_change_with_older_version_finishing_last_does_not_overwrite_newer_commit() {
    let h = opened_at_v1().await;

    let older = handle_document_change(
        h.uri.clone(),
        manifest(2),
        Some(2),
        Arc::clone(&h.state),
        h.client.clone(),
        Arc::clone(&h.config),
    );
    let mut older = std::pin::pin!(older);
    assert_matches!(
        futures::poll!(older.as_mut()),
        Poll::Pending,
        "the older change must be suspended in its parse"
    );

    assert!(h.change(3, Some(3)).await, "the newer change commits");
    let older_task = older.await.unwrap();

    assert!(older_task.is_none(), "a superseded change returns no task");
    assert_eq!(h.content(), manifest(3), "the stale change overwrote v3");
    assert_eq!(h.version(), Some(3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn did_change_version_guard_refuses_lower_and_admits_equal_or_unversioned() {
    let h = opened_at_v1().await;

    assert!(h.change(3, Some(3)).await);
    assert!(h.change(4, Some(3)).await, "an equal version is admitted");
    assert_eq!(h.content(), manifest(4));

    assert!(!h.change(2, Some(2)).await, "a lower version is refused");
    assert_eq!(h.content(), manifest(4), "the refused change wrote nothing");
    assert_eq!(h.version(), Some(3));

    assert!(h.change(5, None).await, "an unversioned change is admitted");
    assert_eq!(h.content(), manifest(5));
}

#[tokio::test(flavor = "current_thread")]
async fn superseded_did_change_is_not_logged_as_a_dropped_change() {
    let (logs, _guard) = log_capture::LogCapture::install();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("package.json");
    std::fs::write(&path, manifest(1)).unwrap();
    let uri = to_lsp_uri(&url::Url::from_file_path(&path).unwrap());

    let (mut service, _socket) = LspService::build(Backend::new).finish();
    let init = tower_lsp_server::jsonrpc::Request::build("initialize")
        .id(1_i64)
        .params(serde_json::to_value(InitializeParams::default()).unwrap())
        .finish();
    assert!(service.call(init).await.unwrap().is_some_and(|r| r.is_ok()));

    let backend = service.inner();
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "json".into(),
                version: 1,
                text: manifest(1),
            },
        })
        .await;
    for (express, version) in [(3, 3), (2, 2)] {
        backend
            .did_change(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier {
                    uri: uri.clone(),
                    version,
                },
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: manifest(express),
                }],
            })
            .await;
    }

    let warnings = logs.warnings_containing("change");
    assert!(
        warnings.is_empty(),
        "a superseded edit logged at WARN/ERROR: {warnings:?}"
    );
    assert!(
        !logs.debug_containing("uperseded").is_empty(),
        "a superseded edit must be visible at debug (message contains \"superseded\")"
    );
}

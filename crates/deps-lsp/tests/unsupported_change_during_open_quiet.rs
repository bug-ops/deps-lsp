//! A didChange on an unsupported file that arrives while its didOpen is still resolving is
//! dropped quietly: the client gets no "Change rejected" error message.

use std::sync::{Arc, Mutex};
use std::task::Poll;

use futures::StreamExt as _;
use tower::Service as _;
use tower_lsp_server::LanguageServer as _;
use tower_lsp_server::ls_types::{
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, InitializeParams,
    TextDocumentContentChangeEvent, TextDocumentItem, VersionedTextDocumentIdentifier,
};

#[tokio::test]
async fn change_during_unsupported_open_is_not_reported_to_the_client() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("rustfmt.toml");
    std::fs::write(&path, "x = 1\n").unwrap();
    let uri = deps_lsp::lsp_types_interop::to_lsp_uri(&url::Url::from_file_path(&path).unwrap());

    let (mut service, mut socket) =
        tower_lsp_server::LspService::build(deps_lsp::Backend::new).finish();
    let init = tower_lsp_server::jsonrpc::Request::build("initialize")
        .id(1_i64)
        .params(serde_json::to_value(InitializeParams::default()).unwrap())
        .finish();
    assert!(service.call(init).await.unwrap().is_some_and(|r| r.is_ok()));

    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Some(message) = socket.next().await {
            sink.lock().unwrap().push(format!("{message:?}"));
        }
    });

    let backend = service.inner();
    let open = backend.did_open(DidOpenTextDocumentParams {
        text_document: TextDocumentItem {
            uri: uri.clone(),
            language_id: "toml".into(),
            version: 1,
            text: "x = 1\n".into(),
        },
    });
    let mut open = std::pin::pin!(open);
    assert!(
        matches!(futures::poll!(open.as_mut()), Poll::Pending),
        "open must still be probing"
    );

    let change = backend.did_change(DidChangeTextDocumentParams {
        text_document: VersionedTextDocumentIdentifier {
            uri: uri.clone(),
            version: 2,
        },
        content_changes: vec![TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "x = 2\n".into(),
        }],
    });
    futures::join!(change, open);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let seen = seen.lock().unwrap();
    let rejected: Vec<_> = seen
        .iter()
        .filter(|m| m.contains("Change rejected"))
        .collect();
    assert!(
        rejected.is_empty(),
        "unsupported file reached the client as an error: {rejected:?}"
    );
}

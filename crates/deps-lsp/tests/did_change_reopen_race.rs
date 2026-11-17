//! Regression test for #2022: a `didChange` that started under one open of a document must not
//! commit over a later open of the same URI.
#![cfg(feature = "npm")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code; clippy's allow-*-in-tests does not see this integration test crate"
)]

use std::sync::Arc;

use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{
    DocumentState, ServerState, handle_document_change, handle_document_open,
};
use deps_lsp::lsp_types_interop::to_lsp_uri;
use tokio::sync::RwLock;
use tower_lsp_server::LspService;

const OPEN: &str = r#"{"dependencies": {"express": "^4.18.0"}}"#;
const STALE: &str = r#"{"dependencies": {"express": "^4.18.0", "lodash": "^4.0.0"}}"#;
const REOPEN: &str = r#"{"dependencies": {"express": "^4.19.0"}}"#;

#[tokio::test]
async fn did_change_started_before_a_close_and_reopen_does_not_commit_over_the_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("package.json");
    std::fs::write(&path, OPEN).unwrap();
    let state = Arc::new(ServerState::new());
    let config = Arc::new(RwLock::new(DepsConfig::default()));
    let slot = std::sync::Mutex::new(None);
    let (_service, _socket) = LspService::new(|client| {
        *slot.lock().unwrap() = Some(client.clone());
        Backend::new(client)
    });
    let client = slot.into_inner().unwrap().unwrap();
    let uri = to_lsp_uri(&url::Url::from_file_path(&path).unwrap());

    handle_document_open(
        uri.clone(),
        OPEN.to_owned(),
        Some(1),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    )
    .await
    .unwrap()
    .abort();

    // 1. did_change starts and suspends inside `parse_manifest_blocking`.
    let change = tokio::spawn(handle_document_change(
        uri.clone(),
        STALE.to_owned(),
        Some(2),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    ));
    tokio::task::yield_now().await;
    assert_eq!(
        state.get_document(&uri).unwrap().content,
        OPEN,
        "not yet committed"
    );

    // 2./3. did_close removes the document, did_open re-inserts it (the open path's insert is
    // `update_document`), with no await in between.
    state.remove_document(&uri);
    state.update_document(
        uri.clone(),
        DocumentState::new_without_parse_result(deps_core::EcosystemId::Npm, REOPEN.to_owned()),
    );

    // 4. The stale change finishes.
    let committed = change.await.unwrap().unwrap();
    let content = state.get_document(&uri).unwrap().content.clone();
    assert!(
        committed.is_none(),
        "a change of a closed open returns no task"
    );
    assert_eq!(
        content, REOPEN,
        "the stale did_change committed its content over the reopened document"
    );
}

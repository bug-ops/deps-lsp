//! Regression test for #2022: a `didChange` that started under one open of a document must not
//! commit over a later open of the same URI.
#![cfg(feature = "npm")]
#![expect(clippy::unwrap_used, reason = "test code")]

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

/// Fresh fixtures tried before giving up on seeing the change suspended in its parse.
const ATTEMPTS: usize = 5;

/// Runs the close/reopen interleaving once on a fresh fixture: the stale change's returned task
/// and the document content afterwards. `None` when the change finished on its very first poll,
/// so no reopen could land inside it.
async fn reopen_during_change() -> Option<(Option<tokio::task::JoinHandle<()>>, String)> {
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
    .unwrap();
    state.cancel_background_task(&uri).await;

    // 1. did_change captures the open's epoch on its first poll and suspends in the parse; an
    // unpolled future cannot commit, so the suspension needs no timing assumption.
    let change = handle_document_change(
        uri.clone(),
        STALE.to_owned(),
        Some(2),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    );
    let mut change = std::pin::pin!(change);
    if futures::poll!(change.as_mut()).is_ready() {
        return None;
    }
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
    let committed = change.await.unwrap();
    let content = state.get_document(&uri).unwrap().content.clone();
    Some((committed, content))
}

#[tokio::test]
async fn did_change_started_before_a_close_and_reopen_does_not_commit_over_the_reopen() {
    for _ in 0..ATTEMPTS {
        let Some((committed, content)) = reopen_during_change().await else {
            continue;
        };
        assert!(
            committed.is_none(),
            "a change of a closed open returns no task"
        );
        assert_eq!(
            content, REOPEN,
            "the stale did_change committed its content over the reopened document"
        );
        return;
    }
    panic!(
        "the change finished on its first poll in every attempt, so the race was never exercised"
    );
}

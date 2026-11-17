//! Tests for #2022's didOpen/didChange window: a change dispatched while the open of the same
//! URI is still parsing captures the epoch the open reserved and commits once the open lands.
//!
//! Declared from `lifecycle.rs` as a child module.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;
use deps_core::EcosystemId;

const OPEN_CONTENT: &str = r#"{"dependencies": {"express": "^4.18.0"}}"#;
const CHANGED_CONTENT: &str = r#"{"dependencies": {"express": "^4.20.0"}}"#;

fn package_json_uri() -> Uri {
    crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri("/test/package.json"))
}

fn opened_document() -> DocumentState {
    DocumentState::new_without_parse_result(EcosystemId::Npm, OPEN_CONTENT.to_owned())
}

#[tokio::test]
async fn change_captured_during_an_open_commits_once_the_open_lands() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let reservation = state.reserve_open(&uri);
    let epoch = state
        .capture_open_epoch(&uri)
        .expect("an open still parsing is capturable");
    state.insert_opened(reservation, opened_document());

    assert_eq!(
        state.with_document(&uri, DocumentState::open_epoch),
        Some(epoch),
        "the open stamps the epoch it reserved"
    );
    let task = handle_document_change_guarded(
        uri.clone(),
        CHANGED_CONTENT.to_owned(),
        Some(2),
        CommitGuard::SameOpen(epoch),
        ParseTrigger::Content,
        RefetchPolicy::Diff,
        Arc::clone(&state),
        client,
        config,
    )
    .await
    .unwrap();

    task.expect("the change of the open it captured commits")
        .await
        .unwrap();
    assert_eq!(state.get_document(&uri).unwrap().content, CHANGED_CONTENT);
}

#[tokio::test]
async fn dropped_reservation_leaves_the_uri_untracked() {
    let state = ServerState::new();
    let uri = package_json_uri();

    drop(state.reserve_open(&uri));

    assert_eq!(state.capture_open_epoch(&uri), None);
}

#[tokio::test]
async fn close_clears_a_pending_reservation() {
    let state = ServerState::new();
    let uri = package_json_uri();

    let reservation = state.reserve_open(&uri);
    state.remove_document(&uri);

    assert_eq!(state.capture_open_epoch(&uri), None);
    drop(reservation);
}

#[tokio::test]
async fn an_older_reservation_does_not_release_a_newer_one() {
    let state = ServerState::new();
    let uri = package_json_uri();

    let older = state.reserve_open(&uri);
    let newer = state.reserve_open(&uri);
    let newer_epoch = state.capture_open_epoch(&uri).unwrap();
    drop(older);

    assert_eq!(state.capture_open_epoch(&uri), Some(newer_epoch));
    drop(newer);
    assert_eq!(state.capture_open_epoch(&uri), None);
}

#[tokio::test]
async fn rejected_open_releases_its_reservation() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();
    let oversized = "a".repeat(MAX_FILE_SIZE as usize + 1);

    let result = handle_document_open(
        uri.clone(),
        oversized,
        Some(1),
        Arc::clone(&state),
        client,
        config,
    )
    .await;

    assert!(result.is_err());
    assert_eq!(state.capture_open_epoch(&uri), None);
}

//! Acceptance tests for #2022: `ServerState::register_change_task` registers a change task only
//! for the open it was started under, checked under the `tasks` lock.
//!
//! Declared from `state.rs` as a child module (`#[cfg(test)] #[path = "state_open_epoch_tests.rs"]`),
//! so it can read the private `tasks` registry.

use super::*;
use deps_core::EcosystemId;
use std::time::Duration;
use tower_lsp_server::ls_types::Uri;

fn uri() -> Uri {
    "file:///tmp/open-epoch/Cargo.toml".parse().unwrap()
}

fn open(state: &ServerState, uri: &Uri) {
    state.update_document(
        uri.clone(),
        DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new()),
    );
}

fn close(state: &ServerState, uri: &Uri) {
    state.remove_document(uri);
}

fn pending_task() -> (tokio::task::JoinHandle<()>, tokio::task::AbortHandle) {
    let task = tokio::spawn(std::future::pending::<()>());
    let abort = task.abort_handle();
    (task, abort)
}

async fn eventually_finished(handle: &tokio::task::AbortHandle) -> bool {
    for _ in 0..200 {
        if handle.is_finished() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

async fn registered_id(state: &ServerState, uri: &Uri) -> Option<tokio::task::Id> {
    state.tasks.read().await.get(uri).map(|(id, _)| *id)
}

#[tokio::test]
async fn update_document_stamps_a_fresh_epoch_on_every_open() {
    let state = ServerState::new();
    let uri = uri();

    open(&state, &uri);
    let first = state.with_document(&uri, |d| d.open_epoch()).unwrap();
    open(&state, &uri);
    let repeated_open = state.with_document(&uri, |d| d.open_epoch()).unwrap();
    close(&state, &uri);
    open(&state, &uri);
    let reopened = state.with_document(&uri, |d| d.open_epoch()).unwrap();

    assert_ne!(first, repeated_open);
    assert_ne!(repeated_open, reopened);
    assert_ne!(first, reopened);
}

#[tokio::test]
async fn register_change_task_with_current_epoch_registers_and_aborts_the_previous_task() {
    let state = Arc::new(ServerState::new());
    let uri = uri();
    open(&state, &uri);
    let epoch = state.with_document(&uri, |d| d.open_epoch()).unwrap();

    let (first, first_abort) = pending_task();
    let (second, second_abort) = pending_task();
    let second_id = second.id();

    assert!(state.register_change_task(uri.clone(), first, epoch).await);
    assert!(state.register_change_task(uri.clone(), second, epoch).await);

    assert!(
        eventually_finished(&first_abort).await,
        "the superseded task of the same open must be aborted"
    );
    assert!(!second_abort.is_finished());
    assert_eq!(registered_id(&state, &uri).await, Some(second_id));
    second_abort.abort();
}

#[tokio::test]
async fn register_change_task_after_close_aborts_the_new_task_and_registers_nothing() {
    let state = Arc::new(ServerState::new());
    let uri = uri();
    open(&state, &uri);
    let stale_epoch = state.with_document(&uri, |d| d.open_epoch()).unwrap();
    close(&state, &uri);

    let (stale, stale_abort) = pending_task();
    let registered = state
        .register_change_task(uri.clone(), stale, stale_epoch)
        .await;

    assert!(!registered);
    assert!(eventually_finished(&stale_abort).await);
    assert_eq!(registered_id(&state, &uri).await, None);
}

#[tokio::test]
async fn register_change_task_after_reopen_aborts_only_the_stale_task() {
    let state = Arc::new(ServerState::new());
    let uri = uri();

    open(&state, &uri);
    let stale_epoch = state.with_document(&uri, |d| d.open_epoch()).unwrap();
    close(&state, &uri);

    open(&state, &uri);
    let reopen_epoch = state.with_document(&uri, |d| d.open_epoch()).unwrap();
    assert_ne!(stale_epoch, reopen_epoch);

    let (reopen_fetch, reopen_abort) = pending_task();
    let reopen_id = reopen_fetch.id();
    assert!(
        state
            .register_change_task(uri.clone(), reopen_fetch, reopen_epoch)
            .await
    );

    let typosquat = tokio::spawn(std::future::pending::<()>());
    let typosquat_abort = typosquat.abort_handle();
    let generation = state.next_typosquat_task_generation();
    state
        .track_typosquat_task(uri.clone(), generation, typosquat_abort.clone())
        .await;
    let typosquat_id = state.typosquat_task_id(&uri).await;

    let (stale, stale_abort) = pending_task();
    let registered = state
        .register_change_task(uri.clone(), stale, stale_epoch)
        .await;

    assert!(!registered);
    assert!(
        eventually_finished(&stale_abort).await,
        "the stale task is aborted"
    );
    assert!(
        !reopen_abort.is_finished(),
        "the reopen's fetch task must survive"
    );
    assert_eq!(registered_id(&state, &uri).await, Some(reopen_id));
    assert!(
        !typosquat_abort.is_finished(),
        "the reopen's typosquat task must survive"
    );
    assert_eq!(state.typosquat_task_id(&uri).await, typosquat_id);

    reopen_abort.abort();
    typosquat_abort.abort();
}

#[tokio::test]
async fn register_change_task_for_a_never_opened_uri_registers_nothing() {
    let state = Arc::new(ServerState::new());
    let other: Uri = "file:///tmp/open-epoch-never-opened/Cargo.toml"
        .parse()
        .unwrap();
    let donor: Uri = "file:///tmp/open-epoch-donor/Cargo.toml".parse().unwrap();
    open(&state, &donor);
    let epoch = state.with_document(&donor, |d| d.open_epoch()).unwrap();

    let (task, abort) = pending_task();
    assert!(!state.register_change_task(other.clone(), task, epoch).await);
    assert!(eventually_finished(&abort).await);
    assert_eq!(registered_id(&state, &other).await, None);
}

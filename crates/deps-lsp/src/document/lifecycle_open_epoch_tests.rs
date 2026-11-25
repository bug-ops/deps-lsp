//! Acceptance tests for #2022: a change or reparse that started under one open of a document
//! must not commit over a later open of the same URI, even when the reopen restarts at the same
//! LSP version.
//!
//! Declared from `lifecycle.rs` as a child module (`#[cfg(all(test, feature = "npm"))]
//! #[path = "lifecycle_open_epoch_tests.rs"]`).

#![expect(
    clippy::unwrap_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;

const OPEN_CONTENT: &str = r#"{"dependencies": {"express": "^4.18.0"}}"#;
const REOPEN_CONTENT: &str = r#"{"dependencies": {"express": "^4.19.0"}}"#;
const STALE_CONTENT: &str = r#"{"dependencies": {"express": "^4.18.0", "lodash": "^4.0.0"}}"#;
const NEXT_CONTENT: &str = r#"{"dependencies": {"express": "^4.20.0"}}"#;

struct Race {
    state: Arc<ServerState>,
    uri: Uri,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
}

async fn open(race: &Race, content: &str) {
    handle_document_open(
        race.uri.clone(),
        content.to_owned(),
        Some(1),
        Arc::clone(&race.state),
        race.client.clone(),
        Arc::clone(&race.config),
    )
    .await
    .unwrap();
}

/// Opens, snapshots the open's epoch, closes, and reopens at the same version with different
/// content: the exact interleaving of the issue. A macro rather than a fn so the epoch's type
/// is inferred and never named.
macro_rules! closed_and_reopened {
    () => {{
        let url = deps_core::test_util::test_uri("/test/package.json");
        let (client, config) = create_test_client_and_config();
        let race = Race {
            state: Arc::new(ServerState::new()),
            uri: crate::lsp_types_interop::to_lsp_uri(&url),
            client,
            config,
        };
        open(&race, OPEN_CONTENT).await;
        let stale_epoch = race
            .state
            .with_document(&race.uri, |d| d.open_epoch())
            .unwrap();
        race.state.cancel_background_task(&race.uri).await;
        race.state.remove_document(&race.uri);
        open(&race, REOPEN_CONTENT).await;
        (race, stale_epoch)
    }};
}

async fn guarded_change(
    race: &Race,
    content: &str,
    version: Option<i32>,
    guard: CommitGuard,
) -> Option<JoinHandle<()>> {
    handle_document_change_guarded(
        race.uri.clone(),
        content.to_owned(),
        version,
        guard,
        ParseTrigger::Content,
        RefetchPolicy::Diff,
        Arc::clone(&race.state),
        race.client.clone(),
        Arc::clone(&race.config),
    )
    .await
    .unwrap()
}

fn content_of(race: &Race) -> String {
    race.state.get_document(&race.uri).unwrap().content.clone()
}

#[tokio::test]
async fn same_open_guard_skips_a_commit_from_a_previous_open() {
    let (race, stale_epoch) = closed_and_reopened!();

    let task = guarded_change(
        &race,
        STALE_CONTENT,
        Some(2),
        CommitGuard::SameOpen(stale_epoch),
    )
    .await;

    assert!(task.is_none(), "a stale open's change must return no task");
    assert_eq!(content_of(&race), REOPEN_CONTENT);
}

#[tokio::test]
async fn same_open_and_version_guard_skips_a_previous_open_even_at_the_same_version() {
    let (race, stale_epoch) = closed_and_reopened!();
    let version = race.state.get_document(&race.uri).unwrap().version;
    assert_eq!(
        version,
        Some(1),
        "the reopen restarts at the stale reparse's version"
    );

    let task = guarded_change(
        &race,
        STALE_CONTENT,
        version,
        CommitGuard::SameOpenAndVersion {
            epoch: stale_epoch,
            version,
        },
    )
    .await;

    assert!(task.is_none());
    assert_eq!(content_of(&race), REOPEN_CONTENT);
}

#[tokio::test]
async fn same_open_guard_commits_for_the_current_open() {
    let (race, _stale_epoch) = closed_and_reopened!();
    let current = race
        .state
        .with_document(&race.uri, |d| d.open_epoch())
        .unwrap();

    let task = guarded_change(&race, NEXT_CONTENT, Some(2), CommitGuard::SameOpen(current)).await;

    task.expect("the current open commits").await.unwrap();
    assert_eq!(content_of(&race), NEXT_CONTENT);
}

#[tokio::test]
async fn commit_preserves_the_open_epoch_of_the_entry_it_replaces() {
    let (race, _stale_epoch) = closed_and_reopened!();
    let current = race
        .state
        .with_document(&race.uri, |d| d.open_epoch())
        .unwrap();

    let task = guarded_change(&race, NEXT_CONTENT, Some(2), CommitGuard::SameOpen(current)).await;
    task.expect("commits").await.unwrap();

    let after = race
        .state
        .with_document(&race.uri, |d| d.open_epoch())
        .unwrap();
    assert_eq!(after, current, "an edit is the same open, not a new one");
}

#[tokio::test]
async fn same_open_and_version_guard_still_skips_a_version_mismatch_within_one_open() {
    let (race, _stale_epoch) = closed_and_reopened!();
    let current = race
        .state
        .with_document(&race.uri, |d| d.open_epoch())
        .unwrap();

    let task = guarded_change(
        &race,
        STALE_CONTENT,
        Some(3),
        CommitGuard::SameOpenAndVersion {
            epoch: current,
            version: Some(999),
        },
    )
    .await;

    assert!(task.is_none());
    assert_eq!(content_of(&race), REOPEN_CONTENT);
}

#[tokio::test]
async fn same_open_and_version_guard_commits_when_open_and_version_match() {
    let (race, _stale_epoch) = closed_and_reopened!();
    let current = race
        .state
        .with_document(&race.uri, |d| d.open_epoch())
        .unwrap();

    let task = guarded_change(
        &race,
        NEXT_CONTENT,
        Some(1),
        CommitGuard::SameOpenAndVersion {
            epoch: current,
            version: Some(1),
        },
    )
    .await;

    task.expect("matching open and version commit")
        .await
        .unwrap();
    assert_eq!(content_of(&race), NEXT_CONTENT);
}

#[tokio::test]
async fn public_handle_document_change_keeps_its_signature_and_commits_for_an_open_document() {
    let (race, _stale_epoch) = closed_and_reopened!();

    let task: Option<JoinHandle<()>> = handle_document_change(
        race.uri.clone(),
        NEXT_CONTENT.to_owned(),
        Some(2),
        Arc::clone(&race.state),
        race.client.clone(),
        Arc::clone(&race.config),
    )
    .await
    .unwrap();

    task.expect("an open document commits").await.unwrap();
    assert_eq!(content_of(&race), NEXT_CONTENT);
}

fn npm_state() -> DocumentState {
    DocumentState::new_without_parse_result(deps_core::EcosystemId::Npm, OPEN_CONTENT.to_owned())
}

#[test]
fn same_open_guard_refuses_only_a_strictly_lower_version() {
    let mut current = npm_state();
    let guard = CommitGuard::SameOpen(current.open_epoch());

    current.set_version(Some(3));
    assert!(!guard.admits(&current, Some(2)), "lower is refused");
    assert!(guard.admits(&current, Some(3)), "equal is admitted");
    assert!(guard.admits(&current, Some(4)), "higher is admitted");
    assert!(
        guard.admits(&current, None),
        "unversioned incoming is admitted"
    );

    current.set_version(None);
    assert!(
        guard.admits(&current, Some(1)),
        "unversioned stored is admitted"
    );
}

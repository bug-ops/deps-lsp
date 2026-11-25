//! A change that captured the epoch of an open still in flight is applied once the open lands,
//! not dropped because it committed before the document was inserted (#2161 live contract L4r).
//!
//! Declared from `lifecycle.rs` as a child module.

#![expect(
    clippy::unwrap_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;
use deps_core::EcosystemId;
use std::assert_matches;
use std::task::Poll;

const SETTINGS: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";
const CATALOG: &str = "[versions]\nx = \"1\"\n";
const CHANGED_CATALOG: &str = "[versions]\nx = \"2\"\n";

struct Fixture {
    _dir: tempfile::TempDir,
    claimed: Uri,
    static_catalog: Uri,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS).unwrap();
    let to_uri = |name: &str| {
        let url = url::Url::from_file_path(root.join(name)).unwrap();
        crate::lsp_types_interop::to_lsp_uri(&url)
    };
    Fixture {
        claimed: to_uri("gradle/deps.toml"),
        static_catalog: to_uri("gradle/libs.versions.toml"),
        _dir: dir,
    }
}

/// Drives a change that captured the in-flight open of `uri`: it must stay pending while the
/// open has not landed, and be committed once the open inserts the document.
async fn change_during_open_is_applied_after_the_open_lands(uri: &Uri) {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let state = Arc::new(ServerState::new());
    let (client, config) = create_test_client_and_config();
    let reservation = state.reserve_open(uri);

    let change = handle_document_change_for_open(
        uri.clone(),
        CHANGED_CATALOG.to_owned(),
        Some(2),
        Arc::clone(&state),
        client,
        config,
    );
    let mut change = std::pin::pin!(change);
    for _ in 0..20 {
        tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(1)))
            .await
            .unwrap();
        assert_matches!(
            futures::poll!(change.as_mut()),
            Poll::Pending,
            "a change must wait for the open it captured instead of committing before it lands"
        );
    }

    let document = DocumentState::new_without_parse_result(EcosystemId::Gradle, CATALOG.to_owned());
    assert!(state.insert_opened(reservation, document));
    let Some(committed) = change.await.unwrap().committed() else {
        panic!("the change of the open it captured must commit");
    };

    committed.task.await.unwrap();
    assert_eq!(state.get_document(uri).unwrap().content, CHANGED_CATALOG);
}

#[tokio::test]
async fn change_during_a_claimed_open_is_applied_after_the_open_lands() {
    let fx = fixture();
    change_during_open_is_applied_after_the_open_lands(&fx.claimed).await;
}

#[tokio::test]
async fn change_during_a_static_open_is_applied_after_the_open_lands() {
    let fx = fixture();
    change_during_open_is_applied_after_the_open_lands(&fx.static_catalog).await;
}

/// Starts a change that waits on a reserved open of `uri`, abandons the open, and returns the
/// change's outcome.
async fn change_outcome_when_the_open_is_abandoned(uri: &Uri) -> Result<ChangeOutcome> {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let state = Arc::new(ServerState::new());
    let (client, config) = create_test_client_and_config();
    let reservation = state.reserve_open(uri);

    let change = handle_document_change_for_open(
        uri.clone(),
        CHANGED_CATALOG.to_owned(),
        Some(2),
        Arc::clone(&state),
        client,
        config,
    );
    let mut change = std::pin::pin!(change);
    assert_matches!(futures::poll!(change.as_mut()), Poll::Pending);
    drop(reservation);

    let outcome = change.await;
    assert!(state.get_document(uri).is_none());
    outcome
}

#[tokio::test]
async fn change_waiting_for_an_abandoned_claimed_open_is_unsupported() {
    let fx = fixture();

    let outcome = change_outcome_when_the_open_is_abandoned(&fx.claimed).await;

    assert_matches!(outcome, Err(deps_core::DepsError::UnsupportedEcosystem(_)));
}

#[tokio::test]
async fn change_waiting_for_an_abandoned_static_open_is_dropped() {
    let fx = fixture();

    let outcome = change_outcome_when_the_open_is_abandoned(&fx.static_catalog).await;

    assert_matches!(
        outcome,
        Ok(ChangeOutcome::Dropped(CommitRefusal::Untracked))
    );
}

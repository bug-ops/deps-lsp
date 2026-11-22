//! Tests for #2022's didOpen/didChange window: a change dispatched while the open of the same
//! URI is still parsing captures the epoch the open reserved and commits once the open lands.
//!
//! Declared from `lifecycle.rs` as a child module.

#![expect(
    clippy::unwrap_used,
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

#[tokio::test]
async fn insert_opened_refuses_when_a_close_cleared_the_reservation() {
    let state = ServerState::new();
    let uri = package_json_uri();

    let reservation = state.reserve_open(&uri);
    state.remove_document(&uri);

    assert!(!state.insert_opened(reservation, opened_document()));
    assert!(state.get_document(&uri).is_none());
    assert_eq!(state.capture_open_epoch(&uri), None);
}

#[tokio::test]
async fn insert_opened_refuses_when_a_newer_open_reserved_the_uri() {
    let state = ServerState::new();
    let uri = package_json_uri();

    let older = state.reserve_open(&uri);
    let newer = state.reserve_open(&uri);

    assert!(!state.insert_opened(older, opened_document()));
    assert!(state.get_document(&uri).is_none());
    assert!(state.insert_opened(newer, opened_document()));
    assert!(state.get_document(&uri).is_some());
    assert_eq!(
        state.capture_open_epoch(&uri),
        state.with_document(&uri, DocumentState::open_epoch)
    );
}

/// #2036 (`zz_critic_close_during_open_repro`): the close runs while the open still parses.
/// `join!` polls the open first, so it has reserved its epoch and is suspended in the parse
/// when the close runs.
#[tokio::test]
async fn close_during_the_first_parse_leaves_the_document_closed() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let (opened, ()) = tokio::join!(
        handle_document_open(
            uri.clone(),
            OPEN_CONTENT.to_owned(),
            Some(1),
            Arc::clone(&state),
            client,
            config,
        ),
        async {
            state.remove_document(&uri);
        }
    );

    assert!(
        !opened.unwrap(),
        "a close that won must report the open as superseded"
    );
    assert!(state.get_document(&uri).is_none());
    assert_eq!(state.capture_open_epoch(&uri), None);
    assert!(
        !state.has_background_task(&uri).await,
        "no task may outlive the close"
    );
}

#[tokio::test]
async fn close_then_reopen_during_the_first_parse_keeps_the_second_open() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let first = handle_document_open(
        uri.clone(),
        OPEN_CONTENT.to_owned(),
        Some(1),
        Arc::clone(&state),
        client.clone(),
        Arc::clone(&config),
    );
    let close_and_reopen = async {
        state.remove_document(&uri);
        handle_document_open(
            uri.clone(),
            CHANGED_CONTENT.to_owned(),
            Some(2),
            Arc::clone(&state),
            client.clone(),
            Arc::clone(&config),
        )
        .await
    };
    let (first, second) = tokio::join!(first, close_and_reopen);

    assert!(
        !first.unwrap(),
        "the first open lost to the close and reopen"
    );
    assert!(second.unwrap());
    assert_eq!(state.get_document(&uri).unwrap().content, CHANGED_CONTENT);
}

#[tokio::test]
async fn close_between_insert_and_registration_refuses_the_task() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let change = open_document(
        uri.clone(),
        OPEN_CONTENT.to_owned(),
        Some(1),
        Arc::clone(&state),
        client,
        config,
    )
    .await
    .unwrap()
    .expect("nothing raced the parse");
    state.remove_document(&uri);

    assert!(
        !state
            .register_change_task(uri.clone(), change.task, change.epoch)
            .await
    );
    assert!(state.get_document(&uri).is_none());
    assert!(!state.has_background_task(&uri).await);
}

#[tokio::test]
async fn open_registers_its_task_and_reports_success() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let opened = handle_document_open(
        uri.clone(),
        OPEN_CONTENT.to_owned(),
        Some(1),
        Arc::clone(&state),
        client,
        config,
    )
    .await
    .unwrap();

    assert!(opened);
    assert!(state.has_background_task(&uri).await);
    state.cancel_background_task(&uri).await;
}

#[tokio::test]
async fn cold_start_is_skipped_while_an_open_is_in_flight() {
    let state = Arc::new(ServerState::new());
    let uri = package_json_uri();
    let (client, config) = create_test_client_and_config();

    let reservation = state.reserve_open(&uri);

    assert!(!ensure_document_loaded(&uri, Arc::clone(&state), client, config).await);
    assert_eq!(state.capture_open_epoch(&uri), Some(reservation.epoch()));
    assert!(state.get_document(&uri).is_none());
}

mod cold_start_race {
    use super::*;
    use std::time::Duration;

    const DISK: &str = r#"{"dependencies": {"express": "^4.0.0"}}"#;
    const EDITOR: &str = r#"{"dependencies": {"express": "^4.18.0"}}"#;

    /// A cold start pinned on its config read by a held write lock.
    struct PinnedColdStart {
        uri: Uri,
        state: Arc<ServerState>,
        client: tower_lsp_server::Client,
        config: Arc<RwLock<DepsConfig>>,
        guard: Option<tokio::sync::OwnedRwLockWriteGuard<DepsConfig>>,
        cold: tokio::task::JoinHandle<bool>,
        _dir: tempfile::TempDir,
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    async fn pin_cold_start() -> PinnedColdStart {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(&path, DISK).unwrap();
        let uri = Uri::from_file_path(&path).unwrap();
        let state = Arc::new(ServerState::new());
        let (client, config) = create_test_client_and_config();
        config
            .write()
            .await
            .policy
            .diagnostics
            .vulnerabilities_enabled = false;
        let guard = Arc::clone(&config).write_owned().await;
        let cold = tokio::spawn({
            let (uri, state, client, config) =
                (uri.clone(), state.clone(), client.clone(), config.clone());
            async move { ensure_document_loaded(&uri, state, client, config).await }
        });
        settle().await;
        PinnedColdStart {
            uri,
            state,
            client,
            config,
            guard: Some(guard),
            cold,
            _dir: dir,
        }
    }

    impl PinnedColdStart {
        async fn release(&mut self) -> bool {
            drop(self.guard.take());
            (&mut self.cold).await.unwrap()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn didopen_during_a_cold_start_keeps_the_editor_content() {
        let mut pinned = pin_cold_start().await;
        let open = tokio::spawn({
            let (uri, state, client, config) = (
                pinned.uri.clone(),
                pinned.state.clone(),
                pinned.client.clone(),
                pinned.config.clone(),
            );
            async move {
                handle_document_open(uri, EDITOR.to_owned(), Some(1), state, client, config).await
            }
        });
        settle().await;

        pinned.release().await;

        assert!(open.await.unwrap().unwrap(), "the editor's open must win");
        let content = pinned
            .state
            .with_document(&pinned.uri, |doc| doc.content.clone());
        assert_eq!(content.as_deref(), Some(EDITOR));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn didopen_parsing_during_a_cold_start_is_not_refused() {
        let mut pinned = pin_cold_start().await;
        let state = Arc::clone(&pinned.state);
        let reservation = state.reserve_open(&pinned.uri);

        pinned.release().await;

        assert!(
            state.insert_opened(
                reservation,
                DocumentState::new_without_parse_result(EcosystemId::Npm, EDITOR.to_owned()),
            ),
            "the editor's open must supersede the cold start"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_during_a_cold_start_leaves_the_document_closed() {
        let mut pinned = pin_cold_start().await;
        pinned.state.remove_document(&pinned.uri);
        pinned.state.cancel_background_task(&pinned.uri).await;

        let loaded = pinned.release().await;

        assert!(!loaded);
        assert!(pinned.state.get_document(&pinned.uri).is_none());
        assert!(!pinned.state.has_background_task(&pinned.uri).await);
    }
}

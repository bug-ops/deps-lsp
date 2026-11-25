//! #2161: an open (or a change racing an open) of a `*.toml` that `settings.gradle(.kts)` declares
//! as a version catalog resolves its ecosystem off the runtime workers, with the open's
//! reservation visible to `capture_open_epoch` before the first await, and an unsupported URI
//! releases that reservation.
//!
//! Declared from `lifecycle.rs` as a child module.

#![expect(
    clippy::unwrap_used,
    reason = "test code; clippy's allow-*-in-tests does not see this `cfg(all(test, ..))` module"
)]

use super::*;
use crate::test_utils::test_helpers::create_test_client_and_config;
use deps_core::{DepsError, EcosystemId};
use std::assert_matches;

const SETTINGS: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";
const CATALOG: &str = "[versions]\nx = \"1\"\n";
const CHANGED_CATALOG: &str = "[versions]\nx = \"2\"\n";

struct Fixture {
    _dir: tempfile::TempDir,
    declared: Uri,
    declared_url: url::Url,
    undeclared: Uri,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("gradle")).unwrap();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS).unwrap();
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).unwrap();
    std::fs::write(root.join("other.toml"), CATALOG).unwrap();
    let declared_url = url::Url::from_file_path(root.join("gradle/deps.toml")).unwrap();
    let undeclared_url = url::Url::from_file_path(root.join("other.toml")).unwrap();
    Fixture {
        declared: crate::lsp_types_interop::to_lsp_uri(&declared_url),
        declared_url,
        undeclared: crate::lsp_types_interop::to_lsp_uri(&undeclared_url),
        _dir: dir,
    }
}

fn gradle_document() -> DocumentState {
    DocumentState::new_without_parse_result(EcosystemId::Gradle, CATALOG.to_owned())
}

#[tokio::test]
async fn reserve_and_resolve_exposes_the_reservation_while_the_probe_is_pending() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());

    let mut open = std::pin::pin!(reserve_and_resolve(&state, &fx.declared, None));
    let first_poll = futures::poll!(open.as_mut());

    assert!(
        first_poll.is_pending(),
        "the probe must still be running, or this test proves nothing"
    );
    assert!(state.capture_open_epoch(&fx.declared).is_some());
    assert!(state.get_document(&fx.declared).is_none());
}

#[tokio::test]
async fn reserve_and_resolve_resolves_a_declared_catalog_to_gradle() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());

    let Ok(resolved) = reserve_and_resolve(&state, &fx.declared, None).await else {
        panic!("a declared catalog must resolve");
    };

    assert_eq!(resolved.ecosystem.ecosystem_id(), EcosystemId::Gradle);
    assert_eq!(resolved.domain_uri, fx.declared_url);
    assert!(state.capture_open_epoch(&fx.declared).is_some());
}

#[tokio::test]
async fn change_ecosystem_resolves_a_claimed_uri_while_an_open_holds_a_reservation() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let _reservation = state.reserve_open(&fx.declared);

    assert!(
        state.ecosystem_registry.for_uri(&fx.declared_url).is_none(),
        "static routing does not know the catalog"
    );
    let resolved = change_ecosystem(&state, &fx.declared, &fx.declared_url)
        .await
        .unwrap();

    assert_eq!(resolved.ecosystem_id(), EcosystemId::Gradle);
}

#[tokio::test]
async fn change_ecosystem_resolves_a_claimed_uri_during_a_cold_start_reservation() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let _cold_start = state.try_reserve_cold_start(&fx.declared).unwrap();

    let resolved = change_ecosystem(&state, &fx.declared, &fx.declared_url)
        .await
        .unwrap();

    assert_eq!(resolved.ecosystem_id(), EcosystemId::Gradle);
}

#[tokio::test]
async fn change_ecosystem_does_not_probe_a_uri_that_is_neither_tracked_nor_opening() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());

    let before = deps_core::fs_probe::snapshot();
    let resolved = change_ecosystem(&state, &fx.declared, &fx.declared_url).await;
    let after = deps_core::fs_probe::snapshot();

    assert!(resolved.is_none());
    assert_eq!(
        after, before,
        "no filesystem probe for a URI that is not open"
    );
}

#[tokio::test]
async fn tracked_ecosystem_returns_the_stored_ecosystem_of_a_tracked_document() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let reservation = state.reserve_open(&fx.declared);
    state.insert_opened(reservation, gradle_document());

    let before = deps_core::fs_probe::snapshot();
    let tracked = tracked_ecosystem(&state, &fx.declared, &fx.declared_url).unwrap();
    let after = deps_core::fs_probe::snapshot();

    assert_eq!(tracked.ecosystem_id(), EcosystemId::Gradle);
    assert_eq!(after, before, "tracked_ecosystem performs no I/O");
}

#[tokio::test]
async fn change_captured_during_a_claimed_open_commits_once_the_open_lands() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let (client, config) = create_test_client_and_config();

    let reservation = state.reserve_open(&fx.declared);
    let epoch = state.capture_open_epoch(&fx.declared).unwrap();
    let while_untracked = change_ecosystem(&state, &fx.declared, &fx.declared_url)
        .await
        .unwrap();
    assert_eq!(while_untracked.ecosystem_id(), EcosystemId::Gradle);
    assert!(state.insert_opened(reservation, gradle_document()));

    let task = handle_document_change_guarded(
        fx.declared.clone(),
        CHANGED_CATALOG.to_owned(),
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
    assert_eq!(
        state.get_document(&fx.declared).unwrap().content,
        CHANGED_CATALOG
    );
}

#[tokio::test]
async fn reserve_and_resolve_rejects_an_undeclared_toml_and_releases_the_reservation() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());

    let result = reserve_and_resolve(&state, &fx.undeclared, None).await;

    assert_matches!(
        result.as_ref().err(),
        Some(DepsError::UnsupportedEcosystem(_))
    );
    assert_eq!(state.capture_open_epoch(&fx.undeclared), None);
}

#[tokio::test]
async fn reserve_and_resolve_dropped_while_probing_releases_the_reservation() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());

    {
        let mut open = std::pin::pin!(reserve_and_resolve(&state, &fx.undeclared, None));
        assert!(
            futures::poll!(open.as_mut()).is_pending(),
            "the probe must still be running, or this test proves nothing"
        );
        assert!(state.capture_open_epoch(&fx.undeclared).is_some());
    }

    assert_eq!(state.capture_open_epoch(&fx.undeclared), None);
}

#[tokio::test]
async fn reserve_and_resolve_reuses_a_cold_start_reservation() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let cold_start = state.try_reserve_cold_start(&fx.declared).unwrap();
    let epoch = state.capture_open_epoch(&fx.declared).unwrap();

    let Ok(resolved) = reserve_and_resolve(&state, &fx.declared, Some(cold_start)).await else {
        panic!("a declared catalog must resolve");
    };

    assert_eq!(resolved.ecosystem.ecosystem_id(), EcosystemId::Gradle);
    assert_eq!(state.capture_open_epoch(&fx.declared), Some(epoch));
}

#[tokio::test]
async fn change_for_an_untracked_unopened_catalog_is_dropped_quietly() {
    let _guard = deps_core::fs_probe::snapshot_guard_async().await;
    let fx = fixture();
    let state = Arc::new(ServerState::new());
    let (client, config) = create_test_client_and_config();

    let result = handle_document_change_for_open(
        fx.declared.clone(),
        CHANGED_CATALOG.to_owned(),
        Some(2),
        Arc::clone(&state),
        client,
        config,
    )
    .await;

    assert_matches!(result, Ok(None), "not an error");
    assert!(state.get_document(&fx.declared).is_none());
}

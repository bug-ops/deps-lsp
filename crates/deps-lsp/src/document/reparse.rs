//! Shared reparse driver for issue #590 (watched config file changes) and issue #592
//! (live-reloadable `DepsConfig` settings): reparses every currently open document matching
//! a [`ReparseScope`], reusing the version-guarded, sequential-await machinery
//! [`handle_document_change_guarded`] already provides against a concurrent `did_change`.

use super::lifecycle::{CommitGuard, RefetchPolicy, handle_document_change_guarded};
use super::state::{CLIENT_REFRESH_TIMEOUT, ServerState};
use crate::config::{DepsConfig, ReparseScope};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

/// Debounce window for coalescing a burst of `workspace/didChangeConfiguration`
/// notifications (issue #592) into a single reparse — a settings-file save can emit
/// several notifications in quick succession. Independent of the 100ms lifecycle debounce
/// in `document::lifecycle::run_document_change_task`: `Loading` is only ever set inside
/// the fetch window itself (see `fetch_registry_versions_for_change`), so this value only
/// affects how many separate reparse rounds a burst produces, never a
/// diagnostics-suppression window.
pub(crate) const RECONFIGURE_DEBOUNCE: Duration = Duration::from_millis(250);

/// Upper bound on how long a coalesced config-change reparse may be deferred by a
/// continuous burst of `workspace/didChangeConfiguration` notifications arriving faster
/// than [`RECONFIGURE_DEBOUNCE`] (issue #592 security M3). Without this cap, a chatty
/// client (e.g. an editor watching a settings file that re-saves repeatedly) could starve
/// the reparse indefinitely while `set_registry_policy` has already taken effect —
/// hover/diagnostics would keep rendering `cached_versions` resolved under a revoked
/// policy for as long as the burst continues. See `ServerState::pending_reparse_overdue`.
pub(crate) const MAX_DEBOUNCE_WAIT: Duration = Duration::from_secs(2);

/// Reparses every open document matching `scope`, sharing the version-guarded,
/// sequential-await machinery [`handle_document_change_guarded`] provides.
///
/// A free function rather than a `Backend` method (issue #592 critic S6): `Backend` is a
/// plain struct, never `Arc`-shared, so a `did_change_configuration`-triggered reparse
/// (which must run detached, since a notification owes no response) cannot be a
/// `tokio::spawn`ed `&self` method. `crate::server::Backend::handle_watched_config_change`
/// (issue #590) awaits this directly instead of spawning it, since that path is triggered
/// by a `didChangeWatchedFiles` notification handler that already returns promptly.
///
/// Reparses are awaited one at a time, not concurrently: this preserves the version-guard
/// semantics `commit_parsed_document`'s `CommitGuard::ExpectVersion` relies on (a
/// concurrent `did_change` for one document must never be reverted by a stale reparse for
/// another in this loop), and bounds peak memory to one document's content/AST at a time.
/// An `Ok(None)` skip must never touch the task registry — see
/// [`handle_document_change_guarded`]'s doc for why.
pub(crate) async fn reparse_open_documents(
    scope: ReparseScope,
    refetch: RefetchPolicy,
    reason: &'static str,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) {
    let affected: Vec<(Uri, String, Option<i32>)> = state
        .documents
        .iter()
        .filter(|entry| scope.matches(entry.value().ecosystem_id()))
        .map(|entry| {
            (
                entry.key().clone(),
                entry.value().content.clone(),
                entry.value().version,
            )
        })
        .collect();

    // #590's watched-config path previously sent only the inlay-hint/code-lens refresh
    // below, never `workspace/diagnostic/refresh` — an omission, not a design choice: a
    // reparse changes parse results exactly as a config-change reparse does, so a
    // pull-diagnostics client benefits identically (issue #592 critic M5). Made the same
    // for both callers deliberately. Spawned detached and timeout-bounded, rather than
    // awaited inline like `did_change_configuration`'s own no-reparse-needed fast path,
    // since an unresponsive client must not hang whichever caller is awaiting this
    // function — it would otherwise leak a detached task rather than hang a handler.
    //
    // Fired *before* the `affected.is_empty()` early return below (critic M3): pre-#592,
    // `did_change_configuration` sent this refresh unconditionally for any parse-affecting
    // change, regardless of whether the change currently affects any open document — a
    // pull-diagnostics client with no open documents in the changed scope must not lose
    // that invalidation signal just because nothing needed reparsing *this time*.
    if state.diagnostic_refresh_supported() {
        let client = client.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(
                CLIENT_REFRESH_TIMEOUT,
                client.workspace_diagnostic_refresh(),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!("workspace/diagnostic/refresh failed: {:?}", e),
                Err(_) => tracing::debug!("workspace/diagnostic/refresh timed out"),
            }
        });
    }

    if affected.is_empty() {
        tracing::debug!("no open documents affected by {reason}");
        return;
    }

    tracing::info!(
        "reparsing {} document(s) affected by {reason}",
        affected.len()
    );

    for (uri, content, version) in affected {
        match handle_document_change_guarded(
            uri.clone(),
            content,
            version,
            CommitGuard::ExpectVersion(version),
            refetch,
            Arc::clone(&state),
            client.clone(),
            Arc::clone(&config),
        )
        .await
        {
            Ok(Some(task)) => state.spawn_background_task(uri, task).await,
            // A skip (superseded by a concurrent `did_change`) must never touch the task
            // registry for this URI — `spawn_background_task` unconditionally aborts
            // whatever task is already registered there, which would cancel the
            // concurrent edit's own, already-installed background task.
            Ok(None) => tracing::debug!(
                "skipped stale reparse for {:?}: superseded by a concurrent edit",
                uri
            ),
            Err(e) => tracing::error!("failed to reparse {:?} after {reason}: {}", uri, e),
        }
    }

    // Detached, capability-gated, timeout-bounded (issue #493 precedent): see
    // `ServerState::spawn_refresh_requests` for rationale.
    state.spawn_refresh_requests(&client);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use deps_core::EcosystemId;

    /// A `scope` that matches no open document must be a quiet no-op.
    #[tokio::test]
    async fn test_reparse_open_documents_with_no_matching_documents_is_noop() {
        let state = Arc::new(ServerState::new());
        let (client, config) = create_test_client_and_config();

        // Empty `state.documents` — nothing to match regardless of scope.
        reparse_open_documents(
            ReparseScope::All,
            RefetchPolicy::Diff,
            "test",
            state,
            client,
            config,
        )
        .await;
    }

    /// A scope that matches no open document's ecosystem is also a no-op, even when
    /// documents exist — proving `ReparseScope::matches` is actually consulted, not just
    /// the emptiness of `state.documents`.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_reparse_open_documents_scope_excluding_every_document_is_noop() {
        let state = Arc::new(ServerState::new());
        let (client, config) = create_test_client_and_config();
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
        let mut doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        doc_state.set_version(Some(1));
        state.update_document(uri.clone(), doc_state);

        // "npm" matches no document here — the cargo document must be left untouched
        // (still present, still version 1, no background task installed for it).
        reparse_open_documents(
            ReparseScope::Ecosystems(vec!["npm"]),
            RefetchPolicy::Diff,
            "test",
            Arc::clone(&state),
            client,
            config,
        )
        .await;

        let doc = state.get_document(&uri).unwrap();
        assert_eq!(doc.version, Some(1));
        assert_eq!(doc.ecosystem, EcosystemId::Cargo);
    }
}

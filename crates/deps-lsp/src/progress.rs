//! LSP Work Done Progress protocol support for loading indicators.
//!
//! Drives the LSP work-done-progress lifecycle (begin → report → end) from a
//! [`deps_engine::progress`] port: [`RegistryProgress::start`] opens the port via
//! [`deps_engine::progress::channel`] and spawns a task draining the paired receiver into
//! `$/progress` notifications.
//!
//! # Protocol Flow
//!
//! 1. `window/workDoneProgress/create` - Request token creation
//! 2. `$/progress` with `WorkDoneProgressBegin` - Start indicator
//! 3. `$/progress` with `WorkDoneProgressReport` - Update progress (via channel)
//! 4. `$/progress` with `WorkDoneProgressEnd` - Complete indicator

use crate::document::ServerState;
use dashmap::DashMap;
pub use deps_engine::progress::{ProgressSender, ProgressUpdate};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tower_lsp_server::Client;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::{
    ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressEnd, WorkDoneProgressReport,
};

/// Set by the task registry just before it aborts a task, so a [`RegistryProgress`] dropped by
/// that abort can tell a deliberate cancellation from a leaked indicator (#2001).
#[derive(Debug, Clone, Default)]
pub(crate) struct AbortMarker(Arc<AtomicBool>);

impl AbortMarker {
    fn set(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Markers of the tasks currently holding a [`RegistryProgress`], keyed by task id, so the task
/// registry can flag a task as deliberately aborted before it aborts it (#2001).
#[derive(Debug, Default)]
pub(crate) struct AbortRegistry(DashMap<tokio::task::Id, AbortMarker>);

impl AbortRegistry {
    /// Registers the calling task and returns its marker; outside a spawned task the marker is
    /// never set.
    pub(crate) fn register_current(self: &Arc<Self>) -> AbortRegistration {
        let marker = AbortMarker::default();
        let task = tokio::task::try_id();
        if let Some(id) = task {
            self.0.insert(id, marker.clone());
        }
        AbortRegistration {
            marker,
            registry: Arc::clone(self),
            task,
        }
    }

    /// Flags `task` as about to be aborted deliberately; a no-op for a task holding no progress.
    pub(crate) fn mark_aborted(&self, task: tokio::task::Id) {
        if let Some(marker) = self.0.get(&task) {
            marker.set();
        }
    }
}

/// A task's entry in the [`AbortRegistry`], removed on drop so the registry holds exactly the
/// tasks with a live progress indicator.
#[derive(Debug)]
pub(crate) struct AbortRegistration {
    marker: AbortMarker,
    registry: Arc<AbortRegistry>,
    task: Option<tokio::task::Id>,
}

impl Drop for AbortRegistration {
    fn drop(&mut self) {
        if let Some(task) = self.task {
            self.registry.0.remove(&task);
        }
    }
}

/// Opens the registry progress report when the client supports it, bounded by a short timeout
/// so a slow client cannot stall the fetch.
pub(crate) async fn start_registry_progress(
    state: &ServerState,
    client: &Client,
    uri: &tower_lsp_server::ls_types::Uri,
    dep_count: usize,
) -> (Option<RegistryProgress>, Option<ProgressSender>) {
    if !state.supports_progress() {
        return (None, None);
    }
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        RegistryProgress::start(client.clone(), uri.as_str(), dep_count),
    )
    .await
    {
        Ok(Ok((progress, sender))) => (
            Some(progress.with_abort_registration(state.abort_registry().register_current())),
            Some(sender),
        ),
        _ => (None, None),
    }
}

/// Progress tracker for registry data fetching.
///
/// Owns the LSP progress lifecycle (begin → report → end).
/// Creates a [`ProgressSender`] for non-blocking updates from fetch tasks.
pub struct RegistryProgress {
    client: Client,
    token: ProgressToken,
    active: bool,
    abort: Option<AbortRegistration>,
    /// Background task draining progress updates.
    /// Dropped when `RegistryProgress` is dropped or `end()` is called.
    _consumer_handle: tokio::task::JoinHandle<()>,
}

impl RegistryProgress {
    /// Create and start a new progress indicator.
    ///
    /// Returns both the progress tracker and a [`ProgressSender`] for
    /// non-blocking updates from fetch tasks.
    ///
    /// Callers wrap this in a short timeout so a slow/unresponsive client can't
    /// stall a fetch. If the timeout fires while the `create` round-trip is
    /// still pending after the request bytes already reached the client, the
    /// client may register a token this call never learns about and therefore
    /// never sends `begin`/`end` for. This is an accepted trade-off: no `begin`
    /// means spec-compliant clients show no UI for it, so the only cost is a
    /// harmless dangling token client-side.
    ///
    /// # Errors
    ///
    /// Returns an error if the `window/workDoneProgress/create` request to the client
    /// fails or is rejected.
    pub async fn start(
        client: Client,
        uri: &str,
        total_deps: usize,
    ) -> Result<(Self, ProgressSender)> {
        let token = ProgressToken::String(format!("deps-fetch-{}", uri));

        client
            .send_request::<tower_lsp_server::ls_types::request::WorkDoneProgressCreate>(
                tower_lsp_server::ls_types::WorkDoneProgressCreateParams {
                    token: token.clone(),
                },
            )
            .await?;

        client
            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                ProgressParams {
                    token: token.clone(),
                    value: ProgressParamsValue::WorkDone(WorkDoneProgress::Begin(
                        WorkDoneProgressBegin {
                            title: "Fetching package versions".to_string(),
                            message: Some(format!("Loading {} dependencies...", total_deps)),
                            cancellable: Some(false),
                            percentage: Some(0),
                        },
                    )),
                },
            )
            .await;

        let (sender, rx) = deps_engine::progress::channel(total_deps);

        let consumer_client = client.clone();
        let consumer_token = token.clone();
        let consumer_handle = tokio::spawn(async move {
            consume_progress_updates(rx, consumer_client, consumer_token).await;
        });

        Ok((
            Self {
                client,
                token,
                active: true,
                abort: None,
                _consumer_handle: consumer_handle,
            },
            sender,
        ))
    }

    fn with_abort_registration(mut self, abort: AbortRegistration) -> Self {
        self.abort = Some(abort);
        self
    }

    /// End progress indicator.
    pub async fn end(mut self, success: bool) {
        if !self.active {
            return;
        }

        self.active = false;

        // Remaining updates are irrelevant after end.
        self._consumer_handle.abort();

        let message = if success {
            "Package versions loaded"
        } else {
            "Failed to fetch some versions"
        };

        self.client
            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                ProgressParams {
                    token: self.token.clone(),
                    value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(
                        WorkDoneProgressEnd {
                            message: Some(message.to_string()),
                        },
                    )),
                },
            )
            .await;
    }
}

/// Drains progress updates from the channel and sends LSP notifications.
async fn consume_progress_updates(
    mut rx: mpsc::Receiver<ProgressUpdate>,
    client: Client,
    token: ProgressToken,
) {
    while let Some(update) = rx.recv().await {
        let percentage = if update.total > 0 {
            ((update.fetched as f64 / update.total as f64) * 100.0) as u32
        } else {
            0
        };

        client
            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                ProgressParams {
                    token: token.clone(),
                    value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(
                        WorkDoneProgressReport {
                            message: Some(format!(
                                "Fetched {}/{} packages",
                                update.fetched, update.total
                            )),
                            percentage: Some(percentage),
                            cancellable: Some(false),
                        },
                    )),
                },
            )
            .await;
    }
}

/// Ensure progress is cleaned up on drop
impl Drop for RegistryProgress {
    fn drop(&mut self) {
        if self.active {
            if self
                .abort
                .as_ref()
                .is_some_and(|abort| abort.marker.is_set())
            {
                tracing::debug!(
                    token = ?self.token,
                    "fetch aborted by a newer task; ending its progress"
                );
            } else {
                tracing::warn!(
                    token = ?self.token,
                    "RegistryProgress dropped without explicit end() - spawning cleanup"
                );
            }
            self._consumer_handle.abort();
            let client = self.client.clone();
            let token = self.token.clone();
            tokio::spawn(async move {
                client
                    .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                        ProgressParams {
                            token,
                            value: ProgressParamsValue::WorkDone(WorkDoneProgress::End(
                                WorkDoneProgressEnd { message: None },
                            )),
                        },
                    )
                    .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn marking_an_aborted_task_sets_its_marker_and_dropping_deregisters() {
        let registry = Arc::new(AbortRegistry::default());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn({
            let registry = Arc::clone(&registry);
            async move {
                let registration = registry.register_current();
                tx.send(registration.marker.clone()).unwrap();
                std::future::pending::<()>().await;
                drop(registration);
            }
        });
        let marker = rx.await.unwrap();
        assert!(!marker.is_set());

        registry.mark_aborted(task.id());
        assert!(marker.is_set());

        task.abort();
        let _ = task.await;
        assert!(
            registry.0.is_empty(),
            "an aborted task's registration must be removed on drop"
        );
    }

    /// Spawns a task that enrolls itself in `state`'s abort registry and parks, returning its
    /// handle and marker.
    async fn parked_progress_task(
        state: &Arc<ServerState>,
    ) -> (tokio::task::JoinHandle<()>, AbortMarker) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let registry = Arc::clone(state.abort_registry());
        let task = tokio::spawn(async move {
            let registration = registry.register_current();
            tx.send(registration.marker.clone()).unwrap();
            std::future::pending::<()>().await;
            drop(registration);
        });
        (task, rx.await.unwrap())
    }

    fn test_uri() -> tower_lsp_server::ls_types::Uri {
        "file:///tmp/abort-marker/Cargo.toml".parse().unwrap()
    }

    #[tokio::test]
    async fn replacing_a_background_task_marks_the_old_one_aborted() {
        let state = Arc::new(ServerState::new());
        let uri = test_uri();
        let (first, marker) = parked_progress_task(&state).await;
        state.spawn_background_task(uri.clone(), first).await;
        assert!(!marker.is_set());

        let (second, second_marker) = parked_progress_task(&state).await;
        state.spawn_background_task(uri.clone(), second).await;

        assert!(marker.is_set(), "the superseded task must be marked");
        assert!(
            !second_marker.is_set(),
            "the replacement must stay unmarked"
        );
    }

    #[tokio::test]
    async fn cancelling_a_background_task_marks_it_aborted() {
        let state = Arc::new(ServerState::new());
        let uri = test_uri();
        let (task, marker) = parked_progress_task(&state).await;
        state.spawn_background_task(uri.clone(), task).await;

        state.cancel_background_task(&uri).await;

        assert!(marker.is_set());
    }

    fn progress_holding(abort: Option<AbortRegistration>) -> RegistryProgress {
        let (client, _) = crate::test_utils::test_helpers::create_test_client_and_config();
        RegistryProgress {
            client,
            token: ProgressToken::String("deps-fetch-test".to_string()),
            active: true,
            abort,
            _consumer_handle: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn dropping_progress_after_a_deliberate_abort_logs_at_debug_only() {
        let registry = Arc::new(AbortRegistry::default());
        let registration = registry.register_current();
        registration.marker.set();

        let log =
            deps_core::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
                drop(progress_holding(Some(registration)));
            })
            .await;

        assert!(log.contains("aborted by a newer task"), "{log}");
        assert!(!log.contains("dropped without explicit end()"), "{log}");
    }

    #[tokio::test]
    async fn dropping_unmarked_progress_still_warns() {
        let registry = Arc::new(AbortRegistry::default());

        let log =
            deps_core::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
                drop(progress_holding(Some(registry.register_current())));
            })
            .await;

        assert!(log.contains("dropped without explicit end()"), "{log}");
        assert!(!log.contains("aborted by a newer task"), "{log}");
    }

    #[tokio::test]
    async fn marking_an_unregistered_task_is_a_no_op() {
        let registry = AbortRegistry::default();
        let id = tokio::spawn(async {}).id();
        registry.mark_aborted(id);
        assert!(registry.0.is_empty());
    }

    #[test]
    fn test_progress_token_format() {
        let uri = "file:///test/Cargo.toml";
        let token = format!("deps-fetch-{}", uri);
        assert_eq!(token, "deps-fetch-file:///test/Cargo.toml");
    }

    #[test]
    fn test_progress_message_format() {
        let format_message = |fetched: usize, total: usize| -> String {
            format!("Fetched {}/{} packages", fetched, total)
        };

        assert_eq!(format_message(5, 10), "Fetched 5/10 packages");
        assert_eq!(format_message(0, 15), "Fetched 0/15 packages");
        assert_eq!(format_message(20, 20), "Fetched 20/20 packages");
    }
}

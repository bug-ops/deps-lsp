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

pub use deps_engine::progress::{ProgressSender, ProgressUpdate};
use tokio::sync::mpsc;
use tower_lsp_server::Client;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::{
    ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressEnd, WorkDoneProgressReport,
};

/// Progress tracker for registry data fetching.
///
/// Owns the LSP progress lifecycle (begin → report → end).
/// Creates a [`ProgressSender`] for non-blocking updates from fetch tasks.
pub struct RegistryProgress {
    client: Client,
    token: ProgressToken,
    active: bool,
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

        // Request progress token creation (blocking request to client)
        client
            .send_request::<tower_lsp_server::ls_types::request::WorkDoneProgressCreate>(
                tower_lsp_server::ls_types::WorkDoneProgressCreateParams {
                    token: token.clone(),
                },
            )
            .await?;

        // Send begin notification
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

        // Spawn consumer task that drains the channel and sends LSP notifications
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
                _consumer_handle: consumer_handle,
            },
            sender,
        ))
    }

    /// End progress indicator.
    pub async fn end(mut self, success: bool) {
        if !self.active {
            return;
        }

        self.active = false;

        // Abort the consumer task — remaining updates are irrelevant after end
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
            tracing::warn!(
                token = ?self.token,
                "RegistryProgress dropped without explicit end() - spawning cleanup"
            );
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

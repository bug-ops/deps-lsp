//! LSP Work Done Progress protocol support for loading indicators.
//!
//! Uses a channel-based architecture to decouple progress producers (fetch tasks)
//! from the LSP transport consumer, preventing backpressure from blocking fetches.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     mpsc channel     ┌──────────────┐     LSP transport
//! │ fetch task 1 │──┐                   │              │──────────────────►
//! │ fetch task 2 │──┼── ProgressUpdate ──► progress    │  send_notification
//! │ fetch task N │──┘                   │   task       │──────────────────►
//! └─────────────┘                       └──────────────┘
//! ```
//!
//! # Protocol Flow
//!
//! 1. `window/workDoneProgress/create` - Request token creation
//! 2. `$/progress` with `WorkDoneProgressBegin` - Start indicator
//! 3. `$/progress` with `WorkDoneProgressReport` - Update progress (via channel)
//! 4. `$/progress` with `WorkDoneProgressEnd` - Complete indicator

use tokio::sync::mpsc;
use tower_lsp_server::Client;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::{
    ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressEnd, WorkDoneProgressReport,
};

/// Channel capacity for progress updates.
/// Small buffer is sufficient since updates are coalesced by the editor.
const PROGRESS_CHANNEL_CAPACITY: usize = 8;

/// Non-blocking sender for progress updates from fetch tasks.
///
/// Cheap to clone and safe to use from multiple concurrent futures.
/// Dropped messages are acceptable — progress is best-effort UI feedback.
#[derive(Clone)]
pub struct ProgressSender {
    tx: mpsc::Sender<ProgressUpdate>,
    total: usize,
}

struct ProgressUpdate {
    fetched: usize,
    total: usize,
}

impl ProgressSender {
    /// Send a progress update without blocking.
    ///
    /// Uses `try_send` — if the channel is full, the update is silently dropped.
    /// This is intentional: progress is best-effort UI feedback, and dropping
    /// updates is always preferable to blocking fetch tasks.
    pub fn send(&self, fetched: usize) {
        let _ = self.tx.try_send(ProgressUpdate {
            fetched,
            total: self.total,
        });
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
    /// Background task draining progress updates.
    /// Dropped when `RegistryProgress` is dropped or `end()` is called.
    _consumer_handle: tokio::task::JoinHandle<()>,
}

impl RegistryProgress {
    /// Create and start a new progress indicator.
    ///
    /// Returns both the progress tracker and a [`ProgressSender`] for
    /// non-blocking updates from fetch tasks.
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

        let (tx, rx) = mpsc::channel(PROGRESS_CHANNEL_CAPACITY);

        // Spawn consumer task that drains the channel and sends LSP notifications
        let consumer_client = client.clone();
        let consumer_token = token.clone();
        let consumer_handle = tokio::spawn(async move {
            consume_progress_updates(rx, consumer_client, consumer_token).await;
        });

        let sender = ProgressSender {
            tx,
            total: total_deps,
        };

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
    fn test_percentage_calculation() {
        let calculate = |fetched: usize, total: usize| -> u32 {
            if total == 0 {
                return 0;
            }
            ((fetched as f64 / total as f64) * 100.0) as u32
        };

        assert_eq!(calculate(0, 10), 0);
        assert_eq!(calculate(5, 10), 50);
        assert_eq!(calculate(10, 10), 100);
        assert_eq!(calculate(7, 10), 70);
        assert_eq!(calculate(0, 0), 0);
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

    #[tokio::test]
    async fn test_progress_sender_try_send_on_closed_channel() {
        use super::*;

        let (tx, rx) = mpsc::channel(1);
        let sender = ProgressSender { tx, total: 10 };

        // Drop receiver — channel is closed
        drop(rx);

        // Should not panic
        sender.send(5);
    }

    #[tokio::test]
    async fn test_progress_sender_try_send_on_full_channel() {
        use super::*;

        let (tx, _rx) = mpsc::channel(1);
        let sender = ProgressSender { tx, total: 10 };

        // Fill the channel
        sender.send(1);
        // Should silently drop — channel is full
        sender.send(2);
        sender.send(3);
    }
}

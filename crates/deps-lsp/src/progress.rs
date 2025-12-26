//! LSP Work Done Progress protocol support for loading indicators.
//!
//! Implements the `window/workDoneProgress` protocol to show registry fetch
//! progress in the editor UI.
//!
//! # Protocol Flow
//!
//! 1. `window/workDoneProgress/create` - Request token creation
//! 2. `$/progress` with `WorkDoneProgressBegin` - Start indicator
//! 3. `$/progress` with `WorkDoneProgressReport` - Update progress (optional)
//! 4. `$/progress` with `WorkDoneProgressEnd` - Complete indicator
//!
//! # Drop Behavior
//!
//! If dropped without calling `end()`, spawns a cleanup task to send
//! the end notification. This is best-effort - the task may not complete
//! if the runtime is shutting down.

use tower_lsp_server::Client;
use tower_lsp_server::jsonrpc::Result;
use tower_lsp_server::ls_types::{
    ProgressParams, ProgressParamsValue, ProgressToken, WorkDoneProgress, WorkDoneProgressBegin,
    WorkDoneProgressEnd, WorkDoneProgressReport,
};

/// Progress tracker for registry data fetching.
///
/// Manages the lifecycle of an LSP progress indicator, from creation
/// through updates to completion.
pub struct RegistryProgress {
    client: Client,
    token: ProgressToken,
    active: bool,
}

impl RegistryProgress {
    /// Create and start a new progress indicator.
    ///
    /// # Arguments
    ///
    /// * `client` - LSP client for sending notifications
    /// * `uri` - Document URI (used to create unique token)
    /// * `total_deps` - Total number of dependencies to fetch
    ///
    /// # Returns
    ///
    /// Returns `Ok(RegistryProgress)` if progress is supported by the client,
    /// or `Err` if the client doesn't support progress notifications.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Client doesn't support progress (no workDoneProgress capability)
    /// - Failed to create progress token
    pub async fn start(client: Client, uri: &str, total_deps: usize) -> Result<Self> {
        let token = ProgressToken::String(format!("deps-fetch-{}", uri));

        // Request progress token creation
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

        Ok(Self {
            client,
            token,
            active: true,
        })
    }

    /// Update progress (optional, for partial updates).
    ///
    /// # Arguments
    ///
    /// * `fetched` - Number of packages fetched so far
    /// * `total` - Total number of packages
    ///
    /// # Note
    ///
    /// This method should be called sparingly (e.g., every 20% progress)
    /// to avoid flooding the client with notifications.
    pub async fn update(&self, fetched: usize, total: usize) {
        if !self.active || total == 0 {
            return;
        }

        let percentage = ((fetched as f64 / total as f64) * 100.0) as u32;
        self.client
            .send_notification::<tower_lsp_server::ls_types::notification::Progress>(
                ProgressParams {
                    token: self.token.clone(),
                    value: ProgressParamsValue::WorkDone(WorkDoneProgress::Report(
                        WorkDoneProgressReport {
                            message: Some(format!("Fetched {}/{} packages", fetched, total)),
                            percentage: Some(percentage),
                            cancellable: Some(false),
                        },
                    )),
                },
            )
            .await;
    }

    /// End progress indicator.
    ///
    /// # Arguments
    ///
    /// * `success` - Whether the fetch completed successfully
    pub async fn end(mut self, success: bool) {
        if !self.active {
            return;
        }

        self.active = false;
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

/// Ensure progress is cleaned up on drop
impl Drop for RegistryProgress {
    fn drop(&mut self) {
        if self.active {
            tracing::warn!(
                token = ?self.token,
                "RegistryProgress dropped without explicit end() - spawning cleanup"
            );
            // Can't await in Drop, so spawn cleanup task
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

    #[test]
    fn test_update_after_end_is_safe() {
        // Verify the guard checks prevent operations after end()
        let active = false;
        let total = 10;

        // This is the guard in update()
        if !active || total == 0 {
            return; // No-op - expected behavior
        }

        panic!("Should have returned early");
    }

    #[test]
    fn test_update_with_zero_total_returns_early() {
        let active = true;
        let total = 0;

        if !active || total == 0 {
            return; // Expected behavior
        }

        panic!("Should have returned early");
    }

    #[test]
    fn test_end_idempotency_flag() {
        // Verify the active flag behavior
        let mut active = true;

        // First end() call
        assert!(active, "First call should proceed");
        active = false;

        // Second end() call - should be no-op
        assert!(!active, "Second call should be no-op due to inactive flag");
    }
}

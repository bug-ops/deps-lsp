//! Refetch of Swift documents after a Keychain credential resolves late (#1771).
//!
//! A registry fetch that waits on a macOS Keychain access prompt can hit its own timeout before
//! the user answers. The credential store then announces the late `Found` on the handle's
//! `resolved` channel, and the listener here reparses every open Swift document with a full
//! refetch, so the fetch that timed out is retried with the credential in hand. The store
//! announces only after a caller gave up and only on the first `Found` per server, and a reparse
//! reuses its memo, so this cannot loop.

use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{RwLock, broadcast};
use tower_lsp_server::Client;
use tracing::Instrument;

use super::listener_lifecycle::ListenerLifecycle;
use super::reparse::reparse_open_documents;
use super::resolved::RefetchPolicy;
use super::state::{ServerState, spawn_supervised};
use crate::config::{DepsConfig, ReparseScope, SWIFT_KEYCHAIN_CREDENTIALS_ECOSYSTEMS};

/// The `resolved` receiver taken at server construction, before any document can open, so no
/// event is lost between construction and the listener starting.
#[derive(Debug)]
pub(crate) struct KeychainRefreshSubscription(broadcast::Receiver<()>);

impl KeychainRefreshSubscription {
    /// Subscribes to the live Keychain handle's `resolved` channel.
    pub(crate) fn subscribe(state: &ServerState) -> Self {
        Self(state.keychain_credentials.subscribe_resolved())
    }

    /// Spawns the supervised listener.
    pub(crate) fn spawn(
        self,
        state: &Arc<ServerState>,
        client: &Client,
        config: &Arc<RwLock<DepsConfig>>,
    ) -> tokio::task::AbortHandle {
        let (state, client, config) = (Arc::clone(state), client.clone(), Arc::clone(config));
        spawn_supervised(
            run_listener(self.0, move || {
                reparse_open_documents(
                    ReparseScope::Ecosystems(SWIFT_KEYCHAIN_CREDENTIALS_ECOSYSTEMS.to_vec()),
                    RefetchPolicy::AllDependencies,
                    "keychain credential resolved",
                    Arc::clone(&state),
                    client.clone(),
                    Arc::clone(&config),
                )
            })
            .instrument(tracing::Span::current()),
            |e| {
                tracing::error!(
                    "keychain refresh listener panicked ({e}); a late Keychain credential is \
                     picked up only on the next reparse"
                );
            },
        )
    }
}

/// Runs `on_resolved` once per event until the channel closes; a lagged receiver means events
/// were missed, which is the same as one event.
async fn run_listener<F, Fut>(mut resolved: broadcast::Receiver<()>, mut on_resolved: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    while let Ok(()) | Err(RecvError::Lagged(_)) = resolved.recv().await {
        on_resolved().await;
    }
}

/// Lifecycle of the Keychain listener owned by the backend.
pub(crate) type KeychainRefreshLifecycle =
    ListenerLifecycle<KeychainRefreshSubscription, tokio::task::AbortHandle>;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn counter_listener(
        resolved: broadcast::Receiver<()>,
    ) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let task = tokio::spawn(run_listener(resolved, move || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        }));
        (count, task)
    }

    #[tokio::test]
    async fn each_event_reparses_once_and_closing_ends_the_listener() {
        let (sender, receiver) = broadcast::channel(4);
        let (count, task) = counter_listener(receiver);
        sender.send(()).unwrap();
        sender.send(()).unwrap();
        drop(sender);
        task.await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_lagged_receiver_still_reparses() {
        let (sender, receiver) = broadcast::channel(1);
        for _ in 0..3 {
            sender.send(()).unwrap();
        }
        let (count, task) = counter_listener(receiver);
        drop(sender);
        task.await.unwrap();
        assert!(count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn no_event_means_no_reparse() {
        let (sender, receiver) = broadcast::channel::<()>(4);
        let (count, task) = counter_listener(receiver);
        drop(sender);
        task.await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lifecycle_starts_once_and_stop_is_terminal() {
        let state = ServerState::new();
        let mut lifecycle =
            KeychainRefreshLifecycle::Subscribed(KeychainRefreshSubscription::subscribe(&state));
        let starts = Arc::new(AtomicUsize::new(0));
        let spawn = |starts: &Arc<AtomicUsize>| {
            let starts = Arc::clone(starts);
            move |_: KeychainRefreshSubscription| {
                starts.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(std::future::pending::<()>()).abort_handle()
            }
        };
        lifecycle.start(spawn(&starts));
        lifecycle.start(spawn(&starts));
        assert!(matches!(lifecycle, KeychainRefreshLifecycle::Running(_)));
        lifecycle.stop();
        lifecycle.start(spawn(&starts));
        assert!(matches!(lifecycle, KeychainRefreshLifecycle::Stopped));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }
}

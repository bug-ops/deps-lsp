//! Coalesced republish of every open document's diagnostics (#1794, #1799).
//!
//! A `workspace/didChangeConfiguration` that a push-only client cannot be told to pull after
//! needs every loaded document republished under the new config. One long-lived worker waits on
//! [`ServerState::request_republish`]'s `Notify`, whose retained permit means a burst of
//! requests costs at most one extra pass and a request that arrives mid-pass is never lost.
//! A pass that panics is logged and contained, so the next request still finds a live worker.

use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;
use tracing::Instrument;

use super::listener_lifecycle::ListenerLifecycle;
use super::state::{ServerState, spawn_supervised};
use crate::config::{DepsConfig, ReparseScope};
use crate::handlers::diagnostics;

/// Lifecycle of the republish worker owned by the backend; there is nothing to subscribe at
/// construction, because the `Notify` permit is retained from the first request on.
pub(crate) type RepublishLifecycle = ListenerLifecycle<(), tokio::task::AbortHandle>;

/// Spawns the supervised republish worker.
pub(crate) fn spawn(
    state: &Arc<ServerState>,
    client: &Client,
    config: &Arc<RwLock<DepsConfig>>,
) -> tokio::task::AbortHandle {
    let (state, client, config) = (Arc::clone(state), client.clone(), Arc::clone(config));
    spawn_supervised(
        run_worker(Arc::clone(&state), move || {
            let (state, client, config) = (Arc::clone(&state), client.clone(), Arc::clone(&config));
            async move { republish_documents(&state, &client, &config, None).await }
        })
        .instrument(tracing::Span::current()),
        |e| {
            tracing::error!(
                "diagnostics republish worker stopped ({e}); open documents may show stale \
                 diagnostics until their next edit or reopen"
            );
        },
    )
}

/// Runs one `pass` per wake until aborted. Each pass runs in its own task inside a [`JoinSet`],
/// so a panic is contained to that pass and aborting the worker aborts the pass with it.
async fn run_worker<F, Fut>(state: Arc<ServerState>, pass: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut running = JoinSet::new();
    loop {
        state.republish_requested().await;
        running.spawn(pass());
        if let Some(Err(e)) = running.join_next().await
            && e.is_panic()
        {
            tracing::error!(
                "diagnostics republish pass panicked ({e}); open documents may show stale \
                 diagnostics until their next edit or reopen"
            );
        }
    }
}

/// The loaded, not-loading documents a republish should cover, skipping those inside `skip`
/// (documents a reparse is about to republish itself, #1799).
pub(crate) async fn republish_targets(
    state: &ServerState,
    skip: Option<&ReparseScope>,
) -> Vec<Uri> {
    let candidates: Vec<(Uri, deps_core::EcosystemId)> = state
        .documents
        .iter()
        // A loading document's own fetch task publishes when it finishes.
        .filter(|entry| entry.value().loading_state() != deps_core::LoadingState::Loading)
        .map(|entry| (entry.key().clone(), entry.value().ecosystem))
        .collect();
    let skipped = match skip {
        Some(scope) => crate::config::uris_in_scope(scope, candidates.clone()).await,
        None => std::collections::HashSet::new(),
    };
    candidates
        .into_iter()
        .map(|(uri, _)| uri)
        .filter(|uri| !skipped.contains(uri))
        .collect()
}

/// Republishes the documents [`republish_targets`] selects under the live config.
pub(crate) async fn republish_documents(
    state: &Arc<ServerState>,
    client: &Client,
    config: &RwLock<DepsConfig>,
    skip: Option<&ReparseScope>,
) {
    for uri in republish_targets(state, skip).await {
        let dep_count = diagnostics::document_dependency_count(state, &uri);
        diagnostics::publish_document_diagnostics(state, client, &uri, config, dep_count).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::document::DocumentState;
    use deps_core::EcosystemId;

    fn hermetic_state() -> ServerState {
        ServerState::with_private_registries(deps_core::net_policy::AllowlistOutcome::Unset)
    }

    fn doc_uri(path: &str) -> Uri {
        crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(path))
    }

    fn open_doc(state: &ServerState, path: &str, ecosystem: EcosystemId, loading: bool) -> Uri {
        let uri = doc_uri(path);
        let mut doc = DocumentState::new_without_parse_result(ecosystem, String::new());
        if loading {
            doc.set_loading();
        }
        state.update_document(uri.clone(), doc);
        uri
    }

    #[tokio::test]
    async fn targets_skip_loading_documents_and_the_reparse_scope() {
        let state = hermetic_state();
        let cargo = open_doc(&state, "/t/a/Cargo.toml", EcosystemId::Cargo, false);
        let npm = open_doc(&state, "/t/b/package.json", EcosystemId::Npm, false);
        open_doc(&state, "/t/c/Cargo.toml", EcosystemId::Cargo, true);

        let mut all = republish_targets(&state, None).await;
        all.sort_by_key(|uri| uri.to_string());
        assert_eq!(all, vec![cargo, npm.clone()]);

        let reparsed = ReparseScope::Ecosystems(vec![EcosystemId::Cargo]);
        assert_eq!(republish_targets(&state, Some(&reparsed)).await, vec![npm]);

        assert!(
            republish_targets(&state, Some(&ReparseScope::All))
                .await
                .is_empty()
        );
    }

    async fn wait_for(count: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while count.load(Ordering::SeqCst) < expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {expected} passes, saw {}",
                count.load(Ordering::SeqCst)
            )
        });
    }

    #[tokio::test]
    async fn request_before_the_worker_waits_is_not_lost() {
        let state = Arc::new(hermetic_state());
        state.request_republish();
        let passes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&passes);
        let worker = tokio::spawn(run_worker(Arc::clone(&state), move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }));
        wait_for(&passes, 1).await;
        worker.abort();
    }

    #[tokio::test]
    async fn a_burst_of_requests_collapses_into_one_extra_pass() {
        let state = Arc::new(hermetic_state());
        let passes = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (counter, pass_gate) = (Arc::clone(&passes), Arc::clone(&gate));
        let worker = tokio::spawn(run_worker(Arc::clone(&state), move || {
            let (counter, gate) = (Arc::clone(&counter), Arc::clone(&pass_gate));
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                gate.acquire().await.expect("gate open").forget();
            }
        }));
        state.request_republish();
        wait_for(&passes, 1).await;
        for _ in 0..10 {
            state.request_republish();
        }
        gate.add_permits(10);
        wait_for(&passes, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(passes.load(Ordering::SeqCst), 2);
        worker.abort();
    }

    #[tokio::test]
    async fn a_panicking_pass_does_not_stop_the_worker() {
        let state = Arc::new(hermetic_state());
        let passes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&passes);
        let worker = tokio::spawn(run_worker(Arc::clone(&state), move || {
            let counter = Arc::clone(&counter);
            async move {
                let previous_passes = counter.fetch_add(1, Ordering::SeqCst);
                assert_ne!(previous_passes, 0, "first pass fails");
            }
        }));
        state.request_republish();
        wait_for(&passes, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        state.request_republish();
        wait_for(&passes, 2).await;
        assert!(!worker.is_finished());
        worker.abort();
    }
}

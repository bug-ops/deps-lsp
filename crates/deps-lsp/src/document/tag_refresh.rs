//! Cross-document rescans after a tag-index refresh (#1716).
//!
//! A floating tag pin (`@v4`) is rescanned after a registry fetch only for the document whose
//! fetch refreshed the tag index. An ecosystem that exposes
//! [`Ecosystem::tag_index_refreshes`] emits the repository name on every refresh, from any
//! source (lifecycle fetch, completion), and the listener here re-evaluates the OSV scan-plan
//! predicate ([`rescan_osv_if_tag_index_now_warm`]) for every other open document that uses
//! that repository.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use deps_core::{Dependency, Ecosystem, EcosystemId, PackageName, TagIndexRefreshes};
use tokio::sync::{RwLock, broadcast::error::RecvError};
use tokio::task::JoinSet;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;
use tracing::Instrument;

use super::osv_scan::{RescanOutcome, rescan_osv_if_tag_index_now_warm};
use super::state::{ServerState, spawn_supervised};
use crate::config::DepsConfig;
use crate::handlers::diagnostics::{self, DiagnosticsSnapshot};

/// Window over which refresh events are merged into one sweep, so a manifest fetch that
/// refreshes many repositories triggers one pass over the open documents, not one per event.
const COALESCE_WINDOW: Duration = Duration::from_millis(250);

/// Upper bound on documents rescanned at once, so one slow OSV phase A (up to
/// `fetch_timeout_secs`) cannot stall the others.
const RESCAN_CONCURRENCY: usize = 4;

/// Which repositories' tag indexes were refreshed within one coalescing window.
#[derive(Debug, PartialEq, Eq)]
enum RefreshedRepos {
    Only(HashSet<PackageName>),
    /// The receiver lagged and events were dropped: every repository must be assumed refreshed.
    All,
}

impl RefreshedRepos {
    fn add(&mut self, name: PackageName) {
        if let Self::Only(names) = self {
            names.insert(name);
        }
    }

    fn covers(&self, dependencies: &[&dyn Dependency]) -> bool {
        match self {
            Self::Only(names) => dependencies.iter().any(|dep| names.contains(dep.name())),
            Self::All => true,
        }
    }
}

/// URIs of the open documents of `ecosystem` that use a repository in `refreshed`.
fn affected_documents(
    state: &ServerState,
    ecosystem: EcosystemId,
    refreshed: &RefreshedRepos,
) -> Vec<Uri> {
    state
        .documents
        .iter()
        .filter(|entry| {
            let doc = entry.value();
            doc.ecosystem == ecosystem
                && doc
                    .parse_result()
                    .is_some_and(|parsed| refreshed.covers(&parsed.dependencies()))
        })
        .map(|entry| entry.key().clone())
        .collect()
}

/// Runs `rescan` over every affected document with bounded concurrency, returning how many
/// reported [`RescanOutcome::Rescanned`].
///
/// Skipped entirely while the OSV latest-check is disabled or the server is offline, the same
/// gate [`rescan_osv_if_tag_index_now_warm`] applies per document, checked live so a setting
/// change is honored.
async fn sweep<F, Fut>(
    state: &ServerState,
    ecosystem: EcosystemId,
    refreshed: &RefreshedRepos,
    rescan: F,
) -> usize
where
    F: Fn(Uri) -> Fut,
    Fut: Future<Output = RescanOutcome> + Send + 'static,
{
    if !state.is_osv_latest_check_enabled() {
        return 0;
    }
    let uris = affected_documents(state, ecosystem, refreshed);
    if uris.is_empty() {
        return 0;
    }
    tracing::debug!(
        documents = uris.len(),
        ?ecosystem,
        "tag index refreshed, re-evaluating open documents"
    );
    // Each rescan runs in its own task so a panic in one document cannot kill the listener;
    // dropping the set (listener abort on shutdown) aborts the in-flight rescans.
    let mut in_flight = JoinSet::new();
    let mut pending = uris.into_iter();
    let mut rescanned = 0;
    loop {
        while in_flight.len() < RESCAN_CONCURRENCY
            && let Some(uri) = pending.next()
        {
            in_flight.spawn(rescan(uri));
        }
        match in_flight.join_next().await {
            None => return rescanned,
            Some(Ok(RescanOutcome::Rescanned)) => rescanned += 1,
            Some(Ok(RescanOutcome::Unchanged)) => {}
            Some(Err(e)) if e.is_panic() => {
                tracing::error!(
                    "tag-refresh rescan panicked ({e}); that document is rescanned on its own \
                     next fetch"
                );
            }
            Some(Err(_cancelled)) => {}
        }
    }
}

/// Drains `refreshes`, coalescing events over [`COALESCE_WINDOW`], and calls `rescan` for the
/// affected documents of each batch. Returns when the channel closes.
///
/// A document whose own fetch is in flight (including the one whose fetch caused the event)
/// may be scanned twice, and the older scan's commit can land last. That is accepted: the
/// document's own post-fetch rescan runs after its fetch and self-heals it, and the OSV query
/// cache absorbs the duplicate traffic.
async fn drain_refreshes<F, Fut>(
    state: &ServerState,
    ecosystem: EcosystemId,
    mut refreshes: TagIndexRefreshes,
    rescan: F,
) where
    F: Fn(Uri) -> Fut + Send + Sync,
    Fut: Future<Output = RescanOutcome> + Send + 'static,
{
    loop {
        let mut pending = match refreshes.recv().await {
            Ok(name) => RefreshedRepos::Only(HashSet::from([name])),
            Err(RecvError::Lagged(_)) => RefreshedRepos::All,
            Err(RecvError::Closed) => return,
        };
        let deadline = tokio::time::Instant::now() + COALESCE_WINDOW;
        let mut closed = false;
        loop {
            match tokio::time::timeout_at(deadline, refreshes.recv()).await {
                Err(_elapsed) => break,
                Ok(Ok(name)) => pending.add(name),
                Ok(Err(RecvError::Lagged(_))) => pending = RefreshedRepos::All,
                Ok(Err(RecvError::Closed)) => {
                    closed = true;
                    break;
                }
            }
        }
        sweep(state, ecosystem, &pending, &rescan).await;
        if closed {
            return;
        }
    }
}

/// Listener for one ecosystem: rescans affected documents and republishes their diagnostics
/// (the rescan itself already requests inlay hint and code lens refreshes).
async fn run_listener(
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    ecosystem: Arc<dyn Ecosystem>,
    refreshes: TagIndexRefreshes,
) {
    drain_refreshes(&state, ecosystem.ecosystem_id(), refreshes, |uri| {
        let state = Arc::clone(&state);
        let client = client.clone();
        let config = Arc::clone(&config);
        let ecosystem = Arc::clone(&ecosystem);
        async move {
            let snapshot = DiagnosticsSnapshot::from_config(&*config.read().await);
            let outcome = rescan_osv_if_tag_index_now_warm(
                &uri,
                &state,
                &client,
                &ecosystem,
                snapshot.fetch_timeout_secs,
            )
            .await;
            if outcome == RescanOutcome::Rescanned {
                let dep_count = diagnostics::document_dependency_count(&state, &uri);
                diagnostics::publish_document_diagnostics(
                    &state, &client, &uri, &snapshot, dep_count,
                )
                .await;
            }
            outcome
        }
    })
    .await;
}

/// Tag-refresh receivers taken at server construction, before any document can open, so no
/// first-populate event is lost between construction and the listener starting.
pub(crate) struct TagRefreshSubscriptions(Vec<(Arc<dyn Ecosystem>, TagIndexRefreshes)>);

impl std::fmt::Debug for TagRefreshSubscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(ecosystem, _)| ecosystem.ecosystem_id()))
            .finish()
    }
}

impl TagRefreshSubscriptions {
    /// Subscribes to every registered ecosystem that emits tag-index refreshes.
    pub(crate) fn subscribe(state: &ServerState) -> Self {
        Self(
            state
                .ecosystem_registry
                .ecosystem_ids()
                .into_iter()
                .filter_map(|id| state.ecosystem_registry.get(id))
                .filter_map(|ecosystem| {
                    let refreshes = ecosystem.tag_index_refreshes()?;
                    Some((ecosystem, refreshes))
                })
                .collect(),
        )
    }

    /// Spawns one supervised listener per subscription.
    pub(crate) fn spawn(
        self,
        state: &Arc<ServerState>,
        client: &Client,
        config: &Arc<RwLock<DepsConfig>>,
    ) -> TagRefreshTasks {
        tracing::debug!(listeners = self.0.len(), "starting tag-refresh listeners");
        TagRefreshTasks(
            self.0
                .into_iter()
                .map(|(ecosystem, refreshes)| {
                    spawn_supervised(
                        run_listener(
                            Arc::clone(state),
                            client.clone(),
                            Arc::clone(config),
                            ecosystem,
                            refreshes,
                        )
                        .instrument(tracing::Span::current()),
                        |e| {
                            tracing::error!(
                                "tag-refresh listener panicked ({e}); documents sharing a \
                                 refreshed tag index are rescanned only on their own next fetch"
                            );
                        },
                    )
                })
                .collect(),
        )
    }
}

/// Handles of the running listeners, aborted on server shutdown.
#[derive(Debug)]
pub(crate) struct TagRefreshTasks(Vec<tokio::task::AbortHandle>);

impl TagRefreshTasks {
    pub(crate) fn abort(self) {
        for handle in self.0 {
            handle.abort();
        }
    }
}

/// Lifecycle of the tag-refresh listeners owned by the backend.
#[derive(Debug)]
pub(crate) enum TagRefreshLifecycle {
    Subscribed(TagRefreshSubscriptions),
    Running(TagRefreshTasks),
    Stopped,
}

impl TagRefreshLifecycle {
    /// Spawns the listeners from `Subscribed`; in any other state this is a no-op, so a
    /// repeated start neither orphans running listeners nor starts a second set.
    pub(crate) fn start(&mut self, spawn: impl FnOnce(TagRefreshSubscriptions) -> TagRefreshTasks) {
        match std::mem::replace(self, Self::Stopped) {
            Self::Subscribed(subscriptions) => *self = Self::Running(spawn(subscriptions)),
            other => *self = other,
        }
    }

    /// Aborts running listeners and moves to `Stopped`, which no later `start` can leave.
    pub(crate) fn stop(&mut self) {
        if let Self::Running(tasks) = std::mem::replace(self, Self::Stopped) {
            tasks.abort();
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn running_task() -> (tokio::task::JoinHandle<()>, TagRefreshTasks) {
        let handle = tokio::spawn(std::future::pending());
        let tasks = TagRefreshTasks(vec![handle.abort_handle()]);
        (handle, tasks)
    }

    fn subscribed() -> TagRefreshLifecycle {
        TagRefreshLifecycle::Subscribed(TagRefreshSubscriptions(Vec::new()))
    }

    #[tokio::test]
    async fn repeated_start_neither_orphans_nor_duplicates_listeners() {
        let mut lifecycle = subscribed();
        let (handle, tasks) = running_task();
        let starts = AtomicUsize::new(0);

        lifecycle.start(|_| {
            starts.fetch_add(1, Ordering::SeqCst);
            tasks
        });
        lifecycle.start(|_| {
            starts.fetch_add(1, Ordering::SeqCst);
            TagRefreshTasks(Vec::new())
        });

        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(matches!(lifecycle, TagRefreshLifecycle::Running(_)));
        assert!(!handle.is_finished());
        lifecycle.stop();
        assert!(handle.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn stop_aborts_running_listeners() {
        let mut lifecycle = subscribed();
        let (handle, tasks) = running_task();
        lifecycle.start(|_| tasks);

        lifecycle.stop();

        assert!(matches!(lifecycle, TagRefreshLifecycle::Stopped));
        assert!(handle.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn start_after_stop_stays_stopped() {
        let mut lifecycle = subscribed();
        lifecycle.stop();
        lifecycle.start(|_| unreachable!("a stopped lifecycle must not restart"));
        assert!(matches!(lifecycle, TagRefreshLifecycle::Stopped));
    }
}

#[cfg(test)]
#[cfg(feature = "github-actions")]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::document::DocumentState;

    async fn open_document(state: &ServerState, path: &str, content: &str) -> Uri {
        let url = deps_core::test_util::test_uri(path);
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem =
            deps_github_actions::GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
        state.update_document(
            uri.clone(),
            DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content.to_string(),
                parse_result,
            ),
        );
        uri
    }

    fn workflow(repo: &str) -> String {
        format!("steps:\n  - uses: {repo}@v4\n")
    }

    /// Counts the uris handed to the rescan closure.
    fn counting_rescan(
        seen: &Arc<std::sync::Mutex<Vec<Uri>>>,
        outcome: RescanOutcome,
    ) -> impl Fn(Uri) -> std::future::Ready<RescanOutcome> {
        let seen = Arc::clone(seen);
        move |uri| {
            seen.lock().unwrap().push(uri);
            std::future::ready(outcome)
        }
    }

    #[tokio::test]
    async fn sweep_rescans_only_documents_using_a_refreshed_repo() {
        let state = ServerState::new();
        let peer = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        open_document(
            &state,
            "/b/.github/workflows/b.yml",
            &workflow("o/unrelated"),
        )
        .await;
        let seen = Arc::default();

        let rescanned = sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::Only(HashSet::from([PackageName::new("o/shared")])),
            counting_rescan(&seen, RescanOutcome::Rescanned),
        )
        .await;

        assert_eq!(rescanned, 1);
        assert_eq!(*seen.lock().unwrap(), vec![peer]);
    }

    #[tokio::test]
    async fn sweep_all_covers_every_open_document_of_the_ecosystem() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        open_document(&state, "/b/.github/workflows/b.yml", &workflow("o/two")).await;
        let seen = Arc::default();

        sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn sweep_ignores_documents_of_other_ecosystems() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        let seen = Arc::default();

        sweep(
            &state,
            EcosystemId::Cargo,
            &RefreshedRepos::All,
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sweep_respects_the_osv_latest_check_gate() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        state.set_osv_latest_check_enabled(false);
        let seen = Arc::default();

        sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            counting_rescan(&seen, RescanOutcome::Rescanned),
        )
        .await;

        assert!(seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sweep_runs_rescans_concurrently_up_to_the_bound() {
        let state = ServerState::new();
        for i in 0..8 {
            open_document(
                &state,
                &format!("/d{i}/.github/workflows/w.yml"),
                &workflow("o/shared"),
            )
            .await;
        }
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            |_uri| {
                let in_flight = Arc::clone(&in_flight);
                let peak = Arc::clone(&peak);
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    RescanOutcome::Unchanged
                }
            },
        )
        .await;

        assert_eq!(peak.load(Ordering::SeqCst), RESCAN_CONCURRENCY);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_coalesces_events_and_rescans_the_peer_once() {
        let state = ServerState::new();
        let peer = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        open_document(
            &state,
            "/b/.github/workflows/b.yml",
            &workflow("o/unrelated"),
        )
        .await;
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let seen = Arc::default();

        tx.send(PackageName::new("o/shared")).unwrap();
        tx.send(PackageName::new("o/shared")).unwrap();
        drop(tx);
        drain_refreshes(
            &state,
            EcosystemId::GithubActions,
            rx,
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert_eq!(*seen.lock().unwrap(), vec![peer]);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_treats_lag_as_a_full_sweep() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        open_document(&state, "/b/.github/workflows/b.yml", &workflow("o/two")).await;
        let (tx, rx) = tokio::sync::broadcast::channel(2);
        let seen = Arc::default();

        for i in 0..5 {
            tx.send(PackageName::new(format!("o/other{i}"))).unwrap();
        }
        drop(tx);
        drain_refreshes(
            &state,
            EcosystemId::GithubActions,
            rx,
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_sweeps_a_late_event_after_the_first_window() {
        let state = Arc::new(ServerState::new());
        let peer = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let seen = Arc::default();
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            let seen = Arc::clone(&seen);
            async move {
                drain_refreshes(
                    &state,
                    EcosystemId::GithubActions,
                    rx,
                    counting_rescan(&seen, RescanOutcome::Unchanged),
                )
                .await;
            }
        });

        tokio::time::sleep(Duration::from_secs(10)).await;
        tx.send(PackageName::new("o/shared")).unwrap();
        tokio::time::sleep(COALESCE_WINDOW * 2).await;
        assert_eq!(*seen.lock().unwrap(), vec![peer]);

        drop(tx);
        task.await.unwrap();
    }

    /// End to end: an event for a repository whose index warmed through some other document
    /// makes the listener rescan this cold peer, replacing its stale skip with a real result.
    #[tokio::test]
    async fn listener_rescans_cold_peer_after_refresh_event() {
        use deps_core::lsp_helpers::{CommitSha, ResolvedPin, TagIndex};
        use deps_core::osv::{OsvClient, ScanOutcome, SkipReason};

        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let mut server = mockito::Server::new_async().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        let mut state = ServerState::new();
        state.osv = Arc::new(OsvClient::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
        ));
        let state = Arc::new(state);
        let (client, config) = crate::test_utils::test_helpers::create_test_client_and_config();
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(
            deps_github_actions::GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new())),
        );

        let sha = "f".repeat(40);
        let uri = open_document(
            &state,
            "/repo/.github/workflows/ci.yml",
            &format!("steps:\n  - uses: actions/checkout@{sha} # v1\n"),
        )
        .await;
        let cold = run_osv_scan_phase_a_for_test(&state, &uri, &ecosystem).await;
        assert!(matches!(
            cold,
            Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
        ));

        let mut index = TagIndex::default();
        index.insert_sha_pin(
            CommitSha::parse(&sha).unwrap(),
            ResolvedPin::most_specific(deps_core::ConcreteVersion::new("v1.3.0")),
        );
        let index =
            index.with_canonical_repo_name(deps_core::github::CanonicalRepoName::from_commit_url(
                "https://api.github.com/repos/actions/checkout/commits/abc",
            ));
        let registry = ecosystem.registry();
        registry
            .as_any()
            .downcast_ref::<deps_github_actions::GithubActionsRegistry>()
            .unwrap()
            .tag_index()
            .insert(PackageName::new("actions/checkout"), Arc::new(index));

        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let listener = tokio::spawn(run_listener(
            Arc::clone(&state),
            client,
            config,
            Arc::clone(&ecosystem),
            rx,
        ));
        tx.send(PackageName::new("actions/checkout")).unwrap();
        drop(tx);
        tokio::time::timeout(Duration::from_secs(10), listener)
            .await
            .expect("listener must finish once the channel closes")
            .unwrap();

        batch.assert_async().await;
        let key = deps_core::test_util::vuln_key("actions/checkout");
        let doc = state.get_document(&uri).unwrap();
        assert!(matches!(
            doc.signals.vulnerabilities.get(&key),
            Some(ScanOutcome::Clean)
        ));
    }

    /// Runs the cold OSV pipeline for `uri` and returns its `actions/checkout` outcome.
    async fn run_osv_scan_phase_a_for_test(
        state: &Arc<ServerState>,
        uri: &Uri,
        ecosystem: &Arc<dyn Ecosystem>,
    ) -> Option<deps_core::osv::ScanOutcome> {
        let phase_a = crate::document::osv_scan::run_osv_scan_phase_a(
            uri.clone(),
            Arc::clone(state),
            Arc::clone(ecosystem),
            5,
        )
        .await?;
        crate::document::osv_scan::run_osv_phase_b_and_commit(
            uri,
            state,
            ecosystem.ecosystem_id(),
            ecosystem.formatter(),
            5,
            phase_a,
        )
        .await;
        let key = deps_core::test_util::vuln_key("actions/checkout");
        state
            .get_document(uri)?
            .signals
            .vulnerabilities
            .get(&key)
            .cloned()
    }

    #[tokio::test]
    async fn sweep_survives_a_panicking_rescan() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        open_document(&state, "/b/.github/workflows/b.yml", &workflow("o/two")).await;
        let calls = Arc::new(AtomicUsize::new(0));

        let rescanned = sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            |_uri| {
                let calls = Arc::clone(&calls);
                async move {
                    assert!(
                        calls.fetch_add(1, Ordering::SeqCst) != 0,
                        "injected rescan panic"
                    );
                    RescanOutcome::Rescanned
                }
            },
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(rescanned, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_keeps_serving_events_after_a_panicking_rescan() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let calls = Arc::new(AtomicUsize::new(0));

        let calls_in_rescan = Arc::clone(&calls);
        let drain = drain_refreshes(&state, EcosystemId::GithubActions, rx, move |_uri| {
            let calls = Arc::clone(&calls_in_rescan);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                panic!("injected rescan panic");
            }
        });
        let producer = async {
            tx.send(PackageName::new("o/shared")).unwrap();
            tokio::time::sleep(COALESCE_WINDOW * 4).await;
            tx.send(PackageName::new("o/shared")).unwrap();
            drop(tx);
        };
        tokio::join!(drain, producer);

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

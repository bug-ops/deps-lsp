//! Cross-document rescans after a tag-index refresh (#1716).
//!
//! A floating tag pin (`@v4`) is rescanned after a registry fetch only for the document whose
//! fetch refreshed the tag index. An ecosystem that exposes
//! [`Ecosystem::tag_index_refreshes`] emits the repository name on every refresh, from any
//! source (lifecycle fetch, completion), and the listener here, for every other open document
//! that uses that repository, re-evaluates the OSV scan-plan predicate
//! ([`rescan_osv_if_tag_index_now_warm`], which applies the vulnerability/offline gate itself)
//! and then republishes the document's diagnostics whatever the rescan did, since a refreshed
//! tag index changes diagnostics that never depended on OSV (a SHA pin's comment check, a tag
//! pin's status). A sweep that leaves a republished document without a refresh requests one
//! inlay hint and code lens refresh.

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

/// Runs `rescan` over every affected document with bounded concurrency, returning whether any
/// republished document (not panicked, not mid-load or closed) still needs a hint and code
/// lens refresh, i.e. reported [`RescanOutcome::Unchanged`]: a [`RescanOutcome::Rescanned`]
/// document already requested its own.
///
/// Not gated on the OSV latest-check: the per-document job decides what the gate skips, so
/// diagnostics are republished even with vulnerabilities disabled or while offline.
async fn sweep<F, Fut>(
    state: &ServerState,
    ecosystem: EcosystemId,
    refreshed: &RefreshedRepos,
    rescan: F,
) -> bool
where
    F: Fn(Uri) -> Fut,
    Fut: Future<Output = RescanOutcome> + Send + 'static,
{
    let uris = affected_documents(state, ecosystem, refreshed);
    if uris.is_empty() {
        return false;
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
    let mut needs_refresh = false;
    loop {
        while in_flight.len() < RESCAN_CONCURRENCY
            && let Some(uri) = pending.next()
        {
            let job = rescan(uri.clone());
            in_flight.spawn(async move { (uri, job.await) });
        }
        match in_flight.join_next().await {
            None => return needs_refresh,
            Some(Ok((uri, RescanOutcome::Unchanged))) if is_publishable(state, &uri) => {
                needs_refresh = true;
            }
            Some(Ok(_)) => {}
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
/// affected documents of each batch, then `after_sweep` once when the batch left at least one
/// republished document without a hint and code lens refresh. Returns when the channel closes.
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
    after_sweep: impl Fn(),
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
        if sweep(state, ecosystem, &pending, &rescan).await {
            after_sweep();
        }
        if closed {
            return;
        }
    }
}

/// Whether `uri` is open and not mid-load.
///
/// A document still loading yields no diagnostics, so publishing for it would wipe the ones
/// already shown; it publishes after its own load completes.
fn is_publishable(state: &ServerState, uri: &Uri) -> bool {
    state
        .with_document(uri, |doc| {
            doc.loading_state() != crate::document::LoadingState::Loading
        })
        .unwrap_or(false)
}

/// Awaits `rescan`, then `publish` unless the document is mid-load, whatever the rescan did.
async fn rescan_then_republish(
    state: &ServerState,
    uri: &Uri,
    rescan: impl Future<Output = RescanOutcome>,
    publish: impl Future<Output = ()>,
) -> RescanOutcome {
    let outcome = rescan.await;
    if is_publishable(state, uri) {
        publish.await;
    }
    outcome
}

/// Listener for one ecosystem: rescans affected documents, republishes their diagnostics and,
/// once per sweep, requests inlay hint and code lens refreshes.
async fn run_listener(
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    ecosystem: Arc<dyn Ecosystem>,
    refreshes: TagIndexRefreshes,
) {
    drain_refreshes(
        &state,
        ecosystem.ecosystem_id(),
        refreshes,
        |uri| {
            let state = Arc::clone(&state);
            let client = client.clone();
            let config = Arc::clone(&config);
            let ecosystem = Arc::clone(&ecosystem);
            async move {
                let snapshot = DiagnosticsSnapshot::from_config(&*config.read().await);
                rescan_then_republish(
                    &state,
                    &uri,
                    rescan_osv_if_tag_index_now_warm(
                        &uri,
                        &state,
                        &client,
                        &ecosystem,
                        snapshot.fetch_timeout_secs,
                    ),
                    async {
                        let dep_count = diagnostics::document_dependency_count(&state, &uri);
                        diagnostics::publish_document_diagnostics(
                            &state, &client, &uri, &snapshot, dep_count,
                        )
                        .await;
                    },
                )
                .await
            }
        },
        || state.spawn_refresh_requests(&client),
    )
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

        let needs_refresh = sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::Only(HashSet::from([PackageName::new("o/shared")])),
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert!(needs_refresh);
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

    /// #1765: the sweep is ecosystem-generic, so a GitLab peer document that uses a refreshed
    /// project is rescanned too.
    #[tokio::test]
    async fn sweep_rescans_a_gitlab_peer_document_using_a_refreshed_project() {
        let state = ServerState::new();
        let url = deps_core::test_util::test_uri("/a/.gitlab-ci.yml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem =
            deps_gitlab_ci::GitlabCiEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n    file: a.yml\n";
        let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
        let project = parse_result.dependencies()[0].name().clone();
        state.update_document(
            uri.clone(),
            DocumentState::new_from_parse_result(
                EcosystemId::GitlabCi,
                content.to_string(),
                parse_result,
            ),
        );
        let seen = Arc::default();

        sweep(
            &state,
            EcosystemId::GitlabCi,
            &RefreshedRepos::Only(HashSet::from([project])),
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert_eq!(*seen.lock().unwrap(), vec![uri]);
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

    /// #1761: the OSV gate lives inside the per-document rescan, so a sweep still visits every
    /// affected document with vulnerabilities disabled.
    #[tokio::test]
    async fn sweep_visits_documents_while_the_osv_latest_check_is_disabled() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        state.set_osv_latest_check_enabled(false);
        let seen = Arc::default();

        let visited = sweep(
            &state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            counting_rescan(&seen, RescanOutcome::Unchanged),
        )
        .await;

        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(visited);
    }

    async fn run(state: &ServerState, outcome: RescanOutcome) -> bool {
        sweep(
            state,
            EcosystemId::GithubActions,
            &RefreshedRepos::All,
            counting_rescan(&Arc::default(), outcome),
        )
        .await
    }

    #[tokio::test]
    async fn sweep_counts_neither_rescanned_nor_loading_documents_as_needing_a_refresh() {
        let state = ServerState::new();
        let a = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        let b = open_document(&state, "/b/.github/workflows/b.yml", &workflow("o/two")).await;

        assert!(!run(&state, RescanOutcome::Rescanned).await);
        assert!(run(&state, RescanOutcome::Unchanged).await);
        state.documents.get_mut(&a).unwrap().set_loading();
        assert!(run(&state, RescanOutcome::Unchanged).await);
        state.documents.get_mut(&b).unwrap().set_loading();
        assert!(!run(&state, RescanOutcome::Unchanged).await);
    }

    async fn republish_count(state: &ServerState, uri: &Uri, outcome: RescanOutcome) -> usize {
        let published = AtomicUsize::new(0);
        let returned = rescan_then_republish(state, uri, std::future::ready(outcome), async {
            published.fetch_add(1, Ordering::SeqCst);
        })
        .await;
        assert_eq!(returned, outcome);
        published.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn republish_happens_for_unchanged_and_rescanned_outcomes() {
        let state = ServerState::new();
        let uri = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        for outcome in [RescanOutcome::Unchanged, RescanOutcome::Rescanned] {
            assert_eq!(republish_count(&state, &uri, outcome).await, 1);
        }
    }

    #[tokio::test]
    async fn republish_happens_while_offline_or_vulnerabilities_are_disabled() {
        let state = ServerState::new();
        let uri = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        state.set_osv_latest_check_enabled(false);
        assert_eq!(
            republish_count(&state, &uri, RescanOutcome::Unchanged).await,
            1
        );
    }

    /// M1: publishing for a loading document would wipe its diagnostics.
    #[tokio::test]
    async fn republish_skips_a_loading_or_closed_document() {
        let state = ServerState::new();
        let uri = open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/one")).await;
        state.documents.get_mut(&uri).unwrap().set_loading();
        assert_eq!(
            republish_count(&state, &uri, RescanOutcome::Unchanged).await,
            0
        );

        let closed = deps_core::test_util::test_uri("/never/.github/workflows/x.yml");
        let closed = crate::lsp_types_interop::to_lsp_uri(&closed);
        assert_eq!(
            republish_count(&state, &closed, RescanOutcome::Rescanned).await,
            0
        );
    }

    /// Drains one batch of refresh events for `repos`, returning how many `after_sweep` calls it made.
    async fn drain_refresh_calls(state: &ServerState, repos: &[&str]) -> usize {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let refreshes = AtomicUsize::new(0);
        for repo in repos {
            tx.send(PackageName::new(*repo)).unwrap();
        }
        drop(tx);
        drain_refreshes(
            state,
            EcosystemId::GithubActions,
            rx,
            counting_rescan(&Arc::default(), RescanOutcome::Unchanged),
            || {
                refreshes.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        refreshes.load(Ordering::SeqCst)
    }

    #[tokio::test(start_paused = true)]
    async fn drain_requests_one_refresh_per_sweep_that_touched_a_document() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        open_document(&state, "/b/.github/workflows/b.yml", &workflow("o/shared")).await;

        assert_eq!(
            drain_refresh_calls(&state, &["o/shared", "o/unrelated"]).await,
            1
        );
        assert_eq!(
            drain_refresh_calls(&state, &["o/unrelated"]).await,
            0,
            "no document, no refresh"
        );
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
            || {},
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
            || {},
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
                    || {},
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

        let needs_refresh = sweep(
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
                    RescanOutcome::Unchanged
                }
            },
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(needs_refresh);
    }

    #[tokio::test(start_paused = true)]
    async fn drain_keeps_serving_events_after_a_panicking_rescan() {
        let state = ServerState::new();
        open_document(&state, "/a/.github/workflows/a.yml", &workflow("o/shared")).await;
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let calls = Arc::new(AtomicUsize::new(0));

        let calls_in_rescan = Arc::clone(&calls);
        let drain = drain_refreshes(
            &state,
            EcosystemId::GithubActions,
            rx,
            move |_uri| {
                let calls = Arc::clone(&calls_in_rescan);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    panic!("injected rescan panic");
                }
            },
            || {},
        );
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

//! Background probes of open documents (specs 086, 087): what triggers them, how overlapping
//! triggers coalesce, and how their evidence reaches the client.
//!
//! A probe asks the forge something synchronous diagnostics must not (see
//! [`Ecosystem::background_probes`]). It runs in a spawned task, never in a handler, after a
//! document's registry fetch has populated the tag index it needs. The ecosystem stores only
//! authoritative answers and announces a [`RefreshEvent::ProbeEvidence`] per changed
//! repository; the listener here answers that event by republishing diagnostics, and nothing
//! else, so a probe's own event can never trigger another probe or an OSV rescan.

use std::future::Future;
use std::sync::Arc;

use dashmap::DashMap;
use deps_core::lsp_helpers::ProbePhase;
use deps_core::{Ecosystem, EcosystemId, RefreshEvent, RefreshEvents};
use tokio::sync::{RwLock, broadcast::error::RecvError};
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

use super::state::ServerState;
use super::tag_refresh::{COALESCE_WINDOW, RefreshedRepos, affected_documents};
use crate::config::DepsConfig;
use crate::handlers::diagnostics;

/// Where a document's probe task is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeSlot {
    /// A task is running and no further trigger arrived.
    Running,
    /// A task is running and a trigger arrived meanwhile: it runs once more when it finishes.
    RerunRequested,
}

/// What [`ProbeSlots::claim`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    /// The caller owns the document's probe task and must run it.
    Started,
    /// A task is already running; it was asked to run once more.
    Coalesced,
}

/// What [`ProbeSlots::finish`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Finish {
    /// A trigger arrived while the pass ran: run another pass.
    RunAgain,
    /// Nothing is pending; the slot is released.
    Done,
}

/// Single-flight state of the probe tasks, one slot per open document.
///
/// Overlapping triggers coalesce to one re-run instead of aborting the running pass, so permits
/// already drawn and quota already spent are never wasted.
#[derive(Debug, Default)]
pub(crate) struct ProbeSlots(DashMap<Uri, ProbeSlot>);

impl ProbeSlots {
    fn claim(&self, uri: &Uri) -> Claim {
        match self.0.entry(uri.clone()) {
            dashmap::Entry::Vacant(slot) => {
                slot.insert(ProbeSlot::Running);
                Claim::Started
            }
            dashmap::Entry::Occupied(mut slot) => {
                slot.insert(ProbeSlot::RerunRequested);
                Claim::Coalesced
            }
        }
    }

    fn finish(&self, uri: &Uri) -> Finish {
        match self.0.entry(uri.clone()) {
            dashmap::Entry::Occupied(mut slot) if *slot.get() == ProbeSlot::RerunRequested => {
                slot.insert(ProbeSlot::Running);
                Finish::RunAgain
            }
            dashmap::Entry::Occupied(slot) => {
                slot.remove();
                Finish::Done
            }
            dashmap::Entry::Vacant(_) => Finish::Done,
        }
    }
}

/// Releases a document's slot if its task unwinds, so one panic cannot leave later triggers
/// coalescing into a task that no longer exists.
struct SlotGuard {
    state: Arc<ServerState>,
    uri: Uri,
    finished: bool,
}

impl SlotGuard {
    const fn disarm(&mut self) {
        self.finished = true;
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.state.probe_slots.0.remove(&self.uri);
        }
    }
}

/// Starts, or coalesces into, the background probe task of `uri`.
///
/// Called after a document's open or change fetch merged, and for every open document that
/// references a repository whose tag index just refreshed. Returns immediately; offline,
/// nothing is spawned.
pub(crate) fn spawn_background_probes(
    state: &Arc<ServerState>,
    uri: &Uri,
    ecosystem: &Arc<dyn Ecosystem>,
) {
    if state.cache.is_offline() || state.probe_slots.claim(uri) == Claim::Coalesced {
        return;
    }
    let mut guard = SlotGuard {
        state: Arc::clone(state),
        uri: uri.clone(),
        finished: false,
    };
    let ecosystem = Arc::clone(ecosystem);
    tokio::spawn(async move {
        loop {
            run_pass(&guard.state, &guard.uri, ecosystem.as_ref()).await;
            if guard.state.probe_slots.finish(&guard.uri) == Finish::Done {
                guard.disarm();
                break;
            }
        }
    });
}

/// One probe pass over the document's current parse result, if it is still open.
async fn run_pass(state: &ServerState, uri: &Uri, ecosystem: &dyn Ecosystem) {
    let Some(parse_result) = state
        .with_document(uri, super::state::DocumentState::parse_result_arc)
        .flatten()
    else {
        return;
    };
    let report = ecosystem
        .background_probes(parse_result.as_ref(), ProbePhase::PostFetch)
        .await;
    tracing::debug!(
        issued = report.issued,
        skipped_over_budget = report.skipped_over_budget,
        inconclusive = report.inconclusive,
        effect = ?report.effect,
        "background probes finished"
    );
}

/// Drains `events`, coalescing over [`COALESCE_WINDOW`]:
///
/// - [`RefreshEvent::TagIndex`] runs `probe` for every open document using the repository
///   (a probe gate needs a `Complete` index that may only warm later);
/// - [`RefreshEvent::ProbeEvidence`] runs `republish` for those documents and calls `after`
///   once per batch that republished any, and nothing else;
/// - [`RefreshEvent::ReparseOpenDocuments`] belongs to the Swift re-parse listener and is
///   ignored here.
///
/// A lagged receiver treats every repository as affected. Returns when the channel closes.
async fn drain_probe_events<Fut>(
    state: &ServerState,
    ecosystem: EcosystemId,
    mut events: RefreshEvents,
    probe: impl Fn(&Uri),
    republish: impl Fn(Uri) -> Fut,
    after: impl Fn(),
) where
    Fut: Future<Output = ()>,
{
    loop {
        let mut batch = ProbeBatch::default();
        match events.recv().await {
            Ok(event) => batch.add(event),
            Err(RecvError::Lagged(_)) => batch.lagged(),
            Err(RecvError::Closed) => return,
        }
        let deadline = tokio::time::Instant::now() + COALESCE_WINDOW;
        let mut closed = false;
        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Err(_elapsed) => break,
                Ok(Ok(event)) => batch.add(event),
                Ok(Err(RecvError::Lagged(_))) => batch.lagged(),
                Ok(Err(RecvError::Closed)) => {
                    closed = true;
                    break;
                }
            }
        }
        for uri in affected_documents(state, ecosystem, &batch.tag_index) {
            probe(&uri);
        }
        let evidence = affected_documents(state, ecosystem, &batch.evidence);
        let republished = !evidence.is_empty();
        for uri in evidence {
            republish(uri).await;
        }
        if republished {
            after();
        }
        if closed {
            return;
        }
    }
}

/// The repositories touched by the events of one coalescing window.
struct ProbeBatch {
    tag_index: RefreshedRepos,
    evidence: RefreshedRepos,
}

impl Default for ProbeBatch {
    fn default() -> Self {
        Self {
            tag_index: RefreshedRepos::none(),
            evidence: RefreshedRepos::none(),
        }
    }
}

impl ProbeBatch {
    fn add(&mut self, event: RefreshEvent) {
        match event {
            RefreshEvent::TagIndex(repository) => self.tag_index.add(repository),
            RefreshEvent::ProbeEvidence(repository) => self.evidence.add(repository),
            RefreshEvent::ReparseOpenDocuments { .. } => {}
        }
    }

    fn lagged(&mut self) {
        self.tag_index = RefreshedRepos::All;
        self.evidence = RefreshedRepos::All;
    }
}

/// Listener for one ecosystem: probes on tag-index refreshes, republishes on probe evidence.
pub(crate) async fn run_probe_listener(
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    ecosystem: Arc<dyn Ecosystem>,
    events: RefreshEvents,
) {
    drain_probe_events(
        &state,
        ecosystem.ecosystem_id(),
        events,
        |uri| spawn_background_probes(&state, uri, &ecosystem),
        |uri| {
            let state = Arc::clone(&state);
            let client = client.clone();
            let config = Arc::clone(&config);
            async move {
                let dep_count = diagnostics::document_dependency_count(&state, &uri);
                diagnostics::publish_document_diagnostics(
                    &state, &client, &uri, &config, dep_count,
                )
                .await;
            }
        },
        || state.spawn_refresh_requests(&client),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use deps_engine::test_util::TestTier3Ecosystem;

    use super::*;

    fn uri(name: &str) -> Uri {
        crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(name))
    }

    #[test]
    fn overlapping_triggers_coalesce_to_one_rerun() {
        let slots = ProbeSlots::default();
        let a = uri("/a.yml");

        assert_eq!(slots.claim(&a), Claim::Started);
        assert_eq!(slots.claim(&a), Claim::Coalesced);
        assert_eq!(slots.claim(&a), Claim::Coalesced);

        assert_eq!(
            slots.finish(&a),
            Finish::RunAgain,
            "one re-run for any number of triggers"
        );
        assert_eq!(slots.finish(&a), Finish::Done);
        assert_eq!(
            slots.claim(&a),
            Claim::Started,
            "released after the last pass"
        );
    }

    #[test]
    fn slots_are_per_document() {
        let slots = ProbeSlots::default();
        assert_eq!(slots.claim(&uri("/a.yml")), Claim::Started);
        assert_eq!(slots.claim(&uri("/b.yml")), Claim::Started);
    }

    #[test]
    fn finishing_an_unclaimed_slot_is_done() {
        assert_eq!(ProbeSlots::default().finish(&uri("/a.yml")), Finish::Done);
    }

    #[tokio::test]
    async fn a_panicking_task_releases_its_slot() {
        let state = Arc::new(ServerState::new());
        let a = uri("/a.yml");
        assert_eq!(state.probe_slots.claim(&a), Claim::Started);
        let guard = SlotGuard {
            state: Arc::clone(&state),
            uri: a.clone(),
            finished: false,
        };
        let joined = tokio::spawn(async move {
            let _guard = guard;
            panic!("probe task failed");
        })
        .await;
        assert!(joined.is_err());
        assert_eq!(state.probe_slots.claim(&a), Claim::Started);
    }

    async fn open_stub_document(state: &ServerState, path: &str) -> (Uri, Arc<TestTier3Ecosystem>) {
        let url = deps_core::test_util::test_uri(path);
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem = Arc::new(TestTier3Ecosystem::returning(vec![]));
        let as_dyn: Arc<dyn Ecosystem> = ecosystem.clone();
        let parse_result = deps_core::parse_manifest_blocking(&as_dyn, "", &url)
            .await
            .unwrap();
        state.update_document(
            uri.clone(),
            super::super::DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                String::new(),
                parse_result,
            ),
        );
        (uri, ecosystem)
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// FR-006: overlapping triggers never abort the running pass; they ask for one more.
    #[tokio::test]
    async fn overlapping_triggers_run_one_pass_and_one_rerun() {
        let state = Arc::new(ServerState::new());
        let (uri, ecosystem) = open_stub_document(&state, "/a/pubspec.yaml").await;
        let dynamic: Arc<dyn Ecosystem> = ecosystem.clone();

        for _ in 0..5 {
            spawn_background_probes(&state, &uri, &dynamic);
        }
        settle().await;

        assert_eq!(
            ecosystem.probe_calls(),
            [ProbePhase::PostFetch, ProbePhase::PostFetch]
        );
        spawn_background_probes(&state, &uri, &dynamic);
        settle().await;
        assert_eq!(ecosystem.probe_calls().len(), 3, "the slot was released");
    }

    #[tokio::test]
    async fn a_closed_document_is_not_probed() {
        let state = Arc::new(ServerState::new());
        let (uri, ecosystem) = open_stub_document(&state, "/a/pubspec.yaml").await;
        let dynamic: Arc<dyn Ecosystem> = ecosystem.clone();
        state.documents.remove(&uri);

        spawn_background_probes(&state, &uri, &dynamic);
        settle().await;

        assert!(ecosystem.probe_calls().is_empty());
    }

    #[tokio::test]
    async fn offline_spawns_nothing() {
        let state = Arc::new(ServerState::new());
        state.cache.set_offline(deps_core::NetworkMode::Offline);
        let a = uri("/a.yml");
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(TestTier3Ecosystem::returning(vec![]));

        spawn_background_probes(&state, &a, &ecosystem);

        assert_eq!(
            state.probe_slots.claim(&a),
            Claim::Started,
            "slot was never taken"
        );
    }

    #[cfg(feature = "github-actions")]
    mod listener {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use super::*;
        use crate::document::DocumentState;
        use deps_core::NormalizedName;

        async fn open(state: &ServerState, path: &str, repo: &str) -> Uri {
            let url = deps_core::test_util::test_uri(path);
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = deps_github_actions::GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            ));
            let content = format!("steps:\n  - uses: {repo}@v4\n");
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            state.update_document(
                uri.clone(),
                DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content,
                    parse_result,
                ),
            );
            uri
        }

        async fn drain(
            state: &ServerState,
            events: &[RefreshEvent],
        ) -> (Vec<Uri>, Vec<Uri>, usize) {
            let (tx, rx) = tokio::sync::broadcast::channel(16);
            for event in events {
                tx.send(event.clone()).unwrap();
            }
            drop(tx);
            let probed = std::sync::Mutex::new(Vec::new());
            let republished = std::sync::Mutex::new(Vec::new());
            let afters = AtomicUsize::new(0);
            drain_probe_events(
                state,
                EcosystemId::GithubActions,
                rx,
                |uri| probed.lock().unwrap().push(uri.clone()),
                |uri| {
                    republished.lock().unwrap().push(uri);
                    std::future::ready(())
                },
                || {
                    afters.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
            (
                probed.into_inner().unwrap(),
                republished.into_inner().unwrap(),
                afters.load(Ordering::SeqCst),
            )
        }

        fn tag_index(repo: &str) -> RefreshEvent {
            RefreshEvent::TagIndex(NormalizedName::for_test(repo))
        }

        fn evidence(repo: &str) -> RefreshEvent {
            RefreshEvent::ProbeEvidence(NormalizedName::for_test(repo))
        }

        #[tokio::test(start_paused = true)]
        async fn tag_index_event_probes_documents_of_that_repository_only() {
            let state = ServerState::new();
            let shared = open(&state, "/a/.github/workflows/a.yml", "o/shared").await;
            open(&state, "/b/.github/workflows/b.yml", "o/other").await;

            let (probed, republished, afters) = drain(&state, &[tag_index("o/shared")]).await;

            assert_eq!(probed, vec![shared]);
            assert!(republished.is_empty());
            assert_eq!(afters, 0);
        }

        /// FR-007: a probe's own evidence only republishes; it never starts another probe.
        #[tokio::test(start_paused = true)]
        async fn probe_evidence_republishes_without_probing_again() {
            let state = ServerState::new();
            let shared = open(&state, "/a/.github/workflows/a.yml", "o/shared").await;
            open(&state, "/b/.github/workflows/b.yml", "o/other").await;

            let (probed, republished, afters) = drain(&state, &[evidence("o/shared")]).await;

            assert!(probed.is_empty());
            assert_eq!(republished, vec![shared]);
            assert_eq!(afters, 1);
        }

        #[tokio::test(start_paused = true)]
        async fn events_of_one_window_are_coalesced_and_reparse_is_ignored() {
            let state = ServerState::new();
            open(&state, "/a/.github/workflows/a.yml", "o/shared").await;

            let (probed, republished, afters) = drain(
                &state,
                &[
                    tag_index("o/shared"),
                    tag_index("o/shared"),
                    evidence("o/shared"),
                    evidence("o/shared"),
                    RefreshEvent::ReparseOpenDocuments { generation: 1 },
                ],
            )
            .await;

            assert_eq!((probed.len(), republished.len(), afters), (1, 1, 1));
        }

        #[tokio::test(start_paused = true)]
        async fn lag_is_a_full_sweep_for_both_kinds() {
            let state = ServerState::new();
            open(&state, "/a/.github/workflows/a.yml", "o/one").await;
            open(&state, "/b/.github/workflows/b.yml", "o/two").await;
            let (tx, rx) = tokio::sync::broadcast::channel(2);
            for n in 0..5 {
                tx.send(tag_index(&format!("o/other{n}"))).unwrap();
            }
            drop(tx);
            let probed = AtomicUsize::new(0);
            let republished = AtomicUsize::new(0);

            drain_probe_events(
                &state,
                EcosystemId::GithubActions,
                rx,
                |_| {
                    probed.fetch_add(1, Ordering::SeqCst);
                },
                |_| {
                    republished.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(())
                },
                || {},
            )
            .await;

            assert_eq!(probed.load(Ordering::SeqCst), 2);
            assert_eq!(republished.load(Ordering::SeqCst), 2);
        }
    }
}

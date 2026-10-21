//! Re-parses open documents when an ecosystem announces that a parse input changed
//! ([`RefreshEvent::ReparseOpenDocuments`]; Swift's SCM-to-registry identity memo, spec 088).
//!
//! The announcement carries a generation. Events are coalesced over [`REPARSE_COALESCE_WINDOW`]
//! per ecosystem, and a document applies a given generation at most once per content version,
//! so neither a burst of answers nor a document that re-announces itself can cause a loop. The
//! re-parse runs no probe: it only re-reads the inputs the announcement is about.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use deps_core::{EcosystemId, RefreshEvent, RefreshEvents};
use tokio::sync::{RwLock, broadcast::error::RecvError};
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

use super::lifecycle::{CommitGuard, ParseTrigger, handle_document_change_guarded};
use super::resolved::RefetchPolicy;
use super::state::ServerState;
use crate::config::DepsConfig;

/// How long events are gathered before the open documents are re-parsed.
pub(crate) const REPARSE_COALESCE_WINDOW: Duration = Duration::from_secs(1);

/// What the events of one coalescing window announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Announced {
    /// Nothing yet.
    Nothing,
    /// The newest generation announced.
    Generation(u64),
    /// Events were dropped, so the generation is unknown and every document re-parses.
    Lagged,
}

impl Announced {
    fn add(self, event: &RefreshEvent) -> Self {
        match (self, event) {
            (Self::Lagged, _) => Self::Lagged,
            (
                Self::Nothing | Self::Generation(_),
                RefreshEvent::ReparseOpenDocuments { generation },
            ) => Self::Generation(match self {
                Self::Generation(seen) => seen.max(*generation),
                Self::Nothing | Self::Lagged => *generation,
            }),
            (current, RefreshEvent::TagIndex(_) | RefreshEvent::ProbeEvidence(_)) => current,
        }
    }
}

/// The generation each document last applied, per content version.
#[derive(Debug, Default)]
struct ReparseLedger(HashMap<Uri, (Option<i32>, u64)>);

impl ReparseLedger {
    /// Whether `uri` at `version` must re-parse for `announced`, recording it when it must.
    fn take(&mut self, uri: &Uri, version: Option<i32>, announced: Announced) -> bool {
        match announced {
            Announced::Nothing => false,
            Announced::Lagged => {
                self.0.remove(uri);
                true
            }
            Announced::Generation(generation) => {
                let applied = self.0.get(uri).is_some_and(|&(seen_version, seen)| {
                    seen_version == version && seen >= generation
                });
                if !applied {
                    self.0.insert(uri.clone(), (version, generation));
                }
                !applied
            }
        }
    }

    /// Forgets documents that are no longer open.
    fn retain_open(&mut self, state: &ServerState) {
        self.0.retain(|uri, _| state.documents.contains_key(uri));
    }
}

/// Open documents of `ecosystem` with the content and version a re-parse needs.
fn open_documents(state: &ServerState, ecosystem: EcosystemId) -> Vec<(Uri, String, Option<i32>)> {
    state
        .documents
        .iter()
        .filter(|entry| entry.value().ecosystem == ecosystem)
        .map(|entry| {
            (
                entry.key().clone(),
                entry.value().content.clone(),
                entry.value().version,
            )
        })
        .collect()
}

/// Re-parses the documents of `ecosystem` that have not yet applied `announced`.
async fn reparse_due(
    state: &Arc<ServerState>,
    client: &Client,
    config: &Arc<RwLock<DepsConfig>>,
    ecosystem: EcosystemId,
    ledger: &mut ReparseLedger,
    announced: Announced,
    last_event: Instant,
) {
    ledger.retain_open(state);
    state
        .pre_fetch_stamps
        .retain(|uri, _| state.documents.contains_key(uri));
    let mut reparsed = false;
    for (uri, content, version) in open_documents(state, ecosystem) {
        if !ledger.take(&uri, version, announced) {
            continue;
        }
        if state
            .pre_fetch_stamps
            .get(&uri)
            .is_some_and(|stamp| *stamp >= last_event)
        {
            tracing::debug!(?uri, "document already parsed with the announced inputs");
            continue;
        }
        match handle_document_change_guarded(
            uri.clone(),
            content,
            version,
            CommitGuard::ExpectVersion(version),
            ParseTrigger::Memo,
            // A swapped dependency has a new name and source, and the re-parse also supersedes
            // a fetch still running for this document, so everything is fetched again.
            RefetchPolicy::AllDependencies,
            Arc::clone(state),
            client.clone(),
            Arc::clone(config),
        )
        .await
        {
            Ok(Some(task)) => {
                reparsed = true;
                state.spawn_background_task(uri, task).await;
            }
            Ok(None) => tracing::debug!(
                "skipped stale reparse for {:?}: superseded by a concurrent edit",
                uri
            ),
            Err(e) => tracing::error!(
                "failed to reparse {:?} after an identity change: {}",
                uri,
                e
            ),
        }
    }
    if reparsed {
        state.spawn_refresh_requests(client);
    }
}

/// Listener for one ecosystem: re-parses its open documents when a parse input changed.
///
/// Returns when the channel closes.
pub(crate) async fn run_reparse_listener(
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    ecosystem: EcosystemId,
    mut events: RefreshEvents,
) {
    let mut ledger = ReparseLedger::default();
    loop {
        let mut announced = Announced::Nothing;
        let mut last_event = Instant::now();
        match events.recv().await {
            Ok(event) => announced = announced.add(&event),
            Err(RecvError::Lagged(_)) => announced = Announced::Lagged,
            Err(RecvError::Closed) => return,
        }
        if announced == Announced::Nothing {
            continue;
        }
        let deadline = tokio::time::Instant::now() + REPARSE_COALESCE_WINDOW;
        let mut closed = false;
        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Err(_elapsed) => break,
                Ok(Ok(event)) => {
                    announced = announced.add(&event);
                    last_event = Instant::now();
                }
                Ok(Err(RecvError::Lagged(_))) => {
                    announced = Announced::Lagged;
                    last_event = Instant::now();
                }
                Ok(Err(RecvError::Closed)) => {
                    closed = true;
                    break;
                }
            }
        }
        reparse_due(
            &state,
            &client,
            &config,
            ecosystem,
            &mut ledger,
            announced,
            last_event,
        )
        .await;
        if closed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(name: &str) -> Uri {
        crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(name))
    }

    fn reparse(generation: u64) -> RefreshEvent {
        RefreshEvent::ReparseOpenDocuments { generation }
    }

    #[test]
    fn announcements_keep_the_newest_generation_and_ignore_other_events() {
        let announced = Announced::Nothing
            .add(&reparse(3))
            .add(&RefreshEvent::TagIndex(
                deps_core::NormalizedName::for_test("o/r"),
            ))
            .add(&reparse(2));
        assert_eq!(announced, Announced::Generation(3));
        assert_eq!(
            Announced::Nothing.add(&RefreshEvent::ProbeEvidence(
                deps_core::NormalizedName::for_test("o/r")
            )),
            Announced::Nothing
        );
    }

    #[test]
    fn lag_dominates_later_announcements() {
        assert_eq!(Announced::Lagged.add(&reparse(9)), Announced::Lagged);
    }

    #[test]
    fn a_generation_applies_once_per_document_and_content_version() {
        let mut ledger = ReparseLedger::default();
        let a = uri("/a/Package.swift");
        let b = uri("/b/Package.swift");

        assert!(ledger.take(&a, Some(1), Announced::Generation(4)));
        assert!(
            !ledger.take(&a, Some(1), Announced::Generation(4)),
            "same generation"
        );
        assert!(
            !ledger.take(&a, Some(1), Announced::Generation(3)),
            "older generation"
        );
        assert!(
            ledger.take(&a, Some(1), Announced::Generation(5)),
            "newer generation"
        );
        assert!(
            ledger.take(&a, Some(2), Announced::Generation(5)),
            "new content version"
        );
        assert!(
            ledger.take(&b, Some(1), Announced::Generation(5)),
            "other document"
        );
    }

    #[test]
    fn a_lagged_window_reparses_every_document_and_forgets_the_ledger_entry() {
        let mut ledger = ReparseLedger::default();
        let a = uri("/a/Package.swift");
        assert!(ledger.take(&a, None, Announced::Generation(1)));
        assert!(ledger.take(&a, None, Announced::Lagged));
        assert!(ledger.take(&a, None, Announced::Generation(1)));
    }

    #[test]
    fn nothing_announced_reparses_nothing() {
        let mut ledger = ReparseLedger::default();
        assert!(!ledger.take(&uri("/a/Package.swift"), None, Announced::Nothing));
    }
}

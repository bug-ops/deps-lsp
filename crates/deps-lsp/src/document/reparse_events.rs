//! Re-parses open documents when an ecosystem announces that a parse input changed
//! ([`RefreshEvent::ReparseOpenDocuments`]; Swift's SCM-to-registry identity memo, spec 088).
//!
//! The announcement carries a generation. Events are coalesced over [`REPARSE_COALESCE_WINDOW`]
//! per ecosystem, and a document applies a given generation at most once per content version,
//! so neither a burst of answers nor a document that re-announces itself can cause a loop. The
//! re-parse runs no probe: it only re-reads the inputs the announcement is about.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use deps_core::{Ecosystem, EcosystemId, ParseInputKey, ParseResult, RefreshEvent, RefreshEvents};
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
#[derive(Debug, Clone, PartialEq, Eq)]
enum Announced {
    /// Nothing yet.
    Nothing,
    /// The newest generation announced and every input whose decision changed.
    Inputs {
        generation: u64,
        inputs: HashSet<ParseInputKey>,
    },
    /// Events were dropped, so the generation and inputs are unknown and every document
    /// re-parses.
    Lagged,
}

impl Announced {
    fn add(self, event: &RefreshEvent) -> Self {
        match (self, event) {
            (Self::Lagged, _) => Self::Lagged,
            (current, RefreshEvent::TagIndex(_) | RefreshEvent::ProbeEvidence(_)) => current,
            (Self::Nothing, RefreshEvent::ReparseOpenDocuments { generation, input }) => {
                Self::Inputs {
                    generation: *generation,
                    inputs: HashSet::from([input.clone()]),
                }
            }
            (
                Self::Inputs {
                    generation: seen,
                    mut inputs,
                },
                RefreshEvent::ReparseOpenDocuments { generation, input },
            ) => {
                inputs.insert(input.clone());
                Self::Inputs {
                    generation: seen.max(*generation),
                    inputs,
                }
            }
        }
    }

    /// Whether a document parsed as `parse_result` must be considered for re-parsing.
    fn concerns(&self, ecosystem: &dyn Ecosystem, parse_result: Option<&dyn ParseResult>) -> bool {
        match self {
            Self::Nothing => false,
            Self::Lagged => true,
            Self::Inputs { inputs, .. } => parse_result.is_some_and(|parsed| {
                inputs
                    .iter()
                    .any(|input| ecosystem.parse_depends_on(parsed, input))
            }),
        }
    }
}

/// The generation each document last applied, per content version.
#[derive(Debug, Default)]
struct ReparseLedger(HashMap<Uri, (Option<i32>, u64)>);

impl ReparseLedger {
    /// Whether `uri` at `version` must re-parse for `announced`, recording it when it must.
    fn take(&mut self, uri: &Uri, version: Option<i32>, announced: &Announced) -> bool {
        match announced {
            Announced::Nothing => false,
            Announced::Lagged => {
                self.0.remove(uri);
                true
            }
            &Announced::Inputs { generation, .. } => {
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

/// An open document with the content, version and parse result a re-parse decision needs.
struct OpenDocument {
    uri: Uri,
    content: String,
    version: Option<i32>,
    parse_result: Option<Arc<dyn ParseResult>>,
}

/// Open documents of `ecosystem`.
fn open_documents(state: &ServerState, ecosystem: EcosystemId) -> Vec<OpenDocument> {
    state
        .documents
        .iter()
        .filter(|entry| entry.value().ecosystem == ecosystem)
        .map(|entry| OpenDocument {
            uri: entry.key().clone(),
            content: entry.value().content.clone(),
            version: entry.value().version,
            parse_result: entry.value().parse_result_arc(),
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
    announced: &Announced,
    last_event: Instant,
) {
    let Some(ecosystem_impl) = state.ecosystem_registry.get(ecosystem) else {
        return;
    };
    ledger.retain_open(state);
    state
        .pre_fetch_stamps
        .retain(|uri, _| state.documents.contains_key(uri));
    let mut reparsed = false;
    for OpenDocument {
        uri,
        content,
        version,
        parse_result,
    } in open_documents(state, ecosystem)
    {
        if !announced.concerns(&*ecosystem_impl, parse_result.as_deref())
            || !ledger.take(&uri, version, announced)
        {
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
            &announced,
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

    fn reparse_input(generation: u64, input: &str) -> RefreshEvent {
        RefreshEvent::ReparseOpenDocuments {
            generation,
            input: ParseInputKey::new(input),
        }
    }

    fn reparse(generation: u64) -> RefreshEvent {
        reparse_input(generation, "input")
    }

    fn inputs(generation: u64, names: &[&str]) -> Announced {
        Announced::Inputs {
            generation,
            inputs: names.iter().map(|name| ParseInputKey::new(*name)).collect(),
        }
    }

    #[test]
    fn announcements_keep_the_newest_generation_and_union_the_inputs() {
        let announced = Announced::Nothing
            .add(&reparse_input(3, "a"))
            .add(&RefreshEvent::TagIndex(
                deps_core::NormalizedName::for_test("o/r"),
            ))
            .add(&reparse_input(2, "b"));
        assert_eq!(announced, inputs(3, &["a", "b"]));
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

        assert!(ledger.take(&a, Some(1), &inputs(4, &["x"])));
        assert!(
            !ledger.take(&a, Some(1), &inputs(4, &["x"])),
            "same generation"
        );
        assert!(
            !ledger.take(&a, Some(1), &inputs(3, &["x"])),
            "older generation"
        );
        assert!(
            ledger.take(&a, Some(1), &inputs(5, &["x"])),
            "newer generation"
        );
        assert!(
            ledger.take(&a, Some(2), &inputs(5, &["x"])),
            "new content version"
        );
        assert!(
            ledger.take(&b, Some(1), &inputs(5, &["x"])),
            "other document"
        );
    }

    #[test]
    fn a_lagged_window_reparses_every_document_and_forgets_the_ledger_entry() {
        let mut ledger = ReparseLedger::default();
        let a = uri("/a/Package.swift");
        assert!(ledger.take(&a, None, &inputs(1, &["x"])));
        assert!(ledger.take(&a, None, &Announced::Lagged));
        assert!(ledger.take(&a, None, &inputs(1, &["x"])));
    }

    #[test]
    fn nothing_announced_reparses_nothing() {
        let mut ledger = ReparseLedger::default();
        assert!(!ledger.take(&uri("/a/Package.swift"), None, &Announced::Nothing));
    }

    #[cfg(feature = "swift")]
    async fn swift_document(ecosystem: &dyn Ecosystem, repository: &str) -> Box<dyn ParseResult> {
        let manifest = format!(r#".package(url: "{repository}", from: "1.0.0")"#);
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        ecosystem.parse_manifest(&manifest, &uri).await.unwrap()
    }

    #[cfg(feature = "swift")]
    fn swift_ecosystem() -> Arc<dyn Ecosystem> {
        ServerState::new()
            .ecosystem_registry
            .get(EcosystemId::Swift)
            .unwrap()
    }

    /// Document A references repository X and B references Y: an announcement for X concerns
    /// only A, one for both concerns both, and a lag or a missing parse result is handled.
    #[cfg(feature = "swift")]
    #[tokio::test]
    async fn an_announcement_concerns_only_documents_referencing_its_inputs() {
        let ecosystem = swift_ecosystem();
        let a = swift_document(&*ecosystem, "https://github.com/apple/swift-nio.git").await;
        let b = swift_document(&*ecosystem, "https://github.com/apple/swift-log").await;
        let nio = "https://github.com/apple/swift-nio";
        let log = "https://github.com/apple/swift-log";

        let for_nio = inputs(1, &[nio]);
        assert!(for_nio.concerns(&*ecosystem, Some(&*a)));
        assert!(!for_nio.concerns(&*ecosystem, Some(&*b)));

        let for_both = inputs(1, &[nio, log]);
        assert!(for_both.concerns(&*ecosystem, Some(&*a)));
        assert!(for_both.concerns(&*ecosystem, Some(&*b)));

        assert!(!for_nio.concerns(&*ecosystem, None), "no parse result");
        assert!(Announced::Lagged.concerns(&*ecosystem, Some(&*b)));
        assert!(Announced::Lagged.concerns(&*ecosystem, None));
        assert!(!Announced::Nothing.concerns(&*ecosystem, Some(&*a)));
    }

    /// An ecosystem without a `parse_depends_on` override re-parses every document.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn an_ecosystem_without_an_override_concerns_every_document() {
        let ecosystem = ServerState::new()
            .ecosystem_registry
            .get(EcosystemId::Cargo)
            .unwrap();
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let parsed = ecosystem
            .parse_manifest("[dependencies]\nserde = \"1\"\n", &uri)
            .await
            .unwrap();
        assert!(inputs(1, &["unrelated"]).concerns(&*ecosystem, Some(&*parsed)));
    }
}

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

use deps_core::{EcosystemId, ParseInputKey, ParsedManifest, RefreshEvent, RefreshEvents};
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
    /// Folds `event` into the window of the listener of `listener`; a key minted by another
    /// ecosystem is not this listener's concern.
    fn add(self, event: &RefreshEvent, listener: EcosystemId) -> Self {
        match (self, event) {
            (Self::Lagged, _) => Self::Lagged,
            (current, RefreshEvent::TagIndex(_) | RefreshEvent::ProbeEvidence(_)) => current,
            (current, RefreshEvent::ReparseOpenDocuments { input, .. })
                if input.owner() != listener =>
            {
                current
            }
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

    /// Whether a document parsed as `manifest` must be considered for re-parsing.
    fn concerns(&self, manifest: Option<&dyn ParsedManifest>) -> bool {
        match self {
            Self::Nothing => false,
            Self::Lagged => true,
            Self::Inputs { inputs, .. } => manifest
                .is_some_and(|parsed| inputs.iter().any(|input| parsed.parse_depends_on(input))),
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
    manifest: Option<Arc<dyn ParsedManifest>>,
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
            manifest: entry.value().manifest_arc(),
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
    ledger.retain_open(state);
    state
        .pre_fetch_stamps
        .retain(|uri, _| state.documents.contains_key(uri));
    let mut reparsed = false;
    for OpenDocument {
        uri,
        content,
        version,
        manifest,
    } in open_documents(state, ecosystem)
    {
        if !announced.concerns(manifest.as_deref()) || !ledger.take(&uri, version, announced) {
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
            Ok(event) => announced = announced.add(&event, ecosystem),
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
                    announced = announced.add(&event, ecosystem);
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

    const SWIFT: EcosystemId = EcosystemId::Swift;

    fn uri(name: &str) -> Uri {
        crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(name))
    }

    fn reparse_input(generation: u64, input: &str) -> RefreshEvent {
        RefreshEvent::ReparseOpenDocuments {
            generation,
            input: ParseInputKey::minted_by(SWIFT, input),
        }
    }

    fn reparse(generation: u64) -> RefreshEvent {
        reparse_input(generation, "input")
    }

    fn inputs(generation: u64, names: &[&str]) -> Announced {
        Announced::Inputs {
            generation,
            inputs: names
                .iter()
                .map(|name| ParseInputKey::minted_by(SWIFT, *name))
                .collect(),
        }
    }

    #[test]
    fn announcements_keep_the_newest_generation_and_union_the_inputs() {
        let announced = Announced::Nothing
            .add(&reparse_input(3, "a"), SWIFT)
            .add(
                &RefreshEvent::TagIndex(deps_core::NormalizedName::for_test("o/r")),
                SWIFT,
            )
            .add(&reparse_input(2, "b"), SWIFT);
        assert_eq!(announced, inputs(3, &["a", "b"]));
        assert_eq!(
            Announced::Nothing.add(
                &RefreshEvent::ProbeEvidence(deps_core::NormalizedName::for_test("o/r")),
                SWIFT
            ),
            Announced::Nothing
        );
    }

    #[test]
    fn keys_minted_by_another_ecosystem_are_not_announced() {
        let foreign = RefreshEvent::ReparseOpenDocuments {
            generation: 1,
            input: ParseInputKey::minted_by(EcosystemId::Cargo, "a"),
        };
        assert_eq!(Announced::Nothing.add(&foreign, SWIFT), Announced::Nothing);
        assert_eq!(
            Announced::Nothing
                .add(&reparse_input(2, "a"), SWIFT)
                .add(&foreign, SWIFT),
            inputs(2, &["a"])
        );
    }

    #[test]
    fn lag_dominates_later_announcements() {
        assert_eq!(Announced::Lagged.add(&reparse(9), SWIFT), Announced::Lagged);
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
    async fn swift_document(
        ecosystem: &Arc<dyn deps_core::Ecosystem>,
        repository: &str,
    ) -> Box<dyn ParsedManifest> {
        let manifest = format!(r#".package(url: "{repository}", from: "1.0.0")"#);
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        Arc::clone(ecosystem)
            .parse_manifest(&manifest, &uri)
            .await
            .unwrap()
    }

    #[cfg(feature = "swift")]
    fn swift_ecosystem() -> Arc<dyn deps_core::Ecosystem> {
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
        let a = swift_document(&ecosystem, "https://github.com/apple/swift-nio.git").await;
        let b = swift_document(&ecosystem, "https://github.com/apple/swift-log").await;
        let nio = "https://github.com/apple/swift-nio";
        let log = "https://github.com/apple/swift-log";

        let for_nio = inputs(1, &[nio]);
        assert!(for_nio.concerns(Some(&*a)));
        assert!(!for_nio.concerns(Some(&*b)));

        let for_both = inputs(1, &[nio, log]);
        assert!(for_both.concerns(Some(&*a)));
        assert!(for_both.concerns(Some(&*b)));

        assert!(!for_nio.concerns(None), "no parse result");
        assert!(Announced::Lagged.concerns(Some(&*b)));
        assert!(Announced::Lagged.concerns(None));
        assert!(!Announced::Nothing.concerns(Some(&*a)));
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
        let parsed = Arc::clone(&ecosystem)
            .parse_manifest("[dependencies]\nserde = \"1\"\n", &uri)
            .await
            .unwrap();
        assert!(inputs(1, &["unrelated"]).concerns(Some(&*parsed)));
    }
}

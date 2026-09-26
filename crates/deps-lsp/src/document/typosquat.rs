//! Typosquat pre-fetch orchestration (issue #1468 item 2): the background pre-fetch of a
//! typosquat-suspect signal per direct dependency, the source-eligibility classification
//! it keys on, and the declared-name staleness gate that decides when a re-check is due.
//! None of this is OSV-related — it lived in `osv_scan.rs` only for historical reasons and
//! is split out here as a pure move (no behavior change).

use super::state::{DocumentState, ServerState};
use deps_core::Ecosystem;
use deps_core::PackageName;
use std::collections::HashSet;
use std::sync::Arc;
use tower_lsp_server::ls_types::Uri;

/// Ceiling on the typosquat pre-fetch's overall timeout, independent of the configured
/// `fetch_timeout_secs` (issue #1437 impl-critic S4/perf NFR-002) — mirrors
/// `deps_core::osv`-scan-style timeout ceilings' exact rationale, bounding one document's whole
/// pre-fetch fan-out (not any single deps.dev call, which has its own, separate
/// `deps_core::deps_dev`-internal timeout) so a pathological manifest can't leave this
/// background task running indefinitely.
const TYPOSQUAT_PREFETCH_TIMEOUT_CEILING_SECS: u64 = 30;

/// Whether a declared dependency's currently-resolved [`deps_core::parser::DependencySource`]
/// is one [`deps_core::lsp_helpers::EcosystemFormatter::source_is_public_registry_content`]
/// classifies as eligible for the deps.dev typosquat check (issue #1462) — folded into
/// [`declared_names`]'s comparison key alongside the package name itself. Only an
/// [`Eligible`](Self::Eligible) dependency is ever actually sent to deps.dev
/// (`deps_core::lsp_helpers::fetch_typosquat_signals` applies the same filter), so a name-only
/// key cannot distinguish "already checked, still ineligible" from "same name, newly eligible,
/// never checked" — the gap this issue closes: a dependency whose source flips (e.g. git ->
/// registry) while its name stays the same must be treated as a gate-relevant change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TyposquatSourceEligibility {
    /// A public-registry source `fetch_typosquat_signals` will actually query deps.dev for.
    Eligible,
    /// Any other source (git, path, url, workspace, SDK, unresolved custom registry, ...).
    Ineligible,
}

impl TyposquatSourceEligibility {
    fn of(is_public_registry: bool) -> Self {
        if is_public_registry {
            Self::Eligible
        } else {
            Self::Ineligible
        }
    }
}

/// The declared dependency name set of `parse_result`, paired with each dependency's
/// [`TyposquatSourceEligibility`] — [`run_typosquat_prefetch`]'s staleness unit (issue #1455
/// critic S1, source-eligibility dimension added by issue #1462). Its result depends only on
/// declared package *names* among *eligible* dependencies (`SimilarityMemoKey`/
/// `PopularityMemoKey` are package-level, with no version dimension at all — plan.md §3), so
/// this is what "has the document moved on" must mean for it, not full manifest text — and a
/// source-type change is exactly as significant as a name change, since it can move a
/// dependency across the eligibility filter `fetch_typosquat_signals` applies.
pub(crate) fn declared_names(
    parse_result: &dyn deps_core::ParseResult,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> HashSet<(PackageName, TyposquatSourceEligibility)> {
    parse_result
        .dependencies()
        .into_iter()
        .map(|dep| {
            let eligibility = TyposquatSourceEligibility::of(
                formatter.source_is_public_registry_content(&dep.source()),
            );
            (dep.name().clone(), eligibility)
        })
        .collect()
}

/// Recomputes `doc`'s current declared (name, eligibility) set, or an empty set if `doc` has
/// no parse result yet (issue #1468 item 1) — the one `doc.parse_result().map_or_else(...)`
/// expression [`TyposquatGate::refresh_from`]'s three `document::lifecycle` call sites and
/// [`run_typosquat_prefetch`]'s own staleness check all previously duplicated inline.
pub(crate) fn current_declared_names(
    doc: &DocumentState,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> HashSet<(PackageName, TyposquatSourceEligibility)> {
    doc.parse_result()
        .map_or_else(HashSet::new, |pr| declared_names(pr, formatter))
}

/// Gate tracking the declared (name, source-eligibility) set as of the last typosquat
/// pre-fetch a document actually spawned (issue #1468 item 1). Replaces a raw
/// `HashSet<(PackageName, TyposquatSourceEligibility)>` field whose empty value doubled as
/// both "never checked" and "checked, found an empty declared set" — two different states
/// collapsed into one representation. `None` here means "never checked"; every comparison
/// below (including this type's own [`PartialEq`] impl) treats it as equivalent to an empty
/// set, exactly reproducing the previous representation's observable behavior (a document
/// with no declared dependencies still never reports its checked set as "changed"). `PartialEq`
/// is hand-written, not derived, specifically so `None == Some(<empty set>)` holds here too —
/// a derived impl would make `==` disagree with [`Self::matches`], a latent trap for any
/// future caller that compares two gates directly instead of going through this type's own
/// methods.
#[derive(Debug, Clone, Default, Eq)]
pub(crate) struct TyposquatGate(Option<HashSet<(PackageName, TyposquatSourceEligibility)>>);

impl PartialEq for TyposquatGate {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (None, Some(set)) | (Some(set), None) => set.is_empty(),
            (Some(a), Some(b)) => a == b,
        }
    }
}

impl TyposquatGate {
    /// Updates the gate to `current`, returning whether it actually differs from what was
    /// previously stored — callers spawn a pre-fetch only when this returns `true`. See
    /// `super::state::PackageSignals::typosquat_checked_names`'s doc for the full staleness
    /// rationale this preserves unchanged.
    pub(crate) fn refresh_from(
        &mut self,
        current: HashSet<(PackageName, TyposquatSourceEligibility)>,
    ) -> bool {
        if self.matches(&current) {
            false
        } else {
            self.0 = Some(current);
            true
        }
    }

    /// Reverts the gate to "never checked" if it still holds exactly `stale_snapshot` — a
    /// no-op if a newer check has since advanced past it (issue #1463). See
    /// [`run_typosquat_prefetch`]'s timeout/degraded-result paths for why a belated cleanup
    /// must not clobber a newer, still-valid state.
    pub(crate) fn clear_if_stale(
        &mut self,
        stale_snapshot: &HashSet<(PackageName, TyposquatSourceEligibility)>,
    ) {
        if self.matches(stale_snapshot) {
            self.0 = None;
        }
    }

    fn matches(&self, other: &HashSet<(PackageName, TyposquatSourceEligibility)>) -> bool {
        self.0
            .as_ref()
            .map_or_else(|| other.is_empty(), |set| set == other)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(HashSet::is_empty)
    }

    /// Number of tracked (name, eligibility) pairs, `0` when never checked — used only for
    /// the summary count in `PackageSignals`' hand-written `Debug` impl.
    pub(crate) fn len(&self) -> usize {
        self.0.as_ref().map_or(0, HashSet::len)
    }
}

impl FromIterator<(PackageName, TyposquatSourceEligibility)> for TyposquatGate {
    fn from_iter<I: IntoIterator<Item = (PackageName, TyposquatSourceEligibility)>>(
        iter: I,
    ) -> Self {
        Self(Some(iter.into_iter().collect()))
    }
}

/// Background pre-fetch of a typosquat-suspect signal per direct dependency (issue #1437,
/// spec 071), gated on [`ServerState::is_typosquat_enabled`] and `network.offline` — both
/// checked here, before the document guard is even taken, so a disabled/offline server does
/// zero work per document lifecycle event. Mirrors `document::osv_scan::run_license_prefetch`'s
/// shape closely: target collection happens while holding the document guard (dropped before
/// the network dispatch, which goes through `deps_core::lsp_helpers::fetch_typosquat_signals` —
/// ecosystem-coverage and public-registry-source gating live there, not here, the same
/// division of responsibility `run_license_prefetch` has with `deps_engine::classify::license`),
/// and the eventual commit is guarded against a stale write by re-checking the declared
/// dependency [`declared_names`] against the snapshot taken before the fetch started (issue
/// #1455 critic S1 — previously this compared full `doc.content`, which discarded an
/// already-correct, already-computed result for a version-only or whitespace-only edit that
/// changed nothing this signal actually depends on).
///
/// Deliberately checks the declared name set only, **not** `resolved_versions_generation` too
/// (issue #1437 code-review Important finding, correcting this function's original design,
/// which copied `run_license_prefetch`'s two-part guard verbatim): a typosquat signal
/// depends only on declared package *names* — `SimilarityMemoKey`/`PopularityMemoKey` are
/// package-level, with no version dimension (plan.md §3) — so a lock-file-only change (which
/// bumps `resolved_versions_generation` without touching declared names, e.g. a concurrent
/// `cargo build`/`npm install` racing this fetch) has nothing to do with this signal's own
/// invariants; checking it too would discard an already-correct, already-computed result for
/// an unrelated reason. `run_license_prefetch`'s own generation check remains correct for
/// *its* signal, which genuinely does depend on the resolved version.
///
/// **Not** called inline from diagnostics generation (NFR-002: a cold-cache
/// `textDocument/diagnostic` request must never block on a per-manifest deps.dev fan-out) —
/// `deps_core::lsp_helpers::VersionData::typosquat_prefetch` only ever reads whatever this
/// background task has already committed to [`super::state::PackageSignals::typosquats`],
/// synchronously, with no `.await` on that read path.
///
/// **Not** joined before the main diagnostics publish either (issue #1437 impl-critic N2,
/// correcting this function's own original design, which mirrored `run_license_prefetch`'s
/// join-before-first-publish shape): `run_license_prefetch`'s join is a deliberate tradeoff
/// justified by its four small tier-3 ecosystems and license violations needing to appear
/// immediately, but typosquat's fan-out covers all seven major deps.dev ecosystems and can be
/// far larger, with each dependency costing up to `2 + 2N` sequential-per-candidate deps.dev
/// round trips — joining that before OSV/outdated diagnostics (real, non-`Hint`-severity
/// content) would let a best-effort signal violate NFR-001's "never becomes a reliability
/// liability". Callers (`document::lifecycle::spawn_typosquat_prefetch_and_republish`) instead
/// let the main publish proceed on its existing schedule and issue a second, later publish
/// once this returns `true`.
///
/// Returns whether a non-empty result was actually merged — `false` covers every early-out
/// (disabled, offline, no document, no parse result, timeout, stale-names drop) *and* the
/// case where the fetch genuinely found nothing, so a caller can skip a pointless republish
/// whose diagnostic set would be identical to the one already published. A degraded
/// ([`deps_core::FetchCompleteness::Incomplete`]) result may still return `true` if some
/// *other* dependency in the same fan-out did resolve a signal — completeness and "was
/// anything merged" are independent (issue #1463): the gate clear this function performs on
/// an incomplete result is unconditional, but the merge/republish decision below it is not.
pub(crate) async fn run_typosquat_prefetch(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> bool {
    if !state.is_typosquat_enabled() || state.cache.is_offline() {
        return false;
    }

    // Issue #1455 critic S1: snapshots the declared *name set*, not full `content` — a
    // version-only or whitespace-only edit racing this pre-fetch must not discard an
    // already-correct, already-computed typosquat result, since the result cannot possibly
    // differ for it (see `declared_names`' doc). The previous `content`-based guard treated
    // any edit as invalidating, which combined with `document::lifecycle`'s per-edit
    // `typosquat_names_changed` gate to leave a document with no typosquat diagnostic at all
    // until some *later*, unrelated name-changing edit happened to re-trigger a check. Also
    // checking `resolved_versions_generation` (which bumps on a lock-file-only change, e.g. a
    // concurrent `cargo build`/`npm install`, without touching declared names) would discard
    // an already-correct, already-computed typosquat result for a reason that has nothing to
    // do with this signal's own invariants.
    let Some((names_snapshot, parse_result)) =
        super::prefetch_support::document_prefetch_snapshot(&state, &uri, |_, parse_result| {
            declared_names(parse_result.as_ref(), ecosystem.formatter())
        })
    else {
        return false;
    };

    let Some(outcome) = super::prefetch_support::bounded_prefetch_fetch(
        fetch_timeout_secs,
        TYPOSQUAT_PREFETCH_TIMEOUT_CEILING_SECS,
        "typosquat",
        deps_core::lsp_helpers::fetch_typosquat_signals(
            ecosystem.ecosystem_id(),
            parse_result.as_ref(),
            ecosystem.formatter(),
            false, // already checked `state.cache.is_offline()` above.
            Some(&state.deps_dev),
        ),
    )
    .await
    else {
        // Issue #1463: a timed-out attempt must not leave the debounced-edit gate
        // believing `names_snapshot` was actually checked, or a later edit that
        // doesn't change names/eligibility again would never re-trigger a retry.
        // Only clears if nothing has since advanced past this snapshot (see the
        // method's own doc for why that guard matters).
        if let Some(mut doc) = state.documents.get_mut(&uri) {
            doc.signals
                .typosquat_checked_names
                .clear_if_stale(&names_snapshot);
        }
        return false;
    };

    // Issue #1463 (impl-critic S1): the outer timeout above only catches the
    // whole-document fan-out running out of its shared deadline — it never fires for a
    // single dependency's deps.dev call failing/timing out/being unreachable, which
    // `fetch_typosquat_signals` degrades internally to a `None`/empty result indistinguishable
    // from a genuine "nothing found" *unless* its `completeness` is read. An `Incomplete`
    // result must be treated the same as the outer-timeout case: clear the gate so the next
    // debounced edit retries even without a name/eligibility change, regardless of whether
    // some other dependency in the same fan-out did resolve a usable signal (merged below
    // either way — a partial result is still worth keeping).
    if outcome.completeness == deps_core::FetchCompleteness::Incomplete {
        tracing::debug!(
            "typosquat pre-fetch degraded: at least one dependency's deps.dev call did not \
             complete"
        );
        if let Some(mut doc) = state.documents.get_mut(&uri) {
            doc.signals
                .typosquat_checked_names
                .clear_if_stale(&names_snapshot);
        }
    }

    if outcome.signals.is_empty() {
        return false;
    }

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        let current_names = current_declared_names(&doc, ecosystem.formatter());
        if current_names != names_snapshot {
            tracing::debug!(
                "dropping stale typosquat pre-fetch result: declared dependency names changed \
                 mid-fetch"
            );
            return false;
        }
        doc.merge_typosquats(outcome.signals);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Issue #1468 item 1: `TyposquatGate::refresh_from` — the debounced-edit typosquat
    /// gate's underlying primitive — must fire exactly when the declared name set differs
    /// from what was last checked, regardless of *why* it differs (an add, a remove, or
    /// both), and must never fire for an unchanged set even after a version-only edit
    /// (modeled here as calling it twice with the same set). Formerly
    /// `refresh_typosquat_checked_names_fires_only_on_a_real_set_change` in
    /// `document::lifecycle`, moved here alongside the type it now tests directly.
    #[test]
    fn refresh_from_fires_only_on_a_real_set_change() {
        let mut gate = TyposquatGate::default();
        let base: HashSet<(PackageName, TyposquatSourceEligibility)> = std::iter::once((
            PackageName::new("serde"),
            TyposquatSourceEligibility::Eligible,
        ))
        .collect();

        assert!(
            gate.refresh_from(base.clone()),
            "the very first check (against the unset default) must always fire"
        );

        assert!(
            !gate.refresh_from(base),
            "an unchanged (name, eligibility) set (e.g. a version-only edit) must not re-fire"
        );

        let added: HashSet<(PackageName, TyposquatSourceEligibility)> = [
            (
                PackageName::new("serde"),
                TyposquatSourceEligibility::Eligible,
            ),
            (
                PackageName::new("tokio"),
                TyposquatSourceEligibility::Eligible,
            ),
        ]
        .into_iter()
        .collect();
        assert!(gate.refresh_from(added.clone()), "an added name must fire");
        assert!(!gate.refresh_from(added));

        let removed: HashSet<(PackageName, TyposquatSourceEligibility)> = std::iter::once((
            PackageName::new("tokio"),
            TyposquatSourceEligibility::Eligible,
        ))
        .collect();
        assert!(gate.refresh_from(removed), "a removed name must also fire");

        // Issue #1462: a source-type flip with the *name set unchanged* must still fire —
        // this is the whole point of folding eligibility into the comparison key.
        let same_name_now_ineligible: HashSet<(PackageName, TyposquatSourceEligibility)> =
            std::iter::once((
                PackageName::new("tokio"),
                TyposquatSourceEligibility::Ineligible,
            ))
            .collect();
        assert!(
            gate.refresh_from(same_name_now_ineligible.clone()),
            "a source-eligibility flip on an otherwise-unchanged name must fire"
        );
        assert!(!gate.refresh_from(same_name_now_ineligible));
    }

    /// Issue #1463: a timed-out/failed prefetch must not permanently suppress retries for a
    /// declared set that never changes again — `TyposquatGate::clear_if_stale` is the
    /// primitive [`run_typosquat_prefetch`]'s timeout path relies on to make that true.
    /// Formerly `clear_typosquat_checked_names_if_stale_only_clears_an_exact_match` in
    /// `document::lifecycle`.
    #[test]
    fn clear_if_stale_only_clears_an_exact_match() {
        let mut gate = TyposquatGate::default();
        let snapshot: HashSet<(PackageName, TyposquatSourceEligibility)> = std::iter::once((
            PackageName::new("serde"),
            TyposquatSourceEligibility::Eligible,
        ))
        .collect();
        gate.refresh_from(snapshot.clone());

        gate.clear_if_stale(&snapshot);
        assert!(
            gate.is_empty(),
            "a failed attempt's own snapshot, still current, must be cleared so the next \
             debounced edit retries even without a name/eligibility change"
        );

        // A newer edit has since advanced the gate past the old snapshot — the older
        // attempt's belated cleanup must not clobber that newer, valid state.
        let newer: HashSet<(PackageName, TyposquatSourceEligibility)> = std::iter::once((
            PackageName::new("tokio"),
            TyposquatSourceEligibility::Eligible,
        ))
        .collect();
        gate.refresh_from(newer.clone());
        gate.clear_if_stale(&snapshot);
        assert_eq!(
            gate,
            TyposquatGate::from_iter(newer),
            "clearing must be a no-op once a newer edit has already superseded the stale \
             snapshot"
        );
    }

    /// Issue #1437: `run_typosquat_prefetch`'s own gates, mirroring `osv_scan`'s
    /// `license_prefetch_tests`' "never touches `DocumentState` at all" style for the
    /// disabled/offline no-op cases.
    #[cfg(feature = "npm")]
    mod typosquat_prefetch_tests {
        use super::super::super::state::DocumentState;
        use super::*;
        use deps_core::EcosystemId;

        /// Default `ServerState` starts with `policy.typosquat.enabled == false` — no
        /// document inserted for `uri` at all, so if the enabled-gate didn't short-circuit
        /// first, `state.get_document(&uri)` would return `None` and the function would
        /// still just return early; this also doubles as a "never panics on a missing
        /// document" check, same as `run_license_prefetch_no_op_for_non_tier3_ecosystem`.
        #[tokio::test]
        async fn run_typosquat_prefetch_no_op_when_disabled() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .get(EcosystemId::Npm)
                .expect("npm ecosystem not found");

            let changed = run_typosquat_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

            assert!(!changed);
            assert_eq!(state.document_count(), 0);
        }

        /// Same shape as the disabled case, for the offline gate.
        #[tokio::test]
        async fn run_typosquat_prefetch_no_op_when_offline() {
            let state = Arc::new(ServerState::new());
            state.set_typosquat_enabled(true);
            state.cache.set_offline(deps_core::NetworkMode::Offline);
            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .get(EcosystemId::Npm)
                .expect("npm ecosystem not found");

            let changed = run_typosquat_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

            assert!(!changed);
            assert_eq!(state.document_count(), 0);
        }

        /// Issue #1463 impl-critic S1: builds a real document, points this test's
        /// `ServerState::deps_dev` at a mocked server that fails (not times out) the
        /// similarity call, and drives `run_typosquat_prefetch` itself end to end — proving
        /// the gate-clear wired into this function's `outcome.completeness` check actually
        /// runs, not just the extracted `TyposquatGate::clear_if_stale` primitive in
        /// isolation. `ServerState::deps_dev`/`cache` are both `pub` fields, so a fresh
        /// `ServerState` built (not yet `Arc`-wrapped) can have `deps_dev` swapped for a
        /// `DepsDevClient::for_test` before this test wraps it in `Arc` itself.
        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn run_typosquat_prefetch_degraded_result_clears_gate_for_retry() {
            let mut server = mockito::Server::new_async().await;
            let _similarity = server
                .mock(
                    "GET",
                    "/v3alpha/systems/npm/packages/crossenv:similarlyNamedPackages",
                )
                .with_status(500)
                .create_async()
                .await;

            let mut state = ServerState::new();
            state.set_typosquat_enabled(true);
            state.deps_dev = Arc::new(deps_core::DepsDevClient::for_test(
                Arc::new(deps_core::HttpCache::new()),
                server.url(),
            ));
            let state = Arc::new(state);

            let url = deps_core::test_util::test_uri("/test/package.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"{"dependencies": {"crossenv": "1.0.0"}}"#;
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("npm ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Npm,
                content.to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            // Seeds the gate exactly like the real open/edit spawn path does
            // (`document::lifecycle`), so this test proves the *degraded-fetch* path clears
            // an already-set gate back out, not merely that a never-set gate stays empty.
            let names_snapshot = {
                let doc = state.get_document(&uri).expect("document just inserted");
                declared_names(
                    doc.parse_result().expect("parse result just inserted"),
                    ecosystem.formatter(),
                )
            };
            {
                let mut doc = state
                    .documents
                    .get_mut(&uri)
                    .expect("document just inserted");
                doc.signals
                    .typosquat_checked_names
                    .refresh_from(names_snapshot);
            }

            let changed =
                run_typosquat_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;
            assert!(
                !changed,
                "a fetch that resolved no usable signal must not report a merge"
            );

            let doc = state.get_document(&uri).expect("document still present");
            assert!(
                doc.signals.typosquat_checked_names.is_empty(),
                "issue #1463: a degraded (non-timeout) deps.dev failure must clear the gate \
                 so the next debounced edit retries even without a name/eligibility change"
            );
        }
    }
}

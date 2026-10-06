//! OSV vulnerability scan orchestration: scan-target construction,
//! phase A/B execution, license pre-fetch, and fix-target
//! verification.

use super::state::{ResolvedGeneration, ServerState};
use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_lsp_server::ls_types::Uri;

/// Ceiling on the OSV scan timeout, independent of the configured
/// `fetch_timeout_secs`: the shared `reqwest` client behind `HttpCache`
/// already imposes its own client-wide 30s timeout (`cache.rs`), so a
/// per-phase timeout longer than that would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

/// Logs the per-document scan summary unconditionally (critique C1) —
/// including when every dependency was filtered out before ever reaching
/// [`deps_core::osv::OsvClient::scan`], which previously produced no log line
/// at all and defeated §8 invariant 0's purpose of making "not scanned"
/// observable.
fn log_osv_run_summary(vulnerabilities: &deps_core::osv::VulnerabilityMap) {
    let mut clean = 0usize;
    let mut vulnerable = 0usize;
    let mut skipped = 0usize;
    for outcome in vulnerabilities.values() {
        match outcome {
            deps_core::osv::ScanOutcome::Clean => clean += 1,
            deps_core::osv::ScanOutcome::Vulnerable(_) => vulnerable += 1,
            deps_core::osv::ScanOutcome::Skipped(_) => skipped += 1,
        }
    }
    tracing::info!(
        "OSV: document scan complete, {} dependencies considered, {clean} clean, {vulnerable} vulnerable, {skipped} skipped",
        vulnerabilities.len(),
    );
}

/// What the scan does for one key: the exact query it sends, or why it sends none.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PlannedQuery {
    Query {
        name: deps_core::osv::OsvQueryName,
        version: deps_core::osv::OsvVersion,
        siblings: Vec<deps_core::osv::OsvVersion>,
        sibling_coverage: deps_core::pagination::ListCoverage,
    },
    Skip(deps_core::osv::SkipReason),
}

/// The per-key inputs of one OSV scan, as [`deps_engine::classify::osv::build_scan_targets`]
/// decided them — committed next to the scan's results so a later rebuild of the same plan
/// tells exactly whether a rescan could produce anything different (#1705, #1706).
///
/// Comparing inputs rather than outcomes is what keeps a permanently skipped key (a branch
/// pin, a bare `@4`, an unconfirmed private repository) from re-running the scan after every
/// registry fetch, while still catching a floating tag that moved to another release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OsvScanPlan(HashMap<deps_core::osv::VulnKey, PlannedQuery>);

impl OsvScanPlan {
    fn new(
        targets: &[deps_core::osv::ScanTarget],
        skipped: &deps_core::osv::VulnerabilityMap,
    ) -> Self {
        let queries = targets.iter().map(|target| {
            (
                target.key.clone(),
                PlannedQuery::Query {
                    name: target.osv_name.clone(),
                    version: target.version.clone(),
                    siblings: target
                        .siblings()
                        .iter()
                        .map(|s| s.version().clone())
                        .collect(),
                    sibling_coverage: target.sibling_coverage(),
                },
            )
        });
        let skips = skipped.iter().filter_map(|(key, outcome)| {
            let deps_core::osv::ScanOutcome::Skipped(reason) = outcome else {
                return None;
            };
            Some((key.clone(), PlannedQuery::Skip(*reason)))
        });
        Self(queries.chain(skips).collect())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Drops the entry for a removed dependency's normalized name.
    pub(crate) fn retain_not_named(&mut self, normalized: &str) {
        self.0.retain(|key, _| !key.is_for_name(normalized));
    }
}

/// Builds the scan targets and pre-filter skips from whatever the document holds right now —
/// the single input both [`run_osv_scan_phase_a`] and the rescan predicate derive from.
fn scan_inputs(
    doc: &super::state::DocumentState,
    ecosystem: &dyn Ecosystem,
) -> Option<(
    Vec<deps_core::osv::ScanTarget>,
    deps_core::osv::VulnerabilityMap,
)> {
    let parse_result = doc.parse_result()?;
    Some(deps_engine::classify::osv::build_scan_targets(
        parse_result,
        &doc.signals.resolved_versions,
        &doc.signals.resolved_version_candidates,
        ecosystem.formatter(),
        ecosystem.ecosystem_id(),
    ))
}

/// Phase A output, carried from the concurrently-spawned scan task into
/// phase B (run later, after the registry fetch resolves — critique S1).
pub(crate) struct OsvScanResult {
    /// Document content at the moment the scan started, to guard the
    /// eventual write against a cross-generation stale commit (critique M4).
    content_snapshot: String,
    /// `PackageSignals::resolved_versions_generation` at the moment the scan started (issue
    /// #1395 critic S3) — `content_snapshot` alone cannot order two phase-A/B pairs whose
    /// resolved-version snapshots differ but whose `content` doesn't (a lock-file-only
    /// reload never touches `content`).
    resolved_generation: ResolvedGeneration,
    vulnerabilities: deps_core::osv::VulnerabilityMap,
    /// `key -> osv_name`, needed to build phase B candidates.
    osv_name_by_key: HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName>,
    /// Inputs this scan ran with, committed next to `vulnerabilities`.
    scan_plan: OsvScanPlan,
}

/// Phase A: builds scan targets, runs [`deps_core::osv::OsvClient::scan`], and
/// merges in the pre-filter skips — all before the registry fetch is known
/// to have completed, so this must be `tokio::spawn`ed by the caller and run
/// concurrently with it, never awaited inline (critique S2/original design
/// note: joining here would gate the inlay-hint refresh that must happen
/// immediately after the registry fetch).
///
/// Returns `None` only when there is nothing to report at all (no
/// dependencies reached any of steps 0-3, including the pre-filter skips —
/// i.e. an empty manifest).
#[tracing::instrument(skip_all, fields(uri = ?uri, ecosystem = ecosystem.id()))]
pub(crate) async fn run_osv_scan_phase_a(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> Option<OsvScanResult> {
    let ecosystem_id = ecosystem.ecosystem_id();

    let (content_snapshot, resolved_generation, targets, mut vulnerabilities) = {
        let doc = state.get_document(&uri)?;
        let (targets, skipped) = scan_inputs(&doc, ecosystem.as_ref())?;
        (
            doc.content.clone(),
            doc.signals.resolved_versions_generation,
            targets,
            skipped,
        )
    };

    if targets.is_empty() && vulnerabilities.is_empty() {
        return None;
    }

    let osv_name_by_key = deps_engine::classify::osv::osv_name_by_key(&targets);
    let scan_plan = OsvScanPlan::new(&targets, &vulnerabilities);

    if !targets.is_empty() {
        let timeout_duration =
            Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));
        let scanned = state
            .osv
            .scan(ecosystem_id, &targets, timeout_duration)
            .await;
        vulnerabilities.extend(scanned);
    }

    log_osv_run_summary(&vulnerabilities);

    Some(OsvScanResult {
        content_snapshot,
        resolved_generation,
        vulnerabilities,
        osv_name_by_key,
        scan_plan,
    })
}

/// Runs phase A followed by phase B and commits the result for a single document —
/// the lock-file-change counterpart of the manifest-change path's spawn-phase-A/
/// await-then-phase-B sequence in `document::lifecycle::run_document_change_task`
/// (issue #1395). Unlike that path, `handle_lockfile_change` never starts a registry
/// fetch of its own for phase A to run concurrently against, so this awaits phase A
/// directly rather than spawning it as a separate task.
///
/// No-op if phase A finds nothing to report (see [`run_osv_scan_phase_a`]'s return
/// contract).
pub(crate) async fn rescan_after_resolved_version_change(
    uri: &Uri,
    state: &Arc<ServerState>,
    ecosystem: &Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) {
    // Issue #1398 critic M2: this is the one OSV rescan that deliberately survives a
    // `did_close` (see `ResolvedGeneration`'s doc) — its caller (`server::handle_lockfile_change`)
    // always bumps the generation via a real `next_resolved_versions_generation()` draw before
    // spawning this. No assert here (impl-critic S2): a `did_close`+`did_open` racing in between
    // the bump and this function's first poll can legitimately reopen the document at the
    // shared `INITIAL` value before this runs — phase A snapshots whatever the document holds
    // when it starts, so a commit against a freshly reopened, still-`INITIAL` document is
    // self-consistent, not a bug.
    let Some(phase_a_result) = run_osv_scan_phase_a(
        uri.clone(),
        Arc::clone(state),
        Arc::clone(ecosystem),
        fetch_timeout_secs,
    )
    .await
    else {
        return;
    };

    run_osv_phase_b_and_commit(
        uri,
        state,
        ecosystem.ecosystem_id(),
        ecosystem.formatter(),
        fetch_timeout_secs,
        phase_a_result,
    )
    .await;
}

/// Whether [`rescan_osv_if_tag_index_now_warm`] ran the OSV pipeline and committed a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RescanOutcome {
    /// The gate was closed, the scan plan was unchanged, or phase A had nothing to report.
    Unchanged,
    /// The pipeline ran again; the caller should republish diagnostics.
    Rescanned,
}

/// Re-runs the OSV phase A/B pipeline once more and commits its result, when needed, right
/// after a registry fetch this document just awaited (#1556 critic S2).
///
/// [`run_osv_scan_phase_a`] builds its scan targets from whatever the document holds the
/// moment it starts, but callers spawn it *concurrently with*, not after, the registry fetch
/// that (for GitHub Actions/GitLab CI) populates `TagIndex` — see
/// [`deps_core::lsp_helpers::RequirementResolution::resolved_pin_version_depends_on_registry_fetch`].
/// On a cold first open/edit this races that fetch: phase A can snapshot an empty `TagIndex`,
/// skip a dependency as [`deps_core::osv::SkipReason::NoConcreteVersion`], and nothing
/// re-checks it once the fetch actually lands, so the diagnostic stays wrong for the rest of
/// the session.
///
/// No-op while [`ServerState::is_osv_latest_check_enabled`] (vulnerabilities enabled and not
/// offline) is `false`, read live so a setting change during the preceding fetch is honored
/// (#1704).
///
/// Cheap no-op in the overwhelmingly common case: returns immediately unless both (a) this
/// ecosystem's formatter opts into
/// `resolved_pin_version_depends_on_registry_fetch` and (b) the [`OsvScanPlan`] rebuilt from the
/// document's current state differs from the one its last committed scan ran with — a
/// cold-index skip that now resolves (#1556), a provisional name now confirmed (#1694), or a
/// floating tag that moved to another release (#1706). A key that stays skipped for the same
/// reason (a branch pin, a bare `@4`) leaves the plans equal and never rescans (#1705). When it
/// does run, it mirrors
/// [`rescan_after_resolved_version_change`]'s "run phase A, then phase B, then commit" shape
/// exactly, plus the same hint/code-lens republish
/// [`super::lifecycle`]'s ordinary commit path gives a phase-B commit, since this can be the
/// first time accurate results are available for this document.
pub(crate) async fn rescan_osv_if_tag_index_now_warm(
    uri: &Uri,
    state: &Arc<ServerState>,
    client: &tower_lsp_server::Client,
    ecosystem: &Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) -> RescanOutcome {
    if !state.is_osv_latest_check_enabled()
        || !ecosystem
            .formatter()
            .resolved_pin_version_depends_on_registry_fetch()
    {
        return RescanOutcome::Unchanged;
    }

    let plan_changed = state.get_document(uri).is_some_and(|doc| {
        scan_inputs(&doc, ecosystem.as_ref()).is_some_and(|(targets, skipped)| {
            OsvScanPlan::new(&targets, &skipped) != doc.signals.osv_scan_plan
        })
    });
    if !plan_changed {
        return RescanOutcome::Unchanged;
    }
    tracing::debug!("OSV scan plan changed after registry fetch, rescanning");

    let Some(phase_a_result) = run_osv_scan_phase_a(
        uri.clone(),
        Arc::clone(state),
        Arc::clone(ecosystem),
        fetch_timeout_secs,
    )
    .await
    else {
        return RescanOutcome::Unchanged;
    };

    run_osv_phase_b_and_commit(
        uri,
        state,
        ecosystem.ecosystem_id(),
        ecosystem.formatter(),
        fetch_timeout_secs,
        phase_a_result,
    )
    .await;
    state.spawn_refresh_requests(client);
    RescanOutcome::Rescanned
}

/// Background pre-fetch of each dependency's license, for whichever ecosystems
/// override [`deps_core::Ecosystem::fetch_license`] (issue #660/#688, spec 010 plan §1
/// tier 3) — today, pub.dev's `/score` endpoint (Dart), the GitHub repository API
/// (Swift), a Maven Central POM fetch (Gradle), and the JSR per-version API (Deno).
/// Mirrors
/// [`run_osv_scan_phase_a`]'s spawn-concurrently-with-the-registry-fetch shape, but
/// commits directly with no phase B. Callers must `.await` the returned
/// `JoinHandle` (via `tokio::spawn`) before their own diagnostics publish, exactly
/// like the OSV `osv_task` join — a tier-3 license-policy violation must be able to
/// appear in the *first* diagnostics publish after the triggering edit, not only
/// whenever some later, unrelated event happens to regenerate diagnostics (code-review
/// round 3 finding #3).
///
/// Target selection (which dependencies to fetch a license for, at which version) is
/// [`deps_engine::classify::license::tier3_license_targets`], and the network dispatch is
/// [`deps_engine::classify::license::fetch_tier3_licenses`] (issue #1133) — both shared with
/// `deps-cli` so both adapters reach the same license-policy verdict for these four
/// ecosystems. Targets are computed synchronously while holding the document guard (mirroring
/// [`run_osv_scan_phase_a`]'s `build_scan_targets` call), which is dropped before the network
/// dispatch below ever awaits. This function keeps only what is genuinely `deps-lsp`'s own:
/// the document snapshot/staleness guard and the additive `PackageSignals::licenses` commit.
///
/// The commit at the end is staleness-guarded on both `doc.content == content_snapshot`
/// and `doc.signals.resolved_versions_generation == resolved_generation` (issue #1407, mirroring
/// [`run_osv_phase_b_and_commit`]'s identical pair of checks) and merges rather than
/// replaces (round 3 finding #1/#2). The content check alone is not enough: a
/// lock-file-only change never touches `content`, so two overlapping lock-file-triggered
/// pre-fetches (each snapshotting a different `resolved_versions`) would both pass a
/// content-only guard, and the older one finishing last could silently overwrite the
/// newer one's results — the same race issue #1395 fixed for OSV scan commits via the
/// generation guard, reproduced here for licenses. Without the merge, a transient
/// per-dependency fetch failure this round (already filtered out by the shared function,
/// before this point) would drop that dependency's previously-cached, still-valid
/// license instead of just failing to refresh it. `DocumentState::merge_licenses`'s own
/// additive contract already provides exactly this — a genuinely *removed* dependency's
/// stale entry is reclaimed separately, by `PackageSignals::prune_removed` (called from
/// `commit_parsed_document`), not by this function replacing the whole map.
///
/// **What version each source actually reflects is per-ecosystem, not uniform** — see
/// [`deps_engine::classify::license::prefetch_tier3_licenses`]'s doc for the full
/// per-ecosystem breakdown (Dart/Swift's tier-3 source isn't pinned to the resolved
/// version the way Gradle/Deno's is).
///
/// No-op (returns immediately) for every ecosystem whose
/// <code>ecosystem.[license_source](deps_core::Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// is `false` (issue #697) — every ecosystem except the four above — or whenever
/// `state`'s current [`ServerState::license_policy`] is empty (issue #1407 code-review
/// should-fix). This check is *load-bearing*, not defense-in-depth: as noted above, this
/// function calls [`deps_engine::classify::license::fetch_tier3_licenses`] directly, not
/// its convenience-wrapper counterpart
/// [`deps_engine::classify::license::prefetch_tier3_licenses`] (used by `deps-cli`) —
/// `prefetch_tier3_licenses` takes a `LicensePolicy` and no-ops on an empty one itself,
/// but `fetch_tier3_licenses` takes no `LicensePolicy` parameter at all and never checks
/// one. Without this early return, a document with no license policy configured would
/// still issue a real tier-3 network fetch (Dart/Swift/Gradle/Deno) on every trigger, for
/// a result nothing ever reads. Centralizing the check here (issue #1407 code-review
/// should-fix) also replaced the now-removed duplicate checks
/// `server::handle_lockfile_change` and `document::lifecycle::change_task_triggers`'s
/// callers used to run externally before deciding whether to trigger a refresh at all.
pub(crate) async fn run_license_prefetch(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) {
    if !ecosystem.license_source().requires_dedicated_fetch() || state.license_policy().is_empty() {
        return;
    }

    let (content_snapshot, resolved_generation, targets): (
        String,
        ResolvedGeneration,
        Vec<(PackageName, ConcreteVersion)>,
    ) = {
        let Some(doc) = state.get_document(&uri) else {
            return;
        };
        let Some(parse_result) = doc.parse_result() else {
            return;
        };
        let targets = deps_engine::classify::license::tier3_license_targets(
            parse_result,
            &doc.signals.resolved_versions,
            &doc.signals.resolved_version_candidates,
            ecosystem.formatter(),
            ecosystem.ecosystem_id(),
        );
        (
            doc.content.clone(),
            doc.signals.resolved_versions_generation,
            targets,
        )
    };

    if targets.is_empty() {
        return;
    }

    let result = deps_engine::classify::license::fetch_tier3_licenses(
        ecosystem.as_ref(),
        targets,
        fetch_timeout_secs,
        LICENSE_PREFETCH_CONCURRENCY,
    )
    .await;

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        if doc.content != content_snapshot {
            tracing::debug!(
                "dropping stale tier-3 license pre-fetch result: document content changed mid-fetch"
            );
        } else if doc.signals.resolved_versions_generation != resolved_generation {
            // Issue #1407, mirroring #1395 critic S3: `content` alone can't order two
            // racing pre-fetches whose resolved-version snapshots differ (e.g. two
            // overlapping lock-file-only reloads) — a newer resolved-versions update
            // landed on this document after this pre-fetch's snapshot was taken.
            tracing::debug!(
                "dropping stale tier-3 license pre-fetch result: resolved versions changed mid-fetch"
            );
        } else {
            doc.merge_licenses(result.licenses);
        }
    }
}

/// Bounds how many concurrent per-dependency license fetches [`run_license_prefetch`] issues
/// at once — tier-3 documents rarely carry more than a handful of dependencies (Dart/Swift/
/// Gradle/Deno are all comparatively small ecosystems in this project's usage), and this
/// pre-fetch is a background nice-to-have, not on the hover critical path, so there is no
/// latency pressure to fan out aggressively. `deps-cli`'s check-gate call passes its own,
/// larger `cache.max_concurrent_fetches` instead (issue #1133 critic M3) — this constant is
/// `deps-lsp`'s own tuning choice, not a shared default.
const LICENSE_PREFETCH_CONCURRENCY: usize = 8;

/// Phase B: checks whether the version currently recommended as "latest" is itself affected
/// for **every** dependency with a registry-cached latest (B.1, issue #1517 — previously
/// restricted to dependencies phase A already flagged
/// [`deps_core::osv::ScanOutcome::Vulnerable`] at their *pinned* version, which let a
/// cleanly-pinned dependency's malicious/vulnerable latest go completely unchecked), then
/// independently verifies each vulnerable dependency's recommended *fix target* F (B.2, #462 —
/// see [`run_osv_fix_target_verification`]), before committing both results into
/// `DocumentState.signals.vulnerabilities`/`latest_status`.
///
/// Must be called only *after* the registry fetch has updated
/// `doc.signals.cached_versions`: calling it concurrently with that fetch (as the
/// original implementation did, by folding phase B into the same spawned
/// task as phase A) reads `cached_versions` before it holds the registry's
/// actual latest version, so hover could report the *already-installed*
/// version as "also affected" instead of the true latest.
///
/// The write is guarded against a cross-generation stale commit (critique
/// M4): `spawn_background_task` aborts the *previous* task only after the
/// new `DocumentState` is already installed, so an in-flight scan from stale
/// content could otherwise commit advisories computed against content the
/// document no longer has. B.1 and B.2 share one `phase_b_deadline` (#462
/// critic S2/M1) rather than each getting a fresh `fetch_timeout_secs`
/// budget: B.2 is a second sequential network round-trip added *before* this
/// guard, so giving it its own full budget would both double phase B's
/// worst-case wall-clock time (contradicting NFR-002's singular "existing...
/// budget" framing) and widen the window in which a mid-scan edit discards
/// this whole result. Sharing one deadline caps the total at the original
/// ceiling, same as before this fix existed. A timeout partway through B.1 gives the
/// unresolved targets a [`deps_core::osv::UpgradeStatus::CandidateUnverified`] entry in
/// `latest_status` (never an absent one — see [`deps_core::osv::OsvClient::check_candidates`]'s
/// own contract), which every renderer's [`deps_core::lsp_helpers::latest_verdict`] already
/// treats as [`deps_core::lsp_helpers::LatestVerdict::Unverified`] (fail-closed) — never
/// silently "verified safe".
pub(crate) async fn run_osv_phase_b_and_commit(
    uri: &Uri,
    state: &Arc<ServerState>,
    ecosystem_id: EcosystemId,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    fetch_timeout_secs: u64,
    mut result: OsvScanResult,
) {
    let vulnerable_keys: Vec<deps_core::osv::VulnKey> = result
        .vulnerabilities
        .iter()
        .filter(|(_, outcome)| matches!(outcome, deps_core::osv::ScanOutcome::Vulnerable(_)))
        .map(|(key, _)| key.clone())
        .collect();

    let phase_b_deadline =
        Instant::now() + Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));

    // B.1 (issue #1517): latest-check targets for every registry dependency with a
    // registry-cached latest, plus explicit structural skips — never only phase A's
    // vulnerable subset. `vuln_keys` is recomputed fresh here (cheap, pure) rather than
    // carried from phase A, since it must reflect the document as of *this* snapshot, not
    // phase A's possibly-earlier one.
    //
    // B.1b (#1524): candidate-check rounds for the same snapshot, sharing this one
    // `vuln_keys`/`parse_result`/`cached_versions` read rather than a second document lookup.
    let (targets, mut latest_status, candidate_rounds, mut candidate_status, candidate_tags) = {
        let Some(doc) = state.get_document(uri) else {
            return;
        };
        let Some(parse_result) = doc.parse_result() else {
            return;
        };
        let vuln_keys = deps_core::osv::vulnerability_keys(
            parse_result,
            &doc.signals.resolved_versions,
            Some(&doc.signals.resolved_version_candidates),
            formatter,
            ecosystem_id,
        );
        let candidate_tags = deps_engine::classify::osv::candidate_tag_sources(
            parse_result,
            &vuln_keys,
            formatter,
            ecosystem_id,
        );
        let (targets, latest_status) = deps_engine::classify::osv::build_latest_check_targets(
            parse_result,
            &doc.signals.cached_versions,
            &vuln_keys,
            &candidate_tags,
            formatter,
        );
        let (candidate_rounds, candidate_status) =
            deps_engine::classify::osv::build_candidate_check_targets(
                parse_result,
                &doc.signals.cached_versions,
                &vuln_keys,
                &candidate_tags,
                formatter,
            );
        (
            targets,
            latest_status,
            candidate_rounds,
            candidate_status,
            candidate_tags,
        )
    };

    if !targets.is_empty() {
        let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
        let checked = state
            .osv
            .check_candidates(ecosystem_id, &targets, timeout_duration)
            .await;
        latest_status.extend(checked);
    }

    // B.2 runs before the B.1b candidate rounds below (impl-critic S1): both draw from the
    // same shared `phase_b_deadline`, and B.2 verifies the recommended-fix quickfix's target F
    // — an existing, higher-value feature than #1524's new candidate rounds. Running the
    // rounds first could starve B.2's budget on a cold cache/large manifest, making the
    // Fix-Vulnerability quickfix silently disappear; ordering B.2 first means only the newer
    // feature ever degrades under time pressure, never the older one.
    if !vulnerable_keys.is_empty() {
        run_osv_fix_target_verification(
            &mut result.vulnerabilities,
            &vulnerable_keys,
            &result.osv_name_by_key,
            &latest_status,
            &candidate_tags,
            ecosystem_id,
            formatter,
            &state.osv,
            phase_b_deadline,
        )
        .await;
    }

    // First commit (impl-critic S1): `vulnerabilities`/`latest_status` land as soon as B.1/B.2
    // finish, independent of how long the B.1b candidate rounds below take — hover/diagnostics
    // consume these two, not `candidate_status`, so gating their staleness on an unrelated,
    // newer (#1524) check would only make already-stale-feeling data stay stale longer.
    //
    // Impl-critic N1: also the early-exit gate for the candidate rounds below. A document that
    // is already stale here (or has been closed entirely) will be stale for the second commit
    // too — nothing has happened in between that could make it fresh again — so there is no
    // point spending a further 6 rounds of OSV network calls whose result is guaranteed to be
    // discarded.
    let stale = if let Some(mut doc) = state.documents.get_mut(uri) {
        if doc.content != result.content_snapshot {
            tracing::debug!("dropping stale OSV scan result: document content changed mid-scan");
            true
        } else if doc.signals.resolved_versions_generation != result.resolved_generation {
            // Issue #1395 critic S3: `content` alone can't order two racing phase-A/B
            // pairs whose resolved-version snapshots differ (e.g. a lock-file-only
            // reload racing a slower manifest-edit scan) — a newer `update_resolved_versions`
            // call landed on this document after this scan's snapshot was taken.
            tracing::debug!("dropping stale OSV scan result: resolved versions changed mid-scan");
            true
        } else {
            doc.update_vulnerabilities(result.vulnerabilities);
            doc.signals.osv_scan_plan = result.scan_plan;
            doc.update_latest_status(latest_status);
            false
        }
    } else {
        // Document closed entirely — nothing to commit, and nothing to check candidates for.
        true
    };
    if stale {
        return;
    }

    // B.1b (#1524): one round trip per candidate-version rank, each batched across every
    // dependency that has a rank-th non-yanked version — never more than one target per
    // `VulnKey` per round, so `check_candidates` never collapses two of one dependency's own
    // candidates together. Runs after B.1/B.2 commit above (impl-critic S1) and concurrently
    // across rounds (`join_all`, not sequential `.await`s): the rounds are independent of each
    // other, so running them one at a time would multiply phase B's worst-case wall-clock time
    // for no correctness benefit — they still share `phase_b_deadline`'s remaining budget, just
    // spend it in parallel instead of serially.
    let round_results =
        futures::future::join_all(candidate_rounds.into_iter().filter_map(|round| {
            if round.is_empty() {
                return None;
            }
            let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
            Some(async move {
                state
                    .osv
                    .check_candidates(ecosystem_id, &round, timeout_duration)
                    .await
            })
        }))
        .await;
    for checked in round_results {
        for (key, status) in checked {
            let version: ConcreteVersion = match &status {
                deps_core::osv::UpgradeStatus::CandidateClean { version }
                | deps_core::osv::UpgradeStatus::CandidateVulnerable { version, .. }
                | deps_core::osv::UpgradeStatus::CandidateUnverified { version, .. } => {
                    version.clone()
                }
                // `check_candidates` never returns `NotChecked`/`StructurallyUnchecked` — a
                // target it could not resolve at all becomes `CandidateUnverified` instead
                // (see its own doc). `#[non_exhaustive]` requires this wildcard even though
                // every real variant is already matched above; a future new variant with no
                // known version string here is nothing to record, not a bug.
                _ => continue,
            };
            // Structural entries never reach this point: `build_candidate_check_targets`
            // never adds a dependency it recorded as `CandidateStatuses::Structural` to any
            // round, so a round result can only ever belong to a `PerVersion` entry. Checked by
            // borrowing first (code-review finding: an unconditional `key.clone()` before the
            // `entry()` move was dead weight on the hot, common `PerVersion` path, paid on every
            // round-result entry just to log the rare/unreachable-in-practice mismatch) — only
            // the mismatch arm below ever needs `key`, and it still owns it there since
            // `entry(key)` was never reached. Exhaustive (not `if let`) because
            // `CandidateStatuses` is deliberately not `#[non_exhaustive]` (#1624 critique S2) —
            // a silently-dropped `Structural` case here would only ever be caught by this
            // `debug_assert!`, since the invariant above is enforced by a comment in
            // `deps-engine`, not by the type system.
            if let Some(deps_core::osv::CandidateStatuses::Structural(reason)) =
                candidate_status.get(&key)
            {
                debug_assert!(
                    false,
                    "candidate-check round result for a dependency recorded as \
                     structurally skipped ({reason:?}) — build_candidate_check_targets \
                     should never have queued a round target for this key"
                );
                tracing::warn!(
                    key = %key,
                    ?reason,
                    "OSV #1624: dropping candidate-check round result for a structurally \
                     skipped dependency"
                );
                continue;
            }
            match candidate_status
                .entry(key)
                .or_insert_with(|| deps_core::osv::CandidateStatuses::PerVersion(HashMap::new()))
            {
                deps_core::osv::CandidateStatuses::PerVersion(per_version) => {
                    per_version.insert(version, status);
                }
                deps_core::osv::CandidateStatuses::Structural(_) => unreachable!(
                    "just checked above via candidate_status.get(&key) that this entry is not Structural"
                ),
            }
        }
    }

    // Second commit (impl-critic S1): `candidate_status` alone, gated by the same staleness
    // guard as the first commit — a slow candidate round never delays the primary commit
    // above, and re-checking staleness here (rather than reusing a flag from the first commit)
    // catches a document change that landed *between* the two commits too.
    if let Some(mut doc) = state.documents.get_mut(uri) {
        if doc.content != result.content_snapshot {
            tracing::debug!(
                "dropping stale OSV candidate-status result: document content changed mid-scan"
            );
        } else if doc.signals.resolved_versions_generation != result.resolved_generation {
            tracing::debug!(
                "dropping stale OSV candidate-status result: resolved versions changed mid-scan"
            );
        } else {
            doc.update_candidate_status(candidate_status);
        }
    }
}

/// B.2 (#462): independently verifies each vulnerable dependency's recommended fix target F
/// (`DependencyVulnerabilities::recommended_fix`'s `version`), which B.1 above never scans —
/// B.1 only ever checks the registry's "latest" candidate, and F is frequently a different,
/// older version (the minimal version that clears the advisories B.1's "latest" check did
/// not already exclude). Without this, `generate_code_actions` could offer F as a verified
/// fix when OSV was never asked about F itself — see
/// `deps_core::osv::DependencyVulnerabilities::fix_target_status`'s doc, which this function
/// populates, and the orphaned-TODO history in this function's git blame (formerly tracked
/// only by a `// TODO(critic): ... see #216 critique D1` comment; now #462).
///
/// Resolution order per dependency, cheapest first:
/// 1. F equals the already-checked "latest" candidate (FR-002) — reuse that entry from the
///    shared [`deps_core::osv::LatestStatusMap`] (issue #1517), no extra call.
/// 2. Otherwise, queue a live [`deps_core::osv::OsvClient::check_candidates`] check for F,
///    batched into a single call across every dependency that reaches this branch (NFR-001)
///    — never one call per dependency. There is no data-derived shortcut here: a proof
///    checking F against the advisories `recommended_fix()` computed F *from* is a
///    tautology at its only call site (critic C1) — phase A only ever queries the
///    dependency's declared version, so an advisory affecting some version strictly
///    between declared and F, but not the declared version itself, is invisible to any
///    check built only from `self.advisories`. Only a live query of F itself can surface
///    that advisory (the actual gap #462 exists to close).
///
/// A dependency whose F fails [`deps_core::lsp_helpers::is_safe_version_string`], or whose
/// `osv_name` is unavailable, is skipped (logged at `debug`), never crashes the scan. A
/// dependency whose live check above times out or fails simply keeps `fix_target_status`
/// left at `NotChecked` (case 2's `HashMap` result never carries that key) — the safe,
/// fail-closed degradation FR-004/NFR-002 call for: `deps_core::lsp_helpers::code_actions::fix_target_is_verified`
/// treats an unresolved status as unverified and omits the fix action, so a stalled
/// verification never surfaces a fix action that was never actually checked.
#[allow(clippy::too_many_arguments)]
async fn run_osv_fix_target_verification(
    vulnerabilities: &mut deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[deps_core::osv::VulnKey],
    osv_name_by_key: &HashMap<deps_core::osv::VulnKey, deps_core::osv::OsvQueryName>,
    latest_status: &deps_core::osv::LatestStatusMap,
    candidate_tags: &deps_engine::classify::osv::CandidateTagSources,
    ecosystem_id: EcosystemId,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    osv: &deps_core::osv::OsvClient,
    phase_b_deadline: Instant,
) {
    use deps_core::osv::ScanOutcome;

    let (resolved, live_check_candidates) =
        deps_engine::classify::osv::collect_fix_target_resolutions(
            vulnerabilities,
            vulnerable_keys,
            osv_name_by_key,
            latest_status,
            candidate_tags,
            formatter,
        );

    for (key, status) in resolved {
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(&key) {
            dv.fix_target_status = status;
        }
    }

    if live_check_candidates.is_empty() {
        return;
    }

    let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
    let statuses = osv
        .check_candidates(ecosystem_id, &live_check_candidates, timeout_duration)
        .await;

    deps_engine::classify::osv::apply_live_fix_target_statuses(vulnerabilities, statuses);
}

#[cfg(test)]
mod tests {
    // Only `license_prefetch_tests`' dart/swift/gradle/deno-gated cases consume this.
    #[cfg(any(
        feature = "dart",
        feature = "swift",
        feature = "gradle",
        feature = "deno"
    ))]
    use super::super::state::DocumentState;
    use super::*;

    /// A non-empty license policy, for every `run_license_prefetch` test below that
    /// needs to get past its new empty-policy early return (issue #1407 code-review
    /// should-fix) to reach the ecosystem-specific fetch under test. The actual
    /// allow/deny content is irrelevant here — only emptiness matters to that gate.
    fn non_empty_license_policy() -> deps_core::LicensePolicy {
        deps_core::LicensePolicy::new(vec!["MIT".to_string()], vec![])
    }

    /// Issue #660: `run_license_prefetch`'s ecosystem gate — only the four tier-3
    /// ecosystems (no `deps_dev_system` coverage, no license in the hot-path
    /// version-list response) should ever reach a network call.
    mod license_prefetch_tests {
        use super::*;

        /// Issue #697: exhaustive per-[`EcosystemId`] table, so a 15th ecosystem or a
        /// 5th [`deps_core::LicenseSource`] variant is a compile error here, mirroring
        /// this project's `EcosystemId` exhaustive-match convention. Replaces the
        /// previous six feature-gated spot checks against `fetch_license(..).is_some()`
        /// with one assertion per registered ecosystem against `license_source()`.
        /// `requires_dedicated_fetch()` needs no separate assertion: it is a pure
        /// function of `license_source()`, so once `license_source()` is pinned to the
        /// table below, capability follows automatically and cannot independently drift.
        const fn expected_license_source(id: EcosystemId) -> deps_core::LicenseSource {
            match id {
                EcosystemId::Dart | EcosystemId::Swift => deps_core::LicenseSource::DetectedSpdx,
                EcosystemId::Gradle => deps_core::LicenseSource::PomFreeText,
                EcosystemId::Deno => deps_core::LicenseSource::FetchedDeclaredSpdx,
                EcosystemId::Cargo
                | EcosystemId::Npm
                | EcosystemId::Pypi
                | EcosystemId::Go
                | EcosystemId::Bundler
                | EcosystemId::Maven
                | EcosystemId::Composer
                | EcosystemId::NuGet
                | EcosystemId::GithubActions
                | EcosystemId::GitlabCi => deps_core::LicenseSource::RegistryDeclaredSpdx,
            }
        }

        #[test]
        fn license_source_is_pinned_per_ecosystem() {
            let state = ServerState::new();

            for id in state.ecosystem_registry.ecosystem_ids() {
                let eco = state
                    .ecosystem_registry
                    .get(id)
                    .unwrap_or_else(|| panic!("{id} ecosystem not found"));

                assert_eq!(
                    eco.license_source(),
                    expected_license_source(id),
                    "{id}: license_source() mismatch"
                );
            }
        }

        /// A non-tier-3 ecosystem must return immediately without touching
        /// `DocumentState` at all (not even an empty-map write) — asserted by never
        /// inserting a document for `uri` and confirming `run_license_prefetch`
        /// doesn't panic on a missing document, which it would if it read past the
        /// ecosystem gate.
        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn run_license_prefetch_no_op_for_non_tier3_ecosystem() {
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");

            // No document inserted for `uri` at all — if the ecosystem gate didn't
            // short-circuit first, `state.get_document(&uri)` inside would return
            // `None` and the function would still just return early, so this also
            // doubles as a "never panics on a missing document" check.
            run_license_prefetch(uri, Arc::clone(&state), ecosystem, 5).await;

            assert_eq!(state.document_count(), 0);
        }

        /// Live end-to-end (Registry Integration Gate): a real Dart document, routed
        /// through the real `EcosystemRegistry` (no mock), fetching `http`'s license
        /// from the real pub.dev `/score` endpoint and committing it into
        /// `DocumentState.signals.licenses`.
        #[cfg(feature = "dart")]
        #[tokio::test]
        #[ignore = "hits the real pub.dev API"]
        async fn run_license_prefetch_live_dart_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "dependencies:\n  http: ^1.0.0\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Dart ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("http"), "1.2.0".into())]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.signals.licenses.contains_key(&PackageName::new("http")),
                "expected a pre-fetched license for 'http', got: {:?}",
                doc.signals.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `Package.swift`
        /// dependency, routed through the real `EcosystemRegistry`, fetching
        /// `apple/swift-nio`'s license from the real GitHub repository API. Skips (rather
        /// than fails) on an expected unauthenticated rate limit — see
        /// `deps_core::test_util::should_skip_on_empty_result`'s doc (#1283).
        #[cfg(feature = "swift")]
        #[tokio::test]
        #[ignore = "hits the real GitHub API"]
        async fn run_license_prefetch_live_swift_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/Package.swift");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#".package(url: "https://github.com/apple/swift-nio.git", .upToNextMajor(from: "2.0.0"))"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Swift ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Swift,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("apple/swift-nio"), "2.65.0".into())]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            state.update_document(uri.clone(), doc_state);

            // `ecosystem` itself (not just a clone) is kept alive past this call so it can
            // still probe below on a missing license (#1283 S2).
            run_license_prefetch(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5).await;

            // Scoped so the `DashMap` shard-lock guard `get_document` returns is dropped
            // before the probe below ever awaits (`clippy::await_holding_invalid_type`).
            let licenses = state.get_document(&uri).unwrap().signals.licenses.clone();
            let has_license = licenses.contains_key(&PackageName::new("apple/swift-nio"));
            // #1283 S2: `run_license_prefetch` swallows *any* fetch error to "no license
            // populated", so a missing entry alone can't tell an expected rate limit apart
            // from a real bug — see `should_skip_on_empty_result`'s doc.
            if deps_core::test_util::should_skip_on_empty_result(
                !has_license,
                "run_license_prefetch_live_swift_populates_document_licenses",
                ecosystem
                    .registry()
                    .get_versions(&PackageName::new("apple/swift-nio")),
            )
            .await
            {
                return;
            }
            assert!(
                has_license,
                "expected a pre-fetched license for 'apple/swift-nio', got: {:?}",
                licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `build.gradle.kts`
        /// dependency, routed through the real `EcosystemRegistry`, fetching
        /// `com.squareup.okhttp3:okhttp`'s license from the real Maven Central POM.
        #[cfg(feature = "gradle")]
        #[tokio::test]
        #[ignore = "hits the real Maven Central API"]
        async fn run_license_prefetch_live_gradle_populates_document_licenses() {
            // Held per `deps_core::fs_probe::snapshot_guard`'s doc: gradle's `parse_manifest`
            // transitively touches fs_probe, and this test runs in the same binary as
            // `document/loader.rs`'s diffing test.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content =
                "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Gradle,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(
                    PackageName::new("com.squareup.okhttp3:okhttp"),
                    "4.12.0".into(),
                )]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.signals
                    .licenses
                    .contains_key(&PackageName::new("com.squareup.okhttp3:okhttp")),
                "expected a pre-fetched license for 'com.squareup.okhttp3:okhttp', got: {:?}",
                doc.signals.licenses
            );
        }

        /// Live end-to-end, issue #692: Guava's own leaf POM
        /// (`guava-32.0.1-jre.pom`) has no `<licenses>` block at all — the license is
        /// declared only on its `guava-parent` POM. Unlike the okhttp test above (whose
        /// own leaf POM already carries `<licenses>`), this specifically exercises
        /// `fetch_license_from`'s `<parent>`-following path against real Maven Central.
        #[cfg(feature = "gradle")]
        #[tokio::test]
        #[ignore = "hits the real Maven Central API"]
        async fn run_license_prefetch_live_gradle_follows_parent_pom_for_guava() {
            // See the comment in `run_license_prefetch_live_gradle_populates_document_licenses`
            // on why this guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content =
                "dependencies {\n    implementation(\"com.google.guava:guava:32.0.1-jre\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Gradle,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(
                    PackageName::new("com.google.guava:guava"),
                    "32.0.1-jre".into(),
                )]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            let license = doc
                .signals
                .licenses
                .get(&PackageName::new("com.google.guava:guava"));
            assert!(
                license.is_some_and(|l| !l.is_empty()),
                "expected a pre-fetched license for 'com.google.guava:guava' via its \
                 parent POM, got: {:?}",
                doc.signals.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `deno.json`
        /// `jsr:` dependency, routed through the real `EcosystemRegistry`, fetching
        /// `@std/fs`'s license from the real JSR per-version API.
        #[cfg(feature = "deno")]
        #[tokio::test]
        #[ignore = "hits the real JSR API"]
        async fn run_license_prefetch_live_deno_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/deno.json");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Deno ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Deno,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("jsr:@std/fs"), "1.0.24".into())]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.signals
                    .licenses
                    .contains_key(&PackageName::new("jsr:@std/fs")),
                "expected a pre-fetched license for 'jsr:@std/fs', got: {:?}",
                doc.signals.licenses
            );
        }
    }

    /// Regression coverage for issue #1407: `run_license_prefetch`'s own
    /// `resolved_versions_generation` guard (mirroring #1395's OSV guard, see
    /// `generation_race_tests` below) must drop a commit that raced against an intervening
    /// resolved-versions bump. Unlike `run_osv_phase_b_and_commit`, `run_license_prefetch`
    /// has no separate phase-A/phase-B split to snapshot against ahead of time, so the race
    /// is reproduced with real concurrency instead: a fake tier-3 `Ecosystem` whose
    /// `fetch_license` signals a barrier once entered (proving the snapshot has already been
    /// taken) and then blocks on a second barrier until the test releases it, giving the test
    /// a deterministic window to mutate the document's generation in between. Network-free —
    /// no real tier-3 registry call is ever made.
    mod license_prefetch_generation_race_tests {
        use super::super::super::state::DocumentState;
        use super::*;
        use deps_core::Dependency;
        use deps_core::LicenseSource;
        use deps_core::Metadata;
        use deps_core::ParseResult;
        use deps_core::Registry;
        use deps_core::VersionReq;
        use deps_core::ecosystem::BoxFuture;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::lsp_helpers::EcosystemFormatter;
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};
        use std::any::Any;
        use tokio::sync::Barrier;

        struct FakeTier3Dep {
            name: PackageName,
            version_req: VersionReq,
        }

        impl Dependency for FakeTier3Dep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::new(Position::new(0, 0), Position::new(0, 1))
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> DependencySource {
                DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct FakeTier3ParseResult {
            dep: FakeTier3Dep,
            uri: url::Url,
        }

        impl deps_core::ParseResult for FakeTier3ParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![&self.dep]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// A single `=`-pinned, registry-sourced dependency (`dep-0`) whose `fetch_license`
        /// is fully controlled by the barriers below — mirrors
        /// `deps_engine::test_util::TestTier3Ecosystem`'s shape, but kept local to this crate
        /// (rather than pulled in as a `deps-engine/test-util` dev-dependency) since only
        /// `deps-lsp`'s own commit-guard needs exercising here, not `fetch_tier3_licenses`
        /// itself.
        struct SignalingLicenseEcosystem {
            started: Arc<Barrier>,
            release: Arc<Barrier>,
            license: Vec<String>,
        }

        impl Sealed for SignalingLicenseEcosystem {}
        impl Ecosystem for SignalingLicenseEcosystem {
            fn ecosystem_id(&self) -> EcosystemId {
                EcosystemId::Dart
            }
            fn display_name(&self) -> &'static str {
                "test-tier3-license"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &[]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                uri: &'a url::Url,
            ) -> BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>> {
                let uri = uri.clone();
                Box::pin(async move {
                    Ok(Box::new(FakeTier3ParseResult {
                        dep: FakeTier3Dep {
                            name: PackageName::new("dep-0"),
                            version_req: VersionReq::new("=1.0.0"),
                        },
                        uri,
                    }) as Box<dyn ParseResult>)
                })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(crate::test_utils::blocking_ecosystem::NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
            }
            fn completion_insert_text(&self, _metadata: &dyn Metadata) -> Option<String> {
                None
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: PackageName,
                _prefix: String,
            ) -> BoxFuture<'a, deps_core::completion::Completions> {
                unimplemented!()
            }
            fn fetch_license<'a>(
                &'a self,
                _name: &'a PackageName,
                _version: &'a ConcreteVersion,
            ) -> BoxFuture<'a, Vec<String>> {
                Box::pin(async move {
                    self.started.wait().await;
                    self.release.wait().await;
                    self.license.clone()
                })
            }
            fn license_source(&self) -> LicenseSource {
                LicenseSource::DetectedSpdx
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// Sets up a document (generation 0, empty content) parsed via `ecosystem` and
        /// registered in `state`, ready for `run_license_prefetch` to be spawned against it.
        async fn setup_document(
            state: &Arc<ServerState>,
            uri: &Uri,
            ecosystem: &Arc<dyn Ecosystem>,
            url: &url::Url,
        ) {
            let parse_result = ecosystem.parse_manifest("", url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                String::new(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);
        }

        #[tokio::test]
        async fn run_license_prefetch_drops_stale_commit_on_concurrent_generation_bump() {
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let started = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let ecosystem: Arc<dyn Ecosystem> = Arc::new(SignalingLicenseEcosystem {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
                license: vec!["MIT".to_string()],
            });
            setup_document(&state, &uri, &ecosystem, &url).await;

            let task = {
                let uri = uri.clone();
                let state = Arc::clone(&state);
                let ecosystem = Arc::clone(&ecosystem);
                tokio::spawn(async move {
                    run_license_prefetch(uri, state, ecosystem, 5).await;
                })
            };

            // `fetch_license` has been entered, so `run_license_prefetch`'s content/generation
            // snapshot has necessarily already been taken. Timeout-wrapped (critic minor,
            // issue #1407): a future regression that made `run_license_prefetch` skip the
            // fetch entirely (e.g. an over-eager early return) would otherwise hang this
            // test forever instead of failing it.
            tokio::time::timeout(std::time::Duration::from_secs(5), started.wait())
                .await
                .expect("run_license_prefetch must reach fetch_license within 5s");

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.bump_resolved_generation(state.next_resolved_versions_generation());
            }

            // Let `fetch_license` return its (otherwise real) license result.
            tokio::time::timeout(std::time::Duration::from_secs(5), release.wait())
                .await
                .expect("test must release fetch_license's second barrier within 5s");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("run_license_prefetch task must complete within 5s")
                .unwrap();

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.signals.licenses.is_empty(),
                "an intervening generation bump between snapshot and commit must drop this \
                 pre-fetch's result, even though the fetch itself succeeded: {:?}",
                doc.signals.licenses
            );
        }

        /// Negative control, proving the guard above is not vacuously passing: with no
        /// intervening bump, the same fetch must still commit successfully.
        #[tokio::test]
        async fn run_license_prefetch_commits_when_no_concurrent_bump() {
            let state = Arc::new(ServerState::new());
            state.set_license_policy(non_empty_license_policy());
            let url = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            let started = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let ecosystem: Arc<dyn Ecosystem> = Arc::new(SignalingLicenseEcosystem {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
                license: vec!["MIT".to_string()],
            });
            setup_document(&state, &uri, &ecosystem, &url).await;

            let task = {
                let uri = uri.clone();
                let state = Arc::clone(&state);
                let ecosystem = Arc::clone(&ecosystem);
                tokio::spawn(async move {
                    run_license_prefetch(uri, state, ecosystem, 5).await;
                })
            };

            // Timeout-wrapped for the same reason as the positive test above (critic
            // minor, issue #1407): a future regression must fail this test cleanly,
            // not hang it.
            tokio::time::timeout(std::time::Duration::from_secs(5), started.wait())
                .await
                .expect("run_license_prefetch must reach fetch_license within 5s");
            tokio::time::timeout(std::time::Duration::from_secs(5), release.wait())
                .await
                .expect("test must release fetch_license's second barrier within 5s");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("run_license_prefetch task must complete within 5s")
                .unwrap();

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.signals.licenses.get(&PackageName::new("dep-0")),
                Some(&vec!["MIT".to_string()]),
                "no intervening bump occurred, so the fetch's result must commit: {:?}",
                doc.signals.licenses
            );
        }
    }

    /// Issue #1517 critique S6: no test covered the actual root-cause wiring — phase B
    /// populating `latest_status` for a dependency phase A found *clean* (the #1517 bug
    /// scenario: a pre-fix build only ever latest-checked dependencies phase A had already
    /// flagged `Vulnerable`, so a cleanly-pinned dependency's malicious/vulnerable "latest"
    /// went completely unchecked).
    #[cfg(feature = "cargo")]
    mod phase_b_latest_status_tests {
        use super::super::super::state::DocumentState;
        use super::*;
        use deps_core::osv::{CandidateStatuses, OsvClient, UpgradeStatus};
        use std::assert_matches;

        /// End to end: a registry-sourced Cargo dependency pinned at a clean version, with a
        /// registry-cached "latest" that differs from it, against a mocked OSV.dev that
        /// reports both the pinned version and the latest as clean. Phase A must find the
        /// pinned version clean (not vulnerable), and phase B must still populate
        /// `latest_status` with a `CandidateClean` entry for the *latest* version — the map
        /// entry every renderer's `latest_verdict` gate depends on to ever render the update
        /// as `Verified` rather than fail closed.
        #[tokio::test]
        async fn phase_b_populates_latest_status_for_a_phase_a_clean_dependency() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            // Phase A's (pinned "1.0.0"), B.1's (latest "1.2.0"), and B.1b's round-0
            // candidate-check (the sole cached version, "1.2.0", is also this dependency's
            // only round-0 candidate — #1624 tester gap 2) batch queries all hit this same
            // endpoint; mocked to report every queried version clean, so this one mock covers
            // all three calls (`.expect(3)`).
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .expect(3)
                .create_async()
                .await;

            let mut state = ServerState::new();
            state.osv = Arc::new(OsvClient::for_test(
                Arc::new(deps_core::HttpCache::new()),
                server.url(),
            ));
            let state = Arc::new(state);

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("serde"), "1.0.0".into())]),
                HashMap::new(),
                state.next_resolved_versions_generation(),
            );
            doc_state.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                deps_core::lsp_helpers::PackageVersions::latest_only("1.2.0"),
            )]));
            state.update_document(uri.clone(), doc_state);

            let phase_a_result =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a registry dependency must produce a phase-A result");

            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a_result,
            )
            .await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals
                    .vulnerabilities
                    .get(&deps_core::test_util::vuln_key("serde")),
                Some(deps_core::osv::ScanOutcome::Clean),
                "phase A must find the pinned version clean: {:?}",
                doc.signals.vulnerabilities
            );
            assert_matches!(
                doc.signals
                    .latest_status
                    .get(&deps_core::test_util::vuln_key("serde")),
                Some(UpgradeStatus::CandidateClean { version }) if version == "1.2.0",
                "phase B must populate latest_status for a phase-A-clean dependency too \
                 (issue #1517) — got: {:?}",
                doc.signals.latest_status
            );
            // #1624 tester gap 2: the B.1b round-merge (rewritten for this issue) must land in
            // `candidate_status` too, keyed by the exact `ConcreteVersion` the round checked —
            // not silently dropped by the `entry().or_insert_with(..)` merge, and not left as a
            // fresh empty `PerVersion` map.
            let candidate_statuses = doc
                .signals
                .candidate_status
                .get(&deps_core::test_util::vuln_key("serde"));
            let Some(CandidateStatuses::PerVersion(per_version)) = candidate_statuses else {
                panic!(
                    "phase B's B.1b round-check must populate candidate_status with a \
                     PerVersion entry for serde — got: {candidate_statuses:?}"
                );
            };
            assert_matches!(
                per_version.get(&deps_core::ConcreteVersion::new("1.2.0")),
                Some(UpgradeStatus::CandidateClean { version }) if version == "1.2.0",
                "round 0's sole candidate (\"1.2.0\") must resolve clean — got: {per_version:?}"
            );
        }
    }

    /// Regression coverage for issue #1395's bidirectional-generation-race finding
    /// (surfaced by code-review after N1/N2): `run_osv_phase_b_and_commit`'s staleness
    /// guard (`resolved_versions_generation` match) is shared by every commit site, so a
    /// bump from *any* source without a corresponding fresh scan of its own can silently
    /// drop a different, still-correct in-flight commit.
    #[cfg(feature = "cargo")]
    mod generation_race_tests {
        use super::super::super::state::DocumentState;
        use super::*;
        use std::assert_matches;

        fn git_dep_content() -> &'static str {
            "[dependencies]\nalpha-dep = { git = \"https://github.com/example/alpha-dep\" }\n"
        }

        async fn setup(state: &Arc<ServerState>, uri: &Uri, url: &url::Url) -> Arc<dyn Ecosystem> {
            let ecosystem = state.ecosystem_registry.for_uri(url).unwrap();
            let parse_result = ecosystem
                .parse_manifest(git_dep_content(), url)
                .await
                .unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                git_dep_content().to_string(),
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);
            ecosystem
        }

        /// The fix: an intervening caller that follows the conditional-bump contract
        /// (`set_resolved_versions_without_bump` with no paired `bump_resolved_generation`,
        /// exactly what `document::lifecycle::run_document_change_task` now does for an
        /// edit with `needs_osv_rescan == false`, and `server::handle_lockfile_change` does
        /// for a document whose own dependencies are unaffected) must NOT cause a
        /// concurrently in-flight, still-correct phase-A/B pair to be dropped.
        #[tokio::test]
        async fn test_unrelated_no_bump_update_does_not_drop_concurrent_scan_commit() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = setup(&state, &uri, &url).await;

            // Phase A of some concurrent scan (e.g. a lock-file-triggered rescan) snapshots
            // the document here, capturing the current generation.
            let phase_a_result =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect(
                        "git-sourced dependency must still produce a NonRegistrySource skip result",
                    );

            // An unrelated event (e.g. a debounced edit that touches no dependency, or a
            // lock-file reload for a document whose own dependencies are unaffected) races
            // in between phase A and phase B. It updates the maps (even to the same values)
            // but — per the fix — must not bump the generation, since it schedules no scan
            // of its own to produce a fresh replacement commit.
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.set_resolved_versions_without_bump(HashMap::new(), HashMap::new());
            }

            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a_result,
            )
            .await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals
                    .vulnerabilities
                    .get(&deps_core::test_util::vuln_key("alpha-dep")),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::NonRegistrySource
                )),
                "an intervening update that correctly does not bump the generation must not \
                 cause this scan's own, still-correct commit to be dropped"
            );
        }

        /// Negative control, proving the guard above is not vacuously passing: a genuine
        /// bump between phase A and phase B (the case the guard exists to catch) must still
        /// drop the now-stale commit.
        #[tokio::test]
        async fn test_concurrent_bump_still_drops_stale_scan_commit() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem = setup(&state, &uri, &url).await;

            let phase_a_result =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect(
                        "git-sourced dependency must still produce a NonRegistrySource skip result",
                    );

            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.set_resolved_versions_without_bump(HashMap::new(), HashMap::new());
                doc.bump_resolved_generation(state.next_resolved_versions_generation());
            }

            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a_result,
            )
            .await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.signals.vulnerabilities.is_empty(),
                "a genuine concurrent generation bump must still cause the now-stale scan's \
                 commit to be dropped, proving the guard itself still functions: {:?}",
                doc.signals.vulnerabilities
            );
        }

        /// Regression guard for issue #1395 critic M10: a close/reopen ABA on the
        /// generation counter. A per-document-instance counter restarting at 0 on every
        /// `DocumentState` rebuild can collide with a stale, `did_close`-surviving rescan's
        /// earlier snapshot from a *previous* instance of the same document — the one scan
        /// kind that deliberately isn't cancelled on close (issue #1395 critic N1).
        /// `ServerState::next_resolved_versions_generation`'s server-global, ever-increasing
        /// source closes this by construction: two different `DocumentState` instances can
        /// never draw the same value.
        #[tokio::test]
        async fn test_close_reopen_does_not_let_a_stale_rescan_commit_over_a_fresh_instance() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use deps_core::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

            let state = Arc::new(ServerState::new());
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            // First document instance, resolved at v1 — a rescan (R1) snapshots it here.
            let ecosystem = setup(&state, &uri, &url).await;
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_resolved_versions(
                    HashMap::from([(PackageName::new("alpha-dep"), "0.1.0".into())]),
                    HashMap::new(),
                    state.next_resolved_versions_generation(),
                );
            }
            let r1_phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect(
                        "git-sourced dependency must still produce a NonRegistrySource skip result",
                    );

            // Document closed, then reopened — a brand new `DocumentState` instance for the
            // same URI, resolved at a different version (v2) by a rescan (S2) that already
            // committed its own, correct result before R1's phase B below returns.
            state.remove_document(&uri);
            let ecosystem = setup(&state, &uri, &url).await;
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                doc.update_resolved_versions(
                    HashMap::from([(PackageName::new("alpha-dep"), "0.2.0".into())]),
                    HashMap::new(),
                    state.next_resolved_versions_generation(),
                );
            }
            let mut s2_result = VulnerabilityMap::new();
            s2_result.insert(
                deps_core::test_util::vuln_key("alpha-dep"),
                ScanOutcome::Skipped(SkipReason::UnmappableName),
            );
            state
                .documents
                .get_mut(&uri)
                .unwrap()
                .update_vulnerabilities(s2_result);

            // R1's phase B, snapshotted against the FIRST (now-closed) document instance,
            // finally returns.
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                r1_phase_a,
            )
            .await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals
                    .vulnerabilities
                    .get(&deps_core::test_util::vuln_key("alpha-dep")),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName)),
                "R1's stale commit (snapshotted against the closed document instance) must \
                 not overwrite the freshly-reopened instance's own result — got: {:?}",
                doc.signals.vulnerabilities
            );
        }
    }

    /// #1556 critic S2/S3: `rescan_osv_if_tag_index_now_warm`.
    #[cfg(feature = "github-actions")]
    mod tag_index_rescan_tests {
        use super::super::super::state::DocumentState;
        use super::*;
        use deps_core::lsp_helpers::{CommitSha, TagIndex};
        use deps_core::osv::OsvClient;
        use deps_github_actions::{GithubActionsEcosystem, GithubActionsRegistry};
        use std::assert_matches;

        /// A cold first open (empty `TagIndex`, mirroring phase A racing ahead of the tags
        /// fetch) must not be a permanent skip: once the fetch that would populate
        /// `TagIndex` lands, `rescan_osv_if_tag_index_now_warm` must re-run the pipeline and
        /// replace the stale `Skipped(NoConcreteVersion)` with a real result — and (S3) do
        /// so under the exact same `VulnKey`, proving no cold-keyed entry is left orphaned
        /// behind by the warm commit's full-replace (`DocumentState::update_vulnerabilities`).
        #[tokio::test]
        async fn rescan_replaces_cold_skip_with_warm_result_under_the_same_key() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _mock = server
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
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let sha = "f".repeat(40);
            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v1\n");

            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content,
                parse_result,
            );
            state.update_document(uri.clone(), doc_state);

            // Cold: `TagIndex` is empty, exactly as it is before this ecosystem's own tags
            // fetch has ever run.
            let cold_phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a SHA-pinned step must still produce a phase-A result");
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                cold_phase_a,
            )
            .await;

            let key = deps_core::test_util::vuln_key("actions/checkout");
            {
                let doc = state.get_document(&uri).unwrap();
                assert_matches!(
                    doc.signals.vulnerabilities.get(&key),
                    Some(deps_core::osv::ScanOutcome::Skipped(
                        deps_core::osv::SkipReason::NoConcreteVersion
                    )),
                    "cold TagIndex: expected the SHA pin to be skipped, got: {:?}",
                    doc.signals.vulnerabilities
                );
            }

            // Warm: the tags fetch that would normally populate `TagIndex` lands now.
            let registry = ecosystem.registry();
            let gha_registry = registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry");
            let mut index = TagIndex::default();
            index.insert_sha_pin(
                CommitSha::parse(&sha).unwrap(),
                deps_core::lsp_helpers::ResolvedPin::most_specific(
                    deps_core::ConcreteVersion::new("v1.3.0"),
                ),
            );
            let index = index.with_canonical_repo_name(
                deps_core::github::CanonicalRepoName::from_commit_url(
                    "https://api.github.com/repos/actions/checkout/commits/abc",
                ),
            );
            gha_registry
                .tag_index()
                .insert(PackageName::new("actions/checkout"), Arc::new(index));

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals.vulnerabilities.get(&key),
                Some(deps_core::osv::ScanOutcome::Clean),
                "warm rescan must replace the stale skip under the SAME key with a real \
                 result: {:?}",
                doc.signals.vulnerabilities
            );
            assert_eq!(
                doc.signals.vulnerabilities.len(),
                1,
                "the rescan's full-replace commit must leave no leftover stale entry \
                 behind: {:?}",
                doc.signals.vulnerabilities
            );
        }

        /// #1704: with vulnerabilities disabled or the server offline (both fold into
        /// `is_osv_latest_check_enabled`, see the `did_change_configuration` tests in
        /// `server.rs`) a warm `TagIndex` must not trigger an OSV request or replace the stale
        /// skip.
        #[tokio::test]
        async fn rescan_is_noop_when_vulnerabilities_disabled_or_offline() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .expect(0)
                .create_async()
                .await;

            let mut state = ServerState::new();
            state.osv = Arc::new(OsvClient::for_test(
                Arc::new(deps_core::HttpCache::new()),
                server.url(),
            ));
            state.set_osv_latest_check_enabled(false);
            let state = Arc::new(state);
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let sha = "f".repeat(40);
            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v1\n");

            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content,
                parse_result,
            );
            let key = deps_core::test_util::vuln_key("actions/checkout");
            doc_state.signals.vulnerabilities.insert(
                key.clone(),
                deps_core::osv::ScanOutcome::Skipped(deps_core::osv::SkipReason::NoConcreteVersion),
            );
            state.update_document(uri.clone(), doc_state);

            let registry = ecosystem.registry();
            let gha_registry = registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry");
            let mut index = TagIndex::default();
            index.insert_sha_pin(
                CommitSha::parse(&sha).unwrap(),
                deps_core::lsp_helpers::ResolvedPin::most_specific(
                    deps_core::ConcreteVersion::new("v1.3.0"),
                ),
            );
            gha_registry
                .tag_index()
                .insert(PackageName::new("actions/checkout"), Arc::new(index));

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            batch.assert_async().await;
            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals.vulnerabilities.get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::NoConcreteVersion
                ))
            );
        }

        /// #1683: a non-SHA pin (`@v4.1.2`) needs no tag lookup to resolve its version, but its
        /// OSV name needs the canonical casing from the tags fetch. On a cold open the scan
        /// must skip transiently (never as an unmappable name), and the rescan must run once
        /// the index lands and replace it with a real result.
        #[tokio::test]
        async fn rescan_replaces_cold_canonical_name_skip_for_non_sha_pin() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let batch = server
                .mock("POST", "/v1/querybatch")
                .match_body(mockito::Matcher::Regex("actions/checkout".into()))
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
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "steps:\n  - uses: actions/checkout@v4.1.2\n".to_string();

            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            state.update_document(
                uri.clone(),
                DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content,
                    parse_result,
                ),
            );

            let cold_phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a tag-pinned step must produce a phase-A result");
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                cold_phase_a,
            )
            .await;

            let key = deps_core::test_util::vuln_key("actions/checkout");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::CanonicalNameUnconfirmed
                ))
            );

            let registry = ecosystem.registry();
            let gha_registry = registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry");
            gha_registry.tag_index().insert(
                PackageName::new("actions/checkout"),
                Arc::new(TagIndex::default().with_canonical_repo_name(
                    deps_core::github::CanonicalRepoName::from_commit_url(
                        "https://api.github.com/repos/actions/checkout/commits/abc",
                    ),
                )),
            );

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Clean)
            );
            batch.assert_async().await;
        }

        /// #1709: an exact tag pin used to be independent of the `TagIndex`; now a cold scan
        /// checks only the written tag, and the warm index adding a sibling release tag must
        /// change the scan plan so the rescan flags an advisory introduced in that sibling.
        #[tokio::test]
        async fn rescan_flags_sibling_release_tag_advisory_for_exact_tag_pin_once_index_warm() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","modified":"2025-01-01T00:00:00Z"}]}]}"#)
                .create_async()
                .await;
            let _record = server
                .mock("GET", "/v1/vulns/GHSA-aaaa-bbbb-cccc")
                .with_status(200)
                .with_body(
                    r#"{"id":"GHSA-aaaa-bbbb-cccc","modified":"2025-01-01T00:00:00Z",
                    "affected":[{"package":{"name":"actions/checkout","ecosystem":"GitHub Actions"},
                    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.9.0"},{"fixed":"4.9.1"}]}]}]}"#,
                )
                .create_async()
                .await;

            let mut state = ServerState::new();
            state.osv = Arc::new(OsvClient::for_test(
                Arc::new(deps_core::HttpCache::new()),
                server.url(),
            ));
            let state = Arc::new(state);
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "steps:\n  - uses: actions/checkout@v4.8.0\n".to_string();
            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            state.update_document(
                uri.clone(),
                DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content,
                    parse_result,
                ),
            );
            let canonical = || {
                deps_core::github::CanonicalRepoName::from_commit_url(
                    "https://api.github.com/repos/actions/checkout/commits/abc",
                )
            };
            let registry = ecosystem.registry();
            let tag_index = registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry")
                .tag_index();
            tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(TagIndex::default().with_canonical_repo_name(canonical())),
            );

            let cold_phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a tag-pinned step must produce a phase-A result");
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                cold_phase_a,
            )
            .await;
            let key = deps_core::test_util::vuln_key("actions/checkout");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Clean)
            );

            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(
                    TagIndex::from_tags([("v4.8.0", &commit), ("v4.9.0", &commit)])
                        .with_canonical_repo_name(canonical()),
                ),
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            let Some(deps_core::osv::ScanOutcome::Vulnerable(dv)) =
                doc.signals.vulnerabilities.get(&key)
            else {
                panic!("warm rescan must flag the sibling-only advisory");
            };
            assert!(dv.sibling_match("GHSA-aaaa-bbbb-cccc").is_some());
        }

        /// #1709: two plans that differ only by a target's sibling tags are not equal, so a
        /// tag index refresh adding or removing a sibling triggers a rescan (#1715 contract).
        #[test]
        fn osv_scan_plan_differs_when_only_siblings_differ() {
            use deps_core::ConcreteVersion;
            use deps_core::osv::{OsvPackageName, OsvQueryName, ScanTarget};

            struct Identity;
            impl deps_core::lsp_helpers::OsvNaming for Identity {}

            let target = |siblings: &[&str]| {
                let versions = deps_core::lsp_helpers::InUseVersions::for_test(
                    ConcreteVersion::new("4.8.0"),
                    siblings.iter().map(|s| ConcreteVersion::new(*s)).collect(),
                );
                ScanTarget::from_native(
                    deps_core::test_util::vuln_key("actions/checkout"),
                    OsvQueryName::Confirmed(OsvPackageName::new("actions/checkout").unwrap()),
                    ConcreteVersion::new("4.8.0"),
                    &Identity,
                )
                .with_siblings(&versions, &Identity)
            };
            let skipped = deps_core::osv::VulnerabilityMap::new();
            let plan = |siblings: &[&str]| OsvScanPlan::new(&[target(siblings)], &skipped);

            assert_ne!(plan(&[]), plan(&["4.9.0"]));
            assert_ne!(plan(&["4.9.0"]), plan(&["4.9.0", "4.10.0"]));
            assert_eq!(plan(&["4.9.0"]), plan(&["4.9.0"]));
        }

        /// #1668: a skip because the resolved tag was only a moving alias (`v2`) is just as
        /// `TagIndex`-dependent as a cold-cache skip — once a refreshed index knows a more
        /// specific tag for the SHA, the rescan must replace it with a real result.
        #[tokio::test]
        async fn rescan_replaces_resolved_tag_not_full_version_skip_after_index_refresh() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _mock = server
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
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let sha = "e".repeat(40);
            let commit = CommitSha::parse(&sha).unwrap();
            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v2\n");

            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            state.update_document(
                uri.clone(),
                DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content,
                    parse_result,
                ),
            );

            let registry = ecosystem.registry();
            let tag_index = registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry")
                .tag_index();
            tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(
                    TagIndex::from_tags([("v2", &commit)]).with_canonical_repo_name(
                        deps_core::github::CanonicalRepoName::from_commit_url(
                            "https://api.github.com/repos/actions/checkout/commits/abc",
                        ),
                    ),
                ),
            );

            let phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a SHA-pinned step must still produce a phase-A result");
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a,
            )
            .await;

            let key = deps_core::test_util::vuln_key("actions/checkout");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::ResolvedTagNotFullVersion
                ))
            );

            tag_index.insert(
                PackageName::new("actions/checkout"),
                Arc::new(
                    TagIndex::from_tags([("v2", &commit), ("v2.9.1", &commit)])
                        .with_canonical_repo_name(
                            deps_core::github::CanonicalRepoName::from_commit_url(
                                "https://api.github.com/repos/actions/checkout/commits/abc",
                            ),
                        ),
                ),
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Clean)
            );
        }

        /// #1705: branch, bare-major and alias-only pins stay skipped for the same reason across
        /// a warm index, so a rescan must never run — a sentinel entry survives only if the
        /// full-replace commit never happened.
        #[tokio::test]
        async fn unchanged_skipped_pins_do_not_rescan() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let server = mockito::Server::new_async().await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) = open_gha_document(
                server.url(),
                "steps:\n  - uses: actions/checkout@main\n  - uses: actions/setup-node@4\n  - uses: actions/cache@v4\n",
            )
            .await;
            let commit = CommitSha::parse(&"c".repeat(40)).unwrap();
            for name in ["actions/checkout", "actions/setup-node", "actions/cache"] {
                land_tags(
                    &ecosystem,
                    name,
                    &[("v4", &commit)],
                    &format!("https://api.github.com/repos/{name}/commits/abc"),
                );
            }

            scan_and_commit(&state, &uri, &ecosystem).await;

            let sentinel = deps_core::test_util::vuln_key("sentinel");
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                assert_eq!(doc.signals.osv_scan_plan.len(), 3);
                assert!(
                    doc.signals
                        .osv_scan_plan
                        .0
                        .values()
                        .all(|planned| matches!(planned, PlannedQuery::Skip(_))),
                    "{:?}",
                    doc.signals.osv_scan_plan
                );
                doc.signals
                    .vulnerabilities
                    .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);
            }

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .contains_key(&sentinel),
                "skips that did not change must not rescan"
            );
        }

        /// #1705: a failed tags fetch leaves the index untouched, so a cold-index skip stays
        /// equal to its stored plan and does not rescan.
        #[tokio::test]
        async fn unchanged_cold_index_skip_does_not_rescan() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let server = mockito::Server::new_async().await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@v4\n").await;

            scan_and_commit(&state, &uri, &ecosystem).await;

            let sentinel = deps_core::test_util::vuln_key("sentinel");
            state
                .documents
                .get_mut(&uri)
                .unwrap()
                .signals
                .vulnerabilities
                .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .contains_key(&sentinel),
                "an index that stayed cold must not rescan"
            );
        }

        /// #1706: a floating `@v4` whose tag moves to another release is re-queried under the
        /// new version, and a further rescan with the index unchanged does nothing.
        #[tokio::test]
        async fn moved_floating_tag_triggers_rescan_once() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@v4\n").await;
            let canonical = "https://api.github.com/repos/actions/checkout/commits/abc";
            let old = CommitSha::parse(&"a".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "actions/checkout",
                &[("v4", &old), ("v4.1.0", &old)],
                canonical,
            );

            scan_and_commit(&state, &uri, &ecosystem).await;
            let key = deps_core::test_util::vuln_key("actions/checkout");
            let planned_version = |state: &Arc<ServerState>| match state
                .get_document(&uri)
                .unwrap()
                .signals
                .osv_scan_plan
                .0
                .get(&key)
            {
                Some(PlannedQuery::Query { version, .. }) => version.as_str().to_string(),
                other => panic!("expected a planned query, got {other:?}"),
            };
            assert!(planned_version(&state).contains("4.1.0"));

            let new = CommitSha::parse(&"b".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "actions/checkout",
                &[("v4", &new), ("v4.1.0", &old), ("v4.2.0", &new)],
                canonical,
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;
            assert!(planned_version(&state).contains("4.2.0"));

            let sentinel = deps_core::test_util::vuln_key("sentinel");
            state
                .documents
                .get_mut(&uri)
                .unwrap()
                .signals
                .vulnerabilities
                .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .contains_key(&sentinel),
                "an unchanged plan must not rescan again"
            );
        }

        /// A dependency removed from the manifest drops its plan entry with its other
        /// per-key state.
        #[tokio::test]
        async fn prune_removed_drops_the_plan_entry() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let server = mockito::Server::new_async().await;
            let (state, uri, ecosystem) = open_gha_document(
                server.url(),
                "steps:\n  - uses: actions/checkout@main\n  - uses: actions/cache@main\n",
            )
            .await;
            scan_and_commit(&state, &uri, &ecosystem).await;

            let mut doc = state.documents.get_mut(&uri).unwrap();
            assert_eq!(doc.signals.osv_scan_plan.len(), 2);
            doc.signals
                .prune_removed(&[PackageName::new("actions/cache")], ecosystem.formatter());

            assert_eq!(doc.signals.osv_scan_plan.len(), 1);
            assert!(
                !doc.signals
                    .osv_scan_plan
                    .0
                    .contains_key(&deps_core::test_util::vuln_key("actions/cache"))
            );
        }

        /// Plan equality is decided by the query's name, trust, version, or skip reason.
        #[test]
        fn scan_plan_equality_tracks_query_inputs() {
            let target = |name: &str, version: &str, confirmed: bool| {
                let package = deps_core::osv::OsvPackageName::new(name).unwrap();
                deps_core::osv::ScanTarget::new(
                    deps_core::test_util::vuln_key(name),
                    if confirmed {
                        deps_core::osv::OsvQueryName::Confirmed(package)
                    } else {
                        deps_core::osv::OsvQueryName::Provisional(package)
                    },
                    deps_core::osv::OsvVersion::new(version.to_string()),
                    ConcreteVersion::new(version),
                )
            };
            let skipped = |reason| {
                deps_core::osv::VulnerabilityMap::from([(
                    deps_core::test_util::vuln_key("b"),
                    deps_core::osv::ScanOutcome::Skipped(reason),
                )])
            };
            let base = OsvScanPlan::new(
                &[target("a", "1.0.0", true)],
                &skipped(deps_core::osv::SkipReason::NoConcreteVersion),
            );

            assert_eq!(
                base,
                OsvScanPlan::new(
                    &[target("a", "1.0.0", true)],
                    &skipped(deps_core::osv::SkipReason::NoConcreteVersion),
                )
            );
            assert_ne!(
                base,
                OsvScanPlan::new(
                    &[target("a", "1.1.0", true)],
                    &skipped(deps_core::osv::SkipReason::NoConcreteVersion),
                )
            );
            assert_ne!(
                base,
                OsvScanPlan::new(
                    &[target("a", "1.0.0", false)],
                    &skipped(deps_core::osv::SkipReason::NoConcreteVersion),
                )
            );
            assert_ne!(
                base,
                OsvScanPlan::new(
                    &[target("a", "1.0.0", true)],
                    &skipped(deps_core::osv::SkipReason::ResolvedTagNotFullVersion),
                )
            );
        }

        /// #1705: a floating `@v4` on a warm index whose tags did not move (e.g. the tags
        /// fetch failed and left the index untouched) does not rescan.
        #[tokio::test]
        async fn unchanged_warm_floating_tag_does_not_rescan() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@v4\n").await;
            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "actions/checkout",
                &[("v4", &commit), ("v4.1.0", &commit)],
                "https://api.github.com/repos/actions/checkout/commits/abc",
            );
            scan_and_commit(&state, &uri, &ecosystem).await;

            let sentinel = deps_core::test_util::vuln_key("sentinel");
            state
                .documents
                .get_mut(&uri)
                .unwrap()
                .signals
                .vulnerabilities
                .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .contains_key(&sentinel),
                "a warm index that did not change must not rescan"
            );
        }

        /// A dependency added or removed between the last scan and the predicate changes the
        /// plan's key set, so the rescan runs both times.
        #[tokio::test]
        async fn added_and_removed_dependency_trigger_rescan() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let server = mockito::Server::new_async().await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@main\n").await;
            scan_and_commit(&state, &uri, &ecosystem).await;

            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let sentinel = deps_core::test_util::vuln_key("sentinel");
            let cache_key = deps_core::test_util::vuln_key("actions/cache");
            for (content, cache_planned) in [
                (
                    "steps:\n  - uses: actions/checkout@main\n  - uses: actions/cache@main\n",
                    true,
                ),
                ("steps:\n  - uses: actions/checkout@main\n", false),
            ] {
                let mut signals = state.get_document(&uri).unwrap().signals.clone();
                signals
                    .vulnerabilities
                    .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);
                let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
                let mut edited = DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content.to_string(),
                    parse_result,
                );
                edited.signals = signals;
                state.update_document(uri.clone(), edited);

                rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

                let doc = state.get_document(&uri).unwrap();
                assert!(
                    !doc.signals.vulnerabilities.contains_key(&sentinel),
                    "a changed key set must rescan"
                );
                assert_eq!(
                    doc.signals.osv_scan_plan.0.contains_key(&cache_key),
                    cache_planned
                );
            }
        }

        /// A version-qualified key of a duplicated dependency is pruned with its name.
        #[test]
        fn retain_not_named_drops_version_qualified_keys() {
            let skipped = [
                deps_core::test_util::vuln_key("a"),
                deps_core::test_util::vuln_key("a\u{0}v:1.0"),
                deps_core::test_util::vuln_key("ab"),
            ]
            .into_iter()
            .map(|key| {
                (
                    key,
                    deps_core::osv::ScanOutcome::Skipped(
                        deps_core::osv::SkipReason::NoConcreteVersion,
                    ),
                )
            })
            .collect();
            let mut plan = OsvScanPlan::new(&[], &skipped);

            plan.retain_not_named("a");

            assert_eq!(plan.len(), 1);
            assert!(plan.0.contains_key(&deps_core::test_util::vuln_key("ab")));
        }

        async fn open_gha_document(
            osv_base_url: String,
            content: &str,
        ) -> (Arc<ServerState>, Uri, Arc<dyn Ecosystem>) {
            let mut state = ServerState::new();
            state.osv = Arc::new(OsvClient::for_test(
                Arc::new(deps_core::HttpCache::new()),
                osv_base_url,
            ));
            let state = Arc::new(state);
            let url = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let ecosystem: Arc<dyn Ecosystem> = Arc::new(GithubActionsEcosystem::new(Arc::new(
                deps_core::HttpCache::new(),
            )));
            let parse_result = ecosystem.parse_manifest(content, &url).await.unwrap();
            state.update_document(
                uri.clone(),
                DocumentState::new_from_parse_result(
                    EcosystemId::GithubActions,
                    content.to_string(),
                    parse_result,
                ),
            );
            (state, uri, ecosystem)
        }

        async fn scan_and_commit(
            state: &Arc<ServerState>,
            uri: &Uri,
            ecosystem: &Arc<dyn Ecosystem>,
        ) {
            let phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(state), Arc::clone(ecosystem), 5)
                    .await
                    .expect("a workflow step must produce a phase-A result");
            run_osv_phase_b_and_commit(
                uri,
                state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a,
            )
            .await;
        }

        fn land_tags(
            ecosystem: &Arc<dyn Ecosystem>,
            name: &str,
            tags: &[(&str, &CommitSha)],
            canonical_commit_url: &str,
        ) {
            land_tags_with_coverage(
                ecosystem,
                name,
                tags,
                canonical_commit_url,
                deps_core::pagination::ListCoverage::Complete,
            );
        }

        fn land_tags_with_coverage(
            ecosystem: &Arc<dyn Ecosystem>,
            name: &str,
            tags: &[(&str, &CommitSha)],
            canonical_commit_url: &str,
            coverage: deps_core::pagination::ListCoverage,
        ) {
            let registry = ecosystem.registry();
            registry
                .as_any()
                .downcast_ref::<GithubActionsRegistry>()
                .expect("GithubActionsEcosystem::registry() must return a GithubActionsRegistry")
                .tag_index()
                .insert(
                    PackageName::new(name),
                    Arc::new(
                        TagIndex::from_tags(tags.iter().map(|(t, c)| (*t, *c)))
                            .with_canonical_repo_name(
                                deps_core::github::CanonicalRepoName::from_commit_url(
                                    canonical_commit_url,
                                ),
                            )
                            .with_coverage(coverage),
                    ),
                );
        }

        /// #1769: a refetch that only flips the tag list from complete to truncated changes the
        /// scan plan's sibling coverage, so the rescan runs and the stale clean answer is
        /// downgraded instead of surviving.
        #[tokio::test]
        async fn coverage_only_refresh_to_truncated_rescans_and_downgrades_clean() {
            use deps_core::pagination::ListCoverage;

            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .expect_at_least(1)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) = open_gha_document(
                server.url(),
                "steps:\n  - uses: azure/setup-kubectl@v4.1.2\n",
            )
            .await;
            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            let canonical = "https://api.github.com/repos/Azure/setup-kubectl/commits/abc";
            land_tags(
                &ecosystem,
                "azure/setup-kubectl",
                &[("v4.1.2", &commit)],
                canonical,
            );

            scan_and_commit(&state, &uri, &ecosystem).await;
            let key = deps_core::test_util::vuln_key("azure/setup-kubectl");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Clean)
            );

            land_tags_with_coverage(
                &ecosystem,
                "azure/setup-kubectl",
                &[("v4.1.2", &commit)],
                canonical,
                ListCoverage::Truncated,
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals.vulnerabilities.get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::SiblingTagsUnknown
                )),
                "{:?}",
                doc.signals.vulnerabilities
            );
            assert_matches!(
                doc.signals.osv_scan_plan.0.get(&key),
                Some(PlannedQuery::Query {
                    sibling_coverage: ListCoverage::Truncated,
                    ..
                })
            );
        }

        /// #1694: a hit under the written name lands before any tags do, and is re-queried
        /// under the canonical casing once it is confirmed (clearing the provisional mark).
        #[tokio::test]
        async fn provisional_positive_hit_is_requeried_under_canonical_name_once_tags_land() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let written = server
                .mock("POST", "/v1/querybatch")
                .match_body(mockito::Matcher::Regex("azure/setup-kubectl".into()))
                .with_status(200)
                .with_body(r#"{"results":[{"vulns":[{"id":"GHSA-cxww-7g56-2vh6","modified":"2025-01-22T17:31:55Z"}]}]}"#)
                .expect(1)
                .create_async()
                .await;
            let _record = server
                .mock("GET", "/v1/vulns/GHSA-cxww-7g56-2vh6")
                .with_status(200)
                .with_body(
                    r#"{"id":"GHSA-cxww-7g56-2vh6","modified":"2025-01-22T17:31:55Z",
                    "affected":[{"package":{"name":"azure/setup-kubectl","ecosystem":"GitHub Actions"},
                    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}]}]}"#,
                )
                .create_async()
                .await;
            let canonical = server
                .mock("POST", "/v1/querybatch")
                .match_body(mockito::Matcher::Regex("Azure/setup-kubectl".into()))
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .expect(1)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) = open_gha_document(
                server.url(),
                "steps:\n  - uses: azure/setup-kubectl@v4.1.2\n",
            )
            .await;

            scan_and_commit(&state, &uri, &ecosystem).await;

            let key = deps_core::test_util::vuln_key("azure/setup-kubectl");
            {
                let doc = state.get_document(&uri).unwrap();
                assert_matches!(
                    doc.signals.vulnerabilities.get(&key),
                    Some(deps_core::osv::ScanOutcome::Vulnerable(_)),
                    "{:?}",
                    doc.signals.vulnerabilities
                );
                assert_matches!(
                    doc.signals.osv_scan_plan.0.get(&key),
                    Some(PlannedQuery::Query {
                        name: deps_core::osv::OsvQueryName::Provisional(_),
                        ..
                    })
                );
            }
            written.assert_async().await;

            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "azure/setup-kubectl",
                &[("v4.1.2", &commit)],
                "https://api.github.com/repos/Azure/setup-kubectl/commits/abc",
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            {
                let doc = state.get_document(&uri).unwrap();
                assert_matches!(
                    doc.signals.vulnerabilities.get(&key),
                    Some(deps_core::osv::ScanOutcome::Clean),
                    "{:?}",
                    doc.signals.vulnerabilities
                );
                assert_matches!(
                    doc.signals.osv_scan_plan.0.get(&key),
                    Some(PlannedQuery::Query {
                        name: deps_core::osv::OsvQueryName::Confirmed(_),
                        ..
                    })
                );
            }
            canonical.assert_async().await;
        }

        /// #1694: an empty answer under the written name is unconfirmed, and the rescan under the
        /// canonical casing can still end in a real vulnerability.
        #[tokio::test]
        async fn provisional_clean_rescan_under_canonical_name_can_end_vulnerable() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _written = server
                .mock("POST", "/v1/querybatch")
                .match_body(mockito::Matcher::Regex("azure/setup-kubectl".into()))
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .create_async()
                .await;
            let _canonical = server
                .mock("POST", "/v1/querybatch")
                .match_body(mockito::Matcher::Regex("Azure/setup-kubectl".into()))
                .with_status(200)
                .with_body(r#"{"results":[{"vulns":[{"id":"GHSA-cxww-7g56-2vh6","modified":"2025-01-22T17:31:55Z"}]}]}"#)
                .create_async()
                .await;
            let _record = server
                .mock("GET", "/v1/vulns/GHSA-cxww-7g56-2vh6")
                .with_status(200)
                .with_body(
                    r#"{"id":"GHSA-cxww-7g56-2vh6","modified":"2025-01-22T17:31:55Z",
                    "affected":[{"package":{"name":"Azure/setup-kubectl","ecosystem":"GitHub Actions"},
                    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0.0"}]}]}]}"#,
                )
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) = open_gha_document(
                server.url(),
                "steps:\n  - uses: azure/setup-kubectl@v4.1.2\n",
            )
            .await;

            scan_and_commit(&state, &uri, &ecosystem).await;

            let key = deps_core::test_util::vuln_key("azure/setup-kubectl");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::CanonicalNameUnconfirmed
                ))
            );

            let commit = CommitSha::parse(&"a".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "azure/setup-kubectl",
                &[("v4.1.2", &commit)],
                "https://api.github.com/repos/Azure/setup-kubectl/commits/abc",
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert_matches!(
                doc.signals.vulnerabilities.get(&key),
                Some(deps_core::osv::ScanOutcome::Vulnerable(_)),
                "{:?}",
                doc.signals.vulnerabilities
            );
            assert_matches!(
                doc.signals.osv_scan_plan.0.get(&key),
                Some(PlannedQuery::Query {
                    name: deps_core::osv::OsvQueryName::Confirmed(_),
                    ..
                })
            );
        }

        /// #1694 (critic N2): a dependency whose canonical name never arrives (private
        /// repository, no tags) must not re-run the pipeline on every open/edit. A sentinel
        /// entry survives only if the full-replace commit of a rescan never happened.
        #[tokio::test]
        async fn permanently_provisional_dependency_does_not_trigger_rescan() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@v4.1.2\n")
                    .await;

            scan_and_commit(&state, &uri, &ecosystem).await;

            let key = deps_core::test_util::vuln_key("actions/checkout");
            let sentinel = deps_core::test_util::vuln_key("sentinel");
            {
                let mut doc = state.documents.get_mut(&uri).unwrap();
                assert_matches!(
                    doc.signals.osv_scan_plan.0.get(&key),
                    Some(PlannedQuery::Query {
                        name: deps_core::osv::OsvQueryName::Provisional(_),
                        ..
                    })
                );
                assert_matches!(
                    doc.signals.vulnerabilities.get(&key),
                    Some(deps_core::osv::ScanOutcome::Skipped(
                        deps_core::osv::SkipReason::CanonicalNameUnconfirmed
                    ))
                );
                doc.signals
                    .vulnerabilities
                    .insert(sentinel.clone(), deps_core::osv::ScanOutcome::Clean);
            }

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .contains_key(&sentinel),
                "an unconfirmed name with no new registry data must not rescan"
            );
        }

        /// #1684: a floating `@v4` is a cold skip until the tags land, then resolves to the
        /// release its commit carries and gets a real result.
        #[tokio::test]
        async fn rescan_resolves_floating_tag_once_index_lands() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let mut server = mockito::Server::new_async().await;
            let batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{}]}"#)
                .expect(1)
                .create_async()
                .await;
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();
            let (state, uri, ecosystem) =
                open_gha_document(server.url(), "steps:\n  - uses: actions/checkout@v4\n").await;

            scan_and_commit(&state, &uri, &ecosystem).await;

            let key = deps_core::test_util::vuln_key("actions/checkout");
            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::NoConcreteVersion
                ))
            );

            let commit = CommitSha::parse(&"b".repeat(40)).unwrap();
            land_tags(
                &ecosystem,
                "actions/checkout",
                &[("v4", &commit), ("v4.2.2", &commit)],
                "https://api.github.com/repos/actions/checkout/commits/abc",
            );
            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            assert_matches!(
                state
                    .get_document(&uri)
                    .unwrap()
                    .signals
                    .vulnerabilities
                    .get(&key),
                Some(deps_core::osv::ScanOutcome::Clean)
            );
            batch.assert_async().await;
        }

        /// No-op guard: an ecosystem that doesn't override
        /// `resolved_pin_version_depends_on_registry_fetch` (the vast majority) must never
        /// pay for a rescan, even when something was genuinely skipped for an unrelated
        /// reason.
        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn rescan_is_a_no_op_for_an_ecosystem_that_does_not_opt_in() {
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let state = Arc::new(ServerState::new());
            let (client, _config) =
                crate::test_utils::test_helpers::create_test_client_and_config();

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"^1.0\"\n".to_string();
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&url)
                .expect("Cargo ecosystem not found");
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc_state);

            let phase_a =
                run_osv_scan_phase_a(uri.clone(), Arc::clone(&state), Arc::clone(&ecosystem), 5)
                    .await
                    .expect("a caret range with no lock file must still produce a phase-A result");
            run_osv_phase_b_and_commit(
                &uri,
                &state,
                ecosystem.ecosystem_id(),
                ecosystem.formatter(),
                5,
                phase_a,
            )
            .await;

            let key = deps_core::test_util::vuln_key("serde");
            let before_len = state
                .get_document(&uri)
                .unwrap()
                .signals
                .vulnerabilities
                .len();

            rescan_osv_if_tag_index_now_warm(&uri, &state, &client, &ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert_eq!(
                doc.signals.vulnerabilities.len(),
                before_len,
                "an ecosystem that never overrides resolved_pin_version_depends_on_registry_fetch \
                 must not trigger a rescan"
            );
            assert_matches!(
                doc.signals.vulnerabilities.get(&key),
                Some(deps_core::osv::ScanOutcome::Skipped(
                    deps_core::osv::SkipReason::NoConcreteVersion
                )),
                "the pre-existing skip must survive untouched: {:?}",
                doc.signals.vulnerabilities
            );
        }
    }
}

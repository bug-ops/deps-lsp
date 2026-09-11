//! OSV vulnerability scan orchestration: scan-target construction,
//! phase A/B execution, license pre-fetch, and fix-target
//! verification.

use super::state::ServerState;
use deps_core::ConcreteVersion;
use deps_core::Ecosystem;
use deps_core::EcosystemId;
use deps_core::PackageName;
use deps_core::lsp_helpers::resolve_in_use_version;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_lsp_server::ls_types::Uri;

/// Ceiling on the OSV scan timeout, independent of the configured
/// `fetch_timeout_secs`: the shared `reqwest` client behind `HttpCache`
/// already imposes its own client-wide 30s timeout (`cache.rs`), so a
/// per-phase timeout longer than that would never actually bind.
const OSV_SCAN_TIMEOUT_CEILING_SECS: u64 = 30;

/// Builds the OSV scan targets for one manifest's dependencies, applying the
/// version-selection policy from `architecture.md` §3 in order:
///
/// 0. Skip unless `formatter.source_is_public_registry_content(&dep.source())` — a patched
///    git/path fork must never be flagged with a CVE for a version it does
///    not actually contain, and neither must a genuinely different private registry's
///    dependency (only a verified crates.io mirror counts as public-registry content,
///    F1/F1b).
/// 1. Use the lock-file-resolved version if present.
/// 2. Otherwise use the declared requirement, if it is already concrete.
/// 3. Otherwise skip — querying a fabricated version is a silent false
///    negative, which is worse than not scanning at all.
///
/// **Go exception** (#228 follow-up, unified with #235's
/// [`deps_core::lsp_helpers::RequirementResolution::manifest_requirement_is_resolved_version`]):
/// step 1 is skipped entirely for a dependency whose manifest requirement is
/// itself the resolved version (a Go `require`-directive dependency), going
/// straight to step 2. Go's `go.mod` `require` line is already an exact
/// pinned version, never a range, unlike Cargo/npm where the manifest is a
/// range and the lockfile holds the pin. go.sum-derived `resolved_versions`
/// is unreliable here: go.sum is a checksum ledger that `go get`/`go build`
/// only ever append to (only `go mod tidy` prunes it), so its
/// last-occurrence-wins parse can surface a version still recorded in the
/// file but no longer selected by Go's MVS — silently querying OSV against
/// the wrong version. Routing through the formatter hook (rather than a bare
/// `ecosystem == EcosystemId::Go` check) also excludes Go's `exclude`/
/// `replace` directive pseudo-dependencies, whose `version_requirement()` is
/// not an in-use version.
///
/// Every dependency that does **not** become a [`deps_core::osv::ScanTarget`]
/// gets an explicit [`deps_core::osv::ScanOutcome::Skipped`] entry in the
/// returned map instead of silently vanishing (critique C1) — absence from
/// [`deps_core::osv::VulnerabilityMap`] must never happen for an input this
/// function considered.
///
/// Each dependency's map/target key comes from
/// [`deps_core::osv::vulnerability_keys`] rather than a bare
/// `formatter.normalize_package_name(dep.name())` (#394 S2): when two
/// occurrences of one name resolve to different in-use versions (or mix a
/// registry source with a git/path fork), their keys are disambiguated so
/// one occurrence's OSV result never overwrites another's in the shared
/// [`deps_core::osv::VulnerabilityMap`]. Occurrences that share both a name
/// and an identical in-use version keep the plain key and are scanned once —
/// a dedup, not a gap, since the OSV result would be identical either way.
fn build_scan_targets(
    parse_result: &dyn deps_core::ParseResult,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: &HashMap<PackageName, Vec<ConcreteVersion>>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    ecosystem: EcosystemId,
) -> (
    Vec<deps_core::osv::ScanTarget>,
    deps_core::osv::VulnerabilityMap,
) {
    use deps_core::osv::{ScanOutcome, SkipReason};

    let mut targets = Vec::new();
    let mut skipped = deps_core::osv::VulnerabilityMap::new();
    let keys = deps_core::osv::vulnerability_keys(
        parse_result,
        resolved_versions,
        Some(resolved_version_candidates),
        formatter,
        ecosystem,
    );

    for dep in parse_result.dependencies() {
        let normalized_name = formatter.normalize_package_name(dep.name());
        let key = keys
            .get(&dep.name_range())
            .cloned()
            .unwrap_or_else(|| normalized_name.clone());

        if !formatter.source_is_public_registry_content(&dep.source()) {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NonRegistrySource));
            continue;
        }

        // lockfile holds the pin) — so for a Go `require` dependency the
        // manifest itself is the authoritative version, not go.sum. go.sum is
        // a checksum ledger that `go get`/`go build` only ever append to
        // (only `go mod tidy` prunes it), so its last-occurrence-wins parse
        // can yield a stale version still recorded in the file but no longer
        // selected by Go's MVS, silently mismatching whatever's actually in
        // use. Skipping the lockfile lookup avoids feeding that stale version
        // to OSV (excludes/replaces fall through to the lockfile lookup below
        // like any other ecosystem, since their `version_requirement()` is
        // not an in-use version — see `manifest_requirement_is_resolved_version`).
        let version = resolve_in_use_version(
            dep,
            &normalized_name,
            resolved_versions,
            Some(resolved_version_candidates),
            formatter,
            ecosystem,
        );

        let Some(version) = version else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::NoConcreteVersion));
            continue;
        };

        let Some(osv_name) = formatter.osv_package_name(dep) else {
            skipped.insert(key, ScanOutcome::Skipped(SkipReason::UnmappableName));
            continue;
        };

        targets.push(deps_core::osv::ScanTarget::new(
            key,
            osv_name,
            formatter.osv_version(&version),
            version,
        ));
    }

    (targets, skipped)
}

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

/// Phase A output, carried from the concurrently-spawned scan task into
/// phase B (run later, after the registry fetch resolves — critique S1).
pub(crate) struct OsvScanResult {
    /// Document content at the moment the scan started, to guard the
    /// eventual write against a cross-generation stale commit (critique M4).
    content_snapshot: String,
    vulnerabilities: deps_core::osv::VulnerabilityMap,
    /// `key -> osv_name`, needed to build phase B candidates.
    osv_name_by_key: HashMap<String, String>,
    /// `key -> dep.name()` (raw, pre-normalization), the fallback
    /// `cached_versions` lookup needs since that map is keyed by the raw
    /// name while `key` is normalized (critique S2) — they differ for
    /// Composer/Swift/NuGet-style ecosystems.
    raw_name_by_key: HashMap<String, String>,
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

    let (content_snapshot, targets, mut vulnerabilities, raw_name_by_key) = {
        let doc = state.get_document(&uri)?;
        let parse_result = doc.parse_result()?;
        let (targets, skipped) = build_scan_targets(
            parse_result,
            &doc.resolved_versions,
            &doc.resolved_version_candidates,
            ecosystem.formatter(),
            ecosystem_id,
        );
        // Keyed the same way `targets`/`skipped` are (#394 S2: possibly
        // version-qualified, not just the plain normalized name) so phase B's
        // `raw_name_by_key.get(key)` fallback below still finds this
        // occurrence's raw name when its key was disambiguated.
        let vuln_keys = deps_core::osv::vulnerability_keys(
            parse_result,
            &doc.resolved_versions,
            Some(&doc.resolved_version_candidates),
            ecosystem.formatter(),
            ecosystem_id,
        );
        let raw_name_by_key: HashMap<String, String> = parse_result
            .dependencies()
            .into_iter()
            .map(|d| {
                let key = vuln_keys
                    .get(&d.name_range())
                    .cloned()
                    .unwrap_or_else(|| ecosystem.formatter().normalize_package_name(d.name()));
                (key, d.name().to_string())
            })
            .collect();
        (doc.content.clone(), targets, skipped, raw_name_by_key)
    };

    if targets.is_empty() && vulnerabilities.is_empty() {
        return None;
    }

    let osv_name_by_key: HashMap<String, String> = targets
        .iter()
        .map(|t| (t.key.clone(), t.osv_name.clone()))
        .collect();

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
        vulnerabilities,
        osv_name_by_key,
        raw_name_by_key,
    })
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
/// The commit at the end is staleness-guarded (`doc.content == content_snapshot`,
/// mirroring [`run_osv_phase_b_and_commit`]'s identical guard) and merges rather than
/// replaces (round 3 finding #1/#2): two overlapping edits can spawn two overlapping
/// pre-fetches, and without the guard the older one finishing last could silently
/// overwrite the newer one's results with stale data; without a merge, a transient
/// per-dependency fetch failure this round (already filtered out below, before this
/// point) would drop that dependency's previously-cached, still-valid license instead
/// of just failing to refresh it. `DocumentState::merge_licenses`'s own additive
/// contract already provides exactly this — a genuinely *removed* dependency's stale
/// entry is reclaimed separately, by the manifest-diff pruning loop in
/// `commit_parsed_document`, not by this function replacing the whole map.
///
/// **What version each source actually reflects is per-ecosystem, not uniform**
/// (critic S1 — corrects this doc's previous blanket "only ever targets the
/// resolved/in-use version" claim): Gradle's POM fetch and Deno's JSR API are
/// genuinely version-specific (fetched at the dependency's resolved/in-use version, the
/// `version` passed into [`Ecosystem::fetch_license`]). Dart's `get_license` calls
/// pub.dev's per-*package* `/score` endpoint, which carries no version parameter at
/// all — it reflects pana's detection on whatever pub.dev last scored, not necessarily
/// the resolved version. Swift's `get_license` calls GitHub's `GET /repos/{owner}/{repo}`,
/// which reflects the repository's *default branch*, not the resolved version's tag.
/// `resolve_in_use_version` below is still required as a *gate* for all four (no version
/// resolved means nothing to look up), but for Dart/Swift it does not pin which
/// version's license is actually returned.
///
/// Filters on [`deps_core::lsp_helpers::SourcePolicy::source_is_public_registry_content`]
/// (critic M3/S6), the same stricter filter [`build_scan_targets`]'s OSV path already
/// uses, not the looser [`deps_core::lsp_helpers::SourcePolicy::can_resolve_source`]: a
/// patched git/path fork is resolvable but must never have its license misattributed to
/// the upstream registry package it forked from — the identical "is this really the
/// same package" problem OSV's stricter filter exists to solve.
///
/// No-op (returns immediately) for every ecosystem whose
/// <code>ecosystem.[license_source](deps_core::Ecosystem::license_source)().[requires_dedicated_fetch](deps_core::LicenseSource::requires_dedicated_fetch)()</code>
/// is `false` (issue #697) — every ecosystem except the four above.
pub(crate) async fn run_license_prefetch(
    uri: Uri,
    state: Arc<ServerState>,
    ecosystem: Arc<dyn Ecosystem>,
    fetch_timeout_secs: u64,
) {
    let ecosystem_id = ecosystem.ecosystem_id();
    if !ecosystem.license_source().requires_dedicated_fetch() {
        return;
    }

    let (content_snapshot, targets): (String, Vec<(PackageName, String)>) = {
        let Some(doc) = state.get_document(&uri) else {
            return;
        };
        let Some(parse_result) = doc.parse_result() else {
            return;
        };
        let formatter = ecosystem.formatter();
        let targets = parse_result
            .dependencies()
            .into_iter()
            .filter(|d| formatter.source_is_public_registry_content(&d.source()))
            .filter_map(|d| {
                let normalized = formatter.normalize_package_name(d.name());
                let version = resolve_in_use_version(
                    d,
                    normalized.as_str(),
                    &doc.resolved_versions,
                    Some(&doc.resolved_version_candidates),
                    formatter,
                    ecosystem_id,
                )?;
                Some((d.name().clone(), version))
            })
            .collect();
        (doc.content.clone(), targets)
    };

    if targets.is_empty() {
        return;
    }

    use futures::stream::{self, StreamExt};

    let timeout_duration = Duration::from_secs(fetch_timeout_secs.clamp(
        LICENSE_PREFETCH_TIMEOUT_FLOOR_SECS,
        LICENSE_PREFETCH_TIMEOUT_CEILING_SECS,
    ));
    let ecosystem = &ecosystem;
    let licenses: HashMap<PackageName, Vec<String>> = stream::iter(targets)
        .map(|(name, version)| async move {
            let found = tokio::time::timeout(
                timeout_duration,
                ecosystem.fetch_license(name.as_str(), &version),
            )
            .await
            .unwrap_or_else(|_| {
                tracing::debug!(package = %name, "tier-3 license fetch timed out");
                Vec::new()
            });
            (name, found)
        })
        .buffer_unordered(LICENSE_PREFETCH_CONCURRENCY)
        .filter(|(_, found)| std::future::ready(!found.is_empty()))
        .collect()
        .await;

    if let Some(mut doc) = state.documents.get_mut(&uri) {
        if doc.content == content_snapshot {
            doc.merge_licenses(licenses);
        } else {
            tracing::debug!(
                "dropping stale tier-3 license pre-fetch result: document content changed mid-fetch"
            );
        }
    }
}

/// Bounds how many concurrent per-dependency license fetches [`run_license_prefetch`]
/// issues at once — same rationale as `fetch_latest_versions_parallel`'s
/// `max_concurrent`, scaled down: tier-3 documents rarely carry more than a handful of
/// dependencies (Dart/Swift/Gradle/Deno are all comparatively small ecosystems in this
/// project's usage), and this pre-fetch is a background nice-to-have, not on the hover
/// critical path, so there is no latency pressure to fan out aggressively.
const LICENSE_PREFETCH_CONCURRENCY: usize = 8;

/// Ceiling on the per-dependency tier-3 license fetch timeout, independent of the
/// configured `fetch_timeout_secs` (critic S4/M2: the direct `Ecosystem::fetch_license`
/// call in [`run_license_prefetch`] previously had no bound at all, unlike every other
/// registry call in this codebase, e.g. `fetch_and_classify_package`'s
/// `tokio::time::timeout(timeout, ...)`). Mirrors
/// [`OSV_SCAN_TIMEOUT_CEILING_SECS`]'s rationale: the shared `reqwest` client behind
/// `HttpCache` already imposes its own client-wide 30s timeout, so a per-call timeout
/// longer than that would never actually bind.
const LICENSE_PREFETCH_TIMEOUT_CEILING_SECS: u64 = 30;

/// Floor on the per-dependency tier-3 license fetch timeout, independent of the
/// configured `fetch_timeout_secs` (issue #692 critic M2). `fetch_timeout_secs` is
/// user-configurable down to a minimum of 1s (see `config.rs`'s validation), but
/// `deps_gradle::license::fetch_license_from` may now perform up to
/// `deps_gradle::license::MAX_POM_FETCHES` **sequential** HTTPS round trips inside the
/// single `tokio::time::timeout` this budget bounds, where it previously performed one
/// — a low `fetch_timeout_secs` would otherwise silently starve exactly the
/// parent-chained artifacts (e.g. Guava) issue #692 exists to resolve. This pre-fetch is
/// a background nice-to-have, never on the hover critical path (see
/// [`run_license_prefetch`]'s doc), so raising its effective minimum costs nothing but a
/// few extra seconds before this best-effort signal gives up.
const LICENSE_PREFETCH_TIMEOUT_FLOOR_SECS: u64 = 10;

/// Phase B: for every dependency phase A flagged [`deps_core::osv::ScanOutcome::Vulnerable`],
/// checks whether the version currently recommended (the registry's latest,
/// now that the registry fetch has resolved — critique S1) is itself
/// affected (B.1), then independently verifies each dependency's recommended
/// *fix target* F (B.2, #462 — see [`run_osv_fix_target_verification`]),
/// before committing the result into `DocumentState.vulnerabilities`.
///
/// Must be called only *after* the registry fetch has updated
/// `doc.cached_versions`: calling it concurrently with that fetch (as the
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
/// this whole result, `upgrade_status` included. Sharing one deadline caps
/// the total at the original ceiling, same as before this fix existed.
pub(crate) async fn run_osv_phase_b_and_commit(
    uri: &Uri,
    state: &Arc<ServerState>,
    ecosystem_id: EcosystemId,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    fetch_timeout_secs: u64,
    mut result: OsvScanResult,
) {
    let vulnerable_keys: Vec<String> = result
        .vulnerabilities
        .iter()
        .filter(|(_, outcome)| matches!(outcome, deps_core::osv::ScanOutcome::Vulnerable(_)))
        .map(|(key, _)| key.clone())
        .collect();

    if !vulnerable_keys.is_empty() {
        let phase_b_deadline = Instant::now()
            + Duration::from_secs(fetch_timeout_secs.min(OSV_SCAN_TIMEOUT_CEILING_SECS));

        // B.1 (US-002, unchanged by #462): checks the registry's "latest" candidate.
        // `latest_native_by_key` is kept for B.2 below, which needs the same native
        // "latest" string to detect a fix target F that coincides with latest (FR-002)
        // without re-deriving it from `doc.cached_versions` a second time.
        let latest_native_by_key: HashMap<String, String> = {
            let Some(doc) = state.get_document(uri) else {
                return;
            };
            vulnerable_keys
                .iter()
                .filter_map(|key| {
                    let latest = doc
                        .cached_versions
                        .get(key.as_str())
                        .or_else(|| {
                            let raw = result.raw_name_by_key.get(key)?;
                            doc.cached_versions.get(raw.as_str())
                        })?
                        .latest
                        .clone();
                    Some((key.clone(), latest.to_string()))
                })
                .collect()
        };

        let candidates: Vec<deps_core::osv::ScanTarget> = vulnerable_keys
            .iter()
            .filter_map(|key| {
                let osv_name = result.osv_name_by_key.get(key)?.clone();
                let latest_native = latest_native_by_key.get(key)?.clone();
                Some(deps_core::osv::ScanTarget::new(
                    key.clone(),
                    osv_name,
                    formatter.osv_version(&latest_native),
                    latest_native,
                ))
            })
            .collect();

        if !candidates.is_empty() {
            let timeout_duration = phase_b_deadline.saturating_duration_since(Instant::now());
            let statuses = state
                .osv
                .check_candidates(ecosystem_id, &candidates, timeout_duration)
                .await;
            for (key, status) in statuses {
                if let Some(deps_core::osv::ScanOutcome::Vulnerable(dv)) =
                    result.vulnerabilities.get_mut(&key)
                {
                    dv.upgrade_status = status;
                }
            }
        }

        run_osv_fix_target_verification(
            &mut result.vulnerabilities,
            &vulnerable_keys,
            &result.osv_name_by_key,
            &latest_native_by_key,
            ecosystem_id,
            formatter,
            &state.osv,
            phase_b_deadline,
        )
        .await;
    }

    if let Some(mut doc) = state.documents.get_mut(uri) {
        if doc.content == result.content_snapshot {
            doc.update_vulnerabilities(result.vulnerabilities);
        } else {
            tracing::debug!("dropping stale OSV scan result: document content changed mid-scan");
        }
    }
}

/// Synthetic [`deps_core::osv::ScanTarget::key`] suffix marking a fix-target (F) live-check
/// candidate as distinct from the same dependency's "latest" candidate (B.1) within the
/// shared `VulnerabilityMap` key space — see [`run_osv_fix_target_verification`].
const FIX_TARGET_KEY_SUFFIX: &str = "\u{0}fix";

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
/// 1. F equals the already-checked "latest" candidate (FR-002) — reuse `upgrade_status`,
///    no extra call.
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
    vulnerable_keys: &[String],
    osv_name_by_key: &HashMap<String, String>,
    latest_native_by_key: &HashMap<String, String>,
    ecosystem_id: EcosystemId,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    osv: &deps_core::osv::OsvClient,
    phase_b_deadline: Instant,
) {
    use deps_core::osv::ScanOutcome;

    let (resolved, live_check_candidates) = collect_fix_target_resolutions(
        vulnerabilities,
        vulnerable_keys,
        osv_name_by_key,
        latest_native_by_key,
        formatter,
    );

    for (key, status) in resolved {
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(key.as_str()) {
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

    apply_live_fix_target_statuses(vulnerabilities, statuses);
}

/// Outcome of [`resolve_fix_target`] for one vulnerable dependency.
#[derive(Debug, PartialEq, Eq)]
enum FixTargetResolution {
    /// No fix recommended, F failed [`deps_core::lsp_helpers::is_safe_version_string`], or no
    /// `osv_name` is on record for this key — nothing to verify or record; `fix_target_status`
    /// stays untouched (left at `NotChecked`).
    Skip,
    /// F's status was resolved without a network call by reusing the already-checked
    /// "latest" candidate's result (FR-002, F == latest).
    Resolved(deps_core::osv::UpgradeStatus),
    /// F differs from latest and needs a live [`deps_core::osv::OsvClient::check_candidates`]
    /// check — carries the [`deps_core::osv::ScanTarget`] to batch into the caller's single
    /// combined call (NFR-001), keyed with [`FIX_TARGET_KEY_SUFFIX`] so its result cannot
    /// collide with the same dependency's "latest" candidate in the same `VulnerabilityMap`
    /// key space.
    NeedsLiveCheck(deps_core::osv::ScanTarget),
}

/// Pure (network-free) decision logic for [`run_osv_fix_target_verification`]'s per-dependency
/// resolution order — see that function's doc for the two cases and their rationale. Split
/// out so each case is unit-testable without an `OsvClient`/network dependency.
fn resolve_fix_target(
    dv: &deps_core::osv::DependencyVulnerabilities,
    key: &str,
    latest_native_by_key: &HashMap<String, String>,
    osv_name_by_key: &HashMap<String, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> FixTargetResolution {
    use deps_core::lsp_helpers::is_safe_version_string;
    use deps_core::osv::ScanTarget;

    let Some(fix) = dv.recommended_fix() else {
        return FixTargetResolution::Skip;
    };
    let version_native = formatter.osv_version_to_native(&fix.version);
    if !is_safe_version_string(&version_native) {
        tracing::debug!(
            key,
            version = %fix.version,
            "OSV #462: fix-target version failed validation, skipping verification"
        );
        return FixTargetResolution::Skip;
    }

    if latest_native_by_key.get(key) == Some(&version_native) {
        return FixTargetResolution::Resolved(dv.upgrade_status.clone());
    }

    let Some(osv_name) = osv_name_by_key.get(key).cloned() else {
        tracing::debug!(
            key,
            "OSV #462: no osv_name on record for fix-target verification, skipping"
        );
        return FixTargetResolution::Skip;
    };
    FixTargetResolution::NeedsLiveCheck(ScanTarget::new(
        format!("{key}{FIX_TARGET_KEY_SUFFIX}"),
        osv_name,
        fix.version,
        version_native,
    ))
}

/// Pure aggregation step of [`run_osv_fix_target_verification`]: resolves every vulnerable
/// dependency's fix target via [`resolve_fix_target`], splitting immediately-resolvable
/// results (`resolved`) from the ones that need a live check (`live_check_candidates`) — the
/// latter collected into one `Vec` across *every* dependency before the caller's single
/// `check_candidates` call, so multiple dependencies needing a live check always batch into
/// one network round-trip rather than one per dependency (NFR-001). Split out from the async
/// orchestrator specifically so this batching/aggregation behavior is unit-testable without
/// an `OsvClient`.
fn collect_fix_target_resolutions(
    vulnerabilities: &deps_core::osv::VulnerabilityMap,
    vulnerable_keys: &[String],
    osv_name_by_key: &HashMap<String, String>,
    latest_native_by_key: &HashMap<String, String>,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
) -> (
    Vec<(String, deps_core::osv::UpgradeStatus)>,
    Vec<deps_core::osv::ScanTarget>,
) {
    use deps_core::osv::ScanOutcome;

    let mut resolved = Vec::new();
    let mut live_check_candidates = Vec::new();

    for key in vulnerable_keys {
        let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get(key.as_str()) else {
            continue;
        };
        match resolve_fix_target(dv, key, latest_native_by_key, osv_name_by_key, formatter) {
            FixTargetResolution::Skip => {}
            FixTargetResolution::Resolved(status) => resolved.push((key.clone(), status)),
            FixTargetResolution::NeedsLiveCheck(target) => live_check_candidates.push(target),
        }
    }

    (resolved, live_check_candidates)
}

/// Applies a live [`deps_core::osv::OsvClient::check_candidates`] result keyed with
/// [`FIX_TARGET_KEY_SUFFIX`] back onto the matching dependency's `fix_target_status`.
///
/// A key absent from `statuses` (timeout, OSV outage, or a chunk `check_candidates` itself
/// dropped) simply leaves that dependency's `fix_target_status` untouched — still
/// `NotChecked` if it was never set, which is exactly the fail-closed degradation
/// FR-004/NFR-002 call for (never a panic, never a fabricated "verified" status).
fn apply_live_fix_target_statuses(
    vulnerabilities: &mut deps_core::osv::VulnerabilityMap,
    statuses: HashMap<String, deps_core::osv::UpgradeStatus>,
) {
    use deps_core::osv::ScanOutcome;

    for (synthetic_key, status) in statuses {
        let Some(key) = synthetic_key.strip_suffix(FIX_TARGET_KEY_SUFFIX) else {
            continue;
        };
        if let Some(ScanOutcome::Vulnerable(dv)) = vulnerabilities.get_mut(key) {
            dv.fix_target_status = status;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolved::collect_in_use_versions;
    use super::super::state::DocumentState;
    use super::*;
    use deps_core::VersionReq;
    use std::assert_matches;

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

            for id_str in state.ecosystem_registry.ecosystem_ids() {
                let id: EcosystemId = id_str.parse().expect("valid ecosystem id");
                let eco = state
                    .ecosystem_registry
                    .get(id_str)
                    .unwrap_or_else(|| panic!("{id_str} ecosystem not found"));

                assert_eq!(
                    eco.license_source(),
                    expected_license_source(id),
                    "{id_str}: license_source() mismatch"
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
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
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
        /// `DocumentState.licenses`.
        #[cfg(feature = "dart")]
        #[tokio::test]
        #[ignore = "hits the real pub.dev API"]
        async fn run_license_prefetch_live_dart_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
            let content = "dependencies:\n  http: ^1.0.0\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
                .expect("Dart ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Dart,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("http"), "1.2.0".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses.contains_key(&PackageName::new("http")),
                "expected a pre-fetched license for 'http', got: {:?}",
                doc.licenses
            );
        }

        /// Live end-to-end, mirroring the Dart test above: a real `Package.swift`
        /// dependency, routed through the real `EcosystemRegistry`, fetching
        /// `apple/swift-nio`'s license from the real GitHub repository API.
        ///
        /// Unauthenticated GitHub API calls are capped at 60 req/h — this can fail
        /// with an empty result under an exhausted rate limit (no `GITHUB_TOKEN` set)
        /// rather than a genuine regression; that is the same graceful-degradation
        /// path `SwiftRegistry::get_license` takes for any fetch failure (NFR-003).
        #[cfg(feature = "swift")]
        #[tokio::test]
        #[ignore = "hits the real GitHub API"]
        async fn run_license_prefetch_live_swift_populates_document_licenses() {
            let state = Arc::new(ServerState::new());
            let uri = deps_core::test_util::test_uri("/test/Package.swift");
            let content = r#".package(url: "https://github.com/apple/swift-nio.git", .upToNextMajor(from: "2.0.0"))"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
                .expect("Swift ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Swift,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("apple/swift-nio"), "2.65.0".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses
                    .contains_key(&PackageName::new("apple/swift-nio")),
                "expected a pre-fetched license for 'apple/swift-nio', got: {:?}",
                doc.licenses
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
            let uri = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let content =
                "dependencies {\n    implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
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
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses
                    .contains_key(&PackageName::new("com.squareup.okhttp3:okhttp")),
                "expected a pre-fetched license for 'com.squareup.okhttp3:okhttp', got: {:?}",
                doc.licenses
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
            let uri = deps_core::test_util::test_uri("/test/build.gradle.kts");
            let content =
                "dependencies {\n    implementation(\"com.google.guava:guava:32.0.1-jre\")\n}\n";

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
                .expect("Gradle ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
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
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            let license = doc
                .licenses
                .get(&PackageName::new("com.google.guava:guava"));
            assert!(
                license.is_some_and(|l| !l.is_empty()),
                "expected a pre-fetched license for 'com.google.guava:guava' via its \
                 parent POM, got: {:?}",
                doc.licenses
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
            let uri = deps_core::test_util::test_uri("/test/deno.json");
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0"}}"#;

            let ecosystem = state
                .ecosystem_registry
                .for_uri(&uri)
                .expect("Deno ecosystem not found");
            let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Deno,
                content.to_string(),
                parse_result,
            );
            doc_state.update_resolved_versions(
                HashMap::from([(PackageName::new("jsr:@std/fs"), "1.0.24".into())]),
                HashMap::new(),
            );
            state.update_document(uri.clone(), doc_state);

            run_license_prefetch(uri.clone(), Arc::clone(&state), ecosystem, 5).await;

            let doc = state.get_document(&uri).unwrap();
            assert!(
                doc.licenses.contains_key(&PackageName::new("jsr:@std/fs")),
                "expected a pre-fetched license for 'jsr:@std/fs', got: {:?}",
                doc.licenses
            );
        }
    }

    mod osv_scan_target_tests {
        use super::*;
        use deps_core::Dependency;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy,
        };
        use deps_core::parser::DependencySource;
        use std::any::Any;
        use tower_lsp_server::ls_types::{Position, Range};

        struct MockFormatter;
        impl PackageNaming for MockFormatter {}

        impl PackageRendering for MockFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockFormatter {}

        impl DiagnosticMessages for MockFormatter {}

        impl DiagnosticPolicy for MockFormatter {}

        impl SourcePolicy for MockFormatter {}

        impl OsvNaming for MockFormatter {}

        struct MockDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            source: DependencySource,
        }

        impl Dependency for MockDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                // Distinct per instance (not a fixed constant): `vulnerability_keys`
                // (#394 S2) keys a `HashMap<Range, String>` by `name_range()`,
                // requiring it to uniquely identify each occurrence the way a
                // real parser's source-derived range always does. A hardcoded
                // range here would make every `MockDep` in a test collide on
                // one map entry.
                let addr = std::ptr::from_ref(self) as u32;
                Range::new(Position::new(0, addr), Position::new(0, addr + 1))
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                None
            }
            fn source(&self) -> DependencySource {
                self.source.clone()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            deps: Vec<MockDep>,
        }

        impl deps_core::ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                static URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
                URI.get_or_init(|| deps_core::test_util::test_uri("/test/Cargo.toml"))
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        use deps_core::osv::{ScanOutcome, SkipReason};

        // `is_concrete_version`/`concrete_pin_version` unit tests moved to
        // `deps-core`'s `lsp_helpers::in_use_version` module alongside the
        // functions themselves (#394).

        #[test]
        fn build_scan_targets_step0_skips_non_registry_source_even_with_lockfile_version() {
            // A git/path/patched fork must never be flagged with a CVE for a
            // version it does not actually contain, even when its lockfile
            // entry carries a plausible-looking version (critique C2).
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("0.1.43")),
                    source: DependencySource::Git {
                        url: "https://github.com/example/time".to_string(),
                        rev: None,
                    },
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("time"), "0.1.43".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("time"),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            );
        }

        #[test]
        fn build_scan_targets_step1_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert!(skipped.is_empty());
        }

        /// Formatter stub mirroring `GoFormatter`'s override: every
        /// dependency's manifest requirement is itself the resolved version
        /// (#235's `manifest_requirement_is_resolved_version` unification).
        struct MockGoFormatter;
        impl PackageNaming for MockGoFormatter {}

        impl PackageRendering for MockGoFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pkg.go.dev/{name}")
            }
        }

        impl RequirementResolution for MockGoFormatter {
            fn manifest_requirement_is_resolved_version(&self, _dep: &dyn Dependency) -> bool {
                true
            }
        }

        impl DiagnosticMessages for MockGoFormatter {}

        impl DiagnosticPolicy for MockGoFormatter {}

        impl SourcePolicy for MockGoFormatter {}

        impl OsvNaming for MockGoFormatter {}

        struct MockVPrefixFormatter;
        impl PackageNaming for MockVPrefixFormatter {}

        impl PackageRendering for MockVPrefixFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockVPrefixFormatter {}

        impl DiagnosticMessages for MockVPrefixFormatter {}

        impl DiagnosticPolicy for MockVPrefixFormatter {}

        impl SourcePolicy for MockVPrefixFormatter {}

        impl OsvNaming for MockVPrefixFormatter {
            fn osv_version(&self, version: &str) -> String {
                version.strip_prefix('v').unwrap_or(version).to_string()
            }
        }

        #[test]
        fn build_scan_targets_normalizes_version_via_formatter_osv_version_hook() {
            // Go module versions carry a mandatory "v" prefix that OSV's
            // SEMVER range matching forbids (#228) — build_scan_targets must
            // route the resolved version through the formatter hook rather
            // than sending the native spelling on the wire.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/gin-gonic/gin"),
                    version_req: Some(VersionReq::new("v1.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(
                PackageName::new("github.com/gin-gonic/gin"),
                "v1.9.0".into(),
            );

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockVPrefixFormatter,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.9.0");
            // display_version keeps the ecosystem-native "v" spelling (S1
            // regression guard) — only the wire-format `version` is stripped.
            assert_eq!(targets[0].display_version, "v1.9.0");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_leaves_version_unaffected_for_default_identity_formatter() {
            // Regression guard: ecosystems that do not override osv_version
            // must keep sending the native spelling verbatim (no regression
            // from introducing the hook).
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.195");
            assert_eq!(targets[0].display_version, "1.0.195");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_go_ignores_stale_lockfile_version_uses_go_mod_requirement() {
            // go.sum is a checksum ledger that `go get`/`go build` only ever
            // append to — a stale, no-longer-selected higher version can
            // remain recorded there after a downgrade (only `go mod tidy`
            // prunes it), and since go.sum is written sorted ascending by
            // semver, that stale entry always sorts last and wins
            // last-occurrence-wins parsing. Unlike Cargo/npm, go.mod's
            // `require` line is already an exact pinned version, so for Go
            // the manifest itself — not the lockfile-derived
            // `resolved_versions` — must be authoritative for OSV scanning.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("github.com/pkg/errors"),
                    version_req: Some(VersionReq::new("v0.8.1")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            // Stale entry: go.sum still records v0.9.1 from before a
            // downgrade back to v0.8.1 that only `go get` (not `go mod
            // tidy`) performed.
            resolved.insert(PackageName::new("github.com/pkg/errors"), "v0.9.1".into());

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockGoFormatter,
                EcosystemId::Go,
            );
            assert_eq!(targets.len(), 1);
            // `.version` (the wire-format value) goes through `formatter.osv_version`,
            // whose shared default (`deps-core`) strips a leading `v`/`V` — `MockGoFormatter`
            // doesn't override it, unlike the real `GoFormatter`. `.display_version` is the
            // raw, untransformed value this test is actually about (manifest vs. lockfile
            // authority), so it keeps the native "v" spelling.
            assert_eq!(targets[0].version, "0.8.1");
            assert_eq!(targets[0].display_version, "v0.8.1");
            assert!(skipped.is_empty());
        }

        /// #667 follow-up (impl-critic): before this reclassification, a Deno `jsr:`
        /// dependency's bare requirement always failed the version gate under
        /// `AlwaysRange` (`resolve_in_use_version` always `None`), so `DenoFormatter::
        /// osv_package_name`'s `_ => None` arm for `jsr:` never actually ran in a live
        /// scan. Now that Deno is `ConcreteIfFullVersion`, a bare-full-version-pinned
        /// `jsr:` dependency passes the version gate and correctness rests entirely on
        /// that match arm — this exercises it end-to-end through the real
        /// `DenoFormatter`, not just `osv_package_name`'s own unit test in isolation.
        #[cfg(feature = "deno")]
        #[test]
        fn build_scan_targets_deno_bare_pinned_jsr_dep_is_unmappable_name_skip() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("jsr:@std/fs"),
                    version_req: Some(VersionReq::new("1.0.0")),
                    source: DependencySource::Registry,
                }],
            };

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &HashMap::new(),
                &HashMap::new(),
                &deps_deno::DenoFormatter,
                EcosystemId::Deno,
            );

            assert!(targets.is_empty(), "jsr: dep must never reach an OSV query");
            assert_eq!(skipped.len(), 1);
            // Key is the full scheme-qualified name: `DenoFormatter` doesn't override
            // `normalize_package_name`, unlike `osv_package_name` (which strips the
            // scheme only for `npm:` and returns `None` for everything else).
            assert_matches!(
                skipped.get("jsr:@std/fs"),
                Some(ScanOutcome::Skipped(SkipReason::UnmappableName))
            );
        }

        #[test]
        fn build_scan_targets_step2_uses_concrete_requirement_verbatim() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Maven,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "2.14.1");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step2_strips_pin_marker_for_operator_prefixed_requirements() {
            // impl-critic M2: the `concrete_pin_version` fix (originally
            // scoped to the PyPI `==` case) also strips Cargo's `=` and
            // NuGet's `[..]` exact-pin markers, since both callers share the
            // same helper — a strict improvement over the old verbatim
            // `"=1.2.3"`/`"[1.0.0]"` OSV scan targets, which would never
            // have matched a real advisory's affected-version range anyway.
            let cargo_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("=1.2.3")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &cargo_result,
                &HashMap::new(),
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.2.3");
            assert!(skipped.is_empty());

            let nuget_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("Newtonsoft.Json"),
                    version_req: Some(VersionReq::new("[1.0.0]")),
                    source: DependencySource::Registry,
                }],
            };
            let (targets, skipped) = build_scan_targets(
                &nuget_result,
                &HashMap::new(),
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::NuGet,
            );
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].version, "1.0.0");
            assert!(skipped.is_empty());
        }

        #[test]
        fn build_scan_targets_step3_skips_caret_range_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("serde"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
        }

        #[test]
        fn build_scan_targets_step3_skips_wildcard_with_no_lockfile_entry() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("*")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(targets.is_empty());
            assert_matches!(
                skipped.get("serde"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
        }

        #[test]
        fn build_scan_targets_all_non_registry_sources_are_skipped() {
            let sources = vec![
                DependencySource::Path {
                    path: "../local".to_string(),
                },
                DependencySource::Url {
                    url: "https://example.com/pkg.tgz".to_string(),
                },
                DependencySource::Sdk {
                    sdk: "flutter".to_string(),
                },
                DependencySource::Workspace,
                DependencySource::CustomRegistry {
                    url: "https://private.example.com".to_string(),
                },
            ];

            for source in sources {
                let parse_result = MockParseResult {
                    deps: vec![MockDep {
                        name: PackageName::new("pkg"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: source.clone(),
                    }],
                };
                let mut resolved = HashMap::new();
                resolved.insert(PackageName::new("pkg"), "1.0.0".into());

                let (targets, skipped) = build_scan_targets(
                    &parse_result,
                    &resolved,
                    &HashMap::new(),
                    &MockFormatter,
                    EcosystemId::Cargo,
                );
                assert!(targets.is_empty(), "{source:?} must be skipped (step 0)");
                assert_matches!(
                    skipped.get("pkg"),
                    Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
                );
            }
        }

        #[test]
        fn build_scan_targets_never_drops_a_dependency_silently() {
            // Critique C1: every dependency considered must end up in either
            // `targets` or `skipped` — never absent from both.
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("concrete"),
                        version_req: Some(VersionReq::new("2.14.1")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("range-only"),
                        version_req: Some(VersionReq::new("^1.0")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("git-dep"),
                        version_req: Some(VersionReq::new("1.0.0")),
                        source: DependencySource::Git {
                            url: "https://example.com/git-dep".to_string(),
                            rev: None,
                        },
                    },
                ],
            };
            let resolved = HashMap::new();

            let (targets, skipped) = build_scan_targets(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Maven,
            );

            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].key, "concrete");
            assert_eq!(skipped.len(), 2);
            assert_matches!(
                skipped.get("range-only"),
                Some(ScanOutcome::Skipped(SkipReason::NoConcreteVersion))
            );
            assert_matches!(
                skipped.get("git-dep"),
                Some(ScanOutcome::Skipped(SkipReason::NonRegistrySource))
            );
        }

        // `collect_in_use_versions` (§4.6) reuses the same `resolve_in_use_version`
        // ladder as `build_scan_targets` above, plus its own step-0 filter —
        // these tests exercise that reuse directly.

        #[test]
        fn collect_in_use_versions_prefers_lockfile_resolved_version() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("serde"), "1.0.195".into());

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("serde")),
                Some(&vec!["1.0.195".to_string()])
            );
        }

        #[test]
        fn collect_in_use_versions_concrete_pin_without_lockfile() {
            // Closes the former R4 gap: an exact pin with no lock file must
            // still produce an in-use version for the yanked probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("log4j-core"),
                    version_req: Some(VersionReq::new("2.14.1")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Maven,
            );
            assert_eq!(
                in_use.get(&PackageName::new("log4j-core")),
                Some(&vec!["2.14.1".to_string()])
            );
        }

        #[test]
        fn collect_in_use_versions_strips_pep440_double_equals_pin_for_pypi() {
            // The scenario the plan's R4 closure claim actually targets:
            // a PyPI `requirements.txt`-style `==` exact pin with no lock
            // file. `in_use.get(..)` must be the bare `"4.9.0"` so it can
            // ever match a real registry version string during the probe.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("typing_extensions"),
                    version_req: Some(VersionReq::new("==4.9.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Pypi,
            );
            assert_eq!(
                in_use.get(&PackageName::new("typing_extensions")),
                Some(&vec!["4.9.0".to_string()]),
                "pep440 '==' comparator must be stripped, not carried into the in-use version"
            );
        }

        #[test]
        fn collect_in_use_versions_skips_non_concrete_requirement_with_no_lockfile() {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("serde"),
                    version_req: Some(VersionReq::new("^1.0")),
                    source: DependencySource::Registry,
                }],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_excludes_non_registry_source_even_with_lockfile_version() {
            // Step 0 (§4.5): a patched git/path fork must never be flagged
            // for a registry version it does not contain.
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: PackageName::new("time"),
                    version_req: Some(VersionReq::new("0.1.43")),
                    source: DependencySource::Git {
                        url: "https://github.com/example/time".to_string(),
                        rev: None,
                    },
                }],
            };
            let mut resolved = HashMap::new();
            resolved.insert(PackageName::new("time"), "0.1.43".into());

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert!(in_use.is_empty());
        }

        #[test]
        fn collect_in_use_versions_tracks_all_occurrences_of_duplicate_name() {
            // Regression guard for #394: two occurrences of the same
            // dependency name (e.g. under different
            // `[target.*.dependencies]` blocks, or `[dependencies]` +
            // `[dev-dependencies]`) with different concrete pins and no lock
            // file must both surface an in-use version for the yanked probe
            // — a name-keyed `HashMap<PackageName, String>` would silently
            // drop all but the last occurrence's pin.
            let parse_result = MockParseResult {
                deps: vec![
                    MockDep {
                        name: PackageName::new("time"),
                        version_req: Some(VersionReq::new("=0.1.43")),
                        source: DependencySource::Registry,
                    },
                    MockDep {
                        name: PackageName::new("time"),
                        version_req: Some(VersionReq::new("=0.1.44")),
                        source: DependencySource::Registry,
                    },
                ],
            };
            let resolved = HashMap::new();

            let in_use = collect_in_use_versions(
                &parse_result,
                &resolved,
                &HashMap::new(),
                &MockFormatter,
                EcosystemId::Cargo,
            );
            assert_eq!(
                in_use.get(&PackageName::new("time")),
                Some(&vec!["0.1.43".to_string(), "0.1.44".to_string()]),
                "both occurrences' in-use versions must be tracked, not just the last one"
            );
        }
    }

    /// #462: `resolve_fix_target`'s pure per-dependency decision logic (reuse / provably
    /// clean / needs a live check / skip), and `apply_live_fix_target_statuses`'s handling of
    /// a live-check result map that may be missing keys (timeout/outage).
    mod fix_target_verification_tests {
        use super::*;
        use deps_core::lsp_helpers::{
            DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
            RequirementResolution, SourcePolicy,
        };
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };
        use std::sync::Arc;

        struct IdentityFormatter;
        impl PackageNaming for IdentityFormatter {}

        impl PackageRendering for IdentityFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for IdentityFormatter {}

        impl DiagnosticMessages for IdentityFormatter {}

        impl DiagnosticPolicy for IdentityFormatter {}

        impl SourcePolicy for IdentityFormatter {}

        impl OsvNaming for IdentityFormatter {}

        fn advisory(id: &str, fixed_versions: &[&str]) -> Arc<Advisory> {
            Arc::new(
                Advisory::new(
                    id.to_string(),
                    "2023-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                    String::new(),
                )
                .with_fixed_versions(fixed_versions.iter().map(ToString::to_string).collect()),
            )
        }

        fn dv(
            advisories: Vec<Arc<Advisory>>,
            upgrade_status: UpgradeStatus,
        ) -> DependencyVulnerabilities {
            let total = advisories.len();
            DependencyVulnerabilities::new(Capped::new(advisories, total))
                .with_upgrade_status(upgrade_status)
        }

        #[test]
        fn resolve_fix_target_skips_when_no_fix_is_recommended() {
            // No advisory has a known fix, so `recommended_fix()` returns `None`.
            let dv = dv(vec![advisory("A1", &[])], UpgradeStatus::NotChecked);
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_reuses_latest_when_f_equals_latest() {
            // Case (c): F (1.2.0, the only advisory's fix) coincides with the already-checked
            // "latest" candidate — reuse its result, no live check queued.
            let latest_status = UpgradeStatus::CandidateClean {
                version: "1.2.0".to_string(),
            };
            let dv = dv(vec![advisory("A1", &["1.2.0"])], latest_status.clone());
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("pkg".to_string(), "1.2.0".to_string());

            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &latest_native_by_key,
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Resolved(latest_status));
        }

        #[test]
        fn resolve_fix_target_always_needs_live_check_when_f_differs_from_latest() {
            // #462 critic C1: there is no data-derived shortcut. Even though every known
            // advisory's fix (1.2.0) is already at or below F, that is a tautology — F is
            // *computed from* these exact advisories, so this check would always pass at its
            // only call site and prove nothing about an advisory phase A never fetched at
            // all. F (1.2.0) differs from latest (3.0.0), so this must always queue a live
            // check, batched under the fix-target key suffix.
            let dv = dv(
                vec![advisory("A1", &["1.2.0"])],
                UpgradeStatus::CandidateClean {
                    version: "3.0.0".to_string(),
                },
            );
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("pkg".to_string(), "3.0.0".to_string());
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert("pkg".to_string(), "pkg".to_string());

            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &latest_native_by_key,
                &osv_name_by_key,
                &IdentityFormatter,
            );
            assert_eq!(
                resolution,
                FixTargetResolution::NeedsLiveCheck(deps_core::osv::ScanTarget::new(
                    format!("pkg{FIX_TARGET_KEY_SUFFIX}"),
                    "pkg".to_string(),
                    "1.2.0".to_string(),
                    "1.2.0".to_string(),
                ))
            );
        }

        #[test]
        fn resolve_fix_target_skips_when_osv_name_is_unavailable() {
            // A live check is needed (F != latest) but no `osv_name` is on record for this
            // key — nothing to query, so this degrades to `Skip` rather than panicking or
            // building a `ScanTarget` with an empty name.
            let dv = dv(vec![advisory("A1", &["1.0.0"])], UpgradeStatus::NotChecked);
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn resolve_fix_target_skips_when_f_is_not_a_safe_version_string() {
            // A malformed `fixed_versions` entry (as if it somehow reached this dependency's
            // `advisories` despite OSV's own wire-boundary validation) must never be queued
            // for a live check or treated as any kind of resolvable target — `is_safe_version_string`
            // rejects it before anything else runs.
            let dv = dv(
                vec![advisory("A1", &["1.2.0\", \"evil\": \"true"])],
                UpgradeStatus::NotChecked,
            );
            let resolution = resolve_fix_target(
                &dv,
                "pkg",
                &HashMap::new(),
                &HashMap::new(),
                &IdentityFormatter,
            );
            assert_eq!(resolution, FixTargetResolution::Skip);
        }

        #[test]
        fn collect_fix_target_resolutions_batches_multiple_dependencies_needing_live_check_into_one_vec()
         {
            // #462 NFR-001: three vulnerable dependencies — "reused" (F == latest, resolved
            // without a call), "live-a" and "live-b" (F != latest, both need a live check) —
            // must collapse into exactly one `resolved` entry and one `live_check_candidates`
            // Vec of length 2, proving multiple dependencies needing verification are batched
            // into a single prospective `check_candidates` call rather than one per dependency.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "reused".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A1", &["1.0.0"])],
                    UpgradeStatus::CandidateClean {
                        version: "1.0.0".to_string(),
                    },
                )),
            );
            vulnerabilities.insert(
                "live-a".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A2", &["1.2.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );
            vulnerabilities.insert(
                "live-b".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A3", &["2.2.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );

            let vulnerable_keys = vec![
                "reused".to_string(),
                "live-a".to_string(),
                "live-b".to_string(),
            ];
            let mut latest_native_by_key = HashMap::new();
            latest_native_by_key.insert("reused".to_string(), "1.0.0".to_string());
            latest_native_by_key.insert("live-a".to_string(), "9.0.0".to_string());
            latest_native_by_key.insert("live-b".to_string(), "9.0.0".to_string());
            let mut osv_name_by_key = HashMap::new();
            osv_name_by_key.insert("reused".to_string(), "reused".to_string());
            osv_name_by_key.insert("live-a".to_string(), "live-a".to_string());
            osv_name_by_key.insert("live-b".to_string(), "live-b".to_string());

            let (resolved, live_check_candidates) = collect_fix_target_resolutions(
                &vulnerabilities,
                &vulnerable_keys,
                &osv_name_by_key,
                &latest_native_by_key,
                &IdentityFormatter,
            );

            assert_eq!(resolved.len(), 1, "{resolved:?}");
            assert_eq!(resolved[0].0, "reused");

            assert_eq!(live_check_candidates.len(), 2, "{live_check_candidates:?}");
            let keys: std::collections::HashSet<&str> = live_check_candidates
                .iter()
                .map(|t| t.key.as_str())
                .collect();
            assert!(keys.contains(format!("live-a{FIX_TARGET_KEY_SUFFIX}").as_str()));
            assert!(keys.contains(format!("live-b{FIX_TARGET_KEY_SUFFIX}").as_str()));
        }

        #[test]
        fn apply_live_fix_target_statuses_sets_only_matching_keys_leaving_others_untouched() {
            // Case (e): a live-check batch that timed out for one dependency simply omits
            // its key from `statuses` — that dependency's `fix_target_status` must stay
            // `NotChecked` afterward, with no panic, while a dependency whose result did
            // arrive gets it applied.
            let mut vulnerabilities = VulnerabilityMap::new();
            vulnerabilities.insert(
                "checked".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A1", &["1.0.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );
            vulnerabilities.insert(
                "timed-out".to_string(),
                ScanOutcome::Vulnerable(dv(
                    vec![advisory("A2", &["1.0.0"])],
                    UpgradeStatus::NotChecked,
                )),
            );

            let mut statuses = HashMap::new();
            statuses.insert(
                format!("checked{FIX_TARGET_KEY_SUFFIX}"),
                UpgradeStatus::CandidateClean {
                    version: "1.0.0".to_string(),
                },
            );
            // "timed-out" deliberately has no entry in `statuses`.

            apply_live_fix_target_statuses(&mut vulnerabilities, statuses);

            let ScanOutcome::Vulnerable(checked) = vulnerabilities.get("checked").unwrap() else {
                panic!("expected Vulnerable");
            };
            assert_eq!(
                checked.fix_target_status,
                UpgradeStatus::CandidateClean {
                    version: "1.0.0".to_string()
                }
            );

            let ScanOutcome::Vulnerable(timed_out) = vulnerabilities.get("timed-out").unwrap()
            else {
                panic!("expected Vulnerable");
            };
            assert_eq!(timed_out.fix_target_status, UpgradeStatus::NotChecked);
        }
    }
}

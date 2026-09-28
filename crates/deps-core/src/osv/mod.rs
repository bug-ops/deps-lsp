//! OSV.dev vulnerability scanning.
//!
//! [`OsvClient`] batches dependency versions against the [OSV.dev](https://osv.dev)
//! API (`POST /v1/querybatch`) and resolves matching advisories
//! (`GET /v1/vulns/{id}`), with a semantic cache of its own — not
//! [`crate::cache::HttpCache`]'s entry map, since OSV sends no ETag/Last-Modified
//! validators and the batch endpoint is a POST with a request-body-dependent
//! response. See `architecture.md` §5 for why this is a deliberate deviation
//! from reusing `HttpCache` wholesale, and §8 for the four correctness
//! invariants this module exists to uphold (positional batch results,
//! pagination truncation, scan observability, and bounded record fan-out).
//!
//! [`OsvClient::scan`] never fails: every dependency passed in gets exactly
//! one [`ScanOutcome`] back, so an OSV outage degrades to an empty-ish map
//! rather than propagating an error into the LSP response (FR-007).

mod severity;
mod types;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub use severity::to_diagnostic_severity as diagnostic_severity_for;
use types::worst_severity;
pub use types::{
    Advisory, CandidateStatusMap, CandidateStatuses, Capped, DependencyVulnerabilities,
    FixRecommendation, LatestStatusMap, OsvEcosystem, OsvVersion, ScanOutcome, ScanTarget,
    SkipReason, StructuralSkipReason, UpgradeStatus, VulnKey, VulnKeys, VulnSeverity,
    VulnerabilityMap, is_valid_osv_id, validated_osv_url, vuln_key_for, vulnerability_keys,
};
use types::{
    OsvBatchRequest, OsvBatchResponse, OsvPackage, OsvQuery, OsvSingleQueryResponse, OsvVulnRecord,
};

use crate::cache::HttpCache;

/// Advisories rendered (§7) per dependency in hover/diagnostics/`deps-cli` output.
///
/// Paired with a trailing "+N more advisories" entry when [`Capped::total`] exceeds this.
/// Deliberately smaller than [`MAX_ADVISORY_RECORDS`] (#1422): the *fetch* bound and the
/// *render* bound used to be the same constant, which silently capped
/// [`DependencyVulnerabilities::recommended_fix`]'s input to whatever fit in the hover panel —
/// see [`DependencyVulnerabilities::advisories_for_display`] for the render-time truncation
/// this cap now governs on its own.
pub const ADVISORY_DISPLAY_CAP: usize = 5;

/// Bound on full advisory records fetched (invariant 3) per dependency.
///
/// The input budget for [`DependencyVulnerabilities::recommended_fix`]/`fix_target_is_verified`,
/// independent of [`ADVISORY_DISPLAY_CAP`] (#1422). Larger than the display cap because a
/// dependency's highest `fixed` version is not guaranteed to appear among the first
/// [`ADVISORY_DISPLAY_CAP`] advisories OSV returns — a fix recommendation computed from only
/// those would claim to resolve everything while leaving a later-indexed advisory's
/// vulnerability open. Still a cap, not "fetch everything": a dependency with more than this
/// many advisories is the accepted, documented under-report case
/// ([`DependencyVulnerabilities::recommended_fix`]'s "Limitations" section), traded off against
/// bounding this client's per-scan fan-out cost.
pub const MAX_ADVISORY_RECORDS: usize = 50;

/// Query cache TTL (approved Q6).
const QUERY_CACHE_TTL: Duration = Duration::from_hours(6);

/// `/v1/querybatch` chunk size (FR-009).
const BATCH_CHUNK_SIZE: usize = 1000;

/// Bound on individually-requeried truncated entries per [`OsvClient::scan`]/
/// [`OsvClient::check_candidates`] call (§8 invariant 2).
const MAX_TRUNCATED_REQUERY_BUDGET: usize = 20;

/// Bounded concurrency for the `/v1/vulns/{id}` and `/v1/query` (truncation recovery) fan-out
/// (§8 invariant 3), mirroring the registry fetch fan-out's `buffer_unordered` usage.
///
/// Enforced by [`OsvClient::record_fetch_semaphore`], shared across every call on the client —
/// not by `buffer_unordered` alone, which only bounds concurrency *within* a single call. Issue
/// #1535: `deps-lsp`'s round-based candidate check fires up to `MAX_CANDIDATE_CHECK_VERSIONS`
/// concurrent [`OsvClient::check_candidates`] calls, each of which used to get its own fresh
/// `buffer_unordered(RECORD_FETCH_CONCURRENCY)` window — multiplying the real fan-out to OSV.dev
/// well past this constant's intended bound.
const RECORD_FETCH_CONCURRENCY: usize = 10;

/// Entry-count bound shared by `query_cache` and `record_cache`.
const MAX_CACHE_ENTRIES: usize = 10_000;

const OSV_API_BASE: &str = "https://api.osv.dev";

/// Compares two version-like strings by their leading numeric-and-dot release prefix (the
/// longest leading run of `[0-9.]` after stripping a single leading `v`/`V` tag-prefix marker,
/// trailing dot trimmed — `"2.0.0-rc.1"` and `"2.2.0.dev0"` both yield the release prefix
/// `"2.0.0"`/`"2.2.0"`, and `"v1.20.3"` yields `"1.20.3"`), preferring a bare release over any
/// string carrying a non-numeric suffix past that prefix once the two release prefixes tie — a
/// pre-release marker in every scheme this workspace scans (SemVer's `-rc.1`, PEP 440's
/// `rc1`/`.dev0`, Go's pseudo-version `-0.20210101000000-abcdef123456`, Maven's `-SNAPSHOT`) —
/// then falling back to a lexicographic compare of any remaining tie.
///
/// Used only to order [`Advisory::fixed_versions`] ascending and to pick
/// [`DependencyVulnerabilities::recommended_fix`]'s target across advisories — not a general
/// semver/PEP 440/Maven comparator, and deliberately **not** applied to `GIT`-range `fixed`
/// events (40-hex commit SHAs), which [`OsvVulnRecord::into_advisory`] excludes from
/// `fixed_versions` entirely before this ever runs (issue #1482) — this comparator has no
/// meaningful way to rank a SHA against a real version, and a caller with an ecosystem-native
/// parser at hand (`semver`, `pep440_rs`, ...) should prefer that over this heuristic when one
/// is available.
///
/// The plain-release tie-break is a deliberate, documented over-simplification for a suffix
/// this comparator cannot classify further: it also ranks a *post*-release (PEP 440's
/// `1.0.0.post1`, Maven's `1.2.3-1` build number) below its own base release, which is
/// backwards for those two schemes specifically — a real regression only if an OSV record's
/// `fixed_versions` for one advisory ever mixes a bare release with that same release's
/// post-release/build-number spelling, which is rarer than the pre-release case this fixes
/// (PyPI/OSV normalize most post-releases to the `.postN` form regardless, and no live-verified
/// OSV record in this project's test fixtures has hit it).
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    /// The longest leading run of `[0-9.]` in `s`, trailing dot trimmed — the "release" part of
    /// a version string, stopping before any pre-release/build/metadata suffix regardless of
    /// whether that suffix starts with a dot (`.dev0`), a hyphen (`-rc.1`), or no separator at
    /// all (`rc0`). Callers must strip a leading `v`/`V` tag-prefix marker before calling this —
    /// see [`compare_version_strings`]'s own `normalize_tag` call — otherwise the marker itself
    /// is the first non-digit-non-dot character and the whole release prefix collapses to
    /// empty.
    fn release_prefix(s: &str) -> &str {
        let end = s
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_digit() || *c == '.'))
            .map_or(s.len(), |(i, _)| i);
        // `end` always lands on a char boundary (`char_indices` guarantees it), but
        // `clippy::string_slice` can't prove that statically — `get` sidesteps the lint
        // without changing behavior, since the slice can never actually fail.
        s.get(..end).unwrap_or(s).trim_end_matches('.')
    }

    fn segments(s: &str) -> Vec<u64> {
        release_prefix(s)
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    }

    /// Whether `s` is entirely its own release prefix (no pre-release/build/metadata suffix).
    fn is_plain_release(s: &str) -> bool {
        release_prefix(s).len() == s.len()
    }

    // Code-review regression (#1482): a leading `v`/`V` tag-prefix marker (a git release tag an
    // OSV record can echo verbatim) is itself the first non-digit-non-dot character, so without
    // stripping it first `release_prefix` collapsed to empty for both operands — "v1.20.3" and
    // "v1.3.10" then tied on `segments`/`is_plain_release` and fell all the way to the
    // lexicographic fallback, which compares character-by-character and ranks "v1.20.3" *below*
    // "v1.3.10" (wrong: 20 > 3). `normalize_tag` is the same single-`v`/`V`-prefix strip
    // [`crate::lsp_helpers::OsvNaming::osv_version`]/`osv_version_to_native` already apply to
    // this exact class of value, so the rest of the release-prefix logic runs on real numeric
    // content instead of stopping at the marker.
    let a = crate::github::normalize_tag(a);
    let b = crate::github::normalize_tag(b);

    let (sa, sb) = (segments(a), segments(b));
    sa.cmp(&sb)
        .then_with(|| is_plain_release(a).cmp(&is_plain_release(b)))
        .then_with(|| a.cmp(b))
}

struct QueryCacheEntry {
    vuln_ids: Vec<(String, String)>,
    fetched_at: Instant,
}

struct RecordCacheEntry {
    advisory: Arc<Advisory>,
    modified: String,
    fetched_at: Instant,
}

/// A single-flight fetch slot for one advisory id, tracking how many concurrent callers are
/// currently waiting on it (issue #1539 review finding: solo-caller timeout leak).
///
/// [`OsvClient::fetch_record_single_flight`] evicts a completed entry from `record_in_flight`
/// unconditionally, but a caller that times out via its own per-caller deadline must only evict
/// when it was the *last* caller still waiting on this id — otherwise a caller whose timeout
/// fires while a different caller is still driving `cell` to completion would rip the shared
/// slot out from under it (the bug finding #1 fixed). `waiters` makes that "was I last"
/// determination race-free: incremented once per caller under the `DashMap` entry's own lock
/// before that caller starts waiting, decremented via `fetch_sub` (whose return value is the
/// pre-decrement count) when that caller stops waiting for any reason. Exactly one concurrent
/// decrementer ever observes the count reaching zero, even if multiple solo timeouts race.
struct InFlightRecord {
    cell: tokio::sync::OnceCell<Option<Arc<OsvVulnRecord>>>,
    waiters: std::sync::atomic::AtomicUsize,
}

impl InFlightRecord {
    fn new() -> Self {
        Self {
            cell: tokio::sync::OnceCell::new(),
            waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// Batches dependency versions against OSV.dev and resolves matching
/// advisories, with its own semantic cache layered on top of
/// [`HttpCache`]'s transport (`post_json`/`get_cached`).
///
/// One instance is shared server-lifetime on `ServerState` in `deps-lsp`, so
/// every open document's scan benefits from the same query/record cache.
pub struct OsvClient {
    cache: Arc<HttpCache>,
    query_cache: DashMap<(OsvEcosystem, String, OsvVersion), QueryCacheEntry>,
    record_cache: DashMap<String, RecordCacheEntry>,
    /// Client-wide bound (permits = [`RECORD_FETCH_CONCURRENCY`]) on concurrent
    /// `/v1/vulns/{id}`/`/v1/query` requests — see [`RECORD_FETCH_CONCURRENCY`]'s doc for why
    /// this must be a field shared via `Arc` rather than a per-call `buffer_unordered` bound
    /// (issue #1535).
    record_fetch_semaphore: Arc<tokio::sync::Semaphore>,
    /// Coalesces concurrent fetches of the *same advisory id* — across every call sharing this
    /// client, not just one [`Self::fetch_records`] invocation — into a single in-flight `GET
    /// /v1/vulns/{id}` (issue #1535). Keyed by advisory id alone, not `(id, osv_name, osv_eco)`:
    /// only the raw [`OsvVulnRecord`] fetch is shared; each caller still derives its own
    /// [`Advisory`] via `into_advisory` for the package it actually queried, since one record
    /// can describe several unrelated packages (see the `scan_filters_affected_entries_to_the_queried_package`
    /// test). See [`InFlightRecord`] for how eviction avoids both stranding a live waiter and
    /// leaking an entry no caller is left to clean up (issue #1539).
    record_in_flight: DashMap<String, Arc<InFlightRecord>>,
    /// Overridable in test builds only, so `mockito` can stand in for
    /// `https://api.osv.dev` — mirrors [`crate::cache::ensure_https`]'s existing
    /// `#[cfg(test)]` relaxation for the same reason, and [`crate::deps_dev::DepsDevClient`]'s
    /// own `base_url` field.
    #[cfg(any(test, feature = "test-util"))]
    base_url: String,
}

impl OsvClient {
    /// Creates a client that reuses `cache`'s HTTP transport (`Client`,
    /// HTTPS enforcement, size cap, timeout) for both the batch POST and the
    /// per-advisory GET.
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            cache,
            query_cache: DashMap::new(),
            record_cache: DashMap::new(),
            record_fetch_semaphore: Arc::new(tokio::sync::Semaphore::new(RECORD_FETCH_CONCURRENCY)),
            record_in_flight: DashMap::new(),
            #[cfg(any(test, feature = "test-util"))]
            base_url: OSV_API_BASE.to_string(),
        }
    }

    /// Creates a client pointed at `base_url` instead of the real OSV.dev API, for
    /// `mockito`-backed tests — issue #1517 critique S6, so a downstream crate (e.g.
    /// `deps-lsp`, via its `test-util`-featured dev-dependency on this crate) can exercise
    /// [`Self::scan`]/[`Self::check_candidates`] against a mock server the same way
    /// [`crate::deps_dev::DepsDevClient::for_test`] already lets it do for deps.dev calls.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(cache: Arc<HttpCache>, base_url: impl Into<String>) -> Self {
        Self::with_base_url(cache, base_url.into())
    }

    #[cfg(any(test, feature = "test-util"))]
    fn with_base_url(cache: Arc<HttpCache>, base_url: String) -> Self {
        Self {
            cache,
            query_cache: DashMap::new(),
            record_cache: DashMap::new(),
            record_fetch_semaphore: Arc::new(tokio::sync::Semaphore::new(RECORD_FETCH_CONCURRENCY)),
            record_in_flight: DashMap::new(),
            base_url,
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    fn api_base(&self) -> &str {
        &self.base_url
    }

    #[cfg(not(any(test, feature = "test-util")))]
    const fn api_base(&self) -> &str {
        OSV_API_BASE
    }

    fn batch_url(&self) -> String {
        format!("{}/v1/querybatch", self.api_base())
    }

    fn single_query_url(&self) -> String {
        format!("{}/v1/query", self.api_base())
    }

    fn vuln_record_url(&self, id: &str) -> String {
        format!("{}/v1/vulns/{id}", self.api_base())
    }

    /// Phase A: scans `deps` and returns the map consumed by the rendering
    /// helpers.
    ///
    /// `timeout` bounds the *entire* scan (all chunks and any truncation
    /// recovery), not any single request — the underlying `reqwest` client
    /// already caps each individual request at 30s. The deadline is checked
    /// between chunks/recovery items, not mid-request, so already-completed
    /// work is never discarded on timeout: only whatever had not yet started
    /// degrades to [`SkipReason::QueryFailed`]/[`SkipReason::Truncated`]
    /// (critique S5).
    ///
    /// Never returns an error: every failure degrades to a
    /// [`ScanOutcome::Skipped`] entry, never an absent one. Logs a
    /// per-scan summary at `info` (§8 invariant 0).
    pub async fn scan(
        &self,
        ecosystem: crate::EcosystemId,
        deps: &[ScanTarget],
        timeout: Duration,
    ) -> VulnerabilityMap {
        if deps.is_empty() {
            return VulnerabilityMap::new();
        }
        let outcomes = self.resolve(ecosystem, deps, timeout).await;
        log_scan_summary(&outcomes);
        outcomes
    }

    /// Phase B: checks whether the versions about to be recommended (e.g.
    /// "latest" from the registry) are themselves affected.
    ///
    /// Callers may build `candidates` from any subset of dependencies with a registry-cached
    /// candidate to check — issue #1517 removed the earlier restriction to only dependencies
    /// phase A already flagged [`ScanOutcome::Vulnerable`], since a cleanly-pinned dependency's
    /// "latest" must be checked too (a phase-A-only gate silently let a malicious/vulnerable
    /// "latest" through for every dependency that was clean at its *pinned* version). `timeout`
    /// has the same meaning as in [`Self::scan`].
    ///
    /// Every `candidates` entry gets exactly one result back (never silently dropped): a
    /// [`ScanOutcome::Skipped`] outcome, or a target this call never resolved a result for at
    /// all, becomes [`UpgradeStatus::CandidateUnverified`] rather than an absent map entry — a
    /// caller must fail closed on that, never treat "absent" as "safe" (issue #1517 AC4).
    pub async fn check_candidates(
        &self,
        ecosystem: crate::EcosystemId,
        candidates: &[ScanTarget],
        timeout: Duration,
    ) -> LatestStatusMap {
        if candidates.is_empty() {
            return HashMap::new();
        }

        let outcomes = self.resolve(ecosystem, candidates, timeout).await;

        candidates
            .iter()
            .map(|candidate| {
                let key = candidate.key.clone();
                // `display_version`, not `version`: the latter is OSV's wire spelling (e.g.
                // Go's `v`-prefix stripped), but `UpgradeStatus` must surface the
                // ecosystem-native one.
                let version = candidate.display_version.clone();
                let status = match outcomes.get(&key) {
                    Some(ScanOutcome::Clean) => UpgradeStatus::CandidateClean { version },
                    Some(ScanOutcome::Vulnerable(dv)) => {
                        // Issue #1517 critique S2: `dv.advisories.items()` only holds the
                        // records that were actually fetched and passed validation — a record
                        // dropped by `fetch_records` (network failure, parse failure) or
                        // truncated by `MAX_ADVISORY_RECORDS` is silently absent from `items()`
                        // but still counted in `total()`. Computing `worst_severity` over an
                        // incomplete `items()` can under-report (an Informational record fetched
                        // alongside a higher-severity one that failed to fetch would otherwise
                        // read as `Some(Informational)` -> `Verified`, fail-open). `None` here
                        // is the same "could not be determined" signal `worst_severity` already
                        // returns for an empty slice, and `CandidateVulnerable::worst_severity`'s
                        // own contract already treats `None` as blocking.
                        let worst_severity = dv
                            .advisories
                            .is_complete()
                            .then(|| worst_severity(dv.advisories.items()))
                            .flatten();
                        UpgradeStatus::CandidateVulnerable {
                            version,
                            advisory_ids: Capped::new(
                                dv.advisories.items().iter().map(|a| a.id.clone()).collect(),
                                dv.advisories.total(),
                            ),
                            worst_severity,
                        }
                    }
                    Some(ScanOutcome::Skipped(reason)) => UpgradeStatus::CandidateUnverified {
                        version,
                        reason: *reason,
                    },
                    // `resolve` is documented to always produce one outcome per target, but a
                    // caller must still fail closed here rather than assume it, per this
                    // method's own contract above (issue #1517 AC4).
                    None => UpgradeStatus::CandidateUnverified {
                        version,
                        reason: SkipReason::QueryFailed,
                    },
                };
                (key, status)
            })
            .collect()
    }

    /// Shared resolution logic for [`Self::scan`] and [`Self::check_candidates`]:
    /// cache lookup, chunked batch query (invariant 1), truncation recovery
    /// (invariant 2), and bounded record fetch (invariant 3).
    ///
    /// `timeout` is enforced as a wall-clock deadline checked before each
    /// chunk and before truncation recovery begins — never by wrapping the
    /// whole future in `tokio::time::timeout`, which would drop
    /// already-accumulated `outcomes` along with whatever was still running
    /// (critique S5).
    async fn resolve(
        &self,
        ecosystem: crate::EcosystemId,
        targets: &[ScanTarget],
        timeout: Duration,
    ) -> VulnerabilityMap {
        let deadline = Instant::now() + timeout;
        let mut outcomes = HashMap::with_capacity(targets.len());

        let Some(osv_eco) = ecosystem.osv_ecosystem() else {
            for t in targets {
                outcomes.insert(
                    t.key.clone(),
                    ScanOutcome::Skipped(SkipReason::UnmappableEcosystem),
                );
            }
            return outcomes;
        };

        let mut to_query: Vec<ScanTarget> = Vec::new();
        let mut seen: HashSet<&VulnKey> = HashSet::with_capacity(targets.len());
        for t in targets {
            // Duplicate keys share one result; querying them twice would only waste requests.
            if !seen.insert(&t.key) {
                continue;
            }
            let cache_key = (osv_eco, t.osv_name.clone(), t.version.clone());
            let cached_ids = self.query_cache.get(&cache_key).and_then(|entry| {
                (entry.fetched_at.elapsed() < QUERY_CACHE_TTL).then(|| entry.vuln_ids.clone())
            });
            if let Some(vuln_ids) = cached_ids {
                outcomes.insert(
                    t.key.clone(),
                    self.build_outcome(osv_eco, &t.osv_name, &vuln_ids, deadline)
                        .await,
                );
            } else {
                to_query.push(t.clone());
            }
        }

        if to_query.is_empty() {
            return outcomes;
        }

        let mut truncated: Vec<ScanTarget> = Vec::new();
        let mut chunks = to_query.chunks(BATCH_CHUNK_SIZE);

        while let Some(chunk) = chunks.next() {
            if Instant::now() >= deadline {
                tracing::warn!(
                    remaining = chunk.len(),
                    "OSV scan deadline exceeded, marking remaining chunks as query-failed"
                );
                mark_chunk_failed(chunk, &mut outcomes);
                for remaining in chunks {
                    mark_chunk_failed(remaining, &mut outcomes);
                }
                return outcomes;
            }
            self.resolve_chunk(osv_eco, chunk, &mut outcomes, &mut truncated, deadline)
                .await;
        }

        if Instant::now() >= deadline {
            tracing::warn!(
                count = truncated.len(),
                "OSV scan deadline exceeded before truncation recovery"
            );
            for target in &truncated {
                outcomes.insert(
                    target.key.clone(),
                    ScanOutcome::Skipped(SkipReason::Truncated),
                );
            }
            return outcomes;
        }

        self.recover_truncated(osv_eco, &truncated, &mut outcomes, deadline)
            .await;

        outcomes
    }

    /// Queries one batch chunk and populates `outcomes`/`truncated`.
    ///
    /// Owns `chunk` end-to-end and zips results only against it (never the
    /// full document dependency list) — §8 invariant 1. On any failure
    /// (network error, non-2xx, malformed JSON, or a result-count mismatch)
    /// the *entire* chunk degrades to [`SkipReason::QueryFailed`] rather than
    /// risking misattributing an advisory to the wrong dependency.
    #[tracing::instrument(
        skip(self, osv_eco, chunk, outcomes, truncated),
        fields(url = tracing::field::Empty, osv_eco = osv_eco.as_str())
    )]
    async fn resolve_chunk(
        &self,
        osv_eco: OsvEcosystem,
        chunk: &[ScanTarget],
        outcomes: &mut VulnerabilityMap,
        truncated: &mut Vec<ScanTarget>,
        deadline: Instant,
    ) {
        let url = self.batch_url();
        tracing::Span::current().record(
            "url",
            tracing::field::display(crate::redact::RedactedUrl::new(&url)),
        );

        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|t| OsvQuery {
                package: OsvPackage {
                    name: t.osv_name.clone(),
                    ecosystem: osv_eco.as_str().to_owned(),
                },
                version: t.version.clone().into_string(),
            })
            .collect();

        let body = OsvBatchRequest { queries };
        let response_bytes = match self.cache.post_json(&url, &body).await {
            Ok(b) => b,
            Err(e) => {
                // #756: never interpolate `e`'s `Display` — it can embed the raw request
                // URL (`DepsError::HttpStatus`/`RegistryError`; see
                // `DepsError::safe_tracing_summary`'s docs).
                let (status, cause) = e.safe_tracing_summary();
                tracing::warn!(status = ?status, cause, "OSV batch query failed");
                mark_chunk_failed(chunk, outcomes);
                return;
            }
        };

        let parsed: OsvBatchResponse = match crate::parser::parse_json_checked(&response_bytes) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse OSV batch response");
                mark_chunk_failed(chunk, outcomes);
                return;
            }
        };

        if parsed.results.len() != chunk.len() {
            tracing::warn!(
                expected = chunk.len(),
                got = parsed.results.len(),
                "OSV batch result count mismatch, dropping chunk"
            );
            mark_chunk_failed(chunk, outcomes);
            return;
        }

        for (target, result) in chunk.iter().zip(parsed.results) {
            if result.next_page_token.is_some() {
                truncated.push(target.clone());
                continue;
            }
            let vuln_ids: Vec<(String, String)> = result
                .vulns
                .into_iter()
                .map(|v| (v.id, v.modified))
                .collect();
            self.store_query_cache(osv_eco, target, &vuln_ids);
            outcomes.insert(
                target.key.clone(),
                self.build_outcome(osv_eco, &target.osv_name, &vuln_ids, deadline)
                    .await,
            );
        }
    }

    /// Recovers batch-truncated entries via individual `POST /v1/query`
    /// calls (§8 invariant 2), bounded by [`MAX_TRUNCATED_REQUERY_BUDGET`]
    /// and run concurrently (mirroring the registry fan-out, critique M3).
    /// Entries beyond the budget become [`SkipReason::Truncated`] rather than
    /// ever rendering as zero advisories.
    async fn recover_truncated(
        &self,
        osv_eco: OsvEcosystem,
        truncated: &[ScanTarget],
        outcomes: &mut VulnerabilityMap,
        deadline: Instant,
    ) {
        use futures::stream::{self, StreamExt};

        let budget = MAX_TRUNCATED_REQUERY_BUDGET.min(truncated.len());
        let (to_recover, exhausted) = truncated.split_at(budget);

        // Cloned, not borrowed: a closure borrowing both `self` and a `truncated` slice
        // element triggers a higher-ranked-lifetime inference failure once nested inside an
        // outer `tokio::spawn` — `fetch_records` hit the same issue and fixed it with `.cloned()`.
        let recovered: Vec<(VulnKey, ScanOutcome)> = stream::iter(to_recover.iter().cloned())
            .map(|target| async move {
                // Same client-wide OSV request budget as `fetch_record_single_flight` (issue
                // #1535) — a `/v1/query` requery is as expensive as a `/v1/vulns/{id}` fetch,
                // so it draws from the same semaphore rather than its own separate window. The
                // wait itself is bounded by `deadline` (issue #1539): a scan must not overrun its
                // timeout window sitting in the semaphore queue, so an expired wait fails this
                // item closed exactly like an `Err` from `acquire_owned` already did.
                let _permit = match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    Arc::clone(&self.record_fetch_semaphore).acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => {
                        return (target.key.clone(), ScanOutcome::Skipped(SkipReason::QueryFailed));
                    }
                    Err(_) => {
                        tracing::warn!(
                            dep = %target.key,
                            "OSV truncation-requery permit wait exceeded scan deadline"
                        );
                        return (target.key.clone(), ScanOutcome::Skipped(SkipReason::QueryFailed));
                    }
                };
                let outcome = match self.query_single(osv_eco, &target).await {
                    // `/v1/query` can itself paginate — never trust its
                    // `vulns.len()` as complete when it says there is more
                    // (critique S4).
                    Some(resp) if resp.next_page_token.is_some() => {
                        tracing::warn!(
                            dep = %target.key,
                            "OSV single-package requery itself paginated; treating as still truncated"
                        );
                        ScanOutcome::Skipped(SkipReason::Truncated)
                    }
                    Some(resp) => self.outcome_from_full_records(osv_eco, &target, resp.vulns),
                    None => ScanOutcome::Skipped(SkipReason::QueryFailed),
                };
                (target.key.clone(), outcome)
            })
            .buffer_unordered(RECORD_FETCH_CONCURRENCY)
            .collect()
            .await;

        for (key, outcome) in recovered {
            outcomes.insert(key, outcome);
        }

        for target in exhausted {
            outcomes.insert(
                target.key.clone(),
                ScanOutcome::Skipped(SkipReason::Truncated),
            );
        }
    }

    /// Converts full advisory records recovered via `/v1/query` directly
    /// into a [`ScanOutcome`], populating the record cache along the way —
    /// no follow-up `GET /v1/vulns/{id}` is needed for these (§8 invariant 2).
    /// A record whose id fails [`types::OsvVulnRecord::into_advisory`]'s
    /// validation is dropped, not counted toward `advisories`/the cache, but
    /// [`Capped::total`] still reflects OSV's reported count (critique M1).
    fn outcome_from_full_records(
        &self,
        osv_eco: OsvEcosystem,
        target: &ScanTarget,
        records: Vec<OsvVulnRecord>,
    ) -> ScanOutcome {
        let total = records.len();
        let mut advisories = Vec::with_capacity(total.min(MAX_ADVISORY_RECORDS));
        let mut vuln_ids = Vec::with_capacity(total);

        for record in records {
            let Some(advisory) = record.into_advisory(&target.osv_name, osv_eco) else {
                continue;
            };
            let advisory = Arc::new(advisory);
            vuln_ids.push((advisory.id.clone(), advisory.modified.clone()));
            self.store_record_cache(&advisory);
            if advisories.len() < MAX_ADVISORY_RECORDS {
                advisories.push(advisory);
            }
        }

        self.store_query_cache(osv_eco, target, &vuln_ids);

        if total == 0 {
            ScanOutcome::Clean
        } else {
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(advisories, total),
                fix_target_status: UpgradeStatus::NotChecked,
            })
        }
    }

    /// Builds a [`ScanOutcome`] from a list of `(id, modified)` stubs,
    /// fetching up to [`MAX_ADVISORY_RECORDS`] full records.
    async fn build_outcome(
        &self,
        osv_eco: OsvEcosystem,
        osv_name: &str,
        vuln_ids: &[(String, String)],
        deadline: Instant,
    ) -> ScanOutcome {
        if vuln_ids.is_empty() {
            return ScanOutcome::Clean;
        }

        #[expect(
            clippy::indexing_slicing,
            reason = "the slice upper bound is min(vuln_ids.len(), MAX_ADVISORY_RECORDS), \
                      always <= vuln_ids.len()"
        )]
        let to_fetch = &vuln_ids[..vuln_ids.len().min(MAX_ADVISORY_RECORDS)];
        let advisories = self
            .fetch_records(osv_eco, osv_name, to_fetch, deadline)
            .await;

        ScanOutcome::Vulnerable(DependencyVulnerabilities {
            advisories: Capped::new(advisories, vuln_ids.len()),
            fix_target_status: UpgradeStatus::NotChecked,
        })
    }

    /// Fetches full advisory records for `ids`, checking the record cache
    /// first and bounding fetch concurrency (§8 invariant 3). A record that
    /// fails to fetch, parse, or validate (malformed id, or no matching
    /// `affected[].package` — critique S3/M1) is dropped, not substituted
    /// with a half-populated placeholder.
    async fn fetch_records(
        &self,
        osv_eco: OsvEcosystem,
        osv_name: &str,
        ids: &[(String, String)],
        deadline: Instant,
    ) -> Vec<Arc<Advisory>> {
        use futures::stream::{self, StreamExt};

        stream::iter(ids.iter().cloned())
            .map(|(id, modified)| async move {
                let cached = self.record_cache.get(&id).and_then(|entry| {
                    (entry.modified == modified).then(|| Arc::clone(&entry.advisory))
                });
                if let Some(advisory) = cached {
                    return Some(advisory);
                }

                let record = self.fetch_record_single_flight(&id, deadline).await?;
                let advisory = Arc::new((*record).clone().into_advisory(osv_name, osv_eco)?);
                self.store_record_cache(&advisory);
                Some(advisory)
            })
            .buffer_unordered(RECORD_FETCH_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Coalesces concurrent fetches of the same advisory id — across every call sharing this
    /// client, not just one [`Self::fetch_records`] invocation — into a single in-flight `GET
    /// /v1/vulns/{id}`, and gates the underlying HTTP fetch through `record_fetch_semaphore` so
    /// [`RECORD_FETCH_CONCURRENCY`] bounds fetch concurrency client-wide (issue #1535) rather
    /// than resetting to a fresh window on every call.
    ///
    /// The wait (permit acquire + HTTP fetch) is bounded by each *caller's own* `deadline`
    /// (issue #1539): wrapping the whole [`tokio::sync::OnceCell::get_or_init`] call in an outer
    /// `timeout_at`, rather than only the permit acquire inside the initializer closure, matters
    /// because `record_in_flight` is shared client-wide — a caller that joins a cell some other
    /// caller is already initializing must not be bound by *that* caller's deadline instead of
    /// its own (issue #1539 critique S1). Two failure modes that would otherwise follow:
    /// overrunning a short-lived caller's own deadline while piggybacking on a longer-lived
    /// initializer, or a near-expired initializer poisoning the cell with `None` for a
    /// long-lived caller that still had budget left. `OnceCell::get_or_init` is documented
    /// cancel-safe: dropping the initializing future on this caller's own timeout releases the
    /// cell's internal lock so a still-waiting caller starts its own initialization attempt with
    /// its own deadline, rather than inheriting a poisoned result.
    async fn fetch_record_single_flight(
        &self,
        id: &str,
        deadline: Instant,
    ) -> Option<Arc<OsvVulnRecord>> {
        let entry = Arc::clone(
            self.record_in_flight
                .entry(id.to_string())
                .or_insert_with(|| Arc::new(InFlightRecord::new()))
                .value(),
        );
        entry
            .waiters
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            entry.cell.get_or_init(|| async {
                let permit = Arc::clone(&self.record_fetch_semaphore)
                    .acquire_owned()
                    .await
                    .ok()?;
                let record = self.fetch_single_record(id).await.map(Arc::new);
                drop(permit);
                record
            }),
        )
        .await
        {
            Ok(value) => {
                let result = value.clone();

                // Only a dedup window for concurrently-overlapping requests, not a persistent
                // cache (`record_cache` already serves that role) — drop the entry once resolved
                // so a later, non-overlapping fetch of the same id re-queries rather than growing
                // this map forever over a server-lifetime client. Eviction is unconditional here:
                // this caller's own `get_or_init` actually completed, so `entry.cell` is
                // guaranteed fully initialized regardless of how many other callers are still
                // waiting on it (they'll each observe the same completed value via their own
                // `get_or_init` call, independent of the map entry).
                self.record_in_flight
                    .remove_if(id, |_, v| Arc::ptr_eq(v, &entry));

                result
            }
            Err(_) => {
                tracing::warn!(id, "OSV record fetch wait exceeded scan deadline");

                // Evicting unconditionally on this caller's own timeout would remove the entry
                // out from under a *different* caller still legitimately driving the same cell to
                // completion (issue #1539 critique finding #1): a third caller joining in that
                // window would then create a brand-new cell and issue a redundant `GET
                // /v1/vulns/{id}`, defeating single-flight coalescing (#1535). But never evicting
                // on timeout leaks the entry forever when this caller was the *only* one waiting
                // — nobody else is left to ever drive `entry.cell` to completion and evict it
                // (issue #1539 review finding). `waiters.fetch_sub` returns the pre-decrement
                // count, so exactly one concurrent caller — whichever one's decrement observes
                // `1` — is guaranteed to be the last, even if multiple solo timeouts race.
                if entry
                    .waiters
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
                    == 1
                {
                    self.record_in_flight
                        .remove_if(id, |_, v| Arc::ptr_eq(v, &entry));
                }

                None
            }
        }
    }

    /// Fetches a single advisory record. Uses [`HttpCache::get_transport_only`]
    /// rather than [`HttpCache::get_cached`] deliberately: this client's own
    /// `record_cache` (validated by `modified`, not `ETag`) is the real
    /// cache for these bodies, so also caching them in `HttpCache`'s
    /// entry map would double-cache every fetched record there, competing
    /// with registry responses for its byte budget for no benefit (critique
    /// M2 — nothing ever reads that copy back).
    #[tracing::instrument(skip(self), fields(url = tracing::field::Empty))]
    async fn fetch_single_record(&self, id: &str) -> Option<OsvVulnRecord> {
        let url = self.vuln_record_url(id);
        tracing::Span::current().record(
            "url",
            tracing::field::display(crate::redact::RedactedUrl::new(&url)),
        );
        match self.cache.get_transport_only(&url).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<OsvVulnRecord>(&bytes) {
                Ok(record) => Some(record),
                Err(e) => {
                    tracing::warn!(id, error = %e, "failed to parse OSV vulnerability record");
                    None
                }
            },
            // #756: never interpolate `e`'s `Display` — see `DepsError::safe_tracing_summary`.
            Err(e) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::warn!(
                    id,
                    status = ?status,
                    cause,
                    "failed to fetch OSV vulnerability record"
                );
                None
            }
        }
    }

    #[tracing::instrument(
        skip(self, osv_eco, target),
        fields(url = tracing::field::Empty, osv_eco = osv_eco.as_str())
    )]
    async fn query_single(
        &self,
        osv_eco: OsvEcosystem,
        target: &ScanTarget,
    ) -> Option<OsvSingleQueryResponse> {
        let url = self.single_query_url();
        tracing::Span::current().record(
            "url",
            tracing::field::display(crate::redact::RedactedUrl::new(&url)),
        );

        let body = OsvQuery {
            package: OsvPackage {
                name: target.osv_name.clone(),
                ecosystem: osv_eco.as_str().to_owned(),
            },
            version: target.version.clone().into_string(),
        };

        let bytes = match self.cache.post_json(&url, &body).await {
            Ok(b) => b,
            // #756: never interpolate `e`'s `Display` — see `DepsError::safe_tracing_summary`.
            Err(e) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::warn!(
                    dep = %target.key,
                    status = ?status,
                    cause,
                    "OSV single-package requery failed"
                );
                return None;
            }
        };

        match crate::parser::parse_json_checked::<OsvSingleQueryResponse>(&bytes) {
            Ok(resp) => Some(resp),
            Err(e) => {
                tracing::warn!(dep = %target.key, error = %e, "failed to parse OSV single-package response");
                None
            }
        }
    }

    fn store_query_cache(
        &self,
        osv_eco: OsvEcosystem,
        target: &ScanTarget,
        vuln_ids: &[(String, String)],
    ) {
        if self.query_cache.len() >= MAX_CACHE_ENTRIES {
            crate::cache_policy::evict_oldest_batch(&self.query_cache, MAX_CACHE_ENTRIES, |e| {
                e.fetched_at
            });
        }
        self.query_cache.insert(
            (osv_eco, target.osv_name.clone(), target.version.clone()),
            QueryCacheEntry {
                vuln_ids: vuln_ids.to_vec(),
                fetched_at: Instant::now(),
            },
        );
    }

    fn store_record_cache(&self, advisory: &Arc<Advisory>) {
        if self.record_cache.len() >= MAX_CACHE_ENTRIES {
            crate::cache_policy::evict_oldest_batch(&self.record_cache, MAX_CACHE_ENTRIES, |e| {
                e.fetched_at
            });
        }
        self.record_cache.insert(
            advisory.id.clone(),
            RecordCacheEntry {
                advisory: Arc::clone(advisory),
                modified: advisory.modified.clone(),
                fetched_at: Instant::now(),
            },
        );
    }
}

/// Marks every dependency in a failed chunk as [`SkipReason::QueryFailed`].
fn mark_chunk_failed(chunk: &[ScanTarget], outcomes: &mut VulnerabilityMap) {
    for t in chunk {
        outcomes.insert(t.key.clone(), ScanOutcome::Skipped(SkipReason::QueryFailed));
    }
}

/// Logs the `info`-level scan summary mandated by §8 invariant 0.
fn log_scan_summary(outcomes: &VulnerabilityMap) {
    let mut clean = 0usize;
    let mut vulnerable = 0usize;
    let mut skip_counts: HashMap<&'static str, usize> = HashMap::new();

    for outcome in outcomes.values() {
        match outcome {
            ScanOutcome::Clean => clean += 1,
            ScanOutcome::Vulnerable(_) => vulnerable += 1,
            ScanOutcome::Skipped(reason) => {
                *skip_counts.entry(reason.as_str()).or_insert(0) += 1;
            }
        }
    }

    let skipped: usize = skip_counts.values().sum();
    let reasons = skip_counts
        .iter()
        .map(|(reason, count)| format!("{count} {reason}"))
        .collect::<Vec<_>>()
        .join(", ");

    tracing::info!(
        "OSV: scanned {}, clean {clean}, vulnerable {vulnerable}, skipped {skipped}{}",
        outcomes.len(),
        if reasons.is_empty() {
            String::new()
        } else {
            format!(" ({reasons})")
        }
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConcreteVersion, EcosystemId};
    use std::assert_matches;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn client() -> OsvClient {
        OsvClient::new(Arc::new(HttpCache::new()))
    }

    async fn mock_client() -> (mockito::ServerGuard, OsvClient) {
        let server = mockito::Server::new_async().await;
        let client = OsvClient::with_base_url(Arc::new(HttpCache::new()), server.url());
        (server, client)
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    fn target(name: &str, version: &str) -> ScanTarget {
        ScanTarget {
            key: crate::test_util::vuln_key(name),
            osv_name: name.to_string(),
            version: OsvVersion::new(version),
            display_version: ConcreteVersion::new(version),
        }
    }

    #[test]
    fn compare_version_strings_orders_numerically() {
        let mut versions = vec![
            "0.2.10".to_string(),
            "0.2.2".to_string(),
            "0.2.23".to_string(),
            "0.2.0".to_string(),
        ];
        versions.sort_by(|a, b| compare_version_strings(a, b));
        assert_eq!(versions, vec!["0.2.0", "0.2.2", "0.2.10", "0.2.23"]);
    }

    /// A PEP 440 release candidate must never outrank its own release when the leading
    /// numeric dot-segments tie — a bare lexicographic fallback puts `2.2.0rc0` after
    /// `2.2.0` (longer string, same prefix), which would let a pre-release "win" as
    /// `recommended_fix`'s target.
    #[test]
    fn compare_version_strings_prefers_plain_release_over_same_prefix_prerelease() {
        assert_eq!(
            compare_version_strings("2.2.0", "2.2.0rc0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("2.2.0rc0", "2.2.0"),
            std::cmp::Ordering::Less
        );

        let mut versions = vec!["2.2.0rc0".to_string(), "2.2.0".to_string()];
        versions.sort_by(|a, b| compare_version_strings(a, b));
        assert_eq!(versions, vec!["2.2.0rc0", "2.2.0"]);
    }

    /// impl-critic S1: the undotted-suffix case above (`2.2.0rc0`) is not representative —
    /// SemVer's own spec (and Cargo/npm/NuGet, which follow it) always separates a pre-release
    /// identifier with a `-`, usually followed by further dot segments. A fix must not only
    /// tie-break on the exact leading digit segments matching; it must recognize that
    /// `"2.0.0-rc.1"`'s *release* is `2.0.0`, the same as bare `"2.0.0"`.
    #[test]
    fn compare_version_strings_prefers_plain_release_over_dotted_semver_prerelease() {
        assert_eq!(
            compare_version_strings("2.0.0", "2.0.0-rc.1"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("1.0.0", "1.0.0-beta.2"),
            std::cmp::Ordering::Greater
        );

        let mut versions = vec!["2.0.0-rc.1".to_string(), "2.0.0".to_string()];
        versions.sort_by(|a, b| compare_version_strings(a, b));
        assert_eq!(versions, vec!["2.0.0-rc.1", "2.0.0"]);
    }

    /// impl-critic S1: PEP 440's `.dev0`/`rc1.dev0` and Go's pseudo-version suffixes are also
    /// dotted or hyphen-separated past the release segments — the same bug class as the SemVer
    /// case above, for different ecosystems.
    #[test]
    fn compare_version_strings_prefers_plain_release_over_pep440_and_go_pseudo_suffixes() {
        assert_eq!(
            compare_version_strings("2.2.0", "2.2.0.dev0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("2.2.0", "2.2.0rc1.dev0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("1.2.4", "1.2.4-0.20210101000000-abcdef123456"),
            std::cmp::Ordering::Greater
        );
    }

    /// Tester gap: an unrelated, lower pre-release must still lose to a higher plain release
    /// purely on the leading numeric segments — the plain-release tie-break must only kick in
    /// once the release segments already tie, never override a genuine version difference.
    #[test]
    fn compare_version_strings_numeric_ordering_still_wins_over_prerelease_tiebreak() {
        assert_eq!(
            compare_version_strings("2.2.0", "1.9.0rc1"),
            std::cmp::Ordering::Greater
        );
    }

    /// Code-review regression: without stripping a leading `v`/`V` tag-prefix marker first,
    /// the marker itself was the first non-digit-non-dot character in the whole string, so
    /// `release_prefix` collapsed to empty for both operands and the comparison fell through to
    /// a purely lexicographic (character-by-character) compare — wrongly ranking `v1.20.3`
    /// below `v1.3.10` (`'2' < '3'` at the second character) even though `20 > 3`.
    #[test]
    fn compare_version_strings_strips_leading_tag_prefix_before_ranking() {
        assert_eq!(
            compare_version_strings("v1.20.3", "v1.3.10"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_version_strings("V1.20.3", "v1.3.10"),
            std::cmp::Ordering::Greater
        );

        let mut versions = vec!["v1.3.10".to_string(), "v1.20.3".to_string()];
        versions.sort_by(|a, b| compare_version_strings(a, b));
        assert_eq!(versions, vec!["v1.3.10", "v1.20.3"]);
    }

    #[tokio::test]
    async fn scan_empty_input_returns_empty_map() {
        let client = client();
        let outcomes = client.scan(EcosystemId::Cargo, &[], TEST_TIMEOUT).await;
        assert!(outcomes.is_empty());
    }

    #[tokio::test]
    async fn check_candidates_empty_input_returns_empty_map() {
        let client = client();
        let statuses = client
            .check_candidates(EcosystemId::Cargo, &[], TEST_TIMEOUT)
            .await;
        assert!(statuses.is_empty());
    }

    #[tokio::test]
    async fn scan_all_clean_batch_result() {
        let (mut server, client) = mock_client().await;
        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .create_async()
            .await;

        let targets = vec![target("left-pad", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        assert_eq!(outcomes.len(), 1);
        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("left-pad")),
            Some(ScanOutcome::Clean)
        );
    }

    #[tokio::test]
    async fn scan_batch_http_400_skips_whole_chunk() {
        let (mut server, client) = mock_client().await;
        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(400)
            .with_body(r#"{"code":3,"message":"error in query at index 0"}"#)
            .create_async()
            .await;

        let targets = vec![target("a", "1.0.0"), target("b", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        assert_eq!(outcomes.len(), 2);
        for key in ["a", "b"] {
            assert_matches!(
                outcomes.get(&crate::test_util::vuln_key(key)),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            );
        }
    }

    #[tokio::test]
    async fn scan_malformed_batch_json_skips_whole_chunk() {
        let (mut server, client) = mock_client().await;
        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body("not json")
            .create_async()
            .await;

        let targets = vec![target("a", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("a")),
            Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
        );
    }

    #[tokio::test]
    async fn scan_deeply_nested_batch_json_skips_whole_chunk() {
        // #430: a deeply nested array must be rejected by the depth guard before
        // `serde_json::from_slice` sees it — cheaper than relying on serde_json's own limit.
        let (mut server, client) = mock_client().await;
        let deeply_nested = format!(
            "{}1{}",
            "[".repeat(crate::parser::MAX_JSON_NESTING_DEPTH + 1),
            "]".repeat(crate::parser::MAX_JSON_NESTING_DEPTH + 1)
        );
        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(format!(
                r#"{{"results":[{{"vulns":[{{"id":"ADV-1","modified":"2023-01-01T00:00:00Z","database_specific":{deeply_nested}}}]}}]}}"#
            ))
            .create_async()
            .await;

        let targets = vec![target("pkg", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("pkg")),
            Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
        );
    }

    #[tokio::test]
    async fn scan_result_count_mismatch_drops_whole_chunk() {
        let (mut server, client) = mock_client().await;
        // Two queries sent, only one result returned.
        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .create_async()
            .await;

        let targets = vec![target("a", "1.0.0"), target("b", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        for key in ["a", "b"] {
            assert_matches!(
                outcomes.get(&crate::test_util::vuln_key(key)),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            );
        }
    }

    #[tokio::test]
    async fn scan_over_chunk_size_input_issues_exactly_two_batch_requests() {
        let (mut server, client) = mock_client().await;

        let n = BATCH_CHUNK_SIZE + 1;
        let targets: Vec<ScanTarget> = (0..n)
            .map(|i| target(&format!("pkg-{i}"), "1.0.0"))
            .collect();

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body_from_request(move |req| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                let body = req.body().expect("request body");
                let parsed: serde_json::Value =
                    serde_json::from_slice(body).expect("valid JSON request body");
                let count = parsed["queries"].as_array().map_or(0, Vec::len);
                let results = vec!["{}"; count].join(",");
                format!(r#"{{"results":[{results}]}}"#).into_bytes()
            })
            .expect(2)
            .create_async()
            .await;

        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        assert_eq!(outcomes.len(), n);
        assert!(outcomes.values().all(|o| matches!(o, ScanOutcome::Clean)));
        batch.assert_async().await;
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "a >1000-entry scan must issue exactly two chunked batch requests"
        );
    }

    #[tokio::test]
    async fn scan_deadline_exceeded_before_first_chunk_marks_everything_query_failed() {
        let (_server, client) = mock_client().await;
        // No mock registered at all: `client` still points at a live mockito
        // server with no matching route, so a would-be request 404s — but
        // the zero-duration deadline must make `resolve` bail before ever
        // sending it, proving the deadline check runs before network I/O.
        let targets = vec![target("a", "1.0.0"), target("b", "1.0.0")];
        let outcomes = client
            .scan(EcosystemId::Npm, &targets, Duration::from_secs(0))
            .await;

        for key in ["a", "b"] {
            assert_matches!(
                outcomes.get(&crate::test_util::vuln_key(key)),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            );
        }
    }

    #[tokio::test]
    async fn scan_filters_affected_entries_to_the_queried_package() {
        // Critique S3: a record can cover several unrelated packages sharing
        // one advisory id (e.g. log4j-core/log4j-api). Only the entry whose
        // `package` matches the queried package must contribute
        // fixed_versions/severity.
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[{"id":"GHSA-cross-pkg","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/GHSA-cross-pkg")
            .with_status(200)
            .with_body(
                r#"{"id":"GHSA-cross-pkg","modified":"2023-01-01T00:00:00Z",
                   "affected":[
                     {"package":{"name":"log4j-api","ecosystem":"Maven"},
                      "ecosystem_specific":{"severity":"LOW"},
                      "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.0.0"}]}]},
                     {"package":{"name":"log4j-core","ecosystem":"Maven"},
                      "ecosystem_specific":{"severity":"CRITICAL"},
                      "ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"2.17.1"}]}]}
                   ]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("log4j-core", "2.14.1")];
        let outcomes = client
            .scan(EcosystemId::Maven, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) =
            outcomes.get(&crate::test_util::vuln_key("log4j-core"))
        else {
            panic!("expected Vulnerable outcome");
        };
        // Must pick up log4j-core's own severity/fix, not log4j-api's.
        assert_eq!(dv.advisories.items()[0].severity, VulnSeverity::Critical);
        assert_eq!(
            dv.advisories.items()[0].fixed_versions,
            vec![OsvVersion::new("2.17.1")]
        );
    }

    #[tokio::test]
    async fn scan_malformed_advisory_id_is_dropped() {
        // Critique M1: `id` is echoed into a markdown link destination and a
        // Diagnostic.code; a malformed id must never survive into an
        // `Advisory`.
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[{"id":"evil](javascript:alert(1))","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("pkg", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        // total() still counts the batch stub; the malformed-id record
        // is dropped rather than rendered with an unsafe id.
        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key("pkg"))
        else {
            panic!(
                "expected Vulnerable outcome, got {:?}",
                outcomes.get(&crate::test_util::vuln_key("pkg"))
            );
        };
        assert_eq!(dv.advisories.total(), 1);
        assert!(dv.advisories.items().is_empty());
    }

    #[tokio::test]
    async fn recover_truncated_single_query_that_itself_paginates_is_skipped_truncated() {
        // Critique S4: `/v1/query` can itself paginate; a `next_page_token`
        // on that response must never be trusted as a complete `vulns` list.
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{"next_page_token":"abc"}]}"#)
            .create_async()
            .await;
        let _requery = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_body(
                r#"{"vulns":[{"id":"GHSA-1","modified":"2023-01-01T00:00:00Z"}],"next_page_token":"still-more"}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("linux", "5.10.1")];
        let outcomes = client.scan(EcosystemId::Go, &targets, TEST_TIMEOUT).await;

        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("linux")),
            Some(ScanOutcome::Skipped(SkipReason::Truncated))
        );
    }

    /// Issue #1539: `recover_truncated`'s permit wait must also fail closed at the scan
    /// deadline — the same bound as `fetch_record_single_flight`, exercised end-to-end through
    /// `scan` with the client-wide semaphore held externally so the requery can never acquire a
    /// permit before the deadline elapses. Budget widened to 1s (critique M3) to comfortably
    /// cover the mock-server round trip on a slow CI runner without risking the pre-recovery
    /// deadline check (mod.rs `resolve`) firing first and yielding `Truncated` instead of the
    /// `QueryFailed` this test targets; the whole call is wrapped in an outer test timeout
    /// (critique M2) so a regression fails this test rather than hanging CI.
    #[tokio::test]
    async fn recover_truncated_permit_wait_bounded_by_deadline_fails_query_failed() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{"next_page_token":"abc"}]}"#)
            .create_async()
            .await;

        let _permits: Vec<_> = futures::future::join_all(
            (0..RECORD_FETCH_CONCURRENCY)
                .map(|_| Arc::clone(&client.record_fetch_semaphore).acquire_owned()),
        )
        .await
        .into_iter()
        .map(|permit| permit.expect("semaphore is not closed"))
        .collect();

        let targets = vec![target("linux", "5.10.1")];
        let outcomes = tokio::time::timeout(
            Duration::from_secs(10),
            client.scan(EcosystemId::Go, &targets, Duration::from_secs(1)),
        )
        .await
        .expect("the requery must fail at the deadline, not hang until a permit frees up");

        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("linux")),
            Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
        );
    }

    #[tokio::test]
    async fn scan_vulnerable_fetches_advisory_record() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{"vulns":[{"id":"RUSTSEC-2020-0071","modified":"2023-01-01T00:00:00Z"}]}]}"#)
            .create_async()
            .await;
        // Real shape of RUSTSEC-2020-0071's `affected[].ranges` (architecture.md §6): 8
        // `fixed` events across several ranges, deliberately out of order so a "take the
        // last event, no sort" bug wouldn't be caught by a trivially-ordered fixture. First
        // `fixed` in document order is `0.2.0`; the highest (real guidance) is `0.2.23`.
        let _record = server
            .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
            .with_status(200)
            .with_body(
                r#"{"id":"RUSTSEC-2020-0071","modified":"2023-01-01T00:00:00Z",
                   "summary":"Potential segfault","database_specific":{"severity":"HIGH"},
                   "affected":[
                     {"package":{"name":"time","ecosystem":"crates.io"},"ranges":[
                       {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.0"},{"fixed":"0.1.44"}]},
                       {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.4"},{"fixed":"0.1.43"}]},
                       {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.2"},{"fixed":"0.2.23"}]},
                       {"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.1"},{"fixed":"0.2.3"}]}
                     ]}
                   ]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("time", "0.1.43")];
        let outcomes = client
            .scan(EcosystemId::Cargo, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key("time"))
        else {
            panic!(
                "expected Vulnerable outcome, got {:?}",
                outcomes.get(&crate::test_util::vuln_key("time"))
            );
        };
        assert_eq!(dv.advisories.total(), 1);
        assert_eq!(dv.advisories.items().len(), 1);
        assert_eq!(dv.advisories.items()[0].id, "RUSTSEC-2020-0071");
        assert_eq!(dv.advisories.items()[0].severity, VulnSeverity::High);
        assert_eq!(
            dv.advisories.items()[0].fixed_versions,
            vec![
                "0.1.43", "0.1.44", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.23"
            ]
            .into_iter()
            .map(OsvVersion::new)
            .collect::<Vec<_>>()
        );
        // The highest fixed version, not the first in document order.
        assert_eq!(
            dv.advisories.items()[0].fixed_versions.last(),
            Some(&OsvVersion::new("0.2.23"))
        );
    }

    #[tokio::test]
    async fn scan_dropped_advisory_record_still_yields_vulnerable_with_fewer_advisories() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[{"id":"MISSING-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/MISSING-1")
            .with_status(404)
            .create_async()
            .await;

        let targets = vec![target("pkg", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        // total() still reflects the batch stub count; the failed fetch
        // is dropped rather than rendered half-populated.
        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key("pkg"))
        else {
            panic!(
                "expected Vulnerable outcome, got {:?}",
                outcomes.get(&crate::test_util::vuln_key("pkg"))
            );
        };
        assert_eq!(dv.advisories.total(), 1);
        assert!(dv.advisories.items().is_empty());
    }

    #[tokio::test]
    async fn scan_next_page_token_is_never_rendered_as_clean() {
        let (mut server, client) = mock_client().await;
        // No `vulns` key at all — only `next_page_token` — per the live-verified
        // truncation shape in architecture.md §8 invariant 2.
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{"next_page_token":"abc"}]}"#)
            .create_async()
            .await;
        let _requery = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_body(
                r#"{"vulns":[{"id":"GHSA-1","modified":"2023-01-01T00:00:00Z","database_specific":{"severity":"CRITICAL"}}]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("linux", "5.10.1")];
        let outcomes = client.scan(EcosystemId::Go, &targets, TEST_TIMEOUT).await;

        let Some(outcome) = outcomes.get(&crate::test_util::vuln_key("linux")) else {
            panic!("dependency missing from outcome map");
        };
        assert!(
            !matches!(outcome, ScanOutcome::Clean),
            "a truncated batch result must never render as clean"
        );
        assert_matches!(outcome, ScanOutcome::Vulnerable(_));
    }

    #[tokio::test]
    async fn scan_advisory_fetch_is_capped_but_total_known_reflects_full_count() {
        let (mut server, client) = mock_client().await;

        let vuln_count = MAX_ADVISORY_RECORDS + 10;
        let vulns_json: String = (0..vuln_count)
            .map(|i| format!(r#"{{"id":"ADV-{i}","modified":"2023-01-01T00:00:00Z"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(format!(r#"{{"results":[{{"vulns":[{vulns_json}]}}]}}"#))
            .create_async()
            .await;

        // Only expect fetches for however many the cap allows.
        let record = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/v1/vulns/ADV-\d+$".into()),
            )
            .with_status(200)
            .with_body(r#"{"id":"ADV-x","modified":"2023-01-01T00:00:00Z"}"#)
            .expect(MAX_ADVISORY_RECORDS)
            .create_async()
            .await;

        let targets = vec![target("rack", "2.0.5")];
        let outcomes = client
            .scan(EcosystemId::Bundler, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key("rack"))
        else {
            panic!("expected Vulnerable outcome");
        };
        assert_eq!(dv.advisories.total(), vuln_count);
        // The fix-computation set is capped at MAX_ADVISORY_RECORDS, well beyond what
        // ADVISORY_DISPLAY_CAP alone would allow (#1422) ...
        assert_eq!(dv.advisories.items().len(), MAX_ADVISORY_RECORDS);
        // ... but rendering still truncates to ADVISORY_DISPLAY_CAP.
        assert_eq!(
            dv.advisories_for_display().items().len(),
            ADVISORY_DISPLAY_CAP
        );
        assert_eq!(dv.advisories_for_display().total(), vuln_count);
        record.assert_async().await;
    }

    #[tokio::test]
    async fn scan_recommended_fix_considers_advisories_beyond_display_cap() {
        // #1422: reproduces the golang.org/x/net repro (18 advisories; the true highest
        // `fixed` version sits on an advisory OSV returns after the first ADVISORY_DISPLAY_CAP
        // records). `recommended_fix()` must not silently pick a lower version just because
        // the display cap used to also bound the fetch.
        let (mut server, client) = mock_client().await;

        let advisory_count = 18;
        let vulns_json: String = (0..advisory_count)
            .map(|i| format!(r#"{{"id":"ADV-{i}","modified":"2023-01-01T00:00:00Z"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(format!(r#"{{"results":[{{"vulns":[{vulns_json}]}}]}}"#))
            .create_async()
            .await;

        for i in 0..advisory_count {
            // Only the last advisory (well beyond ADVISORY_DISPLAY_CAP=5) carries the true
            // highest fix — every other one fixes at a lower version.
            let fixed = if i == advisory_count - 1 {
                "0.56.0"
            } else {
                "0.20.0"
            };
            let _record = server
                .mock("GET", format!("/v1/vulns/ADV-{i}").as_str())
                .with_status(200)
                .with_body(format!(
                    r#"{{"id":"ADV-{i}","modified":"2023-01-01T00:00:00Z",
                       "database_specific":{{"severity":"HIGH"}},
                       "affected":[{{"package":{{"name":"golang.org/x/net","ecosystem":"Go"}},
                         "ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
                ))
                .create_async()
                .await;
        }

        let targets = vec![target("golang.org/x/net", "0.17.0")];
        let outcomes = client.scan(EcosystemId::Go, &targets, TEST_TIMEOUT).await;

        let Some(ScanOutcome::Vulnerable(dv)) =
            outcomes.get(&crate::test_util::vuln_key("golang.org/x/net"))
        else {
            panic!("expected Vulnerable outcome");
        };

        assert_eq!(dv.advisories.total(), advisory_count);
        assert_eq!(
            dv.advisories.items().len(),
            advisory_count,
            "every advisory must be fetched: advisory_count is well under MAX_ADVISORY_RECORDS"
        );

        let fix = dv.recommended_fix(None).expect("a fix must be recommended");
        assert_eq!(
            fix.version, "0.56.0",
            "recommended_fix must consider the advisory beyond ADVISORY_DISPLAY_CAP"
        );

        let display = dv.advisories_for_display();
        assert_eq!(
            display.items().len(),
            ADVISORY_DISPLAY_CAP,
            "rendering must still truncate to ADVISORY_DISPLAY_CAP"
        );
        assert_eq!(display.total(), advisory_count);
    }

    #[tokio::test]
    async fn scan_second_call_within_ttl_issues_zero_requests() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        let targets = vec![target("pkg", "1.0.0")];
        client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;
        client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        batch.assert_async().await;
    }

    #[tokio::test]
    async fn check_candidates_maps_clean_and_vulnerable() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{},{"vulns":[{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/ADV-1")
            .with_status(200)
            .with_body(r#"{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}"#)
            .create_async()
            .await;

        let candidates = vec![target("clean-pkg", "2.0.0"), target("bad-pkg", "2.0.0")];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("clean-pkg")),
            Some(UpgradeStatus::CandidateClean { version }) if version == "2.0.0"
        );
        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("bad-pkg")),
            Some(UpgradeStatus::CandidateVulnerable { version, advisory_ids, .. })
                if version == "2.0.0"
                    && advisory_ids.items() == ["ADV-1".to_string()]
                    && advisory_ids.total() == 1
        );
    }

    /// Issue #1655: candidates sharing a `VulnKey` (one dependency declared in several
    /// sections) must all reflect the one real OSV outcome, not a spurious `QueryFailed`.
    #[tokio::test]
    async fn check_candidates_duplicate_keys_share_the_real_outcome() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        let candidates = vec![target("dup", "2.0.0"), target("dup", "2.0.0")];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        batch.assert_async().await;
        assert_eq!(statuses.len(), 1);
        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("dup")),
            Some(UpgradeStatus::CandidateClean { version }) if version == "2.0.0"
        );
    }

    #[tokio::test]
    async fn check_candidates_three_duplicates_share_one_query_and_outcome() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        let candidates = vec![
            target("dup", "2.0.0"),
            target("dup", "2.0.0"),
            target("dup", "2.0.0"),
        ];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        batch.assert_async().await;
        assert_eq!(statuses.len(), 1);
        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("dup")),
            Some(UpgradeStatus::CandidateClean { .. })
        );
    }

    #[tokio::test]
    async fn check_candidates_mixed_duplicate_and_unique_keys_keep_their_own_outcomes() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{},{"vulns":[{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/ADV-1")
            .with_status(200)
            .with_body(r#"{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}"#)
            .create_async()
            .await;

        let candidates = vec![
            target("dup", "2.0.0"),
            target("other", "3.0.0"),
            target("dup", "2.0.0"),
        ];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        assert_eq!(statuses.len(), 2);
        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("dup")),
            Some(UpgradeStatus::CandidateClean { version }) if version == "2.0.0"
        );
        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("other")),
            Some(UpgradeStatus::CandidateVulnerable { version, advisory_ids, .. })
                if version == "3.0.0" && advisory_ids.items() == ["ADV-1".to_string()]
        );
    }

    #[tokio::test]
    async fn check_candidates_vulnerable_duplicates_carry_advisories() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/ADV-1")
            .with_status(200)
            .with_body(r#"{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}"#)
            .create_async()
            .await;

        let candidates = vec![target("dup", "2.0.0"), target("dup", "2.0.0")];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("dup")),
            Some(UpgradeStatus::CandidateVulnerable { advisory_ids, .. })
                if advisory_ids.items() == ["ADV-1".to_string()] && advisory_ids.total() == 1
        );
    }

    #[tokio::test]
    async fn scan_duplicate_keys_are_queried_once_and_keep_their_own_outcomes() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{},{"vulns":[{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let _record = server
            .mock("GET", "/v1/vulns/ADV-1")
            .with_status(200)
            .with_body(r#"{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}"#)
            .create_async()
            .await;

        let targets = vec![
            target("dup", "2.0.0"),
            target("other", "3.0.0"),
            target("dup", "2.0.0"),
        ];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        batch.assert_async().await;
        assert_eq!(outcomes.len(), 2);
        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("dup")),
            Some(ScanOutcome::Clean)
        );
        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("other")),
            Some(ScanOutcome::Vulnerable(_))
        );
    }

    /// Same key with a different version is unreachable from the builders (the key encodes the
    /// in-use signature); `resolve` pins first-wins should it ever happen.
    #[tokio::test]
    async fn resolve_same_key_different_version_queries_only_the_first() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        let targets = vec![target("dup", "1.0.0"), target("dup", "2.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        batch.assert_async().await;
        assert_eq!(outcomes.len(), 1);
        assert_matches!(
            outcomes.get(&crate::test_util::vuln_key("dup")),
            Some(ScanOutcome::Clean)
        );
    }

    #[tokio::test]
    async fn check_candidates_duplicate_keys_all_unverified_when_query_fails() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(500)
            .create_async()
            .await;

        let candidates = vec![target("dup", "2.0.0"), target("dup", "2.0.0")];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("dup")),
            Some(UpgradeStatus::CandidateUnverified {
                reason: SkipReason::QueryFailed,
                ..
            })
        );
    }

    /// Issue #1517: `check_candidates` must never silently drop a target it queried —
    /// [`SkipReason::UnmappableEcosystem`] (a whole-batch skip, since GitLab CI has no
    /// `osv_ecosystem`) must surface as `CandidateUnverified`, not an absent map entry.
    #[tokio::test]
    async fn check_candidates_maps_unmappable_ecosystem_to_candidate_unverified() {
        let client = client();
        let candidates = vec![target("pkg", "2.0.0")];

        let statuses = client
            .check_candidates(EcosystemId::GitlabCi, &candidates, TEST_TIMEOUT)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("pkg")),
            Some(UpgradeStatus::CandidateUnverified {
                version,
                reason: SkipReason::UnmappableEcosystem
            }) if version == "2.0.0"
        );
    }

    /// Issue #1517 critique S2: a record that failed to fetch must never be silently excluded
    /// from `worst_severity`'s input — an `Informational`-only record that *did* fetch,
    /// alongside a second, unfetched record, must not read as `Some(Informational)` (which
    /// `latest_verdict` treats as `Verified`, the exact fail-open gap S2 found). `worst_severity`
    /// must come back `None` (blocking, per `CandidateVulnerable::worst_severity`'s own
    /// contract) whenever `advisories.items().len() < advisories.total()`.
    #[tokio::test]
    async fn check_candidates_forces_none_severity_when_a_record_failed_to_fetch() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[
                    {"id":"ADV-OK","modified":"2023-01-01T00:00:00Z"},
                    {"id":"ADV-MISSING","modified":"2023-01-01T00:00:00Z"}
                ]}]}"#,
            )
            .create_async()
            .await;
        let _fetched = server
            .mock("GET", "/v1/vulns/ADV-OK")
            .with_status(200)
            .with_body(r#"{"id":"ADV-OK","modified":"2023-01-01T00:00:00Z"}"#)
            .create_async()
            .await;
        let _missing = server
            .mock("GET", "/v1/vulns/ADV-MISSING")
            .with_status(500)
            .create_async()
            .await;

        let candidates = vec![target("bad-pkg", "2.0.0")];
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, TEST_TIMEOUT)
            .await;

        let Some(UpgradeStatus::CandidateVulnerable {
            advisory_ids,
            worst_severity,
            ..
        }) = statuses.get(&crate::test_util::vuln_key("bad-pkg"))
        else {
            panic!(
                "expected CandidateVulnerable, got {:?}",
                statuses.get(&crate::test_util::vuln_key("bad-pkg"))
            );
        };
        assert_eq!(advisory_ids.items(), ["ADV-OK".to_string()]);
        assert_eq!(
            advisory_ids.total(),
            2,
            "the unfetched record still counts toward total"
        );
        assert_eq!(
            *worst_severity, None,
            "an incomplete advisory set must never report a severity — the caller's \
             `latest_verdict` treats only `Some(Informational)` as non-blocking, and `None` \
             must stay blocking (Flagged), never silently pass as clean"
        );
    }

    /// Issue #1517 critique S6: `check_candidates` must never silently drop a target whose
    /// query never even got a chance to run because the deadline had already elapsed —
    /// [`resolve`](OsvClient::resolve)'s own deadline check (checked before each chunk) marks
    /// the whole remaining batch [`SkipReason::QueryFailed`], and `check_candidates` must map
    /// that to [`UpgradeStatus::CandidateUnverified`], the fail-closed outcome every caller's
    /// [`crate::lsp_helpers::latest_verdict`] treats as `Unverified`, never as an absent
    /// (implicitly "safe") entry.
    #[tokio::test]
    async fn check_candidates_deadline_exceeded_yields_candidate_unverified() {
        let client = client();
        let candidates = vec![target("pkg", "2.0.0")];

        // A zero-duration budget: `resolve`'s deadline (`Instant::now() + timeout`) has
        // already elapsed by the time the first chunk is checked, before any network call.
        let statuses = client
            .check_candidates(EcosystemId::Npm, &candidates, Duration::ZERO)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("pkg")),
            Some(UpgradeStatus::CandidateUnverified {
                version,
                reason: SkipReason::QueryFailed,
            }) if version == "2.0.0"
        );
    }

    #[tokio::test]
    async fn check_candidates_uses_display_version_not_wire_version() {
        // S1 regression guard: `ScanTarget.version` is the OSV wire spelling, but
        // `UpgradeStatus` is rendered to the user and must carry `display_version` instead.
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .create_async()
            .await;

        let candidate = ScanTarget {
            key: crate::test_util::vuln_key("golang.org/x/text"),
            osv_name: "golang.org/x/text".to_string(),
            version: OsvVersion::new("0.4.0"),
            display_version: ConcreteVersion::new("v0.4.0"),
        };
        let statuses = client
            .check_candidates(EcosystemId::Go, &[candidate], TEST_TIMEOUT)
            .await;

        assert_matches!(
            statuses.get(&crate::test_util::vuln_key("golang.org/x/text")),
            Some(UpgradeStatus::CandidateClean { version }) if version == "v0.4.0"
        );
    }

    #[test]
    fn query_cache_evicts_oldest_when_max_entries_reached() {
        let client = client();
        for i in 0..MAX_CACHE_ENTRIES {
            client.store_query_cache(
                OsvEcosystem::Npm,
                &target(&format!("pkg-{i}"), "1.0.0"),
                &[],
            );
        }
        assert_eq!(client.query_cache.len(), MAX_CACHE_ENTRIES);

        client.store_query_cache(OsvEcosystem::Npm, &target("overflow", "1.0.0"), &[]);

        assert!(
            client.query_cache.len() <= MAX_CACHE_ENTRIES,
            "query_cache must stay bounded at MAX_CACHE_ENTRIES, got {}",
            client.query_cache.len()
        );
        assert!(client.query_cache.len() < MAX_CACHE_ENTRIES + 1);
    }

    #[test]
    fn record_cache_evicts_oldest_when_max_entries_reached() {
        let client = client();
        for i in 0..MAX_CACHE_ENTRIES {
            let advisory = Arc::new(
                Advisory::new(
                    format!("ADV-{i}"),
                    "2023-01-01T00:00:00Z".to_string(),
                    VulnSeverity::Unknown,
                )
                .expect("valid osv id"),
            );
            client.store_record_cache(&advisory);
        }
        assert_eq!(client.record_cache.len(), MAX_CACHE_ENTRIES);

        let overflow = Arc::new(
            Advisory::new(
                "ADV-overflow".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::Unknown,
            )
            .expect("valid osv id"),
        );
        client.store_record_cache(&overflow);

        assert!(
            client.record_cache.len() <= MAX_CACHE_ENTRIES,
            "record_cache must stay bounded at MAX_CACHE_ENTRIES, got {}",
            client.record_cache.len()
        );
    }

    #[tokio::test]
    async fn query_cache_ttl_expiry_forces_requery() {
        let (mut server, client) = mock_client().await;
        let t = target("pkg", "1.0.0");

        client.query_cache.insert(
            (OsvEcosystem::Npm, t.osv_name.clone(), t.version.clone()),
            QueryCacheEntry {
                vuln_ids: vec![],
                fetched_at: Instant::now()
                    .checked_sub(QUERY_CACHE_TTL + Duration::from_secs(1))
                    .expect("test clock has more than QUERY_CACHE_TTL of headroom"),
            },
        );

        let batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .expect(1)
            .create_async()
            .await;

        client.scan(EcosystemId::Npm, &[t], TEST_TIMEOUT).await;

        batch.assert_async().await;
    }

    #[tokio::test]
    async fn record_cache_newer_modified_invalidates_and_refetches() {
        let (mut server, client) = mock_client().await;

        client.record_cache.insert(
            "ADV-1".to_string(),
            RecordCacheEntry {
                advisory: Arc::new(
                    Advisory::new(
                        "ADV-1".to_string(),
                        "2020-01-01T00:00:00Z".to_string(),
                        VulnSeverity::Unknown,
                    )
                    .expect("valid osv id")
                    .with_summary("stale summary".to_string()),
                ),
                modified: "2020-01-01T00:00:00Z".to_string(),
                fetched_at: Instant::now(),
            },
        );

        let _batch = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .with_body(
                r#"{"results":[{"vulns":[{"id":"ADV-1","modified":"2023-01-01T00:00:00Z"}]}]}"#,
            )
            .create_async()
            .await;
        let record = server
            .mock("GET", "/v1/vulns/ADV-1")
            .with_status(200)
            .with_body(
                r#"{"id":"ADV-1","modified":"2023-01-01T00:00:00Z","summary":"updated summary"}"#,
            )
            .expect(1)
            .create_async()
            .await;

        let targets = vec![target("pkg", "1.0.0")];
        let outcomes = client.scan(EcosystemId::Npm, &targets, TEST_TIMEOUT).await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get(&crate::test_util::vuln_key("pkg"))
        else {
            panic!("expected Vulnerable outcome");
        };
        assert_eq!(
            dv.advisories.items()[0].summary.as_deref(),
            Some("updated summary")
        );
        record.assert_async().await;
    }

    /// A minimal raw-TCP `GET /v1/vulns/{id}` responder for the concurrency tests below.
    ///
    /// `mockito` 1.7.2 has no delay/hold-open API, so it can't force concurrent requests to
    /// overlap deterministically — a real accept loop with an artificial per-request delay is
    /// the only way to make "N requests were in flight at once" or "only one request landed"
    /// assertions reliable rather than racy. Returns the listener address, the current-in-flight
    /// counter, the peak-in-flight watermark, and the total-accepted-connections counter.
    async fn spawn_mock_vuln_server(
        delay: Duration,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener has a local addr");

        let in_flight = Arc::new(AtomicUsize::new(0));
        let watermark = Arc::new(AtomicUsize::new(0));
        let total = Arc::new(AtomicUsize::new(0));

        let (in_flight2, watermark2, total2) = (
            Arc::clone(&in_flight),
            Arc::clone(&watermark),
            Arc::clone(&total),
        );
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let (in_flight, watermark, total) = (
                    Arc::clone(&in_flight2),
                    Arc::clone(&watermark2),
                    Arc::clone(&total2),
                );
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let id = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .and_then(|path| path.rsplit('/').next())
                        .unwrap_or("unknown")
                        .to_string();

                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    watermark.fetch_max(now, Ordering::SeqCst);
                    total.fetch_add(1, Ordering::SeqCst);

                    tokio::time::sleep(delay).await;

                    let body = format!(r#"{{"id":"{id}","modified":"2023-01-01T00:00:00Z"}}"#);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;

                    in_flight.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        (addr, in_flight, watermark, total)
    }

    /// Issue #1535: `RECORD_FETCH_CONCURRENCY` must bound `fetch_record_single_flight`'s
    /// underlying HTTP fetches *client-wide*, not reset to a fresh window per call — a
    /// regression here (e.g. a semaphore constructed per-call instead of stored on `OsvClient`)
    /// would still pass every other test in this module, since none of them exercise
    /// cross-call concurrency.
    #[tokio::test]
    async fn record_fetch_semaphore_bounds_client_wide_concurrent_fetches() {
        let (addr, _in_flight, watermark, total) =
            spawn_mock_vuln_server(Duration::from_millis(50)).await;
        let client = Arc::new(OsvClient::with_base_url(
            Arc::new(HttpCache::new()),
            format!("http://{addr}"),
        ));

        let deadline = Instant::now() + Duration::from_secs(30);
        let handles: Vec<_> = (0..20)
            .map(|i| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .fetch_record_single_flight(&format!("ADVISORY-{i}"), deadline)
                        .await
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.await.expect("task did not panic").is_some());
        }

        let peak = watermark.load(Ordering::SeqCst);
        assert!(
            peak <= RECORD_FETCH_CONCURRENCY,
            "peak concurrent in-flight fetches ({peak}) exceeded the client-wide bound \
             ({RECORD_FETCH_CONCURRENCY})"
        );
        assert_eq!(
            total.load(Ordering::SeqCst),
            20,
            "all 20 distinct-id fetches must still land, just not all at once"
        );
    }

    /// Issue #1535: concurrent fetches of the *same* advisory id must coalesce into one
    /// in-flight `GET /v1/vulns/{id}` via `record_in_flight`'s single-flight `OnceCell`, not
    /// fire one request per caller.
    #[tokio::test]
    async fn fetch_record_single_flight_coalesces_concurrent_same_id_requests() {
        let (addr, _in_flight, _watermark, total) =
            spawn_mock_vuln_server(Duration::from_millis(50)).await;
        let client = Arc::new(OsvClient::with_base_url(
            Arc::new(HttpCache::new()),
            format!("http://{addr}"),
        ));

        let deadline = Instant::now() + Duration::from_secs(30);
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let client = Arc::clone(&client);
                tokio::spawn(
                    async move { client.fetch_record_single_flight("SAME-ID", deadline).await },
                )
            })
            .collect();

        for handle in handles {
            let record = handle.await.expect("task did not panic");
            assert_eq!(
                record.map(|r| r.id.clone()),
                Some("SAME-ID".to_string()),
                "every follower must observe the leader's real fetched value"
            );
        }

        assert_eq!(
            total.load(Ordering::SeqCst),
            1,
            "20 concurrent fetches of the same id must land exactly one HTTP request"
        );
    }

    /// Issue #1539: the permit wait itself must be bounded by the scan deadline, not only the
    /// per-chunk/per-requery checks around it — otherwise a scan can overrun its timeout window
    /// sitting in the semaphore queue under heavy client-wide load. No mock server is needed:
    /// the semaphore is saturated so the deadline must expire before any HTTP fetch is even
    /// attempted. The whole call is wrapped in an outer test timeout (critique M2) so a
    /// regression that reintroduces an unbounded wait fails this test rather than hanging CI.
    #[tokio::test]
    async fn fetch_record_single_flight_fails_fast_when_permit_wait_exceeds_deadline() {
        let client = client();

        let _permits: Vec<_> = futures::future::join_all(
            (0..RECORD_FETCH_CONCURRENCY)
                .map(|_| Arc::clone(&client.record_fetch_semaphore).acquire_owned()),
        )
        .await
        .into_iter()
        .map(|permit| permit.expect("semaphore is not closed"))
        .collect();

        let deadline = Instant::now() + Duration::from_millis(50);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.fetch_record_single_flight("UNREACHABLE-ID", deadline),
        )
        .await
        .expect("the wait must fail at the deadline, not hang until a permit frees up");

        assert!(
            result.is_none(),
            "a permit wait that outlives the deadline must fail closed, not eventually succeed"
        );
    }

    /// Issue #1539 code-review finding: a *solo* caller (no other caller ever waits on the same
    /// advisory id) that times out must still evict its own `record_in_flight` entry — the
    /// finding-#1 fix (only evicting on `Ok`) otherwise leaves nobody to ever clean it up, leaking
    /// one entry per unique id that times out with no follower for the client's lifetime.
    #[tokio::test]
    async fn fetch_record_single_flight_solo_caller_timeout_does_not_leak_in_flight_entry() {
        let client = client();

        let _permits: Vec<_> = futures::future::join_all(
            (0..RECORD_FETCH_CONCURRENCY)
                .map(|_| Arc::clone(&client.record_fetch_semaphore).acquire_owned()),
        )
        .await
        .into_iter()
        .map(|permit| permit.expect("semaphore is not closed"))
        .collect();

        let deadline = Instant::now() + Duration::from_millis(50);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client.fetch_record_single_flight("SOLO-ID", deadline),
        )
        .await
        .expect("a solo caller must fail at its own deadline, not hang");

        assert!(
            result.is_none(),
            "a solo caller's own timeout must fail closed"
        );
        assert!(
            !client.record_in_flight.contains_key("SOLO-ID"),
            "a solo caller's timeout must evict its own record_in_flight entry, not leak it \
             for the rest of the client's lifetime"
        );
    }

    /// Issue #1539 critique S1: `record_in_flight` is shared client-wide, so a caller joining a
    /// cell some other caller is already initializing must be bounded by *its own* deadline, not
    /// the initializer's. Caller A (near-expired deadline) starts initializing on a saturated
    /// semaphore; caller B (ample deadline) joins the same cell a moment later. Once A's timeout
    /// fires, `OnceCell::get_or_init`'s cancel-safety must let B take over its own initialization
    /// attempt with B's own deadline — proven here by releasing the permits only after A's
    /// deadline has elapsed but well before B's, so B can only succeed if it is not bound by A's
    /// (already-expired) deadline.
    #[tokio::test]
    async fn fetch_record_single_flight_bounds_each_caller_by_its_own_deadline() {
        let (addr, _in_flight, _watermark, _total) =
            spawn_mock_vuln_server(Duration::from_millis(10)).await;
        let client = Arc::new(OsvClient::with_base_url(
            Arc::new(HttpCache::new()),
            format!("http://{addr}"),
        ));

        let permits: Vec<_> = futures::future::join_all(
            (0..RECORD_FETCH_CONCURRENCY)
                .map(|_| Arc::clone(&client.record_fetch_semaphore).acquire_owned()),
        )
        .await
        .into_iter()
        .map(|permit| permit.expect("semaphore is not closed"))
        .collect();

        let short_deadline = Instant::now() + Duration::from_millis(50);
        let long_deadline = Instant::now() + Duration::from_secs(10);

        let a = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .fetch_record_single_flight("SHARED-ID", short_deadline)
                    .await
            }
        });
        // Give A time to become the cell's initializer (queued on the saturated semaphore)
        // before B joins the same in-flight cell.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let b = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .fetch_record_single_flight("SHARED-ID", long_deadline)
                    .await
            }
        });

        // Release the permits only once A's own deadline has certainly elapsed — B must not
        // inherit A's timeout, so B can only observe `Some` if it re-initializes on its own.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(permits);

        let a_result = tokio::time::timeout(Duration::from_secs(5), a)
            .await
            .expect("A must fail at its own deadline, not hang")
            .expect("task did not panic");
        let b_result = tokio::time::timeout(Duration::from_secs(5), b)
            .await
            .expect("B must not be bounded by A's already-expired deadline")
            .expect("task did not panic");

        assert!(
            a_result.is_none(),
            "A's own short deadline must fail its wait closed"
        );
        assert!(
            b_result.is_some(),
            "B must not be poisoned by A's timeout — it has to run its own initialization \
             attempt with its own, still-live deadline"
        );
    }

    /// Issue #1539 critique finding #1: evicting `record_in_flight`'s entry unconditionally
    /// (including on a caller's own timeout) would remove the cell out from under a *different*
    /// caller still legitimately driving it to completion, breaking single-flight coalescing
    /// (#1535). Caller A (short deadline) starts initializing on a saturated semaphore; caller B
    /// (long deadline) joins the same cell and becomes the new leader once A's timeout fires and
    /// cancels A's attempt; caller C (long deadline) joins afterward, while B is still the active
    /// initializer. If A's own timeout wrongly evicted the shared cell, C would find no map entry
    /// and start a second, redundant `GET /v1/vulns/{id}` — asserted here via the mock server's
    /// request counter staying at exactly 1.
    #[tokio::test]
    async fn fetch_record_single_flight_third_caller_reuses_cell_after_first_callers_timeout() {
        let (addr, _in_flight, _watermark, total) =
            spawn_mock_vuln_server(Duration::from_millis(10)).await;
        let client = Arc::new(OsvClient::with_base_url(
            Arc::new(HttpCache::new()),
            format!("http://{addr}"),
        ));

        let permits: Vec<_> = futures::future::join_all(
            (0..RECORD_FETCH_CONCURRENCY)
                .map(|_| Arc::clone(&client.record_fetch_semaphore).acquire_owned()),
        )
        .await
        .into_iter()
        .map(|permit| permit.expect("semaphore is not closed"))
        .collect();

        let short_deadline = Instant::now() + Duration::from_millis(50);
        let long_deadline = Instant::now() + Duration::from_secs(10);

        let a = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .fetch_record_single_flight("SHARED-ID", short_deadline)
                    .await
            }
        });
        // Give A time to become the cell's initializer before B joins.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let b = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .fetch_record_single_flight("SHARED-ID", long_deadline)
                    .await
            }
        });

        // Wait past A's deadline (so A has timed out and, pre-fix, would have evicted the cell)
        // before C joins — B must still be the one driving the cell to completion at this point,
        // since the semaphore stays saturated until well after this.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let c = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .fetch_record_single_flight("SHARED-ID", long_deadline)
                    .await
            }
        });

        // Give C a moment to join the in-flight cell before releasing the permits B is waiting
        // on, then let B (and, transitively, C) complete.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(permits);

        let a_result = tokio::time::timeout(Duration::from_secs(5), a)
            .await
            .expect("A must fail at its own deadline, not hang")
            .expect("task did not panic");
        let b_result = tokio::time::timeout(Duration::from_secs(5), b)
            .await
            .expect("B must not hang")
            .expect("task did not panic");
        let c_result = tokio::time::timeout(Duration::from_secs(5), c)
            .await
            .expect("C must not hang")
            .expect("task did not panic");

        assert!(a_result.is_none(), "A's own short deadline must fail");
        assert!(
            b_result.is_some(),
            "B must complete the fetch it is driving"
        );
        assert!(
            c_result.is_some(),
            "C must observe B's result by joining the same cell, not fail or hang"
        );
        assert_eq!(
            total.load(Ordering::SeqCst),
            1,
            "C must reuse B's in-flight cell rather than issuing a second, redundant fetch"
        );
    }
}

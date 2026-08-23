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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

pub use severity::to_diagnostic_severity as diagnostic_severity_for;
pub use types::{
    Advisory, DependencyVulnerabilities, ScanOutcome, ScanTarget, SkipReason, UpgradeStatus,
    VulnSeverity, VulnerabilityMap,
};
use types::{
    OsvBatchRequest, OsvBatchResponse, OsvPackage, OsvQuery, OsvSingleQueryResponse, OsvVulnRecord,
};

use crate::cache::HttpCache;

/// Advisories fetched (invariant 3) and rendered (§7) per dependency, plus a
/// trailing "+N more advisories" entry when `total_known` exceeds this.
pub const ADVISORY_DISPLAY_CAP: usize = 5;

/// Query cache TTL (approved Q6).
const QUERY_CACHE_TTL: Duration = Duration::from_hours(6);

/// `/v1/querybatch` chunk size (FR-009).
const BATCH_CHUNK_SIZE: usize = 1000;

/// Bound on individually-requeried truncated entries per [`OsvClient::scan`]/
/// [`OsvClient::check_candidates`] call (§8 invariant 2).
const MAX_TRUNCATED_REQUERY_BUDGET: usize = 20;

/// Bounded concurrency for the `/v1/vulns/{id}` fan-out (§8 invariant 3),
/// mirroring the registry fetch fan-out's `buffer_unordered` usage.
const RECORD_FETCH_CONCURRENCY: usize = 10;

/// Entry-count bound shared by `query_cache` and `record_cache`.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// Percentage of cache entries evicted when [`MAX_CACHE_ENTRIES`] is reached,
/// mirroring [`crate::cache::HttpCache::evict_entries`].
const CACHE_EVICTION_PERCENTAGE: usize = 10;

const OSV_API_BASE: &str = "https://api.osv.dev";

/// Compares two version-like strings by their leading numeric dot-segments,
/// falling back to a lexicographic compare of any non-numeric remainder.
///
/// Used only to order [`Advisory::fixed_versions`] ascending — not a general
/// semver comparator. Good enough for that purpose because the ordering only
/// needs to pick out "the highest fixed version", and OSV's `fixed` events
/// are plain dotted-numeric strings in every ecosystem this workspace scans.
fn compare_version_strings(a: &str, b: &str) -> std::cmp::Ordering {
    fn segments(s: &str) -> Vec<u64> {
        s.split('.')
            .map(|part| {
                part.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            })
            .collect()
    }

    let (sa, sb) = (segments(a), segments(b));
    sa.cmp(&sb).then_with(|| a.cmp(b))
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

/// Evicts the oldest `1/CACHE_EVICTION_PERCENTAGE` of `map`'s entries,
/// mirroring [`crate::cache::HttpCache::evict_entries`]'s oldest-first policy.
fn evict_oldest<K, V>(map: &DashMap<K, V>, fetched_at: impl Fn(&V) -> Instant)
where
    K: Eq + std::hash::Hash + Clone + Ord,
{
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let target_removals = (MAX_CACHE_ENTRIES / CACHE_EVICTION_PERCENTAGE).max(1);
    let mut oldest: BinaryHeap<Reverse<(Instant, K)>> = map
        .iter()
        .map(|entry| Reverse((fetched_at(entry.value()), entry.key().clone())))
        .collect();

    for _ in 0..target_removals {
        let Some(Reverse((_, key))) = oldest.pop() else {
            break;
        };
        map.remove(&key);
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
    query_cache: DashMap<(&'static str, String, String), QueryCacheEntry>,
    record_cache: DashMap<String, RecordCacheEntry>,
    /// Overridable in test builds only, so `mockito` can stand in for
    /// `https://api.osv.dev` — mirrors [`crate::cache::ensure_https`]'s existing
    /// `#[cfg(test)]` relaxation for the same reason.
    #[cfg(test)]
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
            #[cfg(test)]
            base_url: OSV_API_BASE.to_string(),
        }
    }

    #[cfg(test)]
    fn with_base_url(cache: Arc<HttpCache>, base_url: String) -> Self {
        Self {
            cache,
            query_cache: DashMap::new(),
            record_cache: DashMap::new(),
            base_url,
        }
    }

    #[cfg(test)]
    fn api_base(&self) -> &str {
        &self.base_url
    }

    #[cfg(not(test))]
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
    /// Only meaningful for dependencies phase A already flagged — callers
    /// should build `candidates` from that subset. `timeout` has the same
    /// meaning as in [`Self::scan`].
    pub async fn check_candidates(
        &self,
        ecosystem: crate::EcosystemId,
        candidates: &[ScanTarget],
        timeout: Duration,
    ) -> HashMap<String, UpgradeStatus> {
        if candidates.is_empty() {
            return HashMap::new();
        }

        let versions: HashMap<&str, &str> = candidates
            .iter()
            .map(|c| (c.key.as_str(), c.version.as_str()))
            .collect();

        let outcomes = self.resolve(ecosystem, candidates, timeout).await;

        outcomes
            .into_iter()
            .filter_map(|(key, outcome)| {
                let version = (*versions.get(key.as_str())?).to_string();
                let status = match outcome {
                    ScanOutcome::Clean => UpgradeStatus::CandidateClean { version },
                    ScanOutcome::Vulnerable(dv) => UpgradeStatus::CandidateVulnerable {
                        version,
                        advisory_ids: dv.advisories.iter().map(|a| a.id.clone()).collect(),
                    },
                    ScanOutcome::Skipped(_) => return None,
                };
                Some((key, status))
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
    ) -> HashMap<String, ScanOutcome> {
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
        for t in targets {
            let cache_key = (osv_eco, t.osv_name.clone(), t.version.clone());
            let cached_ids = self.query_cache.get(&cache_key).and_then(|entry| {
                (entry.fetched_at.elapsed() < QUERY_CACHE_TTL).then(|| entry.vuln_ids.clone())
            });
            if let Some(vuln_ids) = cached_ids {
                outcomes.insert(
                    t.key.clone(),
                    self.build_outcome(osv_eco, &t.osv_name, &vuln_ids).await,
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
            self.resolve_chunk(osv_eco, chunk, &mut outcomes, &mut truncated)
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

        self.recover_truncated(osv_eco, &truncated, &mut outcomes)
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
    async fn resolve_chunk(
        &self,
        osv_eco: &'static str,
        chunk: &[ScanTarget],
        outcomes: &mut HashMap<String, ScanOutcome>,
        truncated: &mut Vec<ScanTarget>,
    ) {
        let queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|t| OsvQuery {
                package: OsvPackage {
                    name: t.osv_name.clone(),
                    ecosystem: osv_eco.to_string(),
                },
                version: t.version.clone(),
            })
            .collect();

        let body = OsvBatchRequest { queries };
        let response_bytes = match self.cache.post_json(&self.batch_url(), &body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "OSV batch query failed");
                mark_chunk_failed(chunk, outcomes);
                return;
            }
        };

        let parsed: OsvBatchResponse = match serde_json::from_slice(&response_bytes) {
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
                self.build_outcome(osv_eco, &target.osv_name, &vuln_ids)
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
        osv_eco: &'static str,
        truncated: &[ScanTarget],
        outcomes: &mut HashMap<String, ScanOutcome>,
    ) {
        use futures::stream::{self, StreamExt};

        let budget = MAX_TRUNCATED_REQUERY_BUDGET.min(truncated.len());
        let (to_recover, exhausted) = truncated.split_at(budget);

        // Cloned (not borrowed) targets: a closure borrowing both `self` and
        // an element from `truncated`'s slice inside `stream::map` triggers
        // a higher-ranked-lifetime inference failure ("implementation of
        // `FnOnce` is not general enough") once this future is nested inside
        // an outer `tokio::spawn`, as `fetch_records` already learned to
        // avoid via `.cloned()`.
        let recovered: Vec<(String, ScanOutcome)> = stream::iter(to_recover.iter().cloned())
            .map(|target| async move {
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
    /// `total_known` still reflects OSV's reported count (critique M1).
    fn outcome_from_full_records(
        &self,
        osv_eco: &'static str,
        target: &ScanTarget,
        records: Vec<OsvVulnRecord>,
    ) -> ScanOutcome {
        let total = records.len();
        let mut advisories = Vec::with_capacity(total.min(ADVISORY_DISPLAY_CAP));
        let mut vuln_ids = Vec::with_capacity(total);

        for record in records {
            let Some(advisory) = record.into_advisory(&target.osv_name, osv_eco) else {
                continue;
            };
            let advisory = Arc::new(advisory);
            vuln_ids.push((advisory.id.clone(), advisory.modified.clone()));
            self.store_record_cache(&advisory);
            if advisories.len() < ADVISORY_DISPLAY_CAP {
                advisories.push(advisory);
            }
        }

        self.store_query_cache(osv_eco, target, &vuln_ids);

        if total == 0 {
            ScanOutcome::Clean
        } else {
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories,
                total_known: total,
                upgrade_status: UpgradeStatus::NotChecked,
            })
        }
    }

    /// Builds a [`ScanOutcome`] from a list of `(id, modified)` stubs,
    /// fetching up to [`ADVISORY_DISPLAY_CAP`] full records.
    async fn build_outcome(
        &self,
        osv_eco: &str,
        osv_name: &str,
        vuln_ids: &[(String, String)],
    ) -> ScanOutcome {
        if vuln_ids.is_empty() {
            return ScanOutcome::Clean;
        }

        let to_fetch = &vuln_ids[..vuln_ids.len().min(ADVISORY_DISPLAY_CAP)];
        let advisories = self.fetch_records(osv_eco, osv_name, to_fetch).await;

        ScanOutcome::Vulnerable(DependencyVulnerabilities {
            advisories,
            total_known: vuln_ids.len(),
            upgrade_status: UpgradeStatus::NotChecked,
        })
    }

    /// Fetches full advisory records for `ids`, checking the record cache
    /// first and bounding fetch concurrency (§8 invariant 3). A record that
    /// fails to fetch, parse, or validate (malformed id, or no matching
    /// `affected[].package` — critique S3/M1) is dropped, not substituted
    /// with a half-populated placeholder.
    async fn fetch_records(
        &self,
        osv_eco: &str,
        osv_name: &str,
        ids: &[(String, String)],
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

                let record = self.fetch_single_record(&id).await?;
                let advisory = Arc::new(record.into_advisory(osv_name, osv_eco)?);
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

    /// Fetches a single advisory record. Uses [`HttpCache::get_transport_only`]
    /// rather than [`HttpCache::get_cached`] deliberately: this client's own
    /// `record_cache` (validated by `modified`, not `ETag`) is the real
    /// cache for these bodies, so also caching them in `HttpCache`'s
    /// entry map would double-cache every fetched record there, competing
    /// with registry responses for its byte budget for no benefit (critique
    /// M2 — nothing ever reads that copy back).
    async fn fetch_single_record(&self, id: &str) -> Option<OsvVulnRecord> {
        let url = self.vuln_record_url(id);
        match self.cache.get_transport_only(&url).await {
            Ok(bytes) => match serde_json::from_slice::<OsvVulnRecord>(&bytes) {
                Ok(record) => Some(record),
                Err(e) => {
                    tracing::warn!(id, error = %e, "failed to parse OSV vulnerability record");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(id, error = %e, "failed to fetch OSV vulnerability record");
                None
            }
        }
    }

    async fn query_single(
        &self,
        osv_eco: &'static str,
        target: &ScanTarget,
    ) -> Option<OsvSingleQueryResponse> {
        let body = OsvQuery {
            package: OsvPackage {
                name: target.osv_name.clone(),
                ecosystem: osv_eco.to_string(),
            },
            version: target.version.clone(),
        };

        let bytes = match self.cache.post_json(&self.single_query_url(), &body).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(dep = %target.key, error = %e, "OSV single-package requery failed");
                return None;
            }
        };

        match serde_json::from_slice::<OsvSingleQueryResponse>(&bytes) {
            Ok(resp) => Some(resp),
            Err(e) => {
                tracing::warn!(dep = %target.key, error = %e, "failed to parse OSV single-package response");
                None
            }
        }
    }

    fn store_query_cache(
        &self,
        osv_eco: &'static str,
        target: &ScanTarget,
        vuln_ids: &[(String, String)],
    ) {
        if self.query_cache.len() >= MAX_CACHE_ENTRIES {
            evict_oldest(&self.query_cache, |e| e.fetched_at);
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
            evict_oldest(&self.record_cache, |e| e.fetched_at);
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
fn mark_chunk_failed(chunk: &[ScanTarget], outcomes: &mut HashMap<String, ScanOutcome>) {
    for t in chunk {
        outcomes.insert(t.key.clone(), ScanOutcome::Skipped(SkipReason::QueryFailed));
    }
}

/// Logs the `info`-level scan summary mandated by §8 invariant 0.
fn log_scan_summary(outcomes: &HashMap<String, ScanOutcome>) {
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
    use crate::EcosystemId;

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
            key: name.to_string(),
            osv_name: name.to_string(),
            version: version.to_string(),
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
        assert!(matches!(outcomes.get("left-pad"), Some(ScanOutcome::Clean)));
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
            assert!(matches!(
                outcomes.get(key),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            ));
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

        assert!(matches!(
            outcomes.get("a"),
            Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
        ));
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
            assert!(matches!(
                outcomes.get(key),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            ));
        }
    }

    #[tokio::test]
    async fn scan_over_chunk_size_input_issues_exactly_two_batch_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering};

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
            assert!(matches!(
                outcomes.get(key),
                Some(ScanOutcome::Skipped(SkipReason::QueryFailed))
            ));
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
                      "ranges":[{"events":[{"fixed":"1.0.0"}]}]},
                     {"package":{"name":"log4j-core","ecosystem":"Maven"},
                      "ecosystem_specific":{"severity":"CRITICAL"},
                      "ranges":[{"events":[{"fixed":"2.17.1"}]}]}
                   ]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("log4j-core", "2.14.1")];
        let outcomes = client
            .scan(EcosystemId::Maven, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("log4j-core") else {
            panic!("expected Vulnerable outcome");
        };
        // Must pick up log4j-core's own severity/fix, not log4j-api's.
        assert_eq!(dv.advisories[0].severity, VulnSeverity::Critical);
        assert_eq!(dv.advisories[0].fixed_versions, vec!["2.17.1".to_string()]);
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

        // total_known still counts the batch stub; the malformed-id record
        // is dropped rather than rendered with an unsafe id.
        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("pkg") else {
            panic!("expected Vulnerable outcome, got {:?}", outcomes.get("pkg"));
        };
        assert_eq!(dv.total_known, 1);
        assert!(dv.advisories.is_empty());
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

        assert!(matches!(
            outcomes.get("linux"),
            Some(ScanOutcome::Skipped(SkipReason::Truncated))
        ));
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
        // Real shape of RUSTSEC-2020-0071's `affected[].ranges` per
        // architecture.md §6: 8 `fixed` events spread across several
        // ranges (one per patched branch), deliberately out of order in the
        // JSON so a "take the last event, no sort" bug would still pass a
        // trivially-ordered 2-event fixture but fails this one. First `fixed`
        // in document order is `0.2.0`; the highest (the real guidance) is
        // `0.2.23`.
        let _record = server
            .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
            .with_status(200)
            .with_body(
                r#"{"id":"RUSTSEC-2020-0071","modified":"2023-01-01T00:00:00Z",
                   "summary":"Potential segfault","database_specific":{"severity":"HIGH"},
                   "affected":[
                     {"package":{"name":"time","ecosystem":"crates.io"},"ranges":[
                       {"events":[{"introduced":"0"},{"fixed":"0.2.0"},{"fixed":"0.1.44"}]},
                       {"events":[{"introduced":"0"},{"fixed":"0.2.4"},{"fixed":"0.1.43"}]},
                       {"events":[{"introduced":"0"},{"fixed":"0.2.2"},{"fixed":"0.2.23"}]},
                       {"events":[{"introduced":"0"},{"fixed":"0.2.1"},{"fixed":"0.2.3"}]}
                     ]}
                   ]}"#,
            )
            .create_async()
            .await;

        let targets = vec![target("time", "0.1.43")];
        let outcomes = client
            .scan(EcosystemId::Cargo, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("time") else {
            panic!(
                "expected Vulnerable outcome, got {:?}",
                outcomes.get("time")
            );
        };
        assert_eq!(dv.total_known, 1);
        assert_eq!(dv.advisories.len(), 1);
        assert_eq!(dv.advisories[0].id, "RUSTSEC-2020-0071");
        assert_eq!(dv.advisories[0].severity, VulnSeverity::High);
        assert_eq!(
            dv.advisories[0].fixed_versions,
            vec![
                "0.1.43", "0.1.44", "0.2.0", "0.2.1", "0.2.2", "0.2.3", "0.2.4", "0.2.23"
            ]
        );
        // The highest fixed version, not the first in document order.
        assert_eq!(
            dv.advisories[0].fixed_versions.last(),
            Some(&"0.2.23".to_string())
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

        // total_known still reflects the batch stub count; the failed fetch
        // is dropped rather than rendered half-populated.
        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("pkg") else {
            panic!("expected Vulnerable outcome, got {:?}", outcomes.get("pkg"));
        };
        assert_eq!(dv.total_known, 1);
        assert!(dv.advisories.is_empty());
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

        let Some(outcome) = outcomes.get("linux") else {
            panic!("dependency missing from outcome map");
        };
        assert!(
            !matches!(outcome, ScanOutcome::Clean),
            "a truncated batch result must never render as clean"
        );
        assert!(matches!(outcome, ScanOutcome::Vulnerable(_)));
    }

    #[tokio::test]
    async fn scan_advisory_fetch_is_capped_but_total_known_reflects_full_count() {
        let (mut server, client) = mock_client().await;

        let vulns_json: String = (0..40)
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
            .expect(ADVISORY_DISPLAY_CAP)
            .create_async()
            .await;

        let targets = vec![target("rack", "2.0.5")];
        let outcomes = client
            .scan(EcosystemId::Bundler, &targets, TEST_TIMEOUT)
            .await;

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("rack") else {
            panic!("expected Vulnerable outcome");
        };
        assert_eq!(dv.total_known, 40);
        assert_eq!(dv.advisories.len(), ADVISORY_DISPLAY_CAP);
        record.assert_async().await;
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

        assert!(matches!(
            statuses.get("clean-pkg"),
            Some(UpgradeStatus::CandidateClean { version }) if version == "2.0.0"
        ));
        assert!(matches!(
            statuses.get("bad-pkg"),
            Some(UpgradeStatus::CandidateVulnerable { version, advisory_ids })
                if version == "2.0.0" && advisory_ids == &vec!["ADV-1".to_string()]
        ));
    }

    #[test]
    fn query_cache_evicts_oldest_when_max_entries_reached() {
        let client = client();
        for i in 0..MAX_CACHE_ENTRIES {
            client.store_query_cache("npm", &target(&format!("pkg-{i}"), "1.0.0"), &[]);
        }
        assert_eq!(client.query_cache.len(), MAX_CACHE_ENTRIES);

        client.store_query_cache("npm", &target("overflow", "1.0.0"), &[]);

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
            let advisory = Arc::new(Advisory {
                id: format!("ADV-{i}"),
                modified: "2023-01-01T00:00:00Z".to_string(),
                summary: None,
                aliases: vec![],
                severity: VulnSeverity::Unknown,
                cvss_vector: None,
                fixed_versions: vec![],
                url: format!("https://osv.dev/vulnerability/ADV-{i}"),
            });
            client.store_record_cache(&advisory);
        }
        assert_eq!(client.record_cache.len(), MAX_CACHE_ENTRIES);

        let overflow = Arc::new(Advisory {
            id: "ADV-overflow".to_string(),
            modified: "2023-01-01T00:00:00Z".to_string(),
            summary: None,
            aliases: vec![],
            severity: VulnSeverity::Unknown,
            cvss_vector: None,
            fixed_versions: vec![],
            url: "https://osv.dev/vulnerability/ADV-overflow".to_string(),
        });
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

        // Pre-populate the cache with an entry older than QUERY_CACHE_TTL.
        client.query_cache.insert(
            ("npm", t.osv_name.clone(), t.version.clone()),
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

        // Pre-populate record_cache with a stale `modified` timestamp.
        client.record_cache.insert(
            "ADV-1".to_string(),
            RecordCacheEntry {
                advisory: Arc::new(Advisory {
                    id: "ADV-1".to_string(),
                    modified: "2020-01-01T00:00:00Z".to_string(),
                    summary: Some("stale summary".to_string()),
                    aliases: vec![],
                    severity: VulnSeverity::Unknown,
                    cvss_vector: None,
                    fixed_versions: vec![],
                    url: "https://osv.dev/vulnerability/ADV-1".to_string(),
                }),
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

        let Some(ScanOutcome::Vulnerable(dv)) = outcomes.get("pkg") else {
            panic!("expected Vulnerable outcome");
        };
        assert_eq!(dv.advisories[0].summary.as_deref(), Some("updated summary"));
        record.assert_async().await;
    }
}

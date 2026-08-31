//! In-memory PyPI package-name search index, built once from the live PEP 691 Simple
//! API project list.
//!
//! PyPI removed its XML-RPC search API and offers no first-party ranked search, so
//! this mimics how PyCharm and similar tools fill the gap: download the full list of
//! ~882k project names, normalize and sort it locally, and serve prefix matches with
//! no popularity ranking. See `.local/plans/419-pypi-search.md` for the full design
//! rationale (issue #419).
//!
//! # Lifecycle
//!
//! The index is built at most once per process (see [`IndexCell`]): there is no TTL
//! and it is never refreshed once [`IndexState::Ready`]. Measured against the live
//! endpoint, the index's `X-PyPI-Last-Serial` advances roughly 1,820 times per hour,
//! so any TTL short enough to matter would mean re-downloading the ~9.6 MB gzipped
//! body on almost every expiry — worse than simply accepting that a long-lived
//! process serves a name list that is at most a few hours stale.
//!
//! A failed build (network error, malformed body, or an implausibly small parse —
//! see [`MIN_PLAUSIBLE_INDEX_ENTRIES`]) is retried with exponential backoff rather
//! than on every call, so a persistently failing link costs one attempt per backoff
//! window, not one per keystroke.

use std::borrow::Cow;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use deps_core::{BodyLimit, DepsError, HttpCache, Result};
use serde::Deserialize;

use crate::registry::{REGISTRY, SIMPLE_API_ACCEPT};

/// URL for PyPI's full Simple API project index (PEP 691).
pub(crate) const SIMPLE_INDEX_URL: &str = "https://pypi.org/simple/";

/// Origin the index fetch's redirect policy is pinned to (L1, security review):
/// this is the one fetch in the workspace carrying a [`SIMPLE_INDEX_MAX_BYTES`]
/// (96 MiB) budget rather than [`deps_core::BodyLimit::DEFAULT`]'s 32 MiB, so a
/// cross-host redirect is worth stopping explicitly rather than following
/// `reqwest`'s default up-to-10-hop policy. Only constrains *redirects*, not the
/// initial request — `index_url` itself is always [`SIMPLE_INDEX_URL`] in
/// production (or a test's own mock server URL), never user-controlled.
const PYPI_TRUSTED_ORIGIN: &str = "https://pypi.org/";

/// Upper bound on the index response body. Roughly 2x the ~43 MB decompressed size
/// observed live (2026-08-31), bounded well under [`deps_core::cache::BodyLimit`]'s
/// own 128 MiB ceiling so this doesn't silently grow the cache's largest-response
/// footprint if PyPI's project count keeps climbing.
const SIMPLE_INDEX_MAX_BYTES: BodyLimit = BodyLimit::new(96 * 1024 * 1024);

/// Upper bound on the number of parsed project entries, independent of
/// [`SIMPLE_INDEX_MAX_BYTES`]'s byte cap — defense in depth against a body that is
/// small but contains an implausible number of tiny entries.
///
/// Enforced *during* deserialization by `deserialize_projects`'s streaming
/// `Visitor`, not by truncating an already-fully-materialized `Vec` afterward: a
/// 96 MiB body of minimal `{"name":"a"}` entries deserializes to ~7.7M elements,
/// and holding all of them live at once (rather than normalizing/filtering each
/// one and discarding it immediately) previously peaked at ~370 MB RSS for a
/// 1-entry result — the cap did nothing to prevent that. See `deserialize_projects`.
const MAX_INDEX_ENTRIES: usize = 2_000_000;

/// Upper bound on a single raw (pre-normalization) project name, checked before
/// [`crate::name::normalize`] runs.
///
/// PyPI's own package-name validation caps a real name at 214 characters, so 1024
/// bytes loses no legitimate name. Checked first because `normalize` itself
/// allocates three full copies of its input (`to_lowercase` → `replace` → `join`):
/// a single ~95 MiB name in an otherwise well-formed body peaked at ~400 MB RSS
/// before the (still-necessary) [`deps_core::is_safe_package_name`] gate discarded
/// it anyway — this check makes that discard immediate instead.
const MAX_RAW_NAME_LEN: usize = 1024;

/// A successful parse with fewer than this many entries is treated as a failed
/// build rather than cached as [`IndexState::Ready`].
///
/// Dropping the TTL (see the module doc) means a successful build is never
/// invalidated later, so a body that arrives truncated-but-still-valid-JSON would
/// otherwise pin the process to a degraded index for its entire lifetime with no
/// path back. The live index carries ~882k entries; 100,000 is comfortably below
/// any plausible legitimate response while still well above what a truncated
/// transfer would produce.
const MIN_PLAUSIBLE_INDEX_ENTRIES: usize = 100_000;

/// Base backoff after the first failed build attempt.
const RETRY_BASE_BACKOFF: Duration = Duration::from_secs(30);

/// Ceiling on the computed backoff duration, regardless of how many attempts have
/// failed.
const RETRY_MAX_BACKOFF: Duration = Duration::from_mins(15);

/// Ceiling on the *exponent* used to compute backoff, independent of
/// [`RETRY_MAX_BACKOFF`]'s ceiling on the resulting duration.
///
/// `attempts` (see [`IndexState::Failed`]) grows without bound on a permanently
/// failing link — a long-lived editor session can accumulate far more than 64 of
/// them. Capping only the backoff *duration* would still compute `1u64 <<
/// (attempts - 1)` first, which panics on overflow in debug builds once `attempts`
/// exceeds 64. Clamping the exponent itself means the shift is always well-formed,
/// independent of how large `attempts` gets.
const MAX_BACKOFF_EXPONENT: u32 = 10;

/// Computes the backoff duration for the `attempts`-th failed build (`attempts >=
/// 1`): `min(RETRY_BASE_BACKOFF * 2^(attempts - 1), RETRY_MAX_BACKOFF)`, with the
/// exponent itself clamped to [`MAX_BACKOFF_EXPONENT`] so the shift can never
/// overflow regardless of how large `attempts` grows.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(backoff_for(1), Duration::from_secs(30));
/// assert_eq!(backoff_for(2), Duration::from_secs(60));
/// ```
fn backoff_for(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(MAX_BACKOFF_EXPONENT);
    let secs = RETRY_BASE_BACKOFF
        .as_secs()
        .saturating_mul(1u64 << exponent);
    Duration::from_secs(secs.min(RETRY_MAX_BACKOFF.as_secs()))
}

/// A sorted, PEP 503-normalized set of PyPI project names, laid out as one
/// concatenated `String` blob plus an offset table rather than a `Vec<String>`.
///
/// At ~882k entries a `Vec<String>` would cost roughly 12 MB of name bytes plus
/// ~28 MB of per-`String` allocator/pointer overhead; the blob layout keeps the
/// total near 15 MB in the common case. That figure is the *typical* case, not the
/// bound: [`MAX_INDEX_ENTRIES`] bounds entry count and [`SIMPLE_INDEX_MAX_BYTES`]
/// bounds the wire body, but neither bounds the blob directly, so a maximally
/// adversarial (but within-cap) body — many short names packed into the 96 MiB
/// limit — could parse to roughly 70 MB of blob plus 8 MB of offsets, ~78 MB total.
/// This is this struct's own *steady-state* size once parsing has finished and the
/// input body has been dropped; see [`deserialize_projects`] for the (separately
/// bounded) transient peak *during* parsing.
pub(crate) struct PackageIndex {
    /// Every entry's normalized name, concatenated in sorted order.
    blob: String,
    /// `n + 1` byte offsets into `blob`; entry `i` spans `blob[offsets[i]..offsets[i
    /// + 1]]`.
    offsets: Vec<u32>,
}

impl PackageIndex {
    /// Builds an index from already deduplicated, sorted, normalized names.
    fn from_sorted_names(names: Vec<String>) -> Self {
        let mut blob = String::with_capacity(names.iter().map(String::len).sum());
        let mut offsets = Vec::with_capacity(names.len() + 1);
        offsets.push(0u32);
        for name in &names {
            blob.push_str(name);
            // `SIMPLE_INDEX_MAX_BYTES` (96 MiB) bounds the source body far below
            // u32::MAX bytes, so this never actually saturates; the clamp is
            // defense in depth rather than a reachable path.
            offsets.push(u32::try_from(blob.len()).unwrap_or(u32::MAX));
        }
        Self { blob, offsets }
    }

    /// Number of entries in the index.
    fn len(&self) -> usize {
        self.offsets.len() - 1
    }

    /// The normalized name at `index`.
    fn name(&self, index: usize) -> &str {
        &self.blob[self.offsets[index] as usize..self.offsets[index + 1] as usize]
    }

    /// Index of the first entry that is `>= prefix`, via binary search
    /// (`slice::partition_point`'s underlying algorithm, adapted to the blob
    /// layout rather than a slice of `&str`).
    fn lower_bound(&self, prefix: &str) -> usize {
        let mut lo = 0usize;
        let mut hi = self.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.name(mid) < prefix {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Returns up to `limit` normalized names starting with `normalized_prefix`, in
    /// sorted (alphabetical, unranked) order.
    ///
    /// O(log n + limit): [`Self::lower_bound`] locates the first candidate, then a
    /// forward scan collects matches until either a non-matching entry or `limit`
    /// is reached.
    pub(crate) fn prefix_matches(&self, normalized_prefix: &str, limit: usize) -> Vec<&str> {
        if limit == 0 || normalized_prefix.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(limit.min(self.len()));
        for index in self.lower_bound(normalized_prefix)..self.len() {
            let name = self.name(index);
            if !name.starts_with(normalized_prefix) {
                break;
            }
            out.push(name);
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}

/// State of the lazily-built, build-once package index.
enum IndexState {
    /// No build has ever been attempted.
    NotBuilt,
    /// A build succeeded; served forever (see the module doc — there is no TTL).
    Ready(Arc<PackageIndex>),
    /// The most recent build attempt failed. Retried only once
    /// `last_attempt.elapsed() >= backoff_for(attempts)`.
    Failed {
        last_attempt: Instant,
        attempts: u32,
    },
}

/// Holds the build-once [`PackageIndex`] state behind a [`std::sync::RwLock`] (never
/// held across an `.await`, matching the discipline `HttpCache` itself uses), plus a
/// [`tokio::sync::Mutex`] that serializes the build itself so N concurrently-queued
/// completion requests trigger exactly one download rather than one each.
pub(crate) struct IndexCell {
    state: RwLock<IndexState>,
    build_lock: tokio::sync::Mutex<()>,
}

impl IndexCell {
    pub(crate) fn new() -> Self {
        Self {
            state: RwLock::new(IndexState::NotBuilt),
            build_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Reads the current state. Lock poisoning (only reachable if a prior writer
    /// panicked mid-update, which none of this module's critical sections can do
    /// mid-guard) is recovered from rather than propagated, since a poisoned search
    /// index is still safe to treat as "not built yet".
    fn read_state(&self) -> RwLockReadGuard<'_, IndexState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, IndexState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the ready index, if any, without touching the network.
    pub(crate) fn ready(&self) -> Option<Arc<PackageIndex>> {
        match &*self.read_state() {
            IndexState::Ready(index) => Some(Arc::clone(index)),
            IndexState::NotBuilt | IndexState::Failed { .. } => None,
        }
    }

    /// Whether a build attempt should be made right now: never built yet, or
    /// previously failed and its backoff window has elapsed.
    fn needs_attempt(&self) -> bool {
        match &*self.read_state() {
            IndexState::Ready(_) => false,
            IndexState::NotBuilt => true,
            IndexState::Failed {
                last_attempt,
                attempts,
            } => last_attempt.elapsed() >= backoff_for(*attempts),
        }
    }

    fn failed_attempts(&self) -> u32 {
        match &*self.read_state() {
            IndexState::Failed { attempts, .. } => *attempts,
            IndexState::NotBuilt | IndexState::Ready(_) => 0,
        }
    }

    fn set_ready(&self, index: PackageIndex) {
        *self.write_state() = IndexState::Ready(Arc::new(index));
    }

    fn set_failed(&self, prior_attempts: u32) {
        *self.write_state() = IndexState::Failed {
            last_attempt: Instant::now(),
            attempts: prior_attempts.saturating_add(1),
        };
    }
}

/// Starts building `cell`'s index in the background if [`IndexCell::needs_attempt`]
/// says one is due, otherwise returns immediately without spawning anything.
///
/// Safe to call unconditionally and often (every completion request in a Python
/// manifest calls this via [`crate::registry::PypiRegistry::warm_search_index`]):
/// the cheap synchronous [`IndexCell::needs_attempt`] check short-circuits the
/// common case (already [`IndexState::Ready`]) without spawning a task at all, and
/// the single-flight [`IndexCell::build_lock`] — re-checked *after* it is acquired —
/// ensures that even many callers racing on a cold cell produce exactly one fetch.
///
/// The spawned task's `JoinHandle` is retained and awaited by a supervisor task
/// that logs a panic instead of discarding it silently (mirroring the fix in
/// commit b8cd6210 for the cold-start-limiter cleanup task).
pub(crate) fn trigger_index_build(cache: Arc<HttpCache>, index_url: String, cell: Arc<IndexCell>) {
    if !cell.needs_attempt() {
        return;
    }

    let build_task = tokio::spawn(async move {
        ensure_index_built(&cache, &index_url, &cell).await;
    });
    tokio::spawn(async move {
        if let Err(e) = build_task.await {
            tracing::error!("PyPI simple index build task exited unexpectedly: {e}");
        }
    });
}

/// Builds the index if [`IndexCell::needs_attempt`] still holds after acquiring the
/// single-flight lock (double-checked locking, N3: the first check in
/// [`trigger_index_build`] happens before the lock, so a racing caller that loses
/// the race must re-check once it actually holds the lock rather than repeat the
/// download).
async fn ensure_index_built(cache: &HttpCache, index_url: &str, cell: &IndexCell) {
    let _guard = cell.build_lock.lock().await;

    if !cell.needs_attempt() {
        return;
    }

    let prior_attempts = cell.failed_attempts();

    match fetch_and_parse_index(cache, index_url).await {
        Some(index) if index.len() >= MIN_PLAUSIBLE_INDEX_ENTRIES => {
            tracing::info!("PyPI simple index built: {} entries", index.len());
            cell.set_ready(index);
        }
        Some(too_small) => {
            tracing::warn!(
                "PyPI simple index parsed but implausibly small ({} entries, expected at least \
                 {MIN_PLAUSIBLE_INDEX_ENTRIES}); treating as a failed build so backoff retries",
                too_small.len()
            );
            cell.set_failed(prior_attempts);
        }
        None => cell.set_failed(prior_attempts),
    }
}

/// Fetches the Simple API index and parses it on a blocking thread. Never returns
/// `Err`: every failure mode (network, HTTP status, malformed JSON, or a panicked
/// parse task) is logged and folded into `None`, since a failed background index
/// build must degrade to "search still returns empty", not propagate an error.
async fn fetch_and_parse_index(cache: &HttpCache, index_url: &str) -> Option<PackageIndex> {
    let body = match cache
        .get_transport_only_with_headers_limited_trusted_origin(
            index_url,
            &[(reqwest::header::ACCEPT, SIMPLE_API_ACCEPT)],
            SIMPLE_INDEX_MAX_BYTES,
            PYPI_TRUSTED_ORIGIN,
        )
        .await
    {
        Ok(body) => body,
        Err(e) => {
            tracing::warn!("failed to fetch PyPI simple index: {e}");
            return None;
        }
    };

    match tokio::task::spawn_blocking(move || parse_index(&body)).await {
        Ok(Ok(index)) => Some(index),
        Ok(Err(e)) => {
            tracing::warn!("failed to parse PyPI simple index: {e}");
            None
        }
        Err(e) => {
            tracing::warn!("PyPI simple index parse task panicked: {e}");
            None
        }
    }
}

/// PEP 691 Simple API response shape, narrowed to the one field this module needs.
///
/// `projects` deserializes straight into normalized, filtered, capped `String`
/// names (via [`deserialize_projects`]) rather than an intermediate
/// `Vec<Project<'a>>` — see that function's doc for why the intermediate shape was
/// a real memory-amplification bug (#419 S3/M1), not just an inefficiency.
#[derive(Deserialize)]
struct SimpleIndex {
    #[serde(deserialize_with = "deserialize_projects")]
    projects: Vec<String>,
}

/// A single project entry as it appears on the wire. `Cow<'a, str>`, not `&'a
/// str`: `serde_json` can only borrow a string that needs no unescaping, so a
/// plain `&str` here would make a *single* escaped name anywhere in the
/// ~882k-entry response fail the whole parse and silently drop every name. PEP
/// 508 package-name rules should preclude characters that need JSON escaping, but
/// the parser must not rest on that.
#[derive(Deserialize)]
struct Project<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
}

/// Deserializes the `projects` JSON array directly into a bounded, normalized,
/// filtered `Vec<String>` — never materializing a `Vec<Project>` of the full
/// input size.
///
/// This is the fix for #419 S3/M1: the original shape deserialized into
/// `Vec<Project<'a>>` first and applied [`MAX_INDEX_ENTRIES`] via `.take(...)`
/// *afterward*, so the cap bounded nothing about peak memory — a 96 MiB body of
/// minimal `{"name":"a"}` entries decodes to ~7.7M elements, and holding all of
/// them live simultaneously (rather than processing and discarding each one)
/// measured at ~370 MB peak RSS for a final 1-entry index. Streaming via this
/// [`serde::de::Visitor`] means each element exists only for the duration of one
/// loop iteration: normalized and pushed if it survives every filter, dropped
/// immediately otherwise, with `names` never growing past [`MAX_INDEX_ENTRIES`].
///
/// The raw-length gate ([`MAX_RAW_NAME_LEN`], M2) runs first, before
/// [`crate::name::normalize`] (three allocations per call) or
/// [`deps_core::is_safe_package_name`] even look at the name — both would reject
/// an oversized name anyway, but only after paying its allocation cost.
///
/// The sequence is drained to its end even after `names` reaches
/// [`MAX_INDEX_ENTRIES`] (each further element is still parsed and immediately
/// dropped, not accumulated): a `SeqAccess` must be fully consumed for the
/// deserializer's cursor to land correctly past the closing `]`, so stopping
/// early would corrupt parsing of whatever JSON follows.
fn deserialize_projects<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ProjectsVisitor;

    impl<'de> serde::de::Visitor<'de> for ProjectsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a sequence of PyPI Simple API project objects")
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut names = Vec::new();
            while let Some(project) = seq.next_element::<Project<'de>>()? {
                if names.len() >= MAX_INDEX_ENTRIES || project.name.len() > MAX_RAW_NAME_LEN {
                    continue;
                }
                let normalized = crate::name::normalize(&project.name);
                if normalized.is_empty() || !deps_core::is_safe_package_name(&normalized) {
                    continue;
                }
                names.push(normalized);
            }
            Ok(names)
        }
    }

    deserializer.deserialize_seq(ProjectsVisitor)
}

/// Parses a Simple API index response body into a sorted [`PackageIndex`].
///
/// Each name is normalized via [`crate::name::normalize`] (the same normalizer used
/// for registry lookups, so a query and the index it searches always agree on
/// spelling), filtered through [`deps_core::is_safe_package_name`], and deduplicated
/// — normalization collapses some distinct raw spellings onto the same key. PyPI's
/// own wire order is a punctuation-insensitive collation, not byte order, so the
/// names are always re-sorted here regardless of input order.
///
/// Intended to run inside [`tokio::task::spawn_blocking`]: normalizing and sorting
/// up to [`MAX_INDEX_ENTRIES`] names is CPU-bound work that must not sit on the
/// async runtime.
fn parse_index(body: &[u8]) -> Result<PackageIndex> {
    let index: SimpleIndex = serde_json::from_slice(body).map_err(|e| DepsError::ApiResponse {
        package: "<pypi-simple-index>".to_string(),
        registry: REGISTRY,
        source: e,
    })?;

    let mut names = index.projects;
    names.sort_unstable();
    names.dedup();

    Ok(PackageIndex::from_sorted_names(names))
}

/// Builds a Simple API response body plausible enough to clear
/// [`MIN_PLAUSIBLE_INDEX_ENTRIES`] (padded with synthetic entries), plus
/// `extra_names`, for tests elsewhere in the crate that need a real successful
/// index build against a mock server (`crate::registry`, `crate::ecosystem`).
#[cfg(test)]
pub(crate) fn sample_index_body(extra_names: &[&str]) -> String {
    let mut projects: Vec<String> = (0..MIN_PLAUSIBLE_INDEX_ENTRIES)
        .map(|i| format!(r#"{{"name": "synthetic-package-{i}"}}"#))
        .collect();
    projects.extend(
        extra_names
            .iter()
            .map(|name| format!(r#"{{"name": "{name}"}}"#)),
    );
    format!(
        r#"{{"meta": {{"api-version": "1.4"}}, "projects": [{}]}}"#,
        projects.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(names: &[&str]) -> PackageIndex {
        let mut owned: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
        owned.sort_unstable();
        owned.dedup();
        PackageIndex::from_sorted_names(owned)
    }

    #[test]
    fn test_prefix_matches_alphabetical_order_and_limit() {
        let index = index_of(&["pytz", "pytest", "pytest-cov", "pyyaml", "requests"]);
        let matches = index.prefix_matches("pyt", 10);
        assert_eq!(matches, vec!["pytest", "pytest-cov", "pytz"]);

        let limited = index.prefix_matches("pyt", 2);
        assert_eq!(limited, vec!["pytest", "pytest-cov"]);
    }

    #[test]
    fn test_prefix_matches_limit_zero() {
        let index = index_of(&["requests"]);
        assert!(index.prefix_matches("req", 0).is_empty());
    }

    #[test]
    fn test_prefix_matches_empty_prefix() {
        let index = index_of(&["requests", "flask"]);
        assert!(index.prefix_matches("", 10).is_empty());
    }

    #[test]
    fn test_prefix_matches_past_last_entry() {
        let index = index_of(&["alpha", "beta"]);
        assert!(index.prefix_matches("zzz", 10).is_empty());
    }

    #[test]
    fn test_prefix_matches_matches_final_entry() {
        let index = index_of(&["alpha", "beta", "zeta"]);
        assert_eq!(index.prefix_matches("zeta", 10), vec!["zeta"]);
    }

    #[test]
    fn test_prefix_matches_multi_byte_prefix() {
        // "café" survives `name::normalize` unchanged (`str::to_lowercase` is full
        // Unicode-aware, and 'é' is already lowercase) — this exercises a
        // non-ASCII, multi-byte-in-UTF-8 prefix through the byte-offset blob
        // lookup rather than assuming every character is a single byte.
        let index = index_of(&["café-lib", "cafeteria"]);
        assert_eq!(index.prefix_matches("café", 10), vec!["café-lib"]);
    }

    #[test]
    fn test_prefix_matches_case_and_separator_insensitive_query() {
        // The index stores normalized names; a caller is expected to normalize the
        // query the same way before calling this (as `PypiRegistry::search` does),
        // so this pins that "Django" the *raw* form is never what's stored.
        let index = index_of(&["django", "django-rest-framework"]);
        assert_eq!(
            index.prefix_matches("django", 10),
            vec!["django", "django-rest-framework"]
        );
    }

    #[test]
    fn test_parse_index_normalizes_sorts_and_dedupes() {
        // Deliberately mis-ordered and using mixed separators/casing: PyPI's own
        // wire order is a punctuation-insensitive collation, not byte order, so a
        // correct parser must re-sort regardless of input order.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "projects": [
                {"name": "Zope.Interface"},
                {"name": "Django"},
                {"name": "zope-interface"},
                {"name": "attrs"}
            ]
        }"#;
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.len(), 3, "Zope.Interface and zope-interface dedupe");
        assert_eq!(
            index.prefix_matches("a", 10),
            vec!["attrs"],
            "sorted ascending regardless of wire order"
        );
        assert_eq!(index.prefix_matches("django", 10), vec!["django"]);
        assert_eq!(index.prefix_matches("zope", 10), vec!["zope-interface"]);
    }

    #[test]
    fn test_parse_index_trailing_separator_pinning() {
        // N5/N7: `name::normalize` deliberately strips a leading/trailing
        // separator run rather than collapsing it to a leading/trailing `-` (see
        // that function's doc) — this pins that the *same* normalizer is applied
        // uniformly to index entries, so a raw name ending in a separator still
        // lands on a prefix-matchable, query-consistent key rather than silently
        // vanishing from the index.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "projects": [{"name": "zope."}]
        }"#;
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.prefix_matches("zope", 10), vec!["zope"]);
    }

    #[test]
    fn test_parse_index_rejects_unsafe_names() {
        // The embedded quote and semicolon survive `name::normalize` (which only
        // touches case and `-`/`_`/`.` separators) and must be rejected by
        // `is_safe_package_name`, the same gate every other completion path uses
        // before a registry-reported name reaches manifest text.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "projects": [
                {"name": "requests"},
                {"name": "evil\"; DROP TABLE"}
            ]
        }"#;
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index.prefix_matches("requests", 10), vec!["requests"]);
    }

    /// #419 M2 regression: a raw name over [`MAX_RAW_NAME_LEN`] must be discarded
    /// by that length check alone — cheap enough to run in a unit test without the
    /// ~95 MiB fixture security used to measure the RSS impact of running
    /// `normalize` (three allocations) before this gate existed.
    #[test]
    fn test_parse_index_rejects_oversized_raw_name_before_normalizing() {
        let oversized_name = "a".repeat(MAX_RAW_NAME_LEN + 1);
        assert!(oversized_name.len() > MAX_RAW_NAME_LEN);
        let json = format!(
            r#"{{"meta": {{"api-version": "1.4"}}, "projects": [{{"name": "requests"}}, {{"name": "{oversized_name}"}}]}}"#
        );
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index.prefix_matches("requests", 10), vec!["requests"]);
    }

    #[test]
    fn test_parse_index_escaped_name_survives() {
        // S5 regression: `e` (an escaped "e") forces `serde_json` to allocate
        // rather than borrow this one name. A `&'a str` borrow target would fail
        // the *entire* parse on this single escape and drop every other entry
        // along with it; `Cow<'a, str>` must not.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "projects": [
                {"name": "requests"},
                {"name": "weird-nam\u0065"}
            ]
        }"#;
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index.prefix_matches("weird", 10), vec!["weird-name"]);
    }

    #[test]
    fn test_parse_index_malformed_json() {
        assert!(parse_index(b"not json").is_err());
    }

    #[test]
    fn test_parse_index_empty_projects() {
        let json = r#"{"meta": {"api-version": "1.4"}, "projects": []}"#;
        let index = parse_index(json.as_bytes()).unwrap();
        assert_eq!(index.len(), 0);
        assert!(index.prefix_matches("a", 10).is_empty());
    }

    #[test]
    fn test_backoff_for_matches_spec() {
        assert_eq!(backoff_for(1), Duration::from_secs(30));
        assert_eq!(backoff_for(2), Duration::from_secs(60));
        assert_eq!(backoff_for(3), Duration::from_secs(120));
    }

    #[test]
    fn test_backoff_for_caps_at_max() {
        assert_eq!(backoff_for(20), RETRY_MAX_BACKOFF);
    }

    #[test]
    fn test_backoff_for_never_overflows_shift_for_huge_attempts() {
        // N2 regression: `attempts` can grow unboundedly on a permanently-failing
        // link. Without clamping the exponent, `1u64 << (attempts - 1)` panics in
        // debug builds once `attempts` exceeds 64.
        assert_eq!(backoff_for(u32::MAX), RETRY_MAX_BACKOFF);
        assert_eq!(backoff_for(1000), RETRY_MAX_BACKOFF);
    }

    #[tokio::test]
    async fn test_index_cell_starts_not_built_and_needs_attempt() {
        let cell = IndexCell::new();
        assert!(cell.ready().is_none());
        assert!(cell.needs_attempt());
    }

    #[tokio::test]
    async fn test_index_cell_ready_after_set_ready_never_needs_attempt_again() {
        let cell = IndexCell::new();
        cell.set_ready(index_of(&["requests"]));
        assert!(cell.ready().is_some());
        assert!(!cell.needs_attempt(), "C2: a Ready index is never rebuilt");
    }

    #[tokio::test]
    async fn test_index_cell_failed_respects_backoff_then_allows_retry() {
        let cell = IndexCell::new();
        cell.set_failed(0);
        assert_eq!(cell.failed_attempts(), 1);
        assert!(
            !cell.needs_attempt(),
            "S4: must not retry immediately after a failure"
        );

        // Simulate the backoff window having elapsed by writing a state whose
        // `last_attempt` is already in the past relative to `backoff_for(1)`.
        *cell.write_state() = IndexState::Failed {
            last_attempt: Instant::now().checked_sub(Duration::from_secs(31)).unwrap(),
            attempts: 1,
        };
        assert!(cell.needs_attempt());
    }

    #[tokio::test]
    async fn test_trigger_index_build_single_flight_against_mock() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(sample_index_body(&["requests"]))
            .expect(1)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let cell = Arc::new(IndexCell::new());
        let index_url = format!("{}/simple/", server.url());

        // N concurrent triggers must still produce exactly one fetch.
        let mut handles = Vec::new();
        for _ in 0..5 {
            handles.push(tokio::spawn({
                let cache = Arc::clone(&cache);
                let index_url = index_url.clone();
                let cell = Arc::clone(&cell);
                async move { trigger_index_build(cache, index_url, cell) }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Poll (rather than a single fixed sleep) so the test isn't flaky under
        // slower CI machines: parsing ~100k entries plus the HTTP round trip can
        // occasionally exceed a short fixed delay.
        for _ in 0..100 {
            if cell.ready().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            cell.ready().is_some(),
            "index should have built successfully"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_ensure_index_built_marks_implausibly_small_parse_as_failed() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(r#"{"meta": {"api-version": "1.4"}, "projects": [{"name": "requests"}]}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let cell = IndexCell::new();
        let index_url = format!("{}/simple/", server.url());

        ensure_index_built(&cache, &index_url, &cell).await;

        assert!(
            cell.ready().is_none(),
            "N1: a plausible-but-tiny parse must not be cached as Ready"
        );
        assert_eq!(cell.failed_attempts(), 1);
    }

    #[tokio::test]
    async fn test_ensure_index_built_failure_then_backoff_then_retry() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(500)
            .expect(2)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let cell = IndexCell::new();
        let index_url = format!("{}/simple/", server.url());

        ensure_index_built(&cache, &index_url, &cell).await;
        assert_eq!(cell.failed_attempts(), 1);

        // Still within backoff: a second call must not touch the network again.
        ensure_index_built(&cache, &index_url, &cell).await;
        assert_eq!(
            cell.failed_attempts(),
            1,
            "still within backoff, must not have retried"
        );

        // #419 M4 regression (§6.7's "after the window elapses, exactly one more
        // attempt" half, previously untested): once `backoff_for(1)` (30s) has
        // elapsed, the *next* call must retry exactly once more, not stay stuck at
        // `attempts == 1` forever. `set_failed` (and so `last_attempt`) is only
        // ever mutated under `build_lock` inside `ensure_index_built` itself, so
        // directly rewriting the cell's state to simulate elapsed wall-clock time
        // is the only way to test this without pausing the tokio clock crate-wide.
        *cell.write_state() = IndexState::Failed {
            last_attempt: Instant::now().checked_sub(Duration::from_secs(31)).unwrap(),
            attempts: 1,
        };
        ensure_index_built(&cache, &index_url, &cell).await;
        assert_eq!(
            cell.failed_attempts(),
            2,
            "backoff window elapsed: must have retried exactly once more"
        );

        mock.assert_async().await;
    }

    /// Live-network regression, required by the project's Registry Integration
    /// Gate: parses the real `pypi.org/simple/` index and confirms `requests` is
    /// present. Kept `#[ignore]`d (network access) but intentionally the *only*
    /// live-network test for this feature — every other case above runs against
    /// mockito fixtures so CI stays network-free.
    #[tokio::test]
    #[ignore]
    async fn test_live_pypi_simple_index_parses_and_contains_requests() {
        let cache = HttpCache::new();
        let body = cache
            .get_transport_only_with_headers_limited_trusted_origin(
                SIMPLE_INDEX_URL,
                &[(reqwest::header::ACCEPT, SIMPLE_API_ACCEPT)],
                SIMPLE_INDEX_MAX_BYTES,
                PYPI_TRUSTED_ORIGIN,
            )
            .await
            .expect("live fetch of the real PyPI simple index");
        let index = parse_index(&body).expect("live index must parse");
        assert!(
            index.len() >= MIN_PLAUSIBLE_INDEX_ENTRIES,
            "live index unexpectedly small: {} entries",
            index.len()
        );
        assert_eq!(index.prefix_matches("requests", 1), vec!["requests"]);
    }
}

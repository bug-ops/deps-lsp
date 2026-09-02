//! Maven Central registry client.
//!
//! Uses `maven-metadata.xml` from Maven Central CDN for version fetching
//! (fast, CDN-cached) and Solr search API for package search (full-text).

use crate::types::{ArtifactInfo, MavenVersion};
use crate::version::compare_versions;
use bytes::Bytes;
use dashmap::DashMap;
use deps_core::{
    DepsError, HttpCache, PublishTime, Result, is_safe_maven_coordinate_segment,
    lsp_helpers::warn_rejected_value,
};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const MAVEN_REPO_BASE: &str = "https://repo1.maven.org/maven2";

/// Display name for Maven Central used in not-found and API-response error
/// messages. Reused by `deps-gradle`, which resolves through this registry.
pub const REGISTRY: &str = "Maven Central";
const GOOGLE_MAVEN_BASE: &str = "https://dl.google.com/dl/android/maven2";
const GRADLE_PLUGIN_PORTAL_BASE: &str = "https://plugins.gradle.org/m2";
const MAVEN_SEARCH_BASE: &str = "https://search.maven.org/solrsearch/select";

/// Per-attempt timeouts for `search_typed`'s retry loop: first attempt, then second.
///
/// `search.maven.org/solrsearch` fails intermittently as a silent, zero-byte hang
/// rather than a clean HTTP error — live-verified 2026-08-24 (#274): identical
/// back-to-back requests for the same popular query (`guava`, `spring`) alternate
/// between a fast success and a full hang, with no correlation to query content that
/// would make the failure predictable or avoidable by query shape alone; failures also
/// arrive in multi-second correlated bursts, not independently per request.
///
/// The second attempt gets a larger timeout than the first: a cold TCP+TLS handshake
/// on a higher-latency link can push a genuinely healthy response past a tight budget
/// (live-verified successful response time: ~0.4s on a low-latency link vs. an
/// estimated ~1.0s on a 150ms-RTT one), and `tokio::time::timeout` cancels the first
/// attempt's connection without returning it to `reqwest`'s pool, so the second attempt
/// always pays the handshake cold again and needs the extra headroom.
///
/// Their sum, plus [`SEARCH_RETRY_DELAY`], is deliberately larger than
/// `deps_core::completion::COMPLETION_SEARCH_TIMEOUT` — enforced by
/// `test_search_attempt_budget_exceeds_completion_search_timeout` below. On a total
/// failure with no stale cache to serve (see `search_with_retry`'s `stale` fallback),
/// `search_typed` must not finish before the caller's own timeout does: `deps-lsp`'s
/// completion handler otherwise cannot tell a fast empty/error result apart from
/// "genuinely no results," and re-runs a wasted fallback search against the same
/// struggling registry instead of taking its existing skip-fallback path.
///
/// This guarantee only covers `solrsearch`'s dominant *hang* failure mode, where both
/// attempts run their full timeout. A fast-failing, retryable error (e.g. connection
/// refused, DNS failure) still exhausts both attempts and returns well inside the 2s
/// deadline — the handler's `Ok(empty)` branch still runs the fallback search for that
/// failure mode, same as before this fix. Not a regression, but worth noting since M1's
/// 4xx-is-terminal guard means that failure mode is the one most likely to return fast.
const SEARCH_ATTEMPT_TIMEOUTS: [Duration; 2] =
    [Duration::from_millis(1000), Duration::from_millis(1200)];

/// Delay between `search_typed` retry attempts.
const SEARCH_RETRY_DELAY: Duration = Duration::from_millis(100);

/// `rows` value used for every `solrsearch` request, regardless of the caller's
/// requested `limit` (#282 gap 2).
///
/// `search_typed`'s caller-facing result count is still capped at `limit` by
/// `parse_search_response`'s `.take(limit)` — this only fixes the *request URL*,
/// which doubles as `HttpCache`'s cache key. `deps-lsp`'s completion handler calls
/// `search_typed` with `limit=20` for its primary (typed-field) search and `limit=50`
/// for its fallback search; before this constant, those two calls built different
/// URLs (`rows=20` vs `rows=50`) and so never shared a cache entry, making
/// `HttpCache::peek_cached`'s stale-fallback (see `search_with_retry`) always miss on
/// the fallback path even when a same-query result was already cached moments earlier
/// by the primary path. Set to the largest `limit` any caller passes, so a smaller
/// request is always answerable from the same cache entry as a larger one.
const SEARCH_CACHE_ROWS: usize = 50;

/// TTL for `MavenCentralRegistry::recent_search_failures` (#282 gap 1).
///
/// A completion request's own fallback search (`deps-lsp`'s `completion.rs`, once its
/// extracted query matches the primary path's — see `extract_prefix`'s XML-tag
/// stripping) issues a second `search_typed` call for the same query within the same
/// request, well inside `COMPLETION_SEARCH_TIMEOUT`, whenever the first call fails
/// *fast* (DNS failure, connection refused) rather than hanging —
/// `SEARCH_ATTEMPT_TIMEOUTS`'s hang-mode guarantee (see its doc) only protects against
/// the hang case, not this one. Reusing `COMPLETION_SEARCH_TIMEOUT` as the TTL is sized
/// to comfortably span that in-request duplicate-call window without also suppressing a
/// legitimate retry on a later, unrelated completion request for the same prefix.
///
/// By design, this memo is never populated for the hang failure mode itself: a hang
/// exhausts `SEARCH_ATTEMPT_TIMEOUTS`' full budget, which `deps-lsp`'s own outer
/// `COMPLETION_SEARCH_TIMEOUT` deadline always wins against first (see that constant's
/// doc) — the whole `search_typed` future, including the code that would record a
/// failure here, is cancelled before it can run. That's fine: the hang case is already
/// handled by the caller's existing skip-fallback path, so no second call happens for
/// this memo to prevent.
const RECENT_FAILURE_TTL: Duration = deps_core::completion::COMPLETION_SEARCH_TIMEOUT;

const GOOGLE_PREFIXES: &[&str] = &[
    "androidx.",
    "com.google.firebase.",
    "com.google.android.",
    "com.google.gms.",
    "com.android.",
];

fn is_google_group(group_id: &str) -> bool {
    GOOGLE_PREFIXES.iter().any(|p| group_id.starts_with(p))
}

fn repo_base_for_group(group_id: &str) -> &'static str {
    if is_google_group(group_id) {
        GOOGLE_MAVEN_BASE
    } else {
        MAVEN_REPO_BASE
    }
}

/// Returns the URL for a coordinate's page on Maven Central (or maven.google.com for a
/// Google-group coordinate), falling back to a Central search query when `name` is not a
/// `groupId:artifactId` pair.
///
/// Display link only, never fetched by this process — unlike `metadata_urls` (a fetch
/// sink), so it is deliberately not gated against a `.`/`..` segment (see
/// [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link scope split, #379).
pub fn package_url(name: &str) -> String {
    let parts: Vec<&str> = name.splitn(2, ':').collect();
    if parts.len() == 2 {
        let group_id = parts[0];
        let artifact_id = parts[1];
        if is_google_group(group_id) {
            format!(
                "https://maven.google.com/web/index.html#{}:{}",
                urlencoding::encode(group_id),
                urlencoding::encode(artifact_id)
            )
        } else {
            format!(
                "https://central.sonatype.com/artifact/{}/{}",
                urlencoding::encode(group_id),
                urlencoding::encode(artifact_id)
            )
        }
    } else {
        format!(
            "https://central.sonatype.com/search?q={}",
            urlencoding::encode(name)
        )
    }
}

/// Moves the entry that should be considered "latest" to the front of `versions`, in place:
///
/// - If `release` (maven-metadata.xml's `<release>` element — the authoritative "last
///   deployed" version, which is not necessarily the qualifier-sorted top entry: it can
///   legitimately be a milestone/RC that was the most recent deploy) names an entry present
///   in `versions`, that entry moves to the front. A `release` naming something absent from
///   `versions` (malformed/inconsistent metadata) leaves the list untouched — there's
///   nothing in it to move, and nothing can be synthesized without violating the "index into
///   an existing slice" contract `select_latest_matching` needs.
/// - If `release` is absent (`<release>` missing from the metadata entirely, common for
///   Gradle Plugin Portal and older artifacts), the first non-prerelease entry moves to the
///   front instead — reproducing `get_latest_matching_typed`'s pre-existing else-branch, so
///   an artifact without `<release>` doesn't report a prerelease as "latest" just because it
///   happens to sort first (S7: this was the actual bug behind an earlier version of this
///   fix, which only handled the `release`-present case).
///
/// This lets every consumer of the (already sorted) list — `select_latest_matching`'s
/// pure `Some(0)` pick (`Registry::get_versions` is the only round trip available to it,
/// with no side channel for `<release>`), hover's "Recent versions" `*(latest)*` marker,
/// and completion's version list — agree with the wildcard pick without a second registry
/// call: `get_versions_typed` and `get_latest_matching_typed` already fetch
/// `(versions, release)` from the same single `get_metadata` call, so reordering here is free.
fn move_release_to_front(versions: &mut Vec<MavenVersion>, release: Option<&str>) {
    let target = match release {
        Some(release) => versions.iter().position(|v| v.version == release),
        None => versions
            .iter()
            .position(|v| !crate::version::is_prerelease(v.version.as_str())),
    };
    let Some(pos) = target else { return };
    if pos != 0 {
        let entry = versions.remove(pos);
        versions.insert(0, entry);
    }
}

/// Picks the "latest" version for a wildcard (`*`/empty) requirement from already-fetched
/// `(versions, release)` metadata: prefers the `<release>`-designated entry — synthesizing a
/// placeholder `MavenVersion` if `release` names something absent from `versions`, since
/// `<release>` is still authoritative even when the metadata is otherwise inconsistent,
/// *unless* `release` itself is a prerelease (#340 edge case — see below) — else the first
/// non-prerelease entry, else the first entry.
///
/// Shares its release-present/absent decision shape with [`move_release_to_front`], but
/// differs in the one case that function structurally cannot handle: `release` naming an
/// entry absent from `versions`. `move_release_to_front` must return an index into the
/// existing slice (or no-op), so it can't invent an entry; this function returns an owned
/// `MavenVersion` and has no such constraint, so it trusts `release` unconditionally instead
/// — the same asymmetry `get_latest_matching_typed` had before this extraction. The one
/// exception: when `release` is absent from `versions` AND is itself a prerelease, this
/// returns `None` rather than synthesizing it. This is the sole path through which this
/// function is reachable in production (`Registry::get_latest_matching`'s only caller,
/// `deps-lsp`'s bulk fetch loop, only falls back to it when
/// `Registry::select_latest_matching`'s wildcard branch returned `None`, which for Maven
/// only happens when `versions` is empty) — so without this guard, a
/// `<release>`-names-a-prerelease-absent-from-an-empty-`<versions>`-list metadata shape
/// (malformed but real: `parse_metadata_xml` parses `<release>` and `<versions>`
/// independently) would reproduce #340 through this one narrow, otherwise-unscoped corner.
/// Trade-off, not a free fix: `None` here surfaces as diagnostics' "Unknown package" for
/// this narrow malformed shape — the inverse of #338's general "don't report a resolvable
/// package as unknown" principle. Accepted deliberately (returning `None` rather than
/// inventing a version is the safer failure mode for metadata this inconsistent), not
/// something this function's normal contract silently absorbs.
fn pick_wildcard_latest(versions: &[MavenVersion], release: Option<&str>) -> Option<MavenVersion> {
    if let Some(rel) = release {
        if let Some(found) = versions.iter().find(|v| v.version == rel) {
            return Some(found.clone());
        }
        if crate::version::is_prerelease(rel) {
            return None;
        }
        return Some(MavenVersion {
            version: rel.into(),
            published_at: None,
        });
    }
    versions
        .iter()
        .find(|v| !crate::version::is_prerelease(v.version.as_str()))
        .or_else(|| versions.first())
        .cloned()
}

/// Whether `base` (a metadata directory URL returned by `get_metadata`) is served by
/// Maven Central specifically, i.e. whether fetching its directory listing is worth the
/// request.
///
/// Google Maven's listing always 404s (no negative caching in [`HttpCache`], so an
/// unconditional fetch would retry forever) and the Gradle Plugin Portal's listing has no
/// date column (a wasted fetch+parse every time) — both must cost zero extra requests, not
/// one doomed one, so this checks the specific winning base rather than "some base exists".
fn should_fetch_listing(base: &str) -> bool {
    base.starts_with(MAVEN_REPO_BASE)
}

/// Attaches `published_at` to each version whose string matches an entry in `times`.
///
/// A version present in `versions` but absent from `times` (or vice versa) is not an
/// error: it simply keeps/never gets a `published_at`. Order is untouched — this must run
/// before [`move_release_to_front`] so ordering stays governed by that function alone.
fn attach_publish_times(versions: &mut [MavenVersion], times: &HashMap<String, PublishTime>) {
    for v in versions {
        v.published_at = times.get(v.version.as_str()).copied();
    }
}

#[derive(Clone)]
pub struct MavenCentralRegistry {
    cache: Arc<HttpCache>,
    /// Query -> instant of its last unrecoverable live search failure (#282 gap 1).
    ///
    /// Checked at the top of `search_typed`: a repeat call for the same query within
    /// `RECENT_FAILURE_TTL` returns immediately without a network attempt. A `DashMap`
    /// (like `HttpCache::entries`) rather than a `Mutex<HashMap<_>>`, so concurrent
    /// completion requests for different queries don't contend on one lock and a panic
    /// while holding a shard can't poison the whole map. Wrapped in `Arc` (`DashMap`
    /// itself clones its contents, not a shared handle) so every `Clone` of this
    /// registry shares one map, matching `cache`'s sharing semantics.
    recent_search_failures: Arc<DashMap<String, tokio::time::Instant>>,
}

impl MavenCentralRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            cache,
            recent_search_failures: Arc::new(DashMap::new()),
        }
    }

    /// Fetches and parses `maven-metadata.xml`, also returning the directory URL of
    /// whichever repository base (Maven Central, Google Maven, or the Gradle Plugin
    /// Portal fallback) actually served it — `metadata_urls`' bases differ per group, so
    /// the winning base can only be known after the fetch succeeds, not guessed upfront.
    async fn get_metadata(
        &self,
        name: &str,
    ) -> Result<(Vec<MavenVersion>, Option<String>, Option<String>)> {
        let urls = metadata_urls(name)?;
        if urls.is_empty() {
            tracing::debug!(package = %name, "skipping: invalid groupId:artifactId format");
            return Ok((vec![], None, None));
        }

        let mut last_err = None;
        for url in &urls {
            match self.cache.get_cached(url).await {
                Ok(data) => {
                    let (versions, release) = parse_metadata_xml(&data)?;
                    let base = url.strip_suffix("maven-metadata.xml").map(str::to_string);
                    return Ok((versions, release, base));
                }
                Err(e) => {
                    tracing::debug!(package = %name, url = %url, error = %e, "metadata fetch failed, trying next");
                    last_err = Some(e);
                }
            }
        }

        let e = last_err.expect("urls is non-empty");
        tracing::warn!(package = %name, error = %e, "all metadata URLs failed");
        Err(e)
    }

    /// Fetches the directory listing at `base` (a Maven Central artifact directory URL,
    /// trailing slash) and returns the version → publish-time map parsed from it.
    ///
    /// Never fails the caller: any fetch error, timeout, or unparseable body degrades to
    /// an empty map, logged at `debug`, so a listing outage never affects the version list
    /// itself — only whether ages are shown alongside it.
    async fn fetch_publish_times(&self, base: &str) -> HashMap<String, PublishTime> {
        match self.cache.get_cached(base).await {
            Ok(data) => parse_publish_times(&data),
            Err(e) => {
                tracing::debug!(url = %base, error = %e, "listing fetch failed, publish times unavailable");
                HashMap::new()
            }
        }
    }

    /// Same as [`Self::get_versions_typed`], but attaches [`MavenVersion::published_at`]
    /// from the `repo1.maven.org` directory listing when `freshness_enabled` and the
    /// artifact resolved through Maven Central.
    ///
    /// The listing fetch is gated on the winning base being Maven Central specifically —
    /// not merely present — because Google Maven's listing always 404s (no negative
    /// caching in [`HttpCache`], so an unconditional fetch would retry forever) and the
    /// Gradle Plugin Portal's listing has no date column (a wasted fetch+parse on every
    /// call). Both degrade to zero extra requests here rather than one doomed one.
    pub async fn get_versions_typed_with(
        &self,
        name: &str,
        freshness_enabled: bool,
    ) -> Result<Vec<MavenVersion>> {
        let (mut versions, release, base) = self.get_metadata(name).await?;
        if freshness_enabled && let Some(base) = base.as_deref().filter(|b| should_fetch_listing(b))
        {
            let times = self.fetch_publish_times(base).await;
            attach_publish_times(&mut versions, &times);
        }
        move_release_to_front(&mut versions, release.as_deref());
        Ok(versions)
    }

    /// Fetches all available versions, without publish-time enrichment.
    ///
    /// Delegates to [`Self::get_versions_typed_with`] with freshness disabled so the two
    /// paths cannot drift apart.
    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<MavenVersion>> {
        self.get_versions_typed_with(name, false).await
    }

    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<MavenVersion>> {
        let (versions, release, _base) = self.get_metadata(name).await?;
        // For Maven MVP: exact string match, or latest stable if req is empty/wildcard
        if req.is_empty() || req == "*" {
            return Ok(pick_wildcard_latest(&versions, release.as_deref()));
        }
        Ok(versions.into_iter().find(|v| v.version == req))
    }

    /// Searches Maven Central for artifacts matching `query`.
    ///
    /// Retries against `solrsearch` via `search_with_retry`, falling back to a stale
    /// cached result (if any) on failure, to work around its silent-timeout
    /// unreliability (#274) without exceeding the caller's own completion deadline. See
    /// `SEARCH_ATTEMPT_TIMEOUTS` and `search_with_retry` for the retry/fallback policy.
    ///
    /// A query that failed live within the last `RECENT_FAILURE_TTL` short-circuits to
    /// the same error with no network attempt at all (#282 gap 1) — this is what keeps
    /// a completion request's own fallback search (`deps-lsp`'s `completion.rs`) from
    /// doubling live request volume against an endpoint that is already fast-failing
    /// for this query, since a fast failure (unlike a hang) returns well inside the
    /// caller's own deadline and so does not get skipped by that deadline alone.
    ///
    /// The request always asks `solrsearch` for `SEARCH_CACHE_ROWS` rows regardless of
    /// `limit` (#282 gap 2), so that calls with different `limit`s for the same `query`
    /// share one `HttpCache` entry — `limit` only trims the parsed result afterward via
    /// `parse_search_response`.
    ///
    /// # Errors
    ///
    /// Returns the last error (an HTTP/network error, or a synthesized timeout error)
    /// if every attempt fails and no cached result is available to fall back to.
    pub async fn search_typed(&self, query: &str, limit: usize) -> Result<Vec<ArtifactInfo>> {
        debug_assert!(
            limit <= SEARCH_CACHE_ROWS,
            "search_typed's limit ({limit}) exceeds SEARCH_CACHE_ROWS ({SEARCH_CACHE_ROWS}); \
             raise SEARCH_CACHE_ROWS to cover every caller's requested limit"
        );

        if is_recently_failed(&self.recent_search_failures, query) {
            return Err(DepsError::CacheError(format!(
                "solrsearch recently failed for query {query:?}, \
                 skipping duplicate live attempt"
            )));
        }

        let url = search_url(query);
        let data = search_with_retry(
            || self.cache.get_cached(&url),
            || self.cache.peek_cached(&url),
        )
        .await;

        let data = match data {
            Ok(data) => data,
            Err(e) => {
                // Skip recording an offline block (issue #483 M2): unlike a genuine
                // registry failure, this isn't evidence the query itself is problematic,
                // and poisoning `recent_search_failures` with `RECENT_FAILURE_TTL` would
                // leave search silently broken after `network.offline` flips back to
                // `false`, until the TTL expires on its own.
                if !e.is_offline() {
                    record_search_failure(&self.recent_search_failures, query);
                }
                return Err(e);
            }
        };

        // Only clear the failure memo once the body is confirmed parseable: an HTTP 200
        // with a zero-byte/garbage body is `solrsearch`'s documented failure signature
        // (#274), and `search_with_retry` reports that as `Ok`. Clearing on fetch alone
        // would erase a real failure record without recording the parse failure that
        // follows.
        match parse_search_response(&data, limit) {
            Ok(results) => {
                record_search_success(&self.recent_search_failures, query);
                Ok(results)
            }
            Err(e) => {
                record_search_failure(&self.recent_search_failures, query);
                Err(e)
            }
        }
    }
}

/// Builds the `solrsearch` request URL for `query`.
///
/// Deliberately takes no `limit`: the URL doubles as `HttpCache`'s cache key, and
/// always requesting [`SEARCH_CACHE_ROWS`] rows keeps that key identical across calls
/// for the same `query` regardless of the caller's requested `limit` (#282 gap 2).
fn search_url(query: &str) -> String {
    format!(
        "{MAVEN_SEARCH_BASE}?q={q}&rows={SEARCH_CACHE_ROWS}&wt=json",
        q = urlencoding::encode(query),
    )
}

/// Whether `query` failed live within [`RECENT_FAILURE_TTL`], per `failures`.
fn is_recently_failed(failures: &DashMap<String, tokio::time::Instant>, query: &str) -> bool {
    failures
        .get(query)
        .is_some_and(|failed_at| failed_at.elapsed() < RECENT_FAILURE_TTL)
}

/// Records `query`'s live search failure, pruning already-expired entries first so
/// `failures` doesn't grow unbounded over the server's lifetime. Pruning only happens
/// here (on a new failure), not on every lookup, so `failures` can transiently hold
/// entries older than `RECENT_FAILURE_TTL` between failures — harmless, since
/// `is_recently_failed` still checks each entry's age itself before trusting it.
fn record_search_failure(failures: &DashMap<String, tokio::time::Instant>, query: &str) {
    failures.retain(|_, failed_at| failed_at.elapsed() < RECENT_FAILURE_TTL);
    failures.insert(query.to_string(), tokio::time::Instant::now());
}

/// Clears `query`'s failure record, if any, after a fully successful (fetched and
/// parsed) `search_typed` call.
fn record_search_success(failures: &DashMap<String, tokio::time::Instant>, query: &str) {
    failures.remove(query);
}

/// Whether a failed search attempt is worth retrying live (#274).
///
/// A client-side timeout is always worth retrying — `solrsearch`'s dominant failure
/// mode is a silent hang, not a clean error. An HTTP 5xx may be transient. Any 4xx is
/// treated as terminal: a 400 means the query itself is malformed and retrying changes
/// nothing, and a 429 specifically must NOT be retried immediately — that adds to the
/// very request volume this endpoint's undocumented rate limiting reacts to.
///
/// `DepsError::Offline` (issue #483) is likewise terminal: it is deterministic and
/// permanent for the duration of the config, so retrying it just pays
/// [`SEARCH_RETRY_DELAY`] and an extra iteration for nothing, on a path with a
/// user-facing completion deadline. Before the M2 fix this cost was absorbed by
/// `recent_search_failures` after the first query; now that `search_typed` skips
/// recording an offline block there, every offline completion would otherwise pay it.
fn is_retryable_error(e: &DepsError) -> bool {
    !matches!(e, DepsError::HttpStatus { status, .. } if (400..500).contains(status))
        && !e.is_offline()
}

/// Retries `fetch` across [`SEARCH_ATTEMPT_TIMEOUTS`], each attempt bounded by its own
/// timeout, falling back to a synchronous, non-network `stale` cache peek after any
/// failed attempt (whether it timed out or returned a retryable error) before trying
/// again or giving up (#274).
///
/// The stale check runs after *every* failed attempt, not only once all attempts are
/// exhausted: `solrsearch`'s dominant failure mode is a multi-second hang, and
/// [`SEARCH_ATTEMPT_TIMEOUTS`] plus [`SEARCH_RETRY_DELAY`] are deliberately sized to
/// outlast the caller's own completion deadline on total failure — checking only after
/// full exhaustion would mean this fallback rarely gets a chance to run for that
/// dominant failure mode, since the caller's own timeout would cancel the whole future
/// first. Checking eagerly also serves a repeat query without paying out the full
/// retry budget when cached data is already available (though still only after the
/// first attempt's timeout has elapsed, not instantly).
///
/// Extracted from `search_typed` so the retry/timeout/backoff/stale-fallback mechanics
/// can be unit-tested with a fake `fetch`/`stale` pair under `tokio::time::pause`,
/// without a real HTTPS endpoint: `HttpCache` has no test-mode escape hatch for a
/// mocked server across a crate boundary (its `ensure_https`, in
/// `crates/deps-core/src/cache.rs`, only relaxes for `#[cfg(test)]` within `deps-core`'s
/// own compilation, which does not apply when `deps-maven` links it as a normal
/// dependency).
async fn search_with_retry<F, Fut, S>(mut fetch: F, stale: S) -> Result<Bytes>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Bytes>>,
    S: Fn() -> Option<Bytes>,
{
    let mut last_err = None;
    for (i, attempt_timeout) in SEARCH_ATTEMPT_TIMEOUTS.iter().enumerate() {
        let retryable = match tokio::time::timeout(*attempt_timeout, fetch()).await {
            Ok(Ok(body)) => return Ok(body),
            Ok(Err(e)) => {
                let retryable = is_retryable_error(&e);
                tracing::debug!(attempt = i + 1, error = %e, retryable, "solrsearch attempt failed");
                last_err = Some(e);
                retryable
            }
            Err(_) => {
                tracing::debug!(attempt = i + 1, timeout = ?attempt_timeout, "solrsearch attempt timed out");
                last_err = Some(DepsError::CacheError(format!(
                    "search request timed out after {attempt_timeout:?}"
                )));
                true
            }
        };

        if let Some(body) = stale() {
            tracing::warn!("solrsearch: serving stale cached result after a failed live attempt");
            return Ok(body);
        }

        if !retryable || i + 1 == SEARCH_ATTEMPT_TIMEOUTS.len() {
            break;
        }
        tokio::time::sleep(SEARCH_RETRY_DELAY).await;
    }
    Err(last_err
        .expect("SEARCH_ATTEMPT_TIMEOUTS is non-empty, so at least one attempt always runs"))
}

/// Returns ordered list of maven-metadata.xml URLs to try for the given package.
///
/// Non-Google packages get two URLs: Maven Central (primary) and Gradle Plugin Portal (fallback).
/// Google-hosted packages get only the Google Maven URL — they are not mirrored elsewhere.
///
/// Returns `Ok(vec![])` (treated by [`MavenCentralRegistry::get_metadata`] as "no versions
/// found") only for a malformed `groupId:artifactId` pair with no `:` separator.
///
/// Returns `Err(DepsError::PackageNotFound)` — mirroring `deps-dart`'s `reject_dot_segment`
/// (#349) — when either coordinate segment fails [`is_safe_maven_coordinate_segment`]: a
/// `groupId`/`artifactId` containing `../` (or other path-breakout characters) must never
/// reach the `.`→`/` replace and URL construction below, since `group_path`/`artifact_id`
/// are interpolated into the request URL unescaped. Propagating this as an error (rather
/// than folding it into the empty-URL-list case) keeps it distinguishable from a genuine
/// 404, so hover correctly renders nothing for a rejected coordinate instead of a broken
/// "package not found" section (#366).
fn metadata_urls(name: &str) -> Result<Vec<String>> {
    let Some((group_id, artifact_id)) = name.split_once(':') else {
        return Ok(vec![]);
    };
    if !is_safe_maven_coordinate_segment(group_id) {
        warn_rejected_value(
            "is_safe_maven_coordinate_segment",
            "maven metadata URL groupId",
            group_id,
        );
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    if !is_safe_maven_coordinate_segment(artifact_id) {
        warn_rejected_value(
            "is_safe_maven_coordinate_segment",
            "maven metadata URL artifactId",
            artifact_id,
        );
        return Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    let group_path = group_id.replace('.', "/");
    let primary_base = repo_base_for_group(group_id);
    let primary = format!("{primary_base}/{group_path}/{artifact_id}/maven-metadata.xml");

    Ok(if is_google_group(group_id) {
        vec![primary]
    } else {
        vec![
            primary,
            format!("{GRADLE_PLUGIN_PORTAL_BASE}/{group_path}/{artifact_id}/maven-metadata.xml"),
        ]
    })
}

/// Parses maven-metadata.xml to extract version list and the authoritative release version.
///
/// Returns `(versions, release)` where `release` is the `<release>` element from
/// `<versioning>`, if present. Use `release` as the authoritative latest stable version
/// instead of sorting all versions.
///
/// # Errors
///
/// Returns `DepsError::CacheError` if the XML is malformed. A truncated `versions` list from
/// silently stopping at the parse error, rather than surfacing it, would itself be a source
/// of the same "real version missing from `available`" false-positive class this PR's
/// diagnostic guards against elsewhere.
fn parse_metadata_xml(data: &[u8]) -> Result<(Vec<MavenVersion>, Option<String>)> {
    let mut reader = Reader::from_reader(data);
    let mut versions = Vec::new();
    let mut release: Option<String> = None;
    let mut in_versions = false;
    let mut in_version = false;
    let mut in_release = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                "versions" => in_versions = true,
                "version" if in_versions => in_version = true,
                "release" if !in_versions => in_release = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                "versions" => in_versions = false,
                "version" => in_version = false,
                "release" => in_release = false,
                _ => {}
            },
            Ok(Event::Text(e)) => {
                let text = quick_xml::escape::unescape(&e).unwrap_or_default();
                let s = text.trim().to_string();
                if s.is_empty() {
                    buf.clear();
                    continue;
                }
                if in_version {
                    versions.push(MavenVersion {
                        version: s.into(),
                        published_at: None,
                    });
                } else if in_release {
                    release = Some(s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(DepsError::CacheError(format!(
                    "malformed maven-metadata.xml: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    versions.sort_by(|a, b| compare_versions(b.version.as_str(), a.version.as_str()));
    Ok((versions, release))
}

/// Parses a Maven Central directory listing (`repo1.maven.org/maven2/{g}/{a}/`) into a
/// version → publish-time map.
///
/// Line-oriented, not a full HTML parser: each line is checked independently for both an
/// anchor `href` (never the display text, which Maven Central sometimes pads or wraps in
/// a `title=` attribute) and a `YYYY-MM-DD HH:MM` timestamp anywhere on the line; a line
/// missing either yields nothing. This is what makes the Gradle Plugin Portal's dateless
/// `<pre><a href="X/">X/</a></pre>` listing format — and any other listing that carries no
/// date column — parse to an empty map instead of a guess.
///
/// Bounded by the same 32 MiB response cap [`HttpCache`] applies to every fetch (not a
/// meaningfully tight bound on its own); real listings are far smaller (up to ~245 KB /
/// ~2000 anchors observed for a large artifact).
fn parse_publish_times(html: &[u8]) -> HashMap<String, PublishTime> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(html);
    let Some(pre) = extract_pre_block(&text) else {
        return map;
    };

    for line in pre.lines() {
        let Some(href) = extract_href(line) else {
            continue;
        };
        // Only directory entries (trailing `/`) are version directories — a sibling file
        // entry (`maven-metadata.xml`, `.md5`, `.sha1`, ...) also carries an href and a
        // date, but is never a version, so keeping it out of the map avoids polluting it
        // with keys that will just never be looked up.
        let Some(version) = href.strip_suffix('/') else {
            continue;
        };
        if version.is_empty() || version == ".." {
            continue;
        }
        let Some(date_str) = find_date_time(line) else {
            continue;
        };
        let rfc3339 = format!("{}T{}:00Z", &date_str[..10], &date_str[11..16]);
        if let Some(published) = PublishTime::parse_rfc3339(&rfc3339) {
            map.insert(version.to_string(), published);
        }
    }

    map
}

/// Slices out the body of the first `<pre>...</pre>` block, case-sensitively (Maven
/// Central and the Gradle Plugin Portal both emit lowercase tags). Returns `None` when no
/// `<pre>` block is present, so a page shaped nothing like a directory listing yields an
/// empty map rather than scanning arbitrary HTML for anchor-shaped text.
fn extract_pre_block(html: &str) -> Option<&str> {
    let open = html.find("<pre")?;
    let content_start = html[open..].find('>')? + open + 1;
    let close = html[content_start..].find("</pre")?;
    Some(&html[content_start..content_start + close])
}

/// Extracts an anchor's `href` attribute value from a listing line, ignoring display text.
fn extract_href(line: &str) -> Option<&str> {
    let idx = line.find("href=\"")?;
    let rest = &line[idx + 6..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Finds the first `YYYY-MM-DD HH:MM` substring anywhere in `line`, independent of column
/// alignment or padding. All matched bytes are ASCII, so the returned slice's byte offsets
/// are always valid `str` char boundaries.
fn find_date_time(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let window = 16; // "YYYY-MM-DD HH:MM"
    if bytes.len() < window {
        return None;
    }
    for start in 0..=(bytes.len() - window) {
        let candidate = &bytes[start..start + window];
        if is_date_time_shape(candidate) {
            return Some(&line[start..start + window]);
        }
    }
    None
}

fn is_date_time_shape(b: &[u8]) -> bool {
    let digit = u8::is_ascii_digit;
    digit(&b[0])
        && digit(&b[1])
        && digit(&b[2])
        && digit(&b[3])
        && b[4] == b'-'
        && digit(&b[5])
        && digit(&b[6])
        && b[7] == b'-'
        && digit(&b[8])
        && digit(&b[9])
        && b[10] == b' '
        && digit(&b[11])
        && digit(&b[12])
        && b[13] == b':'
        && digit(&b[14])
        && digit(&b[15])
}

#[derive(Deserialize)]
struct SolrSearchResponse {
    response: SolrSearchBody,
}

#[derive(Deserialize)]
struct SolrSearchBody {
    #[serde(default)]
    docs: Vec<SearchDoc>,
}

#[derive(Deserialize)]
struct SearchDoc {
    g: String,
    a: String,
    #[serde(rename = "latestVersion")]
    latest_version: Option<String>,
}

fn parse_search_response(data: &[u8], limit: usize) -> Result<Vec<ArtifactInfo>> {
    let response: SolrSearchResponse = deps_core::parse_json_checked(data)?;

    let results = response
        .response
        .docs
        .into_iter()
        .take(limit)
        .map(|d| {
            let name = format!("{}:{}", d.g, d.a);
            ArtifactInfo {
                group_id: d.g,
                artifact_id: d.a,
                name: name.into(),
                description: None,
                latest_version: d.latest_version.unwrap_or_default().into(),
                repository: None,
            }
        })
        .collect();

    Ok(results)
}

impl deps_core::Registry for MavenCentralRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions_typed(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self
                .get_versions_typed_with(name.as_str(), freshness.enabled)
                .await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching_typed(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let results = self.search_typed(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        // `versions` is `get_versions`'s output, which already moved the maven-metadata.xml
        // `<release>` entry to the front (`move_release_to_front`). Unlike npm's curated
        // `dist-tags.latest`, Maven Central's `<release>`/`<latest>` tags carry no
        // prerelease semantics — they simply track the most recently *deployed* artifact,
        // which can itself be a prerelease. So index 0 is trusted only when it isn't one;
        // otherwise scan for the newest non-prerelease entry. When every version is a
        // prerelease (#340), this does NOT fall back to raw index 0 either — see the
        // version-comparison scan below (M1) — since `move_release_to_front` may have
        // hoisted a `<release>`-tagged prerelease that isn't actually the newest deployed
        // one. This keeps `select_latest_matching` (no I/O, no side channel) agreeing with
        // hover's `is_stable()`-based pick whenever a stable version exists.
        let req_str = req.as_str();
        if req_str.is_empty() || req_str == "*" {
            if versions.is_empty() {
                return None;
            }
            if let Some(idx) = versions.iter().position(|v| !v.is_prerelease()) {
                return Some(idx);
            }
            // FR-002: every version is a prerelease. Don't just trust index 0 here —
            // `move_release_to_front` may have hoisted a `<release>`-tagged prerelease
            // that isn't actually the newest deployed one (M1); scan by actual version
            // comparison instead, same comparator `get_versions` already sorted by.
            return versions
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    crate::version::compare_versions(
                        a.version_string().as_str(),
                        b.version_string().as_str(),
                    )
                })
                .map(|(idx, _)| idx);
        }
        versions.iter().position(|v| v.version_string() == req_str)
    }

    // Maven Central has no retraction concept (`types.rs:98`) — `removal_status`
    // uses the trait's default `Available`. Also covers Gradle, whose `registry()`
    // returns its own instance of this same `MavenCentralRegistry` type (#233).
    fn reports_yanked(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_base_for_group_central() {
        assert_eq!(repo_base_for_group("org.apache.commons"), MAVEN_REPO_BASE);
        assert_eq!(repo_base_for_group("com.example"), MAVEN_REPO_BASE);
        // com.google.protobuf is on Maven Central, not Google Maven
        assert_eq!(repo_base_for_group("com.google.protobuf"), MAVEN_REPO_BASE);
    }

    #[test]
    fn test_repo_base_for_group_google() {
        assert_eq!(repo_base_for_group("androidx.core"), GOOGLE_MAVEN_BASE);
        assert_eq!(
            repo_base_for_group("com.google.firebase.crashlytics"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(
            repo_base_for_group("com.google.android.gms"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(
            repo_base_for_group("com.google.gms.google-services"),
            GOOGLE_MAVEN_BASE
        );
        assert_eq!(repo_base_for_group("com.android.tools"), GOOGLE_MAVEN_BASE);
    }

    #[test]
    fn test_package_url_central() {
        assert_eq!(
            package_url("org.apache.commons:commons-lang3"),
            "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3"
        );
    }

    #[test]
    fn test_package_url_google() {
        assert_eq!(
            package_url("androidx.core:core-ktx"),
            "https://maven.google.com/web/index.html#androidx.core:core-ktx"
        );
        assert_eq!(
            package_url("com.google.firebase.crashlytics:firebase-crashlytics"),
            "https://maven.google.com/web/index.html#com.google.firebase.crashlytics:firebase-crashlytics"
        );
    }

    #[test]
    fn test_package_url_no_colon() {
        let url = package_url("bad");
        assert!(url.contains("search.maven") || url.contains("sonatype.com"));
    }

    #[test]
    fn test_package_url_encodes_malicious_group_and_artifact() {
        let url = package_url("evil)[:pkg](x");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_google_encodes_malicious_group_and_artifact() {
        let url = package_url("androidx.evil)[:pkg](x");
        assert!(url.contains("maven.google.com"));
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<%:pkg>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_metadata_urls_central_has_two_urls() {
        let urls = metadata_urls("org.apache.commons:commons-lang3").unwrap();
        assert_eq!(urls.len(), 2);
        assert_eq!(
            urls[0],
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
        assert_eq!(
            urls[1],
            "https://plugins.gradle.org/m2/org/apache/commons/commons-lang3/maven-metadata.xml"
        );
    }

    #[test]
    fn test_metadata_urls_google_has_one_url() {
        let urls = metadata_urls("androidx.core:core-ktx").unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0],
            "https://dl.google.com/dl/android/maven2/androidx/core/core-ktx/maven-metadata.xml"
        );

        let urls = metadata_urls("com.google.firebase.crashlytics:firebase-crashlytics").unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(
            urls[0],
            "https://dl.google.com/dl/android/maven2/com/google/firebase/crashlytics/firebase-crashlytics/maven-metadata.xml"
        );
    }

    #[test]
    fn test_metadata_urls_no_colon() {
        assert!(metadata_urls("bad").unwrap().is_empty());
    }

    /// #366: a rejected coordinate must surface specifically as `PackageNotFound`, not
    /// merely *some* error — `DepsError::is_not_found()` (checked by
    /// `deps-lsp/src/document/lifecycle.rs`) is what keeps the diagnostic classified as
    /// "Unknown package" rather than "Registry lookup failed", and is also what makes
    /// `generate_hover`'s `.ok()?` chain return `None` the same way it already does for a
    /// genuine 404.
    fn assert_rejected_as_not_found(result: Result<Vec<String>>) {
        let err = result.expect_err("rejected coordinate must be Err");
        assert!(
            matches!(err, DepsError::PackageNotFound { .. }),
            "expected PackageNotFound, got {err:?}"
        );
        assert!(err.is_not_found());
    }

    /// #349: `com.example:../../../admin` (confirmed live) must not escape the `maven2`
    /// prefix via the artifact_id segment. The fix rejects the coordinate outright
    /// (`is_safe_maven_coordinate_segment` gate) rather than attempting to
    /// escape/percent-encode it, so the correct regression assertion is that *no* metadata
    /// URL is built at all — there is structurally nothing left for a
    /// `url::Url::parse` check to validate once the request itself is suppressed.
    ///
    /// #366: the rejection is a distinct error (`PackageNotFound`), not the same empty-list
    /// case as a malformed `groupId:artifactId` pair — this is what lets hover distinguish
    /// "not found" from a security-gated coordinate and return `None` for both.
    #[test]
    fn test_metadata_urls_rejects_path_traversal_artifact_id() {
        assert_rejected_as_not_found(metadata_urls("com.example:../../../admin"));
    }

    /// #349: same guard, but the traversal sits in the groupId segment instead.
    #[test]
    fn test_metadata_urls_rejects_path_traversal_group_id() {
        assert_rejected_as_not_found(metadata_urls("../../../admin:artifact"));
    }

    /// M1 (impl-critic): a literal `..` artifactId is made only of otherwise-allowed
    /// characters (`is_safe_maven_coordinate_segment`'s charset permits `.`), so it used to
    /// slip past the gate even though it is not a real Maven coordinate segment —
    /// `metadata_urls("com.example:..")` collapsed to `/maven2/com/maven-metadata.xml`,
    /// dropping the `example`/artifactId path components via dot-segment normalization.
    /// Confined to the `maven2` prefix (not a breakout, per the critique), but must still
    /// be rejected outright like any other dot-segment gate in this PR.
    #[test]
    fn test_metadata_urls_rejects_literal_dot_dot_artifact_id() {
        assert_rejected_as_not_found(metadata_urls("com.example:.."));
        assert_rejected_as_not_found(metadata_urls("a:.."));
    }

    /// M1: same guard for a literal `.` artifactId/groupId.
    #[test]
    fn test_metadata_urls_rejects_literal_dot_segment() {
        assert_rejected_as_not_found(metadata_urls("com.example:."));
        assert_rejected_as_not_found(metadata_urls(".:artifact"));
    }

    /// #365 regression sweep: exercises the real production, self-gating `metadata_urls`
    /// sink against the shared adversarial input set (varying artifactId, then groupId),
    /// guarding against a 6th recurrence of #349's defect class.
    #[test]
    fn test_metadata_urls_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                metadata_urls(&format!("com.example:{seg}"))
                    .ok()
                    .and_then(|urls| urls.into_iter().next())
            },
            "repo1.maven.org",
            "/maven2/",
        );
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                metadata_urls(&format!("{seg}:artifact"))
                    .ok()
                    .and_then(|urls| urls.into_iter().next())
            },
            "repo1.maven.org",
            "/maven2/",
        );
    }

    /// #349: a legitimate coordinate must still resolve to a URL confined to the
    /// `maven2` (or Gradle Plugin Portal) prefix — verified structurally via
    /// `url::Url::parse`, not a raw-string `contains` check, so a future regression that
    /// reintroduces unescaped interpolation without breaking the existing exact-string
    /// tests would still be caught here.
    #[test]
    fn test_metadata_urls_parsed_url_stays_within_maven2_prefix() {
        let urls = metadata_urls("org.apache.commons:commons-lang3").unwrap();
        let parsed = url::Url::parse(&urls[0]).unwrap();
        let segments: Vec<&str> = parsed.path_segments().unwrap().collect();
        assert_eq!(
            segments,
            vec![
                "maven2",
                "org",
                "apache",
                "commons",
                "commons-lang3",
                "maven-metadata.xml"
            ]
        );
    }

    #[test]
    fn test_parse_metadata_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <versioning>
    <latest>3.14.0</latest>
    <release>3.14.0</release>
    <versions>
      <version>3.12.0</version>
      <version>3.13.0</version>
      <version>3.14.0</version>
    </versions>
  </versioning>
</metadata>"#;

        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, "3.14.0");
        assert_eq!(versions[1].version, "3.13.0");
        assert_eq!(versions[2].version, "3.12.0");
        assert_eq!(release.as_deref(), Some("3.14.0"));
    }

    #[test]
    fn test_parse_metadata_xml_empty() {
        let xml = r#"<?xml version="1.0"?><metadata><versioning><versions></versions></versioning></metadata>"#;
        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert!(versions.is_empty());
        assert!(release.is_none());
    }

    #[test]
    fn test_parse_metadata_xml_legacy_versions_release_wins() {
        // Guava scenario: legacy bare-qualifier r03-r09 releases must sort below
        // properly-formed numeric releases, and <release> is authoritative for latest stable.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>33.5.0-jre</latest>
    <release>33.5.0-jre</release>
    <versions>
      <version>r03</version>
      <version>r05</version>
      <version>r09</version>
      <version>14.0</version>
      <version>33.4.0-jre</version>
      <version>33.5.0-jre</version>
    </versions>
  </versioning>
</metadata>"#;

        let (versions, release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        assert_eq!(versions.len(), 6);
        assert_eq!(release.as_deref(), Some("33.5.0-jre"));

        let ordered: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(
            ordered,
            vec!["33.5.0-jre", "33.4.0-jre", "14.0", "r09", "r05", "r03"],
            "numeric releases must sort above legacy bare qualifiers"
        );
    }

    #[test]
    fn test_parse_metadata_xml_mixed_segment_count_sort_does_not_panic() {
        // C1 regression guard: an artifact publishing both a 2- and 3-segment
        // spelling of the same release plus a same-base above-release
        // qualifier build used to make compare_versions a non-total order
        // (#182's absent-as-zero rule collided with qualifier ranking at the
        // flat segment index), which panics `Vec::sort_by`'s total-order
        // detector. compare_versions must stay total-order; range/interval
        // normalization lives in compare_versions_for_range instead.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>widget</artifactId>
  <versioning>
    <versions>
      <version>1.0</version>
      <version>1.0.0</version>
      <version>1.0-jre</version>
    </versions>
  </versioning>
</metadata>"#;

        let (versions, _release) = parse_metadata_xml(xml.as_bytes()).unwrap();
        let ordered: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(ordered, vec!["1.0.0", "1.0-jre", "1.0"]);
    }

    /// Minor item: malformed XML must surface as an error, not silently return a truncated
    /// `versions` list — a truncation could itself drop a real, installable version out of
    /// `available`, the exact false-positive class this PR's diagnostic guards against.
    #[test]
    fn test_parse_metadata_xml_malformed_returns_error_instead_of_silent_truncation() {
        let xml = b"<metadata><versioning><versions><version>1.0.0</version></versions></wrong></metadata>";
        let result = parse_metadata_xml(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "response": {
                "numFound": 2,
                "docs": [
                    {"g": "org.apache.commons", "a": "commons-lang3", "latestVersion": "3.14.0"},
                    {"g": "org.apache.commons", "a": "commons-math3", "latestVersion": "3.6.1"}
                ]
            }
        }"#;

        let results = parse_search_response(json.as_bytes(), 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].name, "org.apache.commons:commons-lang3");
        assert_eq!(results[0].latest_version, "3.14.0");
    }

    #[test]
    fn test_parse_search_response_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"response": {{"docs": []}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_search_response(json.as_bytes(), 10).is_ok());
    }

    #[test]
    fn test_parse_search_response_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"response": {{"docs": []}}, "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_search_response(json.as_bytes(), 10).is_err());
    }

    /// Manual live probe against the real endpoint (#274) — NOT deterministic
    /// regression coverage: `solrsearch`'s live health varies run to run, so this can
    /// pass or fail independently of whether `search_with_retry`'s logic is correct.
    /// Deterministic coverage for the retry/timeout/backoff/stale-fallback mechanics
    /// lives in the `search_with_retry` tests below, which use fakes under
    /// `tokio::time::pause` and don't depend on network health. Run this one manually
    /// via `cargo test -p deps-maven -- --ignored` to sanity-check against the real
    /// endpoint.
    #[tokio::test]
    #[ignore]
    async fn test_search_typed_real_guava() {
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let results = registry.search_typed("guava", 20).await.unwrap();

        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .any(|r| r.group_id == "com.google.guava" && r.artifact_id == "guava")
        );
    }

    /// S1 guard rail: a total-failure `search_typed` call (no stale cache to fall back
    /// on) must take longer than `deps-lsp`'s completion deadline, so that deadline's
    /// own timeout fires first and takes its existing skip-fallback path, rather than
    /// `search_typed` finishing fast with an empty/error result the caller cannot
    /// distinguish from "genuinely no results" (see [`SEARCH_ATTEMPT_TIMEOUTS`]'s doc).
    #[test]
    fn test_search_attempt_budget_exceeds_completion_search_timeout() {
        let attempts_total: Duration = SEARCH_ATTEMPT_TIMEOUTS.iter().sum();
        let delays_total = SEARCH_RETRY_DELAY * (SEARCH_ATTEMPT_TIMEOUTS.len() as u32 - 1);
        assert!(
            attempts_total + delays_total > deps_core::completion::COMPLETION_SEARCH_TIMEOUT,
            "search_typed's worst-case retry budget must outlast the completion \
             handler's own timeout (#274/S1)"
        );
    }

    /// R4 (code review of #274/S1's guard): the constant-arithmetic assertion in
    /// `test_search_attempt_budget_exceeds_completion_search_timeout` holds even under
    /// a fast-failing retryable error, where the invariant it's meant to guard doesn't
    /// actually apply (see [`SEARCH_ATTEMPT_TIMEOUTS`]'s doc). This test exercises the
    /// actual hang-mode behavior instead: a total-failure `search_with_retry` call (no
    /// stale cache) must not resolve before `COMPLETION_SEARCH_TIMEOUT` elapses.
    #[tokio::test(start_paused = true)]
    async fn test_search_with_retry_total_failure_outlasts_completion_search_timeout() {
        let start = tokio::time::Instant::now();
        let result = search_with_retry(
            || async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(Bytes::new())
            },
            || None,
        )
        .await;

        assert!(result.is_err());
        assert!(
            start.elapsed() >= deps_core::completion::COMPLETION_SEARCH_TIMEOUT,
            "a total-failure call must not resolve before the completion handler's own \
             timeout does (#274/S1), elapsed={:?}",
            start.elapsed()
        );
    }

    /// #282 gap 2: the request URL (which doubles as `HttpCache`'s cache key) must not
    /// vary with the caller's requested `limit`, so a `limit=50` fallback search can
    /// reuse a `limit=20` primary search's cached/stale result for the same query.
    #[test]
    fn test_search_url_is_limit_independent() {
        assert_eq!(
            search_url("commons-lang3"),
            "https://search.maven.org/solrsearch/select?q=commons-lang3&rows=50&wt=json"
        );
    }

    #[test]
    fn test_is_recently_failed_true_within_ttl() {
        let failures = DashMap::new();
        failures.insert("guava".to_string(), tokio::time::Instant::now());
        assert!(is_recently_failed(&failures, "guava"));
    }

    #[test]
    fn test_is_recently_failed_false_for_unknown_query() {
        let failures = DashMap::new();
        assert!(!is_recently_failed(&failures, "guava"));
    }

    /// #282 gap 1: an expired entry must not keep suppressing live attempts forever —
    /// once `RECENT_FAILURE_TTL` has passed, a legitimate retry is allowed again.
    #[tokio::test(start_paused = true)]
    async fn test_is_recently_failed_false_after_ttl_expires() {
        let failures = DashMap::new();
        failures.insert("guava".to_string(), tokio::time::Instant::now());

        tokio::time::advance(RECENT_FAILURE_TTL + Duration::from_millis(1)).await;

        assert!(!is_recently_failed(&failures, "guava"));
    }

    /// #282 gap 1: `record_search_failure` must not let `failures` grow unbounded —
    /// already-expired entries for other queries are pruned on every new failure.
    #[tokio::test(start_paused = true)]
    async fn test_record_search_failure_prunes_expired_entries() {
        let failures = DashMap::new();
        record_search_failure(&failures, "old-query");
        assert_eq!(failures.len(), 1);

        tokio::time::advance(RECENT_FAILURE_TTL + Duration::from_millis(1)).await;
        record_search_failure(&failures, "new-query");

        assert_eq!(failures.len(), 1);
        assert!(failures.contains_key("new-query"));
        assert!(!failures.contains_key("old-query"));
    }

    #[test]
    fn test_record_search_success_clears_failure() {
        let failures = DashMap::new();
        failures.insert("guava".to_string(), tokio::time::Instant::now());

        record_search_success(&failures, "guava");

        assert!(!failures.contains_key("guava"));
    }

    #[test]
    fn test_record_search_success_on_unknown_query_is_a_no_op() {
        let failures = DashMap::new();
        record_search_success(&failures, "guava");
        assert!(failures.is_empty());
    }

    /// #282 gap 1: a query that just failed live short-circuits the next `search_typed`
    /// call for the same query with no network attempt — the returned error names the
    /// suppression explicitly, distinguishing it from a real HTTP/timeout failure.
    #[tokio::test]
    async fn test_search_typed_short_circuits_on_recent_failure() {
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        registry
            .recent_search_failures
            .insert("guava".to_string(), tokio::time::Instant::now());

        let err = registry.search_typed("guava", 20).await.unwrap_err();

        assert!(err.to_string().contains("skipping duplicate live attempt"));
    }

    /// Issue #483 M2: an offline block must not poison `recent_search_failures` — unlike a
    /// genuine registry failure, it says nothing about whether `query` itself is broken, and
    /// `RECENT_FAILURE_TTL` would otherwise leave search silently short-circuited for a
    /// while after `network.offline` flips back to `false`.
    #[tokio::test]
    async fn test_search_typed_offline_does_not_poison_recent_failures() {
        let cache = Arc::new(HttpCache::new());
        cache.set_offline(true);
        let registry = MavenCentralRegistry::new(cache);

        let err = registry.search_typed("guava", 20).await.unwrap_err();

        assert!(err.is_offline(), "expected Offline, got {err:?}");
        assert!(
            registry.recent_search_failures.is_empty(),
            "an offline block must not be recorded as a search failure"
        );
    }

    /// #282 S1: `parse_search_response` is the sole trim mechanism now that the request
    /// URL always asks for `SEARCH_CACHE_ROWS` regardless of the caller's `limit` — a
    /// caller asking for fewer results than the response contains must still get back
    /// only what it asked for.
    #[test]
    fn test_parse_search_response_trims_to_limit() {
        let json = r#"{
            "response": {
                "numFound": 2,
                "docs": [
                    {"g": "org.apache.commons", "a": "commons-lang3", "latestVersion": "3.14.0"},
                    {"g": "org.apache.commons", "a": "commons-math3", "latestVersion": "3.6.1"}
                ]
            }
        }"#;

        let results = parse_search_response(json.as_bytes(), 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "org.apache.commons:commons-lang3");
    }

    #[tokio::test(start_paused = true)]
    async fn test_search_with_retry_first_attempt_fails_second_succeeds() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let result = search_with_retry(
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(DepsError::CacheError("boom".into()))
                    } else {
                        Ok(Bytes::from_static(b"ok"))
                    }
                }
            },
            || None,
        )
        .await;

        assert_eq!(result.unwrap(), Bytes::from_static(b"ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_search_with_retry_all_attempts_timeout_no_cache_returns_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let result = search_with_retry(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok(Bytes::new())
                }
            },
            || None,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// #274/S2: a hung live attempt must not prevent a known-good stale cached result
    /// from being served, and it must be served after the *first* failed attempt, not
    /// only once every attempt is exhausted (see `search_with_retry`'s doc for why).
    #[tokio::test(start_paused = true)]
    async fn test_search_with_retry_serves_stale_cache_after_first_timeout() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let result = search_with_retry(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok(Bytes::new())
                }
            },
            || Some(Bytes::from_static(b"stale")),
        )
        .await;

        assert_eq!(result.unwrap(), Bytes::from_static(b"stale"));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "stale cache should short-circuit after the first failed attempt, not wait \
             for both"
        );
    }

    /// #274/M1: a 4xx (e.g. malformed query, or 429 rate-limiting) must not be retried
    /// immediately — retrying 429 specifically would add to the load suspected of
    /// triggering the rate limit in the first place.
    #[tokio::test]
    async fn test_search_with_retry_4xx_status_is_not_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let result = search_with_retry(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(DepsError::HttpStatus {
                        url: MAVEN_SEARCH_BASE.to_string(),
                        status: 400,
                    })
                }
            },
            || None,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_search_with_retry_5xx_status_is_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = AtomicUsize::new(0);
        let result = search_with_retry(
            || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        Err(DepsError::HttpStatus {
                            url: MAVEN_SEARCH_BASE.to_string(),
                            status: 503,
                        })
                    } else {
                        Ok(Bytes::from_static(b"ok"))
                    }
                }
            },
            || None,
        )
        .await;

        assert_eq!(result.unwrap(), Bytes::from_static(b"ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = MavenCentralRegistry::new(cache);
    }

    #[test]
    fn test_registry_as_any() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        assert!(registry.as_any().is::<MavenCentralRegistry>());
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        // `select_latest_matching`'s contract is "index 0 of a `get_versions`-shaped list
        // is latest" — `get_versions_typed` is what puts the right entry at index 0 (via
        // `move_release_to_front`), not `select_latest_matching` itself, so this fixture
        // reflects an already-correctly-ordered list rather than an unordered one.
        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            }),
            Box::new(MavenVersion {
                version: "2.0.0-SNAPSHOT".into(),
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_move_release_to_front_reorders() {
        let mut versions = vec![
            MavenVersion {
                version: "3.4.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "4.0.0-M1".into(),
                published_at: None,
            },
        ];
        // <release> designates the milestone even though it isn't the "stable-looking"
        // entry — the exact `spring-core` scenario this fix targets.
        move_release_to_front(&mut versions, Some("4.0.0-M1"));
        assert_eq!(versions[0].version, "4.0.0-M1");
        assert_eq!(versions[1].version, "3.4.0");
    }

    #[test]
    fn test_move_release_to_front_already_first_is_a_no_op() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                published_at: None,
            },
        ];
        move_release_to_front(&mut versions, Some("1.0.0"));
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "0.9.0");
    }

    #[test]
    fn test_move_release_to_front_release_absent_from_list_is_a_no_op() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "0.9.0".into(),
                published_at: None,
            },
        ];
        move_release_to_front(&mut versions, Some("2.0.0"));
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "0.9.0");
    }

    #[test]
    fn test_move_release_to_front_no_release_is_a_no_op() {
        let mut versions = vec![MavenVersion {
            version: "1.0.0".into(),
            published_at: None,
        }];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "1.0.0");
    }

    /// S7 regression: an artifact without a `<release>` element used to leave index 0 at
    /// whatever the raw qualifier sort put first, which can be a prerelease.
    #[test]
    fn test_move_release_to_front_no_release_falls_back_to_first_non_prerelease() {
        let mut versions = vec![
            MavenVersion {
                version: "1.5.0-alpha01".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.4.0".into(),
                published_at: None,
            },
        ];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "1.4.0");
        assert_eq!(versions[1].version, "1.5.0-alpha01");
    }

    #[test]
    fn test_move_release_to_front_no_release_and_all_prerelease_leaves_sorted_top() {
        let mut versions = vec![
            MavenVersion {
                version: "2.0.0-alpha".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.0.0-beta".into(),
                published_at: None,
            },
        ];
        move_release_to_front(&mut versions, None);
        assert_eq!(versions[0].version, "2.0.0-alpha");
    }

    #[test]
    fn test_pick_wildcard_latest_prefers_release() {
        let versions = vec![
            MavenVersion {
                version: "1.4.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.5.0-M1".into(),
                published_at: None,
            },
        ];
        let picked = pick_wildcard_latest(&versions, Some("1.5.0-M1")).unwrap();
        assert_eq!(picked.version, "1.5.0-M1");
    }

    #[test]
    fn test_pick_wildcard_latest_release_absent_from_list_synthesizes() {
        // The one documented case where pick_wildcard_latest and
        // move_release_to_front/select_latest_matching structurally cannot agree: <release>
        // is still trusted here since this function can return an owned value, but
        // move_release_to_front can only return an index into the existing slice.
        let versions = vec![MavenVersion {
            version: "1.0.0".into(),
            published_at: None,
        }];
        let picked = pick_wildcard_latest(&versions, Some("9.9.9")).unwrap();
        assert_eq!(picked.version, "9.9.9");
    }

    /// #340 residual edge case (found during validation, not the original spec): when
    /// `release` names a prerelease absent from `versions` — the exact shape
    /// `Registry::get_latest_matching`'s only production caller reaches this function
    /// through, since `versions` is always empty there — `pick_wildcard_latest` must not
    /// synthesize a placeholder for it. Doing so would reproduce #340 through this one
    /// narrow corner even after the `select_latest_matching` fix.
    #[test]
    fn test_pick_wildcard_latest_release_prerelease_absent_from_list_returns_none() {
        let versions: Vec<MavenVersion> = vec![];
        let picked = pick_wildcard_latest(&versions, Some("8.0.0.Beta1"));
        assert!(picked.is_none());
    }

    /// Companion to the above: a *stable* `release` absent from `versions` is unaffected
    /// (unlikely to be a real issue in practice — this is the pre-existing, deliberately
    /// documented synthesis behavior for a non-prerelease `<release>` tag).
    #[test]
    fn test_pick_wildcard_latest_release_stable_absent_from_empty_list_still_synthesizes() {
        let versions: Vec<MavenVersion> = vec![];
        let picked = pick_wildcard_latest(&versions, Some("1.2.3")).unwrap();
        assert_eq!(picked.version, "1.2.3");
    }

    #[test]
    fn test_pick_wildcard_latest_no_release_prefers_non_prerelease() {
        let versions = vec![
            MavenVersion {
                version: "2.0.0-alpha".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
        ];
        let picked = pick_wildcard_latest(&versions, None).unwrap();
        assert_eq!(picked.version, "1.0.0");
    }

    /// S8: `select_latest_matching` (via `move_release_to_front`) and
    /// `get_latest_matching_typed`'s own wildcard branch (via `pick_wildcard_latest`) must
    /// agree on the same `(versions, release)` fixture when `<release>` names a stable
    /// version or is absent (S3/S7). They deliberately no longer agree when `<release>`
    /// itself names a prerelease *present in `versions`* (#340): `select_latest_matching`
    /// now skips past it to the newest stable version, matching hover's
    /// `is_stable()`-based pick, while `pick_wildcard_latest` still trusts a
    /// `<release>` found in `versions` verbatim — see
    /// `test_select_latest_matching_skips_prerelease_release_tag`. When `<release>` names a
    /// prerelease *absent* from `versions` instead, `pick_wildcard_latest` no longer trusts
    /// it either (see `test_pick_wildcard_latest_release_prerelease_absent_from_list_returns_none`).
    fn assert_select_latest_matching_agrees_with_pick_wildcard_latest(
        versions: Vec<MavenVersion>,
        release: Option<&str>,
    ) {
        use deps_core::{Registry, VersionReq};

        let wildcard_pick = pick_wildcard_latest(&versions, release);

        let mut reordered = versions;
        move_release_to_front(&mut reordered, release);
        let boxed: Vec<Box<dyn deps_core::Version>> = reordered
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();

        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(
            boxed[idx].version_string().as_str(),
            wildcard_pick
                .expect("fixture always has a pick")
                .version
                .as_str()
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_present_stable() {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "1.5.0-M1".into(),
                    published_at: None,
                },
                MavenVersion {
                    version: "1.4.0".into(),
                    published_at: None,
                },
            ],
            Some("1.4.0"),
        );
    }

    /// #340: `<release>` names a prerelease (`8.0.0.Beta1`-shaped scenario), but a stable
    /// release also exists in the list. `select_latest_matching`'s wildcard fast path must
    /// skip past the front-loaded prerelease and return the newest stable version instead
    /// of blindly trusting index 0, matching hover's `is_stable()`-based pick (FR-001).
    #[test]
    fn test_select_latest_matching_skips_prerelease_release_tag() {
        use deps_core::{Registry, VersionReq};

        let mut versions = vec![
            MavenVersion {
                version: "1.4.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.5.0-M1".into(),
                published_at: None,
            },
        ];
        // `<release>` names the prerelease, so `move_release_to_front` puts it at index 0 —
        // reproducing the real `maven-metadata.xml` shape this bug was found in.
        move_release_to_front(&mut versions, Some("1.5.0-M1"));
        assert_eq!(versions[0].version, "1.5.0-M1");

        let boxed: Vec<Box<dyn deps_core::Version>> = versions
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();

        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(boxed[idx].version_string(), "1.4.0");
    }

    /// FR-002: when every version in the list is a prerelease, the wildcard fast path
    /// falls back to the newest version regardless of prerelease status.
    #[test]
    fn test_select_latest_matching_wildcard_all_prerelease_falls_back_to_newest() {
        use deps_core::{Registry, VersionReq};

        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(MavenVersion {
                version: "2.0.0-alpha".into(),
                published_at: None,
            }),
            Box::new(MavenVersion {
                version: "1.0.0-beta".into(),
                published_at: None,
            }),
        ];

        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let idx = registry
            .select_latest_matching(&versions, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(versions[idx].version_string(), "2.0.0-alpha");
    }

    /// M1: when every version is a prerelease AND `<release>` hoisted an *older*
    /// prerelease to index 0 (`move_release_to_front` trusts `<release>` unconditionally,
    /// independent of whether it's actually the newest deployed artifact), the FR-002
    /// fallback must scan by actual version comparison rather than blindly trusting
    /// index 0 — otherwise a stale/inconsistent `<release>` tag reproduces #340 even in
    /// this all-prerelease branch.
    #[test]
    fn test_select_latest_matching_wildcard_all_prerelease_ignores_stale_release_hoist() {
        use deps_core::{Registry, VersionReq};

        let mut versions = vec![
            MavenVersion {
                version: "2.0.0-beta".into(),
                published_at: None,
            },
            MavenVersion {
                version: "1.0.0-alpha".into(),
                published_at: None,
            },
        ];
        // `<release>` names the OLDER prerelease — `move_release_to_front` hoists it to
        // index 0 regardless, reproducing the real shape a stale/inconsistent
        // `maven-metadata.xml` could produce.
        move_release_to_front(&mut versions, Some("1.0.0-alpha"));
        assert_eq!(versions[0].version, "1.0.0-alpha");

        let boxed: Vec<Box<dyn deps_core::Version>> = versions
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();

        let cache = Arc::new(HttpCache::new());
        let registry = MavenCentralRegistry::new(cache);
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(
            boxed[idx].version_string(),
            "2.0.0-beta",
            "must scan for the actual newest prerelease, not trust the release-tag hoist"
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_absent_non_prerelease_exists()
     {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "1.5.0-alpha01".into(),
                    published_at: None,
                },
                MavenVersion {
                    version: "1.4.0".into(),
                    published_at: None,
                },
            ],
            None,
        );
    }

    #[test]
    fn test_select_latest_matching_agrees_with_pick_wildcard_latest_release_absent_only_prereleases()
     {
        assert_select_latest_matching_agrees_with_pick_wildcard_latest(
            vec![
                MavenVersion {
                    version: "2.0.0-alpha".into(),
                    published_at: None,
                },
                MavenVersion {
                    version: "1.0.0-beta".into(),
                    published_at: None,
                },
            ],
            None,
        );
    }

    // --- parse_publish_times: fixtures captured live from repo1.maven.org and
    // plugins.gradle.org on 2026-08-24 (see handoff for the exact `curl` commands) ---

    /// A trimmed excerpt of the real `repo1.maven.org/maven2/org/apache/commons/commons-lang3/`
    /// listing: the `../` parent anchor, several version directories (padded display text +
    /// `title=` attribute, exactly as Maven Central emits), and a couple of sibling file
    /// entries (`maven-metadata.xml.md5` etc.) that carry dates too but are not versions.
    const REPO1_FIXTURE: &str = r#"<pre id="contents">
<a href="../">../</a>
<a href="3.12.0/" title="3.12.0/">3.12.0/</a>                                           2021-02-26 20:40         -
<a href="3.13.0/" title="3.13.0/">3.13.0/</a>                                           2023-07-23 19:44         -
<a href="3.14.0/" title="3.14.0/">3.14.0/</a>                                           2023-11-18 15:03         -
<a href="maven-metadata.xml" title="maven-metadata.xml">maven-metadata.xml</a>                                2025-11-16 12:55       817
<a href="maven-metadata.xml.md5" title="maven-metadata.xml.md5">maven-metadata.xml.md5</a>                            2025-11-16 12:55        32
</pre>"#;

    #[test]
    fn test_parse_publish_times_repo1_fixture() {
        let map = parse_publish_times(REPO1_FIXTURE.as_bytes());

        assert_eq!(
            map.get("3.14.0").copied(),
            PublishTime::parse_rfc3339("2023-11-18T15:03:00Z")
        );
        assert_eq!(
            map.get("3.12.0").copied(),
            PublishTime::parse_rfc3339("2021-02-26T20:40:00Z")
        );
        // The `../` parent anchor never becomes a "version".
        assert!(!map.contains_key(".."));
        assert!(!map.contains_key(""));
        // Sibling file entries (no trailing `/` in their href) are not versions either,
        // even though they carry a date too (M2).
        assert!(!map.contains_key("maven-metadata.xml"));
        assert!(!map.contains_key("maven-metadata.xml.md5"));
    }

    /// Real `plugins.gradle.org/m2/.../spring-boot-gradle-plugin/` shape: one `<pre>` per
    /// anchor, no date column at all. `extract_pre_block` only ever sees the first `<pre>`,
    /// but the outcome is the same either way — no line here carries a date, so nothing
    /// is ever inserted.
    const GRADLE_PLUGIN_PORTAL_FIXTURE: &str = r#"<pre><a href="1.4.2.RELEASE/">1.4.2.RELEASE/</a></pre>
<pre><a href="1.5.0.RELEASE/">1.5.0.RELEASE/</a></pre>"#;

    #[test]
    fn test_parse_publish_times_gradle_plugin_portal_dateless_is_empty() {
        let map = parse_publish_times(GRADLE_PLUGIN_PORTAL_FIXTURE.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_publish_times_malformed_date_entry_absent_rest_parsed() {
        let html = r#"<pre id="contents">
<a href="1.0.0/" title="1.0.0/">1.0.0/</a>                                            2011-13-45 99:99         -
<a href="1.0.1/" title="1.0.1/">1.0.1/</a>                                            2011-09-28 16:04         -
</pre>"#;
        let map = parse_publish_times(html.as_bytes());
        assert!(!map.contains_key("1.0.0"));
        assert_eq!(
            map.get("1.0.1").copied(),
            PublishTime::parse_rfc3339("2011-09-28T16:04:00Z")
        );
    }

    #[test]
    fn test_parse_publish_times_no_pre_block_is_empty() {
        let html = r"<html><body>not a listing at all</body></html>";
        let map = parse_publish_times(html.as_bytes());
        assert!(map.is_empty());
    }

    #[test]
    fn test_parse_publish_times_empty_body_is_empty() {
        let map = parse_publish_times(b"");
        assert!(map.is_empty());
    }

    // --- should_fetch_listing (S2: gate on the winning base, not "some base exists") ---

    #[test]
    fn test_should_fetch_listing_maven_central_base() {
        assert!(should_fetch_listing(
            "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/"
        ));
    }

    #[test]
    fn test_should_fetch_listing_google_maven_base_is_false() {
        assert!(!should_fetch_listing(
            "https://dl.google.com/dl/android/maven2/androidx/core/core/"
        ));
    }

    #[test]
    fn test_should_fetch_listing_gradle_plugin_portal_base_is_false() {
        assert!(!should_fetch_listing(
            "https://plugins.gradle.org/m2/org/example/plugin/"
        ));
    }

    // --- attach_publish_times: version/date pairing edge cases ---

    #[test]
    fn test_attach_publish_times_matches_by_version_string() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "2.0.0".into(),
                published_at: None,
            },
        ];
        let mut times = HashMap::new();
        times.insert(
            "1.0.0".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        attach_publish_times(&mut versions, &times);

        assert_eq!(
            versions[0].published_at,
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z")
        );
        assert_eq!(versions[1].published_at, None);
        // Order is untouched.
        assert_eq!(versions[0].version, "1.0.0");
        assert_eq!(versions[1].version, "2.0.0");
    }

    #[test]
    fn test_attach_publish_times_extra_map_entry_does_not_panic_or_cross_assign() {
        let mut versions = vec![MavenVersion {
            version: "1.0.0".into(),
            published_at: None,
        }];
        let mut times = HashMap::new();
        // A version present in the listing but absent from maven-metadata.xml — must not
        // be assigned to an unrelated entry, and must not panic.
        times.insert(
            "9.9.9-not-in-metadata".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        attach_publish_times(&mut versions, &times);
        assert_eq!(versions[0].published_at, None);
    }

    #[test]
    fn test_attach_publish_times_empty_map_leaves_all_none() {
        let mut versions = vec![
            MavenVersion {
                version: "1.0.0".into(),
                published_at: None,
            },
            MavenVersion {
                version: "2.0.0".into(),
                published_at: None,
            },
        ];
        attach_publish_times(&mut versions, &HashMap::new());
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    // --- fetch_publish_times: HTTP degradation (mockito) ---

    #[tokio::test]
    async fn test_fetch_publish_times_success_parses_and_attaches() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/org/example/widget/")
            .with_status(200)
            .with_body(REPO1_FIXTURE)
            .expect(1)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert_eq!(
            times.get("3.14.0").copied(),
            PublishTime::parse_rfc3339("2023-11-18T15:03:00Z")
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_publish_times_404_degrades_to_empty_map() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/org/example/widget/")
            .with_status(404)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert!(times.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_publish_times_500_degrades_to_empty_map() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/org/example/widget/")
            .with_status(500)
            .create_async()
            .await;

        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let url = format!("{}/org/example/widget/", server.url());
        let times = registry.fetch_publish_times(&url).await;

        assert!(times.is_empty());
    }

    // --- get_versions_typed_with: end-to-end gating and degradation on the metadata path ---

    #[tokio::test]
    async fn test_get_versions_typed_with_invalid_name_short_circuits_before_any_request() {
        // No colon in the name => `metadata_urls` returns empty and `get_metadata` never
        // issues a request at all, so this also exercises `get_versions_typed`'s delegation
        // to `get_versions_typed_with(name, false)` (M1) without needing a network mock.
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        assert!(
            registry
                .get_versions_typed("bad-name")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            registry
                .get_versions_typed_with("bad-name", true)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// #366: unlike the malformed-pair case above, a coordinate rejected by
    /// `is_safe_maven_coordinate_segment` must surface as `Err`, not `Ok(vec![])` — this is
    /// what lets hover (`registry.get_versions_with(...).ok()?`) return `None` for a
    /// rejected coordinate instead of a broken "package not found" hover section.
    #[tokio::test]
    async fn test_get_versions_typed_dot_segment_artifact_id_returns_err() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let err = registry
            .get_versions_typed("com.example:..")
            .await
            .expect_err("dot-segment artifactId must be rejected");
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
        assert!(err.is_not_found());
    }

    // --- NFR-006 live verification (real network, run explicitly with `--ignored`) ---

    #[tokio::test]
    #[ignore]
    async fn test_live_maven_central_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("org.apache.commons:commons-lang3", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        // Maven Central: the listing exists, so at least the most recent releases carry a
        // publish date (some very old/legacy entries may not, but recent ones always do).
        assert!(versions.iter().take(5).any(|v| v.published_at.is_some()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_google_maven_never_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("androidx.core:core", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        // Google Maven's listing 404s by design (§1.3) — the version list itself must be
        // unaffected, exactly as before this feature.
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    #[tokio::test]
    #[ignore]
    async fn test_live_gradle_plugin_portal_never_attaches_publish_times() {
        let registry = MavenCentralRegistry::new(Arc::new(HttpCache::new()));
        // The Gradle plugin marker artifact for `com.gradle.develocity` (404s on Maven
        // Central; verified `repo1` 404 / plugin portal 200 on 2026-08-24) — resolves only
        // via the Gradle Plugin Portal fallback.
        let versions = registry
            .get_versions_typed_with(
                "com.gradle.develocity:com.gradle.develocity.gradle.plugin",
                true,
            )
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }
}

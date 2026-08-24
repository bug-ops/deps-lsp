use crate::error::{DepsError, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use reqwest::{Client, Response, StatusCode, header};
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Maximum number of cached entries to prevent unbounded memory growth.
const MAX_CACHE_ENTRIES: usize = 1000;

/// Maximum total bytes retained across all cached response bodies.
///
/// `MAX_CACHE_ENTRIES` alone bounds entry *count*, not size: since a single
/// response body may be as large as [`MAX_RESPONSE_BYTES`] (32 MiB), a cache
/// full of near-cap entries could retain tens of gigabytes even though real
/// registry payloads are typically well under 1 MB. This budget is a
/// defense-in-depth cap (CWE-400) against that worst case, evicted
/// alongside the count-based limit in [`HttpCache::evict_entries`]. 64 MiB
/// comfortably holds thousands of typical registry responses while still
/// bounding the pathological case.
///
/// This is a best-effort bound, not a hard guarantee: it is checked once
/// per request in [`HttpCache::get_cached_with_headers`], so multiple
/// requests already in flight when the budget is crossed can each finish
/// inserting before the next check fires. [`MAX_CACHEABLE_ENTRY_BYTES`]
/// keeps that per-request overshoot small (at most one admission-cap-sized
/// insert per concurrent in-flight request) rather than bounding it exactly.
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum size of a single response body that will be retained in the
/// cache; larger bodies are still returned to the caller, just never
/// stored.
///
/// Without this cap, [`MAX_CACHE_BYTES`] alone lets a handful of
/// large-but-legitimate responses (up to [`MAX_RESPONSE_BYTES`], 32 MiB
/// each) evict the *entire* rest of the cache: at a 2x ratio between the
/// two constants, just two max-size entries would saturate the whole
/// budget. Set to an eighth of [`MAX_CACHE_BYTES`] (8 MiB) so no single
/// entry can claim more than 1/8 of the budget — a handful of large
/// responses degrade to "not cached" instead of "evicts the small-payload
/// working set".
const MAX_CACHEABLE_ENTRY_BYTES: usize = MAX_CACHE_BYTES / 8;

/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Maximum decompressed response body size accepted from a single request.
///
/// `reqwest`'s `gzip` feature strips `Content-Length`/`Content-Encoding` after
/// decoding a response, so a header-based pre-check cannot bound body size
/// (`response.content_length()` is `None` for every decoded response). This
/// cap is instead enforced by counting bytes as the body streams in, aborting
/// as soon as the running total would exceed the limit.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Percentage of cache entries to evict when capacity is reached.
const CACHE_EVICTION_PERCENTAGE: usize = 10;

/// Whether `url`'s host is loopback (`127.0.0.1`, `localhost`, or `::1`), with any scheme
/// and an optional port — the shape every `mockito::Server` binds to.
///
/// Only compiled into test builds (see [`ensure_https`]): a non-loopback host must never
/// be allowed to bypass the HTTPS requirement, even under `cfg(test)`/`test-util`.
#[cfg(any(test, feature = "test-util"))]
fn is_loopback_host(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    let host_and_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = if let Some(bracketed) = host_and_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host_and_port.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Validates that a URL uses HTTPS protocol.
///
/// Returns an error if the URL doesn't start with "https://".
/// This ensures all network requests are encrypted.
///
/// A loopback HTTP URL (`127.0.0.1`/`localhost`/`::1`, the shape every `mockito::Server`
/// binds to) is allowed in `deps-core`'s own test builds (`cfg(test)`) and in other
/// workspace crates' test builds via the `test-util` feature — `cfg(test)` alone does not
/// apply there, since those crates depend on `deps-core` as a normal, non-dev dependency.
/// Any other HTTP host is still rejected even under those cfgs: `test-util` is a public,
/// independently-enablable crates.io feature, so this must not become "any host, any
/// environment" just because the feature is on.
#[inline]
fn ensure_https(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    #[cfg(any(test, feature = "test-util"))]
    if is_loopback_host(url) {
        return Ok(());
    }
    Err(DepsError::CacheError(format!("URL must use HTTPS: {url}")))
}

/// Reads a response body incrementally, aborting once it exceeds
/// [`MAX_RESPONSE_BYTES`].
///
/// Chunked reading (via [`Response::chunk`]) is required because the
/// decompressed body size is not known upfront: `gzip` decoding strips
/// `Content-Length`, so the only reliable guard against an oversized or
/// maliciously amplified (decompression-bomb) response is counting bytes
/// as they arrive and bailing before the whole body is buffered.
async fn read_body_capped(url: &str, mut response: Response) -> Result<Bytes> {
    let mut body = BytesMut::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DepsError::RegistryError {
            package: url.to_string(),
            source: e,
        })?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(DepsError::ResponseTooLarge {
                url: url.to_string(),
                limit: MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

/// Cached HTTP response with validation headers.
///
/// Stores response body and cache validation headers (ETag, Last-Modified)
/// for efficient conditional requests. The body uses `Bytes` which is an
/// Arc-like type optimized for network data, enabling zero-cost cloning
/// across multiple consumers without copying.
///
/// # Examples
///
/// ```
/// use deps_core::cache::CachedResponse;
/// use bytes::Bytes;
/// use std::time::Instant;
///
/// let response = CachedResponse {
///     body: Bytes::from("response data"),
///     etag: Some("\"abc123\"".into()),
///     last_modified: None,
///     fetched_at: Instant::now(),
/// };
///
/// // Clone is cheap - only increments reference count
/// let cloned = response.clone();
/// ```
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub body: Bytes,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub fetched_at: Instant,
}

/// HTTP cache with ETag and Last-Modified validation.
///
/// Implements RFC 7232 conditional requests to minimize network traffic.
/// All responses are cached with their validation headers, and subsequent
/// requests use `If-None-Match` (ETag) or `If-Modified-Since` headers
/// to check for updates.
///
/// The cache uses `Bytes` for response bodies, enabling efficient sharing
/// of cached data across multiple consumers without copying. `Bytes` is
/// an Arc-like type optimized for network I/O.
///
/// # Examples
///
/// ```no_run
/// use deps_core::cache::HttpCache;
///
/// # async fn example() -> deps_core::error::Result<()> {
/// let cache = HttpCache::new();
///
/// // First request - fetches from network
/// let data1 = cache.get_cached("https://index.crates.io/se/rd/serde").await?;
///
/// // Second request - uses conditional GET (304 Not Modified if unchanged)
/// let data2 = cache.get_cached("https://index.crates.io/se/rd/serde").await?;
/// # Ok(())
/// # }
/// ```
///
/// # Cache key
///
/// Entries are keyed by URL alone — `extra_headers` (see
/// [`HttpCache::get_cached_with_headers`]) play no part in the cache key.
/// This is safe only as long as "same URL" implies "same representation":
/// a content-negotiating header (e.g. a per-request `Accept`) that can vary
/// the response body for an otherwise-identical URL requires giving each
/// distinct representation its own URL (e.g. a query parameter or distinct
/// path), not just a distinct header value, or callers requesting different
/// representations of the same URL will silently share one cache entry.
pub struct HttpCache {
    entries: DashMap<String, CachedResponse>,
    /// Running total of `body.len()` across all `entries`, kept in sync by
    /// [`HttpCache::store_entry`], [`HttpCache::evict_entries`], and
    /// [`HttpCache::clear`] via relative `fetch_add`/`fetch_sub` only —
    /// never an absolute `store` after the initial `0`, since that would
    /// silently discard any concurrent relative update racing with it. Used
    /// to trigger byte-bounded eviction without summing every entry on each
    /// check; advisory (see [`MAX_CACHE_BYTES`]), not an exact live count
    /// under concurrent access.
    total_bytes: AtomicUsize,
    client: Client,
}

impl HttpCache {
    /// Creates a new HTTP cache with default configuration.
    ///
    /// The cache uses a configurable timeout for all requests and identifies
    /// itself with an auto-versioned user agent.
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent(format!("deps-lsp/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
            .build()
            .expect("failed to create HTTP client");

        Self {
            entries: DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            client,
        }
    }

    /// Retrieves data from URL with intelligent caching.
    ///
    /// On first request, fetches data from the network and caches it.
    /// On subsequent requests, performs a conditional GET request using
    /// cached ETag or Last-Modified headers. If the server responds with
    /// 304 Not Modified, returns the cached data. Otherwise, fetches and
    /// caches the new data.
    ///
    /// If the conditional request fails due to network errors, falls back
    /// to the cached data (stale-while-revalidate pattern).
    ///
    /// # Returns
    ///
    /// Returns `Bytes` containing the response body. Multiple calls for the
    /// same URL return cheap clones (reference counting) without copying data.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::RegistryError` if the initial fetch fails and no
    /// cached data exists, `DepsError::HttpStatus` if the server returns a
    /// non-2xx status on that initial fetch, or `DepsError::ResponseTooLarge`
    /// if the response body exceeds the configured size cap.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_core::cache::HttpCache;
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let data = cache.get_cached("https://example.com/api/data").await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached(&self, url: &str) -> Result<Bytes> {
        self.get_cached_with_headers(url, &[]).await
    }

    /// Returns the cached body for `url` without making any network request.
    ///
    /// Unlike `get_cached`'s own stale-while-revalidate fallback (the `Err` arm of
    /// `conditional_request_with_headers`'s match in `get_cached_with_headers`), this
    /// is reachable even when a caller wraps `get_cached` in a short outer timeout: a
    /// hung conditional request that never resolves within that timeout gets its whole
    /// future cancelled, so `get_cached`'s internal fallback logic never runs and the
    /// caller sees a timeout instead of stale data. A caller in that position can call
    /// this instead — a synchronous map lookup, no I/O — to serve the last known-good
    /// body itself. Returns `None` if `url` has never been successfully cached.
    ///
    /// The returned body carries no age bound: this bypasses `get_cached`'s own
    /// freshness/revalidation logic entirely, so a caller that surfaces this body to
    /// the user (e.g. inserting it into a manifest edit) should treat it as
    /// arbitrarily stale, not just-expired.
    #[must_use]
    pub fn peek_cached(&self, url: &str) -> Option<Bytes> {
        self.entries.get(url).map(|r| r.body.clone())
    }

    /// Fetches a URL with additional request headers, using the cache.
    ///
    /// Works the same as `get_cached` but injects extra headers (e.g., Authorization)
    /// into every request. Useful for APIs that require authentication tokens.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::RegistryError` if the initial fetch fails and no
    /// cached data exists, `DepsError::HttpStatus` if the server returns a
    /// non-2xx status on that initial fetch, or `DepsError::ResponseTooLarge`
    /// if the response body exceeds the configured size cap.
    pub async fn get_cached_with_headers(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        if self.entries.len() >= MAX_CACHE_ENTRIES
            || self.total_bytes.load(Ordering::Relaxed) >= MAX_CACHE_BYTES
        {
            self.evict_entries();
        }

        // Clone and drop the DashMap Ref immediately to release the shard lock.
        // Holding a Ref across .await causes deadlocks when concurrent tasks
        // need write access to the same shard (e.g., conditional_request_with_headers → insert).
        if let Some(cached) = self.entries.get(url).map(|r| r.clone()) {
            match self
                .conditional_request_with_headers(url, &cached, extra_headers)
                .await
            {
                Ok(Some(new_body)) => return Ok(new_body),
                Ok(None) => return Ok(cached.body),
                Err(e) => {
                    tracing::warn!("conditional request failed, using cache: {e}");
                    return Ok(cached.body);
                }
            }
        }

        self.fetch_and_store_with_headers(url, extra_headers).await
    }

    /// Performs conditional HTTP request using cached validation headers.
    ///
    /// Sends `If-None-Match` (ETag) and/or `If-Modified-Since` headers
    /// to check if the cached content is still valid.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(Bytes))` - Server returned 200 OK with new content
    /// - `Ok(None)` - Server returned 304 Not Modified (cache is valid)
    /// - `Err(_)` - Network or HTTP error occurred
    async fn conditional_request_with_headers(
        &self,
        url: &str,
        cached: &CachedResponse,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Option<Bytes>> {
        ensure_https(url)?;
        let mut request = self.client.get(url);

        for (name, value) in extra_headers {
            request = request.header(name, *value);
        }
        if let Some(etag) = &cached.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &cached.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
        }

        let response = request.send().await.map_err(|e| DepsError::RegistryError {
            package: url.to_string(),
            source: e,
        })?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(DepsError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let body = read_body_capped(url, response).await?;

        self.store_entry(
            url.to_string(),
            CachedResponse {
                body: body.clone(),
                etag,
                last_modified,
                fetched_at: Instant::now(),
            },
        );

        Ok(Some(body))
    }

    /// Fetches a fresh response from the network and stores it in the cache.
    ///
    /// This method bypasses the cache and always makes a network request.
    /// The response is stored with its ETag and Last-Modified headers for
    /// future conditional requests.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx status code,
    /// `DepsError::RegistryError` if the network request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    async fn fetch_and_store_with_headers(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        ensure_https(url)?;
        tracing::debug!(extra_headers = extra_headers.len(), "fetching fresh: {url}");

        let mut request = self.client.get(url);
        for (name, value) in extra_headers {
            request = request.header(name, *value);
        }

        let response = request.send().await.map_err(|e| DepsError::RegistryError {
            package: url.to_string(),
            source: e,
        })?;

        if !response.status().is_success() {
            return Err(DepsError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let last_modified = response
            .headers()
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let body = read_body_capped(url, response).await?;

        self.store_entry(
            url.to_string(),
            CachedResponse {
                body: body.clone(),
                etag,
                last_modified,
                fetched_at: Instant::now(),
            },
        );

        Ok(body)
    }

    /// POSTs `body` as JSON and returns the response body.
    ///
    /// Deliberately does not cache: the OSV batch endpoint is a POST with a
    /// request-body-dependent response and sends no `ETag`/`Last-Modified`
    /// validators, so entry-map caching would be meaningless here — every
    /// call reuses the client, HTTPS enforcement, size cap, and timeout
    /// (via `read_body_capped`) without touching the entry map or
    /// [`Self::total_bytes`].
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn post_json<T: Serialize + ?Sized>(&self, url: &str, body: &T) -> Result<Bytes> {
        ensure_https(url)?;

        let response = self.client.post(url).json(body).send().await.map_err(|e| {
            DepsError::RegistryError {
                package: url.to_string(),
                source: e,
            }
        })?;

        if !response.status().is_success() {
            return Err(DepsError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        read_body_capped(url, response).await
    }

    /// GETs `url` and returns the response body, bypassing the entry-map
    /// cache entirely — reuses the client, HTTPS enforcement, size cap, and
    /// timeout, exactly like [`Self::post_json`], but for a plain GET.
    ///
    /// For a caller whose own values are already cached elsewhere (e.g.
    /// `OsvClient`'s record cache, validated by a `modified` timestamp
    /// rather than `ETag`/`Last-Modified`): reusing [`Self::get_cached`]
    /// there would double-cache every fetched record in *this* cache's byte
    /// budget too, competing with registry responses for it even though
    /// nothing here ever reads that cached copy back.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn get_transport_only(&self, url: &str) -> Result<Bytes> {
        ensure_https(url)?;

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DepsError::RegistryError {
                package: url.to_string(),
                source: e,
            })?;

        if !response.status().is_success() {
            return Err(DepsError::HttpStatus {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }

        read_body_capped(url, response).await
    }

    /// Inserts (or replaces) a cache entry, keeping [`Self::total_bytes`] in sync.
    ///
    /// `DashMap::insert` returns the replaced value, if any, so the byte
    /// delta is computed from a single insert rather than a separate
    /// lookup-then-insert (which would race with concurrent writers).
    ///
    /// A body larger than [`MAX_CACHEABLE_ENTRY_BYTES`] is not inserted at
    /// all (the caller already has it from the network response; only
    /// caching is skipped), and any stale entry previously cached for this
    /// URL is dropped rather than left to serve increasingly outdated data.
    fn store_entry(&self, url: String, response: CachedResponse) {
        let new_len = response.body.len();

        if new_len > MAX_CACHEABLE_ENTRY_BYTES {
            if let Some((_, old)) = self.entries.remove(&url) {
                self.total_bytes
                    .fetch_sub(old.body.len(), Ordering::Relaxed);
            }
            return;
        }

        let old_len = self
            .entries
            .insert(url, response)
            .map_or(0, |old| old.body.len());
        self.total_bytes.fetch_add(new_len, Ordering::Relaxed);
        self.total_bytes.fetch_sub(old_len, Ordering::Relaxed);
    }

    /// Clears all cached entries.
    ///
    /// This removes all cached responses, forcing the next request for
    /// any URL to fetch fresh data from the network.
    pub fn clear(&self) {
        self.entries.clear();
        self.total_bytes.store(0, Ordering::Relaxed);
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the total bytes retained across all cached response bodies.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Evicts the oldest cache entries when either capacity limit is reached.
    ///
    /// When the entry count is at or over `MAX_CACHE_ENTRIES`, evicts at
    /// least `CACHE_EVICTION_PERCENTAGE`% of entries (by count). Note this
    /// is a *fix*, not a preserved behavior: the original count-only
    /// eviction built its bounded min-heap with an inverted comparison
    /// (`peek()` returns the oldest entry, but the old code treated it as
    /// the newest-of-the-oldest-so-far and only replaced it when a *newer*
    /// candidate came along that was still older than it — backwards), so
    /// it evicted roughly the first `target_removals` entries in DashMap
    /// hash-iteration order, not the oldest ones. This version evicts
    /// genuinely oldest-first.
    ///
    /// Independently, if the tracked byte total is over [`MAX_CACHE_BYTES`]
    /// — which can happen with far fewer than `MAX_CACHE_ENTRIES` entries if
    /// a few responses are large — eviction keeps removing the next-oldest
    /// entries until the byte budget is satisfied too. A cache that is over
    /// the byte budget but well under the entry-count threshold only evicts
    /// as many entries as the byte budget requires, not a fixed count-based
    /// batch.
    ///
    /// Builds a min-heap over all entry keys by `fetched_at` (O(N)), then
    /// pops the oldest one at a time (O(R log N) for R removals) — unlike a
    /// heap bounded to a fixed top-K, the removal count isn't known upfront
    /// since it depends on the byte budget as well as the count target.
    ///
    /// Every byte-count adjustment here is a relative `fetch_sub` applied to
    /// exactly the entry [`DashMap::remove`] actually returned — never a
    /// snapshot-then-absolute-`store` of a locally computed total. The
    /// latter would silently discard any [`Self::store_entry`] delta that
    /// lands between this method's start and its end (lost-update race), and
    /// under adversarial timing could even underflow `total_bytes` to
    /// `usize::MAX`, permanently wedging every future request into
    /// evicting the entire cache. Reading `total_bytes` fresh on every loop
    /// iteration (rather than maintaining a local mirror) keeps this
    /// correct under concurrent `evict_entries`/`store_entry` calls: two
    /// callers can race to remove the same key — the second `remove` simply
    /// returns `None` and is a no-op, not a double-subtraction.
    fn evict_entries(&self) {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let count_target_removals = if self.entries.len() >= MAX_CACHE_ENTRIES {
            (MAX_CACHE_ENTRIES / CACHE_EVICTION_PERCENTAGE).max(1)
        } else {
            0
        };

        let mut oldest: BinaryHeap<Reverse<(Instant, String)>> = self
            .entries
            .iter()
            .map(|entry| Reverse((entry.value().fetched_at, entry.key().clone())))
            .collect();

        let mut removed = 0usize;

        while removed < count_target_removals
            || self.total_bytes.load(Ordering::Relaxed) > MAX_CACHE_BYTES
        {
            let Some(Reverse((_, url))) = oldest.pop() else {
                break;
            };
            if let Some((_, old)) = self.entries.remove(&url) {
                self.total_bytes
                    .fetch_sub(old.body.len(), Ordering::Relaxed);
            }
            removed += 1;
        }

        tracing::debug!(
            "evicted {removed} cache entries ({} bytes remaining)",
            self.total_bytes.load(Ordering::Relaxed)
        );
    }

    /// Benchmark-only helper: Direct cache lookup without network requests.
    #[doc(hidden)]
    pub fn get_for_bench(&self, url: &str) -> Option<Bytes> {
        self.entries.get(url).map(|entry| entry.body.clone())
    }

    /// Benchmark-only helper: Direct cache insertion.
    #[doc(hidden)]
    pub fn insert_for_bench(&self, url: String, response: CachedResponse) {
        self.store_entry(url, response);
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards the non-loopback path of `ensure_https`: every other test in this
    // module reaches it only through loopback `mockito` URLs, so without this
    // test the "reject any other HTTP host" branch would never run.
    #[test]
    fn test_ensure_https_rejects_non_loopback_http() {
        assert!(ensure_https("http://example.com").is_err());
    }

    // `http://example.com` alone would still pass under a regressed, substring-based
    // `is_loopback_host` (e.g. `url.contains("localhost")`) — these hosts embed a
    // loopback token without actually being loopback, and must still be rejected.
    #[test]
    fn test_ensure_https_rejects_hosts_resembling_loopback() {
        assert!(ensure_https("http://localhost.evil.com/").is_err());
        assert!(ensure_https("http://127.0.0.1.evil.com/").is_err());
        assert!(ensure_https("http://evil.com/?cb=127.0.0.1").is_err());
    }

    // The sole exerciser of `is_loopback_host`'s bracketed-IPv6 branch
    // (`strip_prefix('[')`/`split(']')`) — every other test/mockito URL in this
    // module uses `127.0.0.1`.
    #[test]
    fn test_ensure_https_accepts_bracketed_ipv6_loopback() {
        assert!(ensure_https("http://[::1]:1234/x").is_ok());
    }

    #[test]
    fn test_cache_creation() {
        let cache = HttpCache::new();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let cache = HttpCache::new();
        cache.entries.insert(
            "test".into(),
            CachedResponse {
                body: Bytes::from_static(&[1, 2, 3]),
                etag: None,
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cached_response_clone() {
        let response = CachedResponse {
            body: Bytes::from_static(&[1, 2, 3]),
            etag: Some("test".into()),
            last_modified: Some("date".into()),
            fetched_at: Instant::now(),
        };
        let cloned = response.clone();
        // Bytes clone is cheap (reference counting)
        assert_eq!(response.body, cloned.body);
        assert_eq!(response.etag, cloned.etag);
    }

    #[test]
    fn test_cache_len() {
        let cache = HttpCache::new();
        assert_eq!(cache.len(), 0);

        cache.entries.insert(
            "url1".into(),
            CachedResponse {
                body: Bytes::new(),
                etag: None,
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_get_cached_fresh_fetch() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("test data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/data", server.url());
        let result: Bytes = cache.get_cached(&url).await.unwrap();

        assert_eq!(result.as_ref(), b"test data");
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn test_get_cached_cache_hit() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("original data")
            .create_async()
            .await;

        let result1: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result1.as_ref(), b"original data");
        assert_eq!(cache.len(), 1);

        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(304)
            .create_async()
            .await;

        let result2: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result2.as_ref(), b"original data");
    }

    #[tokio::test]
    async fn test_get_cached_304_not_modified() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("original data")
            .create_async()
            .await;

        let result1: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result1.as_ref(), b"original data");

        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(304)
            .create_async()
            .await;

        let result2: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result2.as_ref(), b"original data");
    }

    #[tokio::test]
    async fn test_get_cached_etag_validation() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"cached"),
                etag: Some("\"tag123\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"tag123\"")
            .with_status(304)
            .create_async()
            .await;

        let result: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result.as_ref(), b"cached");
    }

    #[tokio::test]
    async fn test_get_cached_last_modified_validation() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"cached"),
                etag: None,
                last_modified: Some("Wed, 21 Oct 2024 07:28:00 GMT".into()),
                fetched_at: Instant::now(),
            },
        );

        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-modified-since", "Wed, 21 Oct 2024 07:28:00 GMT")
            .with_status(304)
            .create_async()
            .await;

        let result: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result.as_ref(), b"cached");
    }

    #[tokio::test]
    async fn test_get_cached_network_error_fallback() {
        let cache = HttpCache::new();
        let url = "http://invalid.localhost.test/data";

        cache.entries.insert(
            url.to_string(),
            CachedResponse {
                body: Bytes::from_static(b"stale data"),
                etag: Some("\"old\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        let result: Bytes = cache.get_cached(url).await.unwrap();
        assert_eq!(result.as_ref(), b"stale data");
    }

    #[tokio::test]
    async fn test_fetch_and_store_http_error() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/missing")
            .with_status(404)
            .with_body("Not Found")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/missing", server.url());
        let result: Result<Bytes> = cache.fetch_and_store_with_headers(&url, &[]).await;

        assert!(result.is_err());
        match result {
            Err(DepsError::HttpStatus { status, .. }) => {
                assert_eq!(status, 404);
            }
            _ => panic!("Expected HttpStatus"),
        }
    }

    #[tokio::test]
    async fn test_fetch_and_store_stores_headers() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_header("last-modified", "Wed, 21 Oct 2024 07:28:00 GMT")
            .with_body("test")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/data", server.url());
        let _: Bytes = cache.fetch_and_store_with_headers(&url, &[]).await.unwrap();

        let cached = cache.entries.get(&url).unwrap();
        assert_eq!(cached.etag, Some("\"abc123\"".into()));
        assert_eq!(
            cached.last_modified,
            Some("Wed, 21 Oct 2024 07:28:00 GMT".into())
        );
    }

    #[tokio::test]
    async fn test_get_cached_with_headers_sends_extra_headers() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .match_header("authorization", "Bearer token123")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("authed data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let headers = [(header::AUTHORIZATION, "Bearer token123")];
        let result: Bytes = cache.get_cached_with_headers(&url, &headers).await.unwrap();

        assert_eq!(result.as_ref(), b"authed data");
    }

    #[tokio::test]
    async fn test_fetch_and_store_rejects_oversized_response() {
        let mut server = mockito::Server::new_async().await;
        let oversized_body = vec![0u8; MAX_RESPONSE_BYTES + 1];

        let _m = server
            .mock("GET", "/api/huge")
            .with_status(200)
            .with_body(oversized_body)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/huge", server.url());
        let result: Result<Bytes> = cache.fetch_and_store_with_headers(&url, &[]).await;

        match result {
            Err(DepsError::ResponseTooLarge { limit, .. }) => {
                assert_eq!(limit, MAX_RESPONSE_BYTES);
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }

        // The oversized response must not have been cached.
        assert!(cache.entries.get(&url).is_none());
    }

    #[tokio::test]
    async fn test_fetch_and_store_accepts_response_at_exact_cap() {
        // A response at MAX_RESPONSE_BYTES (32 MiB) is well over
        // MAX_CACHEABLE_ENTRY_BYTES (8 MiB), so the network-layer cap and
        // the cache admission cap are independent: the fetch succeeds and
        // returns the full body, but the response is not retained in the
        // cache (see test_store_entry_skips_caching_oversized_entry).
        let mut server = mockito::Server::new_async().await;
        let exact_cap_body = vec![0u8; MAX_RESPONSE_BYTES];

        let _m = server
            .mock("GET", "/api/exact")
            .with_status(200)
            .with_body(exact_cap_body)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/exact", server.url());
        let result: Bytes = cache.fetch_and_store_with_headers(&url, &[]).await.unwrap();

        assert_eq!(result.len(), MAX_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn test_get_cached_non_2xx_on_refresh_preserves_stale_cache() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();
        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"stale but good"),
                etag: Some("\"stale-etag\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );

        // Registry is down for maintenance: the conditional request gets a
        // non-2xx, non-304 response instead of either "unchanged" or "here's
        // the new body".
        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"stale-etag\"")
            .with_status(503)
            .with_body("<html>maintenance</html>")
            .create_async()
            .await;

        let result: Bytes = cache.get_cached(&url).await.unwrap();

        // The stale-while-revalidate fallback returns the last-known-good
        // body, and the cache entry is left untouched rather than being
        // overwritten with the error page.
        assert_eq!(result.as_ref(), b"stale but good");
        let cached = cache.entries.get(&url).unwrap();
        assert_eq!(cached.etag, Some("\"stale-etag\"".into()));
    }

    #[tokio::test]
    async fn test_post_json_success_returns_body_and_does_not_cache() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/querybatch", server.url());

        let _m = server
            .mock("POST", "/v1/querybatch")
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_body(r#"{"results":[{}]}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let body = serde_json::json!({ "queries": [] });
        let result: Bytes = cache.post_json(&url, &body).await.unwrap();

        assert_eq!(result.as_ref(), br#"{"results":[{}]}"#);
        assert!(
            cache.is_empty(),
            "post_json must not populate the entry-map cache"
        );
    }

    #[tokio::test]
    async fn test_post_json_non_2xx_returns_http_status_error() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/querybatch", server.url());

        let _m = server
            .mock("POST", "/v1/querybatch")
            .with_status(400)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let body = serde_json::json!({ "queries": [] });
        let result: Result<Bytes> = cache.post_json(&url, &body).await;

        match result {
            Err(DepsError::HttpStatus { status, .. }) => assert_eq!(status, 400),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_transport_only_success_returns_body_and_does_not_cache() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/vulns/RUSTSEC-2020-0071", server.url());

        let _m = server
            .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
            .with_status(200)
            .with_body(r#"{"id":"RUSTSEC-2020-0071"}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let result: Bytes = cache.get_transport_only(&url).await.unwrap();

        assert_eq!(result.as_ref(), br#"{"id":"RUSTSEC-2020-0071"}"#);
        assert!(
            cache.is_empty(),
            "get_transport_only must not populate the entry-map cache"
        );
    }

    #[tokio::test]
    async fn test_get_transport_only_non_2xx_returns_http_status_error() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/vulns/missing", server.url());

        let _m = server
            .mock("GET", "/v1/vulns/missing")
            .with_status(404)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let result: Result<Bytes> = cache.get_transport_only(&url).await;

        match result {
            Err(DepsError::HttpStatus { status, .. }) => assert_eq!(status, 404),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    fn dummy_response(size: usize) -> CachedResponse {
        CachedResponse {
            body: Bytes::from(vec![0u8; size]),
            etag: None,
            last_modified: None,
            fetched_at: Instant::now(),
        }
    }

    #[test]
    fn test_total_bytes_tracks_inserts_and_replacement() {
        let cache = HttpCache::new();
        cache.store_entry("url1".into(), dummy_response(100));
        assert_eq!(cache.total_bytes(), 100);

        // Replacing the same key must account for the delta, not just add.
        cache.store_entry("url1".into(), dummy_response(40));
        assert_eq!(cache.total_bytes(), 40);

        cache.store_entry("url2".into(), dummy_response(60));
        assert_eq!(cache.total_bytes(), 100);
    }

    #[test]
    fn test_clear_resets_total_bytes() {
        let cache = HttpCache::new();
        cache.store_entry("url1".into(), dummy_response(1000));
        assert_eq!(cache.total_bytes(), 1000);

        cache.clear();
        assert_eq!(cache.total_bytes(), 0);
    }

    #[test]
    fn test_small_payloads_do_not_trigger_eviction() {
        let cache = HttpCache::new();
        for i in 0..50 {
            cache.store_entry(format!("url{i}"), dummy_response(1024));
        }

        assert_eq!(cache.len(), 50);
        assert_eq!(cache.total_bytes(), 50 * 1024);
    }

    #[test]
    fn test_evict_entries_triggers_on_byte_budget_with_few_entries() {
        let cache = HttpCache::new();

        // 9 entries, each at the per-entry admission cap: far below
        // MAX_CACHE_ENTRIES by count, but their combined size (72 MiB)
        // overshoots MAX_CACHE_BYTES (64 MiB), exercising the byte-only
        // eviction path.
        for i in 0..9 {
            cache.store_entry(format!("url{i}"), dummy_response(MAX_CACHEABLE_ENTRY_BYTES));
        }
        assert_eq!(cache.len(), 9);
        assert!(cache.total_bytes() > MAX_CACHE_BYTES);

        cache.evict_entries();

        // Only as many oldest entries as needed to clear the byte budget
        // are removed - not a fixed count-based batch. Removing the single
        // oldest (8 MiB) entry brings the total to exactly the 64 MiB
        // budget, so eviction stops there.
        assert!(cache.total_bytes() <= MAX_CACHE_BYTES);
        assert_eq!(cache.len(), 8);
    }

    #[test]
    fn test_evict_entries_removes_oldest_first_for_bytes() {
        let cache = HttpCache::new();

        // 9 entries at the per-entry admission cap (8 MiB each = 72 MiB
        // total, 8 MiB over the 64 MiB budget), so evicting just the single
        // oldest entry restores the cache to within budget - proving
        // eviction picks the genuinely oldest entry, not hash-iteration
        // order (the pre-existing count-eviction bug this PR also fixes).
        cache.store_entry("oldest".into(), dummy_response(MAX_CACHEABLE_ENTRY_BYTES));
        std::thread::sleep(std::time::Duration::from_millis(5));
        for i in 0..8 {
            cache.store_entry(
                format!("newer{i}"),
                dummy_response(MAX_CACHEABLE_ENTRY_BYTES),
            );
        }
        assert_eq!(cache.len(), 9);

        cache.evict_entries();

        assert_eq!(cache.len(), 8);
        assert!(cache.entries.get("oldest").is_none());
        for i in 0..8 {
            assert!(cache.entries.get(&format!("newer{i}")).is_some());
        }
    }

    #[tokio::test]
    async fn test_get_cached_with_headers_evicts_on_byte_budget() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let cache = HttpCache::new();

        // Pre-fill the cache past the byte budget with old entries, all
        // under MAX_CACHE_ENTRIES by count and within the per-entry
        // admission cap.
        for i in 0..9 {
            cache.store_entry(
                format!("stale{i}"),
                dummy_response(MAX_CACHEABLE_ENTRY_BYTES),
            );
        }
        assert!(cache.total_bytes() > MAX_CACHE_BYTES);

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("fresh")
            .create_async()
            .await;

        let result: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result.as_ref(), b"fresh");

        // The pre-request byte-budget check evicted stale entries before
        // fetching, so the cache never grows unbounded past the budget.
        assert!(cache.total_bytes() <= MAX_CACHE_BYTES + result.len());
    }

    #[test]
    fn test_store_entry_skips_caching_oversized_entry() {
        let cache = HttpCache::new();

        // A body over the per-entry admission cap is not retained, even
        // though the caller still gets it back (store_entry's caller
        // already holds `body` independently - see fetch_and_store_with_headers).
        cache.store_entry("big".into(), dummy_response(MAX_CACHEABLE_ENTRY_BYTES + 1));
        assert!(cache.entries.get("big").is_none());
        assert_eq!(cache.total_bytes(), 0);

        // Replacing an existing small entry with an oversized one drops the
        // stale small entry too, rather than leaving it to keep serving
        // increasingly outdated data forever.
        cache.store_entry("small".into(), dummy_response(100));
        assert_eq!(cache.total_bytes(), 100);

        cache.store_entry(
            "small".into(),
            dummy_response(MAX_CACHEABLE_ENTRY_BYTES + 1),
        );
        assert!(cache.entries.get("small").is_none());
        assert_eq!(cache.total_bytes(), 0);
    }

    #[test]
    fn test_concurrent_store_and_evict_keeps_total_bytes_consistent() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(HttpCache::new());
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    for i in 0..150 {
                        cache.store_entry(format!("t{t}-{i}"), dummy_response(4096));
                        if i % 10 == 0 {
                            cache.evict_entries();
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
        cache.evict_entries();

        // The regression this guards against: evict_entries used to
        // snapshot total_bytes once and overwrite it with an absolute
        // store at the end, silently discarding any store_entry delta
        // that landed concurrently. That drift is undetectable from a
        // single-threaded test - only genuine concurrent access exercises
        // the race, so this asserts the tracked counter still matches the
        // actual summed size of what remains in the map.
        let actual: usize = cache
            .entries
            .iter()
            .map(|entry| entry.value().body.len())
            .sum();
        assert_eq!(cache.total_bytes(), actual);
    }
}

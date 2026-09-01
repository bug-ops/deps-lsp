use crate::error::{DepsError, Result};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use reqwest::{Client, Response, StatusCode, Url, header};
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
/// per request in [`HttpCache::get_cached_with_headers_via`], so multiple
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

/// Ceiling every [`BodyLimit`] is clamped to at construction, so no caller can weaken
/// the size guard [`read_body_capped`] enforces past this value.
///
/// 128 MiB comfortably covers the largest known caller ([`crate`][deps-pypi]'s PyPI
/// Simple API full index, ~43 MB decompressed today, capped at 96 MiB for organic
/// growth) while still bounding the pathological case.
const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

/// Percentage of cache entries to evict when capacity is reached.
const CACHE_EVICTION_PERCENTAGE: usize = 10;

/// Upper bound on a single response body, clamped at construction so no caller can
/// weaken the guard `read_body_capped` enforces past `ABSOLUTE_MAX_RESPONSE_BYTES`.
///
/// Every cache method that previously read `MAX_RESPONSE_BYTES` directly now takes
/// this newtype instead (defaulting to it via [`Self::DEFAULT`]), so a caller that
/// legitimately needs a larger cap — e.g. a full-index fetch that bypasses the entry
/// cache entirely, like [`HttpCache::get_transport_only_with_headers_limited`] — can
/// request one without touching the shared constant every other registry client
/// relies on.
///
/// # Examples
///
/// ```
/// use deps_core::cache::BodyLimit;
///
/// let default_limit = BodyLimit::DEFAULT;
/// let clamped = BodyLimit::new(usize::MAX);
/// assert_ne!(clamped, default_limit);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLimit(usize);

impl BodyLimit {
    /// The default limit (`MAX_RESPONSE_BYTES`), used by every cache method that
    /// does not take an explicit [`BodyLimit`].
    pub const DEFAULT: Self = Self(MAX_RESPONSE_BYTES);

    /// Creates a limit of `bytes`, clamped down to `ABSOLUTE_MAX_RESPONSE_BYTES` if
    /// `bytes` exceeds it.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        if bytes > ABSOLUTE_MAX_RESPONSE_BYTES {
            Self(ABSOLUTE_MAX_RESPONSE_BYTES)
        } else {
            Self(bytes)
        }
    }

    /// The clamped byte value this limit enforces.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

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

/// True when a redirect hop moves from an `https` origin to a plain `http` one.
///
/// A redirect to any scheme other than `http`/`https` is already rejected by reqwest
/// itself once a hop is followed, so the downgrade case is the only one this needs to
/// catch here.
fn is_https_downgrade(previous: &Url, next: &Url) -> bool {
    previous.scheme() == "https" && next.scheme() == "http"
}

/// Whether a redirect hop's target host is one [`crate::net_policy::HostClass::never_a_registry`]
/// blocks, exempting `Loopback` in test builds — the identical carve-out [`ensure_https`]
/// already uses, without which every mockito redirect chain in this workspace's tests would
/// break.
fn hop_targets_blocked_host(url: &Url) -> bool {
    let class = crate::net_policy::classify_host(url);
    #[cfg(any(test, feature = "test-util"))]
    let class_blocked = class.never_a_registry() && class != crate::net_policy::HostClass::Loopback;
    #[cfg(not(any(test, feature = "test-util")))]
    let class_blocked = class.never_a_registry();
    class_blocked
}

/// Redirect policy for [`HttpCache`]'s client.
///
/// [`ensure_https`] only validates the *initial* request URL; a `3xx` response can still
/// redirect the actual connection anywhere, including down to plain HTTP — or, per spec
/// `.local/specs/023-cargo-custom-registries/spec.md` NFR-003/plan-1b §1.1, straight to a
/// cloud metadata endpoint or other host no legitimate registry redirect ever targets. This
/// policy stops the redirect chain (rather than erroring) the moment a hop would do either,
/// so the caller sees the last successful `3xx` response and handles it exactly like any
/// other non-2xx status (`DepsError::HttpStatus`) instead of needing a distinct
/// "redirect blocked" error variant.
///
/// The blocked-host check is unconditional and policy-independent — it does not consult
/// [`crate::net_policy::RegistryAccessPolicy`] at all, since [`HostClass::never_a_registry`](crate::net_policy::HostClass::never_a_registry)
/// is deliberately narrower than any workspace-registry policy setting: it blocks only the
/// classes (loopback, link-local, cloud metadata, unspecified) that are never a legitimate
/// registry redirect target for *any* ecosystem, benefiting every one of the eleven crates
/// sharing this client, not only Cargo's workspace-declared indexes.
///
/// This only classifies the redirect target's URL string, not its DNS-resolved address — that
/// residual gap (issue #449, "D1" in PR #447's plan) is now closed by [`BlockedAddrResolver`],
/// which [`build_client`] wires into every client this module builds: a redirect hop reuses the
/// same `Client`, so its target's resolved address is validated too, for free (FR-007).
///
/// Every other redirect — including cross-host ones, which are out of scope for this
/// policy — falls through to reqwest's default (`Policy::limited(10)`), preserving the
/// existing hop-count limit and mockito's plain-`http://` loopback chains
/// used throughout this module's tests.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let downgraded = attempt
            .previous()
            .last()
            .is_some_and(|previous| is_https_downgrade(previous, attempt.url()));
        if downgraded || hop_targets_blocked_host(attempt.url()) {
            attempt.stop()
        } else {
            reqwest::redirect::Policy::default().redirect(attempt)
        }
    })
}

/// Redirect policy for a [`HttpCache::client_for_origin`]-scoped client.
///
/// Stops any hop whose URL no longer starts with `trusted_origin` — for a caller (e.g.
/// NuGet's registration-hive paging) that already validated the *initial* request URL
/// against a trusted prefix and needs that guarantee to hold through a redirect too. This
/// alone also covers a downgrade to plain `http://`: every current caller passes an
/// `https://`-prefixed `trusted_origin`, so an `http://` target already fails the prefix
/// check — a separate scheme check (as [`redirect_policy`] has, for its no-trusted-prefix
/// case) would be dead code here.
fn trusted_origin_redirect_policy(trusted_origin: String) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.url().as_str().starts_with(&trusted_origin) {
            reqwest::redirect::Policy::default().redirect(attempt)
        } else {
            attempt.stop()
        }
    })
}

/// Error returned by [`BlockedAddrResolver`] when a DNS resolution cannot be trusted for
/// connection use — either it produced no address, or at least one resolved address falls into
/// a blocked [`crate::net_policy::HostClass`].
///
/// Kept distinct from [`DepsError`] since this crosses into `reqwest::dns::Resolve`'s own
/// `BoxError` (`Box<dyn std::error::Error + Send + Sync>`) return type, not this crate's own
/// error type.
#[derive(Debug, thiserror::Error)]
enum ResolveGuardError {
    /// The resolver returned zero addresses for `host` — fail-closed (NFR-004) rather than
    /// silently treating "nothing resolved" as "nothing to block".
    #[error("DNS resolution for {host} returned no addresses")]
    NoAddresses { host: String },
    /// `addr`, resolved for `host`, falls into `class`, one of the
    /// [`crate::net_policy::HostClass::never_a_registry`] classes no legitimate registry index
    /// (or a redirect from one) could ever target.
    #[error("resolved address {addr} for host {host} is {class}, blocked by net_policy")]
    Blocked {
        host: String,
        addr: std::net::IpAddr,
        class: crate::net_policy::HostClass,
    },
}

/// Validates every address `tokio::net::lookup_host` returned for `host`, rejecting the whole
/// resolution if any is blocked — an attacker's public A record alongside a blocked one must not
/// keep the probe alive (FR-003).
fn validate_resolved_addrs(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
) -> std::result::Result<Vec<std::net::SocketAddr>, ResolveGuardError> {
    if addrs.is_empty() {
        tracing::warn!(host, "DNS resolution returned no addresses");
        return Err(ResolveGuardError::NoAddresses {
            host: host.to_string(),
        });
    }
    for addr in &addrs {
        let class = crate::net_policy::classify_addr(addr.ip());
        if class.never_a_registry() {
            tracing::warn!(host, addr = %addr.ip(), %class, "blocking DNS-resolved address");
            return Err(ResolveGuardError::Blocked {
                host: host.to_string(),
                addr: addr.ip(),
                class,
            });
        }
    }
    Ok(addrs)
}

/// Connect-time DNS resolver that closes the rebinding TOCTOU gap left by [`ensure_https`]/
/// [`hop_targets_blocked_host`]'s URL-string-only classification (issue #449): those check the
/// declared hostname, but `reqwest`'s connector resolves DNS independently, later, and an
/// attacker who controls the hostname's DNS can rebind it to a blocked address in between.
///
/// Wired into every client [`build_client`] returns, so all 11 ecosystem crates sharing this
/// client pool inherit it with zero per-crate plumbing (FR-006/NFR-002).
///
/// # Scope
///
/// A resolver only ever sees a hostname, never which [`crate::net_policy::WorkspaceRegistryAccess`]
/// policy applies to the request that triggered it — so this enforces only the
/// policy-independent [`crate::net_policy::HostClass::never_a_registry`] tier (loopback,
/// link-local, cloud-metadata, unspecified), the same tier [`hop_targets_blocked_host`] already
/// applies. It closes issue #449's filed exploit (cloud-metadata rebinding) but does **not**
/// enforce full `PublicOnly` semantics: a hostname that legitimately resolves to
/// `HostClass::Global` at classification time and is rebound to an RFC1918/CGNAT address at
/// connect time is not caught here — closing that residual needs policy provenance at the
/// connector, tracked as issue #455.
///
/// # Fail-closed (NFR-004)
///
/// Returns `Err` — never `Ok`, never a fallback resolver — on a `lookup_host` error, zero
/// addresses, or any resolved address [`crate::net_policy::HostClass::never_a_registry`] blocks.
///
/// # Known limitations
///
/// - [`ClientBuilder::resolve`](reqwest::ClientBuilder::resolve)/
///   [`resolve_to_addrs`](reqwest::ClientBuilder::resolve_to_addrs) overrides wrap *outside* the
///   configured resolver (`reqwest`'s `DnsResolverWithOverrides`) and would bypass this guard
///   entirely if ever called — this workspace does not call them today.
/// - A configured system proxy (`HTTPS_PROXY`) resolves the target hostname itself; this
///   resolver then only ever sees the proxy's own address. Operator configuration, not
///   attacker-controlled, so NOT claimed as a defended case.
/// - Never applies to an IP-literal host (`https://169.254.169.254/`): `hyper-util`'s connector
///   parses those directly and never calls the configured resolver, so
///   [`classify_host`](crate::net_policy::classify_host) (via [`ensure_https`]/
///   [`hop_targets_blocked_host`]) remains the sole guard for literals — a disjoint domain from
///   this resolver's name-based one, not a gap.
/// - Unlike [`ensure_https`]/[`hop_targets_blocked_host`], this resolver has **no** `test-util`
///   carve-out for `Loopback`: it blocks a `localhost`/`127.0.0.1` *name* unconditionally, in
///   every build. A downstream `test-util` consumer that mocks by binding an IP literal (as
///   this workspace's own `mockito` usage does) is unaffected — literals never reach this
///   resolver at all — but one that mocks via a `localhost` *name* would be newly blocked.
#[derive(Debug, Clone, Copy)]
struct BlockedAddrResolver;

impl reqwest::dns::Resolve for BlockedAddrResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let addrs = validate_resolved_addrs(&host, addrs)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Builds a client with `HttpCache`'s shared configuration (user agent, timeout, resolver),
/// varying only the redirect policy — kept in one place so a future client-wide setting (proxy,
/// connection pool sizing, etc.) added to [`HttpCache::new`] can't silently miss the pooled
/// clients [`HttpCache::client_for_origin`] builds. This is also the workspace's only
/// `Client::builder()` call site, so [`BlockedAddrResolver`] applies everywhere without
/// per-crate plumbing.
fn build_client(redirect: reqwest::redirect::Policy) -> Client {
    Client::builder()
        .user_agent(format!("deps-lsp/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(redirect)
        .dns_resolver(BlockedAddrResolver)
        .build()
        .expect("failed to create HTTP client")
}

/// Reads a response body incrementally, aborting once it exceeds `limit`.
///
/// Chunked reading (via [`Response::chunk`]) is required because the
/// decompressed body size is not known upfront: `gzip` decoding strips
/// `Content-Length`, so the only reliable guard against an oversized or
/// maliciously amplified (decompression-bomb) response is counting bytes
/// as they arrive and bailing before the whole body is buffered.
async fn read_body_capped(url: &str, mut response: Response, limit: BodyLimit) -> Result<Bytes> {
    let mut body = BytesMut::new();
    let limit = limit.bytes();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DepsError::RegistryError {
            package: url.to_string(),
            source: e,
        })?
    {
        if body.len() + chunk.len() > limit {
            return Err(DepsError::ResponseTooLarge {
                url: url.to_string(),
                limit,
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
///
/// Likewise, the key doesn't encode *which* client (and so which redirect policy)
/// produced an entry — [`HttpCache::get_cached`] and [`HttpCache::get_cached_trusted_origin`]
/// share one entry map. No caller today requests the same URL through both, but one that did
/// could observe the other's cached (and differently redirect-validated) body.
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
    /// Per-trusted-origin client pool backing [`Self::get_cached_trusted_origin`], keyed by
    /// the exact `trusted_origin` prefix string passed to that call. reqwest's redirect
    /// policy is fixed per-`Client`, so a distinct client is unavoidable per distinct
    /// origin; pooled here so repeated calls against the same origin reuse one client
    /// (and its connection pool) instead of rebuilding on every call.
    trusted_clients: DashMap<String, Client>,
}

impl HttpCache {
    /// Creates a new HTTP cache with default configuration.
    ///
    /// The cache uses a configurable timeout for all requests and identifies
    /// itself with an auto-versioned user agent.
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            client: build_client(redirect_policy()),
            trusted_clients: DashMap::new(),
        }
    }

    /// Returns the client scoped to `trusted_origin`, building and pooling one on first use.
    ///
    /// The `get` fast path (a shared read lock) serves the common case — a `trusted_origin`
    /// already pooled — without ever taking `trusted_clients`' write-capable `entry` lock;
    /// `entry().or_insert_with()` only runs on a miss, so two callers racing on the same new
    /// origin still only ever build and store one `Client` for it, not one each.
    fn client_for_origin(&self, trusted_origin: &str) -> Client {
        if let Some(existing) = self.trusted_clients.get(trusted_origin) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(trusted_origin.to_string())
            .or_insert_with(|| {
                build_client(trusted_origin_redirect_policy(trusted_origin.to_string()))
            })
            .clone()
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
    /// `conditional_request_with_headers`'s match in `get_cached_with_headers_via`), this
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
        self.get_cached_with_headers_via(url, extra_headers, &self.client)
            .await
    }

    /// Like [`Self::get_cached`], but additionally stops any redirect hop whose target no
    /// longer starts with `trusted_origin` (e.g. `https://api.nuget.org/v3/registration5-gz/`).
    ///
    /// For a caller that already validated the *initial* request URL against a trusted
    /// prefix (NuGet's registration-hive paging validates `page.id` this way) and needs
    /// that guarantee to hold through any redirect too, not just the first hop —
    /// [`Self::get_cached`]'s own policy deliberately does not enforce this, since
    /// cross-host redirects are legitimate for the other registry clients sharing this
    /// cache; the stricter check is opt-in per call rather than global.
    ///
    /// The block only surfaces as an error on a cold cache: like [`Self::get_cached`]'s own
    /// stale-while-revalidate fallback, a warm entry for `url` still returns the last
    /// known-good body (itself already fetched and origin-validated on a prior call)
    /// instead of propagating a blocked-redirect `HttpStatus` from a revalidation attempt.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_trusted_origin(
        &self,
        url: &str,
        trusted_origin: &str,
    ) -> Result<Bytes> {
        let client = self.client_for_origin(trusted_origin);
        self.get_cached_with_headers_via(url, &[], &client).await
    }

    /// Like [`Self::get_cached_trusted_origin`], but additionally injects `extra_headers`
    /// (e.g. an `Authorization` bearer token) into every request — the authenticated
    /// counterpart to [`Self::get_cached_with_headers`], composed with the same
    /// origin-pinned redirect policy [`Self::get_cached_trusted_origin`] uses.
    ///
    /// This exists specifically so a header carrying a credential can never survive a
    /// cross-origin redirect hop: [`Self::get_cached_with_headers`] attaches
    /// `extra_headers` to the *initial* request only and follows reqwest's default
    /// (same-scheme, any-host) redirect policy for every hop after that, which is
    /// exactly the shape a hostile or misconfigured redirect on the resolved index
    /// itself could exploit to exfiltrate a bearer token to an attacker-controlled
    /// host. Composing `Self::client_for_origin`'s pinned-origin client with header
    /// injection closes that by construction — no empirical redirect test is needed
    /// to prove the header cannot leak, since the client stops following before a
    /// cross-origin hop would ever be sent.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached_trusted_origin`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::cache::HttpCache;
    /// use reqwest::header;
    ///
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let data = cache
    ///     .get_cached_trusted_origin_with_headers(
    ///         "https://index.mycorp.dev/se/rd/serde",
    ///         "https://index.mycorp.dev/",
    ///         &[(header::AUTHORIZATION, "Bearer secret-token")],
    ///     )
    ///     .await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached_trusted_origin_with_headers(
        &self,
        url: &str,
        trusted_origin: &str,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        let client = self.client_for_origin(trusted_origin);
        self.get_cached_with_headers_via(url, extra_headers, &client)
            .await
    }

    async fn get_cached_with_headers_via(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        client: &Client,
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
                .conditional_request_with_headers(url, &cached, extra_headers, client)
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

        self.fetch_and_store_with_headers(url, extra_headers, client)
            .await
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
        client: &Client,
    ) -> Result<Option<Bytes>> {
        ensure_https(url)?;
        let mut request = client.get(url);

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
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;

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
        client: &Client,
    ) -> Result<Bytes> {
        ensure_https(url)?;
        tracing::debug!(extra_headers = extra_headers.len(), "fetching fresh: {url}");

        let mut request = client.get(url);
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
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;

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

        read_body_capped(url, response, BodyLimit::DEFAULT).await
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
        self.get_transport_only_with_headers(url, &[]).await
    }

    /// Same as [`Self::get_transport_only`], but injects extra request headers (e.g. a
    /// content-negotiating `Accept`) — mirrors how [`Self::get_cached_with_headers`] relates
    /// to [`Self::get_cached`].
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx
    /// status, `DepsError::RegistryError` if the request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    pub async fn get_transport_only_with_headers(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        self.get_transport_only_with_headers_limited(url, extra_headers, BodyLimit::DEFAULT)
            .await
    }

    /// Same as [`Self::get_transport_only_with_headers`], but takes an explicit
    /// [`BodyLimit`] instead of the [`BodyLimit::DEFAULT`] (`MAX_RESPONSE_BYTES`) cap.
    ///
    /// For a caller whose response is legitimately larger than every other registry
    /// payload — e.g. `deps-pypi`'s full Simple API project index — without weakening
    /// the cap every other caller of this cache relies on. `BodyLimit` clamps at
    /// construction, so this can never be widened past `ABSOLUTE_MAX_RESPONSE_BYTES`
    /// regardless of what the caller passes in.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_transport_only_with_headers`].
    pub async fn get_transport_only_with_headers_limited(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        limit: BodyLimit,
    ) -> Result<Bytes> {
        self.transport_only_via(url, extra_headers, limit, &self.client)
            .await
    }

    /// Same as [`Self::get_transport_only_with_headers_limited`], but additionally
    /// stops any redirect hop whose target no longer starts with `trusted_origin`
    /// (see [`Self::get_cached_trusted_origin`], which applies the identical policy
    /// to the entry-cached path). For a caller carrying a materially larger
    /// [`BodyLimit`] than [`BodyLimit::DEFAULT`] — the bigger the budget, the more
    /// worth pinning the origin an arbitrary cross-host redirect could point it at.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_transport_only_with_headers_limited`].
    pub async fn get_transport_only_with_headers_limited_trusted_origin(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        limit: BodyLimit,
        trusted_origin: &str,
    ) -> Result<Bytes> {
        let client = self.client_for_origin(trusted_origin);
        self.transport_only_via(url, extra_headers, limit, &client)
            .await
    }

    async fn transport_only_via(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        limit: BodyLimit,
        client: &Client,
    ) -> Result<Bytes> {
        ensure_https(url)?;

        let mut request = client.get(url);
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

        read_body_capped(url, response, limit).await
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

    // reqwest's `Attempt` has no public constructor, so the redirect policy closure
    // itself can't be unit-tested directly from outside the reqwest crate; this
    // exercises the pure detection logic it delegates to instead. End-to-end coverage
    // of an actual https->http redirect is not feasible with mockito, which is
    // http-only (see test_get_cached_follows_same_scheme_redirect for the
    // policy-is-wired-in regression check that mockito *can* exercise).
    #[test]
    fn test_is_https_downgrade() {
        let https = Url::parse("https://example.com/a").unwrap();
        let http = Url::parse("http://example.com/a").unwrap();

        assert!(is_https_downgrade(&https, &http));
        assert!(!is_https_downgrade(&http, &https));
        assert!(!is_https_downgrade(&https, &https));
        assert!(!is_https_downgrade(&http, &http));
    }

    #[test]
    fn test_hop_targets_blocked_host_blocks_cloud_metadata() {
        let url = Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
        assert!(hop_targets_blocked_host(&url));
    }

    #[test]
    fn test_hop_targets_blocked_host_allows_global() {
        let url = Url::parse("https://index.crates.io/").unwrap();
        assert!(!hop_targets_blocked_host(&url));
    }

    // The loopback carve-out (identical to `ensure_https`'s) must still exempt
    // loopback hops under `cfg(test)`, or every mockito redirect chain in this
    // module's own tests would start failing.
    #[test]
    fn test_hop_targets_blocked_host_exempts_loopback_under_test_cfg() {
        let url = Url::parse("http://127.0.0.1:1234/api/target").unwrap();
        assert!(!hop_targets_blocked_host(&url));
    }

    // Issue #449: the connect-time resolver guard's pure classification core, unit-tested
    // directly rather than through `tokio::net::lookup_host` — no live DNS/network needed.
    #[test]
    fn test_validate_resolved_addrs_blocks_cloud_metadata() {
        let addrs = vec!["169.254.169.254:0".parse().unwrap()];
        assert!(matches!(
            validate_resolved_addrs("evil.example", addrs),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    // FR-003: an attacker's public A record alongside a blocked one must not keep the probe
    // alive — the whole resolution is rejected, not filtered down to the public address.
    #[test]
    fn test_validate_resolved_addrs_blocks_when_any_address_is_blocked() {
        let addrs = vec![
            "1.1.1.1:0".parse().unwrap(),
            "169.254.169.254:0".parse().unwrap(),
        ];
        assert!(matches!(
            validate_resolved_addrs("evil.example", addrs),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    #[test]
    fn test_validate_resolved_addrs_allows_global() {
        let addrs = vec!["1.1.1.1:0".parse().unwrap()];
        assert_eq!(
            validate_resolved_addrs("index.crates.io", addrs.clone()).unwrap(),
            addrs
        );
    }

    // NFR-004: fail-closed on an empty resolution rather than silently treating "nothing
    // resolved" as "nothing to block".
    #[test]
    fn test_validate_resolved_addrs_fails_closed_on_empty() {
        assert!(matches!(
            validate_resolved_addrs("evil.example", vec![]),
            Err(ResolveGuardError::NoAddresses { .. })
        ));
    }

    #[test]
    fn test_validate_resolved_addrs_unwraps_mapped_v4() {
        let addrs = vec!["[::ffff:169.254.169.254]:0".parse().unwrap()];
        assert!(matches!(
            validate_resolved_addrs("evil.example", addrs),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    // Direct unit coverage of `BlockedAddrResolver::resolve` on a *name* (not an IP literal —
    // that path never reaches any resolver in production, see the struct's `# Known
    // limitations` doc). `localhost` resolves via the OS's own hosts file, no network needed.
    // This alone does not prove the resolver is wired into `build_client` — see the sibling
    // test below (critic S1) for that.
    #[tokio::test]
    async fn test_blocked_addr_resolver_rejects_loopback_name_directly() {
        use reqwest::dns::Resolve;

        let addrs = BlockedAddrResolver
            .resolve("localhost".parse().unwrap())
            .await;
        assert!(addrs.is_err());
    }

    // Issue #449 critic S1: the previous version of this test called
    // `BlockedAddrResolver::resolve` directly and never went through `build_client` at all —
    // deleting `.dns_resolver(BlockedAddrResolver)` from `build_client` left it green. This
    // version proves actual wiring behaviorally: a real mockito listener answers on
    // `server.socket_address()`'s port, reached here through the `localhost` *name* (so the
    // request actually reaches the configured resolver, unlike an IP literal, which
    // hyper-util's connector parses directly and never consults the resolver — see
    // `BlockedAddrResolver`'s `# Known limitations` doc). Without the guard wired in, this
    // request would succeed against the real listener; with it wired in, it must fail before
    // ever reaching the listener.
    #[tokio::test]
    async fn test_build_client_wires_in_blocked_addr_resolver() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/")
            .with_status(200)
            .create_async()
            .await;
        let port = server.socket_address().port();

        let client = build_client(redirect_policy());
        let result = client.get(format!("http://localhost:{port}/")).send().await;

        let err = result.expect_err(
            "expected the wired-in resolver guard to reject a loopback-resolving name even \
             though a real listener answers at this port",
        );
        // Not just any failure: the `Debug` impl (unlike `Display`) surfaces the boxed
        // `source` chain, so this confirms `ResolveGuardError::Blocked` itself produced the
        // error rather than an unrelated failure (timeout, TLS, connection refused)
        // coincidentally also erroring. `derive(Debug)` on an enum prints only the variant
        // name, not `ResolveGuardError::`, hence checking for `Blocked`/`Loopback` together
        // rather than the enum's own name.
        let debug = format!("{err:?}");
        assert!(
            debug.contains("Blocked") && debug.contains("Loopback"),
            "expected the failure to originate from ResolveGuardError::Blocked with class \
             Loopback, got: {debug}"
        );
    }

    // S5 (plan-1b §1.1/§4): a 302 to the cloud-metadata IP must be stopped by the
    // *unconditional* redirect policy, not just the trusted-origin one — this is the
    // empirical proof that #443's default unauthenticated client also closes the
    // redirect-hop bypass, not only `get_cached_trusted_origin`.
    #[tokio::test]
    async fn test_get_cached_stops_redirect_to_cloud_metadata() {
        let mut server = mockito::Server::new_async().await;

        let _redirect = server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", "https://169.254.169.254/latest/meta-data/")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", server.url());
        let result: Result<Bytes> = cache.get_cached(&source_url).await;

        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected the redirect to be stopped and surfaced as HttpStatus(302)"
        );
    }

    #[tokio::test]
    async fn test_get_cached_follows_same_scheme_redirect() {
        let mut server = mockito::Server::new_async().await;
        let target_url = format!("{}/api/target", server.url());

        let _redirect = server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &target_url)
            .create_async()
            .await;
        let _target = server
            .mock("GET", "/api/target")
            .with_status(200)
            .with_body("redirected data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", server.url());
        let result: Bytes = cache.get_cached(&source_url).await.unwrap();

        assert_eq!(result.as_ref(), b"redirected data");
    }

    // Unlike the https->http downgrade case, cross-origin redirect blocking IS reachable
    // through mockito: two separate `mockito::Server` instances bind to distinct ports,
    // and a distinct port is a distinct origin (scheme+host+port), so a 302 from one to
    // the other is a genuine cross-origin redirect the trusted-origin policy must stop.
    #[tokio::test]
    async fn test_get_cached_trusted_origin_stops_cross_origin_redirect() {
        let mut trusted_server = mockito::Server::new_async().await;
        let mut other_server = mockito::Server::new_async().await;

        let trusted_origin = format!("{}/", trusted_server.url());
        let escape_target = format!("{}/api/stolen", other_server.url());

        let _redirect = trusted_server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &escape_target)
            .create_async()
            .await;
        let escape = other_server
            .mock("GET", "/api/stolen")
            .with_status(200)
            .with_body("must not be returned")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", trusted_server.url());
        let result: Result<Bytes> = cache
            .get_cached_trusted_origin(&source_url, &trusted_origin)
            .await;

        // The stopped redirect surfaces as the 302 response itself, handled like any
        // other non-2xx status - not as a distinct "redirect blocked" error variant.
        // Assert via `matches!` rather than debug-formatting `result` in a panic message:
        // on the `Ok` arm that value is the raw response body, which would otherwise be
        // written to the test log by the panic machinery.
        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected HttpStatus(302)"
        );

        // Proves the security property itself (the escape origin was never contacted),
        // not just the symptom (the result is a 302) - a client that followed the
        // redirect and then discarded the body would still pass the assertion above.
        escape.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_cached_trusted_origin_follows_same_origin_redirect() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let target_url = format!("{}/api/target", server.url());

        let _redirect = server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &target_url)
            .create_async()
            .await;
        let _target = server
            .mock("GET", "/api/target")
            .with_status(200)
            .with_body("trusted data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", server.url());
        let result: Bytes = cache
            .get_cached_trusted_origin(&source_url, &trusted_origin)
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"trusted data");
    }

    // Proves every hop is re-checked, not just the first: a same-origin hop is followed,
    // then a second, cross-origin hop from that (already-followed) intermediate is stopped.
    #[tokio::test]
    async fn test_get_cached_trusted_origin_stops_second_hop_of_multi_hop_chain() {
        let mut trusted_server = mockito::Server::new_async().await;
        let mut other_server = mockito::Server::new_async().await;

        let trusted_origin = format!("{}/", trusted_server.url());
        let intermediate_url = format!("{}/api/intermediate", trusted_server.url());
        let escape_target = format!("{}/api/stolen", other_server.url());

        let _first_hop = trusted_server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &intermediate_url)
            .create_async()
            .await;
        let _second_hop = trusted_server
            .mock("GET", "/api/intermediate")
            .with_status(302)
            .with_header("location", &escape_target)
            .create_async()
            .await;
        let escape = other_server
            .mock("GET", "/api/stolen")
            .with_status(200)
            .with_body("must not be returned")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", trusted_server.url());
        let result: Result<Bytes> = cache
            .get_cached_trusted_origin(&source_url, &trusted_origin)
            .await;

        // Assert via `matches!` rather than debug-formatting `result` in a panic message:
        // on the `Ok` arm that value is the raw response body, which would otherwise be
        // written to the test log by the panic machinery.
        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected HttpStatus(302)"
        );
        escape.assert_async().await;
    }

    // Sibling path-prefix rejection: `.../api/` must not accept `.../apiX/...`. The other
    // trusted-origin tests use a bare-host prefix, which never exercises this boundary.
    #[tokio::test]
    async fn test_get_cached_trusted_origin_rejects_sibling_path_prefix() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/api/", server.url());
        let escape_target = format!("{}/apiX/evil", server.url());

        let _redirect = server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &escape_target)
            .create_async()
            .await;
        let escape = server
            .mock("GET", "/apiX/evil")
            .with_status(200)
            .with_body("must not be returned")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", server.url());
        let result: Result<Bytes> = cache
            .get_cached_trusted_origin(&source_url, &trusted_origin)
            .await;

        // Assert via `matches!` rather than debug-formatting `result` in a panic message:
        // on the `Ok` arm that value is the raw response body, which would otherwise be
        // written to the test log by the panic machinery.
        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected HttpStatus(302)"
        );
        escape.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_cached_trusted_origin_with_headers_sends_extra_header() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .match_header("authorization", "Bearer secret-token")
            .with_status(200)
            .with_body("authenticated data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/api/data", server.url());
        let result: Bytes = cache
            .get_cached_trusted_origin_with_headers(
                &url,
                &trusted_origin,
                &[(header::AUTHORIZATION, "Bearer secret-token")],
            )
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"authenticated data");
    }

    // The security property this method exists for: a credential header must never survive
    // a cross-origin redirect hop, proven the same way the unauthenticated trusted-origin
    // test proves it (the escape origin is never contacted at all) rather than by asserting
    // the header was merely absent on a request that did land.
    #[tokio::test]
    async fn test_get_cached_trusted_origin_with_headers_stops_cross_origin_redirect() {
        let mut trusted_server = mockito::Server::new_async().await;
        let mut other_server = mockito::Server::new_async().await;

        let trusted_origin = format!("{}/", trusted_server.url());
        let escape_target = format!("{}/api/stolen", other_server.url());

        let _redirect = trusted_server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &escape_target)
            .create_async()
            .await;
        let escape = other_server
            .mock("GET", "/api/stolen")
            .with_status(200)
            .with_body("must not be returned")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let source_url = format!("{}/api/source", trusted_server.url());
        let result: Result<Bytes> = cache
            .get_cached_trusted_origin_with_headers(
                &source_url,
                &trusted_origin,
                &[(header::AUTHORIZATION, "Bearer secret-token")],
            )
            .await;

        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected HttpStatus(302)"
        );
        escape.assert_async().await;
    }

    // Proves `redirect_policy`'s `Policy::default().redirect(attempt)` delegation is
    // actually wired in and live: without it (e.g. a no-op policy that always follows),
    // this chain would keep following past 10 hops instead of erroring. A single-hop
    // redirect test alone can't distinguish "delegation is live" from "no policy at all".
    #[tokio::test]
    async fn test_get_cached_default_client_enforces_ten_hop_redirect_limit() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        // reqwest's default policy errors once `previous.len() > 10`, i.e. on the 11th
        // redirect hop - so 11 redirecting steps (step/0 through step/10) are needed to
        // trigger it; step/11 must never actually be requested.
        let mut hop_mocks = Vec::new();
        for i in 0..11u32 {
            let path = format!("/step/{i}");
            let next = format!("{base}/step/{}", i + 1);
            hop_mocks.push(
                server
                    .mock("GET", path.as_str())
                    .with_status(302)
                    .with_header("location", &next)
                    .create_async()
                    .await,
            );
        }
        let final_step = server
            .mock("GET", "/step/11")
            .with_status(200)
            .with_body("unreachable")
            .expect(0)
            .create_async()
            .await;

        // Kept alive (not just built) until here: each `Mock` deregisters on drop, so
        // dropping this early would silently turn every hop 404 instead of 302.
        assert_eq!(hop_mocks.len(), 11);

        let cache = HttpCache::new();
        let start_url = format!("{base}/step/0");
        let result: Result<Bytes> = cache.get_cached(&start_url).await;

        assert!(
            matches!(result, Err(DepsError::RegistryError { .. })),
            "expected a too-many-redirects network error, got {result:?}"
        );
        final_step.assert_async().await;
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
        // https:// (not http://) so this exercises DNS-resolution failure, not the
        // HTTPS-only policy enforced by `ensure_https`.
        let url = "https://invalid.localhost.test/data";

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
        let result: Result<Bytes> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.client)
            .await;

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
        let _: Bytes = cache
            .fetch_and_store_with_headers(&url, &[], &cache.client)
            .await
            .unwrap();

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
        let result: Result<Bytes> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.client)
            .await;

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
        let result: Bytes = cache
            .fetch_and_store_with_headers(&url, &[], &cache.client)
            .await
            .unwrap();

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
    async fn test_get_transport_only_with_headers_sends_extra_headers() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/vulns/RUSTSEC-2020-0071", server.url());

        let _m = server
            .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
            .match_header("accept", "application/json")
            .with_status(200)
            .with_body(r#"{"id":"RUSTSEC-2020-0071"}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let headers = [(header::ACCEPT, "application/json")];
        let result: Bytes = cache
            .get_transport_only_with_headers(&url, &headers)
            .await
            .unwrap();

        assert_eq!(result.as_ref(), br#"{"id":"RUSTSEC-2020-0071"}"#);
        assert!(
            cache.is_empty(),
            "get_transport_only_with_headers must not populate the entry-map cache"
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

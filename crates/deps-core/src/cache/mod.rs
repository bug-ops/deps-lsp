//! HTTP response cache shared by every ecosystem's registry client.
//!
//! Wraps outbound registry requests with RFC 7232 conditional-request
//! validation (`ETag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`) so
//! that unchanged registry data is served from a bounded in-memory cache
//! instead of re-fetched. Entry count and total retained bytes are both
//! capped to keep memory use predictable under long-running LSP sessions.

use crate::error::{DepsError, Result};
use crate::net_policy::{RegistryAccessPolicy, TrustedPrefix, WorkspaceRegistryAccess};
use crate::redact::RedactedUrl;
pub use auth::{CredentialHeader, RateLimitRevocation, RequestAuth, RequestHeader};
pub use body::BodyLimit;
use dashmap::DashMap;
pub use response::{CachedResponse, CredentialPartition, RevalidationFailure};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use transport::Transport;

mod auth;
mod body;
mod errors;
mod fetch;
mod guard;
mod pool;
mod redirect;
mod resolver;
mod response;
mod store;
mod transport;

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
/// per request in [`HttpCache::get_cached_via`], so multiple
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

/// Whether [`HttpCache`] may issue outbound network requests (issue #483).
///
/// Passed to [`HttpCache::set_offline`]. `Offline` also overrides
/// [`CacheMode`] to behave as [`CacheMode::Enabled`] — see that method's docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Outbound registry requests are attempted normally.
    Online,
    /// All outbound requests are blocked; only cached/warm entries are served.
    Offline,
}

impl NetworkMode {
    /// Builds a `NetworkMode` from a `network.offline` config/CLI flag (`true` means
    /// [`Self::Offline`]).
    ///
    /// The single, explicitly named conversion point from that boundary's `bool`
    /// representation (issue #1436 S1) — deliberately not a `From<bool>` impl, which would
    /// let any unrelated `bool` (e.g. a `cache.enabled` flag transposed at the call site)
    /// silently convert too, defeating the point of typing this API in the first place.
    #[must_use]
    pub fn from_offline_flag(offline: bool) -> Self {
        if offline { Self::Offline } else { Self::Online }
    }

    /// Whether outbound network requests may be attempted (`self` is [`Self::Online`]).
    ///
    /// Centralizes the `network == NetworkMode::Online` check every call site otherwise
    /// reimplements inline (issue #1557 code-review finding).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::NetworkMode;
    ///
    /// assert!(NetworkMode::Online.is_online());
    /// assert!(!NetworkMode::Offline.is_online());
    /// ```
    #[must_use]
    pub const fn is_online(self) -> bool {
        matches!(self, Self::Online)
    }

    /// Whether outbound network requests are blocked (`self` is [`Self::Offline`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::NetworkMode;
    ///
    /// assert!(NetworkMode::Offline.is_offline());
    /// assert!(!NetworkMode::Online.is_offline());
    /// ```
    #[must_use]
    pub const fn is_offline(self) -> bool {
        matches!(self, Self::Offline)
    }
}

/// Whether [`HttpCache`] uses its entry-map cache to serve warm entries (issue #482).
///
/// Passed to [`HttpCache::set_cache_enabled`]. See that method's docs for the override
/// [`NetworkMode::Offline`] has on this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// The entry map is consulted and populated as usual.
    Enabled,
    /// The entry map is bypassed entirely, except while [`NetworkMode::Offline`] overrides
    /// this to behave as `Enabled`.
    Disabled,
}

impl CacheMode {
    /// Builds a `CacheMode` from a `cache.enabled` config/CLI flag (`true` means
    /// [`Self::Enabled`]).
    ///
    /// The single, explicitly named conversion point from that boundary's `bool`
    /// representation — see [`NetworkMode::from_offline_flag`]'s doc for why this is a named
    /// constructor rather than a `From<bool>` impl.
    #[must_use]
    pub fn from_enabled_flag(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

/// Which cache-key namespace and [`AddrGuard`] tier a [`Transport`] enforces.
///
/// `Baseline` is every non-workspace request (all 11 ecosystems' registry/redirect/API
/// traffic); `WorkspaceDeclared` is Cargo's workspace-declared-registry traffic, carrying the
/// same [`WorkspaceRegistryAccess`] **value snapshot** an [`AddrGuard::WorkspaceDeclared`]
/// carries (see that variant's docs) — [`HttpCache::cache_key`] reads the digit from this
/// snapshot, never from a live `Arc<RegistryAccessPolicy>` read, so a request's cache key and
/// its guard always agree on which policy era they were constructed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CacheTier {
    Baseline,
    WorkspaceDeclared(WorkspaceRegistryAccess),
    /// An origin-pinned, connect-address-guarded tier (issue #561/#562) — see
    /// [`Transport::origin_pinned_guarded`]. `digest` identifies the `(trusted_origin,
    /// policy_snapshot)` pair this transport was built for (**never** a credential identity —
    /// that is the request's [`RequestAuth`], folded into the cache key only).
    Pinned {
        digest: u64,
    },
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
/// Entries are keyed by URL alone (see `Self::cache_key`, private) — `extra_headers` (see
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
///
/// [`Self::get_cached_workspace`] is the one exception: it is namespaced under a distinct,
/// policy-scoped key prefix (see `Self::cache_key`, private) so a body fetched under a looser
/// [`crate::net_policy::WorkspaceRegistryAccess`] can never be served back once the policy
/// tightens.
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
    /// The shared, unauthenticated transport used by every non-workspace request.
    baseline: Transport,
    /// Per-`(trusted_origin, tier)` transport pool backing [`Self::get_cached_trusted_origin`]
    /// and [`Self::get_cached_pinned`] alike (issue #561/#562, FR-017), keyed by the exact
    /// `trusted_origin` prefix string passed to that call, paired with the [`CacheTier`] it was
    /// built for. reqwest's redirect policy is fixed per-`Client`, so a distinct client is
    /// unavoidable per distinct origin; pooled here so repeated calls against the same
    /// `(origin, tier)` reuse one transport (and its connection pool) instead of rebuilding on
    /// every call. Deliberately **uncapped** — see [`Self::set_registry_policy`]'s docs for why
    /// a capacity cap was considered and dropped for this pool.
    trusted_clients: DashMap<(TrustedPrefix, CacheTier), Transport>,
    /// Live-updatable Cargo workspace-registry policy the `workspace` transport field below
    /// and cache-key namespace are derived from. Kept alongside that field (not just read once
    /// at construction) so [`Self::cache_key`] and [`Self::set_registry_policy`] both read the
    /// same discriminant.
    policy: Arc<RegistryAccessPolicy>,
    /// The transport for [`Self::get_cached_workspace`], rebuilt in place by
    /// [`Self::set_registry_policy`] on every actual policy transition.
    workspace: RwLock<Transport>,
    /// Test-only counter of how many times [`Self::set_registry_policy`] has actually rebuilt
    /// the `workspace` transport field above (as opposed to no-op'ing on an unchanged value) —
    /// asserts C4's rebuild-only-on-change behavior directly.
    #[cfg(test)]
    workspace_rebuilds: AtomicUsize,
    /// Live-updatable "no outbound requests" flag (issue #483). Enforced by
    /// [`Self::ensure_online`] at all 4 send sites. See [`Self::set_offline`]'s docs for
    /// the override this has on `cache_enabled` below.
    offline: AtomicBool,
    /// Live-updatable entry-map toggle (issue #482): `false` bypasses the entry map
    /// entirely (see `get_cached_via`). Overridden to effectively `true`
    /// whenever `offline` is set — see [`Self::set_offline`]'s docs.
    cache_enabled: AtomicBool,
}

impl HttpCache {
    /// Creates a new HTTP cache with default configuration and the default
    /// [`crate::net_policy::WorkspaceRegistryAccess`] policy (`PublicOnly`).
    ///
    /// The cache uses a configurable timeout for all requests and identifies
    /// itself with an auto-versioned user agent.
    pub fn new() -> Self {
        Self::with_policy(Arc::new(RegistryAccessPolicy::default()))
    }

    /// Creates a new HTTP cache whose [`Self::get_cached_workspace`] requests are governed by
    /// `policy`'s live value.
    ///
    /// A later [`Self::set_registry_policy`] call rebuilds the workspace transport (and its
    /// cache-key namespace) in place, so every caller holding this `HttpCache` sees the new
    /// policy take effect immediately, with no need to reconstruct the cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::HttpCache;
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use std::sync::Arc;
    ///
    /// let policy = Arc::new(RegistryAccessPolicy::default());
    /// let cache = HttpCache::with_policy(Arc::clone(&policy));
    /// assert!(cache.is_empty());
    /// ```
    pub fn with_policy(policy: Arc<RegistryAccessPolicy>) -> Self {
        let workspace = Transport::workspace(&policy);
        Self {
            entries: DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            baseline: Transport::baseline(),
            trusted_clients: DashMap::new(),
            policy,
            workspace: RwLock::new(workspace),
            #[cfg(test)]
            workspace_rebuilds: AtomicUsize::new(0),
            offline: AtomicBool::new(false),
            cache_enabled: AtomicBool::new(true),
        }
    }

    /// Sets whether outbound network requests are permitted (issue #483).
    ///
    /// Enforced by `Self::ensure_online` (private) at every one of this module's 4 send sites —
    /// effective for every call after this returns. While `mode` is [`NetworkMode::Offline`],
    /// this also overrides `cache_enabled` (see [`Self::set_cache_enabled`]) to behave as
    /// [`CacheMode::Enabled`] on both the read and write path in `get_cached_via`:
    /// without this, a warm entry fetched before going offline could never have been stored in
    /// the first place if caching was disabled, leaving the offline warm-cache path with
    /// nothing to serve — the exact combination `cache.enabled: false` + `network.offline: true`
    /// is meant to survive.
    pub fn set_offline(&self, mode: NetworkMode) {
        self.offline
            .store(mode == NetworkMode::Offline, Ordering::Relaxed);
    }

    /// Returns whether outbound network requests are currently blocked.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.offline.load(Ordering::Relaxed)
    }

    /// Sets whether the entry-map cache is used (issue #482). See [`Self::set_offline`]'s
    /// docs for the override `offline` has on this flag while set.
    pub fn set_cache_enabled(&self, mode: CacheMode) {
        self.cache_enabled
            .store(mode == CacheMode::Enabled, Ordering::Relaxed);
    }

    /// Returns `Err(DepsError::Offline)` when `network.offline` is set, without making any
    /// request — the last check before a socket opens at each of this module's 4 send
    /// sites, placed beside the existing [`ensure_https`] call at each.
    fn ensure_online(&self, url: &str) -> Result<()> {
        if self.is_offline() {
            return Err(DepsError::Offline {
                url: RedactedUrl::new(url),
            });
        }
        Ok(())
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;

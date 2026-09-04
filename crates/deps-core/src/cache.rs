use crate::error::{DepsError, Result};
use crate::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::Serialize;
use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
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
/// be allowed to bypass the HTTPS requirement, even under `cfg(test)`/`test-util`. See
/// [`crate::net_policy::validate_index_url`]'s own private loopback check for the
/// counterpart used on parsed `url::Url` values — kept separate rather than merged, since
/// this one takes a raw `&str` on `ensure_https`'s hot path and has looser (any-scheme)
/// semantics.
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
    /// see [`HttpCache::get_cached_pinned_with_headers`]'s separate `auth_id` argument, folded
    /// into the cache key only). `authenticated` distinguishes an authenticated fetch (#561)
    /// from #562's unauthenticated workspace-declared one for cache-eviction purposes
    /// ([`CacheTier::is_authenticated`]) without affecting pooling — the shipped
    /// [`Transport::origin_pinned`] (public path) stays on [`CacheTier::Baseline`], unaffected.
    Pinned {
        digest: u64,
        authenticated: bool,
    },
}

impl CacheTier {
    /// Whether a 401/403 revalidation response on an entry under this tier should evict the
    /// entry rather than serve the default stale-while-revalidate fallback (FR-015/NFR-004).
    fn is_authenticated(self) -> bool {
        matches!(
            self,
            Self::Pinned {
                authenticated: true,
                ..
            }
        )
    }
}

/// The tier a [`Transport`]'s redirect policy and DNS resolver both enforce.
///
/// `WorkspaceDeclared` holds a [`WorkspaceRegistryAccess`] **value snapshot**, taken once at
/// [`Transport::workspace`] construction time — not a live `Arc<RegistryAccessPolicy>` read on
/// every [`Self::tier_allows`] call. [`Transport::workspace`] takes this same snapshot for its
/// paired [`CacheTier::WorkspaceDeclared`], and [`HttpCache::set_registry_policy`] rebuilds the
/// whole `Transport` (both snapshots included) on every actual policy transition, so a
/// request's cache key and its guard always come from one consistent construction-time value,
/// with no read-skew window between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrGuard {
    Baseline,
    WorkspaceDeclared(WorkspaceRegistryAccess),
}

impl AddrGuard {
    /// Whether a host classified as `class` may be reached under this guard's tier.
    fn tier_allows(self, class: crate::net_policy::HostClass) -> bool {
        match self {
            Self::Baseline => true,
            Self::WorkspaceDeclared(policy) => policy.allows(class),
        }
    }
}

/// Redirect policy for a [`Transport`]'s client, parameterized by the [`AddrGuard`] tier that
/// client enforces.
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
/// The blocked-host check (`hop_targets_blocked_host`) is unconditional and
/// policy-independent — it does not consult `guard` at all, since
/// [`HostClass::never_a_registry`](crate::net_policy::HostClass::never_a_registry)
/// is deliberately narrower than any workspace-registry policy setting: it blocks only the
/// classes (loopback, link-local, cloud metadata, unspecified) that are never a legitimate
/// registry redirect target for *any* ecosystem, benefiting every one of the eleven crates
/// sharing the baseline client, not only Cargo's workspace-declared indexes.
///
/// `guard`'s own [`AddrGuard::tier_allows`] term additionally rejects a hop whose target class
/// the *tier* does not allow — under [`AddrGuard::Baseline`] this term is constant `false`, so
/// every non-Cargo ecosystem (and Cargo's own `$CARGO_HOME`-provenance traffic) is
/// bit-for-bit unaffected; under [`AddrGuard::WorkspaceDeclared`] it closes the redirect-hop
/// half of issue #455 (an IP-literal hop to an RFC1918/CGNAT address, which `hyper-util`
/// parses directly and never routes through a resolver).
///
/// This only classifies the redirect target's URL string, not its DNS-resolved address — that
/// residual gap (issue #449, "D1" in PR #447's plan) is closed for the name-hop case by
/// [`BlockedAddrResolver`], which [`build_guarded_client`] wires into every client this module
/// builds: a redirect hop reuses the same `Client`, so its target's resolved address is
/// validated too, for free (FR-007).
///
/// Every other redirect — including cross-host ones, which are out of scope for this
/// policy — falls through to reqwest's default (`Policy::limited(10)`), preserving the
/// existing hop-count limit and mockito's plain-`http://` loopback chains
/// used throughout this module's tests.
fn redirect_policy(guard: AddrGuard) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let downgraded = attempt
            .previous()
            .last()
            .is_some_and(|previous| is_https_downgrade(previous, attempt.url()));
        if downgraded
            || hop_targets_blocked_host(attempt.url())
            || !guard.tier_allows(crate::net_policy::classify_host(attempt.url()))
        {
            attempt.stop()
        } else {
            reqwest::redirect::Policy::default().redirect(attempt)
        }
    })
}

/// Redirect policy for a [`HttpCache::transport_for_origin`]-scoped client.
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
/// keep the probe alive (FR-003). `guard`'s tier additionally rejects a resolved address whose
/// class the *tier* does not allow (issue #455: an RFC1918/CGNAT-range name rebound at
/// connect time), on top of the policy-independent [`HostClass::never_a_registry`](crate::net_policy::HostClass::never_a_registry)
/// check every tier enforces.
fn validate_resolved_addrs(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
    guard: AddrGuard,
) -> std::result::Result<Vec<std::net::SocketAddr>, ResolveGuardError> {
    if addrs.is_empty() {
        tracing::warn!(host, "DNS resolution returned no addresses");
        return Err(ResolveGuardError::NoAddresses {
            host: host.to_string(),
        });
    }
    for addr in &addrs {
        let class = crate::net_policy::classify_addr(addr.ip());
        if class.never_a_registry() || !guard.tier_allows(class) {
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

/// The synthetic-lookup function signature [`TestLookup`] wraps.
#[cfg(test)]
type SyntheticLookupFn = dyn Fn(&str) -> Vec<std::net::SocketAddr> + Send + Sync;

/// Test-only override for [`BlockedAddrResolver::resolve`], replacing `tokio::net::lookup_host`
/// with a synthetic lookup — lets a test exercise the resolver-guard wiring against an address
/// chosen by the test (e.g. an RFC1918 literal) without depending on real DNS. A newtype rather
/// than a hand-written `Debug` directly on [`BlockedAddrResolver`], so that struct's own
/// `#[derive(Debug)]` stays valid under both `cfg(test)` and not.
#[cfg(test)]
#[derive(Clone)]
struct TestLookup(Arc<SyntheticLookupFn>);

#[cfg(test)]
impl std::fmt::Debug for TestLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestLookup(..)")
    }
}

/// Connect-time DNS resolver that closes the rebinding TOCTOU gap left by [`ensure_https`]/
/// [`hop_targets_blocked_host`]'s URL-string-only classification (issue #449): those check the
/// declared hostname, but `reqwest`'s connector resolves DNS independently, later, and an
/// attacker who controls the hostname's DNS can rebind it to a blocked address in between.
///
/// Wired into every client [`build_guarded_client`] returns, so all 11 ecosystem crates sharing
/// the baseline client pool inherit it with zero per-crate plumbing (FR-006/NFR-002).
///
/// # Scope
///
/// This resolver's guard tier decides how much a resolved address is scrutinized: under
/// [`AddrGuard::Baseline`] this enforces only the policy-independent
/// [`crate::net_policy::HostClass::never_a_registry`] tier (loopback, link-local,
/// cloud-metadata, unspecified), the same tier [`hop_targets_blocked_host`] already applies —
/// closing issue #449's filed exploit (cloud-metadata rebinding) but not full `PublicOnly`
/// semantics. Under [`AddrGuard::WorkspaceDeclared`], [`validate_resolved_addrs`] additionally
/// rejects any resolved address outside the snapshotted [`crate::net_policy::WorkspaceRegistryAccess`]
/// policy's allowed classes — closing issue #455 (a workspace-declared name that legitimately
/// resolves to `HostClass::Global` at parse time, then rebinds to an RFC1918/CGNAT address at
/// connect time).
///
/// # Fail-closed (NFR-004)
///
/// Returns `Err` — never `Ok`, never a fallback resolver — on a `lookup_host` error, zero
/// addresses, or any resolved address [`validate_resolved_addrs`] rejects for `self.guard`'s
/// tier.
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
///   [`hop_targets_blocked_host`]/[`redirect_policy`]'s tier term) remains the sole guard for
///   literals — a disjoint domain from this resolver's name-based one, not a gap. This is also
///   why the cache layer gives [`HttpCache::get_cached_workspace`] zero protection against an
///   *initial* request URL that is itself an IP literal — see that method's docs.
/// - Unlike [`ensure_https`]/[`hop_targets_blocked_host`], this resolver has **no** `test-util`
///   carve-out for `Loopback`: it blocks a `localhost`/`127.0.0.1` *name* unconditionally, in
///   every build. A downstream `test-util` consumer that mocks by binding an IP literal (as
///   this workspace's own `mockito` usage does) is unaffected — literals never reach this
///   resolver at all — but one that mocks via a `localhost` *name* would be newly blocked.
#[derive(Debug, Clone)]
struct BlockedAddrResolver {
    guard: AddrGuard,
    #[cfg(test)]
    lookup: Option<TestLookup>,
}

impl BlockedAddrResolver {
    fn new(guard: AddrGuard) -> Self {
        Self {
            guard,
            #[cfg(test)]
            lookup: None,
        }
    }

    #[cfg(test)]
    fn with_lookup(guard: AddrGuard, lookup: TestLookup) -> Self {
        Self {
            guard,
            lookup: Some(lookup),
        }
    }
}

impl reqwest::dns::Resolve for BlockedAddrResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let guard = self.guard;
        #[cfg(test)]
        let lookup = self.lookup.clone();
        Box::pin(async move {
            #[cfg(test)]
            let addrs: Vec<std::net::SocketAddr> = match &lookup {
                Some(lookup) => (lookup.0)(&host),
                None => tokio::net::lookup_host((host.as_str(), 0)).await?.collect(),
            };
            #[cfg(not(test))]
            let addrs: Vec<std::net::SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();

            let addrs = validate_resolved_addrs(&host, addrs, guard)?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Builds a client with `HttpCache`'s shared configuration (user agent, timeout), varying the
/// redirect policy and resolver — kept in one place so a future client-wide setting (proxy,
/// connection pool sizing, etc.) can't silently miss any [`Transport`] this module builds. This
/// is also the workspace's only `Client::builder()` call site.
fn build_client_inner(
    redirect: reqwest::redirect::Policy,
    resolver: BlockedAddrResolver,
) -> Client {
    Client::builder()
        .user_agent(format!("deps-lsp/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(redirect)
        .dns_resolver(resolver)
        .build()
        .expect("failed to create HTTP client")
}

/// Pairs one [`AddrGuard`] value with both halves it governs — its redirect policy and its
/// resolver — so a client whose redirect policy and resolver enforce different tiers cannot be
/// built by this function.
fn build_guarded_client(guard: AddrGuard) -> Client {
    build_client_inner(redirect_policy(guard), BlockedAddrResolver::new(guard))
}

/// Test-only variant of [`build_guarded_client`] that substitutes a synthetic DNS lookup for
/// `tokio::net::lookup_host` — shares [`build_client_inner`] with the production constructor, so
/// deleting the `.dns_resolver(...)` wiring from that shared function fails any test built on
/// this too, not just the production path.
#[cfg(test)]
fn build_guarded_client_with_lookup(guard: AddrGuard, lookup: TestLookup) -> Client {
    build_client_inner(
        redirect_policy(guard),
        BlockedAddrResolver::with_lookup(guard, lookup),
    )
}

/// A `Client` welded to the [`CacheTier`] its guard enforces.
///
/// [`Self::baseline`], [`Self::workspace`] and [`Self::origin_pinned`] are the only sanctioned
/// way to build one: each derives its redirect policy, its resolver and its tier from a single
/// [`AddrGuard`] value, so a mismatched pairing (e.g. a baseline-guarded client keyed under the
/// workspace cache namespace) never arises through normal construction — though `cache.rs` is
/// one module, so a hand-written `Transport { .. }` literal elsewhere in this file could still
/// mismatch them; the three constructors are what make that a deliberate act, not an accident
/// reachable by passing the wrong argument to an existing function.
#[derive(Clone)]
struct Transport {
    client: Client,
    tier: CacheTier,
}

impl Transport {
    /// The shared, unauthenticated transport used by every non-workspace request.
    fn baseline() -> Self {
        Self {
            client: build_guarded_client(AddrGuard::Baseline),
            tier: CacheTier::Baseline,
        }
    }

    /// The transport for Cargo's workspace-declared-registry requests, snapshotting `policy`'s
    /// current value once and sharing that single snapshot between the guard and the cache-key
    /// tier — see [`AddrGuard::WorkspaceDeclared`]'s docs for why this is a value snapshot, not
    /// a live `Arc` read, and why the guard and the tier must never snapshot independently.
    fn workspace(policy: &Arc<RegistryAccessPolicy>) -> Self {
        let snapshot = policy.get();
        Self {
            client: build_guarded_client(AddrGuard::WorkspaceDeclared(snapshot)),
            tier: CacheTier::WorkspaceDeclared(snapshot),
        }
    }

    /// The transport for one [`HttpCache::transport_for_origin`]-pinned origin: a plain
    /// [`AddrGuard::Baseline`] resolver, paired with [`trusted_origin_redirect_policy`] instead
    /// of [`redirect_policy`] — that policy pins by URL prefix, which already subsumes the
    /// blocked-host hop check, so this is the one documented caller of [`build_client_inner`]
    /// directly rather than [`build_guarded_client`].
    fn origin_pinned(trusted_origin: &str) -> Self {
        Self {
            client: build_client_inner(
                trusted_origin_redirect_policy(trusted_origin.to_string()),
                BlockedAddrResolver::new(AddrGuard::Baseline),
            ),
            tier: CacheTier::Baseline,
        }
    }

    /// The transport for one origin-pinned **workspace-declared** host (issue #561/#562),
    /// optionally carrying a credential. Pairs [`trusted_origin_redirect_policy`] (send-scope
    /// confinement — no redirect hop may leave `trusted_origin`) with
    /// [`AddrGuard::WorkspaceDeclared`] (the connect-address policy guard, #455-class
    /// protection) and the namespaced [`CacheTier::Pinned`] tier. One constructor serves both
    /// #562's unauthenticated workspace-declared fetches (`authenticated: false`) and #561's
    /// authenticated ones (`authenticated: true`) — `authenticated` only affects
    /// [`HttpCache`]'s revalidation-eviction rule (FR-015), never `AddrGuard`/redirect
    /// confinement. The shipped [`Self::origin_pinned`] (public `api.nuget.org` path) is
    /// unaffected — this is a distinct constructor, not a modification of that one.
    fn origin_pinned_guarded(
        trusted_origin: &str,
        policy: &Arc<RegistryAccessPolicy>,
        authenticated: bool,
    ) -> Self {
        let snapshot = policy.get();
        Self {
            client: build_client_inner(
                trusted_origin_redirect_policy(trusted_origin.to_string()),
                BlockedAddrResolver::new(AddrGuard::WorkspaceDeclared(snapshot)),
            ),
            tier: CacheTier::Pinned {
                digest: pinned_digest(trusted_origin, snapshot),
                authenticated,
            },
        }
    }
}

/// Identifies a `(trusted_origin, policy_snapshot)` pair for [`CacheTier::Pinned`] — **never**
/// a credential identity (see that variant's docs). Not cryptographically salted: unlike a
/// caller's own credential-header digest (e.g. `deps_nuget`'s salted `auth_id`), this value is
/// not attacker-observable secret material, only a pool/cache-key discriminant.
fn pinned_digest(trusted_origin: &str, snapshot: WorkspaceRegistryAccess) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    trusted_origin.hash(&mut hasher);
    snapshot.hash(&mut hasher);
    hasher.finish()
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
    trusted_clients: DashMap<(String, CacheTier), Transport>,
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
    /// entirely (see `get_cached_with_headers_via`). Overridden to effectively `true`
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
    /// effective for every call after this returns. While `value` is `true`, this also
    /// overrides `cache_enabled` (see [`Self::set_cache_enabled`]) to behave as `true` on
    /// both the read and write path in `get_cached_with_headers_via`: without this, a
    /// warm entry fetched before going offline could never have been stored in the first
    /// place if caching was disabled, leaving the offline warm-cache path with nothing to
    /// serve — the exact combination `cache.enabled: false` + `network.offline: true` is
    /// meant to survive.
    pub fn set_offline(&self, value: bool) {
        self.offline.store(value, Ordering::Relaxed);
    }

    /// Returns whether outbound network requests are currently blocked.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.offline.load(Ordering::Relaxed)
    }

    /// Sets whether the entry-map cache is used (issue #482). See [`Self::set_offline`]'s
    /// docs for the override `offline` has on this flag while set.
    pub fn set_cache_enabled(&self, value: bool) {
        self.cache_enabled.store(value, Ordering::Relaxed);
    }

    /// Returns `Err(DepsError::Offline)` when `network.offline` is set, without making any
    /// request — the last check before a socket opens at each of this module's 4 send
    /// sites, placed beside the existing [`ensure_https`] call at each.
    fn ensure_online(&self, url: &str) -> Result<()> {
        if self.is_offline() {
            return Err(DepsError::Offline {
                url: url.to_string(),
            });
        }
        Ok(())
    }

    /// Returns the transport scoped to `trusted_origin`, building and pooling one on first use.
    ///
    /// The `get` fast path (a shared read lock) serves the common case — a `trusted_origin`
    /// already pooled — without ever taking `trusted_clients`' write-capable `entry` lock;
    /// `entry().or_insert_with()` only runs on a miss, so two callers racing on the same new
    /// origin still only ever build and store one [`Transport`] for it, not one each.
    fn transport_for_origin(&self, trusted_origin: &str) -> Transport {
        let key = (trusted_origin.to_string(), CacheTier::Baseline);
        if let Some(existing) = self.trusted_clients.get(&key) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(key)
            .or_insert_with(|| Transport::origin_pinned(trusted_origin))
            .clone()
    }

    /// Like [`Self::transport_for_origin`], but for an origin-pinned, connect-address-guarded
    /// [`CacheTier::Pinned`] transport (issue #561/#562) — building and pooling one on first
    /// use, keyed by `(trusted_origin, CacheTier::Pinned { .. })` so an authenticated and
    /// unauthenticated transport for the same origin are pooled separately.
    fn transport_for_pinned(&self, trusted_origin: &str, authenticated: bool) -> Transport {
        let digest = pinned_digest(trusted_origin, self.policy.get());
        let key = (
            trusted_origin.to_string(),
            CacheTier::Pinned {
                digest,
                authenticated,
            },
        );
        if let Some(existing) = self.trusted_clients.get(&key) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(key)
            .or_insert_with(|| {
                Transport::origin_pinned_guarded(trusted_origin, &self.policy, authenticated)
            })
            .clone()
    }

    /// The prefix marking a workspace-tier cache key, chosen as a control character that can
    /// never appear at the start of a URL string this module writes: production code paths
    /// only ever write keys derived from this function, which are either the bare URL (starting
    /// `https://`, or — test cfgs only — `http://` on loopback) or this prefix followed by a
    /// policy digit. No in-process caller other than [`Self::insert_for_bench`] (a
    /// `#[doc(hidden)]` test/bench helper that accepts a caller-chosen key) can write an
    /// arbitrary key, so a `Baseline`-tier and `WorkspaceDeclared`-tier entry can never collide
    /// in production use.
    const WS_KEY_PREFIX: char = '\u{1}';

    /// The prefix marking a [`CacheTier::Pinned`]-tier cache key (issue #561/#562) — distinct
    /// from [`Self::WS_KEY_PREFIX`] so the two namespaces can never collide, chosen as another
    /// control character no URL string this module writes can start with.
    const PINNED_KEY_PREFIX: char = '\u{2}';

    /// Computes the cache-map key for `url` under `tier` — `Cow::Borrowed(url)` for
    /// [`CacheTier::Baseline`] (allocation-free, and identical to every entry this cache wrote
    /// before this policy-tier split existed), or a policy-digit-prefixed owned key for
    /// [`CacheTier::WorkspaceDeclared`] so a policy tightening can never serve a body fetched
    /// under a looser policy (C5): the digit comes from `tier`'s own snapshot — the exact same
    /// value the paired [`Transport`]'s [`AddrGuard`] enforced for this request, taken together
    /// at [`Transport::workspace`] construction time — never a separate live `self.policy` read,
    /// which would open a read-skew window between the guard that let a fetch through and the
    /// key that fetch's body gets stored under. `self.policy` remains this cache's live handle
    /// for [`Self::set_registry_policy`]'s change detection and the write-through source that
    /// method snapshots from when rebuilding the workspace transport — never consulted here.
    ///
    /// Callers must compute this once per request and thread the result through, never
    /// recompute mid-request — a policy flip between two recomputations would read and write
    /// under different keys for what should be one atomic operation.
    ///
    /// `auth_id` (FR-014) is folded in only for [`CacheTier::Pinned`] — a separate credential
    /// identity from `digest` (see that variant's docs), so a rotated or distinct credential
    /// against the same origin never reads back a body fetched under a different one. `None`
    /// serializes as 16 zero hex digits, matching an unauthenticated `#562` fetch.
    fn cache_key<'a>(&self, url: &'a str, tier: CacheTier, auth_id: Option<u64>) -> Cow<'a, str> {
        match tier {
            CacheTier::Baseline => Cow::Borrowed(url),
            CacheTier::WorkspaceDeclared(snapshot) => {
                Cow::Owned(format!("{}{}{url}", Self::WS_KEY_PREFIX, snapshot.to_u8()))
            }
            CacheTier::Pinned { digest, .. } => Cow::Owned(format!(
                "{}{digest:016x}{:016x}{url}",
                Self::PINNED_KEY_PREFIX,
                auth_id.unwrap_or(0)
            )),
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
    ///
    /// Reads the baseline (unprefixed) cache-key namespace only (see `Self::cache_key`, private) — a
    /// body fetched via [`Self::get_cached_workspace`] is never visible through this method.
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
        self.get_cached_with_headers_via(url, extra_headers, &self.baseline, None)
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
        let transport = self.transport_for_origin(trusted_origin);
        self.get_cached_with_headers_via(url, &[], &transport, None)
            .await
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
    /// host. Composing `Self::transport_for_origin`'s (private) pinned-origin transport with header
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
        let transport = self.transport_for_origin(trusted_origin);
        self.get_cached_with_headers_via(url, extra_headers, &transport, None)
            .await
    }

    /// Like [`Self::get_cached_trusted_origin_with_headers`], but for an origin-pinned,
    /// connect-address-guarded `CacheTier::Pinned` transport (issue #561/#562) instead of the
    /// baseline-guarded [`Self::get_cached_trusted_origin`] one — the only sanctioned way to
    /// send a credential to a workspace-declared host. Delegates to
    /// [`Self::get_cached_pinned_with_headers`] with no extra headers.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_pinned(
        &self,
        url: &str,
        trusted_origin: &str,
        authenticated: bool,
        auth_id: Option<u64>,
    ) -> Result<Bytes> {
        self.get_cached_pinned_with_headers(url, trusted_origin, authenticated, auth_id, &[])
            .await
    }

    /// Like [`Self::get_cached_pinned`], but additionally injects `extra_headers` (e.g. an
    /// `Authorization` header carrying a credential) into every request — composed with the
    /// same origin-pinned, connect-address-guarded transport [`Self::get_cached_pinned`] uses,
    /// so a credential header can never survive a cross-origin redirect hop, exactly like
    /// [`Self::get_cached_trusted_origin_with_headers`]'s identical closure argument for the
    /// baseline-guarded tier.
    ///
    /// `auth_id` (FR-014) — a caller-computed, salted digest of the credential actually being
    /// attached (`None` for an unauthenticated #562 fetch) — is folded into the cache key only,
    /// never into `CacheTier`/the transport-pool key, so a rotated or distinct credential
    /// against the same origin never reads back a body fetched under a different one.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_pinned_with_headers(
        &self,
        url: &str,
        trusted_origin: &str,
        authenticated: bool,
        auth_id: Option<u64>,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        let transport = self.transport_for_pinned(trusted_origin, authenticated);
        self.get_cached_with_headers_via(url, extra_headers, &transport, auth_id)
            .await
    }

    /// Like [`Self::get_cached`], but for Cargo's workspace-declared-registry requests: routes
    /// through the workspace transport field, whose guard enforces the live
    /// [`crate::net_policy::WorkspaceRegistryAccess`] policy on both the resolved connect-time
    /// address (issue #455) and any redirect hop, and keys the entry under a
    /// policy-scoped namespace (see `Self::cache_key`, private) distinct from every other method on
    /// this cache.
    ///
    /// This gives the *resolved address* the same policy scrutiny `deps_cargo::config::RegistryIndex::new`
    /// already gives the declared URL string at parse time — it does **not**
    /// re-check the initial request URL itself: a caller passing an IP-literal `url` whose
    /// class the policy would reject connects anyway, since `hyper-util`'s connector parses an
    /// IP literal directly and never calls the configured resolver (see
    /// `BlockedAddrResolver`'s docs, private). `RegistryIndex::new` is the sole, by-design gate for
    /// that residual — every caller of this method already went through it.
    ///
    /// If an entry is already cached, a revalidation failure — including a guard rejection
    /// from a since-rebound or since-tightened-policy address — falls back to serving the
    /// cached body, logging only a `tracing::warn!` (pre-existing behavior, unrelated to
    /// this method). This is not a bypass — no new connection to the blocked address is
    /// made — but it means such a block is invisible to the caller whenever an entry already
    /// exists for that URL.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::HttpCache;
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let policy = Arc::new(RegistryAccessPolicy::default());
    /// let cache = HttpCache::with_policy(policy);
    /// let data = cache
    ///     .get_cached_workspace("https://index.mycorp.dev/se/rd/serde")
    ///     .await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached_workspace(&self, url: &str) -> Result<Bytes> {
        self.get_cached_workspace_with_headers(url, &[]).await
    }

    /// Like [`Self::get_cached_workspace`], but additionally forwards `extra_headers` to the
    /// underlying request — the headered form needed by a registry client whose
    /// workspace-declared fetch requires a non-default header (e.g. `deps-npm`'s abbreviated-
    /// packument `Accept` header for an alternate npm registry).
    ///
    /// # Security
    ///
    /// `extra_headers` are attached to the **initial** request only. The workspace transport
    /// pins by [`crate::net_policy::HostClass`], not origin — unlike
    /// [`Self::get_cached_trusted_origin_with_headers`], which exists precisely to close this
    /// gap for a caller that needs it — so a cross-origin redirect hop to any other
    /// policy-permitted host is followed with `extra_headers` re-sent by reqwest's default
    /// redirect policy. **This method must never carry a credential.** Harmless for its
    /// current sole caller (a fixed `Accept` header), but directly load-bearing for any
    /// future auth-wiring work: reach for [`Self::get_cached_trusted_origin_with_headers`]
    /// instead if a header ever needs to stay pinned to one origin.
    pub async fn get_cached_workspace_with_headers(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
    ) -> Result<Bytes> {
        let transport = self
            .workspace
            .read()
            .expect("workspace transport lock poisoned")
            .clone();
        self.get_cached_with_headers_via(url, extra_headers, &transport, None)
            .await
    }

    /// Updates the policy governing [`Self::get_cached_workspace`], rebuilding the workspace
    /// transport field (and so its cache-key namespace and guard together) when
    /// `value` actually differs from the current setting — a no-op call does not rebuild, so a
    /// caller that re-applies an unchanged configuration does not pay for a fresh `Client` and
    /// its connection pool.
    ///
    /// Effective for every [`Self::get_cached_workspace`] call after this returns. Note this
    /// only gates *future* fetches: an `All -> PublicOnly`/`Off` tightening does not purge
    /// already-registered `deps-cargo` alternate-registry clients resolved under the looser
    /// policy (pre-existing, documented on [`crate::net_policy::RegistryAccessPolicy::set`]).
    ///
    /// Unlike that pre-existing gap, every `CacheTier::Pinned` cache entry (issue #561/#562)
    /// **is** purged on every actual policy transition, along with every pinned-tier pooled
    /// `Transport` — substantially narrowing the `All -> PublicOnly -> All` round-trip hole for
    /// credential-carrying entries specifically (NFR-004): re-namespacing alone (as the
    /// pre-existing workspace-tier digit prefix does) would leave an old-era authenticated
    /// body reachable once the policy round-trips back to a value whose digest happens to
    /// collide again. Not an absolute close: a fetch already in flight when the transition
    /// happens can still land its response and re-insert an old-era key after the purge —
    /// harmless (readable only under the era it was legitimately fetched in), just not
    /// prevented by this purge alone.
    pub fn set_registry_policy(&self, value: WorkspaceRegistryAccess) {
        if self.policy.get() == value {
            return;
        }
        self.policy.set(value);
        let rebuilt = Transport::workspace(&self.policy);
        *self
            .workspace
            .write()
            .expect("workspace transport lock poisoned") = rebuilt;
        #[cfg(test)]
        self.workspace_rebuilds.fetch_add(1, Ordering::Relaxed);

        let mut freed_bytes = 0usize;
        self.entries.retain(|k, v| {
            let keep = !k.starts_with(Self::PINNED_KEY_PREFIX);
            if !keep {
                freed_bytes += v.body.len();
            }
            keep
        });
        self.total_bytes.fetch_sub(freed_bytes, Ordering::Relaxed);
        self.trusted_clients
            .retain(|(_, tier), _| !matches!(tier, CacheTier::Pinned { .. }));
    }

    /// `auth_id` (FR-014) is meaningful only under [`CacheTier::Pinned`] — every other tier
    /// ignores it (see [`Self::cache_key`]'s docs).
    async fn get_cached_with_headers_via(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        transport: &Transport,
        auth_id: Option<u64>,
    ) -> Result<Bytes> {
        if self.entries.len() >= MAX_CACHE_ENTRIES
            || self.total_bytes.load(Ordering::Relaxed) >= MAX_CACHE_BYTES
        {
            self.evict_entries();
        }

        let offline = self.is_offline();
        // `offline` forces `cache_enabled` true on both the read and write path below (S1
        // fix): `cache.enabled: false` otherwise means "never store", which would leave the
        // offline early-return below with nothing to serve for a URL that was only ever
        // fetched while caching was disabled. See `Self::set_offline`'s docs.
        let cache_enabled = self.cache_enabled.load(Ordering::Relaxed) || offline;

        // Computed once and threaded through every downstream call — never recomputed, or a
        // policy flip mid-request would read and write under different keys (see
        // `Self::cache_key`'s docs).
        let cache_key = self.cache_key(url, transport.tier, auth_id);

        if !cache_enabled {
            return self
                .transport_only_via(url, extra_headers, BodyLimit::DEFAULT, &transport.client)
                .await;
        }

        // Clone and drop the DashMap Ref immediately to release the shard lock.
        // Holding a Ref across .await causes deadlocks when concurrent tasks
        // need write access to the same shard (e.g., conditional_request_with_headers → insert).
        if let Some(cached) = self.entries.get(cache_key.as_ref()).map(|r| r.clone()) {
            if offline {
                // Skip the conditional-request attempt entirely: `ensure_online` inside
                // `conditional_request_with_headers` would block it anyway and fall back to
                // this same cached body via the `Err` arm below, but only after a spurious
                // `tracing::warn!` and a wasted request-builder allocation on every offline
                // hover. Behavior is identical either way — this is purely to avoid that.
                return Ok(cached.body);
            }
            match self
                .conditional_request_with_headers(
                    url,
                    &cached,
                    extra_headers,
                    &transport.client,
                    &cache_key,
                )
                .await
            {
                Ok(Some(new_body)) => return Ok(new_body),
                Ok(None) => return Ok(cached.body),
                Err(e) => {
                    // FR-015/NFR-004: a 401/403 revalidation against an *authenticated*
                    // pinned-tier entry must evict rather than serve the possibly-revoked
                    // credential's last-known-good body — every other tier keeps today's
                    // stale-while-revalidate fallback unchanged.
                    if transport.tier.is_authenticated()
                        && matches!(
                            &e,
                            DepsError::HttpStatus {
                                status: 401 | 403,
                                ..
                            }
                        )
                    {
                        if let Some((_, old)) = self.entries.remove(cache_key.as_ref()) {
                            self.total_bytes
                                .fetch_sub(old.body.len(), Ordering::Relaxed);
                        }
                        tracing::warn!(
                            %e,
                            "evicting authenticated cache entry after revalidation failure"
                        );
                        return Err(e);
                    }
                    tracing::warn!("conditional request failed, using cache: {e}");
                    return Ok(cached.body);
                }
            }
        }

        self.fetch_and_store_with_headers(url, extra_headers, &transport.client, &cache_key)
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
        cache_key: &str,
    ) -> Result<Option<Bytes>> {
        self.ensure_online(url)?;
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
            cache_key.to_string(),
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
        cache_key: &str,
    ) -> Result<Bytes> {
        self.ensure_online(url)?;
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
            cache_key.to_string(),
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
        self.ensure_online(url)?;
        ensure_https(url)?;

        let response = self
            .baseline
            .client
            .post(url)
            .json(body)
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
        self.transport_only_via(url, extra_headers, limit, &self.baseline.client)
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
        let transport = self.transport_for_origin(trusted_origin);
        self.transport_only_via(url, extra_headers, limit, &transport.client)
            .await
    }

    /// Note: "transport" here means "bypasses the entry-map cache" (see this method's
    /// callers' docs) — a different axis from the [`Transport`] type, which pairs a `Client`
    /// with its [`CacheTier`]. The name predates that type and is kept as-is to avoid
    /// churning every `get_transport_only*` call site for a naming collision that causes no
    /// actual ambiguity at the call sites themselves.
    async fn transport_only_via(
        &self,
        url: &str,
        extra_headers: &[(header::HeaderName, &str)],
        limit: BodyLimit,
        client: &Client,
    ) -> Result<Bytes> {
        self.ensure_online(url)?;
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
            validate_resolved_addrs("evil.example", addrs, AddrGuard::Baseline),
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
            validate_resolved_addrs("evil.example", addrs, AddrGuard::Baseline),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    #[test]
    fn test_validate_resolved_addrs_allows_global() {
        let addrs = vec!["1.1.1.1:0".parse().unwrap()];
        assert_eq!(
            validate_resolved_addrs("index.crates.io", addrs.clone(), AddrGuard::Baseline).unwrap(),
            addrs
        );
    }

    // NFR-004: fail-closed on an empty resolution rather than silently treating "nothing
    // resolved" as "nothing to block".
    #[test]
    fn test_validate_resolved_addrs_fails_closed_on_empty() {
        assert!(matches!(
            validate_resolved_addrs("evil.example", vec![], AddrGuard::Baseline),
            Err(ResolveGuardError::NoAddresses { .. })
        ));
    }

    #[test]
    fn test_validate_resolved_addrs_unwraps_mapped_v4() {
        let addrs = vec!["[::ffff:169.254.169.254]:0".parse().unwrap()];
        assert!(matches!(
            validate_resolved_addrs("evil.example", addrs, AddrGuard::Baseline),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    // Issue #455, test-plan item 1: under `Baseline`, an RFC1918/CGNAT/unique-local address is
    // allowed (today's pre-#455 behavior) — only `never_a_registry` classes are blocked.
    #[test]
    fn test_validate_resolved_addrs_baseline_allows_private_ranges() {
        for addr_str in ["10.0.0.1:0", "100.64.0.1:0", "[fc00::1]:0"] {
            let addrs = vec![addr_str.parse().unwrap()];
            assert!(
                validate_resolved_addrs("corp.example", addrs, AddrGuard::Baseline).is_ok(),
                "{addr_str} must be allowed under Baseline"
            );
        }
    }

    // Issue #455, test-plan item 1: under `WorkspaceDeclared(PublicOnly)`, every RFC1918/CGNAT/
    // unique-local address is blocked, while a `Global` address is still allowed.
    #[test]
    fn test_validate_resolved_addrs_workspace_public_only_blocks_private_ranges() {
        let guard = AddrGuard::WorkspaceDeclared(WorkspaceRegistryAccess::PublicOnly);
        for addr_str in ["10.0.0.1:0", "100.64.0.1:0", "[fc00::1]:0"] {
            let addrs = vec![addr_str.parse().unwrap()];
            assert!(
                matches!(
                    validate_resolved_addrs("evil.example", addrs, guard),
                    Err(ResolveGuardError::Blocked { .. })
                ),
                "{addr_str} must be blocked under WorkspaceDeclared(PublicOnly)"
            );
        }

        let global = vec!["1.1.1.1:0".parse().unwrap()];
        assert!(validate_resolved_addrs("index.crates.io", global, guard).is_ok());
    }

    // Test-plan item 2: `WorkspaceDeclared(All)` admits a private-range address.
    #[test]
    fn test_validate_resolved_addrs_workspace_all_allows_private_ranges() {
        let guard = AddrGuard::WorkspaceDeclared(WorkspaceRegistryAccess::All);
        let addrs = vec!["10.0.0.1:0".parse().unwrap()];
        assert!(validate_resolved_addrs("corp.example", addrs, guard).is_ok());
    }

    // Test-plan item 2: `WorkspaceDeclared(Off)` rejects even a `Global` address.
    #[test]
    fn test_validate_resolved_addrs_workspace_off_rejects_global() {
        let guard = AddrGuard::WorkspaceDeclared(WorkspaceRegistryAccess::Off);
        let addrs = vec!["1.1.1.1:0".parse().unwrap()];
        assert!(matches!(
            validate_resolved_addrs("index.crates.io", addrs, guard),
            Err(ResolveGuardError::Blocked { .. })
        ));
    }

    // Test-plan item 3: `build_guarded_client_with_lookup` shares `build_client_inner` with the
    // production `build_guarded_client`, so deleting the `.dns_resolver(...)` wiring from that
    // shared function fails this test too, not just the production-path wiring test above. The
    // synthetic lookup returns an RFC1918 address, resolved (not connected — the resolver
    // guard rejects before any TCP attempt) purely through the built `Client`.
    #[tokio::test]
    async fn test_build_guarded_client_with_lookup_blocks_private_range_under_workspace_tier() {
        let lookup = TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]));
        let guard = AddrGuard::WorkspaceDeclared(WorkspaceRegistryAccess::PublicOnly);
        let client = build_guarded_client_with_lookup(guard, lookup);
        let result = client.get("https://corp.example/").send().await;
        let err = result.expect_err(
            "a private-range synthetic lookup must be rejected under WorkspaceDeclared(PublicOnly)",
        );
        assert!(
            format!("{err:?}").contains("Blocked"),
            "expected rejection at the resolver-guard step, got: {err:?}"
        );
    }

    // Test-plan item 3, `Baseline` contrast: the same synthetic private-range lookup is not
    // blocked at the resolver-guard step under `Baseline` — asserted directly against the
    // resolver (not a full `Client`) to avoid depending on any real network behavior of
    // actually connecting to the synthetic address.
    #[tokio::test]
    async fn test_blocked_addr_resolver_allows_private_range_under_baseline() {
        use reqwest::dns::Resolve;

        let lookup = TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]));
        let resolver = BlockedAddrResolver::with_lookup(AddrGuard::Baseline, lookup);
        let result = resolver.resolve("corp.example".parse().unwrap()).await;
        assert!(
            result.is_ok(),
            "Baseline must allow a private-range address through"
        );
    }

    // Direct unit coverage of `BlockedAddrResolver::resolve` on a *name* (not an IP literal —
    // that path never reaches any resolver in production, see the struct's `# Known
    // limitations` doc). `localhost` resolves via the OS's own hosts file, no network needed.
    // This alone does not prove the resolver is wired into `build_guarded_client` — see the
    // sibling test below (critic S1) for that.
    #[tokio::test]
    async fn test_blocked_addr_resolver_rejects_loopback_name_directly() {
        use reqwest::dns::Resolve;

        let addrs = BlockedAddrResolver::new(AddrGuard::Baseline)
            .resolve("localhost".parse().unwrap())
            .await;
        assert!(addrs.is_err());
    }

    // Issue #449 critic S1: the previous version of this test called
    // `BlockedAddrResolver::resolve` directly and never went through `build_guarded_client` at
    // all — deleting `.dns_resolver(...)` from `build_client_inner` left it green. This
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

        let client = build_guarded_client(AddrGuard::Baseline);
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

    // Issue #455, test-plan item 4(a): loopback -> loopback. A `Baseline` transport follows the
    // hop (the `hop_targets_blocked_host` test-cfg carve-out for `Loopback`); a
    // `WorkspaceDeclared(PublicOnly)` transport stops it, since `PublicOnly.allows(Loopback) ==
    // false` — this pins M1' and is the contrast proving the tier split is real. This is one of
    // the tests exercising the documented zero-initial-URL-literal-protection residual: both
    // mockito URLs are IP literals, so the *initial* connection to server A is never checked by
    // policy — only the redirect hop is.
    #[tokio::test]
    async fn test_workspace_transport_stops_loopback_redirect_baseline_follows() {
        let mut server_a = mockito::Server::new_async().await;
        let mut server_b = mockito::Server::new_async().await;
        let target_url = format!("{}/api/target", server_b.url());

        let _redirect = server_a
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &target_url)
            .create_async()
            .await;
        let _target = server_b
            .mock("GET", "/api/target")
            .with_status(200)
            .with_body("redirected data")
            .create_async()
            .await;

        let source_url = format!("{}/api/source", server_a.url());

        let cache = HttpCache::new();
        let result: Bytes = cache
            .get_cached_with_headers_via(&source_url, &[], &Transport::baseline(), None)
            .await
            .unwrap();
        assert_eq!(result.as_ref(), b"redirected data");

        let policy = Arc::new(RegistryAccessPolicy::new(
            WorkspaceRegistryAccess::PublicOnly,
        ));
        let workspace_cache = HttpCache::with_policy(Arc::clone(&policy));
        let result: Result<Bytes> = workspace_cache
            .get_cached_with_headers_via(&source_url, &[], &Transport::workspace(&policy), None)
            .await;
        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected the workspace transport to stop the loopback hop, got {result:?}"
        );
    }

    // Issue #455, test-plan item 4(b): a workspace-blocked literal. Server A 302s to an
    // RFC1918-literal target; the workspace transport under `PublicOnly` stops before
    // connecting (the redirect-policy tier term rejects the hop from its URL string alone, no
    // resolver involved for a literal), so the caller sees `HttpStatus{302}` with no
    // `HTTP_TIMEOUT_SECS` stall. Also exercises the zero-initial-URL-literal-protection
    // residual (the initial hop to server A, an IP literal, is unchecked by policy).
    #[tokio::test]
    async fn test_workspace_transport_stops_redirect_to_private_literal() {
        let mut server = mockito::Server::new_async().await;

        let _redirect = server
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", "https://10.0.0.1/x")
            .create_async()
            .await;

        let policy = Arc::new(RegistryAccessPolicy::new(
            WorkspaceRegistryAccess::PublicOnly,
        ));
        let cache = HttpCache::with_policy(Arc::clone(&policy));
        let source_url = format!("{}/api/source", server.url());
        let result: Result<Bytes> = cache
            .get_cached_with_headers_via(&source_url, &[], &Transport::workspace(&policy), None)
            .await;

        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 302, .. })),
            "expected the redirect to 10.0.0.1 to be stopped, got {result:?}"
        );
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
            .fetch_and_store_with_headers(&url, &[], &cache.baseline.client, &url)
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
            .fetch_and_store_with_headers(&url, &[], &cache.baseline.client, &url)
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

    /// The headered form of `get_cached_workspace` used by `deps-npm`'s alternate-registry
    /// client (A1): forwards `extra_headers` while still going through the workspace-tier
    /// transport (mirrors `test_get_cached_and_get_cached_workspace_do_not_share_an_entry`'s
    /// use of the unheadered `get_cached_workspace` against a loopback mockito server under
    /// the default policy — an IP-literal host like mockito's has no DNS resolution step for
    /// the connect-time `AddrGuard` to intercept, so no policy elevation is needed here
    /// either; that guard's actual job is catching a *hostname* that resolves differently at
    /// connect time than its parse-time classification, see `validate_resolved_addrs`).
    #[tokio::test]
    async fn test_get_cached_workspace_with_headers_sends_extra_headers() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .match_header("accept", "application/vnd.npm.install-v1+json")
            .with_status(200)
            .with_body("abbreviated packument")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let headers = [(header::ACCEPT, "application/vnd.npm.install-v1+json")];
        let result: Bytes = cache
            .get_cached_workspace_with_headers(&url, &headers)
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"abbreviated packument");
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
            .fetch_and_store_with_headers(&url, &[], &cache.baseline.client, &url)
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
            .fetch_and_store_with_headers(&url, &[], &cache.baseline.client, &url)
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

    // Issue #455, test-plan item 5: `get_cached(url)` then `get_cached_workspace(url)` do not
    // share an entry — each is keyed under a distinct namespace (see `HttpCache::cache_key`),
    // so the mockito mock is hit twice and the cache ends up with two entries for one URL.
    #[tokio::test]
    async fn test_get_cached_and_get_cached_workspace_do_not_share_an_entry() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("shared url, distinct tiers")
            .expect(2)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let baseline_result: Bytes = cache.get_cached(&url).await.unwrap();
        let workspace_result: Bytes = cache.get_cached_workspace(&url).await.unwrap();

        assert_eq!(baseline_result.as_ref(), b"shared url, distinct tiers");
        assert_eq!(workspace_result.as_ref(), b"shared url, distinct tiers");
        assert_eq!(cache.len(), 2);
        mock.assert_async().await;
    }

    // Issue #455, test-plan item 6 (C5): fetch under `All`, tighten to `PublicOnly`, re-fetch
    // the same URL — the `All`-era body must not be served, since the policy-scoped key
    // namespace changes with the policy.
    #[tokio::test]
    async fn test_set_registry_policy_change_does_not_serve_stale_era_body() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let _first = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("all-era body")
            .create_async()
            .await;

        let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
        let cache = HttpCache::with_policy(Arc::clone(&policy));
        let first: Bytes = cache.get_cached_workspace(&url).await.unwrap();
        assert_eq!(first.as_ref(), b"all-era body");

        cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);

        let _second = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("public-only-era body")
            .create_async()
            .await;

        let second: Bytes = cache.get_cached_workspace(&url).await.unwrap();
        assert_eq!(
            second.as_ref(),
            b"public-only-era body",
            "the All-era cached body must not be served after tightening to PublicOnly"
        );
        // mockito's second mock answers request 2 regardless of which cache entry (if any) was
        // hit, so the body assertion alone would still pass with a policy-blind cache key —
        // this is the assertion that actually proves the two eras got distinct map entries.
        assert_eq!(cache.len(), 2);
    }

    // Issue #455, test-plan item 7 (C4): `set_registry_policy` rebuilds the workspace transport
    // only on an actual change, not on a no-op re-application of the same value.
    #[test]
    fn test_set_registry_policy_rebuilds_only_on_change() {
        let policy = Arc::new(RegistryAccessPolicy::new(
            WorkspaceRegistryAccess::PublicOnly,
        ));
        let cache = HttpCache::with_policy(policy);
        assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 0);

        cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);
        assert_eq!(
            cache.workspace_rebuilds.load(Ordering::Relaxed),
            0,
            "re-applying the unchanged policy must not rebuild the workspace transport"
        );

        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 1);

        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        assert_eq!(
            cache.workspace_rebuilds.load(Ordering::Relaxed),
            1,
            "re-applying the unchanged (new) policy must not rebuild again"
        );

        cache.set_registry_policy(WorkspaceRegistryAccess::Off);
        assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 2);
    }

    // Issue #483: offline + cold, three send sites. `.expect(0)` proves nothing reached
    // *this mock* — adequate here only because `ensure_https`'s loopback carve-out is what
    // let a mockito server stand in for a real registry at all in this module's tests, not
    // a general proof that zero sockets ever opened.

    #[tokio::test]
    async fn test_offline_cold_get_cached_errors_without_network() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("must not be fetched")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.set_offline(true);

        let result: Result<Bytes> = cache.get_cached(&url).await;
        match result {
            Err(DepsError::Offline { url: blocked }) => assert_eq!(blocked, url),
            other => panic!("expected Offline, got {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_offline_cold_post_json_errors_without_network() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/querybatch", server.url());
        let mock = server
            .mock("POST", "/v1/querybatch")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.set_offline(true);

        let body = serde_json::json!({ "queries": [] });
        let result: Result<Bytes> = cache.post_json(&url, &body).await;
        assert!(matches!(result, Err(DepsError::Offline { .. })));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_offline_cold_get_transport_only_errors_without_network() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/v1/vulns/RUSTSEC-2020-0071", server.url());
        let mock = server
            .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.set_offline(true);

        let result: Result<Bytes> = cache.get_transport_only(&url).await;
        assert!(matches!(result, Err(DepsError::Offline { .. })));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_offline_warm_serves_cached_body_without_network() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("must not be fetched")
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"warm cached body"),
                etag: Some("\"tag123\"".into()),
                last_modified: None,
                fetched_at: Instant::now(),
            },
        );
        cache.set_offline(true);

        let result: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(result.as_ref(), b"warm cached body");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_cache_disabled_two_calls_each_hit_the_server() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("fresh every time")
            .expect(2)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.set_cache_enabled(false);

        let first: Bytes = cache.get_cached(&url).await.unwrap();
        let second: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(first.as_ref(), b"fresh every time");
        assert_eq!(second.as_ref(), b"fresh every time");
        assert!(
            cache.is_empty(),
            "cache.enabled: false must never populate the entry map"
        );
        mock.assert_async().await;
    }

    // S1 fix (critic-corrected): the naive design's `!cache_enabled` bypass ran *before*
    // any offline check, so `cache.enabled: false` + `network.offline: true` cold always
    // took the network-only bypass path — which `ensure_online` then blocked — even though
    // this combination is meant to still surface a clean, immediate signal rather than
    // hang or silently return empty data forever.
    #[tokio::test]
    async fn test_offline_and_cache_disabled_cold_start_errors_cleanly() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        let cache = HttpCache::new();
        cache.set_cache_enabled(false);
        cache.set_offline(true);

        let result: Result<Bytes> = cache.get_cached(&url).await;
        assert!(matches!(result, Err(DepsError::Offline { .. })));
        mock.assert_async().await;
    }

    // The scenario S1 actually exists to fix: an entry stored while caching was enabled
    // must still be servable once `cache.enabled` is later turned off *and* the cache goes
    // offline in the same breath — proving `offline` truly overrides `cache_enabled` on the
    // read path, not just when the two flags never change together.
    #[tokio::test]
    async fn test_offline_overrides_disabled_cache_to_serve_warm_entry() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("fetched while online")
            .expect(1)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let first: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(first.as_ref(), b"fetched while online");

        cache.set_cache_enabled(false);
        cache.set_offline(true);

        let second: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(
            second.as_ref(),
            b"fetched while online",
            "offline must override cache_enabled:false and still serve the warm entry"
        );
        mock.assert_async().await;
    }

    // The primary UX case (critic M6a): a full online -> offline transition on an
    // otherwise-default cache (cache.enabled stays true throughout) must keep serving what
    // was already fetched.
    #[tokio::test]
    async fn test_online_to_offline_transition_serves_previously_fetched_entry() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("fetched while online")
            .expect(1)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let online: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(online.as_ref(), b"fetched while online");

        cache.set_offline(true);

        let offline: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(offline.as_ref(), b"fetched while online");
        mock.assert_async().await;
    }

    // Offline -> online restores live fetches (the flag's other half of critic M6a),
    // exercised here through `get_cached`'s conditional-revalidation path directly (the
    // live `did_change_configuration` toggle is covered by `deps-lsp`'s own test).
    #[tokio::test]
    async fn test_offline_to_online_transition_resumes_fetching() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("fetched while online")
            .expect(1)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let online: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(online.as_ref(), b"fetched while online");
        mock.assert_async().await;

        cache.set_offline(true);
        let offline: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(offline.as_ref(), b"fetched while online");

        cache.set_offline(false);
        drop(mock);
        let revalidate = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(304)
            .expect(1)
            .create_async()
            .await;
        let resumed: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(
            resumed.as_ref(),
            b"fetched while online",
            "returning online must resume live requests, not stay pinned to the cached body"
        );
        revalidate.assert_async().await;
    }

    // Critic M6b: `get_cached_workspace` and `get_cached_trusted_origin` key entries under
    // distinct namespaces from `get_cached`'s baseline tier — the offline warm-cache path
    // needs its own proof it holds for each.
    #[tokio::test]
    async fn test_offline_warm_serves_workspace_tier_without_network() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("workspace fetch")
            .expect(1)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let online: Bytes = cache.get_cached_workspace(&url).await.unwrap();
        assert_eq!(online.as_ref(), b"workspace fetch");

        cache.set_offline(true);
        let offline: Bytes = cache.get_cached_workspace(&url).await.unwrap();
        assert_eq!(offline.as_ref(), b"workspace fetch");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_offline_warm_serves_trusted_origin_tier_without_network() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());
        let mock = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("trusted-origin fetch")
            .expect(1)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let online: Bytes = cache
            .get_cached_trusted_origin(&url, &trusted_origin)
            .await
            .unwrap();
        assert_eq!(online.as_ref(), b"trusted-origin fetch");

        cache.set_offline(true);
        let offline: Bytes = cache
            .get_cached_trusted_origin(&url, &trusted_origin)
            .await
            .unwrap();
        assert_eq!(offline.as_ref(), b"trusted-origin fetch");
        mock.assert_async().await;
    }

    // --- issue #561/#562: CacheTier::Pinned, get_cached_pinned{,_with_headers} ---

    #[tokio::test]
    async fn test_get_cached_pinned_attaches_auth_header() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .match_header("authorization", "Basic dXNlcjpwYXQ=")
            .with_status(200)
            .with_body("authenticated data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let result = cache
            .get_cached_pinned_with_headers(
                &url,
                &trusted_origin,
                true,
                Some(42),
                &[(header::AUTHORIZATION, "Basic dXNlcjpwYXQ=")],
            )
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"authenticated data");
    }

    /// FR-014: distinct `auth_id` values against the same `(url, trusted_origin)` never share
    /// a cache entry — a rotated or distinct credential never reads back a body fetched under a
    /// different one.
    #[tokio::test]
    async fn test_get_cached_pinned_distinct_auth_id_never_shares_cache_entry() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("body-for-credential-a")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let a = cache
            .get_cached_pinned(&url, &trusted_origin, true, Some(1))
            .await
            .unwrap();
        assert_eq!(a.as_ref(), b"body-for-credential-a");
        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("body-for-credential-b")
            .create_async()
            .await;

        let b = cache
            .get_cached_pinned(&url, &trusted_origin, true, Some(2))
            .await
            .unwrap();
        assert_eq!(
            b.as_ref(),
            b"body-for-credential-b",
            "a distinct auth_id must not read back credential A's cached body"
        );
    }

    /// FR-015/NFR-004: a 401 revalidation response against an authenticated `Pinned`-tier
    /// entry evicts the entry and returns the error — never the default
    /// stale-while-revalidate fallback that would serve the possibly-revoked credential's
    /// last-known-good body.
    #[tokio::test]
    async fn test_pinned_authenticated_401_revalidation_evicts_instead_of_stale_serve() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("private data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let first = cache
            .get_cached_pinned(&url, &trusted_origin, true, Some(7))
            .await
            .unwrap();
        assert_eq!(first.as_ref(), b"private data");
        assert_eq!(cache.len(), 1);
        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(401)
            .create_async()
            .await;

        let result = cache
            .get_cached_pinned(&url, &trusted_origin, true, Some(7))
            .await;

        assert!(
            matches!(result, Err(DepsError::HttpStatus { status: 401, .. })),
            "expected the 401 to surface as an error, not a stale-served body: {result:?}"
        );
        assert_eq!(
            cache.len(),
            0,
            "the revoked-credential entry must be evicted, not left cached"
        );
    }

    /// Every other tier keeps today's stale-while-revalidate fallback unchanged — only an
    /// *authenticated* `Pinned` entry evicts on 401/403 (FR-015's scope is deliberately
    /// narrow).
    #[tokio::test]
    async fn test_unauthenticated_pinned_401_revalidation_still_serves_stale() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());

        let _m1 = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("workspace data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let first = cache
            .get_cached_pinned(&url, &trusted_origin, false, None)
            .await
            .unwrap();
        assert_eq!(first.as_ref(), b"workspace data");
        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(401)
            .create_async()
            .await;

        let second = cache
            .get_cached_pinned(&url, &trusted_origin, false, None)
            .await
            .unwrap();
        assert_eq!(
            second.as_ref(),
            b"workspace data",
            "an unauthenticated Pinned entry must keep the default stale-while-revalidate fallback"
        );
        assert_eq!(cache.len(), 1);
    }

    /// `set_registry_policy` purges every `Pinned`-tier cache entry (and pooled transport) on
    /// an actual policy transition — closing the round-trip hole for credential-carrying
    /// entries (NFR-004), unlike the pre-existing `WorkspaceDeclared` non-purge behavior.
    #[tokio::test]
    async fn test_set_registry_policy_purges_pinned_tier_entries() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("private data")
            .create_async()
            .await;

        let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
        let cache = HttpCache::with_policy(Arc::clone(&policy));
        cache
            .get_cached_pinned(&url, &trusted_origin, true, Some(1))
            .await
            .unwrap();
        assert_eq!(cache.len(), 1);

        cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);

        assert_eq!(
            cache.len(),
            0,
            "a Pinned-tier entry must be purged on any actual policy transition"
        );
    }
}

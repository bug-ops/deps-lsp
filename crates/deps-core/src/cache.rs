//! HTTP response cache shared by every ecosystem's registry client.
//!
//! Wraps outbound registry requests with RFC 7232 conditional-request
//! validation (`ETag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`) so
//! that unchanged registry data is served from a bounded in-memory cache
//! instead of re-fetched. Entry count and total retained bytes are both
//! capped to keep memory use predictable under long-running LSP sessions.

use crate::cache_policy::CACHE_EVICTION_PERCENTAGE;
use crate::error::{DepsError, RateLimitEvidence, Result};
use crate::net_policy::{
    AccessSnapshot, BlockingPolicy, GuardedEgress, RegistryAccessPolicy, SystemProxy, Target,
    TrustedPrefix, WorkspaceRegistryAccess, normalize_host,
};
use crate::redact::RedactedUrl;
use crate::secret::{AuthorizationValue, Redacted, auth_digest};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use reqwest::{Client, Response, StatusCode, Url, header};
use serde::Serialize;
use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
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

/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 30;

/// Connect-phase timeout, so a blackholed address fails in 10 s rather than the full request
/// timeout.
const HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;

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
/// 128 MiB comfortably covers the largest known caller (`deps-pypi`'s PyPI
/// Simple API full index, ~43 MB decompressed today, capped at 96 MiB for organic
/// growth) while still bounding the pathological case.
const ABSOLUTE_MAX_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

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

/// Whether `url`'s host is loopback (`127.0.0.1`, `localhost`, or `::1`), with an
/// `http`/`https` scheme and an optional port — the shape every `mockito::Server` binds to.
///
/// Only compiled into test builds (see [`ensure_https`]): a non-loopback host must never
/// be allowed to bypass the HTTPS requirement, even under `cfg(test)`/`test-util`. See
/// [`crate::net_policy::validate_index_url`]'s own private loopback check (`is_loopback_url`)
/// for the counterpart this was modeled on — `is_loopback_url` now matches [`Url::host`]'s
/// structured `Host` enum (`Ipv6Addr::LOCALHOST` comparison, #1568) rather than comparing the
/// bracketed string form, closing the IPv6-loopback gap this doc used to describe as
/// pre-existing/out of scope. The two still differ in accepted scheme: this
/// function matches both `http` and `https` (symmetric with [`ensure_https`]'s own scheme
/// check), while `is_loopback_url` only ever matches `http` — its caller already treats
/// `https` as satisfying the requirement outright, so an `https` loopback host has no need for
/// the carve-out.
///
/// Parses with [`Url::parse`] and compares [`Url::host_str`] rather than splitting the raw
/// string on `:` — a naive split misreads userinfo as the host boundary (e.g.
/// `http://localhost:80@evil.com/x`'s actual host is `evil.com`, but splitting on the first
/// `:` yields `localhost`), which let a public HTTP host bypass the HTTPS requirement by
/// prefixing a loopback-looking userinfo (#1562).
#[cfg(any(test, feature = "test-util"))]
fn is_loopback_host(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    // `Url::host_str` keeps the brackets on an IPv6 literal (`"[::1]"`, not `"::1"`).
    let host = parsed
        .host_str()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'));
    matches!(host, Some("127.0.0.1" | "localhost" | "::1"))
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
    Err(DepsError::CacheError(format!(
        "URL must use HTTPS: {}",
        RedactedUrl::new(url)
    )))
}

/// Whether a non-2xx response carries explicit evidence of genuine rate-limit exhaustion —
/// a 403/429 with `X-RateLimit-Remaining: 0`, or a `Retry-After` header on either (#1295) —
/// as opposed to a 403 for some other reason (abuse-detection false positive, an
/// access-restricted resource).
///
/// `Retry-After` covers GitHub's *secondary* rate limit, which arrives as 403 or 429 with a
/// non-zero (or absent) `X-RateLimit-Remaining` — a `remaining == 0` check alone misses it
/// (critic S4). `429` is included alongside `403` since GitHub returns 429 for some rate-limit
/// responses too, not only 403.
///
/// **Residual false positive** (critic N4): `Retry-After` alone on a 403, with no
/// `X-RateLimit-Remaining` at all, is not *unambiguous* evidence — a WAF/Cloudflare
/// bot-challenge 403 can also carry `Retry-After`, and this predicate cannot distinguish that
/// from a genuine secondary rate limit. This is a narrower false-positive surface than the
/// bug #1295 fixes (which treated *every* untokened 403 as a rate limit with zero
/// corroborating evidence), and considered an acceptable trade-off rather than a bug to
/// eliminate here — see the issue for the full evidence-strength discussion.
///
/// Checked generically here (any header-carrying non-2xx response, not pinned to a GitHub
/// host) rather than in `crate::github`: the response's headers are only available at this
/// live-fetch chokepoint — by the time a caller like `GithubTagsClient` sees the error, it has
/// already collapsed to [`DepsError::HttpStatus`] with no header data left (the exact gap
/// `crate::test_util::unwrap_or_skip_github_rate_limit`'s doc used to describe). Not pinning
/// to a GitHub-shaped `url` also means a `mockito`-backed test can exercise this without a
/// real `api.github.com` request — including from non-GitHub ecosystem crates (`deps-gitlab-ci`)
/// whose registries can send the same evidence shape.
#[inline]
fn confirmed_rate_limit_exhaustion(status: StatusCode, headers: &header::HeaderMap) -> bool {
    if !matches!(
        status,
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
    ) {
        return false;
    }
    let remaining_exhausted = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        == Some(0);
    remaining_exhausted || headers.contains_key("retry-after")
}

/// Fixed, registry-neutral message for a confirmed rate-limit-exhaustion classification
/// (#1295, critic S1). Deliberately generic — [`http_status_error`] runs at every
/// [`HttpCache`] live-fetch site, shared by all 14 ecosystems, not only GitHub, so it must not
/// assume a GitHub-specific remedy (`GITHUB_TOKEN`) applies to whichever registry actually
/// sent the confirming evidence. A GitHub-aware caller
/// (`crate::github::classify_tags_fetch_error`) swaps in the GitHub-specific hint on top of
/// this while keeping `verified: RateLimitEvidence::Confirmed`; `deps-gitlab-ci` does the
/// equivalent for its own gate.
const CONFIRMED_RATE_LIMIT_MESSAGE: &str =
    "registry rate limit exceeded (confirmed by the response)";

/// Builds the `Err` for a non-2xx `response`: a *verified* [`DepsError::RateLimited`] when
/// [`confirmed_rate_limit_exhaustion`] holds, else the usual [`DepsError::HttpStatus`]. Shared
/// by every live-fetch call site in this module so the check can't be forgotten at a new one
/// (#1295).
#[inline]
fn http_status_error(url: &str, status: StatusCode, headers: &header::HeaderMap) -> DepsError {
    if confirmed_rate_limit_exhaustion(status, headers) {
        return DepsError::RateLimited {
            message: CONFIRMED_RATE_LIMIT_MESSAGE.to_string(),
            verified: RateLimitEvidence::Confirmed,
            source_status: Some(status.as_u16()),
        };
    }
    DepsError::HttpStatus {
        url: RedactedUrl::new(url),
        status: status.as_u16(),
    }
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
    /// that is the request's [`RequestAuth`], folded into the cache key only).
    Pinned {
        digest: u64,
    },
}

/// The tier a [`Transport`]'s redirect policy and DNS resolver both enforce.
///
/// `WorkspaceDeclared` holds an [`AccessSnapshot`] (level and allowlist) **value snapshot**, taken once at
/// [`Transport::workspace`] construction time — not a live `Arc<RegistryAccessPolicy>` read on
/// every [`Self::tier_allows`] call. [`Transport::workspace`] takes this same snapshot for its
/// paired [`CacheTier::WorkspaceDeclared`], and [`HttpCache::set_registry_policy`] rebuilds the
/// whole `Transport` (both snapshots included) on every actual policy transition, so a
/// request's cache key and its guard always come from one consistent construction-time value,
/// with no read-skew window between them.
#[derive(Debug, Clone)]
enum AddrGuard {
    Baseline,
    WorkspaceDeclared(AccessSnapshot),
}

impl AddrGuard {
    /// Whether a redirect hop's declared `url` may be reached under this guard's tier.
    fn permits_declared(&self, url: &Url) -> bool {
        match self {
            Self::Baseline => true,
            Self::WorkspaceDeclared(snapshot) => snapshot.permits_url(url),
        }
    }

    /// The rule that refuses a resolved address of `class` under this guard's tier: only the
    /// floor applies at the baseline tier.
    fn blocking_policy(&self, class: crate::net_policy::HostClass) -> BlockingPolicy {
        match self {
            Self::Baseline => BlockingPolicy::Floor,
            Self::WorkspaceDeclared(snapshot) => BlockingPolicy::for_block(class, snapshot.level),
        }
    }

    /// Whether `ip`, resolved for `name`, may be connected to under this guard's tier.
    fn permits_resolved(&self, name: &str, ip: std::net::IpAddr) -> bool {
        match self {
            Self::Baseline => true,
            Self::WorkspaceDeclared(snapshot) => snapshot.permits(Target::Resolved { name, ip }),
        }
    }
}

/// Whether a redirect may leave the host of the request that produced it.
///
/// Guarded traffic through a proxy is preflighted per request host, and a redirect hop's target
/// cannot be preflighted from the synchronous redirect callback, so such traffic stays on the
/// host it started on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectScope {
    AnyHost,
    SameHost,
}

impl RedirectScope {
    const fn for_egress(egress: GuardedEgress) -> Self {
        match egress {
            GuardedEgress::Direct => Self::AnyHost,
            GuardedEgress::Proxy => Self::SameHost,
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
/// classes (loopback, link-local, cloud metadata, unspecified, reserved) that are never a
/// legitimate registry redirect target for *any* ecosystem, benefiting every one of the eleven
/// crates sharing the baseline client, not only Cargo's workspace-declared indexes.
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
fn redirect_policy(guard: AddrGuard, scope: RedirectScope) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        let downgraded = attempt
            .previous()
            .last()
            .is_some_and(|previous| is_https_downgrade(previous, attempt.url()));
        let left_host = match scope {
            RedirectScope::AnyHost => false,
            RedirectScope::SameHost => attempt
                .previous()
                .last()
                .is_some_and(|previous| previous.host() != attempt.url().host()),
        };
        if downgraded
            || left_host
            || hop_targets_blocked_host(attempt.url())
            || !guard.permits_declared(attempt.url())
        {
            attempt.stop()
        } else {
            reqwest::redirect::Policy::default().redirect(attempt)
        }
    })
}

/// Redirect policy for a [`HttpCache::transport_for_origin`]-scoped client.
///
/// Stops any hop unless [`crate::net_policy::is_trusted_prefix`] accepts it against
/// `trusted_origin`, parsed once at [`Transport`] construction — origin equality (scheme,
/// host, and port must match exactly) **and** the hop's path lying at or under
/// `trusted_origin`'s own path, at a proper path-segment boundary.
///
/// Origin equality is the issue #795 fix: the pre-#795 behavior
/// (`attempt.url().as_str().starts_with(&trusted_origin)`, a raw string-prefix test) is
/// satisfied by `https://gitlab.mycorp.dev.evil.com/...`, `https://gitlab.mycorp.dev-evil.com/...`,
/// and `https://gitlab.mycorp.dev@evil.com/...` alike, even though only the last of those
/// three actually shares a host with `evil.com` — `Url::origin()` ignores userinfo and
/// matches scheme+host+port exactly, closing all three shapes at once. This also still
/// covers a downgrade to plain `http://`: an `http://` hop's origin can never equal an
/// `https://`-scheme trusted origin, which every current caller passes — a separate scheme
/// check (as [`redirect_policy`] has, for its no-trusted-origin case) would be dead code
/// here.
///
/// The path-segment-boundary check is **not** subsumed by origin equality, and deliberately
/// kept: a caller (NuGet's registration-hive/flat-container paging, or `deps-cargo`'s sparse
/// index, whose `RegistryIndex::as_str()` carries no trailing-slash guarantee either way —
/// issue #795 S1) pins to a specific *path* on a registry host that also serves other,
/// less-trusted paths, not merely to the host itself. A plain `str::starts_with` on the raw
/// path (this function's pre-S1-fix shape) is itself vulnerable to the same class of bug one
/// level down: a trusted path of `/cargo/index` would wrongly accept the same-origin sibling
/// `/cargo/index-public/steal` or `/cargo/indexEVIL`, since both start with the trusted
/// string textually. [`crate::net_policy::is_trusted_prefix`] requires a hop's path to equal
/// the trusted path or continue immediately after a `/` following it, closing that
/// regardless of whether `trusted_origin`'s own path happens to end in `/`.
///
/// A `trusted_origin` that fails to parse matches no hop — every redirect is stopped
/// (fail-closed) rather than treated as "no restriction" — logged once at construction time
/// via `tracing::warn!` rather than silently, since a caller-side bug producing an
/// unparseable `trusted_origin` would otherwise present only as every redirect on that
/// transport mysteriously failing. This is reachable today: `deps-nuget`'s Public tier builds
/// `trusted_prefix` from a service-index `@id` string that is never `Url`-validated (that
/// validation only runs for [`crate::net_policy::validate_index_url`]'s
/// `NuGetRegistryTier::WorkspaceDeclared` path), so a malformed `@id` reaches this parse.
fn trusted_origin_redirect_policy(trusted_origin: &str) -> reqwest::redirect::Policy {
    let trusted = match Url::parse(trusted_origin) {
        Ok(url) => Some(url),
        Err(error) => {
            tracing::warn!(
                trusted_origin = crate::redact::url_for_tracing(trusted_origin),
                %error,
                "trusted_origin failed to parse; every redirect hop on this transport will be rejected"
            );
            None
        }
    };
    reqwest::redirect::Policy::custom(move |attempt| {
        if is_trusted_origin(attempt.url(), trusted.as_ref()) {
            reqwest::redirect::Policy::default().redirect(attempt)
        } else {
            attempt.stop()
        }
    })
}

/// The origin-and-path decision [`trusted_origin_redirect_policy`]'s closure makes on every
/// redirect hop, extracted as a pure function so the bypass shapes from issue #795 can be
/// regression-tested directly against it — `reqwest::redirect::Attempt`'s fields are private
/// outside the `reqwest` crate, so the closure itself cannot be unit-tested without going
/// through a real HTTP round trip. Delegates to [`crate::net_policy::is_trusted_prefix`],
/// shared with `deps-nuget`'s registration-hive page `@id` pre-check (issue #795 S2).
fn is_trusted_origin(hop_url: &Url, trusted: Option<&Url>) -> bool {
    trusted.is_some_and(|t| crate::net_policy::is_trusted_prefix(hop_url, t))
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
        policy: BlockingPolicy,
    },
}

/// Fails closed when a resolution produced nothing, rather than treating "nothing resolved" as
/// "nothing to block".
fn require_addresses(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
) -> std::result::Result<Vec<std::net::SocketAddr>, ResolveGuardError> {
    if addrs.is_empty() {
        tracing::warn!(host, "DNS resolution returned no addresses");
        return Err(ResolveGuardError::NoAddresses {
            host: host.to_string(),
        });
    }
    Ok(addrs)
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
    guard: &AddrGuard,
) -> std::result::Result<Vec<std::net::SocketAddr>, ResolveGuardError> {
    let addrs = require_addresses(host, addrs)?;
    for addr in &addrs {
        let class = crate::net_policy::classify_addr(addr.ip());
        if class.never_a_registry() || !guard.permits_resolved(host, addr.ip()) {
            tracing::warn!(host, addr = %addr.ip(), %class, "blocking DNS-resolved address");
            return Err(ResolveGuardError::Blocked {
                host: host.to_string(),
                addr: addr.ip(),
                class,
                policy: guard.blocking_policy(class),
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
/// cloud-metadata, unspecified, reserved), the same tier [`hop_targets_blocked_host`] already
/// applies — closing issue #449's filed exploit (cloud-metadata rebinding) but not full `PublicOnly`
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
    /// Normalized names (the proxy's own hosts) whose resolved addresses skip the address check:
    /// a proxy named by DNS is operator configuration, not attacker-controlled input.
    exempt: Arc<[String]>,
    #[cfg(test)]
    lookup: Option<TestLookup>,
}

impl BlockedAddrResolver {
    fn new(guard: AddrGuard, exempt: Arc<[String]>) -> Self {
        Self {
            guard,
            exempt,
            #[cfg(test)]
            lookup: None,
        }
    }

    #[cfg(test)]
    fn with_lookup(guard: AddrGuard, exempt: Arc<[String]>, lookup: TestLookup) -> Self {
        Self {
            guard,
            exempt,
            lookup: Some(lookup),
        }
    }
}

impl BlockedAddrResolver {
    fn exempt_name(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.exempt.contains(&host)
    }
}

impl reqwest::dns::Resolve for BlockedAddrResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let guard = self.guard.clone();
        let exempt = self.exempt_name(&host);
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

            let addrs = if exempt {
                require_addresses(&host, addrs)?
            } else {
                validate_resolved_addrs(&host, addrs, &guard)?
            };
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// What a cached read does when revalidating a stored entry fails.
///
/// A caller that merges several cached responses into one answer (a paginated list) cannot
/// accept a silently stale part: the merged result would mix generations.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RevalidationFailure;
///
/// assert_eq!(RevalidationFailure::default(), RevalidationFailure::ServeStale);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RevalidationFailure {
    /// Serve the stored entry and log the failure (stale-while-revalidate).
    #[default]
    ServeStale,
    /// Return the revalidation error and keep the stored entry.
    Fail,
}

/// A non-credential header an [`HttpCache`] request carries.
///
/// Every header this workspace sends beyond the conditional-request validators is either a
/// fixed content-negotiation `Accept` value or a credential. Credentials are not representable
/// here: they travel as a [`RequestAuth`], which only the origin-confined cached APIs accept.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RequestHeader;
///
/// let headers = [RequestHeader::Accept("application/json")];
/// assert_eq!(headers.len(), 1);
/// ```
#[derive(Debug, Clone, Copy)]
pub enum RequestHeader {
    /// A fixed `Accept` value.
    Accept(&'static str),
}

/// The header a credentialed request carries.
///
/// Both values are sent marked sensitive. An `Authorization` value is an
/// [`AuthorizationValue`], which only the shared `Basic`/`Bearer`/verbatim constructors build.
#[derive(Debug, Clone, Copy)]
pub enum CredentialHeader<'a> {
    /// `Authorization`.
    Authorization(&'a AuthorizationValue),
    /// GitLab's `PRIVATE-TOKEN`, carrying the raw token.
    GitlabPrivateToken(&'a Redacted),
}

impl CredentialHeader<'_> {
    fn expose_secret(&self) -> &str {
        match self {
            Self::Authorization(value) => value.expose_secret(),
            Self::GitlabPrivateToken(token) => token.expose_secret(),
        }
    }
}

/// Whether a confirmed rate limit (a `401`/`403` with exhausted `X-RateLimit-Remaining`) on a
/// credentialed revalidation means the credential may be revoked.
///
/// A per-source decision made by the caller that owns the credential, not a side effect of the
/// transport tier.
///
/// # Examples
///
/// ```
/// use deps_core::cache::RateLimitRevocation;
///
/// assert_eq!(RateLimitRevocation::default(), RateLimitRevocation::Revokes);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RateLimitRevocation {
    /// Treat it like any other `401`/`403`: evict the entry instead of serving it stale (#1295).
    #[default]
    Revokes,
    /// Treat it as throttling only: the credential is fine, so the entry is served stale. For
    /// sources whose rate limiter answers `403` (GitHub).
    Throttles,
}

impl RateLimitRevocation {
    /// Whether `error`, from revalidating a credentialed entry, means the credential may be
    /// revoked, so the entry must be evicted instead of served stale (FR-015/NFR-004).
    ///
    /// A plain `401`/`403` always counts. Written without a catch-all so a new [`DepsError`]
    /// variant must be classified here.
    fn revokes_credential(self, error: &DepsError) -> bool {
        match error {
            DepsError::HttpStatus {
                status: 401 | 403, ..
            } => true,
            DepsError::RateLimited {
                source_status: Some(401 | 403),
                ..
            } => match self {
                Self::Revokes => true,
                Self::Throttles => false,
            },
            DepsError::HttpStatus { .. }
            | DepsError::RateLimited { .. }
            | DepsError::ParseError { .. }
            | DepsError::RegistryError { .. }
            | DepsError::CacheError(_)
            | DepsError::PackageNotFound { .. }
            | DepsError::ApiResponse { .. }
            | DepsError::ResponseTooLarge { .. }
            | DepsError::InvalidVersionReq(_)
            | DepsError::InvalidPackageName(_)
            | DepsError::Io(_)
            | DepsError::Json(_)
            | DepsError::UnsupportedEcosystem(_)
            | DepsError::AmbiguousEcosystem(_)
            | DepsError::InvalidUri(_)
            | DepsError::Offline { .. }
            | DepsError::ChainResolutionHalted
            | DepsError::PaginatedListIncomplete { .. }
            | DepsError::HostBlockedByPolicy { .. } => false,
        }
    }
}

/// The credential state of one origin-confined cached request.
///
/// A credentialed body is always stored under a partition derived from the credential, and an
/// anonymous request never reads it back, so removing or rotating a token cannot make a later
/// request see a body fetched under the old one. The cache key carries the variant too, so the
/// same [`CredentialPartition`] used with a credential and anonymously yields two entries.
///
/// # Examples
///
/// ```
/// use deps_core::cache::{CredentialHeader, CredentialPartition, RequestAuth};
/// use deps_core::net_policy::TrustedPrefix;
/// use deps_core::secret::{Redacted, bearer_auth_header};
///
/// let prefix = TrustedPrefix::parse("https://index.mycorp.dev/").unwrap();
/// let token = bearer_auth_header(&Redacted::new("secret-token".to_string()));
/// let auth = RequestAuth::credential(CredentialHeader::Authorization(&token), &prefix);
/// assert!(!format!("{auth:?}").contains("secret-token"));
/// let _anonymous = RequestAuth::Anonymous { partition: Some(CredentialPartition::new(1)) };
/// ```
#[derive(Debug, Clone, Copy)]
pub enum RequestAuth<'a> {
    /// No credential; `partition` separates cache entries by the caller's credential state.
    Anonymous {
        /// The caller's credential-state partition, `None` for the plain per-URL entry.
        partition: Option<CredentialPartition>,
    },
    /// A credential, always cached under its own partition.
    Credential {
        /// The header to send.
        header: CredentialHeader<'a>,
        /// The partition the response is stored under.
        partition: CredentialPartition,
        /// What a confirmed rate limit on revalidation means for this credential.
        on_rate_limit: RateLimitRevocation,
    },
}

impl<'a> RequestAuth<'a> {
    /// A request with no credential and no partition.
    pub const ANONYMOUS: Self = Self::Anonymous { partition: None };

    /// A credentialed request whose partition is a salted digest of `prefix` and the secret.
    #[must_use]
    pub fn credential(header: CredentialHeader<'a>, prefix: &TrustedPrefix) -> Self {
        Self::credential_in(
            header,
            CredentialPartition::new(auth_digest_of(prefix.as_str(), header.expose_secret())),
        )
    }

    /// A credentialed request stored under a caller-chosen `partition`.
    #[must_use]
    pub const fn credential_in(
        header: CredentialHeader<'a>,
        partition: CredentialPartition,
    ) -> Self {
        Self::Credential {
            header,
            partition,
            on_rate_limit: RateLimitRevocation::Revokes,
        }
    }

    /// Sets what a confirmed rate limit means for this request's credential. No effect on an
    /// anonymous request.
    #[must_use]
    pub const fn with_rate_limit(self, on_rate_limit: RateLimitRevocation) -> Self {
        match self {
            Self::Credential {
                header, partition, ..
            } => Self::Credential {
                header,
                partition,
                on_rate_limit,
            },
            Self::Anonymous { .. } => self,
        }
    }

    fn key_auth(&self) -> KeyAuth {
        match *self {
            Self::Anonymous { partition } => KeyAuth::Anonymous(partition),
            Self::Credential { partition, .. } => KeyAuth::Credential(partition),
        }
    }

    /// Fails closed unless a credentialed request's `url` lies under `prefix`.
    ///
    /// The redirect policy confines every hop to `prefix`'s origin, which includes its scheme,
    /// so a request that starts under an `https` prefix can never be redirected onto plain
    /// `http` with the credential attached. That only holds when the initial URL is itself
    /// under the prefix, so the credential is withheld otherwise.
    fn ensure_within(&self, url: &str, prefix: &TrustedPrefix) -> Result<()> {
        match self {
            Self::Anonymous { .. } => Ok(()),
            Self::Credential { .. } => {
                if Url::parse(url).is_ok_and(|parsed| prefix.permits(&parsed)) {
                    Ok(())
                } else {
                    Err(DepsError::CacheError(format!(
                        "refusing to send a credential to {} outside its trusted prefix",
                        RedactedUrl::new(url)
                    )))
                }
            }
        }
    }

    fn rate_limit(&self) -> RateLimitRevocation {
        match *self {
            Self::Anonymous { .. } => RateLimitRevocation::default(),
            Self::Credential { on_rate_limit, .. } => on_rate_limit,
        }
    }
}

/// The credential state a cache key is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAuth {
    Anonymous(Option<CredentialPartition>),
    Credential(CredentialPartition),
}

impl KeyAuth {
    const ANONYMOUS: Self = Self::Anonymous(None);

    const fn is_credentialed(self) -> bool {
        matches!(self, Self::Credential(_))
    }
}

/// A header as sent on the wire: a fixed `Accept`, or a credential.
#[derive(Debug, Clone, Copy)]
enum WireHeader<'a> {
    Accept(&'static str),
    Credential(CredentialHeader<'a>),
}

impl From<RequestHeader> for WireHeader<'_> {
    fn from(header: RequestHeader) -> Self {
        match header {
            RequestHeader::Accept(value) => Self::Accept(value),
        }
    }
}

fn wire_headers<'a>(accept: &[RequestHeader], auth: &RequestAuth<'a>) -> Vec<WireHeader<'a>> {
    let mut headers: Vec<WireHeader<'a>> = wire_accept_headers(accept);
    match auth {
        RequestAuth::Credential { header, .. } => headers.push(WireHeader::Credential(*header)),
        RequestAuth::Anonymous { .. } => {}
    }
    headers
}

fn wire_accept_headers(accept: &[RequestHeader]) -> Vec<WireHeader<'static>> {
    accept.iter().copied().map(WireHeader::from).collect()
}

fn accept_headers(accept: Option<&'static str>) -> Vec<RequestHeader> {
    accept.map(RequestHeader::Accept).into_iter().collect()
}

fn auth_digest_of(origin: &str, secret: &str) -> u64 {
    // A `Some` secret always digests; the variant tag in the cache key keeps `0` unambiguous anyway.
    auth_digest(origin, Some(secret)).unwrap_or_default()
}

/// Adds `name: secret` to `request`, marked sensitive.
///
/// A value that is not a valid header value is passed through raw so
/// `RequestBuilder::send` fails exactly as it would for any malformed header, with no value
/// in the error.
fn sensitive_header(
    request: reqwest::RequestBuilder,
    name: header::HeaderName,
    secret: &str,
) -> reqwest::RequestBuilder {
    match header::HeaderValue::from_str(secret) {
        Ok(mut value) => {
            value.set_sensitive(true);
            request.header(name, value)
        }
        Err(_) => request.header(name, secret),
    }
}

/// Attaches `headers` to `request`, marking every credential value sensitive.
///
/// A credential value that is not a valid header value is passed through raw so
/// `RequestBuilder::send` fails exactly as it would for any malformed header, with no value
/// in the error.
fn apply_request_headers(
    mut request: reqwest::RequestBuilder,
    headers: &[WireHeader<'_>],
) -> reqwest::RequestBuilder {
    for header in headers {
        request = match header {
            WireHeader::Accept(value) => request.header(header::ACCEPT, *value),
            WireHeader::Credential(CredentialHeader::Authorization(value)) => {
                sensitive_header(request, header::AUTHORIZATION, value.expose_secret())
            }
            WireHeader::Credential(CredentialHeader::GitlabPrivateToken(token)) => {
                sensitive_header(
                    request,
                    header::HeaderName::from_static("private-token"),
                    token.expose_secret(),
                )
            }
        };
    }
    request
}

/// Maps a failed `send()` to a [`DepsError`], surfacing a connect-time resolver-guard block as
/// [`DepsError::HostBlockedByPolicy`] instead of a generic transport error.
///
/// Walks the source chain before the error is sanitized, since [`SanitizedRegistryError`] drops
/// the chain. A [`ResolveGuardError::NoAddresses`] stays a transport error.
fn send_error(url: &str, error: reqwest::Error) -> DepsError {
    let blocked =
        std::iter::successors(std::error::Error::source(&error), |source| source.source())
            .find_map(|source| match source.downcast_ref::<ResolveGuardError>() {
                Some(ResolveGuardError::Blocked { class, policy, .. }) => Some((*class, *policy)),
                Some(ResolveGuardError::NoAddresses { .. }) | None => None,
            });
    match blocked {
        Some((class, policy)) => DepsError::HostBlockedByPolicy {
            url: RedactedUrl::new(url),
            class,
            policy,
        },
        None => DepsError::RegistryError {
            package: RedactedUrl::new(url),
            source: error.into(),
        },
    }
}

/// The system proxy configuration a transport's exemption set is computed from.
///
/// Unit tests see an empty configuration so a developer machine's own proxy (possibly a
/// DNS-named one) cannot change which names the resolver-guard tests exempt.
fn detect_system_proxy() -> SystemProxy {
    #[cfg(test)]
    {
        SystemProxy::default()
    }
    #[cfg(not(test))]
    {
        SystemProxy::detect()
    }
}

/// Which proxy configuration a [`Transport`]'s client is built with, and so which proxy hosts its
/// resolver must exempt from the address check.
///
/// `System` carries the configuration detected at the moment the client is built, the same one
/// reqwest reads at `Client::build`, so the exemption cannot skew from the client's behavior.
#[derive(Debug, Clone)]
enum ProxyRoute {
    System(SystemProxy),
    Bypass,
    #[cfg(test)]
    Fixed(Url),
}

impl ProxyRoute {
    /// The route for a transport enforcing `guard` under `egress`: baseline traffic always uses
    /// the system proxy; guarded traffic bypasses it unless the operator opted in.
    fn for_tier(guard: &AddrGuard, egress: GuardedEgress) -> Self {
        match (guard, egress) {
            (AddrGuard::Baseline, GuardedEgress::Direct | GuardedEgress::Proxy)
            | (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Proxy) => {
                Self::System(detect_system_proxy())
            }
            (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Direct) => Self::Bypass,
        }
    }

    fn exempt_hosts(&self) -> Arc<[String]> {
        match self {
            Self::System(proxy) => proxy.hosts().map(normalize_host).collect(),
            Self::Bypass => Arc::from([]),
            #[cfg(test)]
            Self::Fixed(url) => url.host_str().map(normalize_host).into_iter().collect(),
        }
    }

    fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        match self {
            Self::System(_) => builder,
            Self::Bypass => builder.no_proxy(),
            #[cfg(test)]
            Self::Fixed(url) => match reqwest::Proxy::all(url.as_str()) {
                Ok(proxy) => builder.no_proxy().proxy(proxy),
                Err(_) => builder,
            },
        }
    }
}

/// The client configuration every transport shares: user agent, timeouts and proxy route.
fn base_client_builder(route: &ProxyRoute) -> reqwest::ClientBuilder {
    route
        .apply(Client::builder())
        .user_agent(format!("deps-lsp/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(HTTP_CONNECT_TIMEOUT_SECS))
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
}

/// Builds a client with `HttpCache`'s shared configuration (user agent, timeouts), varying the
/// redirect policy, resolver and proxy route — kept in one place so a future client-wide setting
/// (connection pool sizing, etc.) can't silently miss any [`Transport`] this module builds. This
/// is also the workspace's only `Client::builder()` call site.
fn build_client_inner(
    redirect: reqwest::redirect::Policy,
    resolver: BlockedAddrResolver,
    route: &ProxyRoute,
) -> Client {
    #[expect(
        clippy::expect_used,
        reason = "fixed, hardcoded client configuration — no attacker-influenced input; can \
                  only fail on a genuinely broken TLS backend, which is unrecoverable anyway"
    )]
    base_client_builder(route)
        .redirect(redirect)
        .dns_resolver(resolver)
        .build()
        .expect("failed to create HTTP client")
}

/// Test-only variant of the guarded client constructor that substitutes a synthetic DNS lookup
/// for `tokio::net::lookup_host` — shares [`build_client_inner`] with the production
/// constructors, so deleting the `.dns_resolver(...)` wiring from that shared function fails any
/// test built on this too, not just the production path.
#[cfg(test)]
fn build_guarded_client_with_lookup(guard: AddrGuard, lookup: TestLookup) -> Client {
    let route = ProxyRoute::for_tier(&guard, GuardedEgress::Direct);
    build_client_inner(
        redirect_policy(guard.clone(), RedirectScope::AnyHost),
        BlockedAddrResolver::with_lookup(guard, route.exempt_hosts(), lookup),
        &route,
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
    /// Resolves each request's target name through the transport's own guard before the send,
    /// set only for guarded traffic that goes through the system proxy: the proxy resolves the
    /// target itself, so the client's own resolver never sees it.
    preflight: Option<BlockedAddrResolver>,
}

impl Transport {
    /// The shared, unauthenticated transport used by every non-workspace request.
    fn baseline() -> Self {
        Self::standard(
            AddrGuard::Baseline,
            GuardedEgress::Direct,
            CacheTier::Baseline,
            RedirectScope::AnyHost,
        )
    }

    /// The transport for Cargo's workspace-declared-registry requests, snapshotting `policy`'s
    /// current value once and sharing that single snapshot between the guard and the cache-key
    /// tier — see [`AddrGuard::WorkspaceDeclared`]'s docs for why this is a value snapshot, not
    /// a live `Arc` read, and why the guard and the tier must never snapshot independently.
    fn workspace(policy: &Arc<RegistryAccessPolicy>) -> Self {
        let snapshot = policy.snapshot();
        let tier = CacheTier::WorkspaceDeclared(snapshot.level);
        let egress = policy.egress();
        Self::standard(
            AddrGuard::WorkspaceDeclared(snapshot),
            egress,
            tier,
            RedirectScope::for_egress(egress),
        )
    }

    /// The transport for one [`HttpCache::transport_for_origin`]-pinned origin: a plain
    /// [`AddrGuard::Baseline`] resolver, paired with [`trusted_origin_redirect_policy`] instead
    /// of [`redirect_policy`] — that policy pins by URL prefix, which already subsumes the
    /// blocked-host hop check.
    fn origin_pinned(trusted_origin: &str) -> Self {
        Self::assemble(
            trusted_origin_redirect_policy(trusted_origin),
            AddrGuard::Baseline,
            GuardedEgress::Direct,
            CacheTier::Baseline,
        )
    }

    /// The transport for one origin-pinned **workspace-declared** host (issue #561/#562),
    /// optionally carrying a credential. Pairs [`trusted_origin_redirect_policy`] (send-scope
    /// confinement — no redirect hop may leave `trusted_origin`) with
    /// [`AddrGuard::WorkspaceDeclared`] (the connect-address policy guard, #455-class
    /// protection) and the namespaced [`CacheTier::Pinned`] tier. One constructor serves both
    /// #562's unauthenticated workspace-declared fetches and #561's authenticated ones. The
    /// shipped [`Self::origin_pinned`] (public `api.nuget.org` path) is unaffected — this is a
    /// distinct constructor, not a modification of that one.
    fn origin_pinned_guarded(
        trusted_origin: &str,
        snapshot: AccessSnapshot,
        egress: GuardedEgress,
    ) -> Self {
        let digest = pinned_digest(trusted_origin, snapshot.level);
        Self::assemble(
            trusted_origin_redirect_policy(trusted_origin),
            AddrGuard::WorkspaceDeclared(snapshot),
            egress,
            CacheTier::Pinned { digest },
        )
    }

    fn standard(
        guard: AddrGuard,
        egress: GuardedEgress,
        tier: CacheTier,
        scope: RedirectScope,
    ) -> Self {
        let redirect = redirect_policy(guard.clone(), scope);
        Self::assemble(redirect, guard, egress, tier)
    }

    fn assemble(
        redirect: reqwest::redirect::Policy,
        guard: AddrGuard,
        egress: GuardedEgress,
        tier: CacheTier,
    ) -> Self {
        let route = ProxyRoute::for_tier(&guard, egress);
        let resolver = BlockedAddrResolver::new(guard, route.exempt_hosts());
        Self::from_parts(redirect, resolver, egress, &route, tier)
    }

    fn from_parts(
        redirect: reqwest::redirect::Policy,
        resolver: BlockedAddrResolver,
        egress: GuardedEgress,
        route: &ProxyRoute,
        tier: CacheTier,
    ) -> Self {
        let preflight = match (&resolver.guard, egress) {
            // The preflight resolves only targets, never the proxy, so it carries no proxy-host
            // exemption: a target named like the proxy must still be checked.
            (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Proxy) => Some(BlockedAddrResolver {
                exempt: Arc::from([]),
                ..resolver.clone()
            }),
            (AddrGuard::Baseline, GuardedEgress::Direct | GuardedEgress::Proxy)
            | (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Direct) => None,
        };
        Self {
            client: build_client_inner(redirect, resolver, route),
            tier,
            preflight,
        }
    }

    /// Resolves `url`'s domain host through this transport's guard before a send that will go
    /// through a proxy, so a name that resolves to a blocked address never reaches the proxy.
    ///
    /// Unconditional when [`Self::preflight`] is set: skipping it for a host the proxy matcher
    /// says is direct would fail open if the matcher and the client ever disagree. IP-literal
    /// hosts are classified at parse time instead.
    async fn preflight(&self, url: &str) -> Result<()> {
        let Some(resolver) = &self.preflight else {
            return Ok(());
        };
        let Some(domain) = Url::parse(url).ok().and_then(|parsed| match parsed.host() {
            Some(url::Host::Domain(domain)) => Some(domain.to_string()),
            Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) | None => None,
        }) else {
            return Ok(());
        };
        let name = reqwest::dns::Name::from_str(&domain)
            .map_err(|error| preflight_error(url, Box::new(error)))?;
        reqwest::dns::Resolve::resolve(resolver, name)
            .await
            .map(drop)
            .map_err(|error| preflight_error(url, error))
    }
}

/// Maps a failed preflight resolution to the error a failed send would have produced.
fn preflight_error(url: &str, error: Box<dyn std::error::Error + Send + Sync>) -> DepsError {
    match error.downcast_ref::<ResolveGuardError>() {
        Some(ResolveGuardError::Blocked { class, policy, .. }) => DepsError::HostBlockedByPolicy {
            url: RedactedUrl::new(url),
            class: *class,
            policy: *policy,
        },
        Some(ResolveGuardError::NoAddresses { .. }) | None => DepsError::CacheError(format!(
            "DNS preflight for {} failed: {error}",
            RedactedUrl::new(url)
        )),
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
            package: RedactedUrl::new(url),
            source: e.into(),
        })?
    {
        if body.len() + chunk.len() > limit {
            return Err(DepsError::ResponseTooLarge {
                url: RedactedUrl::new(url),
                limit,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body.freeze())
}

/// Stands in for a `Link` header value that is not visible ASCII, so a caller detecting
/// pagination fails closed (treats the list as truncated) instead of silently ignoring it.
const UNREADABLE_LINK: &str = r#"<>; rel="next""#;

/// The response headers a [`CachedResponse`] keeps, captured before the body consumes the
/// response.
struct ResponseValidators {
    etag: Option<String>,
    last_modified: Option<String>,
    link: Option<String>,
}

impl ResponseValidators {
    fn from_headers(headers: &header::HeaderMap) -> Self {
        let single = |name: header::HeaderName| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let links: Vec<&str> = headers
            .get_all(header::LINK)
            .iter()
            .map(|v| v.to_str().unwrap_or(UNREADABLE_LINK))
            .collect();
        Self {
            etag: single(header::ETAG),
            last_modified: single(header::LAST_MODIFIED),
            link: (!links.is_empty()).then(|| links.join(", ")),
        }
    }

    fn into_response(self, body: Bytes) -> CachedResponse {
        CachedResponse {
            body,
            etag: self.etag,
            last_modified: self.last_modified,
            link: self.link,
            fetched_at: Instant::now(),
        }
    }
}

/// Identifies the credential state a trusted-origin response was fetched under, so the cache can
/// keep bodies of different states apart (see
/// [`HttpCache::get_cached_trusted_origin_response`]).
///
/// A distinct type from the credential-header digests used for pinned requests: the two are
/// both hashes, but only a partition is a statement about "which state", and mixing them up
/// would silently share or split cache entries.
///
/// # Examples
///
/// ```
/// use deps_core::cache::CredentialPartition;
///
/// assert_eq!(CredentialPartition::new(7), CredentialPartition::new(7));
/// assert_ne!(CredentialPartition::new(7), CredentialPartition::new(8));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialPartition(u64);

impl CredentialPartition {
    /// Wraps the caller's hash of its credential state.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    const fn get(self) -> u64 {
        self.0
    }
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
/// let response = CachedResponse::new(Bytes::from("response data")).with_etag("\"abc123\"");
///
/// // Clone is cheap - only increments reference count
/// let cloned = response.clone();
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// Raw response body, shareable across consumers without copying.
    pub body: Bytes,
    /// `ETag` header from the response, used for `If-None-Match` revalidation.
    pub etag: Option<String>,
    /// `Last-Modified` header from the response, used for `If-Modified-Since` revalidation.
    pub last_modified: Option<String>,
    /// Raw `Link` header (RFC 8288) from the response, kept so a caller can detect a paginated
    /// list (see `pagination::ListCoverage::from_link_header`). Several `Link` headers are
    /// joined with `, `. Carried over unchanged on a 304 revalidation.
    pub link: Option<String>,
    /// Local time the response was fetched, used for TTL expiry checks.
    pub fetched_at: Instant,
}

impl CachedResponse {
    /// Constructs a `CachedResponse` for `body`, fetched now, with [`Self::etag`] and
    /// [`Self::last_modified`] left `None` — chain [`Self::with_etag`] and/or
    /// [`Self::with_last_modified`] to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::cache::CachedResponse;
    /// use bytes::Bytes;
    ///
    /// let response = CachedResponse::new(Bytes::from("response data")).with_etag("\"abc123\"");
    /// assert_eq!(response.etag.as_deref(), Some("\"abc123\""));
    /// ```
    #[must_use]
    pub fn new(body: Bytes) -> Self {
        Self {
            body,
            etag: None,
            last_modified: None,
            link: None,
            fetched_at: Instant::now(),
        }
    }

    /// Attaches the response's `Link` header. See [`Self::link`].
    #[must_use]
    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
        self
    }

    /// Attaches the response's `ETag` header. See [`Self::etag`].
    #[must_use]
    pub fn with_etag(mut self, etag: impl Into<String>) -> Self {
        self.etag = Some(etag.into());
        self
    }

    /// Attaches the response's `Last-Modified` header. See [`Self::last_modified`].
    #[must_use]
    pub fn with_last_modified(mut self, last_modified: impl Into<String>) -> Self {
        self.last_modified = Some(last_modified.into());
        self
    }

    /// Overrides when the response was fetched — otherwise [`Self::new`] stamps
    /// [`Instant::now`]. Lets external code (tests, benches) construct a backdated entry to
    /// exercise TTL-expiry behavior, the one thing a direct struct literal used to allow.
    #[must_use]
    pub const fn with_fetched_at(mut self, fetched_at: Instant) -> Self {
        self.fetched_at = fetched_at;
        self
    }
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
    /// unauthenticated transport for the same origin share one pool entry; the credential state
    /// lives in the request's [`RequestAuth`], not the transport.
    fn transport_for_pinned(&self, trusted_origin: &str) -> Transport {
        let snapshot = self.policy.snapshot();
        let digest = pinned_digest(trusted_origin, snapshot.level);
        let key = (trusted_origin.to_string(), CacheTier::Pinned { digest });
        if let Some(existing) = self.trusted_clients.get(&key) {
            return existing.clone();
        }

        self.trusted_clients
            .entry(key)
            .or_insert_with(|| {
                Transport::origin_pinned_guarded(trusted_origin, snapshot, self.policy.egress())
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

    /// The prefix marking a [`CacheTier::Baseline`] key partitioned by a caller-supplied
    /// `auth_id`, followed by that id as 16 fixed-width hex digits and then the URL. Distinct
    /// from [`Self::WS_KEY_PREFIX`] and [`Self::PINNED_KEY_PREFIX`], so it can collide with
    /// neither them nor a bare-URL key.
    const BASELINE_AUTH_KEY_PREFIX: char = '\u{3}';

    /// Byte length of [`Self::BASELINE_AUTH_KEY_PREFIX`], the variant tag and the 16-digit id
    /// field.
    const BASELINE_AUTH_KEY_HEAD_LEN: usize = 1 + 1 + 16;

    /// Computes the cache-map key for `url` under `tier` — `Cow::Borrowed(url)` for an
    /// anonymous, unpartitioned [`CacheTier::Baseline`] request (allocation-free, and identical
    /// to every entry this cache wrote before this policy-tier split existed), or a prefixed
    /// owned key otherwise.
    ///
    /// [`CacheTier::WorkspaceDeclared`] folds in a policy digit so a policy tightening can never
    /// serve a body fetched under a looser policy (C5): the digit comes from `tier`'s own
    /// snapshot — the exact same value the paired [`Transport`]'s [`AddrGuard`] enforced for
    /// this request, taken together at [`Transport::workspace`] construction time — never a
    /// separate live `self.policy` read, which would open a read-skew window between the guard
    /// that let a fetch through and the key that fetch's body gets stored under.
    ///
    /// Callers must compute this once per request and thread the result through, never
    /// recompute mid-request — a policy flip between two recomputations would read and write
    /// under different keys for what should be one atomic operation.
    ///
    /// `auth` is folded in for [`CacheTier::Pinned`] and [`CacheTier::Baseline`], always with a
    /// one-char variant tag (`A` credentialed, `U` anonymous) ahead of the partition, so the
    /// same [`CredentialPartition`] used with and without a credential yields two entries. A
    /// partition is encoded as a tag (`0`/`1`) before a fixed-width hex field rather than a `0`
    /// sentinel: [`auth_digest`](crate::secret::auth_digest) is a non-cryptographic hash, so
    /// `Some(0)` is a legitimate digest (issue #1025). Every field is fixed width, so no tag or
    /// field can be confused with part of another field or `url`.
    fn cache_key<'a>(&self, url: &'a str, tier: CacheTier, auth: KeyAuth) -> Cow<'a, str> {
        match tier {
            CacheTier::Baseline => match auth {
                KeyAuth::Anonymous(None) => Cow::Borrowed(url),
                KeyAuth::Anonymous(Some(partition)) => Cow::Owned(format!(
                    "{}U{:016x}{url}",
                    Self::BASELINE_AUTH_KEY_PREFIX,
                    partition.get()
                )),
                KeyAuth::Credential(partition) => Cow::Owned(format!(
                    "{}A{:016x}{url}",
                    Self::BASELINE_AUTH_KEY_PREFIX,
                    partition.get()
                )),
            },
            CacheTier::WorkspaceDeclared(snapshot) => {
                Cow::Owned(format!("{}{}{url}", Self::WS_KEY_PREFIX, snapshot.to_u8()))
            }
            CacheTier::Pinned { digest } => {
                let (partition_tag, id) = match auth {
                    KeyAuth::Anonymous(None) => ('0', 0),
                    KeyAuth::Anonymous(Some(p)) | KeyAuth::Credential(p) => ('1', p.get()),
                };
                let variant_tag = if auth.is_credentialed() { 'A' } else { 'U' };
                Cow::Owned(format!(
                    "{}{digest:016x}{partition_tag}{id:016x}{variant_tag}{url}",
                    Self::PINNED_KEY_PREFIX,
                ))
            }
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
    /// `conditional_request_with_headers`'s match in `get_cached_via`), this
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
    /// Works the same as `get_cached` but injects extra content-negotiation headers into every
    /// request. A credential never travels here: see [`Self::get_cached_trusted_origin`].
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
        extra_headers: &[RequestHeader],
    ) -> Result<Bytes> {
        let headers = wire_headers(extra_headers, &RequestAuth::ANONYMOUS);
        self.get_cached_via(
            url,
            &headers,
            &self.baseline,
            KeyAuth::ANONYMOUS,
            RevalidationFailure::ServeStale,
            RateLimitRevocation::default(),
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached`], but confines every redirect hop to `trusted_origin` via
    /// [`TrustedPrefix::permits`] (origin equality plus a path-segment-boundary prefix check,
    /// e.g. against `https://api.nuget.org/v3/registration5-gz/`), and optionally sends a
    /// credential.
    ///
    /// This is the only cached API besides [`Self::get_cached_pinned`] that accepts a credential:
    /// the transport stops following before a cross-origin hop would ever be sent, so a header
    /// carrying a token cannot be forwarded to an attacker-controlled host by a hostile
    /// redirect. `auth` splits the cache by credential state — a credentialed body is stored
    /// under its own partition and never served to an anonymous request, even after the token
    /// is removed. `accept` is an optional content-negotiating `Accept` value.
    ///
    /// The block only surfaces as an error on a cold cache: like [`Self::get_cached`]'s own
    /// stale-while-revalidate fallback, a warm entry for `url` still returns the last
    /// known-good body instead of propagating a blocked-redirect `HttpStatus` from a
    /// revalidation attempt. A 401/403 on a credentialed revalidation evicts the entry instead.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::cache::{CredentialHeader, HttpCache, RequestAuth};
    /// use deps_core::net_policy::TrustedPrefix;
    /// use deps_core::secret::{Redacted, bearer_auth_header};
    ///
    /// # async fn example() -> deps_core::error::Result<()> {
    /// let cache = HttpCache::new();
    /// let prefix = TrustedPrefix::parse("https://index.mycorp.dev/").unwrap();
    /// let token = bearer_auth_header(&Redacted::new("secret-token".to_string()));
    /// let data = cache
    ///     .get_cached_trusted_origin(
    ///         "https://index.mycorp.dev/se/rd/serde",
    ///         &prefix,
    ///         RequestAuth::credential(CredentialHeader::Authorization(&token), &prefix),
    ///         None,
    ///     )
    ///     .await?;
    /// println!("Fetched {} bytes", data.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_cached_trusted_origin(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
    ) -> Result<Bytes> {
        self.get_cached_trusted_origin_response(
            url,
            trusted_origin,
            auth,
            accept,
            RevalidationFailure::ServeStale,
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached_trusted_origin`], but returns the whole [`CachedResponse`] (body
    /// plus `ETag`, `Last-Modified` and `Link`) instead of the body alone. For a caller that
    /// must inspect response headers, e.g. to detect a paginated list.
    ///
    /// `on_revalidation_failure` decides whether a failed revalidation of a stored entry
    /// serves that entry or fails the call.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached_trusted_origin`], plus the revalidation error under
    /// [`RevalidationFailure::Fail`].
    pub async fn get_cached_trusted_origin_response(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
        on_revalidation_failure: RevalidationFailure,
    ) -> Result<CachedResponse> {
        auth.ensure_within(url, trusted_origin)?;
        let transport = self.transport_for_origin(trusted_origin.as_str());
        let headers = wire_headers(&accept_headers(accept), &auth);
        self.get_cached_via(
            url,
            &headers,
            &transport,
            auth.key_auth(),
            on_revalidation_failure,
            auth.rate_limit(),
        )
        .await
    }

    /// Reads the stored entry of a credentialed [`Self::get_cached_trusted_origin`] request
    /// without sending anything, for a caller that must answer from the cache while it cannot
    /// obtain the credential (the offline Keychain case).
    ///
    /// Never touches the network and never consults the offline switch, so it cannot send an
    /// unauthenticated request for a credentialed resource whatever the switch says.
    ///
    /// # Errors
    ///
    /// Returns [`DepsError::Offline`] when nothing is stored under `partition`.
    pub fn peek_credentialed_trusted_origin(
        &self,
        url: &str,
        partition: CredentialPartition,
    ) -> Result<CachedResponse> {
        let key = self.cache_key(url, CacheTier::Baseline, KeyAuth::Credential(partition));
        self.entries
            .get(key.as_ref())
            .map(|entry| entry.clone())
            .ok_or_else(|| DepsError::Offline {
                url: RedactedUrl::new(url),
            })
    }

    /// Like [`Self::get_cached_trusted_origin`], but for an origin-pinned,
    /// connect-address-guarded `CacheTier::Pinned` transport (issue #561/#562) instead of the
    /// baseline-guarded one — the only sanctioned way to send a credential to a
    /// workspace-declared host. `auth` partitions the cache exactly as it does there.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_pinned(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
    ) -> Result<Bytes> {
        self.get_cached_pinned_response(
            url,
            trusted_origin,
            auth,
            accept,
            RevalidationFailure::ServeStale,
        )
        .await
        .map(|response| response.body)
    }

    /// Like [`Self::get_cached_pinned`], but returns the whole [`CachedResponse`] (body plus
    /// `ETag`, `Last-Modified` and `Link`) instead of the body alone.
    ///
    /// `on_revalidation_failure` decides whether a failed revalidation of a stored entry
    /// serves that entry or fails the call.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`], plus the revalidation error under
    /// [`RevalidationFailure::Fail`].
    pub async fn get_cached_pinned_response(
        &self,
        url: &str,
        trusted_origin: &TrustedPrefix,
        auth: RequestAuth<'_>,
        accept: Option<&'static str>,
        on_revalidation_failure: RevalidationFailure,
    ) -> Result<CachedResponse> {
        auth.ensure_within(url, trusted_origin)?;
        let transport = self.transport_for_pinned(trusted_origin.as_str());
        let headers = wire_headers(&accept_headers(accept), &auth);
        self.get_cached_via(
            url,
            &headers,
            &transport,
            auth.key_auth(),
            on_revalidation_failure,
            auth.rate_limit(),
        )
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
    /// [`Self::get_cached_trusted_origin`], which exists precisely to close this
    /// gap for a caller that needs it — so a cross-origin redirect hop to any other
    /// policy-permitted host is followed with `extra_headers` re-sent by reqwest's default
    /// redirect policy. **This method must never carry a credential.** Harmless for its
    /// current sole caller (a fixed `Accept` header), but directly load-bearing for any
    /// future auth-wiring work: reach for [`Self::get_cached_trusted_origin`]
    /// instead if a header ever needs to stay pinned to one origin.
    ///
    /// # Errors
    ///
    /// Same as [`Self::get_cached`].
    pub async fn get_cached_workspace_with_headers(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
    ) -> Result<Bytes> {
        #[expect(
            clippy::expect_used,
            reason = "poisoned only if another thread already panicked holding the lock — \
                      propagate via panic, matching RwLock's poisoning contract"
        )]
        let transport = self
            .workspace
            .read()
            .expect("workspace transport lock poisoned")
            .clone();
        self.get_cached_via(
            url,
            &wire_accept_headers(extra_headers),
            &transport,
            KeyAuth::ANONYMOUS,
            RevalidationFailure::ServeStale,
            RateLimitRevocation::default(),
        )
        .await
        .map(|response| response.body)
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
        #[expect(
            clippy::expect_used,
            reason = "poisoned only if another thread panicked while holding the lock — see \
                      the matching justification on get_cached_workspace_with_headers above"
        )]
        {
            *self
                .workspace
                .write()
                .expect("workspace transport lock poisoned") = rebuilt;
        }
        #[cfg(test)]
        self.workspace_rebuilds.fetch_add(1, Ordering::Relaxed);

        self.evict_entries_where(|key| key.starts_with(Self::PINNED_KEY_PREFIX));
        self.trusted_clients
            .retain(|(_, tier), _| !matches!(tier, CacheTier::Pinned { .. }));
    }

    /// The credential state in `auth` is meaningful only under [`CacheTier::Pinned`] and
    /// [`CacheTier::Baseline`] — every other tier ignores it (see [`Self::cache_key`]'s docs).
    #[tracing::instrument(
        name = "get_cached_via",
        skip(self, extra_headers, transport, auth, on_revalidation_failure, rate_limit),
        fields(url = %RedactedUrl::new(url), cache = tracing::field::Empty)
    )]
    async fn get_cached_via(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        auth: KeyAuth,
        on_revalidation_failure: RevalidationFailure,
        rate_limit: RateLimitRevocation,
    ) -> Result<CachedResponse> {
        if self.entries.len() >= MAX_CACHE_ENTRIES
            || self.total_bytes.load(Ordering::Relaxed) >= MAX_CACHE_BYTES
        {
            self.evict_entries();
        }

        let offline = self.is_offline();
        // `offline` forces `cache_enabled` true (S1 fix): otherwise `cache.enabled: false`
        // would leave nothing to serve offline for a URL fetched while caching was disabled.
        // See `Self::set_offline`'s docs.
        let cache_enabled = self.cache_enabled.load(Ordering::Relaxed) || offline;

        // Computed once and threaded through every call — recomputing mid-request could read
        // and write under different keys (see `Self::cache_key`'s docs).
        let cache_key = self.cache_key(url, transport.tier, auth);

        if !cache_enabled {
            // Explicit, not `Empty`: an empty `cache` field would be indistinguishable from
            // broken instrumentation (#756 S3) on a path that's neither a hit nor a miss.
            tracing::Span::current().record("cache", "disabled");
            return self
                .transport_only_response_via(url, extra_headers, BodyLimit::DEFAULT, transport)
                .await;
        }

        // Clone+drop the Ref immediately: holding it across `.await` can deadlock a concurrent
        // task needing write access to the same shard.
        if let Some(cached) = self.entries.get(cache_key.as_ref()).map(|r| r.clone()) {
            if offline {
                // Skips the conditional-request attempt: `ensure_online` would block it and
                // fall back to this same body anyway, just with a spurious warn + wasted
                // allocation. The only branch below that is a genuine zero-network "hit"
                // (#756 S3); every other branch still issued a request.
                tracing::Span::current().record("cache", "hit");
                return Ok(cached);
            }
            match self
                .conditional_request_with_headers(
                    url,
                    &cached,
                    extra_headers,
                    transport,
                    &cache_key,
                )
                .await
            {
                // 304: a round trip happened but no body was re-transferred — distinct from
                // `hit` (no request) and `refreshed` (full re-fetch).
                Ok(None) => {
                    tracing::Span::current().record("cache", "revalidated");
                    return Ok(cached);
                }
                // Stale entry cost a full re-fetch, same as a miss — must not report as a hit.
                Ok(Some(refreshed)) => {
                    tracing::Span::current().record("cache", "refreshed");
                    return Ok(refreshed);
                }
                Err(e) => {
                    debug_assert!(
                        !matches!(
                            &e,
                            DepsError::RateLimited {
                                source_status: None,
                                ..
                            }
                        ),
                        "a RateLimited reaching this eviction guard must always carry \
                         source_status — only http_status_error's confirmed-evidence branch \
                         produces RateLimited here; None would silently bypass FR-015/NFR-004 \
                         eviction on a genuine 401/403 credential-revocation signal"
                    );
                    // FR-015/NFR-004: a 401/403 revalidation of a *credentialed* entry
                    // must evict rather than serve the possibly-revoked
                    // credential's last-known-good body — an anonymous request keeps the
                    // stale-while-revalidate fallback unchanged.
                    //
                    // On a pinned tier, `RateLimited { source_status: Some(401 | 403), .. }`
                    // evicts too (see `RateLimitRevocation::revokes_credential`)
                    // (#1295 critic C1): `e` is always this match's own
                    // `conditional_request_with_headers`'s `Err`, whose only source of that
                    // variant is `http_status_error`'s confirmed-evidence branch — without this
                    // arm, a confirmed-evidence 403 would silently bypass eviction and keep
                    // serving the possibly-revoked credential's stale body. Deliberately
                    // narrowed to `source_status` 401/403 only, not a bare `RateLimited { .. }`
                    // (critic N1 regression fix): `confirmed_rate_limit_exhaustion` also
                    // classifies a 429 this way, but a 429 is mere throttling, not a
                    // credential-revocation signal — NFR-004's scope is "401/403", and evicting
                    // on 429 would drop a still-good cached body the client can no longer
                    // re-fetch until the throttle clears, purely because of a signal unrelated
                    // to the credential's validity.
                    if auth.is_credentialed() && rate_limit.revokes_credential(&e) {
                        if let Some((_, old)) = self.entries.remove(cache_key.as_ref()) {
                            self.total_bytes
                                .fetch_sub(old.body.len(), Ordering::Relaxed);
                        }
                        tracing::Span::current().record("cache", "evicted");
                        // #756 round 2 S1: never interpolate `e` — its `Display`/`Debug` embed
                        // the raw unredacted `url`, defeating this span's `RedactedUrl` field.
                        // `safe_tracing_summary` extracts only the safe status+cause instead.
                        let (status, cause) = e.safe_tracing_summary();
                        tracing::warn!(
                            status = ?status,
                            cause,
                            "evicting authenticated cache entry after revalidation failure"
                        );
                        return Err(e);
                    }
                    if on_revalidation_failure == RevalidationFailure::Fail {
                        tracing::Span::current().record("cache", "revalidation-failed");
                        return Err(e);
                    }
                    tracing::Span::current().record("cache", "stale-fallback");
                    // Same rationale as above: no `e` interpolation.
                    let (status, cause) = e.safe_tracing_summary();
                    tracing::warn!(
                        status = ?status,
                        cause,
                        "conditional request failed, using cache"
                    );
                    return Ok(cached);
                }
            }
        }

        tracing::Span::current().record("cache", "miss");
        self.fetch_and_store_with_headers(url, extra_headers, transport, &cache_key)
            .await
    }

    /// Performs conditional HTTP request using cached validation headers.
    ///
    /// Sends `If-None-Match` (ETag) and/or `If-Modified-Since` headers
    /// to check if the cached content is still valid.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(CachedResponse))` - Server returned 200 OK with new content
    /// - `Ok(None)` - Server returned 304 Not Modified (cache is valid)
    /// - `Err(_)` - Network or HTTP error occurred
    async fn conditional_request_with_headers(
        &self,
        url: &str,
        cached: &CachedResponse,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        cache_key: &str,
    ) -> Result<Option<CachedResponse>> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        transport.preflight(url).await?;
        let mut request = apply_request_headers(transport.client.get(url), extra_headers);
        if let Some(etag) = &cached.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &cached.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
        }

        let response = request.send().await.map_err(|e| send_error(url, e))?;

        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;
        let fresh = validators.into_response(body);
        self.store_entry(cache_key.to_string(), fresh.clone());

        Ok(Some(fresh))
    }

    /// Fetches a fresh response from the network and stores it in the cache.
    ///
    /// This method bypasses the cache and always makes a network request.
    /// The response is stored with its ETag and Last-Modified headers for
    /// future conditional requests.
    ///
    /// # Errors
    ///
    /// Returns `DepsError::HttpStatus` if the server returns a non-2xx status code
    /// (or `DepsError::RateLimited` when that status is a 403 with confirmed
    /// `X-RateLimit-Remaining: 0` evidence — see [`http_status_error`], #1295),
    /// `DepsError::RegistryError` if the network request fails, or
    /// `DepsError::ResponseTooLarge` if the response body exceeds the
    /// configured size cap.
    async fn fetch_and_store_with_headers(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        transport: &Transport,
        cache_key: &str,
    ) -> Result<CachedResponse> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        transport.preflight(url).await?;
        // #756 security follow-up (S-A): `RedactedUrl`, not the raw `url` — this is the
        // direct callee of the now-hardened `get_cached_via`, and at `debug`
        // level, which is this project's own continuous-improvement convention
        // (`RUST_LOG=debug`).
        tracing::debug!(
            extra_headers = extra_headers.len(),
            "fetching fresh: {}",
            RedactedUrl::new(url)
        );

        let request = apply_request_headers(transport.client.get(url), extra_headers);

        let response = request.send().await.map_err(|e| send_error(url, e))?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, BodyLimit::DEFAULT).await?;
        let fresh = validators.into_response(body);
        self.store_entry(cache_key.to_string(), fresh.clone());

        Ok(fresh)
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
    pub async fn post_json<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<Bytes> {
        self.post_json_via(url, body, BodyLimit::DEFAULT, &self.baseline)
            .await
    }

    /// Same as [`Self::post_json`], but additionally takes an explicit [`BodyLimit`]
    /// (rather than the hardcoded [`BodyLimit::DEFAULT`]) and confines every redirect hop to
    /// `trusted_origin` via [`crate::net_policy::is_trusted_prefix`] — the same guarantee
    /// [`Self::get_transport_only_with_headers_limited_trusted_origin`] gives the GET path.
    ///
    /// [`Self::post_json`] itself has neither of these: it sends through
    /// `Self::baseline`'s client (the generic, non-origin-pinned redirect policy) and
    /// always caps the response at [`BodyLimit::DEFAULT`] (32 MiB) regardless of how much
    /// smaller a caller's own payloads actually are — a gap for a caller (deps.dev's GOSSIP
    /// batch endpoint) whose response is expected to be a few KB and whose request body
    /// carries every declared dependency's name, where an unconfined redirect is a bigger
    /// concern than for `post_json`'s existing callers.
    ///
    /// # Errors
    ///
    /// Same as [`Self::post_json`].
    pub async fn post_json_limited_trusted_origin<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
        limit: BodyLimit,
        trusted_origin: &str,
    ) -> Result<Bytes> {
        let transport = self.transport_for_origin(trusted_origin);
        self.post_json_via(url, body, limit, &transport).await
    }

    /// Shared POST body for [`Self::post_json`] and [`Self::post_json_limited_trusted_origin`]
    /// — mirrors [`Self::transport_only_via`]'s role on the GET path exactly: both public POST
    /// methods differ only in which `client` (origin-pinned or not) and [`BodyLimit`] they pass
    /// in, so this is the single place that sends the request, checks the status, and reads the
    /// capped body.
    ///
    /// # Errors
    ///
    /// Same as [`Self::post_json`].
    #[tracing::instrument(
        skip(self, body, transport),
        fields(url = %RedactedUrl::new(url))
    )]
    async fn post_json_via<T: Serialize + Sync + ?Sized>(
        &self,
        url: &str,
        body: &T,
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<Bytes> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        transport.preflight(url).await?;

        let response = transport
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| send_error(url, e))?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        read_body_capped(url, response, limit).await
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
        extra_headers: &[RequestHeader],
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
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
    ) -> Result<Bytes> {
        self.transport_only_via(url, extra_headers, limit, &self.baseline)
            .await
    }

    /// Same as [`Self::get_transport_only_with_headers_limited`], but additionally
    /// stops any redirect hop that does not match `trusted_origin` via
    /// [`crate::net_policy::is_trusted_prefix`]
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
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
        trusted_origin: &str,
    ) -> Result<Bytes> {
        let transport = self.transport_for_origin(trusted_origin);
        self.transport_only_via(url, extra_headers, limit, &transport)
            .await
    }

    /// Note: "transport" here means "bypasses the entry-map cache" (see this method's
    /// callers' docs) — a different axis from the [`Transport`] type, which pairs a `Client`
    /// with its [`CacheTier`]. The name predates that type and is kept as-is to avoid
    /// churning every `get_transport_only*` call site for a naming collision that causes no
    /// actual ambiguity at the call sites themselves.
    #[tracing::instrument(
        skip(self, extra_headers, limit, transport),
        fields(url = %RedactedUrl::new(url))
    )]
    async fn transport_only_via(
        &self,
        url: &str,
        extra_headers: &[RequestHeader],
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<Bytes> {
        self.transport_only_response_via(url, &wire_accept_headers(extra_headers), limit, transport)
            .await
            .map(|response| response.body)
    }

    /// [`Self::transport_only_via`] that also keeps the response validators and `Link` header.
    async fn transport_only_response_via(
        &self,
        url: &str,
        extra_headers: &[WireHeader<'_>],
        limit: BodyLimit,
        transport: &Transport,
    ) -> Result<CachedResponse> {
        self.ensure_online(url)?;
        ensure_https(url)?;
        transport.preflight(url).await?;

        let request = apply_request_headers(transport.client.get(url), extra_headers);

        let response = request.send().await.map_err(|e| send_error(url, e))?;

        if !response.status().is_success() {
            return Err(http_status_error(
                url,
                response.status(),
                response.headers(),
            ));
        }

        let validators = ResponseValidators::from_headers(response.headers());
        let body = read_body_capped(url, response, limit).await?;
        Ok(validators.into_response(body))
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

    /// Drops every baseline-tier entry whose URL starts with `url_prefix`, returning how many.
    ///
    /// For a caller whose request credential or trust changed: drops bare-URL entries and
    /// `auth_id`-partitioned ones alike, as memory hygiene for bodies fetched under a state that
    /// no longer applies.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::cache::HttpCache;
    ///
    /// assert_eq!(HttpCache::new().evict_url_prefix("https://registry.example/api/"), 0);
    /// ```
    pub fn evict_url_prefix(&self, url_prefix: &str) -> usize {
        self.evict_entries_where(|key| {
            let url = if key.starts_with(Self::BASELINE_AUTH_KEY_PREFIX) {
                key.get(Self::BASELINE_AUTH_KEY_HEAD_LEN..)
            } else {
                Some(key)
            };
            url.is_some_and(|url| url.starts_with(url_prefix))
        })
    }

    /// Removes every entry whose key satisfies `matches`, keeping [`Self::total_bytes`] in sync;
    /// returns how many were removed.
    fn evict_entries_where(&self, matches: impl Fn(&str) -> bool) -> usize {
        let mut freed_bytes = 0usize;
        let mut evicted = 0usize;
        self.entries.retain(|key, value| {
            let drop_entry = matches(key);
            if drop_entry {
                freed_bytes += value.body.len();
                evicted += 1;
            }
            !drop_entry
        });
        self.total_bytes.fetch_sub(freed_bytes, Ordering::Relaxed);
        evicted
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
    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn get_for_bench(&self, url: &str) -> Option<Bytes> {
        self.entries.get(url).map(|entry| entry.body.clone())
    }

    /// Benchmark-only helper: Direct cache insertion.
    #[cfg(feature = "test-util")]
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
    use std::assert_matches;

    use super::*;
    use crate::net_policy::PrivateRegistryAllowlist;
    use crate::secret::bearer_auth_header;

    fn bearer(token: &str) -> AuthorizationValue {
        bearer_auth_header(&Redacted::new(token.to_string()))
    }

    fn workspace_guard(level: WorkspaceRegistryAccess, allowlist: &[&str]) -> AddrGuard {
        AddrGuard::WorkspaceDeclared(AccessSnapshot {
            level,
            allowlist: Arc::new(PrivateRegistryAllowlist::for_test(allowlist)),
        })
    }

    fn authorization(token: &AuthorizationValue) -> WireHeader<'_> {
        WireHeader::Credential(CredentialHeader::Authorization(token))
    }

    fn test_token() -> &'static AuthorizationValue {
        static TOKEN: std::sync::OnceLock<AuthorizationValue> = std::sync::OnceLock::new();
        TOKEN.get_or_init(|| bearer("test-token"))
    }

    fn cred_in(partition: u64) -> RequestAuth<'static> {
        RequestAuth::credential_in(
            CredentialHeader::Authorization(test_token()),
            CredentialPartition::new(partition),
        )
    }

    fn prefix(raw: &str) -> TrustedPrefix {
        TrustedPrefix::parse(raw).unwrap()
    }

    fn credential<'a>(token: &'a AuthorizationValue, prefix: &TrustedPrefix) -> RequestAuth<'a> {
        RequestAuth::credential(CredentialHeader::Authorization(token), prefix)
    }

    #[test]
    fn test_apply_request_headers_marks_authorization_sensitive_on_built_request() {
        let client = Client::new();
        let token = bearer("secret-token");
        let request = apply_request_headers(
            client.get("https://example.com/"),
            &[
                WireHeader::Accept("application/json"),
                authorization(&token),
            ],
        )
        .build()
        .unwrap();

        let auth = request.headers().get(header::AUTHORIZATION).unwrap();
        assert!(auth.is_sensitive());
        assert_eq!(auth, "Bearer secret-token");
        assert!(
            !request
                .headers()
                .get(header::ACCEPT)
                .unwrap()
                .is_sensitive()
        );
        assert!(!format!("{:?}", request.headers()).contains("secret-token"));
    }

    #[test]
    fn test_apply_request_headers_marks_private_token_sensitive_on_built_request() {
        let client = Client::new();
        let token = Redacted::new("glpat-secret".to_string());
        let request = apply_request_headers(
            client.get("https://example.com/"),
            &[WireHeader::Credential(
                CredentialHeader::GitlabPrivateToken(&token),
            )],
        )
        .build()
        .unwrap();

        let value = request.headers().get("private-token").unwrap();
        assert!(value.is_sensitive());
        assert!(!format!("{:?}", request.headers()).contains("glpat-secret"));
    }

    #[test]
    fn test_apply_request_headers_invalid_credential_value_fails_the_build() {
        let client = Client::new();
        let token = bearer("bad\nvalue");
        let result =
            apply_request_headers(client.get("https://example.com/"), &[authorization(&token)])
                .build();

        let error = result.unwrap_err();
        assert!(!error.to_string().contains("bad"), "{error}");
    }

    // Guards the non-loopback path of `ensure_https`: every other test in this
    // module reaches it only through loopback `mockito` URLs, so without this
    // test the "reject any other HTTP host" branch would never run.
    #[test]
    fn test_ensure_https_rejects_non_loopback_http() {
        assert!(ensure_https("http://example.com").is_err());
    }

    /// #767 M2: `ensure_https`'s `CacheError` used to bake the raw rejected URL in
    /// verbatim, the same message-level leak class fixed in `deps-cargo::sparse`'s
    /// fail-closed log on the same `window/showMessage` path.
    #[test]
    fn test_ensure_https_rejection_message_redacts_query_string() {
        let err = ensure_https("http://example.com/pkg?token=super-secret-value").unwrap_err();
        assert!(
            !err.to_string().contains("super-secret-value"),
            "err: {err}"
        );
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

    // #1562: a naive `:`-split misread userinfo as the host boundary, so a loopback-looking
    // userinfo let a plain-HTTP request to a public host slip past the HTTPS requirement.
    #[test]
    fn test_ensure_https_rejects_userinfo_spoofed_loopback() {
        assert!(ensure_https("http://localhost:80@evil.com/x").is_err());
        assert!(ensure_https("http://localhost:@evil.com/").is_err());
    }

    // reqwest's `Attempt` has no public constructor, so the redirect closure can't be
    // unit-tested directly; this exercises the pure detection logic it delegates to (mockito is
    // http-only, so an actual https->http redirect isn't testable end-to-end here).
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
        assert_matches!(
            validate_resolved_addrs("evil.example", addrs, &AddrGuard::Baseline),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    // FR-003: an attacker's public A record alongside a blocked one must not keep the probe
    // alive — the whole resolution is rejected, not filtered down to the public address.
    #[test]
    fn test_validate_resolved_addrs_blocks_when_any_address_is_blocked() {
        let addrs = vec![
            "1.1.1.1:0".parse().unwrap(),
            "169.254.169.254:0".parse().unwrap(),
        ];
        assert_matches!(
            validate_resolved_addrs("evil.example", addrs, &AddrGuard::Baseline),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    #[test]
    fn test_validate_resolved_addrs_allows_global() {
        let addrs = vec!["1.1.1.1:0".parse().unwrap()];
        assert_eq!(
            validate_resolved_addrs("index.crates.io", addrs.clone(), &AddrGuard::Baseline)
                .unwrap(),
            addrs
        );
    }

    // NFR-004: fail-closed on an empty resolution rather than silently treating "nothing
    // resolved" as "nothing to block".
    #[test]
    fn test_validate_resolved_addrs_fails_closed_on_empty() {
        assert_matches!(
            validate_resolved_addrs("evil.example", vec![], &AddrGuard::Baseline),
            Err(ResolveGuardError::NoAddresses { .. })
        );
    }

    #[test]
    fn test_validate_resolved_addrs_unwraps_mapped_v4() {
        let addrs = vec!["[::ffff:169.254.169.254]:0".parse().unwrap()];
        assert_matches!(
            validate_resolved_addrs("evil.example", addrs, &AddrGuard::Baseline),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    // Issue #455, test-plan item 1: under `Baseline`, an RFC1918/CGNAT/unique-local address is
    // allowed (today's pre-#455 behavior) — only `never_a_registry` classes are blocked.
    #[test]
    fn test_validate_resolved_addrs_baseline_allows_private_ranges() {
        for addr_str in ["10.0.0.1:0", "100.64.0.1:0", "[fc00::1]:0"] {
            let addrs = vec![addr_str.parse().unwrap()];
            assert!(
                validate_resolved_addrs("corp.example", addrs, &AddrGuard::Baseline).is_ok(),
                "{addr_str} must be allowed under Baseline"
            );
        }
    }

    // Issue #455, test-plan item 1: under `WorkspaceDeclared(PublicOnly)`, every RFC1918/CGNAT/
    // unique-local address is blocked, while a `Global` address is still allowed.
    #[test]
    fn test_validate_resolved_addrs_workspace_public_only_blocks_private_ranges() {
        let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
        for addr_str in ["10.0.0.1:0", "100.64.0.1:0", "[fc00::1]:0"] {
            let addrs = vec![addr_str.parse().unwrap()];
            assert_matches!(
                validate_resolved_addrs("evil.example", addrs, &guard),
                Err(ResolveGuardError::Blocked { .. }),
                "{addr_str} must be blocked under WorkspaceDeclared(PublicOnly)"
            );
        }

        let global = vec!["1.1.1.1:0".parse().unwrap()];
        assert!(validate_resolved_addrs("index.crates.io", global, &guard).is_ok());
    }

    // Test-plan item 2: `WorkspaceDeclared(All)` admits a private-range address.
    #[test]
    fn test_validate_resolved_addrs_workspace_all_allows_private_ranges() {
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &["10.0.0.0/8"]);
        let addrs = vec!["10.0.0.1:0".parse().unwrap()];
        assert!(validate_resolved_addrs("corp.example", addrs, &guard).is_ok());
        let outside = vec!["192.168.0.1:0".parse().unwrap()];
        assert_matches!(
            validate_resolved_addrs("corp.example", outside, &guard),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    #[test]
    fn test_validate_resolved_addrs_workspace_all_without_allowlist_blocks_private_ranges() {
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &[]);
        let addrs = vec!["10.0.0.1:0".parse().unwrap()];
        assert_matches!(
            validate_resolved_addrs("corp.example", addrs, &guard),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    #[test]
    fn test_validate_resolved_addrs_hostname_entry_vouches_only_for_itself() {
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &["registry.corp.example"]);
        let addrs = vec!["10.0.0.1:0".parse().unwrap()];
        assert!(validate_resolved_addrs("registry.corp.example", addrs.clone(), &guard).is_ok());
        assert_matches!(
            validate_resolved_addrs("rebinder.example", addrs, &guard),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    #[test]
    fn test_validate_resolved_addrs_never_a_registry_blocked_under_matching_allowlist() {
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &["169.254.0.0/16"]);
        let addrs = vec!["169.254.169.254:0".parse().unwrap()];
        assert_matches!(
            validate_resolved_addrs("corp.example", addrs, &guard),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    // Test-plan item 2: `WorkspaceDeclared(Off)` rejects even a `Global` address.
    #[test]
    fn test_validate_resolved_addrs_workspace_off_rejects_global() {
        let guard = workspace_guard(WorkspaceRegistryAccess::Off, &[]);
        let addrs = vec!["1.1.1.1:0".parse().unwrap()];
        assert_matches!(
            validate_resolved_addrs("index.crates.io", addrs, &guard),
            Err(ResolveGuardError::Blocked { .. })
        );
    }

    // Test-plan item 3: `build_guarded_client_with_lookup` shares `build_client_inner` with the
    // production `build_guarded_client`, so deleting the `.dns_resolver(...)` wiring from that
    // shared function fails this test too, not just the production-path wiring test above. The
    // synthetic lookup returns an RFC1918 address, resolved (not connected — the resolver
    // guard rejects before any TCP attempt) purely through the built `Client`.
    #[tokio::test]
    async fn test_build_guarded_client_with_lookup_blocks_private_range_under_workspace_tier() {
        let lookup = TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]));
        let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
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

    #[tokio::test]
    async fn test_send_error_maps_gated_class_to_host_blocked_by_policy() {
        let lookup = TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]));
        let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
        let client = build_guarded_client_with_lookup(guard, lookup);
        let url = "https://corp.example/index";
        let error = client.get(url).send().await.unwrap_err();
        match send_error(url, error) {
            DepsError::HostBlockedByPolicy { class, .. } => {
                assert_eq!(class, crate::net_policy::HostClass::PrivateV4);
            }
            other => panic!("expected HostBlockedByPolicy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_send_error_maps_never_a_registry_class_under_baseline() {
        let lookup = TestLookup(Arc::new(|_host: &str| {
            vec!["169.254.169.254:0".parse().unwrap()]
        }));
        let client = build_guarded_client_with_lookup(AddrGuard::Baseline, lookup);
        let url = "https://rebound.example/index";
        let error = client.get(url).send().await.unwrap_err();
        let mapped = send_error(url, error);
        assert_matches!(
            mapped,
            DepsError::HostBlockedByPolicy {
                class: crate::net_policy::HostClass::LinkLocal
                    | crate::net_policy::HostClass::CloudMetadata,
                ..
            },
            "{mapped:?}"
        );
    }

    #[tokio::test]
    async fn test_send_error_keeps_no_addresses_as_registry_error() {
        let lookup = TestLookup(Arc::new(|_host: &str| Vec::new()));
        let client = build_guarded_client_with_lookup(AddrGuard::Baseline, lookup);
        let url = "https://empty.example/index";
        let error = client.get(url).send().await.unwrap_err();
        assert_matches!(send_error(url, error), DepsError::RegistryError { .. });
    }

    #[tokio::test]
    async fn test_get_cached_surfaces_loopback_name_as_host_blocked_by_policy() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/")
            .with_status(200)
            .create_async()
            .await;
        let port = server.socket_address().port();
        let cache = HttpCache::new();
        let result: Result<Bytes> = cache.get_cached(&format!("http://localhost:{port}/")).await;
        assert_matches!(
            result,
            Err(DepsError::HostBlockedByPolicy {
                class: crate::net_policy::HostClass::Loopback,
                ..
            }),
            "{result:?}"
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
        let resolver = BlockedAddrResolver::with_lookup(AddrGuard::Baseline, Arc::from([]), lookup);
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

        let addrs = BlockedAddrResolver::new(AddrGuard::Baseline, Arc::from([]))
            .resolve("localhost".parse().unwrap())
            .await;
        assert!(addrs.is_err());
    }

    // Issue #449 critic S1: the prior version called `BlockedAddrResolver::resolve` directly and
    // never went through `build_guarded_client`, so deleting `.dns_resolver(...)` from
    // `build_client_inner` left it green. This proves actual wiring: a real mockito listener
    // answers on `server.socket_address()`'s port, reached via the `localhost` *name* so the
    // request actually reaches the configured resolver (unlike an IP literal — see
    // `BlockedAddrResolver`'s `# Known limitations` doc).
    #[tokio::test]
    async fn test_build_client_wires_in_blocked_addr_resolver() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/")
            .with_status(200)
            .create_async()
            .await;
        let port = server.socket_address().port();

        let client = Transport::baseline().client;
        let result = client.get(format!("http://localhost:{port}/")).send().await;

        let err = result.expect_err(
            "expected the wired-in resolver guard to reject a loopback-resolving name even \
             though a real listener answers at this port",
        );
        // `Debug` (unlike `Display`) surfaces the boxed source chain, confirming
        // `ResolveGuardError::Blocked` produced the error rather than an unrelated failure.
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

        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
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

    // Issue #455, test-plan item 4(a): loopback -> loopback. `Baseline` follows the hop
    // (test-cfg carve-out for `Loopback`); `WorkspaceDeclared(PublicOnly)` stops it since
    // `PublicOnly.allows(Loopback) == false` — the contrast proving the tier split is real.
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
        let result: CachedResponse = cache
            .get_cached_via(
                &source_url,
                &[],
                &Transport::baseline(),
                KeyAuth::ANONYMOUS,
                RevalidationFailure::ServeStale,
                RateLimitRevocation::default(),
            )
            .await
            .unwrap();
        assert_eq!(result.body.as_ref(), b"redirected data");

        let policy = Arc::new(RegistryAccessPolicy::new(
            WorkspaceRegistryAccess::PublicOnly,
        ));
        let workspace_cache = HttpCache::with_policy(Arc::clone(&policy));
        let result: Result<CachedResponse> = workspace_cache
            .get_cached_via(
                &source_url,
                &[],
                &Transport::workspace(&policy),
                KeyAuth::ANONYMOUS,
                RevalidationFailure::ServeStale,
                RateLimitRevocation::default(),
            )
            .await;
        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
            "expected the workspace transport to stop the loopback hop, got {result:?}"
        );
    }

    // Issue #455, test-plan item 4(b): a workspace-blocked literal. The redirect-policy tier
    // term rejects an RFC1918-literal target from its URL string alone (no resolver involved),
    // so the caller sees `HttpStatus{302}` with no `HTTP_TIMEOUT_SECS` stall.
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
        let result: Result<CachedResponse> = cache
            .get_cached_via(
                &source_url,
                &[],
                &Transport::workspace(&policy),
                KeyAuth::ANONYMOUS,
                RevalidationFailure::ServeStale,
                RateLimitRevocation::default(),
            )
            .await;

        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
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
            .get_cached_trusted_origin(
                &source_url,
                &prefix(&trusted_origin),
                RequestAuth::ANONYMOUS,
                None,
            )
            .await;

        // The stopped redirect surfaces as the 302 response, like any other non-2xx status.
        // `matches!` rather than debug-formatting `result`: the `Ok` arm holds the raw body.
        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
            "expected HttpStatus(302)"
        );

        // Proves the escape origin was never contacted, not just that the result is a 302.
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
            .get_cached_trusted_origin(
                &source_url,
                &prefix(&trusted_origin),
                RequestAuth::ANONYMOUS,
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"trusted data");
    }

    /// Issue #795: a raw `str::starts_with` prefix test (the pre-fix behavior) is satisfied
    /// by a subdomain-suffix bypass — `gitlab.mycorp.dev.evil.com` starts with
    /// `https://gitlab.mycorp.dev` as a string, even though its actual host is
    /// `gitlab.mycorp.dev.evil.com`, entirely under attacker control. Parsed-origin equality
    /// must reject it.
    #[test]
    fn test_is_trusted_origin_rejects_subdomain_suffix_bypass() {
        let trusted = Url::parse("https://gitlab.mycorp.dev").unwrap();
        let hop = Url::parse("https://gitlab.mycorp.dev.evil.com/steal").unwrap();
        assert!(!is_trusted_origin(&hop, Some(&trusted)));
    }

    /// Issue #795: a userinfo bypass — `https://gitlab.mycorp.dev@evil.com/...` also starts
    /// with the trusted origin as a string, but its host is `evil.com`; `gitlab.mycorp.dev`
    /// is merely a (discarded) username. `Url::origin()` ignores userinfo entirely, so this
    /// must be rejected.
    #[test]
    fn test_is_trusted_origin_rejects_userinfo_bypass() {
        let trusted = Url::parse("https://gitlab.mycorp.dev").unwrap();
        let hop = Url::parse("https://gitlab.mycorp.dev@evil.com/steal").unwrap();
        assert!(!is_trusted_origin(&hop, Some(&trusted)));
    }

    /// Issue #795: a hyphen-suffix bypass — `gitlab.mycorp.dev-evil.com` again starts with
    /// the trusted origin as a string while being an entirely distinct, attacker-controlled
    /// host.
    #[test]
    fn test_is_trusted_origin_rejects_hyphen_suffix_bypass() {
        let trusted = Url::parse("https://gitlab.mycorp.dev").unwrap();
        let hop = Url::parse("https://gitlab.mycorp.dev-evil.com/steal").unwrap();
        assert!(!is_trusted_origin(&hop, Some(&trusted)));
    }

    /// Companion to the three bypass-rejection tests above: the legitimate same-origin case
    /// (a different path, same scheme/host/port) must still be accepted.
    #[test]
    fn test_is_trusted_origin_accepts_exact_origin_match() {
        let trusted = Url::parse("https://gitlab.mycorp.dev").unwrap();
        let hop = Url::parse("https://gitlab.mycorp.dev/api/v4/x").unwrap();
        assert!(is_trusted_origin(&hop, Some(&trusted)));
    }

    /// A `trusted_origin` that fails to parse must fail closed — every hop is rejected,
    /// never treated as "no restriction".
    #[test]
    fn test_is_trusted_origin_rejects_when_trusted_origin_unparseable() {
        let hop = Url::parse("https://gitlab.mycorp.dev/api/v4/x").unwrap();
        assert!(!is_trusted_origin(&hop, None));
    }

    /// Path-prefix scoping (NuGet's registration-hive/flat-container pinning) must survive
    /// the #795 origin-equality fix: same origin, but a hop outside the trusted path, is
    /// still rejected — this is what `test_get_cached_trusted_origin_rejects_sibling_path_prefix`
    /// exercises end-to-end; this is the same property pinned at the unit level.
    #[test]
    fn test_is_trusted_origin_rejects_same_origin_sibling_path() {
        let trusted = Url::parse("https://registry.example/v3/registration5-gz/").unwrap();
        let hop = Url::parse("https://registry.example/v3/registration5-gzX/evil").unwrap();
        assert!(!is_trusted_origin(&hop, Some(&trusted)));
    }

    /// Companion: same origin, hop path under the trusted path prefix, is still accepted.
    #[test]
    fn test_is_trusted_origin_accepts_same_origin_nested_path() {
        let trusted = Url::parse("https://registry.example/v3/registration5-gz/").unwrap();
        let hop =
            Url::parse("https://registry.example/v3/registration5-gz/serde/page1.json").unwrap();
        assert!(is_trusted_origin(&hop, Some(&trusted)));
    }

    /// Issue #795 S1: unlike the two trailing-slash tests above (which, with a trailing `/`
    /// already present in the trusted path, would have passed even under the pre-S1-fix raw
    /// `str::starts_with` check — they do not actually exercise the segment-boundary fix),
    /// `RegistryIndex::as_str()` (`deps-cargo`'s sparse-index trusted origin) carries **no**
    /// trailing-slash guarantee. This reproduces that exact shape and the critic's repro: a
    /// same-origin sibling whose path merely shares a textual prefix must still be rejected.
    #[test]
    fn test_is_trusted_origin_rejects_same_origin_sibling_path_no_trailing_slash() {
        let trusted = Url::parse("https://artifacts.corp/cargo/index").unwrap();
        for sibling in [
            "https://artifacts.corp/cargo/index-public/steal",
            "https://artifacts.corp/cargo/indexEVIL",
            "https://artifacts.corp/cargo/index.evil/x",
        ] {
            let hop = Url::parse(sibling).unwrap();
            assert!(
                !is_trusted_origin(&hop, Some(&trusted)),
                "expected {sibling} to be rejected"
            );
        }
    }

    /// Companion: the trusted path itself, and a proper child path, are still accepted when
    /// the trusted path carries no trailing slash — the real `deps-cargo` request shape
    /// (`sparse_index_url` appends `/{crate_path}` to the trimmed base).
    #[test]
    fn test_is_trusted_origin_accepts_self_and_child_no_trailing_slash() {
        let trusted = Url::parse("https://artifacts.corp/cargo/index").unwrap();
        let itself = Url::parse("https://artifacts.corp/cargo/index").unwrap();
        let child = Url::parse("https://artifacts.corp/cargo/index/se/rd/serde").unwrap();
        assert!(is_trusted_origin(&itself, Some(&trusted)));
        assert!(is_trusted_origin(&child, Some(&trusted)));
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
            .get_cached_trusted_origin(
                &source_url,
                &prefix(&trusted_origin),
                RequestAuth::ANONYMOUS,
                None,
            )
            .await;

        // matches! rather than debug-formatting result: the Ok arm holds the raw body.
        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
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
            .get_cached_trusted_origin(
                &source_url,
                &prefix(&trusted_origin),
                RequestAuth::ANONYMOUS,
                None,
            )
            .await;

        // matches! rather than debug-formatting result: the Ok arm holds the raw body.
        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
            "expected HttpStatus(302)"
        );
        escape.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_cached_trusted_origin_credential_sends_extra_header() {
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
        let token = bearer("secret-token");
        let result: Bytes = cache
            .get_cached_trusted_origin(
                &url,
                &prefix(&trusted_origin),
                credential(&token, &prefix(&trusted_origin)),
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"authenticated data");
    }

    #[tokio::test]
    async fn test_gitlab_private_token_header_is_sent_verbatim() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let m = server
            .mock("GET", "/api/data")
            .match_header("private-token", "glpat-secret")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let token = Redacted::new("glpat-secret".to_string());
        let url = format!("{}/api/data", server.url());
        HttpCache::new()
            .get_cached_trusted_origin(
                &url,
                &prefix(&trusted_origin),
                RequestAuth::credential(
                    CredentialHeader::GitlabPrivateToken(&token),
                    &prefix(&trusted_origin),
                ),
                None,
            )
            .await
            .unwrap();
        m.assert_async().await;
    }

    // A credential header must never survive a cross-origin redirect hop — proven by the
    // escape origin never being contacted, not just the header being absent on a landed request.
    #[tokio::test]
    async fn test_get_cached_trusted_origin_credential_stops_cross_origin_redirect() {
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
            .get_cached_trusted_origin(
                &source_url,
                &prefix(&trusted_origin),
                credential(&bearer("secret-token"), &prefix(&trusted_origin)),
                None,
            )
            .await;

        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 302, .. }),
            "expected HttpStatus(302)"
        );
        escape.assert_async().await;
    }

    // Proves `redirect_policy`'s delegation is actually wired in and live: without it, this
    // chain would keep following past 10 hops instead of erroring — a single-hop test can't
    // distinguish "delegation is live" from "no policy at all".
    #[tokio::test]
    async fn test_get_cached_default_client_enforces_ten_hop_redirect_limit() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        // reqwest errors once `previous.len() > 10` (the 11th hop), so 11 redirecting steps
        // (step/0..step/10) are needed to trigger it; step/11 must never be requested.
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

        // Kept alive until here: each `Mock` deregisters on drop, turning hops 404 otherwise.
        assert_eq!(hop_mocks.len(), 11);

        let cache = HttpCache::new();
        let start_url = format!("{base}/step/0");
        let result: Result<Bytes> = cache.get_cached(&start_url).await;

        assert_matches!(
            result,
            Err(DepsError::RegistryError { .. }),
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
                link: None,
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
            link: None,
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
                link: None,
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

    const NEXT_LINK: &str = r#"<https://r.example/p?page=2>; rel="next""#;

    #[tokio::test]
    async fn test_response_captures_link_on_200_and_keeps_it_on_304() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let cache = HttpCache::new();

        let first = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc\"")
            .with_header("link", NEXT_LINK)
            .with_body("page one")
            .create_async()
            .await;
        let response = cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
        assert_eq!(response.link.as_deref(), Some(NEXT_LINK));
        first.remove_async().await;

        let _revalidate = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc\"")
            .with_status(304)
            .create_async()
            .await;
        let response = cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
        assert_eq!(response.body.as_ref(), b"page one");
        assert_eq!(response.link.as_deref(), Some(NEXT_LINK));
    }

    #[tokio::test]
    async fn test_evict_url_prefix_drops_only_matching_entries() {
        let mut server = mockito::Server::new_async().await;
        let _a = server
            .mock("GET", "/api/a")
            .with_status(200)
            .with_body("a")
            .create_async()
            .await;
        let _b = server
            .mock("GET", "/other/b")
            .with_status(200)
            .with_body("b")
            .create_async()
            .await;
        let cache = HttpCache::new();
        cache
            .get_cached(&format!("{}/api/a", server.url()))
            .await
            .unwrap();
        cache
            .get_cached(&format!("{}/other/b", server.url()))
            .await
            .unwrap();
        assert_eq!(cache.evict_url_prefix(&format!("{}/api/", server.url())), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_baseline_auth_partition_keys_never_collide() {
        let cache = HttpCache::new();
        let url = "https://r.example/p";
        let partition = |raw| CredentialPartition::new(raw);
        let bare = cache.cache_key(url, CacheTier::Baseline, KeyAuth::ANONYMOUS);
        let zero = cache.cache_key(
            url,
            CacheTier::Baseline,
            KeyAuth::Anonymous(Some(partition(0))),
        );
        let one = cache.cache_key(
            url,
            CacheTier::Baseline,
            KeyAuth::Anonymous(Some(partition(1))),
        );
        let credentialed =
            cache.cache_key(url, CacheTier::Baseline, KeyAuth::Credential(partition(1)));
        let pinned = cache.cache_key(
            url,
            CacheTier::Pinned { digest: 0 },
            KeyAuth::Anonymous(Some(partition(0))),
        );
        let pinned_credentialed = cache.cache_key(
            url,
            CacheTier::Pinned { digest: 0 },
            KeyAuth::Credential(partition(0)),
        );
        assert_eq!(bare, url);
        let keys = [
            &bare,
            &zero,
            &one,
            &credentialed,
            &pinned,
            &pinned_credentialed,
        ];
        for (i, left) in keys.iter().enumerate() {
            for right in &keys[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[tokio::test]
    async fn test_auth_id_partitions_baseline_entries_and_eviction_reaches_them() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("body")
            .expect(3)
            .create_async()
            .await;
        let cache = HttpCache::new();
        for partition in [
            None,
            Some(CredentialPartition::new(1)),
            Some(CredentialPartition::new(2)),
        ] {
            cache
                .get_cached_trusted_origin_response(
                    &url,
                    &prefix(&origin),
                    RequestAuth::Anonymous { partition },
                    None,
                    RevalidationFailure::ServeStale,
                )
                .await
                .unwrap();
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.evict_url_prefix(&format!("{}/api/", server.url())), 3);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn test_unreadable_link_header_reads_as_a_next_relation() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let cache = HttpCache::new();

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("link", "<https://r.example/p>; title=\"caf\u{e9}\"")
            .with_body("page one")
            .create_async()
            .await;
        let response = cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
        assert_eq!(
            crate::pagination::ListCoverage::from_link_header(response.link.as_deref()),
            crate::pagination::ListCoverage::Truncated
        );
    }

    #[tokio::test]
    async fn test_revalidation_failure_fail_returns_the_error_and_keeps_the_entry() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let cache = HttpCache::new();

        let first = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc\"")
            .with_body("page one")
            .create_async()
            .await;
        cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::Fail,
            )
            .await
            .unwrap();
        first.remove_async().await;

        let _broken = server
            .mock("GET", "/api/data")
            .with_status(500)
            .expect_at_least(2)
            .create_async()
            .await;
        let err = cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::Fail,
            )
            .await
            .unwrap_err();
        assert_matches!(err, DepsError::HttpStatus { status: 500, .. });
        assert_eq!(cache.len(), 1, "the stored entry is kept");

        let stale = cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
        assert_eq!(stale.body.as_ref(), b"page one");
    }

    #[tokio::test]
    async fn test_pinned_revalidation_failure_fail_covers_not_found() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let cache = HttpCache::new();

        let first = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("page one")
            .create_async()
            .await;
        cache
            .get_cached_pinned_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::Fail,
            )
            .await
            .unwrap();
        first.remove_async().await;
        let _gone = server
            .mock("GET", "/api/data")
            .with_status(404)
            .create_async()
            .await;
        let err = cache
            .get_cached_pinned_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::Fail,
            )
            .await
            .unwrap_err();
        assert!(err.is_not_found(), "{err:?}");
    }

    #[tokio::test]
    async fn test_pinned_response_captures_link_with_cache_disabled() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());
        let origin = format!("{}/", server.url());
        let cache = HttpCache::new();
        cache.set_cache_enabled(CacheMode::Disabled);

        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("link", NEXT_LINK)
            .with_body("page one")
            .create_async()
            .await;
        let response = cache
            .get_cached_pinned_response(
                &url,
                &prefix(&origin),
                RequestAuth::ANONYMOUS,
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
        assert_eq!(response.link.as_deref(), Some(NEXT_LINK));
        assert_eq!(cache.len(), 0);
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
                link: None,
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
                link: None,
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
                link: None,
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
        let result: Result<CachedResponse> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await;

        assert!(result.is_err());
        match result {
            Err(DepsError::HttpStatus { status, .. }) => {
                assert_eq!(status, 404);
            }
            _ => panic!("Expected HttpStatus"),
        }
    }

    /// #1295 (a): a 403 carrying confirmed `X-RateLimit-Remaining: 0` evidence classifies as
    /// a *verified* rate limit, not a bare `HttpStatus`.
    #[tokio::test]
    async fn test_fetch_and_store_403_with_confirmed_evidence_is_verified_rate_limited() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/owner/repo/tags")
            .with_status(403)
            .with_header("x-ratelimit-remaining", "0")
            .with_body(r#"{"message":"API rate limit exceeded"}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/repos/owner/repo/tags", server.url());
        let result: Result<CachedResponse> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await;

        match result {
            Err(DepsError::RateLimited { verified, .. }) => {
                assert_eq!(verified, RateLimitEvidence::Confirmed);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    /// #1295 (b): a plain 403 with no `X-RateLimit-Remaining` header at all — the shape a
    /// non-rate-limit 403 cause (abuse-detection false positive, secondary rate limit, an
    /// access-restricted repo) would have — stays a bare `HttpStatus`, distinguishable from
    /// the confirmed case above.
    #[tokio::test]
    async fn test_fetch_and_store_403_without_evidence_stays_http_status() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/owner/repo/tags")
            .with_status(403)
            .with_body(r#"{"message":"Resource not accessible by integration"}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/repos/owner/repo/tags", server.url());
        let result: Result<CachedResponse> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await;

        match result {
            Err(DepsError::HttpStatus { status, .. }) => assert_eq!(status, 403),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    /// #1295: a non-zero `X-RateLimit-Remaining` on a 403 is not confirming evidence either —
    /// the request was rejected for some other reason while quota remains.
    #[tokio::test]
    async fn test_fetch_and_store_403_with_nonzero_remaining_stays_http_status() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/repos/owner/repo/tags")
            .with_status(403)
            .with_header("x-ratelimit-remaining", "42")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let url = format!("{}/repos/owner/repo/tags", server.url());
        let result: Result<CachedResponse> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await;

        match result {
            Err(DepsError::HttpStatus { status, .. }) => assert_eq!(status, 403),
            other => panic!("expected HttpStatus, got {other:?}"),
        }
    }

    /// #1295: a `X-RateLimit-Remaining: 0` header on a status other than 403/429 is not
    /// rate-limit evidence — [`confirmed_rate_limit_exhaustion`] must stay status-gated.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_requires_403_or_429_status() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            header::HeaderValue::from_static("0"),
        );
        assert!(!confirmed_rate_limit_exhaustion(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers
        ));
        assert!(confirmed_rate_limit_exhaustion(
            StatusCode::FORBIDDEN,
            &headers
        ));
    }

    /// #1295 critic S4: GitHub's primary rate limit can also arrive as 429 (not only 403),
    /// with `X-RateLimit-Remaining: 0`.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_accepts_429_with_zero_remaining() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            header::HeaderValue::from_static("0"),
        );
        assert!(confirmed_rate_limit_exhaustion(
            StatusCode::TOO_MANY_REQUESTS,
            &headers
        ));
    }

    /// #1295 critic S4: a secondary rate limit arrives as 403/429 with `Retry-After` and a
    /// *non-zero* (or absent) `X-RateLimit-Remaining` — `Retry-After` alone must count as
    /// evidence, since `remaining == 0` alone would miss this shape entirely.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_accepts_retry_after_without_remaining() {
        let mut headers = header::HeaderMap::new();
        headers.insert("retry-after", header::HeaderValue::from_static("60"));
        assert!(confirmed_rate_limit_exhaustion(
            StatusCode::FORBIDDEN,
            &headers
        ));
        assert!(confirmed_rate_limit_exhaustion(
            StatusCode::TOO_MANY_REQUESTS,
            &headers
        ));
    }

    /// #1295 critic S4: `Retry-After` evidence still requires a 403/429 status — an unrelated
    /// 503 with a `Retry-After` header (ordinary server-maintenance semantics) is not a
    /// rate-limit confirmation.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_retry_after_still_status_gated() {
        let mut headers = header::HeaderMap::new();
        headers.insert("retry-after", header::HeaderValue::from_static("60"));
        assert!(!confirmed_rate_limit_exhaustion(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers
        ));
    }

    /// #1295 critic M4: a malformed/padded `X-RateLimit-Remaining` value (not a bare `"0"`)
    /// must not be treated as confirming evidence — `confirmed_rate_limit_exhaustion` parses
    /// the value rather than comparing it as an exact string, so this is evidence-neutral
    /// (falls through to `HttpStatus`) rather than a false positive or a panic.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_rejects_malformed_remaining() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            header::HeaderValue::from_static("not-a-number"),
        );
        assert!(!confirmed_rate_limit_exhaustion(
            StatusCode::FORBIDDEN,
            &headers
        ));
    }

    /// #1295 critic M4: a padded numeric value (e.g. `"00"`) parses to the same integer `0`
    /// and must still count as evidence — the point of switching from string equality to
    /// `parse::<u64>()`.
    #[test]
    fn test_confirmed_rate_limit_exhaustion_accepts_padded_zero() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining",
            header::HeaderValue::from_static("00"),
        );
        assert!(confirmed_rate_limit_exhaustion(
            StatusCode::FORBIDDEN,
            &headers
        ));
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
        let _: CachedResponse = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await
            .unwrap();

        let cached = cache.entries.get(&url).unwrap();
        assert_eq!(cached.etag, Some("\"abc123\"".into()));
        assert_eq!(
            cached.last_modified,
            Some("Wed, 21 Oct 2024 07:28:00 GMT".into())
        );
    }

    /// #756 security follow-up S-A: the "fetching fresh: {url}" debug log in
    /// `fetch_and_store_with_headers` — the direct callee `get_cached_via`'s
    /// `miss` branch delegates to — must never carry a token embedded in the URL's query
    /// string. This is `debug`-level, the level this project's own continuous-improvement
    /// convention runs at (`RUST_LOG=debug`), so it is not merely a theoretical exposure.
    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn test_fetch_and_store_fetching_fresh_log_redacts_query_string_token() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/pkg?token=super-secret-value", server.url());

        let _m = server
            .mock("GET", "/pkg")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".into(),
                "super-secret-value".into(),
            ))
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let output =
            crate::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
                let result: CachedResponse = cache
                    .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
                    .await
                    .unwrap();
                assert_eq!(result.body.as_ref(), b"ok");
            })
            .await;

        assert!(
            !output.contains("super-secret-value"),
            "leaked token via 'fetching fresh' debug log: {output:?}"
        );
    }

    /// #767 S3 / #789: proves `SanitizedRegistryError`'s `From<reqwest::Error>` actually
    /// strips the URL from the wrapped `reqwest::Error`'s own `Display`, not just that
    /// `RegistryError::package` is redacted — a genuine transport-level error (connection
    /// refused on a closed loopback port, so `.url()` is populated the way a builder-only
    /// error like `Client::get("not a url").build().unwrap_err()` never is) is required to
    /// exercise this: reverting any of the 5 `source: e.into()` call sites in this file back
    /// to a bare `reqwest::Error` must fail to compile, and reverting
    /// `SanitizedRegistryError::from`'s `.without_url()` call must fail this test.
    #[tokio::test]
    async fn test_registry_error_source_redacts_url_on_real_transport_error() {
        // Bind then immediately drop a loopback listener: nothing accepts connections on
        // this port afterward, so a request to it fails fast with connection-refused
        // instead of hanging or needing a real unreachable host.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let url = format!("http://127.0.0.1:{port}/pkg?token=super-secret-value");

        let cache = HttpCache::new();
        let err = cache.get_cached(&url).await.unwrap_err();

        assert_matches!(err, DepsError::RegistryError { .. });
        assert!(
            !err.to_string().contains("super-secret-value"),
            "err: {err}"
        );
    }

    #[tokio::test]
    async fn test_get_cached_with_headers_sends_extra_headers() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/api/data", server.url());

        let _m = server
            .mock("GET", "/api/data")
            .match_header("accept", "application/json")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("negotiated data")
            .create_async()
            .await;

        let cache = HttpCache::new();
        let result: Bytes = cache
            .get_cached_with_headers(&url, &[RequestHeader::Accept("application/json")])
            .await
            .unwrap();

        assert_eq!(result.as_ref(), b"negotiated data");
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
        let headers = [RequestHeader::Accept("application/vnd.npm.install-v1+json")];
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
        let result: Result<CachedResponse> = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await;

        match result {
            Err(DepsError::ResponseTooLarge { limit, .. }) => {
                assert_eq!(limit, MAX_RESPONSE_BYTES);
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }

        assert!(cache.entries.get(&url).is_none());
    }

    #[tokio::test]
    async fn test_fetch_and_store_accepts_response_at_exact_cap() {
        // MAX_RESPONSE_BYTES is well over MAX_CACHEABLE_ENTRY_BYTES, so the network-layer cap
        // and the cache admission cap are independent (see test_store_entry_skips_caching_oversized_entry).
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
        let result: CachedResponse = cache
            .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url)
            .await
            .unwrap();

        assert_eq!(result.body.len(), MAX_RESPONSE_BYTES);
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
                link: None,
                fetched_at: Instant::now(),
            },
        );

        // Registry down for maintenance: a non-2xx, non-304 response instead of "unchanged"
        // or "here's the new body".
        let _m = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"stale-etag\"")
            .with_status(503)
            .with_body("<html>maintenance</html>")
            .create_async()
            .await;

        let result: Bytes = cache.get_cached(&url).await.unwrap();

        // Stale-while-revalidate: last-known-good body returned, entry untouched.
        assert_eq!(result.as_ref(), b"stale but good");
        let cached = cache.entries.get(&url).unwrap();
        assert_eq!(cached.etag, Some("\"stale-etag\"".into()));
    }

    /// A connect-time policy block during revalidation makes no connection, so a warm entry is
    /// still served (stale-while-revalidate) instead of surfacing `HostBlockedByPolicy`.
    #[tokio::test]
    async fn test_get_cached_policy_block_on_refresh_serves_warm_entry() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;
        let url = format!("http://localhost:{}/", server.socket_address().port());

        let cache = HttpCache::new();
        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"warm"),
                etag: None,
                last_modified: None,
                link: None,
                fetched_at: Instant::now(),
            },
        );

        let logs = crate::test_util::capture_tracing_output_async(async {
            for _ in 0..2 {
                let result: Bytes = cache.get_cached(&url).await.unwrap();
                assert_eq!(result.as_ref(), b"warm");
            }
        })
        .await;
        assert!(
            logs.matches("blocking DNS-resolved address").count() >= 2,
            "revalidation must have been attempted and blocked each time: {logs}"
        );
        mock.assert_async().await;
        assert!(cache.entries.contains_key(&url));
    }

    /// #756 round 2 S1 regression: the "conditional request failed, using cache" warn (fired
    /// on exactly this stale-while-revalidate path) must never interpolate the `DepsError`
    /// itself — `DepsError::HttpStatus`'s `Display` embeds the full, unredacted URL (including
    /// the query string), which would defeat `RedactedUrl`'s redaction on this same span's
    /// `url` field two lines above it. Reuses the mock/seeding shape of
    /// `test_get_cached_non_2xx_on_refresh_preserves_stale_cache` with a token-bearing query
    /// string, wrapped in a real tracing capture (an actual `warn!` event fires here, unlike
    /// the offline-hit case covered by `test_get_cached_span_url_field_redacts_query_string_token`).
    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn test_get_cached_conditional_request_failure_does_not_leak_token_via_warn() {
        let mut server = mockito::Server::new_async().await;
        let url = format!("{}/pkg?token=super-secret-value", server.url());

        let cache = HttpCache::new();
        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"stale but good"),
                etag: Some("\"stale-etag\"".into()),
                last_modified: None,
                link: None,
                fetched_at: Instant::now(),
            },
        );

        let _m = server
            .mock("GET", "/pkg")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".into(),
                "super-secret-value".into(),
            ))
            .match_header("if-none-match", "\"stale-etag\"")
            .with_status(503)
            .with_body("<html>maintenance</html>")
            .create_async()
            .await;

        let output = crate::test_util::capture_tracing_output_async(async {
            let result: Bytes = cache.get_cached(&url).await.unwrap();
            assert_eq!(result.as_ref(), b"stale but good");
        })
        .await;

        assert!(
            !output.contains("super-secret-value"),
            "leaked token via warn! output: {output:?}"
        );
    }

    /// #756 C1 regression: `get_cached_via`'s `url` span field must never carry
    /// a token embedded in the URL's query string — the same shape as an `.npmrc`-style
    /// `${VAR}`-expanded `registry=` URL (see `deps-npm`'s `NpmRegistryIndex` security model).
    /// The critic's exact repro was the span's own `url={...}` prefix on a captured log line,
    /// so this enables `FmtSpan::NEW` to capture that prefix directly, at span-creation time
    /// (before the function body runs), rather than relying on some other event firing inside
    /// the span. Deliberately exercises the offline-hit branch — no `DepsError` is ever
    /// constructed on that path — so this is isolated from that type's own (separate,
    /// pre-existing) URL-embedding `Display` impl and tests the span field in isolation.
    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn test_get_cached_span_url_field_redacts_query_string_token() {
        let url = "https://npm.internal/pkg?token=super-secret-value".to_string();
        let cache = HttpCache::new();
        cache.set_offline(NetworkMode::Offline);
        cache.entries.insert(
            url.clone(),
            CachedResponse {
                body: Bytes::from_static(b"cached"),
                etag: None,
                last_modified: None,
                link: None,
                fetched_at: Instant::now(),
            },
        );

        let output = crate::test_util::capture_tracing_span_fields_async(async {
            let result: Bytes = cache.get_cached(&url).await.unwrap();
            assert_eq!(result.as_ref(), b"cached");
        })
        .await;

        assert!(
            !output.contains("super-secret-value"),
            "leaked token into span output: {output:?}"
        );
        assert!(
            output.contains("https://npm.internal/pkg"),
            "expected the redacted host+path in span output: {output:?}"
        );
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
    async fn test_post_json_limited_trusted_origin_success_returns_body_and_does_not_cache() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/v3alpha/findings:batchGet", server.url());

        let _m = server
            .mock("POST", "/v3alpha/findings:batchGet")
            .match_header("content-type", "application/json")
            .with_status(200)
            .with_body(r#"{"findings":[]}"#)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let body = serde_json::json!({ "queries": [] });
        let result: Bytes = cache
            .post_json_limited_trusted_origin(&url, &body, BodyLimit::new(1024), &trusted_origin)
            .await
            .unwrap();

        assert_eq!(result.as_ref(), br#"{"findings":[]}"#);
        assert!(
            cache.is_empty(),
            "post_json_limited_trusted_origin must not populate the entry-map cache"
        );
    }

    #[tokio::test]
    async fn test_post_json_limited_trusted_origin_enforces_body_limit() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/v3alpha/findings:batchGet", server.url());

        let _m = server
            .mock("POST", "/v3alpha/findings:batchGet")
            .with_status(200)
            .with_body("x".repeat(64))
            .create_async()
            .await;

        let cache = HttpCache::new();
        let body = serde_json::json!({ "queries": [] });
        let result: Result<Bytes> = cache
            .post_json_limited_trusted_origin(&url, &body, BodyLimit::new(8), &trusted_origin)
            .await;

        // Assert via `matches!` rather than debug-formatting `result` in a panic message
        // (#409's established pattern): on the `Ok` arm that value is the raw response
        // body, which would otherwise be written to the test log by the panic machinery.
        assert_matches!(
            result,
            Err(DepsError::ResponseTooLarge { .. }),
            "expected ResponseTooLarge"
        );
    }

    #[tokio::test]
    async fn test_post_json_limited_trusted_origin_rejects_untrusted_redirect() {
        let mut server = mockito::Server::new_async().await;
        let mut evil = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/v3alpha/findings:batchGet", server.url());

        let _redirect = server
            .mock("POST", "/v3alpha/findings:batchGet")
            .with_status(302)
            .with_header("location", &format!("{}/steal", evil.url()))
            .create_async()
            .await;
        let evil_call = evil.mock("GET", "/steal").expect(0).create_async().await;

        let cache = HttpCache::new();
        let body = serde_json::json!({ "queries": [] });
        let result: Result<Bytes> = cache
            .post_json_limited_trusted_origin(&url, &body, BodyLimit::DEFAULT, &trusted_origin)
            .await;

        assert!(
            result.is_err(),
            "an untrusted redirect hop must not be followed"
        );
        evil_call.assert_async().await;
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
        let headers = [RequestHeader::Accept("application/json")];
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
            link: None,
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

        // 9 entries at the per-entry admission cap: far below MAX_CACHE_ENTRIES by count, but
        // their combined size (72 MiB) overshoots MAX_CACHE_BYTES (64 MiB).
        for i in 0..9 {
            cache.store_entry(format!("url{i}"), dummy_response(MAX_CACHEABLE_ENTRY_BYTES));
        }
        assert_eq!(cache.len(), 9);
        assert!(cache.total_bytes() > MAX_CACHE_BYTES);

        cache.evict_entries();

        // Only as many oldest entries as needed to clear the byte budget are removed, not a
        // fixed count-based batch.
        assert!(cache.total_bytes() <= MAX_CACHE_BYTES);
        assert_eq!(cache.len(), 8);
    }

    #[test]
    fn test_evict_entries_removes_oldest_first_for_bytes() {
        let cache = HttpCache::new();

        // Evicting just the single oldest entry should restore the cache to within budget,
        // proving eviction picks the genuinely oldest entry, not hash-iteration order.
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

        // Pre-fill past the byte budget, staying under MAX_CACHE_ENTRIES by count.
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

        // The pre-request byte-budget check evicted stale entries before fetching.
        assert!(cache.total_bytes() <= MAX_CACHE_BYTES + result.len());
    }

    #[test]
    fn test_store_entry_skips_caching_oversized_entry() {
        let cache = HttpCache::new();

        // A body over the per-entry admission cap is not retained, even though the caller
        // still gets it back (store_entry's caller already holds `body` independently).
        cache.store_entry("big".into(), dummy_response(MAX_CACHEABLE_ENTRY_BYTES + 1));
        assert!(cache.entries.get("big").is_none());
        assert_eq!(cache.total_bytes(), 0);

        // Replacing an existing small entry with an oversized one drops the stale entry too,
        // rather than leaving it to keep serving increasingly outdated data.
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

        // Regression guard: evict_entries used to snapshot total_bytes once and overwrite it
        // with an absolute store, silently discarding any concurrent store_entry delta.
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
        // mockito's second mock answers regardless of which entry was hit, so the body
        // assertion alone wouldn't prove a policy-blind key — this length check does.
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

    // Issue #483: `.expect(0)` proves nothing reached *this mock*, not that zero sockets
    // ever opened — adequate only because the loopback carve-out lets mockito stand in here.

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
        cache.set_offline(NetworkMode::Offline);

        let result: Result<Bytes> = cache.get_cached(&url).await;
        match result {
            Err(DepsError::Offline { url: blocked }) => {
                assert_eq!(blocked, RedactedUrl::new(&url));
            }
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
        cache.set_offline(NetworkMode::Offline);

        let body = serde_json::json!({ "queries": [] });
        let result: Result<Bytes> = cache.post_json(&url, &body).await;
        assert_matches!(result, Err(DepsError::Offline { .. }));
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
        cache.set_offline(NetworkMode::Offline);

        let result: Result<Bytes> = cache.get_transport_only(&url).await;
        assert_matches!(result, Err(DepsError::Offline { .. }));
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
                link: None,
                fetched_at: Instant::now(),
            },
        );
        cache.set_offline(NetworkMode::Offline);

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
        cache.set_cache_enabled(CacheMode::Disabled);

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
        cache.set_cache_enabled(CacheMode::Disabled);
        cache.set_offline(NetworkMode::Offline);

        let result: Result<Bytes> = cache.get_cached(&url).await;
        assert_matches!(result, Err(DepsError::Offline { .. }));
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

        cache.set_cache_enabled(CacheMode::Disabled);
        cache.set_offline(NetworkMode::Offline);

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

        cache.set_offline(NetworkMode::Offline);

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

        cache.set_offline(NetworkMode::Offline);
        let offline: Bytes = cache.get_cached(&url).await.unwrap();
        assert_eq!(offline.as_ref(), b"fetched while online");

        cache.set_offline(NetworkMode::Online);
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

        cache.set_offline(NetworkMode::Offline);
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
            .get_cached_trusted_origin(&url, &prefix(&trusted_origin), RequestAuth::ANONYMOUS, None)
            .await
            .unwrap();
        assert_eq!(online.as_ref(), b"trusted-origin fetch");

        cache.set_offline(NetworkMode::Offline);
        let offline: Bytes = cache
            .get_cached_trusted_origin(&url, &prefix(&trusted_origin), RequestAuth::ANONYMOUS, None)
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
            .get_cached_pinned(
                &url,
                &prefix(&trusted_origin),
                RequestAuth::credential_in(
                    CredentialHeader::Authorization(&crate::secret::basic_auth_header(
                        &["us", "er"].concat(),
                        &["p", "at"].concat(),
                    )),
                    CredentialPartition::new(42),
                ),
                None,
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(1), None)
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(2), None)
            .await
            .unwrap();
        assert_eq!(
            b.as_ref(),
            b"body-for-credential-b",
            "a distinct auth_id must not read back credential A's cached body"
        );
    }

    fn pinned_tier(digest: u64) -> CacheTier {
        CacheTier::Pinned { digest }
    }

    fn partition(raw: u64) -> CredentialPartition {
        CredentialPartition::new(raw)
    }

    /// #1025: an unpartitioned anonymous request and a credential whose salted digest happens to
    /// hash to exactly `0` must produce different `Pinned`-tier cache keys.
    #[test]
    fn test_cache_key_pinned_anonymous_and_zero_digest_credential_never_collide() {
        let cache = HttpCache::new();
        let tier = pinned_tier(42);

        let anonymous = cache.cache_key("https://example.com/pkg", tier, KeyAuth::ANONYMOUS);
        let zero_digest_credential = cache.cache_key(
            "https://example.com/pkg",
            tier,
            KeyAuth::Credential(partition(0)),
        );

        assert_ne!(anonymous, zero_digest_credential);
    }

    /// Critic S1: the same partition used with a credential and anonymously yields two keys, on
    /// every tier that folds a partition in.
    #[test]
    fn test_cache_key_same_partition_credential_and_anonymous_never_collide() {
        let cache = HttpCache::new();
        for tier in [CacheTier::Baseline, pinned_tier(42)] {
            let credentialed = cache.cache_key(
                "https://example.com/pkg",
                tier,
                KeyAuth::Credential(partition(7)),
            );
            let anonymous = cache.cache_key(
                "https://example.com/pkg",
                tier,
                KeyAuth::Anonymous(Some(partition(7))),
            );
            assert_ne!(credentialed, anonymous, "{tier:?}");
        }
    }

    /// Critic S1, end to end: the same partition id used with a credential and with
    /// `Anonymous { partition: Some(p) }` yields two distinct cache entries on both APIs.
    #[tokio::test]
    async fn test_same_partition_credential_and_anonymous_use_distinct_entries_on_both_apis() {
        let mut server = mockito::Server::new_async().await;
        let trusted_origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());
        let _m = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_body("body")
            .expect(4)
            .create_async()
            .await;

        let cache = HttpCache::new();
        let origin = prefix(&trusted_origin);
        let anonymous = RequestAuth::Anonymous {
            partition: Some(partition(5)),
        };
        cache
            .get_cached_trusted_origin(&url, &origin, cred_in(5), None)
            .await
            .unwrap();
        cache
            .get_cached_trusted_origin(&url, &origin, anonymous, None)
            .await
            .unwrap();
        assert_eq!(cache.len(), 2);
        cache
            .get_cached_pinned(&url, &origin, cred_in(5), None)
            .await
            .unwrap();
        cache
            .get_cached_pinned(&url, &origin, anonymous, None)
            .await
            .unwrap();
        assert_eq!(cache.len(), 4);
    }

    /// #1025 regression guard: distinct partitions keep producing distinct keys.
    #[test]
    fn test_cache_key_pinned_nonzero_partition_still_distinct() {
        let cache = HttpCache::new();
        let tier = pinned_tier(42);

        let a = cache.cache_key(
            "https://example.com/pkg",
            tier,
            KeyAuth::Credential(partition(1)),
        );
        let b = cache.cache_key(
            "https://example.com/pkg",
            tier,
            KeyAuth::Credential(partition(2)),
        );
        let anonymous = cache.cache_key("https://example.com/pkg", tier, KeyAuth::ANONYMOUS);

        assert_ne!(a, b);
        assert_ne!(a, anonymous);
        assert_ne!(b, anonymous);
    }

    /// #1025 M2: proves the fixed-width invariant itself — a regression that dropped zero-padding
    /// would let differently-shaped `(digest, partition)` pairs concatenate to the same string.
    /// Every combination drawn from these boundary-value sets must produce a distinct key.
    #[test]
    fn test_cache_key_pinned_digest_and_partition_matrix_never_collide() {
        let cache = HttpCache::new();
        let digests = [0u64, 1, 0x11, u64::MAX];
        let auths = [
            KeyAuth::ANONYMOUS,
            KeyAuth::Anonymous(Some(partition(0))),
            KeyAuth::Anonymous(Some(partition(1))),
            KeyAuth::Credential(partition(0)),
            KeyAuth::Credential(partition(1)),
            KeyAuth::Credential(partition(0x11)),
            KeyAuth::Credential(partition(u64::MAX)),
        ];

        let mut keys = Vec::new();
        for &digest in &digests {
            for &auth in &auths {
                keys.push((
                    (digest, auth),
                    cache
                        .cache_key("https://example.com/pkg", pinned_tier(digest), auth)
                        .into_owned(),
                ));
            }
        }

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i].1, keys[j].1,
                    "inputs {:?} and {:?} produced the same cache key",
                    keys[i].0, keys[j].0
                );
            }
        }
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
            .await;

        assert_matches!(
            result,
            Err(DepsError::HttpStatus { status: 401, .. }),
            "expected the 401 to surface as an error, not a stale-served body: {result:?}"
        );
        assert_eq!(
            cache.len(),
            0,
            "the revoked-credential entry must be evicted, not left cached"
        );
    }

    /// #1295 critic C1 regression test: a 403 revalidation carrying confirmed
    /// `X-RateLimit-Remaining: 0` evidence now classifies as `DepsError::RateLimited` rather
    /// than `HttpStatus` (see `http_status_error`) — without the eviction guard's
    /// `RateLimited` arm, this would silently bypass FR-015/NFR-004 and keep serving the
    /// possibly-revoked credential's stale body.
    #[tokio::test]
    async fn test_pinned_authenticated_403_with_confirmed_evidence_still_evicts() {
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
            .await
            .unwrap();
        assert_eq!(first.as_ref(), b"private data");
        assert_eq!(cache.len(), 1);
        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(403)
            .with_header("x-ratelimit-remaining", "0")
            .create_async()
            .await;

        let result = cache
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
            .await;

        assert_matches!(
            result,
            Err(DepsError::RateLimited {
                verified: RateLimitEvidence::Confirmed,
                ..
            }),
            "expected the confirmed-evidence 403 to surface as verified RateLimited: {result:?}"
        );
        assert_eq!(
            cache.len(),
            0,
            "the revoked-credential entry must still be evicted on a confirmed-evidence 403, \
             not left cached"
        );
    }

    async fn warm_entry_under(
        server: &mut mockito::ServerGuard,
        cache: &HttpCache,
        auth: RequestAuth<'_>,
    ) -> (String, String) {
        let origin = format!("{}/", server.url());
        let url = format!("{}/api/data", server.url());
        let _warm = server
            .mock("GET", "/api/data")
            .with_status(200)
            .with_header("etag", "\"abc123\"")
            .with_body("private data")
            .create_async()
            .await;
        cache
            .get_cached_trusted_origin(&url, &prefix(&origin), auth, None)
            .await
            .unwrap();
        assert_eq!(cache.len(), 1);
        (origin, url)
    }

    /// A credentialed 401 on the trusted-origin API evicts the entry, like the pinned tier.
    #[tokio::test]
    async fn test_trusted_origin_credentialed_401_revalidation_evicts() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (origin, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
        server.reset();
        let _revoked = server
            .mock("GET", "/api/data")
            .with_status(401)
            .create_async()
            .await;

        let result = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), cred_in(7), None)
            .await;

        assert_matches!(result, Err(DepsError::HttpStatus { status: 401, .. }));
        assert_eq!(cache.len(), 0);
    }

    /// An anonymous request keeps the stale-while-revalidate fallback on a 401.
    #[tokio::test]
    async fn test_trusted_origin_anonymous_401_revalidation_serves_stale() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (origin, url) = warm_entry_under(&mut server, &cache, RequestAuth::ANONYMOUS).await;
        server.reset();
        let _denied = server
            .mock("GET", "/api/data")
            .with_status(401)
            .create_async()
            .await;

        let body = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), RequestAuth::ANONYMOUS, None)
            .await
            .unwrap();

        assert_eq!(body.as_ref(), b"private data");
        assert_eq!(cache.len(), 1);
    }

    /// M4: an exhausted GitHub-style rate limit is throttling, not a revoked token, so a
    /// credentialed trusted-origin entry survives it and is served stale.
    #[tokio::test]
    async fn test_trusted_origin_credentialed_403_rate_limit_serves_stale() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let auth = || cred_in(7).with_rate_limit(RateLimitRevocation::Throttles);
        let (origin, url) = warm_entry_under(&mut server, &cache, auth()).await;
        server.reset();
        let _limited = server
            .mock("GET", "/api/data")
            .with_status(403)
            .with_header("x-ratelimit-remaining", "0")
            .create_async()
            .await;

        let body = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), auth(), None)
            .await
            .unwrap();

        assert_eq!(body.as_ref(), b"private data");
        assert_eq!(cache.len(), 1);
    }

    /// A plain credentialed 403 (no rate-limit evidence) still evicts on the trusted-origin API.
    #[tokio::test]
    async fn test_trusted_origin_credentialed_plain_403_evicts() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (origin, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
        server.reset();
        let _forbidden = server
            .mock("GET", "/api/data")
            .with_status(403)
            .create_async()
            .await;

        let result = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), cred_in(7), None)
            .await;

        assert_matches!(result, Err(DepsError::HttpStatus { status: 403, .. }));
        assert_eq!(cache.len(), 0);
    }

    /// Critic S4: after the credential is removed, an anonymous request never reads the body
    /// that was fetched under it, even when revalidation fails.
    #[tokio::test]
    async fn test_removed_credential_never_serves_credentialed_body_anonymously() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (origin, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
        server.reset();
        let _unauthorized = server
            .mock("GET", "/api/data")
            .with_status(401)
            .create_async()
            .await;

        let result = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), RequestAuth::ANONYMOUS, None)
            .await;

        assert_matches!(result, Err(DepsError::HttpStatus { status: 401, .. }));
    }

    /// The no-network credentialed read serves the stored entry whatever the offline switch says,
    /// and never sends: the mock sees no request.
    #[tokio::test]
    async fn test_peek_credentialed_serves_the_entry_without_a_request_online_or_offline() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (_, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
        server.reset();
        let untouched = server
            .mock("GET", "/api/data")
            .expect(0)
            .create_async()
            .await;

        for mode in [NetworkMode::Online, NetworkMode::Offline] {
            cache.set_offline(mode);
            let body = cache
                .peek_credentialed_trusted_origin(&url, partition(7))
                .unwrap();
            assert_eq!(body.body.as_ref(), b"private data");
        }

        untouched.assert_async().await;
    }

    /// A partition nothing was stored under reads as `Offline`, and an anonymous entry never
    /// answers a credentialed read.
    #[tokio::test]
    async fn test_peek_credentialed_misses_other_partitions_and_anonymous_entries() {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let (_, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
        let anonymous_url = format!("{}/api/other", server.url());
        let _other = server
            .mock("GET", "/api/other")
            .with_status(200)
            .with_body("public")
            .create_async()
            .await;
        cache.get_cached(&anonymous_url).await.unwrap();

        assert_matches!(
            cache.peek_credentialed_trusted_origin(&url, partition(8)),
            Err(DepsError::Offline { .. })
        );
        assert_matches!(
            cache.peek_credentialed_trusted_origin(&anonymous_url, partition(7)),
            Err(DepsError::Offline { .. })
        );
    }

    /// Per-source rate-limit rule: a source that opts into `Throttles` (GitHub) keeps a
    /// credentialed entry past a confirmed rate limit, one on the default `Revokes` (GitLab)
    /// evicts it, both on the baseline trusted-origin tier.
    #[tokio::test]
    async fn test_rate_limit_revocation_is_a_per_source_choice_on_the_trusted_origin_tier() {
        for (rule, evicted) in [
            (RateLimitRevocation::Revokes, true),
            (RateLimitRevocation::Throttles, false),
        ] {
            let mut server = mockito::Server::new_async().await;
            let cache = HttpCache::new();
            let auth = || cred_in(7).with_rate_limit(rule);
            let (origin, url) = warm_entry_under(&mut server, &cache, auth()).await;
            server.reset();
            let _limited = server
                .mock("GET", "/api/data")
                .with_status(403)
                .with_header("x-ratelimit-remaining", "0")
                .create_async()
                .await;

            let result = cache
                .get_cached_trusted_origin(&url, &prefix(&origin), auth(), None)
                .await;

            assert_eq!(result.is_err(), evicted, "{rule:?}");
            assert_eq!(cache.len(), usize::from(!evicted), "{rule:?}");
        }
    }

    #[test]
    fn test_rate_limit_revocation_default_revokes_and_ignores_unrelated_errors() {
        let rate_limited = DepsError::RateLimited {
            message: "m".into(),
            verified: RateLimitEvidence::Confirmed,
            source_status: Some(429),
        };
        assert!(!RateLimitRevocation::Revokes.revokes_credential(&rate_limited));
        assert!(
            !RateLimitRevocation::Revokes.revokes_credential(&DepsError::CacheError("x".into()))
        );
        assert!(
            RateLimitRevocation::Revokes.revokes_credential(&DepsError::HttpStatus {
                url: "https://r.test/".into(),
                status: 401,
            })
        );
        assert!(
            RateLimitRevocation::Throttles.revokes_credential(&DepsError::HttpStatus {
                url: "https://r.test/".into(),
                status: 403,
            })
        );
    }

    /// #1295 critic N1 regression test: a confirmed-evidence 429 (mere throttling, not a
    /// credential-revocation signal) must NOT evict an authenticated pinned-tier entry —
    /// NFR-004's scope is 401/403 only. Counterpart to the 403 test above: same setup, only
    /// the revalidation status differs, and the assertion flips (kept, not evicted).
    #[tokio::test]
    async fn test_pinned_authenticated_429_with_confirmed_evidence_does_not_evict() {
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
            .await
            .unwrap();
        assert_eq!(first.as_ref(), b"private data");
        assert_eq!(cache.len(), 1);
        drop(_m1);

        let _m2 = server
            .mock("GET", "/api/data")
            .match_header("if-none-match", "\"abc123\"")
            .with_status(429)
            .with_header("retry-after", "60")
            .create_async()
            .await;

        let result = cache
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(7), None)
            .await;

        assert_eq!(
            result.unwrap().as_ref(),
            b"private data",
            "a confirmed-evidence 429 must still fall back to stale-while-revalidate, not \
             propagate an error"
        );
        assert_eq!(
            cache.len(),
            1,
            "a 429 (throttling, not a credential-revocation signal) must not evict the \
             authenticated pinned-tier entry"
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), RequestAuth::ANONYMOUS, None)
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), RequestAuth::ANONYMOUS, None)
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
            .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(1), None)
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

    // --- #1816: guarded egress, proxy-host exemption, preflight ---

    /// A TCP listener standing in for an HTTP proxy: records the first line of every request
    /// head it receives and answers 502.
    async fn recording_proxy() -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 2048];
                    if let Ok(read) = stream.read(&mut buf).await {
                        let head = String::from_utf8_lossy(&buf[..read]);
                        let first = head.lines().next().unwrap_or_default().to_string();
                        recorded.lock().unwrap().push(first);
                        let _ = stream
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                });
            }
        });
        (port, seen)
    }

    /// Maps `proxy_name` to loopback (where the recording proxy listens) and every other name
    /// to `target_addr`.
    fn lookup_for(proxy_name: &'static str, target_addr: &'static str) -> TestLookup {
        TestLookup(Arc::new(move |host: &str| {
            let addr = if normalize_host(host) == proxy_name {
                "127.0.0.1:0"
            } else {
                target_addr
            };
            vec![addr.parse().unwrap()]
        }))
    }

    fn proxied_transport(
        guard: AddrGuard,
        egress: GuardedEgress,
        proxy_name: &str,
        port: u16,
        lookup: TestLookup,
    ) -> Transport {
        let route = ProxyRoute::Fixed(Url::parse(&format!("http://{proxy_name}:{port}")).unwrap());
        let resolver =
            BlockedAddrResolver::with_lookup(guard.clone(), route.exempt_hosts(), lookup);
        let tier = CacheTier::Baseline;
        Transport::from_parts(
            redirect_policy(guard, RedirectScope::for_egress(egress)),
            resolver,
            egress,
            &route,
            tier,
        )
    }

    async fn fetch_via(transport: &Transport) -> Result<CachedResponse> {
        fetch_url_via("https://registry.test/index", transport).await
    }

    async fn fetch_url_via(url: &str, transport: &Transport) -> Result<CachedResponse> {
        HttpCache::new()
            .get_cached_via(
                url,
                &[],
                transport,
                KeyAuth::ANONYMOUS,
                RevalidationFailure::ServeStale,
                RateLimitRevocation::default(),
            )
            .await
    }

    #[tokio::test]
    async fn test_baseline_reaches_dns_named_proxy() {
        let (port, seen) = recording_proxy().await;
        let transport = proxied_transport(
            AddrGuard::Baseline,
            GuardedEgress::Direct,
            "proxy.test",
            port,
            lookup_for("proxy.test", "93.184.216.34:0"),
        );

        let _ = fetch_via(&transport).await;

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["CONNECT registry.test:443 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn test_baseline_reaches_localhost_named_proxy() {
        let (port, seen) = recording_proxy().await;
        let transport = proxied_transport(
            AddrGuard::Baseline,
            GuardedEgress::Direct,
            "localhost",
            port,
            lookup_for("localhost", "93.184.216.34:0"),
        );

        let _ = fetch_via(&transport).await;

        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_proxy_exemption_ignores_case_and_trailing_dot() {
        let resolver =
            BlockedAddrResolver::new(AddrGuard::Baseline, Arc::from(["proxy.test".to_string()]));
        assert!(resolver.exempt_name("Proxy.Test."));
        assert!(!resolver.exempt_name("other.test"));
    }

    #[tokio::test]
    async fn test_exempt_proxy_name_still_fails_closed_on_no_addresses() {
        let resolver = BlockedAddrResolver::with_lookup(
            AddrGuard::Baseline,
            Arc::from(["proxy.test".to_string()]),
            TestLookup(Arc::new(|_: &str| Vec::new())),
        );
        let name = reqwest::dns::Name::from_str("proxy.test").unwrap();

        let result = reqwest::dns::Resolve::resolve(&resolver, name).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workspace_proxy_egress_reaches_dns_named_proxy_with_public_target() {
        let (port, seen) = recording_proxy().await;
        let transport = proxied_transport(
            workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
            GuardedEgress::Proxy,
            "proxy.test",
            port,
            lookup_for("proxy.test", "93.184.216.34:0"),
        );
        assert!(transport.preflight.is_some());

        let _ = fetch_via(&transport).await;

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["CONNECT registry.test:443 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn test_workspace_proxy_egress_preflight_refuses_private_target_before_the_proxy() {
        for proxy_name in ["proxy.test", "localhost"] {
            let (port, seen) = recording_proxy().await;
            let transport = proxied_transport(
                workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
                GuardedEgress::Proxy,
                proxy_name,
                port,
                lookup_for(proxy_name, "10.0.0.5:0"),
            );

            let result = fetch_via(&transport).await;

            assert_matches!(result, Err(DepsError::HostBlockedByPolicy { .. }));
            assert!(seen.lock().unwrap().is_empty(), "{proxy_name}");
        }
    }

    #[tokio::test]
    async fn test_workspace_direct_egress_has_no_preflight_and_bypasses_proxy() {
        let route = ProxyRoute::for_tier(
            &workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
            GuardedEgress::Direct,
        );
        assert_matches!(route, ProxyRoute::Bypass);
        assert!(route.exempt_hosts().is_empty());
        let transport = Transport::workspace(&Arc::new(RegistryAccessPolicy::default()));
        assert!(transport.preflight.is_none());
    }

    #[test]
    fn test_cache_with_proxy_egress_policy_preflights_workspace_and_pinned_transports() {
        use crate::net_policy::{MapEnv, RegistryEnvironment, WORKSPACE_REGISTRY_PROXY_ENV};

        let env = MapEnv::new().with_var(WORKSPACE_REGISTRY_PROXY_ENV, "proxy");
        let policy = Arc::new(RegistryAccessPolicy::with_environment(
            WorkspaceRegistryAccess::PublicOnly,
            &RegistryEnvironment::read(&env),
        ));
        let cache = HttpCache::with_policy(policy);

        assert!(cache.workspace.read().unwrap().preflight.is_some());
        assert!(
            cache
                .transport_for_pinned("https://registry.test/")
                .preflight
                .is_some()
        );
        assert!(cache.baseline.preflight.is_none());
        assert!(
            HttpCache::new()
                .transport_for_pinned("https://registry.test/")
                .preflight
                .is_none()
        );
    }

    #[test]
    fn test_proxy_route_table() {
        let workspace = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
        assert_matches!(
            ProxyRoute::for_tier(&AddrGuard::Baseline, GuardedEgress::Direct),
            ProxyRoute::System(_)
        );
        assert_matches!(
            ProxyRoute::for_tier(&AddrGuard::Baseline, GuardedEgress::Proxy),
            ProxyRoute::System(_)
        );
        assert_matches!(
            ProxyRoute::for_tier(&workspace, GuardedEgress::Proxy),
            ProxyRoute::System(_)
        );
        assert_matches!(
            ProxyRoute::for_tier(&workspace, GuardedEgress::Direct),
            ProxyRoute::Bypass
        );
    }

    #[test]
    fn test_connect_timeout_is_shorter_than_the_request_timeout() {
        const { assert!(HTTP_CONNECT_TIMEOUT_SECS == 10) };
        const { assert!(HTTP_CONNECT_TIMEOUT_SECS < HTTP_TIMEOUT_SECS) };
    }

    #[test]
    fn test_redirect_scope_follows_egress() {
        assert_eq!(
            RedirectScope::for_egress(GuardedEgress::Direct),
            RedirectScope::AnyHost
        );
        assert_eq!(
            RedirectScope::for_egress(GuardedEgress::Proxy),
            RedirectScope::SameHost
        );
    }

    #[tokio::test]
    async fn test_proxy_egress_stops_cross_host_redirect() {
        let mut server_a = mockito::Server::new_async().await;
        let mut server_b = mockito::Server::new_async().await;
        let target = format!(
            "http://localhost:{}/api/target",
            server_b.url().rsplit(':').next().unwrap()
        );
        let _redirect = server_a
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &target)
            .create_async()
            .await;
        let landed = server_b
            .mock("GET", "/api/target")
            .with_status(200)
            .expect_at_most(1)
            .create_async()
            .await;
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &[]);
        let status = |scope| {
            let client = reqwest::Client::builder()
                .redirect(redirect_policy(guard.clone(), scope))
                .build()
                .unwrap();
            let url = format!("{}/api/source", server_a.url());
            async move { client.get(url).send().await.unwrap().status() }
        };

        assert_eq!(status(RedirectScope::SameHost).await, 302);
        landed.assert_async().await;
        assert_eq!(status(RedirectScope::AnyHost).await, 200);
    }

    // --- fix cycle: preflight carries no proxy-host exemption, coverage gaps ---

    /// Security MEDIUM: a workspace-declared target whose host equals the proxy's host (any case,
    /// trailing dot, other port) must still be refused by the preflight; the proxy-host
    /// exemption exists only for the client's own connection to the proxy.
    #[tokio::test]
    async fn test_preflight_blocks_a_target_named_like_the_proxy() {
        for target in [
            "proxy.test",
            "PROXY.test",
            "proxy.test.",
            "proxy.test:6379",
            "PROXY.TEST.:8443",
        ] {
            let (port, seen) = recording_proxy().await;
            let transport = proxied_transport(
                workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
                GuardedEgress::Proxy,
                "proxy.test",
                port,
                lookup_for("proxy.test", "93.184.216.34:0"),
            );

            let result = fetch_url_via(&format!("https://{target}/index"), &transport).await;

            assert_matches!(
                result,
                Err(DepsError::HostBlockedByPolicy { .. }),
                "{target}"
            );
            assert!(
                seen.lock().unwrap().is_empty(),
                "{target}: proxy was contacted"
            );
        }
    }

    /// Security MEDIUM, `NO_PROXY=<that host>` variant: the matcher probe still reports the proxy
    /// host as exempt for the client, and the preflight must still refuse a target with that
    /// name before the client would connect to it directly.
    #[tokio::test]
    async fn test_preflight_blocks_a_no_proxy_target_named_like_the_proxy() {
        let proxy = SystemProxy::for_test(Some("http://proxy.test:3128"), Some("proxy.test"));
        let route = ProxyRoute::System(proxy);
        assert!(route.exempt_hosts().iter().all(|host| host == "proxy.test"));
        assert!(!route.exempt_hosts().is_empty());
        let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
        let resolver = BlockedAddrResolver::with_lookup(
            guard.clone(),
            route.exempt_hosts(),
            lookup_for("proxy.test", "93.184.216.34:0"),
        );
        let transport = Transport::from_parts(
            redirect_policy(guard, RedirectScope::SameHost),
            resolver,
            GuardedEgress::Proxy,
            &route,
            CacheTier::Baseline,
        );

        let result = transport.preflight("https://proxy.test/index").await;

        assert_matches!(result, Err(DepsError::HostBlockedByPolicy { .. }));
    }

    /// G1: a resolution that yields no addresses or an I/O error fails the preflight closed,
    /// before the proxy sees anything.
    #[tokio::test]
    async fn test_preflight_fails_closed_on_no_addresses() {
        let (port, seen) = recording_proxy().await;
        let transport = proxied_transport(
            workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
            GuardedEgress::Proxy,
            "proxy.test",
            port,
            TestLookup(Arc::new(|_: &str| Vec::new())),
        );

        let result = fetch_via(&transport).await;

        assert_matches!(result, Err(DepsError::CacheError(message)) if message.contains("DNS preflight"));
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn test_preflight_error_maps_blocked_to_policy_and_everything_else_to_cache_error() {
        let blocked = ResolveGuardError::Blocked {
            host: "h".into(),
            addr: "10.0.0.1".parse().unwrap(),
            class: crate::net_policy::HostClass::PrivateV4,
            policy: BlockingPolicy::WorkspaceRegistries(WorkspaceRegistryAccess::PublicOnly),
        };
        assert_matches!(
            preflight_error("https://h.test/", Box::new(blocked)),
            DepsError::HostBlockedByPolicy { .. }
        );
        let dns = std::io::Error::other("lookup failed");
        assert_matches!(
            preflight_error("https://h.test/", Box::new(dns)),
            DepsError::CacheError(_)
        );
    }

    /// G2: the pinned tier's preflight is enforced on the send path, not merely present.
    #[tokio::test]
    async fn test_pinned_tier_preflight_refuses_a_private_target_before_the_proxy() {
        let (port, seen) = recording_proxy().await;
        let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
        let route = ProxyRoute::Fixed(Url::parse(&format!("http://proxy.test:{port}")).unwrap());
        let resolver = BlockedAddrResolver::with_lookup(
            guard.clone(),
            route.exempt_hosts(),
            lookup_for("proxy.test", "10.0.0.5:0"),
        );
        let transport = Transport::from_parts(
            trusted_origin_redirect_policy("https://registry.test/"),
            resolver,
            GuardedEgress::Proxy,
            &route,
            CacheTier::Pinned { digest: 1 },
        );
        assert!(transport.preflight.is_some());

        let result = fetch_via(&transport).await;

        assert_matches!(result, Err(DepsError::HostBlockedByPolicy { .. }));
        assert!(seen.lock().unwrap().is_empty());
    }

    /// G4: the connect timeout is applied to the client configuration every transport shares.
    #[test]
    fn test_connect_timeout_is_applied_to_the_shared_client_builder() {
        let builder = base_client_builder(&ProxyRoute::Bypass);
        let debug = format!("{builder:?}");
        assert!(debug.contains("connect_timeout: 10s"), "{debug}");
        assert!(debug.contains("timeout: 30s"), "{debug}");
    }

    /// G5: under Proxy egress a cross-host redirect is stopped end to end through a built
    /// transport, and the other host is never contacted.
    #[tokio::test]
    async fn test_proxy_egress_transport_stops_cross_host_redirect_end_to_end() {
        let mut origin = mockito::Server::new_async().await;
        let mut other = mockito::Server::new_async().await;
        let target = format!(
            "http://localhost:{}/api/target",
            other.url().rsplit(':').next().unwrap()
        );
        let _redirect = origin
            .mock("GET", "/api/source")
            .with_status(302)
            .with_header("location", &target)
            .create_async()
            .await;
        let landed = other
            .mock("GET", "/api/target")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;
        let guard = workspace_guard(WorkspaceRegistryAccess::All, &[]);
        let transport = Transport::from_parts(
            redirect_policy(guard.clone(), RedirectScope::SameHost),
            BlockedAddrResolver::new(guard, Arc::from([])),
            GuardedEgress::Proxy,
            &ProxyRoute::Bypass,
            CacheTier::Baseline,
        );

        let result = fetch_url_via(&format!("{}/api/source", origin.url()), &transport).await;

        assert_matches!(result, Err(DepsError::HttpStatus { status: 302, .. }));
        landed.assert_async().await;
    }

    /// CodeQL cleartext-transmission audit: a credential is withheld, on both APIs, from a URL
    /// that is not under the trusted prefix (a different host, scheme or sibling path), so a
    /// request can never start outside the origin the redirect policy confines it to.
    #[tokio::test]
    async fn test_credential_is_refused_for_a_url_outside_the_trusted_prefix() {
        let mut server = mockito::Server::new_async().await;
        let hit = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let cache = HttpCache::new();
        let origin = prefix(&format!("{}/api/", server.url()));
        for url in [
            format!("{}/apiX/data", server.url()),
            format!("{}/other", server.url()),
            "https://elsewhere.test/api/data".to_string(),
            "http://elsewhere.test/api/data".to_string(),
            "not a url".to_string(),
        ] {
            let trusted = cache
                .get_cached_trusted_origin(&url, &origin, cred_in(7), None)
                .await;
            let pinned = cache
                .get_cached_pinned(&url, &origin, cred_in(7), None)
                .await;
            assert_matches!(trusted, Err(DepsError::CacheError(_)), "{url}");
            assert_matches!(pinned, Err(DepsError::CacheError(_)), "{url}");
        }
        hit.assert_async().await;
    }

    /// The same URLs stay reachable anonymously: the guard concerns credentials only.
    #[tokio::test]
    async fn test_anonymous_request_outside_the_prefix_is_not_refused_by_the_credential_guard() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/other")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let cache = HttpCache::new();
        let origin = prefix(&format!("{}/api/", server.url()));

        let body = cache
            .get_cached_trusted_origin(
                &format!("{}/other", server.url()),
                &origin,
                RequestAuth::ANONYMOUS,
                None,
            )
            .await
            .unwrap();

        assert_eq!(body.as_ref(), b"ok");
    }

    /// An `https` request under an `https` prefix is never followed onto plain `http`, with a
    /// credential or without, on the trusted-origin redirect policy.
    #[test]
    fn test_trusted_origin_redirect_policy_origin_includes_the_scheme() {
        let https = prefix("https://registry.test/api/");
        let downgraded = Url::parse("http://registry.test/api/x").unwrap();
        let same = Url::parse("https://registry.test/api/x").unwrap();
        assert!(!https.permits(&downgraded));
        assert!(https.permits(&same));
    }
}

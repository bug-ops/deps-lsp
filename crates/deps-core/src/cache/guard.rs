//! HTTPS enforcement and the resolved-address guard tiers shared by every transport.

use crate::error::{DepsError, Result};
use crate::net_policy::{AccessSnapshot, BlockedHost, Target};
use crate::redact::RedactedUrl;
use reqwest::Url;

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
pub(super) fn is_loopback_host(url: &str) -> bool {
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
/// Returns [`DepsError::InsecureScheme`] if the URL doesn't start with "https://".
/// This ensures all network requests are encrypted.
///
/// Callers pass only URLs built from a configured or operator-declared base; a URL a registry
/// supplies must be vetted by its ecosystem before it reaches here, so this error stays a
/// configuration fault.
///
/// A loopback HTTP URL (`127.0.0.1`/`localhost`/`::1`, the shape every `mockito::Server`
/// binds to) is allowed in `deps-core`'s own test builds (`cfg(test)`) and in other
/// workspace crates' test builds via the `test-util` feature — `cfg(test)` alone does not
/// apply there, since those crates depend on `deps-core` as a normal, non-dev dependency.
/// Any other HTTP host is still rejected even under those cfgs: `test-util` is a public,
/// independently-enablable crates.io feature, so this must not become "any host, any
/// environment" just because the feature is on.
#[inline]
pub(super) fn ensure_https(url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    #[cfg(any(test, feature = "test-util"))]
    if is_loopback_host(url) {
        return Ok(());
    }
    Err(DepsError::InsecureScheme {
        url: RedactedUrl::new(url),
    })
}

/// True when a redirect hop moves from an `https` origin to a plain `http` one.
///
/// A redirect to any scheme other than `http`/`https` is already rejected by reqwest
/// itself once a hop is followed, so the downgrade case is the only one this needs to
/// catch here.
pub(super) fn is_https_downgrade(previous: &Url, next: &Url) -> bool {
    previous.scheme() == "https" && next.scheme() == "http"
}

/// Whether a redirect hop's target host is one [`crate::net_policy::HostClass::never_a_registry`]
/// blocks, exempting `Loopback` in test builds — the identical carve-out [`ensure_https`]
/// already uses, without which every mockito redirect chain in this workspace's tests would
/// break.
pub(super) fn hop_targets_blocked_host(url: &Url) -> bool {
    let class = crate::net_policy::classify_host(url);
    #[cfg(any(test, feature = "test-util"))]
    let class_blocked = class.never_a_registry() && class != crate::net_policy::HostClass::Loopback;
    #[cfg(not(any(test, feature = "test-util")))]
    let class_blocked = class.never_a_registry();
    class_blocked
}

/// The tier a [`Transport`](super::transport::Transport)'s redirect policy and DNS resolver both enforce.
///
/// `WorkspaceDeclared` holds an [`AccessSnapshot`] (level and allowlist) **value snapshot**, taken once at
/// [`Transport::workspace`](super::transport::Transport::workspace) construction time — not a live `Arc<RegistryAccessPolicy>` read on
/// every `AddrGuard::permits_declared` call. [`Transport::workspace`](super::transport::Transport::workspace) takes this same snapshot for its
/// paired [`CacheTier::WorkspaceDeclared`](super::CacheTier::WorkspaceDeclared), and [`HttpCache::set_registry_policy`](super::HttpCache::set_registry_policy) rebuilds the
/// whole `Transport` (both snapshots included) on every actual policy transition, so a
/// request's cache key and its guard always come from one consistent construction-time value,
/// with no read-skew window between them.
#[derive(Debug, Clone)]
pub(super) enum AddrGuard {
    Baseline,
    WorkspaceDeclared(AccessSnapshot),
}

impl AddrGuard {
    /// Whether a redirect hop's declared `url` may be reached under this guard's tier.
    pub(super) fn permits_declared(&self, url: &Url) -> bool {
        match self {
            Self::Baseline => true,
            Self::WorkspaceDeclared(snapshot) => snapshot.permits_url(url),
        }
    }

    /// Why `ip`, resolved for `name` as `class`, may not be connected to under this guard's tier,
    /// or `None` when it may. The one place that both decides and labels the refusal, so a
    /// blocked address can never lose its [`BlockedHost`]: only the floor applies at the
    /// baseline tier, and the workspace tier adds the live policy snapshot.
    pub(super) fn refusal(
        &self,
        name: &str,
        ip: std::net::IpAddr,
        class: crate::net_policy::HostClass,
    ) -> Option<BlockedHost> {
        match self {
            Self::Baseline => BlockedHost::floor(class),
            Self::WorkspaceDeclared(snapshot) => (class.never_a_registry()
                || !snapshot.permits(Target::Resolved { name, ip }))
            .then(|| BlockedHost::new(class, snapshot.level)),
        }
    }
}

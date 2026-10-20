//! Redirect policies that keep redirect hops inside the active egress and trust scope.

use super::guard::AddrGuard;
use super::guard::hop_targets_blocked_host;
use super::guard::is_https_downgrade;
use crate::net_policy::{GuardedEgress, TrustedPrefix};
use crate::redact::url_for_tracing;
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{LazyLock, Mutex, PoisonError};

/// Whether a redirect may leave the host of the request that produced it.
///
/// Guarded traffic through a proxy is preflighted per request host, and a redirect hop's target
/// cannot be preflighted from the synchronous redirect callback, so such traffic stays on the
/// host it started on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RedirectScope {
    AnyHost,
    SameHost,
}

impl RedirectScope {
    pub(super) const fn for_egress(egress: GuardedEgress) -> Self {
        match egress {
            GuardedEgress::Direct => Self::AnyHost,
            GuardedEgress::Proxy => Self::SameHost,
        }
    }
}

/// Redirect policy for a [`Transport`](super::transport::Transport)'s client, parameterized by the [`AddrGuard`] tier that
/// client enforces.
///
/// [`ensure_https`](super::guard::ensure_https) only validates the *initial* request URL; a `3xx` response can still
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
/// `guard`'s own `AddrGuard::permits_declared` term additionally rejects a hop whose target class
/// the *tier* does not allow — under [`AddrGuard::Baseline`] this term is constant `false`, so
/// every non-Cargo ecosystem (and Cargo's own `$CARGO_HOME`-provenance traffic) is
/// bit-for-bit unaffected; under [`AddrGuard::WorkspaceDeclared`] it closes the redirect-hop
/// half of issue #455 (an IP-literal hop to an RFC1918/CGNAT address, which `hyper-util`
/// parses directly and never routes through a resolver).
///
/// This only classifies the redirect target's URL string, not its DNS-resolved address — that
/// residual gap (issue #449, "D1" in PR #447's plan) is closed for the name-hop case by
/// [`BlockedAddrResolver`](super::resolver::BlockedAddrResolver), which `build_client_inner` wires into every client this module
/// builds: a redirect hop reuses the same `Client`, so its target's resolved address is
/// validated too, for free (FR-007).
///
/// Every other redirect — including cross-host ones, which are out of scope for this
/// policy — falls through to reqwest's default (`Policy::limited(10)`), preserving the
/// existing hop-count limit and mockito's plain-`http://` loopback chains
/// used throughout this module's tests.
pub(super) fn redirect_policy(guard: AddrGuard, scope: RedirectScope) -> reqwest::redirect::Policy {
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

/// Redirect policy for a [`HttpCache::transport_for_origin`](super::HttpCache::transport_for_origin)-scoped client.
///
/// Stops any hop unless [`TrustedPrefix::permits`] accepts it — origin equality (scheme, host
/// and port must match exactly) **and** the hop's path lying at or under the prefix's own path,
/// at a proper path-segment boundary (see [`crate::net_policy::is_trusted_prefix`], which
/// carries the issue #795 bypass shapes this closes: subdomain-suffix, userinfo, hyphen-suffix
/// and same-origin sibling paths). The prefix arrives already parsed, so there is no
/// "unparseable prefix" branch to fail closed on.
///
/// Origin equality also covers a downgrade to plain `http://`: an `http://` hop's origin can
/// never equal an `https://`-scheme trusted origin, which every current caller passes.
///
/// This policy is the confinement rule for every request that carries a *header* credential: the
/// credential-bearing entry points route through it, so a registry can never redirect a token
/// header to another origin. A request without a header credential is not bound by it. The
/// anonymous `Trusted` npm, Go and Cargo metadata fetches use [`redirect_policy`] instead and
/// may leave their origin, because operator proxies (Athens in redirect mode, Artifactory
/// redirecting to object storage) do that on purpose; the never-a-registry floor and the
/// https-downgrade stop still apply on every hop. NuGet and Swift keep their anonymous `Trusted`
/// fetches origin-confined by choice.
///
/// A credential embedded in the request URL (a query token, a path token) is not a header and is
/// not covered by the confinement; the shared client therefore sends no `Referer`, so such a URL
/// is never handed to a redirect target.
///
/// A hop this policy stops is logged at `WARN` once per origin pair, with both origins redacted,
/// since the caller only sees the preceding `3xx` status. [`redirect_policy`] stops silently.
pub(super) fn trusted_origin_redirect_policy(prefix: TrustedPrefix) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if prefix.permits(attempt.url()) {
            reqwest::redirect::Policy::default().redirect(attempt)
        } else {
            if let Some(previous) = attempt.previous().last() {
                warn_stopped_hop(previous, attempt.url());
            }
            attempt.stop()
        }
    })
}

/// Origin pairs whose stopped hop has already been logged.
static STOPPED_HOPS_WARNED: LazyLock<Mutex<HashSet<u64>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Cap on distinct origin pairs [`STOPPED_HOPS_WARNED`] remembers.
const MAX_STOPPED_HOP_WARNINGS: usize = 256;

fn warn_stopped_hop(previous: &url::Url, target: &url::Url) {
    let from = previous.origin().ascii_serialization();
    let to = target.origin().ascii_serialization();
    let mut hasher = DefaultHasher::new();
    (&from, &to).hash(&mut hasher);
    let first_time = {
        let mut warned = STOPPED_HOPS_WARNED
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        warned.len() < MAX_STOPPED_HOP_WARNINGS && warned.insert(hasher.finish())
    };
    if !first_time {
        return;
    }
    if from == to {
        tracing::warn!(
            origin = %url_for_tracing(&from),
            "stopped a redirect that left the trusted registry path"
        );
    } else {
        tracing::warn!(
            from = %url_for_tracing(&from),
            to = %url_for_tracing(&to),
            "stopped a redirect that left the trusted origin"
        );
    }
}

//! DNS resolver wrapper that refuses blocked resolved addresses before a connection is made.

use super::guard::AddrGuard;
use crate::net_policy::{BlockedHost, normalize_host};
use std::sync::Arc;

/// Error returned by [`BlockedAddrResolver`] when a DNS resolution cannot be trusted for
/// connection use — either it produced no address, or at least one resolved address falls into
/// a blocked [`crate::net_policy::HostClass`].
///
/// Kept distinct from [`DepsError`](crate::error::DepsError) since this crosses into `reqwest::dns::Resolve`'s own
/// `BoxError` (`Box<dyn std::error::Error + Send + Sync>`) return type, not this crate's own
/// error type.
#[derive(Debug, thiserror::Error)]
pub(super) enum ResolveGuardError {
    /// The resolver returned zero addresses for `host` — fail-closed (NFR-004) rather than
    /// silently treating "nothing resolved" as "nothing to block".
    #[error("DNS resolution for {host} returned no addresses")]
    NoAddresses { host: String },
    /// `addr`, resolved for `host`, falls into `class`, one of the
    /// [`crate::net_policy::HostClass::never_a_registry`] classes no legitimate registry index
    /// (or a redirect from one) could ever target.
    #[error("resolved address {addr} for host {host} is {}, blocked by net_policy", block.class())]
    Blocked {
        host: String,
        addr: std::net::IpAddr,
        block: BlockedHost,
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
pub(super) fn validate_resolved_addrs(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
    guard: &AddrGuard,
) -> std::result::Result<Vec<std::net::SocketAddr>, ResolveGuardError> {
    let addrs = require_addresses(host, addrs)?;
    for addr in &addrs {
        let class = crate::net_policy::classify_addr(addr.ip());
        if let Some(block) = guard.refusal(host, addr.ip(), class) {
            tracing::warn!(host, addr = %addr.ip(), %class, "blocking DNS-resolved address");
            return Err(ResolveGuardError::Blocked {
                host: host.to_string(),
                addr: addr.ip(),
                block,
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
pub(super) struct TestLookup(pub(super) Arc<SyntheticLookupFn>);

#[cfg(test)]
impl std::fmt::Debug for TestLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestLookup(..)")
    }
}

/// Connect-time DNS resolver that closes the rebinding TOCTOU gap left by [`ensure_https`](super::guard::ensure_https)/
/// [`hop_targets_blocked_host`](super::guard::hop_targets_blocked_host)'s URL-string-only classification (issue #449): those check the
/// declared hostname, but `reqwest`'s connector resolves DNS independently, later, and an
/// attacker who controls the hostname's DNS can rebind it to a blocked address in between.
///
/// Wired into every client `build_client_inner` builds, so all 11 ecosystem crates sharing
/// the baseline client pool inherit it with zero per-crate plumbing (FR-006/NFR-002).
///
/// # Scope
///
/// This resolver's guard tier decides how much a resolved address is scrutinized: under
/// [`AddrGuard::Baseline`] this enforces only the policy-independent
/// [`crate::net_policy::HostClass::never_a_registry`] tier (loopback, link-local,
/// cloud-metadata, unspecified, reserved), the same tier [`hop_targets_blocked_host`](super::guard::hop_targets_blocked_host) already
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
///   [`classify_host`](crate::net_policy::classify_host) (via [`ensure_https`](super::guard::ensure_https)/
///   [`hop_targets_blocked_host`](super::guard::hop_targets_blocked_host)/[`redirect_policy`](super::redirect::redirect_policy)'s tier term) remains the sole guard for
///   literals — a disjoint domain from this resolver's name-based one, not a gap. This is also
///   why the cache layer gives [`HttpCache::get_cached_workspace`](super::HttpCache::get_cached_workspace) zero protection against an
///   *initial* request URL that is itself an IP literal — see that method's docs.
/// - Unlike [`ensure_https`](super::guard::ensure_https)/[`hop_targets_blocked_host`](super::guard::hop_targets_blocked_host), this resolver has **no** `test-util`
///   carve-out for `Loopback`: it blocks a `localhost`/`127.0.0.1` *name* unconditionally, in
///   every build. A downstream `test-util` consumer that mocks by binding an IP literal (as
///   this workspace's own `mockito` usage does) is unaffected — literals never reach this
///   resolver at all — but one that mocks via a `localhost` *name* would be newly blocked.
#[derive(Debug, Clone)]
pub(super) struct BlockedAddrResolver {
    pub(super) guard: AddrGuard,
    /// Normalized names (the proxy's own hosts) whose resolved addresses skip the address check:
    /// a proxy named by DNS is operator configuration, not attacker-controlled input.
    pub(super) exempt: Arc<[String]>,
    #[cfg(test)]
    pub(super) lookup: Option<TestLookup>,
}

impl BlockedAddrResolver {
    pub(super) fn new(guard: AddrGuard, exempt: Arc<[String]>) -> Self {
        Self {
            guard,
            exempt,
            #[cfg(test)]
            lookup: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_lookup(guard: AddrGuard, exempt: Arc<[String]>, lookup: TestLookup) -> Self {
        Self {
            guard,
            exempt,
            lookup: Some(lookup),
        }
    }
}

impl BlockedAddrResolver {
    pub(super) fn exempt_name(&self, host: &str) -> bool {
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

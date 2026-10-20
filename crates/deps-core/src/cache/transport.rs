//! Client construction, system-proxy routing, and the per-tier `Transport`.

use super::CacheTier;
use super::errors::preflight_error;
use super::guard::AddrGuard;
use super::redirect::RedirectScope;
use super::redirect::redirect_policy;
use super::redirect::trusted_origin_redirect_policy;
use super::resolver::BlockedAddrResolver;
#[cfg(test)]
use super::resolver::TestLookup;
use crate::error::Result;
use crate::net_policy::{
    AccessSnapshot, GuardedEgress, RegistryAccessPolicy, SystemProxy, TrustedPrefix,
    WorkspaceRegistryAccess, normalize_host,
};
use reqwest::{Client, Url};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

/// HTTP request timeout in seconds.
pub(super) const HTTP_TIMEOUT_SECS: u64 = 30;

/// Connect-phase timeout, so a blackholed address fails in 10 s rather than the full request
/// timeout.
pub(super) const HTTP_CONNECT_TIMEOUT_SECS: u64 = 10;

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
pub(super) enum ProxyRoute {
    System(SystemProxy),
    Bypass,
    #[cfg(test)]
    Fixed(Url),
}

impl ProxyRoute {
    /// The route for a transport enforcing `guard` under `egress`: baseline traffic always uses
    /// the system proxy; guarded traffic bypasses it unless the operator opted in.
    pub(super) fn for_tier(guard: &AddrGuard, egress: GuardedEgress) -> Self {
        match (guard, egress) {
            (AddrGuard::Baseline, GuardedEgress::Direct | GuardedEgress::Proxy)
            | (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Proxy) => {
                Self::System(detect_system_proxy())
            }
            (AddrGuard::WorkspaceDeclared(_), GuardedEgress::Direct) => Self::Bypass,
        }
    }

    pub(super) fn exempt_hosts(&self) -> Arc<[String]> {
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
pub(super) fn base_client_builder(route: &ProxyRoute) -> reqwest::ClientBuilder {
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
pub(super) fn build_client_inner(
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
pub(super) fn build_guarded_client_with_lookup(guard: AddrGuard, lookup: TestLookup) -> Client {
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
/// workspace cache namespace) never arises through normal construction. The fields are private
/// to this module, so those constructors are the only way to build one and a mismatched
/// `Transport { .. }` literal cannot be written elsewhere in `cache`.
#[derive(Clone)]
pub(super) struct Transport {
    client: Client,
    tier: CacheTier,
    /// Resolves each request's target name through the transport's own guard before the send,
    /// set only for guarded traffic that goes through the system proxy: the proxy resolves the
    /// target itself, so the client's own resolver never sees it.
    preflight: Option<BlockedAddrResolver>,
}

impl Transport {
    /// The client whose guard this transport's [`Self::tier`] names.
    pub(super) const fn client(&self) -> &Client {
        &self.client
    }

    /// The cache namespace this transport's requests are keyed under.
    pub(super) const fn tier(&self) -> CacheTier {
        self.tier
    }

    #[cfg(test)]
    pub(super) const fn has_preflight(&self) -> bool {
        self.preflight.is_some()
    }

    /// The shared, unauthenticated transport used by every non-workspace request.
    pub(super) fn baseline() -> Self {
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
    pub(super) fn workspace(policy: &Arc<RegistryAccessPolicy>) -> Self {
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

    /// The transport for one [`HttpCache::transport_for_origin`](super::HttpCache::transport_for_origin)-pinned origin: a plain
    /// [`AddrGuard::Baseline`] resolver, paired with [`trusted_origin_redirect_policy`] instead
    /// of [`redirect_policy`] — that policy pins by URL prefix, which already subsumes the
    /// blocked-host hop check.
    pub(super) fn origin_pinned(trusted_origin: &TrustedPrefix) -> Self {
        Self::assemble(
            trusted_origin_redirect_policy(trusted_origin.clone()),
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
    pub(super) fn origin_pinned_guarded(
        trusted_origin: &TrustedPrefix,
        snapshot: AccessSnapshot,
        egress: GuardedEgress,
    ) -> Self {
        let digest = pinned_digest(trusted_origin, snapshot.level);
        Self::assemble(
            trusted_origin_redirect_policy(trusted_origin.clone()),
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

    pub(super) fn from_parts(
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
    pub(super) async fn preflight(&self, url: &str) -> Result<()> {
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

/// Identifies a `(trusted_origin, policy_snapshot)` pair for [`CacheTier::Pinned`] — **never**
/// a credential identity (see that variant's docs). Not cryptographically salted: unlike a
/// caller's own credential-header digest (e.g. `deps_nuget`'s salted `auth_id`), this value is
/// not attacker-observable secret material, only a pool/cache-key discriminant.
pub(super) fn pinned_digest(
    trusted_origin: &TrustedPrefix,
    snapshot: WorkspaceRegistryAccess,
) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    trusted_origin.hash(&mut hasher);
    snapshot.hash(&mut hasher);
    hasher.finish()
}

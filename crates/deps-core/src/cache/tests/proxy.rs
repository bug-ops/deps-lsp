use super::*;
use std::str::FromStr;

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
            .transport_for_pinned(&prefix("https://registry.test/"))
            .preflight
            .is_some()
    );
    assert!(cache.baseline.preflight.is_none());
    assert!(
        HttpCache::new()
            .transport_for_pinned(&prefix("https://registry.test/"))
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

    assert_matches!(
        result,
        Err(DepsError::RegistryError { source, .. })
            if source.resolution_failure() == Some(crate::error::ResolutionFailure::NoAddresses)
    );
    assert!(seen.lock().unwrap().is_empty());
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
        trusted_origin_redirect_policy(prefix("https://registry.test/")),
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

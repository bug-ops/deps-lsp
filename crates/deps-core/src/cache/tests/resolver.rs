use super::*;

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
        validate_resolved_addrs("index.crates.io", addrs.clone(), &AddrGuard::Baseline).unwrap(),
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
    let Err(DepsError::HostBlockedByPolicy { block, .. }) = result else {
        panic!("expected HostBlockedByPolicy, got {result:?}");
    };
    assert_eq!(block.class(), crate::net_policy::HostClass::Loopback);
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

    let client = Transport::baseline().client().clone();
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

// Spec 084: the transport a URL's trust selects decides what its connect-time guard allows.
// The synthetic lookup resolves every name to an RFC1918 address, so the resolver guard rejects
// (or admits) before any TCP attempt.
mod trust_connect {
    use super::*;
    use crate::EgressTier;
    use crate::config_trust::OperatorPath;
    use crate::net_policy::{OperatorRegistries, RegistryTrust};

    /// A guard the way each trust's egress builds one: Baseline for Trusted, the workspace guard
    /// for workspace-declared.
    fn guard_for(trust: RegistryTrust) -> AddrGuard {
        match trust.egress() {
            EgressTier::Baseline => AddrGuard::Baseline,
            EgressTier::Guarded => workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]),
        }
    }

    fn private_lookup() -> TestLookup {
        TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]))
    }

    fn trust_of(operator: &OperatorRegistries, url: &str) -> RegistryTrust {
        use crate::net_policy::{IndexUrlError, RegistryAccessPolicy, RegistryUrlKind};
        enum Kind {}
        impl crate::net_policy::private::Sealed for Kind {}
        impl RegistryUrlKind for Kind {
            const ECOSYSTEM: crate::EcosystemId = crate::EcosystemId::Npm;
            const REJECT_QUERY_FRAGMENT: bool = false;
            type Error = IndexUrlError;
        }
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::All);
        operator
            .classify::<Kind>(url, url, &policy)
            .unwrap()
            .trust()
    }

    async fn resolves(trust: RegistryTrust) -> bool {
        use reqwest::dns::Resolve;
        BlockedAddrResolver::with_lookup(guard_for(trust), Arc::from([]), private_lookup())
            .resolve("registry.corp.example".parse().unwrap())
            .await
            .is_ok()
    }

    fn operator() -> OperatorRegistries {
        OperatorRegistries::declared_in(
            &OperatorPath::for_test("/home/me/.npmrc"),
            ["https://registry.corp.example/team-a"],
        )
    }

    #[tokio::test]
    async fn a_trusted_private_host_is_reachable() {
        let trust = trust_of(&operator(), "https://registry.corp.example/team-a");
        assert_eq!(trust, RegistryTrust::Trusted);
        assert!(resolves(trust).await);
    }

    #[tokio::test]
    async fn a_project_declared_host_resolving_to_rfc1918_is_blocked_under_public_only() {
        let trust = trust_of(&operator(), "https://repo-chosen.example/team-a");
        assert_eq!(trust, RegistryTrust::WorkspaceDeclared);
        assert!(!resolves(trust).await);
    }

    #[tokio::test]
    async fn the_operators_host_with_another_path_stays_blocked_at_connect() {
        let trust = trust_of(&operator(), "https://registry.corp.example/team-b");
        assert_eq!(trust, RegistryTrust::WorkspaceDeclared);
        assert!(!resolves(trust).await);
    }

    #[tokio::test]
    async fn a_trusted_host_still_cannot_resolve_to_cloud_metadata() {
        use reqwest::dns::Resolve;
        let lookup = TestLookup(Arc::new(|_host: &str| {
            vec!["169.254.169.254:0".parse().unwrap()]
        }));
        let resolver = BlockedAddrResolver::with_lookup(
            guard_for(RegistryTrust::Trusted),
            Arc::from([]),
            lookup,
        );
        assert!(
            resolver
                .resolve("registry.corp.example".parse().unwrap())
                .await
                .is_err()
        );
    }
}

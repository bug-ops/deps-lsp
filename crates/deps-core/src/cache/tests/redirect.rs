use super::*;

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

// #1856: an anonymous fetch is deliberately not origin-confined. Operator proxies (Athens in
// redirect mode, Artifactory redirecting to object storage) answer metadata requests with a
// cross-origin redirect, and npm and Go `Trusted` fetches rely on following it. The floor and the
// https-downgrade stop still apply on every hop (see the cloud-metadata test above).
#[tokio::test]
async fn test_get_cached_anonymous_follows_cross_origin_redirect() {
    let mut origin_server = mockito::Server::new_async().await;
    let mut storage_server = mockito::Server::new_async().await;
    let target_url = format!("{}/api/target", storage_server.url());

    let _redirect = origin_server
        .mock("GET", "/api/source")
        .with_status(302)
        .with_header("location", &target_url)
        .create_async()
        .await;
    let target = storage_server
        .mock("GET", "/api/target")
        .with_status(200)
        .with_body("from the other origin")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let source_url = format!("{}/api/source", origin_server.url());
    let result: Bytes = cache.get_cached(&source_url).await.unwrap();

    assert_eq!(result.as_ref(), b"from the other origin");
    target.assert_async().await;
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
        .post_json_limited_trusted_origin(&url, &body, BodyLimit::DEFAULT, &prefix(&trusted_origin))
        .await;

    assert!(
        result.is_err(),
        "an untrusted redirect hop must not be followed"
    );
    evil_call.assert_async().await;
}

#[tokio::test]
async fn test_get_transport_only_limited_trusted_origin_stops_cross_origin_redirect() {
    let mut server = mockito::Server::new_async().await;
    let mut evil = mockito::Server::new_async().await;
    let _redirect = server
        .mock("GET", "/data")
        .with_status(302)
        .with_header("location", &format!("{}/steal", evil.url()))
        .create_async()
        .await;
    let evil_call = evil.mock("GET", "/steal").expect(0).create_async().await;

    let cache = HttpCache::new();
    let result = cache
        .get_transport_only_with_headers_limited_trusted_origin(
            &format!("{}/data", server.url()),
            &[],
            BodyLimit::DEFAULT,
            &prefix(&format!("{}/", server.url())),
        )
        .await;

    assert!(
        result.is_err(),
        "an untrusted redirect hop must not be followed"
    );
    evil_call.assert_async().await;
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

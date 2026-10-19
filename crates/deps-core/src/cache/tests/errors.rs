use super::*;

#[tokio::test]
async fn test_send_error_maps_gated_class_to_host_blocked_by_policy() {
    let lookup = TestLookup(Arc::new(|_host: &str| vec!["10.0.0.1:0".parse().unwrap()]));
    let guard = workspace_guard(WorkspaceRegistryAccess::PublicOnly, &[]);
    let client = build_guarded_client_with_lookup(guard, lookup);
    let url = "https://corp.example/index";
    let error = client.get(url).send().await.unwrap_err();
    match send_error(url, error) {
        DepsError::HostBlockedByPolicy { block, .. } => {
            assert_eq!(block.class(), crate::net_policy::HostClass::PrivateV4);
            assert_eq!(
                block.policy(),
                crate::net_policy::BlockingPolicy::WorkspaceRegistries(
                    WorkspaceRegistryAccess::PublicOnly
                )
            );
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
    let DepsError::HostBlockedByPolicy { block, .. } = mapped else {
        panic!("expected HostBlockedByPolicy, got {mapped:?}");
    };
    assert_matches!(
        block.class(),
        crate::net_policy::HostClass::LinkLocal | crate::net_policy::HostClass::CloudMetadata
    );
    assert_eq!(block.policy(), crate::net_policy::BlockingPolicy::Floor);
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
    let output = crate::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
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

#[test]
fn test_preflight_error_maps_blocked_to_policy_and_everything_else_to_registry_error() {
    let blocked = ResolveGuardError::Blocked {
        host: "h".into(),
        addr: "10.0.0.1".parse().unwrap(),
        block: crate::net_policy::BlockedHost::new(
            crate::net_policy::HostClass::PrivateV4,
            WorkspaceRegistryAccess::PublicOnly,
        ),
    };
    assert_matches!(
        preflight_error("https://h.test/", Box::new(blocked)),
        DepsError::HostBlockedByPolicy { .. }
    );
    let dns = std::io::Error::other("lookup failed");
    assert_matches!(
        preflight_error("https://h.test/", Box::new(dns)),
        DepsError::RegistryError { source, .. }
            if source.resolution_failure() == Some(crate::error::ResolutionFailure::LookupFailed)
    );
    let empty = ResolveGuardError::NoAddresses { host: "h".into() };
    let error = preflight_error("https://h.test/", Box::new(empty));
    assert_eq!(error.fetch_failure(), crate::FetchFailure::Transient);
}

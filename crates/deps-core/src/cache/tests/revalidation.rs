use super::*;

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
        .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url, LivePolicy::default())
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
        .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url, LivePolicy::default())
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
        .fetch_and_store_with_headers(&url, &[], &cache.baseline, &url, LivePolicy::default())
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

use super::*;

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

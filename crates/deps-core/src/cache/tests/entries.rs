use super::*;

#[test]
fn test_cache_creation() {
    let cache = HttpCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn test_cache_clear() {
    let cache = HttpCache::new();
    cache.entries.insert(
        "test".into(),
        CachedResponse {
            body: Bytes::from_static(&[1, 2, 3]),
            etag: None,
            last_modified: None,
            link: None,
            fetched_at: Instant::now(),
        },
    );
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_cached_response_clone() {
    let response = CachedResponse {
        body: Bytes::from_static(&[1, 2, 3]),
        etag: Some("test".into()),
        last_modified: Some("date".into()),
        link: None,
        fetched_at: Instant::now(),
    };
    let cloned = response.clone();
    // Bytes clone is cheap (reference counting)
    assert_eq!(response.body, cloned.body);
    assert_eq!(response.etag, cloned.etag);
}

#[test]
fn test_cache_len() {
    let cache = HttpCache::new();
    assert_eq!(cache.len(), 0);

    cache.entries.insert(
        "url1".into(),
        CachedResponse {
            body: Bytes::new(),
            etag: None,
            last_modified: None,
            link: None,
            fetched_at: Instant::now(),
        },
    );

    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn test_get_cached_fresh_fetch() {
    let mut server = mockito::Server::new_async().await;

    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_header("etag", "\"abc123\"")
        .with_body("test data")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let url = format!("{}/api/data", server.url());
    let result: Bytes = cache.get_cached(&url).await.unwrap();

    assert_eq!(result.as_ref(), b"test data");
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn test_get_cached_cache_hit() {
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
    assert_eq!(cache.len(), 1);

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
async fn test_evict_url_prefix_drops_only_matching_entries() {
    let mut server = mockito::Server::new_async().await;
    let _a = server
        .mock("GET", "/api/a")
        .with_status(200)
        .with_body("a")
        .create_async()
        .await;
    let _b = server
        .mock("GET", "/other/b")
        .with_status(200)
        .with_body("b")
        .create_async()
        .await;
    let cache = HttpCache::new();
    cache
        .get_cached(&format!("{}/api/a", server.url()))
        .await
        .unwrap();
    cache
        .get_cached(&format!("{}/other/b", server.url()))
        .await
        .unwrap();
    assert_eq!(cache.evict_url_prefix(&format!("{}/api/", server.url())), 1);
    assert_eq!(cache.len(), 1);
}

#[test]
fn test_total_bytes_tracks_inserts_and_replacement() {
    let cache = HttpCache::new();
    cache.store_entry("url1".into(), dummy_response(100));
    assert_eq!(cache.total_bytes(), 100);

    // Replacing the same key must account for the delta, not just add.
    cache.store_entry("url1".into(), dummy_response(40));
    assert_eq!(cache.total_bytes(), 40);

    cache.store_entry("url2".into(), dummy_response(60));
    assert_eq!(cache.total_bytes(), 100);
}

#[test]
fn test_clear_resets_total_bytes() {
    let cache = HttpCache::new();
    cache.store_entry("url1".into(), dummy_response(1000));
    assert_eq!(cache.total_bytes(), 1000);

    cache.clear();
    assert_eq!(cache.total_bytes(), 0);
}

#[test]
fn test_small_payloads_do_not_trigger_eviction() {
    let cache = HttpCache::new();
    for i in 0..50 {
        cache.store_entry(format!("url{i}"), dummy_response(1024));
    }

    assert_eq!(cache.len(), 50);
    assert_eq!(cache.total_bytes(), 50 * 1024);
}

#[test]
fn test_evict_entries_triggers_on_byte_budget_with_few_entries() {
    let cache = HttpCache::new();

    // 9 entries at the per-entry admission cap: far below MAX_CACHE_ENTRIES by count, but
    // their combined size (72 MiB) overshoots MAX_CACHE_BYTES (64 MiB).
    for i in 0..9 {
        cache.store_entry(format!("url{i}"), dummy_response(MAX_CACHEABLE_ENTRY_BYTES));
    }
    assert_eq!(cache.len(), 9);
    assert!(cache.total_bytes() > MAX_CACHE_BYTES);

    cache.evict_entries();

    // Only as many oldest entries as needed to clear the byte budget are removed, not a
    // fixed count-based batch.
    assert!(cache.total_bytes() <= MAX_CACHE_BYTES);
    assert_eq!(cache.len(), 8);
}

#[test]
fn test_evict_entries_removes_oldest_first_for_bytes() {
    let cache = HttpCache::new();

    // Evicting just the single oldest entry should restore the cache to within budget,
    // proving eviction picks the genuinely oldest entry, not hash-iteration order.
    cache.store_entry("oldest".into(), dummy_response(MAX_CACHEABLE_ENTRY_BYTES));
    std::thread::sleep(std::time::Duration::from_millis(5));
    for i in 0..8 {
        cache.store_entry(
            format!("newer{i}"),
            dummy_response(MAX_CACHEABLE_ENTRY_BYTES),
        );
    }
    assert_eq!(cache.len(), 9);

    cache.evict_entries();

    assert_eq!(cache.len(), 8);
    assert!(cache.entries.get("oldest").is_none());
    for i in 0..8 {
        assert!(cache.entries.get(&format!("newer{i}")).is_some());
    }
}

#[tokio::test]
async fn test_get_cached_with_headers_evicts_on_byte_budget() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());

    let cache = HttpCache::new();

    // Pre-fill past the byte budget, staying under MAX_CACHE_ENTRIES by count.
    for i in 0..9 {
        cache.store_entry(
            format!("stale{i}"),
            dummy_response(MAX_CACHEABLE_ENTRY_BYTES),
        );
    }
    assert!(cache.total_bytes() > MAX_CACHE_BYTES);

    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("fresh")
        .create_async()
        .await;

    let result: Bytes = cache.get_cached(&url).await.unwrap();
    assert_eq!(result.as_ref(), b"fresh");

    // The pre-request byte-budget check evicted stale entries before fetching.
    assert!(cache.total_bytes() <= MAX_CACHE_BYTES + result.len());
}

#[test]
fn test_store_entry_skips_caching_oversized_entry() {
    let cache = HttpCache::new();

    // A body over the per-entry admission cap is not retained, even though the caller
    // still gets it back (store_entry's caller already holds `body` independently).
    cache.store_entry("big".into(), dummy_response(MAX_CACHEABLE_ENTRY_BYTES + 1));
    assert!(cache.entries.get("big").is_none());
    assert_eq!(cache.total_bytes(), 0);

    // Replacing an existing small entry with an oversized one drops the stale entry too,
    // rather than leaving it to keep serving increasingly outdated data.
    cache.store_entry("small".into(), dummy_response(100));
    assert_eq!(cache.total_bytes(), 100);

    cache.store_entry(
        "small".into(),
        dummy_response(MAX_CACHEABLE_ENTRY_BYTES + 1),
    );
    assert!(cache.entries.get("small").is_none());
    assert_eq!(cache.total_bytes(), 0);
}

#[test]
fn test_concurrent_store_and_evict_keeps_total_bytes_consistent() {
    use std::sync::Arc;
    use std::thread;

    let cache = Arc::new(HttpCache::new());
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                for i in 0..150 {
                    cache.store_entry(format!("t{t}-{i}"), dummy_response(4096));
                    if i % 10 == 0 {
                        cache.evict_entries();
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
    cache.evict_entries();

    // Regression guard: evict_entries used to snapshot total_bytes once and overwrite it
    // with an absolute store, silently discarding any concurrent store_entry delta.
    let actual: usize = cache
        .entries
        .iter()
        .map(|entry| entry.value().body.len())
        .sum();
    assert_eq!(cache.total_bytes(), actual);
}

// Issue #455, test-plan item 5: `get_cached(url)` then `get_cached_workspace(url)` do not
// share an entry — each is keyed under a distinct namespace (see `HttpCache::cache_key`),
// so the mockito mock is hit twice and the cache ends up with two entries for one URL.
#[tokio::test]
async fn test_get_cached_and_get_cached_workspace_do_not_share_an_entry() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());

    let mock = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("shared url, distinct tiers")
        .expect(2)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let baseline_result: Bytes = cache.get_cached(&url).await.unwrap();
    let workspace_result: Bytes = cache.get_cached_workspace(&url).await.unwrap();

    assert_eq!(baseline_result.as_ref(), b"shared url, distinct tiers");
    assert_eq!(workspace_result.as_ref(), b"shared url, distinct tiers");
    assert_eq!(cache.len(), 2);
    mock.assert_async().await;
}

// Issue #455, test-plan item 6 (C5): fetch under `All`, tighten to `PublicOnly`, re-fetch
// the same URL — the `All`-era body must not be served, since the policy-scoped key
// namespace changes with the policy.
#[tokio::test]
async fn test_set_registry_policy_change_does_not_serve_stale_era_body() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());

    let _first = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("all-era body")
        .create_async()
        .await;

    let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
    let cache = HttpCache::with_policy(Arc::clone(&policy));
    let first: Bytes = cache.get_cached_workspace(&url).await.unwrap();
    assert_eq!(first.as_ref(), b"all-era body");

    cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);

    let _second = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("public-only-era body")
        .create_async()
        .await;

    let second: Bytes = cache.get_cached_workspace(&url).await.unwrap();
    assert_eq!(
        second.as_ref(),
        b"public-only-era body",
        "the All-era cached body must not be served after tightening to PublicOnly"
    );
    // mockito's second mock answers regardless of which entry was hit, so the body
    // assertion alone wouldn't prove a policy-blind key — this length check does.
    assert_eq!(cache.len(), 2);
}

// Issue #455, test-plan item 7 (C4): `set_registry_policy` rebuilds the workspace transport
// only on an actual change, not on a no-op re-application of the same value.
#[test]
fn test_set_registry_policy_rebuilds_only_on_change() {
    let policy = Arc::new(RegistryAccessPolicy::new(
        WorkspaceRegistryAccess::PublicOnly,
    ));
    let cache = HttpCache::with_policy(policy);
    assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 0);

    cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);
    assert_eq!(
        cache.workspace_rebuilds.load(Ordering::Relaxed),
        0,
        "re-applying the unchanged policy must not rebuild the workspace transport"
    );

    cache.set_registry_policy(WorkspaceRegistryAccess::All);
    assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 1);

    cache.set_registry_policy(WorkspaceRegistryAccess::All);
    assert_eq!(
        cache.workspace_rebuilds.load(Ordering::Relaxed),
        1,
        "re-applying the unchanged (new) policy must not rebuild again"
    );

    cache.set_registry_policy(WorkspaceRegistryAccess::Off);
    assert_eq!(cache.workspace_rebuilds.load(Ordering::Relaxed), 2);
}

// Issue #483: `.expect(0)` proves nothing reached *this mock*, not that zero sockets
// ever opened — adequate only because the loopback carve-out lets mockito stand in here.

/// #1025: an unpartitioned anonymous request and a credential whose salted digest happens to
/// hash to exactly `0` must produce different `Pinned`-tier cache keys.
#[test]
fn test_cache_key_pinned_anonymous_and_zero_digest_credential_never_collide() {
    let cache = HttpCache::new();
    let tier = pinned_tier(42);

    let anonymous = cache.cache_key("https://example.com/pkg", tier, KeyAuth::ANONYMOUS);
    let zero_digest_credential = cache.cache_key(
        "https://example.com/pkg",
        tier,
        KeyAuth::Credential(partition(0)),
    );

    assert_ne!(anonymous, zero_digest_credential);
}

/// Critic S1: the same partition used with a credential and anonymously yields two keys, on
/// every tier that folds a partition in.
#[test]
fn test_cache_key_same_partition_credential_and_anonymous_never_collide() {
    let cache = HttpCache::new();
    for tier in [CacheTier::Baseline, pinned_tier(42)] {
        let credentialed = cache.cache_key(
            "https://example.com/pkg",
            tier,
            KeyAuth::Credential(partition(7)),
        );
        let anonymous = cache.cache_key(
            "https://example.com/pkg",
            tier,
            KeyAuth::Anonymous(Some(partition(7))),
        );
        assert_ne!(credentialed, anonymous, "{tier:?}");
    }
}

/// Critic S1, end to end: the same partition id used with a credential and with
/// `Anonymous { partition: Some(p) }` yields two distinct cache entries on both APIs.
#[tokio::test]
async fn test_same_partition_credential_and_anonymous_use_distinct_entries_on_both_apis() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/api/data", server.url());
    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("body")
        .expect(4)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let origin = prefix(&trusted_origin);
    let anonymous = RequestAuth::Anonymous {
        partition: Some(partition(5)),
    };
    cache
        .get_cached_trusted_origin(&url, &origin, cred_in(5), None)
        .await
        .unwrap();
    cache
        .get_cached_trusted_origin(&url, &origin, anonymous, None)
        .await
        .unwrap();
    assert_eq!(cache.len(), 2);
    cache
        .get_cached_pinned(&url, &origin, cred_in(5), None)
        .await
        .unwrap();
    cache
        .get_cached_pinned(&url, &origin, anonymous, None)
        .await
        .unwrap();
    assert_eq!(cache.len(), 4);
}

/// #1025 regression guard: distinct partitions keep producing distinct keys.
#[test]
fn test_cache_key_pinned_nonzero_partition_still_distinct() {
    let cache = HttpCache::new();
    let tier = pinned_tier(42);

    let a = cache.cache_key(
        "https://example.com/pkg",
        tier,
        KeyAuth::Credential(partition(1)),
    );
    let b = cache.cache_key(
        "https://example.com/pkg",
        tier,
        KeyAuth::Credential(partition(2)),
    );
    let anonymous = cache.cache_key("https://example.com/pkg", tier, KeyAuth::ANONYMOUS);

    assert_ne!(a, b);
    assert_ne!(a, anonymous);
    assert_ne!(b, anonymous);
}

/// #1025 M2: proves the fixed-width invariant itself — a regression that dropped zero-padding
/// would let differently-shaped `(digest, partition)` pairs concatenate to the same string.
/// Every combination drawn from these boundary-value sets must produce a distinct key.
#[test]
fn test_cache_key_pinned_digest_and_partition_matrix_never_collide() {
    let cache = HttpCache::new();
    let digests = [0u64, 1, 0x11, u64::MAX];
    let auths = [
        KeyAuth::ANONYMOUS,
        KeyAuth::Anonymous(Some(partition(0))),
        KeyAuth::Anonymous(Some(partition(1))),
        KeyAuth::Credential(partition(0)),
        KeyAuth::Credential(partition(1)),
        KeyAuth::Credential(partition(0x11)),
        KeyAuth::Credential(partition(u64::MAX)),
    ];

    let mut keys = Vec::new();
    for &digest in &digests {
        for &auth in &auths {
            keys.push((
                (digest, auth),
                cache
                    .cache_key("https://example.com/pkg", pinned_tier(digest), auth)
                    .into_owned(),
            ));
        }
    }

    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(
                keys[i].1, keys[j].1,
                "inputs {:?} and {:?} produced the same cache key",
                keys[i].0, keys[j].0
            );
        }
    }
}

/// `set_registry_policy` purges every `Pinned`-tier cache entry (and pooled transport) on
/// an actual policy transition — closing the round-trip hole for credential-carrying
/// entries (NFR-004), unlike the pre-existing `WorkspaceDeclared` non-purge behavior.
#[tokio::test]
async fn test_set_registry_policy_purges_pinned_tier_entries() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/api/data", server.url());

    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("private data")
        .create_async()
        .await;

    let policy = Arc::new(RegistryAccessPolicy::new(WorkspaceRegistryAccess::All));
    let cache = HttpCache::with_policy(Arc::clone(&policy));
    cache
        .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(1), None)
        .await
        .unwrap();
    assert_eq!(cache.len(), 1);

    cache.set_registry_policy(WorkspaceRegistryAccess::PublicOnly);

    assert_eq!(
        cache.len(),
        0,
        "a Pinned-tier entry must be purged on any actual policy transition"
    );
}

// --- #1816: guarded egress, proxy-host exemption, preflight ---

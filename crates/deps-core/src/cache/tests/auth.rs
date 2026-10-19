use super::*;

#[test]
fn test_apply_request_headers_marks_authorization_sensitive_on_built_request() {
    let client = Client::new();
    let token = bearer("secret-token");
    let request = apply_request_headers(
        client.get("https://example.com/"),
        &[
            WireHeader::Accept("application/json"),
            authorization(&token),
        ],
    )
    .build()
    .unwrap();

    let auth = request.headers().get(header::AUTHORIZATION).unwrap();
    assert!(auth.is_sensitive());
    assert_eq!(auth, "Bearer secret-token");
    assert!(
        !request
            .headers()
            .get(header::ACCEPT)
            .unwrap()
            .is_sensitive()
    );
    assert!(!format!("{:?}", request.headers()).contains("secret-token"));
}

#[test]
fn test_apply_request_headers_marks_private_token_sensitive_on_built_request() {
    let client = Client::new();
    let token = Redacted::new("glpat-secret".to_string());
    let request = apply_request_headers(
        client.get("https://example.com/"),
        &[WireHeader::Credential(
            CredentialHeader::GitlabPrivateToken(&token),
        )],
    )
    .build()
    .unwrap();

    let value = request.headers().get("private-token").unwrap();
    assert!(value.is_sensitive());
    assert!(!format!("{:?}", request.headers()).contains("glpat-secret"));
}

#[test]
fn test_apply_request_headers_invalid_credential_value_fails_the_build() {
    let client = Client::new();
    let token = bearer("bad\nvalue");
    let result =
        apply_request_headers(client.get("https://example.com/"), &[authorization(&token)]).build();

    let error = result.unwrap_err();
    assert!(!error.to_string().contains("bad"), "{error}");
}

#[tokio::test]
async fn test_get_cached_trusted_origin_credential_sends_extra_header() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());

    let _m = server
        .mock("GET", "/api/data")
        .match_header("authorization", "Bearer secret-token")
        .with_status(200)
        .with_body("authenticated data")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let url = format!("{}/api/data", server.url());
    let token = bearer("secret-token");
    let result: Bytes = cache
        .get_cached_trusted_origin(
            &url,
            &prefix(&trusted_origin),
            credential(&token, &prefix(&trusted_origin)),
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.as_ref(), b"authenticated data");
}

#[tokio::test]
async fn test_gitlab_private_token_header_is_sent_verbatim() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let m = server
        .mock("GET", "/api/data")
        .match_header("private-token", "glpat-secret")
        .match_header("authorization", mockito::Matcher::Missing)
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;
    let token = Redacted::new("glpat-secret".to_string());
    let url = format!("{}/api/data", server.url());
    HttpCache::new()
        .get_cached_trusted_origin(
            &url,
            &prefix(&trusted_origin),
            RequestAuth::credential(
                CredentialHeader::GitlabPrivateToken(&token),
                &prefix(&trusted_origin),
            ),
            None,
        )
        .await
        .unwrap();
    m.assert_async().await;
}

#[test]
fn test_baseline_auth_partition_keys_never_collide() {
    let cache = HttpCache::new();
    let url = "https://r.example/p";
    let partition = |raw| CredentialPartition::new(raw);
    let bare = cache.cache_key(url, CacheTier::Baseline, KeyAuth::ANONYMOUS);
    let zero = cache.cache_key(
        url,
        CacheTier::Baseline,
        KeyAuth::Anonymous(Some(partition(0))),
    );
    let one = cache.cache_key(
        url,
        CacheTier::Baseline,
        KeyAuth::Anonymous(Some(partition(1))),
    );
    let credentialed = cache.cache_key(url, CacheTier::Baseline, KeyAuth::Credential(partition(1)));
    let pinned = cache.cache_key(
        url,
        CacheTier::Pinned { digest: 0 },
        KeyAuth::Anonymous(Some(partition(0))),
    );
    let pinned_credentialed = cache.cache_key(
        url,
        CacheTier::Pinned { digest: 0 },
        KeyAuth::Credential(partition(0)),
    );
    assert_eq!(bare, url);
    let keys = [
        &bare,
        &zero,
        &one,
        &credentialed,
        &pinned,
        &pinned_credentialed,
    ];
    for (i, left) in keys.iter().enumerate() {
        for right in &keys[i + 1..] {
            assert_ne!(left, right);
        }
    }
}

#[tokio::test]
async fn test_auth_id_partitions_baseline_entries_and_eviction_reaches_them() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());
    let origin = format!("{}/", server.url());
    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("body")
        .expect(3)
        .create_async()
        .await;
    let cache = HttpCache::new();
    for partition in [
        None,
        Some(CredentialPartition::new(1)),
        Some(CredentialPartition::new(2)),
    ] {
        cache
            .get_cached_trusted_origin_response(
                &url,
                &prefix(&origin),
                RequestAuth::Anonymous { partition },
                None,
                RevalidationFailure::ServeStale,
            )
            .await
            .unwrap();
    }
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.evict_url_prefix(&format!("{}/api/", server.url())), 3);
    assert!(cache.is_empty());
}

#[tokio::test]
async fn test_get_cached_with_headers_sends_extra_headers() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());

    let _m = server
        .mock("GET", "/api/data")
        .match_header("accept", "application/json")
        .match_header("authorization", mockito::Matcher::Missing)
        .with_status(200)
        .with_header("etag", "\"abc123\"")
        .with_body("negotiated data")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let result: Bytes = cache
        .get_cached_with_headers(&url, &[RequestHeader::Accept("application/json")])
        .await
        .unwrap();

    assert_eq!(result.as_ref(), b"negotiated data");
}

/// The headered form of `get_cached_workspace` used by `deps-npm`'s alternate-registry
/// client (A1): forwards `extra_headers` while still going through the workspace-tier
/// transport (mirrors `test_get_cached_and_get_cached_workspace_do_not_share_an_entry`'s
/// use of the unheadered `get_cached_workspace` against a loopback mockito server under
/// the default policy — an IP-literal host like mockito's has no DNS resolution step for
/// the connect-time `AddrGuard` to intercept, so no policy elevation is needed here
/// either; that guard's actual job is catching a *hostname* that resolves differently at
/// connect time than its parse-time classification, see `validate_resolved_addrs`).
#[tokio::test]
async fn test_get_cached_workspace_with_headers_sends_extra_headers() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());

    let _m = server
        .mock("GET", "/api/data")
        .match_header("accept", "application/vnd.npm.install-v1+json")
        .with_status(200)
        .with_body("abbreviated packument")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let headers = [RequestHeader::Accept("application/vnd.npm.install-v1+json")];
    let result: Bytes = cache
        .get_cached_workspace_with_headers(&url, &headers)
        .await
        .unwrap();

    assert_eq!(result.as_ref(), b"abbreviated packument");
}

#[tokio::test]
async fn test_get_transport_only_with_headers_sends_extra_headers() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/v1/vulns/RUSTSEC-2020-0071", server.url());

    let _m = server
        .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
        .match_header("accept", "application/json")
        .with_status(200)
        .with_body(r#"{"id":"RUSTSEC-2020-0071"}"#)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let headers = [RequestHeader::Accept("application/json")];
    let result: Bytes = cache
        .get_transport_only_with_headers(&url, &headers)
        .await
        .unwrap();

    assert_eq!(result.as_ref(), br#"{"id":"RUSTSEC-2020-0071"}"#);
    assert!(
        cache.is_empty(),
        "get_transport_only_with_headers must not populate the entry-map cache"
    );
}

#[tokio::test]
async fn test_get_cached_pinned_attaches_auth_header() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/api/data", server.url());

    let _m = server
        .mock("GET", "/api/data")
        .match_header("authorization", "Basic dXNlcjpwYXQ=")
        .with_status(200)
        .with_body("authenticated data")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let result = cache
        .get_cached_pinned(
            &url,
            &prefix(&trusted_origin),
            RequestAuth::credential_in(
                CredentialHeader::Authorization(&crate::secret::basic_auth_header(
                    &["us", "er"].concat(),
                    &["p", "at"].concat(),
                )),
                CredentialPartition::new(42),
            ),
            None,
        )
        .await
        .unwrap();

    assert_eq!(result.as_ref(), b"authenticated data");
}

/// FR-014: distinct `auth_id` values against the same `(url, trusted_origin)` never share
/// a cache entry — a rotated or distinct credential never reads back a body fetched under a
/// different one.
#[tokio::test]
async fn test_get_cached_pinned_distinct_auth_id_never_shares_cache_entry() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/api/data", server.url());

    let _m1 = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("body-for-credential-a")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let a = cache
        .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(1), None)
        .await
        .unwrap();
    assert_eq!(a.as_ref(), b"body-for-credential-a");
    drop(_m1);

    let _m2 = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_body("body-for-credential-b")
        .create_async()
        .await;

    let b = cache
        .get_cached_pinned(&url, &prefix(&trusted_origin), cred_in(2), None)
        .await
        .unwrap();
    assert_eq!(
        b.as_ref(),
        b"body-for-credential-b",
        "a distinct auth_id must not read back credential A's cached body"
    );
}

/// Critic S4: after the credential is removed, an anonymous request never reads the body
/// that was fetched under it, even when revalidation fails.
#[tokio::test]
async fn test_removed_credential_never_serves_credentialed_body_anonymously() {
    let mut server = mockito::Server::new_async().await;
    let cache = HttpCache::new();
    let (origin, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
    server.reset();
    let _unauthorized = server
        .mock("GET", "/api/data")
        .with_status(401)
        .create_async()
        .await;

    let result = cache
        .get_cached_trusted_origin(&url, &prefix(&origin), RequestAuth::ANONYMOUS, None)
        .await;

    assert_matches!(result, Err(DepsError::HttpStatus { status: 401, .. }));
}

/// The no-network credentialed read serves the stored entry whatever the offline switch says,
/// and never sends: the mock sees no request.
#[tokio::test]
async fn test_peek_credentialed_serves_the_entry_without_a_request_online_or_offline() {
    let mut server = mockito::Server::new_async().await;
    let cache = HttpCache::new();
    let (_, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
    server.reset();
    let untouched = server
        .mock("GET", "/api/data")
        .expect(0)
        .create_async()
        .await;

    for mode in [NetworkMode::Online, NetworkMode::Offline] {
        cache.set_offline(mode);
        let body = cache
            .peek_credentialed_trusted_origin(&url, partition(7))
            .unwrap();
        assert_eq!(body.body.as_ref(), b"private data");
    }

    untouched.assert_async().await;
}

/// A partition nothing was stored under reads as `Offline`, and an anonymous entry never
/// answers a credentialed read.
#[tokio::test]
async fn test_peek_credentialed_misses_other_partitions_and_anonymous_entries() {
    let mut server = mockito::Server::new_async().await;
    let cache = HttpCache::new();
    let (_, url) = warm_entry_under(&mut server, &cache, cred_in(7)).await;
    let anonymous_url = format!("{}/api/other", server.url());
    let _other = server
        .mock("GET", "/api/other")
        .with_status(200)
        .with_body("public")
        .create_async()
        .await;
    cache.get_cached(&anonymous_url).await.unwrap();

    assert_matches!(
        cache.peek_credentialed_trusted_origin(&url, partition(8)),
        Err(DepsError::Offline { .. })
    );
    assert_matches!(
        cache.peek_credentialed_trusted_origin(&anonymous_url, partition(7)),
        Err(DepsError::Offline { .. })
    );
}

/// Per-source rate-limit rule: a source that opts into `Throttles` (GitHub) keeps a
/// credentialed entry past a confirmed rate limit, one on the default `Revokes` (GitLab)
/// evicts it, both on the baseline trusted-origin tier.
#[tokio::test]
async fn test_rate_limit_revocation_is_a_per_source_choice_on_the_trusted_origin_tier() {
    for (rule, evicted) in [
        (RateLimitRevocation::Revokes, true),
        (RateLimitRevocation::Throttles, false),
    ] {
        let mut server = mockito::Server::new_async().await;
        let cache = HttpCache::new();
        let auth = || cred_in(7).with_rate_limit(rule);
        let (origin, url) = warm_entry_under(&mut server, &cache, auth()).await;
        server.reset();
        let _limited = server
            .mock("GET", "/api/data")
            .with_status(403)
            .with_header("x-ratelimit-remaining", "0")
            .create_async()
            .await;

        let result = cache
            .get_cached_trusted_origin(&url, &prefix(&origin), auth(), None)
            .await;

        assert_eq!(result.is_err(), evicted, "{rule:?}");
        assert_eq!(cache.len(), usize::from(!evicted), "{rule:?}");
    }
}

#[test]
fn test_rate_limit_revocation_default_revokes_and_ignores_unrelated_errors() {
    let rate_limited = DepsError::RateLimited {
        message: "m".into(),
        verified: RateLimitEvidence::Confirmed,
        source_status: Some(429),
    };
    assert!(!RateLimitRevocation::Revokes.revokes_credential(&rate_limited));
    assert!(!RateLimitRevocation::Revokes.revokes_credential(&DepsError::CacheError("x".into())));
    assert!(
        RateLimitRevocation::Revokes.revokes_credential(&DepsError::HttpStatus {
            url: "https://r.test/".into(),
            status: 401,
        })
    );
    assert!(
        RateLimitRevocation::Throttles.revokes_credential(&DepsError::HttpStatus {
            url: "https://r.test/".into(),
            status: 403,
        })
    );
}

/// CodeQL cleartext-transmission audit: a credential is withheld, on both APIs, from a URL
/// that is not under the trusted prefix (a different host, scheme or sibling path), so a
/// request can never start outside the origin the redirect policy confines it to.
#[tokio::test]
async fn test_credential_is_refused_for_a_url_outside_the_trusted_prefix() {
    let mut server = mockito::Server::new_async().await;
    let hit = server
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let cache = HttpCache::new();
    let origin = prefix(&format!("{}/api/", server.url()));
    for url in [
        format!("{}/apiX/data", server.url()),
        format!("{}/other", server.url()),
        "https://elsewhere.test/api/data".to_string(),
        "https://elsewhere.test/api/data".replacen("https", "http", 1),
        "not a url".to_string(),
    ] {
        let trusted = cache
            .get_cached_trusted_origin(&url, &origin, cred_in(7), None)
            .await;
        let pinned = cache
            .get_cached_pinned(&url, &origin, cred_in(7), None)
            .await;
        assert_matches!(
            trusted,
            Err(DepsError::CredentialOutsideTrustedPrefix { .. }),
            "{url}"
        );
        assert_matches!(
            pinned,
            Err(DepsError::CredentialOutsideTrustedPrefix { .. }),
            "{url}"
        );
    }
    hit.assert_async().await;
}

/// The same URLs stay reachable anonymously: the guard concerns credentials only.
#[tokio::test]
async fn test_anonymous_request_outside_the_prefix_is_not_refused_by_the_credential_guard() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/other")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;
    let cache = HttpCache::new();
    let origin = prefix(&format!("{}/api/", server.url()));

    let body = cache
        .get_cached_trusted_origin(
            &format!("{}/other", server.url()),
            &origin,
            RequestAuth::ANONYMOUS,
            None,
        )
        .await
        .unwrap();

    assert_eq!(body.as_ref(), b"ok");
}

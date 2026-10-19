use super::*;

#[tokio::test]
async fn test_post_json_success_returns_body_and_does_not_cache() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/v1/querybatch", server.url());

    let _m = server
        .mock("POST", "/v1/querybatch")
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_body(r#"{"results":[{}]}"#)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let body = serde_json::json!({ "queries": [] });
    let result: Bytes = cache.post_json(&url, &body).await.unwrap();

    assert_eq!(result.as_ref(), br#"{"results":[{}]}"#);
    assert!(
        cache.is_empty(),
        "post_json must not populate the entry-map cache"
    );
}

#[tokio::test]
async fn test_post_json_limited_trusted_origin_success_returns_body_and_does_not_cache() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/v3alpha/findings:batchGet", server.url());

    let _m = server
        .mock("POST", "/v3alpha/findings:batchGet")
        .match_header("content-type", "application/json")
        .with_status(200)
        .with_body(r#"{"findings":[]}"#)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let body = serde_json::json!({ "queries": [] });
    let result: Bytes = cache
        .post_json_limited_trusted_origin(
            &url,
            &body,
            BodyLimit::new(1024),
            &prefix(&trusted_origin),
        )
        .await
        .unwrap();

    assert_eq!(result.as_ref(), br#"{"findings":[]}"#);
    assert!(
        cache.is_empty(),
        "post_json_limited_trusted_origin must not populate the entry-map cache"
    );
}

#[tokio::test]
async fn test_post_json_limited_trusted_origin_enforces_body_limit() {
    let mut server = mockito::Server::new_async().await;
    let trusted_origin = format!("{}/", server.url());
    let url = format!("{}/v3alpha/findings:batchGet", server.url());

    let _m = server
        .mock("POST", "/v3alpha/findings:batchGet")
        .with_status(200)
        .with_body("x".repeat(64))
        .create_async()
        .await;

    let cache = HttpCache::new();
    let body = serde_json::json!({ "queries": [] });
    let result: Result<Bytes> = cache
        .post_json_limited_trusted_origin(&url, &body, BodyLimit::new(8), &prefix(&trusted_origin))
        .await;

    // Assert via `matches!` rather than debug-formatting `result` in a panic message
    // (#409's established pattern): on the `Ok` arm that value is the raw response
    // body, which would otherwise be written to the test log by the panic machinery.
    assert_matches!(
        result,
        Err(DepsError::ResponseTooLarge { .. }),
        "expected ResponseTooLarge"
    );
}

#[tokio::test]
async fn test_get_transport_only_limited_trusted_origin_success_returns_body() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/data")
        .with_status(200)
        .with_body("payload")
        .create_async()
        .await;

    let cache = HttpCache::new();
    let body = cache
        .get_transport_only_with_headers_limited_trusted_origin(
            &format!("{}/data", server.url()),
            &[],
            BodyLimit::new(1024),
            &prefix(&format!("{}/", server.url())),
        )
        .await
        .unwrap();

    assert_eq!(body.as_ref(), b"payload");
}

#[tokio::test]
async fn test_get_transport_only_limited_trusted_origin_enforces_body_limit() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/data")
        .with_status(200)
        .with_body("x".repeat(64))
        .create_async()
        .await;

    let cache = HttpCache::new();
    let result = cache
        .get_transport_only_with_headers_limited_trusted_origin(
            &format!("{}/data", server.url()),
            &[],
            BodyLimit::new(8),
            &prefix(&format!("{}/", server.url())),
        )
        .await;

    assert_matches!(result, Err(DepsError::ResponseTooLarge { .. }));
}

#[tokio::test]
async fn test_get_transport_only_success_returns_body_and_does_not_cache() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/v1/vulns/RUSTSEC-2020-0071", server.url());

    let _m = server
        .mock("GET", "/v1/vulns/RUSTSEC-2020-0071")
        .with_status(200)
        .with_body(r#"{"id":"RUSTSEC-2020-0071"}"#)
        .create_async()
        .await;

    let cache = HttpCache::new();
    let result: Bytes = cache.get_transport_only(&url).await.unwrap();

    assert_eq!(result.as_ref(), br#"{"id":"RUSTSEC-2020-0071"}"#);
    assert!(
        cache.is_empty(),
        "get_transport_only must not populate the entry-map cache"
    );
}

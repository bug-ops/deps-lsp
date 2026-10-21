//! The live-response quota feed: only a response received over the network reaches a meter.

use crate::rate_limit::{QuotaHeaders, QuotaMeter};

use super::*;

fn far_reset() -> String {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600)
        .to_string()
}

async fn fetch_metered(
    cache: &HttpCache,
    url: &str,
    origin: &str,
    meter: &Arc<QuotaMeter>,
) -> crate::error::Result<CachedResponse> {
    cache
        .get_cached_trusted_origin_response(
            url,
            &prefix(origin),
            RequestAuth::ANONYMOUS.with_quota_meter(meter),
            None,
            RevalidationFailure::ServeStale,
        )
        .await
}

#[tokio::test]
async fn test_live_response_feeds_the_meter_on_miss_and_on_304() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());
    let origin = format!("{}/", server.url());
    let reset = far_reset();
    let first = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_header("x-ratelimit-remaining", "55")
        .with_header("x-ratelimit-reset", &reset)
        .with_body("body")
        .create_async()
        .await;
    let cache = HttpCache::new();
    let meter = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));
    fetch_metered(&cache, &url, &origin, &meter).await.unwrap();
    assert_eq!(meter.current().unwrap().remaining, 55);
    first.remove_async().await;

    let _second = server
        .mock("GET", "/api/data")
        .match_header("if-none-match", "\"v1\"")
        .with_status(304)
        .with_header("x-ratelimit-remaining", "3")
        .with_header("x-ratelimit-reset", &reset)
        .create_async()
        .await;
    fetch_metered(&cache, &url, &origin, &meter).await.unwrap();
    assert_eq!(meter.current().unwrap().remaining, 3);
}

/// SC-004: a stored entry served without a request never replays its old `remaining`.
#[tokio::test]
async fn test_offline_cache_hit_does_not_touch_the_meter() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());
    let origin = format!("{}/", server.url());
    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_header("x-ratelimit-remaining", "55")
        .with_header("x-ratelimit-reset", &far_reset())
        .with_body("body")
        .create_async()
        .await;
    let cache = HttpCache::new();
    let seeding = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));
    fetch_metered(&cache, &url, &origin, &seeding)
        .await
        .unwrap();

    let meter = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));
    cache.set_offline(crate::NetworkMode::Offline);
    fetch_metered(&cache, &url, &origin, &meter).await.unwrap();
    assert!(meter.current().is_none());
}

#[tokio::test]
async fn test_4xx_response_feeds_the_meter_and_5xx_does_not() {
    let mut server = mockito::Server::new_async().await;
    let origin = format!("{}/", server.url());
    let reset = far_reset();
    let _not_found = server
        .mock("GET", "/missing")
        .with_status(404)
        .with_header("x-ratelimit-remaining", "41")
        .with_header("x-ratelimit-reset", &reset)
        .create_async()
        .await;
    let _broken = server
        .mock("GET", "/broken")
        .with_status(503)
        .with_header("x-ratelimit-remaining", "1")
        .with_header("x-ratelimit-reset", &reset)
        .create_async()
        .await;
    let cache = HttpCache::new();
    let meter = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));
    let broken = format!("{}/broken", server.url());
    fetch_metered(&cache, &broken, &origin, &meter)
        .await
        .unwrap_err();
    assert!(meter.current().is_none());
    let missing = format!("{}/missing", server.url());
    fetch_metered(&cache, &missing, &origin, &meter)
        .await
        .unwrap_err();
    assert_eq!(meter.current().unwrap().remaining, 41);
}

/// A meter attached to one request is fed by that request only: another meter, which the
/// request never carried, stays empty.
#[tokio::test]
async fn test_only_the_attached_meter_is_fed() {
    let mut server = mockito::Server::new_async().await;
    let url = format!("{}/api/data", server.url());
    let origin = format!("{}/", server.url());
    let _m = server
        .mock("GET", "/api/data")
        .with_status(200)
        .with_header("x-ratelimit-remaining", "55")
        .with_header("x-ratelimit-reset", &far_reset())
        .create_async()
        .await;
    let cache = HttpCache::new();
    let attached = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));
    let other = Arc::new(QuotaMeter::new(QuotaHeaders::GitHub));

    fetch_metered(&cache, &url, &origin, &attached)
        .await
        .unwrap();

    assert_eq!(attached.current().unwrap().remaining, 55);
    assert!(other.current().is_none());
}

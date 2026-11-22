//! #2041 / spec 099 NFR-004 (amended) acceptance: npm publish times are fetched on native
//! demand (a window applies) even with freshness disabled, and cost exactly nothing extra
//! without one (plan `20-24-32-architect` D2, `20-32-28-architect` N-M3).
//!
//! Written tests-first. Assumed seams: `deps_core::PublishTimeDemand` and
//! `Registry::get_versions_from_with_demand(name, source, freshness, demand)`. Needs the
//! `test-util` feature (`NpmRegistry::with_public_base_for_test`), enabled by `--all-features`.

#![cfg(feature = "test-util")]
#![expect(clippy::unwrap_used, reason = "test code")]

use std::sync::Arc;

use deps_core::{
    DependencySource, FreshnessSettings, HttpCache, PackageName, PublishTimeDemand, Registry,
};
use deps_npm::NpmRegistry;
use mockito::{Matcher, Server, ServerGuard};

const ABBREVIATED: &str = "application/vnd.npm.install-v1+json";
const ABBREVIATED_BODY: &str = r#"{"versions": {"1.0.0": {}, "2.0.0": {}}}"#;
const FULL_BODY: &str =
    r#"{"time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2021-01-01T00:00:00Z"}}"#;

struct Mocks {
    abbreviated: mockito::Mock,
    full: mockito::Mock,
}

async fn mount(server: &mut ServerGuard, abbreviated_hits: usize, full_hits: usize) -> Mocks {
    let abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", ABBREVIATED)
        .with_status(200)
        .with_body(ABBREVIATED_BODY)
        .expect(abbreviated_hits)
        .create_async()
        .await;
    let full = server
        .mock("GET", "/widget")
        .match_header("accept", Matcher::Exact("application/json".into()))
        .with_status(200)
        .with_body(FULL_BODY)
        .expect(full_hits)
        .create_async()
        .await;
    Mocks { abbreviated, full }
}

fn registry(server: &ServerGuard) -> NpmRegistry {
    NpmRegistry::with_public_base_for_test(Arc::new(HttpCache::new()), server.url())
}

async fn fetch(
    registry: &NpmRegistry,
    freshness: FreshnessSettings,
    demand: PublishTimeDemand,
) -> Vec<Option<deps_core::PublishTime>> {
    let versions = registry
        .get_versions_from_with_demand(
            &PackageName::new("widget"),
            &DependencySource::Registry,
            freshness,
            demand,
        )
        .await
        .unwrap();
    versions.iter().map(|v| v.published_at()).collect()
}

#[tokio::test]
async fn native_window_demand_fetches_times_even_with_freshness_disabled() {
    let mut server = Server::new_async().await;
    let mocks = mount(&mut server, 1, 1).await;
    let times = fetch(
        &registry(&server),
        FreshnessSettings::Disabled,
        PublishTimeDemand::NativeWindow,
    )
    .await;
    assert_eq!(times.len(), 2);
    assert!(
        times.iter().all(Option::is_some),
        "every version must be dated, got {times:?}"
    );
    mocks.abbreviated.assert_async().await;
    mocks.full.assert_async().await;
}

#[tokio::test]
async fn not_required_demand_with_freshness_disabled_issues_only_the_abbreviated_request() {
    let mut server = Server::new_async().await;
    let mocks = mount(&mut server, 1, 0).await;
    let times = fetch(
        &registry(&server),
        FreshnessSettings::Disabled,
        PublishTimeDemand::NotRequired,
    )
    .await;
    assert!(
        times.iter().all(Option::is_none),
        "no native config: undated, got {times:?}"
    );
    mocks.abbreviated.assert_async().await;
    mocks.full.assert_async().await;
}

#[tokio::test]
async fn not_required_demand_is_byte_identical_to_get_versions_from() {
    let mut server_a = Server::new_async().await;
    let mocks_a = mount(&mut server_a, 1, 0).await;
    let via_demand = fetch(
        &registry(&server_a),
        FreshnessSettings::Disabled,
        PublishTimeDemand::NotRequired,
    )
    .await;

    let mut server_b = Server::new_async().await;
    let mocks_b = mount(&mut server_b, 1, 0).await;
    let plain: Vec<_> = registry(&server_b)
        .get_versions_from(
            &PackageName::new("widget"),
            &DependencySource::Registry,
            FreshnessSettings::Disabled,
        )
        .await
        .unwrap()
        .iter()
        .map(|v| v.published_at())
        .collect();

    assert_eq!(via_demand, plain);
    mocks_a.abbreviated.assert_async().await;
    mocks_a.full.assert_async().await;
    mocks_b.abbreviated.assert_async().await;
    mocks_b.full.assert_async().await;
}

#[tokio::test]
async fn demand_never_changes_the_set_or_order_of_versions() {
    let mut server = Server::new_async().await;
    let _mocks = mount(&mut server, 1, 1).await;
    let registry = registry(&server);
    let demanded: Vec<String> = registry
        .get_versions_from_with_demand(
            &PackageName::new("widget"),
            &DependencySource::Registry,
            FreshnessSettings::Disabled,
            PublishTimeDemand::NativeWindow,
        )
        .await
        .unwrap()
        .iter()
        .map(|v| v.version_string().as_str().to_owned())
        .collect();
    assert_eq!(demanded, ["2.0.0", "1.0.0"]);
}

#[tokio::test]
async fn native_window_demand_with_a_packument_lacking_time_leaves_versions_undated() {
    let mut server = Server::new_async().await;
    let _abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", ABBREVIATED)
        .with_status(200)
        .with_body(ABBREVIATED_BODY)
        .create_async()
        .await;
    let _full = server
        .mock("GET", "/widget")
        .match_header("accept", Matcher::Exact("application/json".into()))
        .with_status(200)
        .with_body(r#"{"versions": {}}"#)
        .create_async()
        .await;
    let times = fetch(
        &registry(&server),
        FreshnessSettings::Disabled,
        PublishTimeDemand::NativeWindow,
    )
    .await;
    assert!(
        times.iter().all(Option::is_none),
        "no `time` map: stays eligible, got {times:?}"
    );
}

#[tokio::test]
async fn native_window_demand_failing_full_fetch_still_returns_the_versions() {
    let mut server = Server::new_async().await;
    let _abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", ABBREVIATED)
        .with_status(200)
        .with_body(ABBREVIATED_BODY)
        .create_async()
        .await;
    let _full = server
        .mock("GET", "/widget")
        .match_header("accept", Matcher::Exact("application/json".into()))
        .with_status(500)
        .create_async()
        .await;
    let times = fetch(
        &registry(&server),
        FreshnessSettings::Disabled,
        PublishTimeDemand::NativeWindow,
    )
    .await;
    assert_eq!(
        times.len(),
        2,
        "version list must survive a failed time fetch"
    );
    assert!(times.iter().all(Option::is_none));
}

#[tokio::test]
async fn repeated_native_demand_calls_reuse_the_publish_time_cache() {
    let mut server = Server::new_async().await;
    let _abbreviated = server
        .mock("GET", "/widget")
        .match_header("accept", ABBREVIATED)
        .with_status(200)
        .with_body(ABBREVIATED_BODY)
        .expect_at_least(1)
        .create_async()
        .await;
    let full = server
        .mock("GET", "/widget")
        .match_header("accept", Matcher::Exact("application/json".into()))
        .with_status(200)
        .with_body(FULL_BODY)
        .expect(1)
        .create_async()
        .await;
    let registry = registry(&server);
    for _ in 0..3 {
        let times = fetch(
            &registry,
            FreshnessSettings::Disabled,
            PublishTimeDemand::NativeWindow,
        )
        .await;
        assert!(times.iter().all(Option::is_some));
    }
    full.assert_async().await;
}

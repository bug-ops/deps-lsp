//! Pins that the background fetch tags each package's request with its endpoint, so a hover
//! that merely waits on that request counts it toward the endpoint breaker.

use std::collections::HashMap;
use std::sync::Arc;

use deps_core::policy_config::{FetchConcurrency, FetchTimeout};
use deps_core::test_util::{StalledCoalescingRegistry, package_key};
use deps_core::{DependencySource, EcosystemId, FreshnessSettings, SelectionContext};

use super::fetch_latest_versions_parallel;

#[tokio::test(start_paused = true)]
async fn the_background_fetch_tags_each_package_request_with_its_endpoint() {
    let registry = Arc::new(StalledCoalescingRegistry::new());
    let sources = vec![
        (package_key("bg-a"), DependencySource::Registry),
        (package_key("bg-b"), DependencySource::Registry),
    ];
    let background = async {
        let result = fetch_latest_versions_parallel(
            EcosystemId::Cargo,
            Arc::clone(&registry) as Arc<dyn deps_core::Registry>,
            sources,
            &HashMap::new(),
            None,
            FreshnessSettings::Disabled,
            FetchTimeout::constant::<60>(),
            FetchConcurrency::constant::<4>(),
            &SelectionContext::none(),
            None,
        )
        .await;
        drop(result);
    };

    assert!(
        registry
            .waiters_open_the_breaker_while(EcosystemId::Cargo, background)
            .await
    );
}

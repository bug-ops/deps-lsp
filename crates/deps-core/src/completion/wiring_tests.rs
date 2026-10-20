//! Pins that version completion feeds the endpoint breaker's evidence, so a hover that only
//! waits on the completion's request still counts it.

use super::complete_versions_generic_replacing;
use crate::test_util::{StalledCoalescingRegistry, StubFormatter};
use crate::{DependencySource, EcosystemId, FreshnessSettings, PackageName, SelectionContext};

#[tokio::test(start_paused = true)]
async fn version_completion_tags_its_request_with_the_endpoint() {
    let registry = StalledCoalescingRegistry::new();
    let completion = async {
        let items = crate::observe_ecosystem(
            EcosystemId::Cargo,
            complete_versions_generic_replacing(
                &registry,
                &StubFormatter::DEFAULT,
                &PackageName::new("completed"),
                &DependencySource::Registry,
                "",
                &[],
                FreshnessSettings::Disabled,
                None,
                &SelectionContext::none(),
            ),
        )
        .await;
        drop(items);
    };

    assert!(
        registry
            .waiters_open_the_breaker_while(EcosystemId::Cargo, completion)
            .await
    );
}

//! A registry that does not override `get_versions_from_with_demand` does not claim to honor
//! the demand, and forwards to `get_versions_from` unchanged (architect condition on the
//! `honors_publish_time_demand` / `get_versions_from_with_demand` pairing).

#![cfg(feature = "test-util")]
#![allow(clippy::expect_used)]

use deps_core::test_util::{MockRegistry, MockVersion};
use deps_core::{DependencySource, FreshnessSettings, PackageName, PublishTimeDemand, Registry};

#[test]
fn the_default_registry_does_not_honor_publish_time_demand() {
    assert!(!MockRegistry::new().honors_publish_time_demand());
}

#[tokio::test]
async fn the_default_with_demand_fetch_equals_the_plain_fetch() {
    let registry = MockRegistry::new().with_versions(vec![MockVersion::new("1.0.0")]);
    let name = PackageName::new("serde");
    let source = DependencySource::Registry;
    let plain = registry
        .get_versions_from(&name, &source, FreshnessSettings::Disabled)
        .await
        .expect("versions");
    for demand in [
        PublishTimeDemand::NotRequired,
        PublishTimeDemand::NativeWindow,
    ] {
        let demanded = registry
            .get_versions_from_with_demand(&name, &source, FreshnessSettings::Disabled, demand)
            .await
            .expect("versions");
        let strings = |list: &[Box<dyn deps_core::Version>]| {
            list.iter()
                .map(|v| v.version_string().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(strings(&demanded), strings(&plain), "{demand:?}");
    }
}

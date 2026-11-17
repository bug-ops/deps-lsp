//! #2041 / plan `20-24-32-architect` D2 acceptance: the typed publish-time demand a fetch
//! carries (`NotRequired` keeps today's request shape, `NativeWindow` asks for dated versions).
//!
//! Written tests-first. Assumed seam: `deps_core::PublishTimeDemand`. The document-level rule
//! (`for_document`) and the registry override are covered in
//! `crates/deps-npm/tests/native_publish_times.rs`.

use deps_core::PublishTimeDemand;

#[test]
fn publish_time_demand_is_matched_exhaustively_without_wildcard() {
    fn label(demand: PublishTimeDemand) -> &'static str {
        match demand {
            PublishTimeDemand::NotRequired => "none",
            PublishTimeDemand::NativeWindow => "native",
        }
    }
    assert_eq!(label(PublishTimeDemand::NotRequired), "none");
    assert_eq!(label(PublishTimeDemand::NativeWindow), "native");
}

#[test]
fn publish_time_demand_is_copy_and_comparable() {
    let demand = PublishTimeDemand::NativeWindow;
    let copy = demand;
    assert_eq!(demand, copy);
    assert_ne!(
        PublishTimeDemand::NotRequired,
        PublishTimeDemand::NativeWindow
    );
}

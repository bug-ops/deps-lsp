//! Acceptance tests for spec 051 T006: the `CachePersistence` configuration enum.
//!
//! The enum has no `Default` yet (the default flip is T014), so no default is asserted here.

use deps_core::policy_config::CachePersistence;

#[test]
fn deserialize_memory_is_memory() {
    assert_eq!(
        serde_json::from_str::<CachePersistence>("\"memory\"").ok(),
        Some(CachePersistence::Memory)
    );
}

#[test]
fn deserialize_disk_is_disk() {
    assert_eq!(
        serde_json::from_str::<CachePersistence>("\"disk\"").ok(),
        Some(CachePersistence::Disk)
    );
}

#[test]
fn deserialize_rejects_everything_but_the_two_lowercase_names() {
    for raw in [
        "\"Memory\"",
        "\"Disk\"",
        "\"DISK\"",
        "\"ram\"",
        "\"\"",
        "\"disk \"",
        "true",
        "0",
        "null",
        "{}",
    ] {
        assert!(
            serde_json::from_str::<CachePersistence>(raw).is_err(),
            "{raw} must be rejected"
        );
    }
}

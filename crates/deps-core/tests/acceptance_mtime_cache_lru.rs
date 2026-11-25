//! Acceptance test (tester-owned) for #2185: a full `MtimeFileCache` evicts the least recently
//! used entry instead of refusing to cache.

use std::path::PathBuf;
use std::sync::Arc;

use deps_core::mtime_cache::MtimeFileCache;

#[test]
fn get_or_parse_at_capacity_caches_new_file_and_evicts_least_recently_used() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = |name: &str| -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, name).expect("write");
        path
    };
    let (a, b, c) = (file("a"), file("b"), file("c"));
    let cache: MtimeFileCache<String> = MtimeFileCache::new(2, "acceptance");
    let get = |path: &PathBuf| cache.get_or_parse(path, str::to_owned).expect("parsed");

    let first_a = get(&a);
    let first_b = get(&b);
    get(&a);
    let first_c = get(&c);

    assert!(
        Arc::ptr_eq(&first_c, &get(&c)),
        "a file parsed at capacity must be cached"
    );
    assert!(
        Arc::ptr_eq(&first_a, &get(&a)),
        "the recently used entry must survive the eviction"
    );
    assert!(
        !Arc::ptr_eq(&first_b, &get(&b)),
        "the least recently used entry must be the one evicted"
    );
}

//! Acceptance tests for #2159 and #2156.2 (`persist::dir`): `prune_dir` acts only on files in the
//! store's name shape (`StoreFileKind`) that the `EntryTrust` owns, and `StoreDir` carries the
//! trust it was opened with.
//!
//! Mixed ownership inside one directory needs root to create, so ownership is exercised with a
//! foreign trust over own-owned files instead.

use super::dir::{EntryTrust, PruneLimits, prune_dir};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

const HASH_A: &str = "00000000000000aa";
const HASH_B: &str = "00000000000000bb";
const HASH_C: &str = "00000000000000cc";

fn entry(hash: &str) -> String {
    format!("{hash}.entry")
}

fn tmp(hash: &str) -> String {
    format!("{hash}.entry.deps-cli-4242-1700000000000000000.tmp")
}

fn roomy() -> PruneLimits {
    PruneLimits {
        max_bytes: u64::MAX,
        max_files: usize::MAX,
        max_scan: usize::MAX,
    }
}

fn put(dir: &Path, name: &str, now: SystemTime, age: Duration) {
    let path = dir.join(name);
    fs::write(&path, b"x").expect("write");
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open")
        .set_modified(now.checked_sub(age).expect("representable"))
        .expect("set_modified");
}

fn exists(dir: &Path, name: &str) -> bool {
    dir.join(name).exists()
}

#[cfg(unix)]
fn own_trust(dir: &Path) -> EntryTrust {
    use super::dir::ProbeUid;
    use std::os::unix::fs::MetadataExt;

    EntryTrust::for_uid(ProbeUid::new(fs::metadata(dir).expect("metadata").uid()))
}

#[cfg(not(unix))]
fn own_trust(_dir: &Path) -> EntryTrust {
    EntryTrust::probe().expect("probe")
}

const ANCIENT: Duration = Duration::from_hours(24 * 30);

#[test]
fn prune_dir_removes_only_store_shaped_files() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let dir = tmp_dir.path();
    let now = SystemTime::now();
    put(dir, &entry(HASH_A), now, ANCIENT);
    put(dir, &tmp(HASH_B), now, Duration::from_hours(2));
    let foreign = [
        "notes.entry".to_owned(),
        "a.tmp".to_owned(),
        "notes.txt.deps-cli-1-2.tmp".to_owned(),
        format!("{HASH_C}.entry.bak"),
        format!("{}.entry", HASH_C.to_uppercase()),
    ];
    for name in &foreign {
        put(dir, name, now, ANCIENT);
    }

    let report = prune_dir(dir, own_trust(dir), now, roomy()).expect("prune");

    assert_eq!(report.removed, 2);
    assert_eq!(report.failed, 0);
    assert!(!exists(dir, &entry(HASH_A)));
    assert!(!exists(dir, &tmp(HASH_B)));
    for name in &foreign {
        assert!(
            exists(dir, name),
            "{name} is not a store file and must survive"
        );
    }
}

#[test]
fn prune_dir_budget_counts_only_store_shaped_files() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let dir = tmp_dir.path();
    let now = SystemTime::now();
    put(dir, &entry(HASH_A), now, Duration::from_mins(2));
    put(dir, &entry(HASH_B), now, Duration::from_mins(1));
    for name in ["x1.entry", "x2.entry", "x3.entry"] {
        put(dir, name, now, Duration::from_mins(3));
    }
    let limits = PruneLimits {
        max_files: 1,
        ..roomy()
    };

    prune_dir(dir, own_trust(dir), now, limits).expect("prune");

    assert!(
        !exists(dir, &entry(HASH_A)),
        "least recently validated goes first"
    );
    assert!(exists(dir, &entry(HASH_B)));
    for name in ["x1.entry", "x2.entry", "x3.entry"] {
        assert!(exists(dir, name));
    }
}

#[test]
fn prune_dir_keeps_fresh_store_shaped_files_within_budget() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let dir = tmp_dir.path();
    let now = SystemTime::now();
    put(dir, &entry(HASH_A), now, Duration::from_mins(1));
    put(dir, &tmp(HASH_B), now, Duration::from_mins(1));

    let report = prune_dir(dir, own_trust(dir), now, roomy()).expect("prune");

    assert_eq!(report.removed, 0);
    assert!(exists(dir, &entry(HASH_A)));
    assert!(exists(dir, &tmp(HASH_B)));
}

#[cfg(unix)]
#[test]
fn prune_dir_leaves_files_the_trust_does_not_own_untouched() {
    use super::dir::ProbeUid;
    use std::os::unix::fs::MetadataExt;

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let dir = tmp_dir.path();
    let now = SystemTime::now();
    put(dir, &entry(HASH_A), now, ANCIENT);
    put(dir, &tmp(HASH_B), now, Duration::from_hours(2));
    let own = fs::metadata(dir).expect("metadata").uid();
    let foreign = EntryTrust::for_uid(ProbeUid::new(own.wrapping_add(1)));

    let report = prune_dir(dir, foreign, now, roomy()).expect("prune");

    assert_eq!(report.removed, 0);
    assert_eq!(report.failed, 0);
    assert!(exists(dir, &entry(HASH_A)));
    assert!(exists(dir, &tmp(HASH_B)));
}

#[cfg(unix)]
mod store {
    use super::super::dir::{CacheDir, CachePlatform, ProbeUid};
    use super::*;
    use crate::net_policy::MapEnv;
    use std::os::unix::fs::MetadataExt;

    fn cache_dir(root: &Path) -> (CacheDir, MapEnv) {
        let env = MapEnv::new().with_var("XDG_CACHE_HOME", root.to_str().expect("utf-8 path"));
        let dir = CacheDir::resolve(&env, CachePlatform::Unix).expect("resolvable");
        (dir, env)
    }

    #[test]
    fn open_with_stores_the_given_trust() {
        let root = tempfile::tempdir().expect("tempdir");
        let (cache, env) = cache_dir(root.path());
        let trust = own_trust(root.path());

        let store = cache.open_with(&env, trust).expect("open");

        assert_eq!(store.trust(), trust);
    }

    #[test]
    fn open_stores_the_probed_trust() {
        let root = tempfile::tempdir().expect("tempdir");
        let (cache, env) = cache_dir(root.path());

        let store = cache.open(&env).expect("open");

        assert_eq!(store.trust(), EntryTrust::probe().expect("probe"));
    }

    #[test]
    fn store_dir_prune_uses_the_stored_trust() {
        let root = tempfile::tempdir().expect("tempdir");
        let (cache, env) = cache_dir(root.path());
        let own = fs::metadata(root.path()).expect("metadata").uid();
        let now = SystemTime::now();

        let owned = cache.open_with(&env, own_trust(root.path())).expect("open");
        put(owned.path(), &tmp(HASH_A), now, Duration::from_hours(2));
        let foreign = cache.open_with(
            &env,
            EntryTrust::for_uid(ProbeUid::new(own.wrapping_add(1))),
        );
        // A foreign trust cannot even open an owned store, so ownership is exercised through
        // `prune_dir` above; here the owned store must prune with its own trust.
        assert!(foreign.is_err());

        let report = owned.prune(now).expect("prune");

        assert_eq!(report.removed, 1);
        assert!(!exists(owned.path(), &tmp(HASH_A)));
    }
}

//! Acceptance tests for #2153/#2156/#2159 (`persist::key`): `PersistKey` naming accessors, the
//! `StoreFileKind` classifier and its drift guard against the atomic writer's temp names.

use super::key::{PageRole, PersistKey, PersistableHost, StoreFileKind};
use crate::cache::CacheTier;
use crate::cache::auth::KeyAuth;
use crate::fs_probe::atomic_temp_file_name;
use crate::hash::fnv1a64;
use proptest::prelude::*;
use std::collections::HashSet;
use std::ffi::OsStr;

const URL: &str = "https://api.github.com/repos/o/r/tags?page=2";
const ACCEPT: &str = "application/vnd.github+json";
const HASH: &str = "0123456789abcdef";

fn key(url: &str, accept: &str) -> PersistKey {
    PersistKey::new(
        url,
        CacheTier::Baseline,
        KeyAuth::ANONYMOUS,
        accept,
        Some(PageRole::ListingPage),
    )
    .expect("eligible key")
}

#[test]
fn persist_key_accept_returns_the_input_verbatim() {
    assert_eq!(key(URL, ACCEPT).accept(), ACCEPT);
    assert_eq!(key(URL, "").accept(), "");
}

#[test]
fn persist_key_file_name_is_the_hashed_normalized_url_with_entry_extension() {
    let key = key(URL, ACCEPT);
    assert_eq!(
        key.file_name(),
        format!("{:016x}.entry", fnv1a64(key.url().as_bytes()))
    );
}

#[test]
fn persist_key_file_name_ignores_host_case_and_default_port() {
    let plain = key(URL, ACCEPT);
    let noisy = key("https://API.github.com:443/repos/o/r/tags?page=2", ACCEPT);
    assert_eq!(plain.file_name(), noisy.file_name());
    assert_eq!(plain.url(), noisy.url());
}

#[test]
fn persist_key_file_name_differs_per_url() {
    let other = key("https://api.github.com/repos/o/r/tags?page=3", ACCEPT);
    assert_ne!(key(URL, ACCEPT).file_name(), other.file_name());
}

#[test]
fn persistable_host_all_round_trips_through_its_name() {
    for host in PersistableHost::ALL.iter().copied() {
        assert_eq!(PersistableHost::from_host(host.as_str()), Some(host));
    }
}

#[test]
fn persistable_host_all_has_no_duplicate_names() {
    let names: HashSet<_> = PersistableHost::ALL
        .iter()
        .map(|host| host.as_str())
        .collect();
    assert_eq!(names.len(), PersistableHost::ALL.len());
}

fn classify(name: &str) -> Option<StoreFileKind> {
    StoreFileKind::classify(OsStr::new(name))
}

#[test]
fn store_file_kind_classify_accepts_the_two_store_shapes() {
    assert_eq!(
        classify(&format!("{HASH}.entry")),
        Some(StoreFileKind::Entry)
    );
    assert_eq!(
        classify(&format!(
            "{HASH}.entry.deps-cli-4242-1700000000000000000.tmp"
        )),
        Some(StoreFileKind::Tmp)
    );
    assert_eq!(
        classify(&format!("{HASH}.entry.deps-cli-0-0.tmp")),
        Some(StoreFileKind::Tmp)
    );
}

#[test]
fn store_file_kind_classify_rejects_every_foreign_shape() {
    let rejected = [
        "a.entry".to_owned(),
        "0123.entry".to_owned(),
        format!("{}.entry", HASH.to_uppercase()),
        format!("{HASH}0.entry"),
        format!("{HASH}.entry.bak"),
        format!("{HASH}.tmp"),
        format!("{HASH}.entry.deps-cli--1.tmp"),
        format!("{HASH}.entry.deps-cli-1-.tmp"),
        format!("{HASH}.entry.deps-cli-1.tmp"),
        format!("{HASH}.entry.deps-cli-a-2.tmp"),
        format!("{HASH}.entry.other-1-2.tmp"),
        format!("{HASH}.entry.deps-cli-1-2.tmp.bak"),
        format!("{HASH}.ENTRY"),
        "notes.txt.deps-cli-1-2.tmp".to_owned(),
        "notes.entry".to_owned(),
        "a.tmp".to_owned(),
        String::new(),
    ];
    for name in &rejected {
        assert_eq!(classify(name), None, "{name:?} must not be a store file");
    }
}

#[cfg(unix)]
#[test]
fn store_file_kind_classify_rejects_non_utf8_names() {
    use std::os::unix::ffi::OsStrExt;

    let mut name = HASH.as_bytes().to_vec();
    name.extend_from_slice(b".entry\xff");
    assert_eq!(StoreFileKind::classify(OsStr::from_bytes(&name)), None);
}

#[test]
fn atomic_temp_file_name_keeps_the_writer_format() {
    assert_eq!(
        atomic_temp_file_name(OsStr::new("a.entry"), 4242, 17),
        "a.entry.deps-cli-4242-17.tmp"
    );
}

proptest! {
    #[test]
    fn store_file_kind_classify_never_panics(name in "\\PC*") {
        let _ = StoreFileKind::classify(OsStr::new(&name));
    }

    #[test]
    fn persist_key_file_name_classifies_as_entry(page in 1u32..100_000) {
        let key = key(&format!("https://api.github.com/repos/o/r/tags?page={page}"), ACCEPT);
        prop_assert_eq!(
            StoreFileKind::classify(OsStr::new(&key.file_name())),
            Some(StoreFileKind::Entry)
        );
    }

    // Drift guard (C1): the writer and the prune classifier share one temp-name format.
    #[test]
    fn atomic_temp_file_name_of_an_entry_classifies_as_tmp(
        page in 1u32..100_000,
        pid in any::<u32>(),
        nanos in any::<u128>(),
    ) {
        let key = key(&format!("https://api.github.com/repos/o/r/tags?page={page}"), ACCEPT);
        let tmp = atomic_temp_file_name(OsStr::new(&key.file_name()), pid, nanos);
        prop_assert_eq!(StoreFileKind::classify(OsStr::new(&tmp)), Some(StoreFileKind::Tmp));
    }
}

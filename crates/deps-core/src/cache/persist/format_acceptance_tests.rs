//! Acceptance tests for #2153/#2156.1 (`persist::format`): the format layer takes a `PersistKey`
//! and `StoredHeaders`, never raw URL/`Accept` strings, and `decode` has no unused `now`.

use super::format::{DecodeError, EncodeError, PersistedEntry, StoredHeaders};
use super::key::{PageRole, PersistKey};
use crate::cache::CacheTier;
use crate::cache::auth::KeyAuth;
use std::assert_matches;

const URL: &str = "https://api.github.com/repos/o/r/tags?page=2";
const ACCEPT: &str = "application/json";
const BODY: &[u8] = br#"[{"name":"v1.0.0"}]"#;

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

fn headers() -> StoredHeaders<'static> {
    StoredHeaders {
        etag: Some("\"abc\""),
        last_modified: Some("Tue, 01 Jan 2030 00:00:00 GMT"),
        link: Some("<https://api.github.com/repos/o/r/tags?page=3>; rel=\"next\""),
    }
}

#[test]
fn persisted_entry_decode_round_trips_with_the_same_key() {
    let key = key(URL, ACCEPT);
    let entry = PersistedEntry::new(&key, headers(), BODY.to_vec()).expect("fits");
    let decoded = PersistedEntry::decode(&entry.encode(), &key).expect("decodes");
    assert_eq!(decoded, entry);
    assert_eq!(decoded.body(), BODY);
}

#[test]
fn persisted_entry_decode_round_trips_with_default_headers() {
    let key = key(URL, ACCEPT);
    let entry = PersistedEntry::new(&key, StoredHeaders::default(), Vec::new()).expect("fits");
    let decoded = PersistedEntry::decode(&entry.encode(), &key).expect("decodes");
    assert_eq!(decoded.body(), b"");
}

#[test]
fn persisted_entry_decode_rejects_a_key_for_a_different_url() {
    let written = key(URL, ACCEPT);
    let other = key("https://api.github.com/repos/o/r/tags?page=3", ACCEPT);
    let bytes = PersistedEntry::new(&written, headers(), BODY.to_vec())
        .expect("fits")
        .encode();
    assert_matches!(
        PersistedEntry::decode(&bytes, &other),
        Err(DecodeError::UrlMismatch)
    );
}

#[test]
fn persisted_entry_decode_rejects_a_key_with_a_different_accept() {
    let written = key(URL, ACCEPT);
    let other = key(URL, "text/plain");
    let bytes = PersistedEntry::new(&written, headers(), BODY.to_vec())
        .expect("fits")
        .encode();
    assert_matches!(
        PersistedEntry::decode(&bytes, &other),
        Err(DecodeError::AcceptMismatch)
    );
}

#[test]
fn persisted_entry_decode_accepts_an_equivalent_key_spelled_differently() {
    let written = key(URL, ACCEPT);
    let equivalent = key("https://API.github.com:443/repos/o/r/tags?page=2", ACCEPT);
    let bytes = PersistedEntry::new(&written, headers(), BODY.to_vec())
        .expect("fits")
        .encode();
    assert!(PersistedEntry::decode(&bytes, &equivalent).is_ok());
}

#[test]
fn persisted_entry_new_rejects_an_oversized_header() {
    let huge = "x".repeat(64 * 1024);
    let result = PersistedEntry::new(
        &key(URL, ACCEPT),
        StoredHeaders {
            etag: Some(&huge),
            ..StoredHeaders::default()
        },
        Vec::new(),
    );
    assert_matches!(result, Err(EncodeError::HeaderTooLarge));
}

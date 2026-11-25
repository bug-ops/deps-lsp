//! Acceptance tests for spec 051 T003 (`persist::format`): the on-disk entry format.
//!
//! Layout constants are restated as literals so the tests also pin the wire format:
//! magic `DEPSLSPC`, `u16` little-endian version `1`, `u32` little-endian header
//! length (at most 64 KiB), JSON header, body.

use super::format::{DecodeError, EncodeError, EntryFingerprint, PersistedEntry, StoredHeaders};
use super::key::{PageRole, PersistKey};
use crate::cache::auth::KeyAuth;
use crate::cache::{CacheTier, MAX_CACHEABLE_ENTRY_BYTES};
use crate::hash::fnv1a64;
use proptest::prelude::*;
use std::assert_matches;
use std::io::{self, Read};

const MAGIC: &[u8; 8] = b"DEPSLSPC";
const VERSION: u16 = 1;
const PREFIX_LEN: usize = 8 + 2 + 4;
const MAX_HEADER_LEN: usize = 64 * 1024;
const URL: &str = "https://api.github.com/repos/o/r/tags?page=2";
const ACCEPT: &str = "application/json";

fn key_for(url: &str, accept: &str) -> PersistKey {
    PersistKey::new(
        url,
        CacheTier::Baseline,
        KeyAuth::ANONYMOUS,
        accept,
        Some(PageRole::ListingPage),
    )
    .expect("eligible key")
}

fn key() -> PersistKey {
    key_for(URL, ACCEPT)
}

fn etag(etag: &str) -> StoredHeaders<'_> {
    StoredHeaders {
        etag: Some(etag),
        ..StoredHeaders::default()
    }
}

fn sample() -> PersistedEntry {
    PersistedEntry::new(
        &key(),
        StoredHeaders {
            etag: Some("\"abc\""),
            last_modified: Some("Tue, 01 Jan 2030 00:00:00 GMT"),
            link: Some("<https://api.github.com/repos/o/r/tags?page=3>; rel=\"next\""),
        },
        br#"[{"name":"v1.0.0"}]"#.to_vec(),
    )
    .expect("sample header fits")
}

fn header_json(url: &str, accept: &str, body: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "url": url,
        "accept": accept,
        "etag": null,
        "last_modified": null,
        "link": null,
        "body_len": body.len(),
        "body_fnv1a64": fnv1a64(body),
    })
}

fn prefix(version: u16, header_len: u32) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out
}

fn raw(version: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = prefix(
        version,
        u32::try_from(header.len()).expect("header fits u32"),
    );
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}

fn raw_with_header(header: &serde_json::Value, body: &[u8]) -> Vec<u8> {
    raw(VERSION, header.to_string().as_bytes(), body)
}

fn decode(bytes: &[u8]) -> Result<PersistedEntry, DecodeError> {
    PersistedEntry::decode(bytes, &key())
}

#[test]
fn encode_decode_round_trips_all_fields() {
    let entry = sample();
    assert_eq!(decode(&entry.encode()).expect("round trip"), entry);
}

#[test]
fn encode_decode_round_trips_absent_validators_and_empty_body() {
    let entry = PersistedEntry::new(&key(), StoredHeaders::default(), Vec::new()).expect("fits");
    assert_eq!(decode(&entry.encode()).expect("round trip"), entry);
}

#[test]
fn encode_starts_with_magic_version_and_header_length() {
    let bytes = sample().encode();
    assert_eq!(&bytes[..8], MAGIC);
    assert_eq!(&bytes[8..10], &VERSION.to_le_bytes());
    let header_len = u32::from_le_bytes(bytes[10..14].try_into().expect("4 bytes"));
    let header: serde_json::Value =
        serde_json::from_slice(&bytes[PREFIX_LEN..PREFIX_LEN + header_len as usize])
            .expect("header is JSON");
    assert_eq!(header["url"], URL);
    assert_eq!(header["body_len"], sample().body().len());
}

#[test]
fn decode_accepts_hand_built_entry() {
    let body = b"hello";
    let bytes = raw_with_header(&header_json(URL, ACCEPT, body), body);
    assert_eq!(decode(&bytes).expect("valid").body(), body);
}

#[test]
fn decode_bad_magic() {
    let mut bytes = sample().encode();
    bytes[0] = b'X';
    assert_matches!(decode(&bytes), Err(DecodeError::BadMagic));
}

#[test]
fn decode_foreign_version() {
    let body = b"x";
    let header = header_json(URL, ACCEPT, body).to_string();
    let bytes = raw(VERSION + 1, header.as_bytes(), body);
    assert_matches!(decode(&bytes), Err(DecodeError::ForeignVersion));
}

#[test]
fn decode_header_too_large_is_refused_before_reading_it() {
    let bytes = prefix(VERSION, u32::try_from(MAX_HEADER_LEN + 1).expect("fits"));
    assert_matches!(decode(&bytes), Err(DecodeError::HeaderTooLarge));
}

#[test]
fn decode_header_of_exactly_the_cap_is_accepted() {
    let body = b"x";
    let mut header = header_json(URL, ACCEPT, body).to_string().into_bytes();
    header.resize(MAX_HEADER_LEN, b' ');
    let bytes = raw(VERSION, &header, body);
    assert_eq!(decode(&bytes).expect("valid").body(), body);
}

#[test]
fn decode_header_not_json_is_header_error() {
    let bytes = raw(VERSION, b"not json", b"");
    assert_matches!(decode(&bytes), Err(DecodeError::Header(_)));
}

#[test]
fn decode_header_with_unknown_field_is_header_error() {
    let body = b"x";
    let mut header = header_json(URL, ACCEPT, body);
    header["surprise"] = serde_json::json!(1);
    assert_matches!(
        decode(&raw_with_header(&header, body)),
        Err(DecodeError::Header(_))
    );
}

#[test]
fn decode_header_missing_required_field_is_header_error() {
    let body = b"x";
    let mut header = header_json(URL, ACCEPT, body);
    header.as_object_mut().expect("object").remove("body_len");
    assert_matches!(
        decode(&raw_with_header(&header, body)),
        Err(DecodeError::Header(_))
    );
}

#[test]
fn decode_header_field_of_wrong_type_is_header_error() {
    let body = b"x";
    let mut header = header_json(URL, ACCEPT, body);
    header["body_len"] = serde_json::json!("1");
    assert_matches!(
        decode(&raw_with_header(&header, body)),
        Err(DecodeError::Header(_))
    );
}

#[test]
fn decode_truncated_prefix() {
    let bytes = sample().encode();
    assert_matches!(
        decode(&bytes[..PREFIX_LEN - 1]),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn decode_truncated_header() {
    let bytes = sample().encode();
    assert_matches!(
        decode(&bytes[..PREFIX_LEN + 5]),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn decode_truncated_body() {
    let bytes = sample().encode();
    assert_matches!(
        decode(&bytes[..bytes.len() - 1]),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn decode_flipped_body_byte_fails_checksum() {
    let mut bytes = sample().encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert_matches!(decode(&bytes), Err(DecodeError::Checksum));
}

#[test]
fn decode_url_mismatch() {
    let bytes = sample().encode();
    assert_matches!(
        PersistedEntry::decode(
            &bytes,
            &key_for("https://api.github.com/repos/o/r/tags?page=3", ACCEPT)
        ),
        Err(DecodeError::UrlMismatch)
    );
}

#[test]
fn decode_accept_mismatch() {
    let bytes = sample().encode();
    assert_matches!(
        PersistedEntry::decode(&bytes, &key_for(URL, "text/html")),
        Err(DecodeError::AcceptMismatch)
    );
}

#[test]
fn decode_oversize_body_is_rejected_never_truncated() {
    let body = vec![7u8; MAX_CACHEABLE_ENTRY_BYTES + 1];
    let bytes = raw_with_header(&header_json(URL, ACCEPT, &body), &body);
    assert_matches!(decode(&bytes), Err(DecodeError::Oversized));
}

#[test]
fn decode_declared_length_over_cap_is_oversized_without_the_body() {
    let mut header = header_json(URL, ACCEPT, b"x");
    header["body_len"] = serde_json::json!(MAX_CACHEABLE_ENTRY_BYTES as u64 + 1);
    assert_matches!(
        decode(&raw_with_header(&header, b"x")),
        Err(DecodeError::Oversized)
    );
}

#[test]
fn decode_declared_length_u64_max_is_oversized() {
    let mut header = header_json(URL, ACCEPT, b"x");
    header["body_len"] = serde_json::json!(u64::MAX);
    assert_matches!(
        decode(&raw_with_header(&header, b"x")),
        Err(DecodeError::Oversized)
    );
}

#[test]
fn decode_body_exactly_at_cap_is_accepted() {
    let body = vec![7u8; MAX_CACHEABLE_ENTRY_BYTES];
    let bytes = raw_with_header(&header_json(URL, ACCEPT, &body), &body);
    assert_eq!(decode(&bytes).expect("at cap").body().len(), body.len());
}

struct CountingReader<'a> {
    data: &'a [u8],
    served: usize,
}

impl Read for CountingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rest = &self.data[self.served..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.served += n;
        Ok(n)
    }
}

#[test]
fn fingerprint_from_reader_matches_the_entry_fingerprint() {
    let entry = sample();
    let bytes = entry.encode();
    let fingerprint = EntryFingerprint::from_reader(&mut bytes.as_slice()).expect("header");
    assert_eq!(fingerprint, entry.fingerprint());
    assert_eq!(fingerprint.body_len(), entry.body().len() as u64);
    assert_eq!(fingerprint.body_fnv1a64(), fnv1a64(entry.body()));
}

#[test]
fn fingerprint_from_reader_does_not_read_the_body() {
    let entry = PersistedEntry::new(&key(), etag("\"e\""), vec![1u8; 512 * 1024]).expect("fits");
    let bytes = entry.encode();
    let mut reader = CountingReader {
        data: &bytes,
        served: 0,
    };
    let fingerprint = EntryFingerprint::from_reader(&mut reader).expect("header");
    assert_eq!(fingerprint, entry.fingerprint());
    assert!(
        reader.served <= PREFIX_LEN + MAX_HEADER_LEN,
        "served {} bytes",
        reader.served
    );
}

#[test]
fn fingerprint_differs_when_body_differs() {
    let a = PersistedEntry::new(&key(), etag("\"e\""), b"one".to_vec()).expect("fits");
    let b = PersistedEntry::new(&key(), etag("\"e\""), b"two".to_vec()).expect("fits");
    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn fingerprint_differs_when_validator_differs() {
    let a = PersistedEntry::new(&key(), etag("\"e1\""), b"x".to_vec()).expect("fits");
    let b = PersistedEntry::new(&key(), etag("\"e2\""), b"x".to_vec()).expect("fits");
    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn fingerprint_from_reader_rejects_bad_magic_foreign_version_and_oversized_header() {
    let mut bad_magic = sample().encode();
    bad_magic[0] = b'X';
    assert_matches!(
        EntryFingerprint::from_reader(&mut bad_magic.as_slice()),
        Err(DecodeError::BadMagic)
    );

    let mut foreign = sample().encode();
    foreign[8..10].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert_matches!(
        EntryFingerprint::from_reader(&mut foreign.as_slice()),
        Err(DecodeError::ForeignVersion)
    );

    let too_large = prefix(VERSION, u32::try_from(MAX_HEADER_LEN + 1).expect("fits"));
    assert_matches!(
        EntryFingerprint::from_reader(&mut too_large.as_slice()),
        Err(DecodeError::HeaderTooLarge)
    );
}

#[test]
fn fingerprint_from_reader_on_short_input_is_truncated() {
    let bytes = sample().encode();
    assert_matches!(
        EntryFingerprint::from_reader(&mut &bytes[..PREFIX_LEN + 3]),
        Err(DecodeError::Truncated)
    );
}

proptest! {
    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn decode_never_panics_behind_a_valid_prefix(
        header_len in 0u32..2048,
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut bytes = prefix(VERSION, header_len);
        bytes.extend_from_slice(&tail);
        let _ = decode(&bytes);
    }

    #[test]
    fn decode_never_panics_on_a_corrupted_valid_entry(index in any::<usize>(), flip in 1u8..=255) {
        let mut bytes = sample().encode();
        let at = index % bytes.len();
        bytes[at] ^= flip;
        let _ = decode(&bytes);
    }

    #[test]
    fn fingerprint_from_reader_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = EntryFingerprint::from_reader(&mut bytes.as_slice());
    }
}

#[test]
fn new_refuses_a_header_over_the_cap() {
    let huge = "u".repeat(MAX_HEADER_LEN);
    assert_matches!(
        PersistedEntry::new(&key(), etag(&huge), Vec::new()),
        Err(EncodeError::HeaderTooLarge)
    );
}

#[test]
fn new_refuses_a_body_over_the_cacheable_cap() {
    assert_matches!(
        PersistedEntry::new(
            &key(),
            StoredHeaders::default(),
            vec![0u8; MAX_CACHEABLE_ENTRY_BYTES + 1]
        ),
        Err(EncodeError::Oversized)
    );
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
    }
}

#[test]
fn fingerprint_from_reader_maps_a_non_eof_io_failure_to_io() {
    assert_matches!(
        EntryFingerprint::from_reader(FailingReader),
        Err(DecodeError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied
    );
}

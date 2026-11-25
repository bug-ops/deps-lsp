//! #2158: `ReadCompleteness::check` fails closed on a reparse-point read that is short of the
//! handle's reported length or entirely zero-filled, and never rejects an ordinary read.
//!
//! Declared from `fs_probe.rs` as a child module.

use super::ReadCompleteness;
use std::io::ErrorKind;

fn kind(completeness: ReadCompleteness, bytes: &[u8], max_bytes: u64) -> Option<ErrorKind> {
    completeness
        .check(bytes, max_bytes)
        .err()
        .map(|error| error.kind())
}

#[test]
fn exact_rejects_a_read_short_of_the_reported_length() {
    assert_eq!(
        kind(ReadCompleteness::Exact(10), b"", 1024),
        Some(ErrorKind::UnexpectedEof)
    );
    assert_eq!(
        kind(ReadCompleteness::Exact(10), b"123456789", 1024),
        Some(ErrorKind::UnexpectedEof)
    );
}

#[test]
fn exact_accepts_a_full_non_zero_read() {
    assert_eq!(kind(ReadCompleteness::Exact(10), b"0123456789", 1024), None);
}

#[test]
fn exact_rejects_a_full_length_all_zero_read() {
    assert_eq!(
        kind(ReadCompleteness::Exact(10), &[0u8; 10], 1024),
        Some(ErrorKind::InvalidData)
    );
}

#[test]
fn exact_accepts_a_read_that_merely_contains_nul_bytes() {
    assert_eq!(kind(ReadCompleteness::Exact(3), b"a\0\0", 1024), None);
}

#[test]
fn exact_expects_only_up_to_the_cap_plus_one_byte() {
    assert_eq!(kind(ReadCompleteness::Exact(100), b"01234567890", 10), None);
}

#[test]
fn exact_zero_accepts_an_empty_read() {
    assert_eq!(kind(ReadCompleteness::Exact(0), b"", 1024), None);
}

#[test]
fn unchecked_accepts_every_read() {
    for bytes in [&b""[..], &[0u8; 10][..], b"x"] {
        assert_eq!(kind(ReadCompleteness::Unchecked, bytes, 1024), None);
    }
}

//! #2173: `ReadCompleteness::check` additionally refuses a complete `Text` read that ends in a NUL
//! byte (a zero-filled tail of a partially rehydrated reparse-point file), while `Binary` content
//! is exempt from that rule only.
//!
//! Declared from `fs_probe.rs` as a child module, next to `read_completeness_tests`.

use super::{ReadCompleteness, ReadContent};
use std::io::ErrorKind;

fn kind(
    completeness: ReadCompleteness,
    bytes: &[u8],
    max_bytes: u64,
    content: ReadContent,
) -> Option<ErrorKind> {
    completeness
        .check(bytes, max_bytes, content)
        .err()
        .map(|error| error.kind())
}

#[test]
fn text_exact_rejects_a_full_read_ending_in_nul() {
    for bytes in [&b"[a]\n\0\0"[..], b"[a]\n\0"] {
        assert_eq!(
            kind(
                ReadCompleteness::Exact(bytes.len() as u64),
                bytes,
                1024,
                ReadContent::Text
            ),
            Some(ErrorKind::InvalidData),
            "{bytes:?}"
        );
    }
}

#[test]
fn text_exact_accepts_a_full_read_with_only_interior_nul() {
    assert_eq!(
        kind(
            ReadCompleteness::Exact(5),
            b"a\0b\n\x01",
            1024,
            ReadContent::Text
        ),
        None
    );
}

#[test]
fn text_exact_accepts_a_clean_full_read() {
    assert_eq!(
        kind(
            ReadCompleteness::Exact(4),
            b"[a]\n",
            1024,
            ReadContent::Text
        ),
        None
    );
}

#[test]
fn text_exact_does_not_apply_the_nul_rule_to_a_truncated_read() {
    assert_eq!(
        kind(ReadCompleteness::Exact(100), b"abc\0", 3, ReadContent::Text),
        None,
        "a read past the cap is rejected by the cap, not by the NUL rule"
    );
}

#[test]
fn binary_exact_accepts_a_full_read_ending_in_nul() {
    assert_eq!(
        kind(
            ReadCompleteness::Exact(6),
            b"[a]\n\0\0",
            1024,
            ReadContent::Binary
        ),
        None
    );
}

#[test]
fn binary_exact_still_rejects_a_short_or_all_zero_read() {
    assert_eq!(
        kind(
            ReadCompleteness::Exact(10),
            b"123",
            1024,
            ReadContent::Binary
        ),
        Some(ErrorKind::UnexpectedEof)
    );
    assert_eq!(
        kind(
            ReadCompleteness::Exact(4),
            &[0u8; 4],
            1024,
            ReadContent::Binary
        ),
        Some(ErrorKind::InvalidData)
    );
}

#[test]
fn unchecked_accepts_a_trailing_nul_for_both_content_kinds() {
    for content in [ReadContent::Text, ReadContent::Binary] {
        assert_eq!(
            kind(ReadCompleteness::Unchecked, b"[a]\n\0", 1024, content),
            None
        );
    }
}

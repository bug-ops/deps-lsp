//! #2156.4: `deps_core::hash::fnv1a64` is the single FNV-1a 64 implementation. On-disk entry names
//! and update-branch names derive from it, so its output must never change.

use deps_core::hash::fnv1a64;

#[test]
fn fnv1a64_empty_input_is_the_offset_basis() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn fnv1a64_matches_published_vectors() {
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn fnv1a64_is_byte_order_sensitive() {
    assert_ne!(fnv1a64(b"ab"), fnv1a64(b"ba"));
}

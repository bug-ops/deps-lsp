//! #2151: `patterns_overlap` decides whether two `prefix*suffix` manifest patterns can match the
//! same basename. Registration asserts that patterns of different ecosystems never do.

use super::patterns_overlap;

#[test]
fn patterns_overlap_table() {
    let cases = [
        (("", ".toml"), ("", ".versions.toml"), true),
        (("", ".versions.toml"), ("", ".toml"), true),
        (("", ".versions.toml"), ("requirements", ".txt"), false),
        (("req", ""), ("requirements", ".txt"), true),
        (("requirements", ".txt"), ("requirements", ".txt"), true),
        (("requirements", ".txt"), ("constraints", ".txt"), false),
        (("a", ".x"), ("b", ".x"), false),
        (("a", ".x"), ("a", ".y"), false),
    ];
    for (left, right, expected) in cases {
        assert_eq!(
            patterns_overlap(left, right),
            expected,
            "{left:?} vs {right:?}"
        );
    }
}

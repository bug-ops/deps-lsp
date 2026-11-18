//! #2072 acceptance: `deps_core::star_glob::matches` is the shared `*`-only glob (moved from
//! `native_cooldown/exemption.rs`). Written tests-first; the module does not exist yet.

use std::time::{Duration, Instant};

use deps_core::star_glob::matches;

#[test]
fn matches_table_follows_star_only_semantics() {
    let rows: &[(&str, &str, bool)] = &[
        ("*", "anything", true),
        ("*", "", true),
        ("", "", true),
        ("", "a", false),
        ("serde", "serde", true),
        ("serde", "serde_json", false),
        ("serde*", "serde_json", true),
        ("serde*", "xserde", false),
        ("*-core", "deps-core", true),
        ("*-core", "deps-core-x", false),
        ("a*b*c", "aXbYc", true),
        ("a*b*c", "acb", false),
        ("**", "x", true),
        ("@types/*", "@types/node", true),
        ("*", "a/b/c", true),
        ("a*c", "a/b/c", true),
    ];
    for (pattern, text, expected) in rows {
        assert_eq!(matches(pattern, text), *expected, "{pattern:?} vs {text:?}");
    }
}

#[test]
fn matches_treats_every_other_glob_metacharacter_literally() {
    assert!(!matches("a?c", "abc"));
    assert!(matches("a?c", "a?c"));
    assert!(!matches("a[b]c", "abc"));
    assert!(matches("a[b]c", "a[b]c"));
    assert!(!matches("a.c", "abc"));
    assert!(matches("a{b,c}", "a{b,c}"));
}

#[test]
fn matches_is_linear_on_pathological_patterns() {
    let pattern = format!("{}c", "a*".repeat(5_000));
    let text = format!("{}b", "a".repeat(50_000));
    let started = Instant::now();

    let result = matches(&pattern, &text);

    assert!(!result);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "matcher must not backtrack exponentially"
    );
}

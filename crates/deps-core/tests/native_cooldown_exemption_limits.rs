//! Security regression (impl-critic / security M1, M2): exemption lists come from
//! repository-controlled files, so memory and time stay bounded on hostile input.

use std::assert_matches;

use std::sync::Arc;
use std::time::{Duration, Instant};

use deps_core::native_cooldown::{Exemption, ExemptionError, ExemptionSyntax, parse_exemptions};

#[test]
fn total_exempt_versions_are_capped() {
    let alternatives = (0..5000)
        .map(|i| format!("1.0.{i}"))
        .collect::<Vec<_>>()
        .join(" || ");
    let entry = format!("pkg@{alternatives}");
    // Spread over entries so no single one exceeds the per-entry byte cap.
    let chunked: Vec<String> = (0..5000)
        .step_by(20)
        .map(|start| {
            let part = (start..start + 20)
                .map(|i| format!("1.0.{i}"))
                .collect::<Vec<_>>()
                .join(" || ");
            format!("pkg{start}@{part}")
        })
        .collect();
    let refs: Vec<&str> = chunked.iter().map(String::as_str).collect();
    assert_eq!(
        parse_exemptions(&refs, ExemptionSyntax::Pnpm).unwrap_err(),
        ExemptionError::TooLarge
    );
    assert_eq!(
        parse_exemptions(&[entry.as_str()], ExemptionSyntax::Pnpm).unwrap_err(),
        ExemptionError::TooLarge,
        "a single entry over the byte cap is rejected too"
    );
}

#[test]
fn versions_are_shared_between_lookups_not_copied() {
    let list =
        parse_exemptions(&["lodash@4.17.21 || 4.17.20"], ExemptionSyntax::Pnpm).expect("parses");
    let (Exemption::Versions(first), Exemption::Versions(second)) =
        (list.lookup("lodash"), list.lookup("lodash"))
    else {
        panic!("a version-scoped exemption");
    };
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first.len(), 2);
}

#[test]
fn repeated_names_merge_and_a_bare_name_wins() {
    let list = parse_exemptions(
        &["lodash@1.0.0", "lodash@2.0.0", "express@1.0.0", "express"],
        ExemptionSyntax::Npm,
    )
    .expect("parses");
    assert_matches!(
        list.lookup("lodash"),
        Exemption::Versions(versions) if versions.len() == 2
    );
    assert_eq!(list.lookup("express"), Exemption::AllVersions);
}

#[test]
fn names_longer_than_any_real_package_are_never_exempt() {
    let list = parse_exemptions(&["*"], ExemptionSyntax::Pnpm).expect("parses");
    assert_eq!(list.lookup(&"a".repeat(214)), Exemption::AllVersions);
    assert_eq!(list.lookup(&"a".repeat(215)), Exemption::None);
}

/// 64 distinct wildcard patterns (the cap), each shaped to force a full scan of a 214-byte name
/// without ever matching it.
fn distinct_star_patterns(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("{}z{i}", "*a".repeat(24)))
        .collect()
}

#[test]
fn distinct_star_heavy_patterns_stay_fast_on_many_hostile_names() {
    let owned = distinct_star_patterns(64);
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let names: Vec<String> = (0..4000).map(|_| "a".repeat(214)).collect();
    for syntax in [ExemptionSyntax::Npm, ExemptionSyntax::Pnpm] {
        let list = parse_exemptions(&refs, syntax).expect("the cap admits 64 wildcards");
        let started = Instant::now();
        for name in &names {
            assert_eq!(list.lookup(name), Exemption::None);
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{syntax:?}: 4000 lookups of 64 distinct patterns took {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn wildcard_patterns_are_capped_in_number_and_total_size() {
    let too_many = distinct_star_patterns(65);
    let refs: Vec<&str> = too_many.iter().map(String::as_str).collect();
    assert_eq!(
        parse_exemptions(&refs, ExemptionSyntax::Pnpm).unwrap_err(),
        ExemptionError::TooLarge
    );

    let hostile: Vec<String> = (0..1024).map(|i| format!("*a*a*a*z{i}")).collect();
    let refs: Vec<&str> = hostile.iter().map(String::as_str).collect();
    assert_eq!(
        parse_exemptions(&refs, ExemptionSyntax::Npm).unwrap_err(),
        ExemptionError::TooLarge,
        "1024 distinct wildcard patterns are rejected"
    );

    let long: Vec<String> = (0..16)
        .map(|i| format!("*{}{i}*", "a".repeat(300)))
        .collect();
    let refs: Vec<&str> = long.iter().map(String::as_str).collect();
    assert_eq!(
        parse_exemptions(&refs, ExemptionSyntax::Npm).unwrap_err(),
        ExemptionError::TooLarge,
        "16 x ~305 bytes exceeds the total wildcard bytes"
    );
}

#[test]
fn exact_names_are_hashed_not_scanned() {
    let owned: Vec<String> = (0..1024).map(|i| format!("pkg{i}")).collect();
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let list = parse_exemptions(&refs, ExemptionSyntax::Npm).expect("parses");
    let started = Instant::now();
    for i in 0..20_000 {
        let name = format!("pkg{}", i % 2048);
        let expected = if i % 2048 < 1024 {
            Exemption::AllVersions
        } else {
            Exemption::None
        };
        assert_eq!(list.lookup(&name), expected);
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn glob_semantics_survive_the_linear_matcher() {
    let list =
        parse_exemptions(&["a*b*c", "x*", "*y", "m**n"], ExemptionSyntax::Pnpm).expect("parses");
    for (name, exempt) in [
        ("abc", true),
        ("aXbYc", true),
        ("ab", false),
        ("acb", false),
        ("x", true),
        ("xyz", true),
        ("y", true),
        ("zy", true),
        ("yz", false),
        ("mn", true),
        ("mxxn", true),
        ("m", false),
    ] {
        assert_eq!(
            matches!(list.lookup(name), Exemption::AllVersions),
            exempt,
            "{name}"
        );
    }
}

//! #2041 / spec 099 FR-017 acceptance: per-package exemption lists parsed per package-manager
//! dialect (npm minimatch, pnpm, Bun, uv), segment-scoped `*`, conservative rejection of unsupported
//! entries and the linear-time matcher.
//!
//! Written tests-first against plan `2026-11-17T18-35-26-architect` (Contracts) and
//! `20-32-28-architect` (N-M6). Assumed seams: `parse_exemptions(&[&str], ExemptionSyntax)`
//! returning `Result<ExemptionList, _>` (error variants are not asserted), `ExemptionList::lookup(&str) -> Exemption`,
//! all in `deps_core::native_cooldown`.

#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use deps_core::native_cooldown::{Exemption, ExemptionList, ExemptionSyntax, parse_exemptions};

fn list(entries: &[&str], syntax: ExemptionSyntax) -> ExemptionList {
    parse_exemptions(entries, syntax).expect("entries must parse")
}

fn is_all(list: &ExemptionList, name: &str) -> bool {
    matches!(list.lookup(name), Exemption::AllVersions)
}

fn is_none(list: &ExemptionList, name: &str) -> bool {
    matches!(list.lookup(name), Exemption::None)
}

#[test]
fn lookup_exact_name_exempts_all_versions_only_for_that_name() {
    for syntax in [
        ExemptionSyntax::Npm,
        ExemptionSyntax::Pnpm,
        ExemptionSyntax::Bun,
        ExemptionSyntax::Uv,
    ] {
        let l = list(&["lodash"], syntax);
        assert!(is_all(&l, "lodash"), "{syntax:?}");
        assert!(is_none(&l, "lodash-es"), "{syntax:?}");
        assert!(is_none(&l, "express"), "{syntax:?}");
    }
}

#[test]
fn lookup_empty_list_exempts_nothing() {
    let l = list(&[], ExemptionSyntax::Npm);
    assert!(is_none(&l, "lodash"));
}

#[test]
fn lookup_npm_star_matches_within_one_segment_only() {
    let l = list(&["*"], ExemptionSyntax::Npm);
    assert!(is_all(&l, "lodash"));
    assert!(
        is_none(&l, "@types/node"),
        "npm minimatch `*` must not cross `/`"
    );
}

#[test]
fn lookup_npm_scope_star_matches_every_package_of_that_scope() {
    let l = list(&["@types/*"], ExemptionSyntax::Npm);
    assert!(is_all(&l, "@types/node"));
    assert!(is_none(&l, "@babel/core"));
    assert!(is_none(&l, "types"));
}

#[test]
fn lookup_npm_star_inside_a_segment_does_not_absorb_the_slash() {
    let l = list(&["@a*/b"], ExemptionSyntax::Npm);
    assert!(is_all(&l, "@ax/b"));
    assert!(is_none(&l, "@ax/yb/b"), "`*` must not absorb `/` (N-M6)");
    assert!(is_none(&l, "@ax/c"));
}

#[test]
fn lookup_npm_pattern_and_name_with_different_segment_counts_never_match() {
    let l = list(&["@scope/*"], ExemptionSyntax::Npm);
    assert!(is_none(&l, "@scope"));
    assert!(is_none(&l, "@scope/a/b"));
}

#[test]
fn lookup_pnpm_star_may_match_any_character_including_slash() {
    let l = list(&["*"], ExemptionSyntax::Pnpm);
    assert!(is_all(&l, "lodash"));
    assert!(is_all(&l, "@types/node"));
    let scoped = list(&["@babel/*"], ExemptionSyntax::Pnpm);
    assert!(is_all(&scoped, "@babel/core"));
    assert!(is_none(&scoped, "@types/node"));
}

#[test]
fn lookup_name_at_version_yields_versions_exemption_not_all() {
    for (entry, syntax) in [
        ("lodash@4.17.21", ExemptionSyntax::Npm),
        ("lodash@4.17.21", ExemptionSyntax::Pnpm),
        ("lodash@4.17.21", ExemptionSyntax::Bun),
    ] {
        let l = list(&[entry], syntax);
        assert!(
            matches!(l.lookup("lodash"), Exemption::Versions(_)),
            "{syntax:?}"
        );
        assert!(is_none(&l, "express"), "{syntax:?}");
    }
}

#[test]
fn lookup_pnpm_and_bun_or_separated_versions_yield_versions_exemption() {
    for syntax in [ExemptionSyntax::Pnpm, ExemptionSyntax::Bun] {
        let l = list(&["foo@1.0.0 || 1.0.1"], syntax);
        assert!(
            matches!(l.lookup("foo"), Exemption::Versions(_)),
            "{syntax:?}"
        );
    }
}

#[test]
fn lookup_scoped_name_at_version_splits_on_the_last_at_sign() {
    let l = list(&["@scope/pkg@1.2.3"], ExemptionSyntax::Pnpm);
    assert!(matches!(l.lookup("@scope/pkg"), Exemption::Versions(_)));
    assert!(is_none(&l, "@scope/other"));
}

#[test]
fn lookup_any_all_versions_entry_wins_over_version_entries_for_the_same_name() {
    let l = list(&["lodash@4.17.21", "lodash"], ExemptionSyntax::Pnpm);
    assert!(is_all(&l, "lodash"));
    let reversed = list(&["lodash", "lodash@4.17.21"], ExemptionSyntax::Pnpm);
    assert!(is_all(&reversed, "lodash"));
}

#[test]
fn lookup_uv_names_are_matched_as_given_so_the_caller_normalizes() {
    let l = list(&["zope.interface"], ExemptionSyntax::Uv);
    assert!(is_all(&l, "zope.interface"));
    assert!(is_none(&l, "zope-interface"));
}

#[test]
fn parse_exemptions_unsupported_entry_rejects_the_whole_list() {
    for entry in [
        "lod?sh",
        "lod[a-z]sh",
        "{a,b}",
        "!lodash",
        "lodash*@1.0.0",
        "@scope/*@1.0.0",
    ] {
        let result = parse_exemptions(&["express", entry], ExemptionSyntax::Npm);
        assert!(result.is_err(), "{entry:?} must reject the whole list");
    }
}

#[test]
fn parse_exemptions_more_than_1024_entries_is_rejected() {
    let owned: Vec<String> = (0..1025).map(|i| format!("pkg{i}")).collect();
    let entries: Vec<&str> = owned.iter().map(String::as_str).collect();
    assert!(parse_exemptions(&entries, ExemptionSyntax::Npm).is_err());
    assert!(parse_exemptions(&entries[..1024], ExemptionSyntax::Npm).is_ok());
}

#[test]
fn parse_exemptions_entry_longer_than_512_bytes_is_rejected() {
    let long = "a".repeat(513);
    assert!(parse_exemptions(&[long.as_str()], ExemptionSyntax::Npm).is_err());
    let at_limit = "a".repeat(512);
    assert!(parse_exemptions(&[at_limit.as_str()], ExemptionSyntax::Npm).is_ok());
}

#[test]
fn lookup_many_stars_against_a_long_name_stays_linear_time() {
    let pattern = format!("{}b", "*a".repeat(255));
    assert!(pattern.len() <= 512);
    let name = "a".repeat(214);
    for syntax in [ExemptionSyntax::Npm, ExemptionSyntax::Pnpm] {
        let l = list(&[pattern.as_str()], syntax);
        let started = Instant::now();
        assert!(
            is_none(&l, &name),
            "{syntax:?}: no trailing `b` in the name"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{syntax:?}: matcher must not backtrack exponentially"
        );
    }
}

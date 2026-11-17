//! #2041 / spec 099 acceptance: Bun's `[install] minimumReleaseAge` (integer seconds) and
//! `minimumReleaseAgeExcludes` from the project-root `bunfig.toml` (plan `18-35-26-architect`,
//! Q2; `20-24-32-architect` D5).
//!
//! Written tests-first; fixtures live in `tests/common/mod.rs`.

use std::assert_matches;
mod common;

use common::{DAY, cooldown_of, ctx, hold_at_age, honor, label_of, parse_manifest, root, write};
use deps_core::native_cooldown::{NativeHold, NativeLimit};
use deps_core::policy_config::NativeCooldownMode;

const ONE_DAY_IN_SECONDS: &str = "[install]\nminimumReleaseAge = 86400\n";

fn bun_repo(bunfig: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = root();
    write(&root.join("bunfig.toml"), bunfig);
    write(&root.join("bun.lock"), "");
    (guard, root)
}

fn assert_control_applies() {
    let (_g, root) = bun_repo(ONE_DAY_IN_SECONDS);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(
        label_of(&result, "lodash").is_some(),
        "control: a valid window must resolve"
    );
}

#[test]
fn minimum_release_age_is_read_in_seconds() {
    let (_g, root) = bun_repo(ONE_DAY_IN_SECONDS);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
    assert!(cooldown.to_string().contains("minimumReleaseAge"));
    assert_eq!(
        hold_at_age(&cooldown, "4.17.21", 3600),
        Some(NativeHold::For(DAY as u64 - 3600))
    );
    assert_eq!(hold_at_age(&cooldown, "4.17.21", DAY), None);
}

#[test]
fn legacy_bun_lockb_also_selects_bun() {
    let (_g, root) = root();
    write(&root.join("bunfig.toml"), ONE_DAY_IN_SECONDS);
    write(&root.join("bun.lockb"), "");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn bunfig_without_a_lock_file_selects_bun_when_no_other_manager_is_present() {
    let (_g, root) = root();
    write(&root.join("bunfig.toml"), ONE_DAY_IN_SECONDS);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn no_declared_value_means_no_window() {
    assert_control_applies();
    let (_g, root) = bun_repo("[install]\nexact = true\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn missing_bunfig_means_no_window() {
    assert_control_applies();
    let (_g, root) = root();
    write(&root.join("bun.lock"), "");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn zero_negative_fractional_and_non_integer_values_are_ignored() {
    assert_control_applies();
    for body in [
        "minimumReleaseAge = 0",
        "minimumReleaseAge = -60",
        "minimumReleaseAge = 1.5",
        "minimumReleaseAge = \"86400\"",
        "minimumReleaseAge = true",
    ] {
        let (_g, root) = bun_repo(&format!("[install]\n{body}\n"));
        let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
        assert_eq!(label_of(&result, "lodash"), None, "{body:?}");
    }
}

#[test]
fn value_outside_the_install_table_is_ignored() {
    assert_control_applies();
    let (_g, root) = bun_repo("minimumReleaseAge = 86400\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn malformed_toml_is_ignored_without_failing_the_parse() {
    assert_control_applies();
    let (_g, root) = bun_repo("[install\nminimumReleaseAge = 86400\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn excludes_by_name_and_name_at_versions() {
    let (_g, root) = bun_repo(
        "[install]\nminimumReleaseAge = 86400\nminimumReleaseAgeExcludes = [\"lodash\", \"express@4.18.0 || 4.18.1\"]\n",
    );
    let result = parse_manifest(
        &root,
        &[("lodash", "^4"), ("express", "^4"), ("react", "^18")],
        &honor(),
    );
    assert_eq!(label_of(&result, "lodash"), None);
    let express = cooldown_of(&result, "express").expect("window stays for other versions");
    assert_eq!(hold_at_age(&express, "4.18.0", 3600), None);
    assert_eq!(hold_at_age(&express, "4.18.1", 3600), None);
    assert!(hold_at_age(&express, "4.18.2", 3600).is_some());
    assert!(label_of(&result, "react").is_some());
}

#[test]
fn only_the_project_root_bunfig_is_read() {
    let (_g, root) = bun_repo(ONE_DAY_IN_SECONDS);
    let member = root.join("packages/app");
    write(
        &member.join("bunfig.toml"),
        "[install]\nminimumReleaseAge = 3600\n",
    );
    let result = parse_manifest(&member, &[("lodash", "^4")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("root window applies");
    assert_eq!(
        hold_at_age(&cooldown, "4.17.21", 3600),
        Some(NativeHold::For(DAY as u64 - 3600))
    );
}

#[test]
fn ignore_mode_resolves_no_window() {
    assert_control_applies();
    let (_g, root) = bun_repo(ONE_DAY_IN_SECONDS);
    let result = parse_manifest(&root, &[("lodash", "^4")], &ctx(NativeCooldownMode::Ignore));
    assert_eq!(label_of(&result, "lodash"), None);
}

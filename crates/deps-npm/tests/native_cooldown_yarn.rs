//! #2051 / spec 099 acceptance (track B): Yarn's `npmMinimalAgeGate` (global and per scope) and
//! `npmPreapprovedPackages`, read from the project-root `.yarnrc.yml`.
//!
//! Version bands the file itself must be read against: Yarn < 4.10 has no gate, 4.10-4.16 has
//! only the global key, >= 4.17 adds per-scope keys and a 1 day default for a scope entry that
//! lacks the key. A file proves >= 4.17 only by declaring a per-scope key under some
//! `npmScopes.<s>` entry (`ScopedGates::Declared`), whatever that key's value.
//!
//! Written tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`);
//! fixtures live in `tests/common/mod.rs`.

use std::assert_matches;
mod common;

use common::{DAY, cooldown_of, hold_at_age, honor, label_of, parse_manifest, root, write};
use deps_core::native_cooldown::{NativeHold, NativeLimit};

fn yarn_repo(yarnrc: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = root();
    write(&root.join(".yarnrc.yml"), yarnrc);
    write(&root.join("yarn.lock"), "__metadata:\n  version: 8\n");
    (guard, root)
}

fn label(yarnrc: &str, name: &str) -> Option<String> {
    let (_g, root) = yarn_repo(yarnrc);
    let result = parse_manifest(&root, &[(name, "^1")], &honor());
    label_of(&result, name)
}

fn assert_control_applies() {
    assert!(
        label("npmMinimalAgeGate: 7d\n", "lodash").is_some(),
        "control: a valid window must resolve"
    );
}

#[test]
fn global_gate_with_a_unit_is_read() {
    let (_g, root) = yarn_repo("npmMinimalAgeGate: 7d\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
    assert_eq!(cooldown.to_string(), "yarn npmMinimalAgeGate = 7 days");
    assert_eq!(
        hold_at_age(&cooldown, "4.17.21", DAY),
        Some(NativeHold::For(6 * DAY as u64))
    );
    assert_eq!(hold_at_age(&cooldown, "4.17.21", 7 * DAY), None);
}

#[test]
fn global_gate_unitless_value_is_minutes() {
    assert_eq!(
        label("npmMinimalAgeGate: 1440\n", "lodash").as_deref(),
        Some("yarn npmMinimalAgeGate = 1440 minutes")
    );
}

#[test]
fn global_gate_zero_disables_the_window() {
    assert_control_applies();
    assert_eq!(label("npmMinimalAgeGate: 0\n", "lodash"), None);
    assert_eq!(label("npmMinimalAgeGate: 0d\n", "lodash"), None);
}

#[test]
fn malformed_global_gate_is_ignored() {
    assert_control_applies();
    for yaml in [
        "npmMinimalAgeGate: \"${AGE}\"\n",
        "npmMinimalAgeGate: -1d\n",
        "npmMinimalAgeGate: 1y\n",
        "npmMinimalAgeGate: soon\n",
        "npmMinimalAgeGate: [7d]\n",
    ] {
        assert_eq!(label(yaml, "lodash"), None, "{yaml:?}");
    }
}

#[test]
fn no_gate_key_anywhere_means_no_window_and_matches_a_project_without_yarnrc() {
    assert_control_applies();
    let yaml = "nodeLinker: node-modules\nnpmScopes:\n  myorg:\n    npmRegistryServer: \"https://npm.example.com\"\n";
    let (_g, with_rc) = yarn_repo(yaml);
    let with = parse_manifest(&with_rc, &[("lodash", "^4"), ("@myorg/x", "^1")], &honor());
    let (_g2, without_root) = root();
    write(
        &without_root.join("yarn.lock"),
        "__metadata:\n  version: 8\n",
    );
    let without = parse_manifest(
        &without_root,
        &[("lodash", "^4"), ("@myorg/x", "^1")],
        &honor(),
    );
    for name in ["lodash", "@myorg/x"] {
        assert_eq!(label_of(&with, name), None, "{name}");
        assert_eq!(label_of(&without, name), None, "{name}");
    }
}

#[test]
fn missing_yarnrc_means_no_window() {
    assert_control_applies();
    let (_g, root) = root();
    write(&root.join("yarn.lock"), "");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn scope_window_applies_to_its_scope_only() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  myorg:\n    npmMinimalAgeGate: 3d\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(
        &root,
        &[("@myorg/x", "^1"), ("@other/y", "^1"), ("lodash", "^4")],
        &honor(),
    );
    assert_eq!(
        label_of(&result, "@myorg/x").as_deref(),
        Some("yarn npmScopes.myorg.npmMinimalAgeGate = 3 days")
    );
    assert_eq!(
        label_of(&result, "@other/y").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days"),
        "a scope without an entry falls through to the global value"
    );
    assert_eq!(
        label_of(&result, "lodash").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days"),
        "unscoped names never read npmScopes"
    );
}

#[test]
fn scope_zero_turns_the_window_off_over_a_global_value() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  myorg:\n    npmMinimalAgeGate: 0\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(&root, &[("@myorg/x", "^1"), ("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "@myorg/x"), None);
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn scope_only_configuration_gates_that_scope_without_a_global_value() {
    let yaml = "npmScopes:\n  myorg:\n    npmMinimalAgeGate: 3d\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(&root, &[("@myorg/x", "^1"), ("lodash", "^4")], &honor());
    assert_eq!(
        label_of(&result, "@myorg/x").as_deref(),
        Some("yarn npmScopes.myorg.npmMinimalAgeGate = 3 days")
    );
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn keyless_scope_in_a_declared_file_gets_yarns_one_day_default_never_the_global_value() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  a:\n    npmMinimalAgeGate: 3d\n  b:\n    npmRegistryServer: \"https://npm.example.com\"\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(&root, &[("@b/x", "^1")], &honor());
    let cooldown = cooldown_of(&result, "@b/x").expect("Yarn >= 4.17 default applies");
    assert_eq!(
        cooldown.to_string(),
        "yarn npmScopes.b.npmMinimalAgeGate = 1 day (Yarn default)"
    );
    assert_eq!(
        hold_at_age(&cooldown, "1.0.0", DAY / 2),
        Some(NativeHold::For(DAY as u64 / 2))
    );
    assert_eq!(hold_at_age(&cooldown, "1.0.0", DAY), None);
}

#[test]
fn keyless_scope_in_an_absent_file_falls_through_to_the_global_value() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  myorg:\n    npmRegistryServer: \"https://npm.example.com\"\n";
    assert_eq!(
        label(yaml, "@myorg/x").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days"),
        "Yarn 4.10-4.16: no per-scope key exists, so no per-scope default is assumed"
    );
}

#[test]
fn keyless_scope_in_an_absent_file_without_a_global_value_has_no_window() {
    let yaml = "npmScopes:\n  myorg:\n    npmRegistryServer: \"https://npm.example.com\"\n";
    assert_eq!(label(yaml, "@myorg/x"), None);
}

#[test]
fn malformed_scope_value_still_proves_a_declared_file_and_falls_through() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  a:\n    npmMinimalAgeGate: \"${X}\"\n  b:\n    npmRegistryServer: \"https://npm.example.com\"\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(&root, &[("@a/x", "^1"), ("@b/x", "^1")], &honor());
    assert_eq!(
        label_of(&result, "@a/x").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days"),
        "the malformed per-scope value is dropped; the explicit global window applies"
    );
    assert_eq!(
        label_of(&result, "@b/x").as_deref(),
        Some("yarn npmScopes.b.npmMinimalAgeGate = 1 day (Yarn default)"),
        "the key name alone proves Yarn >= 4.17 for the key-less scope"
    );
}

#[test]
fn malformed_scope_value_without_a_global_value_never_invents_a_window() {
    let yaml = "npmScopes:\n  a:\n    npmMinimalAgeGate: -1d\n";
    assert_eq!(label(yaml, "@a/x"), None);
}

#[test]
fn non_mapping_scope_entry_is_ignored() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmScopes:\n  myorg: oops\n";
    assert_eq!(
        label(yaml, "@myorg/x").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days")
    );
}

#[test]
fn preapproved_packages_are_exempt_by_name_and_glob() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmPreapprovedPackages:\n  - lodash\n  - \"@babel/*\"\n";
    let (_g, root) = yarn_repo(yaml);
    let result = parse_manifest(
        &root,
        &[("lodash", "^4"), ("@babel/core", "^7"), ("express", "^4")],
        &honor(),
    );
    assert_eq!(label_of(&result, "lodash"), None);
    assert_eq!(label_of(&result, "@babel/core"), None);
    assert!(label_of(&result, "express").is_some());
}

#[test]
fn preapproved_list_with_a_range_entry_is_rejected_and_the_window_holds_every_package() {
    let yaml = "npmMinimalAgeGate: 7d\nnpmPreapprovedPackages:\n  - \"lodash@^4\"\n";
    assert_eq!(
        label(yaml, "lodash").as_deref(),
        Some("yarn npmMinimalAgeGate = 7 days")
    );
}

#[test]
fn ignore_mode_resolves_no_window() {
    use deps_core::policy_config::NativeCooldownMode;
    assert_control_applies();
    let (_g, root) = yarn_repo("npmMinimalAgeGate: 7d\n");
    let result = parse_manifest(
        &root,
        &[("lodash", "^4")],
        &common::ctx(NativeCooldownMode::Ignore),
    );
    assert_eq!(label_of(&result, "lodash"), None);
}

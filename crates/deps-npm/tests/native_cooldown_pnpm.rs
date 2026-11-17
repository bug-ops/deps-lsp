//! #2041 / spec 099 acceptance: pnpm's `minimumReleaseAge` (integer minutes), its strict switch
//! and `minimumReleaseAgeExclude`, read from `pnpm-workspace.yaml` (FR-001, FR-014, FR-017);
//! the open-buffer read and `catalog:` dependencies (plan `20-24-32-architect` D4).
//!
//! Written tests-first; fixtures live in `tests/common/mod.rs`.

use std::assert_matches;
mod common;

use common::{
    DAY, cooldown_of, ctx, hold_at_age, honor, label_of, parse_manifest, parse_workspace_buffer,
    root, write,
};
use deps_core::native_cooldown::{NativeHold, NativeLimit};
use deps_core::policy_config::NativeCooldownMode;

const ONE_DAY_IN_MINUTES: &str = "minimumReleaseAge: 1440\n";

fn pnpm_repo(workspace_yaml: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = root();
    write(&root.join("pnpm-workspace.yaml"), workspace_yaml);
    write(&root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    (guard, root)
}

fn assert_control_applies() {
    let (_g, root) = pnpm_repo(ONE_DAY_IN_MINUTES);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(
        label_of(&result, "lodash").is_some(),
        "control: a valid window must resolve"
    );
}

#[test]
fn minimum_release_age_is_read_in_minutes() {
    let (_g, root) = pnpm_repo(ONE_DAY_IN_MINUTES);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
    let label = cooldown.to_string();
    assert!(
        label.contains("minimumReleaseAge") && label.contains("1440 minutes"),
        "{label}"
    );
    assert_eq!(
        hold_at_age(&cooldown, "4.17.21", 3600),
        Some(NativeHold::For(DAY as u64 - 3600))
    );
    assert_eq!(hold_at_age(&cooldown, "4.17.21", DAY), None);
}

#[test]
fn no_declared_value_means_no_window_pnpms_builtin_default_is_never_assumed() {
    assert_control_applies();
    let (_g, root) = pnpm_repo("packages:\n  - 'packages/*'\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn minimum_release_age_zero_disables_the_window() {
    assert_control_applies();
    let (_g, root) = pnpm_repo("minimumReleaseAge: 0\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn explicit_strict_false_means_no_window() {
    assert_control_applies();
    let (_g, root) = pnpm_repo("minimumReleaseAge: 1440\nminimumReleaseAgeStrict: false\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn explicit_strict_true_keeps_the_window() {
    let (_g, root) = pnpm_repo("minimumReleaseAge: 1440\nminimumReleaseAgeStrict: true\n");
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn malformed_values_are_ignored() {
    assert_control_applies();
    for yaml in [
        "minimumReleaseAge: soon\n",
        "minimumReleaseAge: -5\n",
        "minimumReleaseAge: 1.5\n",
        "minimumReleaseAge: [1440]\n",
    ] {
        let (_g, root) = pnpm_repo(yaml);
        let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
        assert_eq!(label_of(&result, "lodash"), None, "{yaml:?}");
    }
}

#[test]
fn exclude_by_name_and_glob() {
    let (_g, root) = pnpm_repo(
        "minimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - lodash\n  - '@babel/*'\n",
    );
    let result = parse_manifest(
        &root,
        &[
            ("lodash", "^4"),
            ("@babel/core", "^7"),
            ("express", "^4"),
            ("@types/node", "^20"),
        ],
        &honor(),
    );
    assert_eq!(label_of(&result, "lodash"), None);
    assert_eq!(label_of(&result, "@babel/core"), None);
    assert!(label_of(&result, "express").is_some());
    assert!(label_of(&result, "@types/node").is_some());
}

#[test]
fn exclude_star_matches_any_character_including_the_scope_separator() {
    let (_g, root) = pnpm_repo("minimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - '*'\n");
    let result = parse_manifest(&root, &[("lodash", "^4"), ("@types/node", "^20")], &honor());
    assert_eq!(label_of(&result, "lodash"), None);
    assert_eq!(label_of(&result, "@types/node"), None);
}

#[test]
fn exclude_name_at_versions_keeps_the_window_for_other_versions() {
    let (_g, root) = pnpm_repo(
        "minimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - 'lodash@4.17.21 || 4.17.20'\n",
    );
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window stays for other versions");
    assert_eq!(hold_at_age(&cooldown, "4.17.21", 3600), None);
    assert_eq!(hold_at_age(&cooldown, "4.17.20", 3600), None);
    assert!(hold_at_age(&cooldown, "4.17.22", 3600).is_some());
}

#[test]
fn pnpm_project_without_a_lock_file_is_recognised_by_its_workspace_file() {
    let (_g, root) = root();
    write(&root.join("pnpm-workspace.yaml"), ONE_DAY_IN_MINUTES);
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn ignore_mode_resolves_no_window() {
    assert_control_applies();
    let (_g, root) = pnpm_repo(ONE_DAY_IN_MINUTES);
    let result = parse_manifest(&root, &[("lodash", "^4")], &ctx(NativeCooldownMode::Ignore));
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn catalog_dependency_in_package_json_is_gated_by_its_real_name() {
    let (_g, root) = pnpm_repo(
        "minimumReleaseAge: 1440\ncatalog:\n  react: ^18.0.0\nminimumReleaseAgeExclude:\n  - express\n",
    );
    let result = parse_manifest(&root, &[("react", "catalog:"), ("express", "^4")], &honor());
    assert!(
        label_of(&result, "react").is_some(),
        "catalog: deps are registry deps"
    );
    assert_eq!(label_of(&result, "express"), None);
}

#[test]
fn open_workspace_buffer_reads_the_window_from_the_buffer_not_the_disk() {
    let (_g, root) = pnpm_repo("packages:\n  - 'packages/*'\n");
    let buffer = "minimumReleaseAge: 1440\ncatalog:\n  react: ^18.0.0\n";
    let result = parse_workspace_buffer(&root, buffer, &honor());
    let cooldown = cooldown_of(&result, "react").expect("catalog entry gated from the buffer");
    assert!(cooldown.to_string().contains("1440 minutes"));
}

#[test]
fn open_workspace_buffer_edit_removing_the_window_drops_it_without_saving() {
    let (_g, root) = pnpm_repo(ONE_DAY_IN_MINUTES);
    let buffer = "catalog:\n  react: ^18.0.0\n";
    let result = parse_workspace_buffer(&root, buffer, &honor());
    assert_eq!(label_of(&result, "react"), None);
}

#[test]
fn open_workspace_buffer_applies_its_own_exclude_list() {
    let (_g, root) = pnpm_repo("");
    let buffer = "minimumReleaseAge: 1440\nminimumReleaseAgeExclude:\n  - react\ncatalog:\n  react: ^18.0.0\n  vue: ^3.0.0\n";
    let result = parse_workspace_buffer(&root, buffer, &honor());
    assert_eq!(label_of(&result, "react"), None);
    assert!(label_of(&result, "vue").is_some());
}

#[test]
fn window_defect_does_not_drop_catalog_entries_and_catalog_defect_does_not_drop_the_window() {
    let (_g, root) = root();
    write(&root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    let bad_window = "minimumReleaseAge: soon\ncatalog:\n  react: ^18.0.0\n";
    let result = parse_workspace_buffer(&root, bad_window, &honor());
    assert!(
        result
            .dependencies
            .iter()
            .any(|d| d.name.as_str() == "react"),
        "catalog entries survive a malformed window"
    );
    write(
        &root.join("pnpm-workspace.yaml"),
        "minimumReleaseAge: 1440\ncatalog: 5\n",
    );
    let manifest = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(
        label_of(&manifest, "lodash").is_some(),
        "window survives a catalog defect"
    );
}

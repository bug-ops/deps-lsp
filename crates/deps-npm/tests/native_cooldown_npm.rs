//! #2041 / spec 099 acceptance: npm's own release-age settings (`min-release-age` in days,
//! `before`, `min-release-age-exclude`) read from the repository root `.npmrc` (FR-001, FR-004,
//! FR-007, FR-013, FR-014, FR-017), plus the package-manager ladder that decides whose config
//! applies.
//!
//! Written tests-first against plans `2026-11-17T18-35-26-architect`, `20-24-32-architect`
//! (D5) and `20-32-28-architect`. Fixtures live in `tests/common/mod.rs`.

#![allow(clippy::expect_used)]
use std::assert_matches;

mod common;

use common::{
    DAY, NOW, cooldown_of, ctx, hold_at_age, honor, label_of, parse_manifest, root, write,
};
use deps_core::native_cooldown::{NativeHold, NativeLimit};
use deps_core::policy_config::NativeCooldownMode;
use deps_core::{ConcreteVersion, PublishTime};

const SEVEN_DAYS: &str = "min-release-age=7\n";

fn npm_repo(npmrc: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = root();
    write(&root.join(".npmrc"), npmrc);
    write(&root.join("package-lock.json"), "{}");
    (guard, root)
}

fn lodash_label(root: &std::path::Path) -> Option<String> {
    label_of(
        &parse_manifest(root, &[("lodash", "^4.0.0")], &honor()),
        "lodash",
    )
}

fn assert_control_applies() {
    let (_g, root) = npm_repo(SEVEN_DAYS);
    let label = lodash_label(&root).expect("control: a valid window must resolve");
    assert!(
        label.contains("min-release-age") && label.contains("7 days"),
        "{label}"
    );
}

#[test]
fn min_release_age_days_applies_to_registry_dependency() {
    let (_g, root) = npm_repo(SEVEN_DAYS);
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
    assert_eq!(
        hold_at_age(&cooldown, "4.17.21", DAY),
        Some(NativeHold::For(6 * DAY as u64))
    );
    assert_eq!(hold_at_age(&cooldown, "4.17.21", 8 * DAY), None);
}

#[test]
fn min_release_age_zero_disables_the_window() {
    assert_control_applies();
    let (_g, root) = npm_repo("min-release-age=0\n");
    assert_eq!(lodash_label(&root), None);
}

#[test]
fn min_release_age_fractional_is_ignored_as_malformed() {
    assert_control_applies();
    let (_g, root) = npm_repo("min-release-age=0.5\n");
    assert_eq!(lodash_label(&root), None);
}

#[test]
fn min_release_age_non_numeric_or_negative_is_ignored() {
    assert_control_applies();
    for raw in [
        "min-release-age=abc\n",
        "min-release-age=-3\n",
        "min-release-age=\n",
    ] {
        let (_g, root) = npm_repo(raw);
        assert_eq!(lodash_label(&root), None, "{raw:?}");
    }
}

#[test]
fn before_alone_pins_a_cutoff_and_holds_newer_versions_indefinitely() {
    let (_g, root) = npm_repo("before=2026-01-01T00:00:00Z\n");
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("before alone is a gate");
    assert_matches!(cooldown.limit(), NativeLimit::PublishedAfter(_));
    let label = cooldown.to_string();
    assert!(label.contains("before"), "{label}");
    let newer = PublishTime::from_unix_secs(1_767_225_600 + 1);
    let older = PublishTime::from_unix_secs(1_767_225_600 - 1);
    let now = PublishTime::from_unix_secs(NOW);
    let v = ConcreteVersion::new("4.17.21");
    assert_eq!(
        cooldown.hold(Some(newer), &v, now),
        Some(NativeHold::Indefinite)
    );
    assert_eq!(cooldown.hold(Some(older), &v, now), None);
}

#[test]
fn before_accepts_a_date_only_value_as_midnight_utc() {
    let (_g, root) = npm_repo("before=2026-01-01\n");
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("date-only before is valid for npm");
    let newer = PublishTime::from_unix_secs(1_767_225_600 + 1);
    assert_eq!(
        cooldown.hold(
            Some(newer),
            &ConcreteVersion::new("4.17.21"),
            PublishTime::from_unix_secs(NOW)
        ),
        Some(NativeHold::Indefinite)
    );
}

#[test]
fn before_wins_over_min_release_age_in_the_same_file() {
    let (_g, root) = npm_repo("min-release-age=7\nbefore=2026-01-01T00:00:00Z\n");
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window applies");
    assert_matches!(cooldown.limit(), NativeLimit::PublishedAfter(_));
}

#[test]
fn malformed_before_falls_back_to_min_release_age() {
    let (_g, root) = npm_repo("min-release-age=7\nbefore=not-a-date\n");
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("min-release-age still applies");
    assert_matches!(cooldown.limit(), NativeLimit::MinAge(_));
}

#[test]
fn exclude_by_name_removes_the_window_from_that_dependency_only() {
    let (_g, root) = npm_repo("min-release-age=7\nmin-release-age-exclude=lodash\n");
    let result = parse_manifest(
        &root,
        &[("lodash", "^4.0.0"), ("express", "^4.0.0")],
        &honor(),
    );
    assert_eq!(label_of(&result, "lodash"), None);
    assert!(label_of(&result, "express").is_some());
}

#[test]
fn exclude_array_form_is_read() {
    let (_g, root) = npm_repo(
        "min-release-age=7\nmin-release-age-exclude[]=lodash\nmin-release-age-exclude[]=express\n",
    );
    let result = parse_manifest(
        &root,
        &[("lodash", "^4"), ("express", "^4"), ("react", "^18")],
        &honor(),
    );
    assert_eq!(label_of(&result, "lodash"), None);
    assert_eq!(label_of(&result, "express"), None);
    assert!(label_of(&result, "react").is_some());
}

#[test]
fn exclude_scope_glob_matches_scoped_packages() {
    let (_g, root) = npm_repo("min-release-age=7\nmin-release-age-exclude=@types/*\n");
    let result = parse_manifest(
        &root,
        &[("@types/node", "^20"), ("@babel/core", "^7")],
        &honor(),
    );
    assert_eq!(label_of(&result, "@types/node"), None);
    assert!(label_of(&result, "@babel/core").is_some());
}

#[test]
fn exclude_bare_star_does_not_cross_the_scope_separator() {
    let (_g, root) = npm_repo("min-release-age=7\nmin-release-age-exclude=*\n");
    let result = parse_manifest(&root, &[("lodash", "^4"), ("@types/node", "^20")], &honor());
    assert_eq!(
        label_of(&result, "lodash"),
        None,
        "`*` matches an unscoped name"
    );
    assert!(
        label_of(&result, "@types/node").is_some(),
        "npm's `*` is segment-scoped and must not match `@types/node`"
    );
}

#[test]
fn exclude_name_at_version_keeps_the_window_but_exempts_that_version() {
    let (_g, root) = npm_repo("min-release-age=7\nmin-release-age-exclude=lodash@4.17.21\n");
    let result = parse_manifest(&root, &[("lodash", "^4.0.0")], &honor());
    let cooldown = cooldown_of(&result, "lodash").expect("window still applies to other versions");
    assert_eq!(hold_at_age(&cooldown, "4.17.21", DAY), None);
    assert_eq!(
        hold_at_age(&cooldown, "4.17.22", DAY),
        Some(NativeHold::For(6 * DAY as u64))
    );
}

#[test]
fn exclude_with_an_unsupported_entry_rejects_the_whole_list_so_the_window_holds_more() {
    let (_g, root) = npm_repo(
        "min-release-age=7\nmin-release-age-exclude=lodash\nmin-release-age-exclude=lod?sh\n",
    );
    let result = parse_manifest(&root, &[("lodash", "^4")], &honor());
    assert!(
        label_of(&result, "lodash").is_some(),
        "an unsupported entry must reject the list (conservative), not exempt lodash"
    );
}

#[test]
fn ignore_mode_resolves_no_window() {
    assert_control_applies();
    let (_g, root) = npm_repo(SEVEN_DAYS);
    let result = parse_manifest(
        &root,
        &[("lodash", "^4.0.0")],
        &ctx(NativeCooldownMode::Ignore),
    );
    assert_eq!(label_of(&result, "lodash"), None);
}

#[test]
fn no_config_file_means_no_window() {
    assert_control_applies();
    let (_g, root) = root();
    write(&root.join("package-lock.json"), "{}");
    assert_eq!(lodash_label(&root), None);
}

#[test]
fn only_the_root_npmrc_is_read_a_workspace_member_npmrc_is_ignored() {
    let (_g, root) = npm_repo(SEVEN_DAYS);
    let member = root.join("packages/app");
    write(&member.join(".npmrc"), "min-release-age=30\n");
    let result = parse_manifest(&member, &[("lodash", "^4.0.0")], &honor());
    let label = label_of(&result, "lodash").expect("root window applies to the member");
    assert!(label.contains("7 days"), "root value must win, got {label}");
}

#[test]
fn manifest_dir_is_the_root_when_no_lock_file_exists() {
    let (_g, root) = root();
    write(&root.join(".npmrc"), SEVEN_DAYS);
    assert!(lodash_label(&root).is_some());
}

#[test]
fn yarn_projects_have_no_window_even_with_an_npmrc_setting() {
    let (_g, root) = root();
    write(&root.join(".npmrc"), SEVEN_DAYS);
    write(&root.join("yarn.lock"), "");
    assert_eq!(lodash_label(&root), None);
}

#[test]
fn non_registry_dependencies_get_no_window() {
    let (_g, root) = npm_repo(SEVEN_DAYS);
    let result = parse_manifest(
        &root,
        &[
            ("from-git", "github:user/repo"),
            ("from-file", "file:../local"),
            ("from-url", "https://example.com/pkg.tgz"),
            ("lodash", "^4.0.0"),
        ],
        &honor(),
    );
    assert_eq!(label_of(&result, "from-git"), None);
    assert_eq!(label_of(&result, "from-file"), None);
    assert_eq!(label_of(&result, "from-url"), None);
    assert!(label_of(&result, "lodash").is_some());
}

#[test]
fn aliased_dependency_is_exempted_by_its_real_package_name() {
    let (_g, root) = npm_repo("min-release-age=7\nmin-release-age-exclude=real-pkg\n");
    let result = parse_manifest(
        &root,
        &[("my-alias", "npm:real-pkg@^1.0.0"), ("other", "^1.0.0")],
        &honor(),
    );
    assert_eq!(
        label_of(&result, "my-alias"),
        None,
        "exemption keys on the real name"
    );
    assert!(label_of(&result, "other").is_some());
}

#[test]
fn npmrc_native_keys_never_leak_into_the_pnpm_or_bun_gate() {
    let (_g, root) = root();
    write(&root.join(".npmrc"), SEVEN_DAYS);
    write(&root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    assert_eq!(
        lodash_label(&root),
        None,
        "pnpm reads pnpm-workspace.yaml, not .npmrc"
    );
    let (_g2, bun_root) = root_with_bun();
    assert_eq!(
        lodash_label(&bun_root),
        None,
        "Bun reads bunfig.toml, not .npmrc"
    );
}

fn root_with_bun() -> (tempfile::TempDir, std::path::PathBuf) {
    let (guard, root) = root();
    write(&root.join(".npmrc"), SEVEN_DAYS);
    write(&root.join("bun.lock"), "");
    (guard, root)
}

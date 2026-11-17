//! #2041 / spec 099 FR-010 regression: the npm-family project root must lie inside the
//! repository. A lock file or settings file of the user's home directory, or of anything above
//! it, never becomes the project's config (impl-critic C2).
//!
//! Needs `NpmParseContext::with_user_home_for_test` (the `test-util` feature, enabled by
//! `--all-features`).

#![cfg(feature = "test-util")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{honor, label_of, parse_manifest, root, write};
use deps_core::UserHome;

const THIRTY_DAYS: &str = "min-release-age=30\n";

fn with_home(home: &std::path::Path) -> deps_npm::config::NpmParseContext {
    honor().with_user_home_for_test(UserHome::new(home.to_path_buf()))
}

fn lodash(dir: &std::path::Path, ctx: &deps_npm::config::NpmParseContext) -> Option<String> {
    label_of(&parse_manifest(dir, &[("lodash", "^4.0.0")], ctx), "lodash")
}

#[test]
fn a_stray_lock_in_the_home_directory_does_not_make_its_npmrc_the_project_config() {
    let (_g, home) = root();
    write(&home.join("package-lock.json"), "{}");
    write(&home.join(".npmrc"), THIRTY_DAYS);
    let project = home.join("Dev/app");
    assert_eq!(lodash(&project, &with_home(&home)), None);
}

#[test]
fn a_lock_above_the_home_directory_never_makes_a_project_root() {
    let (_g, outer) = root();
    write(&outer.join("package-lock.json"), "{}");
    write(&outer.join(".npmrc"), THIRTY_DAYS);
    let home = outer.join("user");
    let project = home.join("app");
    assert_eq!(lodash(&project, &with_home(&home)), None);
}

#[test]
fn a_project_inside_the_home_directory_still_reads_its_own_root_files() {
    let (_g, home) = root();
    let project = home.join("Dev/app");
    write(&project.join("package-lock.json"), "{}");
    write(&project.join(".npmrc"), THIRTY_DAYS);
    let label = lodash(&project, &with_home(&home)).expect("project root applies");
    assert!(label.contains("30 days"), "{label}");
}

#[test]
fn a_lockless_manifest_directly_in_the_home_directory_reads_nothing() {
    let (_g, home) = root();
    write(&home.join(".npmrc"), THIRTY_DAYS);
    assert_eq!(lodash(&home, &with_home(&home)), None);
}

#[test]
fn a_project_in_the_home_directory_keeps_its_own_npmrc_when_only_a_stray_lock_is_above_it() {
    let (_g, home) = root();
    write(&home.join("package-lock.json"), "{}");
    let project = home.join("proj");
    write(&project.join(".npmrc"), THIRTY_DAYS);
    let label = lodash(&project, &with_home(&home)).expect("falls back to the manifest directory");
    assert!(label.contains("30 days"), "{label}");
}

#[test]
fn without_a_known_home_an_in_repository_root_applies() {
    let (_g, project) = root();
    write(&project.join("package-lock.json"), "{}");
    write(&project.join(".npmrc"), THIRTY_DAYS);
    assert!(lodash(&project, &honor()).is_some());
}

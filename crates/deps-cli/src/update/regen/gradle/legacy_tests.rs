//! #2102 acceptance (unit level): the lock-set walk of the legacy `gradle/dependency-locks`
//! layout and the validated lock-state newtypes.
//!
//! Written tests-first against the final plan. Declared in `gradle.rs` as
//! `#[cfg(test)] mod legacy_tests;`. Assumes `LockSet { unified: Vec<PathBuf>, legacy:
//! Vec<LegacyProject { dir, files: Vec<PathBuf> }> }` and `pub(super) fn new(&str) -> Option<Self>`
//! on both newtypes (the plan names the constructor's shape, not its name).

#![allow(clippy::panic)]

use std::assert_matches;
use std::path::{Path, PathBuf};

use super::lock_state::{LockConfiguration, LockedCoordinate};
use super::{LockSetError, MAX_LOCK_FILES, lock_set};
use crate::update::regen::{LegacyLayoutConflict, UnsupportedReason};

fn touch(root: &Path, rel: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, b"").expect("write");
}

fn names(root: &Path, files: &[PathBuf]) -> Vec<String> {
    files
        .iter()
        .map(|path| {
            path.strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

#[test]
fn lock_set_collects_the_legacy_files_of_every_project() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    for rel in [
        "gradle/dependency-locks/compileClasspath.lockfile",
        "gradle/dependency-locks/runtimeClasspath.lockfile",
        "app/gradle/dependency-locks/compileClasspath.lockfile",
    ] {
        touch(root, rel);
    }

    let set = lock_set(root).expect("lock set");

    assert!(set.unified.is_empty());
    assert_eq!(set.legacy.len(), 2);
    let mut files: Vec<String> = set
        .legacy
        .iter()
        .flat_map(|project| names(root, &project.files))
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "app/gradle/dependency-locks/compileClasspath.lockfile",
            "gradle/dependency-locks/compileClasspath.lockfile",
            "gradle/dependency-locks/runtimeClasspath.lockfile"
        ]
    );
}

#[test]
fn lock_set_counts_a_legacy_directory_only_when_it_holds_a_lockfile() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    touch(root, "gradle.lockfile");
    std::fs::create_dir_all(root.join("gradle/dependency-locks")).expect("empty dir");
    touch(root, "app/gradle/dependency-locks/README.txt");

    let set = lock_set(root).expect("an empty or lock-less directory is not a layout");

    assert!(set.legacy.is_empty());
    assert_eq!(names(root, &set.unified), ["gradle.lockfile"]);
}

#[test]
fn lock_set_refuses_a_legacy_directory_beside_a_unified_lock_of_the_same_project() {
    let dir = tempfile::tempdir().expect("dir");
    touch(dir.path(), "gradle.lockfile");
    touch(
        dir.path(),
        "gradle/dependency-locks/compileClasspath.lockfile",
    );

    let root = dir.path();
    let Err(LockSetError::Conflict { conflict, path }) = lock_set(root) else {
        panic!("a legacy directory beside a unified lock must conflict");
    };
    assert_eq!(conflict, LegacyLayoutConflict::BesideUnifiedLock);
    assert_eq!(
        names(root, &[path]),
        ["gradle/dependency-locks/compileClasspath.lockfile"]
    );
}

#[test]
fn lock_set_conflict_path_is_the_first_legacy_file_of_the_conflicting_project() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    touch(root, "gradle/dependency-locks/aaa.lockfile");
    touch(root, "lib/gradle.lockfile");
    touch(root, "lib/gradle/dependency-locks/zzz.lockfile");
    touch(root, "lib/gradle/dependency-locks/bbb.lockfile");

    let Err(LockSetError::Conflict { conflict, path }) = lock_set(root) else {
        panic!("the lib project must conflict");
    };

    assert_eq!(conflict, LegacyLayoutConflict::BesideUnifiedLock);
    assert_eq!(
        names(root, &[path]),
        ["lib/gradle/dependency-locks/bbb.lockfile"]
    );
}

#[test]
fn lock_set_allows_a_unified_lock_in_one_project_and_a_legacy_layout_in_another() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    touch(root, "gradle.lockfile");
    touch(
        root,
        "app/gradle/dependency-locks/compileClasspath.lockfile",
    );

    let set = lock_set(root).expect("different projects do not conflict");

    assert_eq!(names(root, &set.unified), ["gradle.lockfile"]);
    assert_eq!(set.legacy.len(), 1);
}

#[test]
fn lock_set_refuses_a_settings_lock_in_the_legacy_directory() {
    let dir = tempfile::tempdir().expect("dir");
    touch(
        dir.path(),
        "gradle/dependency-locks/compileClasspath.lockfile",
    );
    touch(
        dir.path(),
        "gradle/dependency-locks/settings-classpath.lockfile",
    );

    let root = dir.path();
    let Err(LockSetError::Conflict { conflict, path }) = lock_set(root) else {
        panic!("a settings lock must conflict");
    };
    assert_eq!(conflict, LegacyLayoutConflict::SettingsLock);
    assert_eq!(
        names(root, &[path]),
        ["gradle/dependency-locks/settings-classpath.lockfile"]
    );
}

#[test]
fn lock_set_ignores_a_legacy_directory_under_build_or_a_hidden_directory() {
    let dir = tempfile::tempdir().expect("dir");
    touch(
        dir.path(),
        "build/gradle/dependency-locks/compileClasspath.lockfile",
    );
    touch(
        dir.path(),
        ".hidden/gradle/dependency-locks/compileClasspath.lockfile",
    );

    let set = lock_set(dir.path()).expect("lock set");

    assert!(set.legacy.is_empty() && set.unified.is_empty());
}

#[test]
fn lock_set_counts_legacy_files_toward_the_file_cap() {
    let dir = tempfile::tempdir().expect("dir");
    for index in 0..=MAX_LOCK_FILES {
        touch(
            dir.path(),
            &format!("gradle/dependency-locks/c{index}.lockfile"),
        );
    }

    assert_matches!(
        lock_set(dir.path()),
        Err(LockSetError::Refused(
            UnsupportedReason::LockfileSetTooLarge
        ))
    );
}

#[test]
fn lock_configuration_accepts_names_and_rejects_separators_whitespace_and_empty() {
    for valid in ["compileClasspath", "buildscript-classpath", "a.b_c-1"] {
        let configuration = LockConfiguration::new(valid).expect(valid);
        assert_eq!(configuration.as_str(), valid);
        assert_eq!(configuration.to_string(), valid);
    }
    for invalid in ["", "a,b", "a=b", "a b", "a\tb", "a\nb"] {
        assert!(LockConfiguration::new(invalid).is_none(), "{invalid:?}");
    }
}

#[test]
fn locked_coordinate_needs_three_non_empty_parts() {
    let coordinate = LockedCoordinate::new("com.google.guava:guava:32.1.2-jre").expect("valid");
    assert_eq!(coordinate.as_str(), "com.google.guava:guava:32.1.2-jre");
    assert_eq!(coordinate.to_string(), "com.google.guava:guava:32.1.2-jre");
    for invalid in ["", "g", "g:a", "g:a:", ":a:v", "g::v"] {
        assert!(LockedCoordinate::new(invalid).is_none(), "{invalid:?}");
    }
}

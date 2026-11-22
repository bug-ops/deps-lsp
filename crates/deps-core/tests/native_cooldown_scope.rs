//! #2041 / spec 099 FR-010 acceptance: the repository-level config directory scope shared by
//! the Cargo and npm-family readers (manifest dir up to the repository root inclusive, never
//! the user's home directory, bounded depth).
//!
//! Written tests-first against plan `2026-11-17T18-35-26-architect` (Contracts, `RepositoryScope`).
//! Assumed seam: `RepositoryScope::new(&Path, &Path, Option<&Path>)` and
//! `config_dirs()` yielding paths closest-first, in `deps_core::native_cooldown`.

#![expect(clippy::unwrap_used, reason = "test code")]

use std::path::{Path, PathBuf};

use deps_core::native_cooldown::RepositoryScope;

fn dirs(manifest: &Path, root: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    RepositoryScope::new(manifest, root, home).config_dirs()
}

fn tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

#[test]
fn config_dirs_walks_from_manifest_dir_up_to_root_inclusive_closest_first() {
    let (_g, root) = tree();
    let manifest = root.join("packages/app");
    std::fs::create_dir_all(&manifest).unwrap();
    assert_eq!(
        dirs(&manifest, &root, None),
        [manifest.clone(), root.join("packages"), root.clone()]
    );
}

#[test]
fn config_dirs_manifest_at_root_is_just_the_root() {
    let (_g, root) = tree();
    assert_eq!(dirs(&root, &root, None), std::slice::from_ref(&root));
}

#[test]
fn config_dirs_never_includes_the_home_directory() {
    let (_g, root) = tree();
    let manifest = root.join("proj");
    std::fs::create_dir_all(&manifest).unwrap();
    let got = dirs(&manifest, &root, Some(&root));
    assert!(!got.contains(&root), "home must be excluded, got {got:?}");
    assert!(got.contains(&manifest));
}

#[test]
fn config_dirs_never_climbs_above_the_root() {
    let (_g, root) = tree();
    let nested = root.join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    let parent = root.parent().unwrap().to_path_buf();
    assert!(!dirs(&nested, &root, None).contains(&parent));
}

#[test]
fn config_dirs_root_that_is_not_an_ancestor_of_the_manifest_reads_nothing_above_it() {
    let (_g, root) = tree();
    let other = tempfile::tempdir().unwrap();
    let elsewhere = other.path().canonicalize().unwrap();
    let got = dirs(&elsewhere, &root, None);
    assert!(
        !got.contains(&root),
        "an unrelated root must not become a config dir, got {got:?}"
    );
}

#[test]
fn config_dirs_depth_is_bounded() {
    let (_g, root) = tree();
    let mut nested = root.clone();
    for i in 0..200 {
        nested.push(format!("d{i}"));
    }
    let got = dirs(&nested, &root, None);
    assert!(
        got.len() <= 64,
        "walk must be bounded by MAX_CONFIG_ANCESTOR_DEPTH, got {}",
        got.len()
    );
}

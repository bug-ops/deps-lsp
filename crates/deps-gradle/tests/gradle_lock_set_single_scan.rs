//! #2054 acceptance (track C): Gradle's legacy `gradle/dependency-locks` layout is listed once per
//! load. `parse_lock_set` reads exactly the companions it is given (no second scan),
//! `companion_listing_dir` names the directory behind the listing, and the listing itself stats
//! only symlinks.
//!
//! Written tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`);
//! `parse_lock_set` and `companion_listing_dir` do not exist yet.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use deps_core::lockfile::LockFileProvider;
use deps_gradle::GradleLockParser;
use url::Url;

const SLF4J: &str = "org.slf4j:slf4j-api:2.0.9\nempty=\n";
const GUAVA: &str = "com.google.guava:guava:32.1.2-jre\nempty=\n";
const LATE: &str = "org.example:late:1.0.0\nempty=\n";

fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

fn locks_dir(project: &Path) -> PathBuf {
    project.join("gradle/dependency-locks")
}

fn write_lock(project: &Path, file: &str, content: &str) -> PathBuf {
    let dir = locks_dir(project);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(file);
    std::fs::write(&path, content).unwrap();
    path
}

fn manifest_uri(project: &Path) -> Url {
    Url::from_file_path(project.join("build.gradle.kts")).unwrap()
}

#[test]
fn companion_listing_dir_of_a_legacy_file_is_its_directory() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", SLF4J);
    write_lock(&p, "runtimeClasspath.lockfile", GUAVA);

    let dir = GradleLockParser.companion_listing_dir(&located);

    assert_eq!(dir.as_deref(), Some(locks_dir(&p).as_path()));
    assert!(
        GradleLockParser
            .companion_lockfiles(&located)
            .contains(&dir.unwrap()),
        "the listing directory is also one of the companions"
    );
}

#[test]
fn companion_listing_dir_of_a_unified_file_is_none() {
    let (_g, p) = project();
    let unified = p.join("gradle.lockfile");
    std::fs::write(&unified, "org.example:unified:1.0.0=runtimeClasspath\n").unwrap();
    assert_eq!(GradleLockParser.companion_listing_dir(&unified), None);
}

#[tokio::test]
async fn parse_lock_set_legacy_equals_parse_lockfile_on_an_unchanged_tree() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", SLF4J);
    write_lock(&p, "runtimeClasspath.lockfile", GUAVA);
    let companions = GradleLockParser.companion_lockfiles(&located);

    let set = GradleLockParser
        .parse_lock_set(&located, &companions)
        .await
        .unwrap();
    let single = GradleLockParser.parse_lockfile(&located).await.unwrap();

    for name in ["org.slf4j:slf4j-api", "com.google.guava:guava"] {
        assert_eq!(
            set.all(name).is_some(),
            single.all(name).is_some(),
            "{name}"
        );
        assert!(set.all(name).is_some(), "{name} is in the merged set");
    }
}

#[tokio::test]
async fn parse_lock_set_legacy_reads_only_the_given_companions_without_rescanning() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", SLF4J);
    write_lock(&p, "runtimeClasspath.lockfile", GUAVA);
    let companions = GradleLockParser.companion_lockfiles(&located);
    write_lock(&p, "zzzClasspath.lockfile", LATE);

    let set = GradleLockParser
        .parse_lock_set(&located, &companions)
        .await
        .unwrap();

    assert!(set.all("com.google.guava:guava").is_some());
    assert!(
        set.all("org.example:late").is_none(),
        "a file created after the listing is not discovered by a second scan"
    );
    let fresh = GradleLockParser.parse_lockfile(&located).await.unwrap();
    assert!(
        fresh.all("org.example:late").is_some(),
        "parse_lockfile lists afresh"
    );
}

#[tokio::test]
async fn parse_lock_set_legacy_drops_companions_that_vanished_since_the_listing() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", SLF4J);
    let gone = write_lock(&p, "runtimeClasspath.lockfile", GUAVA);
    let companions = GradleLockParser.companion_lockfiles(&located);
    std::fs::remove_file(&gone).unwrap();

    let set = GradleLockParser
        .parse_lock_set(&located, &companions)
        .await
        .unwrap();

    assert!(set.all("org.slf4j:slf4j-api").is_some());
    assert!(set.all("com.google.guava:guava").is_none());
}

#[tokio::test]
async fn parse_lock_set_legacy_tolerates_the_directory_entry_in_the_companion_list() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", SLF4J);
    let dir = locks_dir(&p);

    let set = GradleLockParser
        .parse_lock_set(&located, std::slice::from_ref(&dir))
        .await
        .unwrap();

    assert!(set.all("org.slf4j:slf4j-api").is_some());
}

#[tokio::test]
async fn parse_lock_set_unified_merges_the_given_buildscript_companion_only() {
    let (_g, p) = project();
    let located = p.join("gradle.lockfile");
    std::fs::write(&located, "org.example:app:1.0.0=runtimeClasspath\n").unwrap();
    let buildscript = p.join("buildscript-gradle.lockfile");
    std::fs::write(&buildscript, "org.example:agp:8.0.0=classpath\n").unwrap();

    let with = GradleLockParser
        .parse_lock_set(&located, std::slice::from_ref(&buildscript))
        .await
        .unwrap();
    let without = GradleLockParser
        .parse_lock_set(&located, &[])
        .await
        .unwrap();

    assert!(with.all("org.example:app").is_some());
    assert!(with.all("org.example:agp").is_some());
    assert!(without.all("org.example:app").is_some());
    assert!(
        without.all("org.example:agp").is_none(),
        "the unified layout reads the companions it is handed, not its own listing"
    );
}

#[test]
fn locate_picks_the_name_first_eligible_entry_skipping_directories_and_settings_files() {
    let (_g, p) = project();
    let dir = locks_dir(&p);
    std::fs::create_dir_all(dir.join("a.lockfile")).unwrap();
    write_lock(&p, "settings-x.lockfile", SLF4J);
    let expected = write_lock(&p, "b.lockfile", GUAVA);
    write_lock(&p, "c.lockfile", GUAVA);

    let found = GradleLockParser.locate_lockfile(&manifest_uri(&p)).unwrap();

    assert_eq!(
        std::fs::canonicalize(found).unwrap(),
        std::fs::canonicalize(expected).unwrap()
    );
}

#[test]
fn directory_named_like_a_lock_file_is_never_a_companion() {
    let (_g, p) = project();
    let located = write_lock(&p, "b.lockfile", SLF4J);
    std::fs::create_dir_all(locks_dir(&p).join("d.lockfile")).unwrap();

    let companions = GradleLockParser.companion_lockfiles(&located);

    assert_eq!(companions, vec![locks_dir(&p)], "only the directory itself");
}

#[cfg(unix)]
#[test]
fn symlinked_lock_files_are_companions_only_when_they_resolve_to_a_regular_file() {
    let (_g, p) = project();
    let located = write_lock(&p, "a.lockfile", SLF4J);
    let dir = locks_dir(&p);
    let target_file = p.join("real.txt");
    std::fs::write(&target_file, GUAVA).unwrap();
    std::os::unix::fs::symlink(&target_file, dir.join("b.lockfile")).unwrap();
    let target_dir = p.join("realdir");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::os::unix::fs::symlink(&target_dir, dir.join("c.lockfile")).unwrap();

    let companions = GradleLockParser.companion_lockfiles(&located);

    assert!(
        companions.contains(&dir.join("b.lockfile")),
        "{companions:?}"
    );
    assert!(
        !companions.contains(&dir.join("c.lockfile")),
        "{companions:?}"
    );
}

#[test]
fn listing_a_64_file_legacy_directory_stats_only_symlinks() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_g, p) = project();
    let located = write_lock(&p, "f00.lockfile", SLF4J);
    for n in 1..64 {
        write_lock(&p, &format!("f{n:02}.lockfile"), SLF4J);
    }

    let (stats_before, _) = deps_core::fs_probe::snapshot();
    let companions = GradleLockParser.companion_lockfiles(&located);
    let (stats_after, _) = deps_core::fs_probe::snapshot();

    assert_eq!(companions.len(), 64, "directory plus 63 other files");
    assert!(
        stats_after - stats_before <= 4,
        "plain files are classified by DirEntry::file_type, not stat'd one by one: {} stats",
        stats_after - stats_before
    );
}

#[test]
fn locating_in_a_64_file_legacy_directory_stats_only_symlinks() {
    let _guard = deps_core::fs_probe::snapshot_guard();
    let (_g, p) = project();
    for n in 0..64 {
        write_lock(&p, &format!("f{n:02}.lockfile"), SLF4J);
    }
    let uri = manifest_uri(&p);

    let (stats_before, _) = deps_core::fs_probe::snapshot();
    let found = GradleLockParser.locate_lockfile(&uri);
    let (stats_after, _) = deps_core::fs_probe::snapshot();

    assert!(found.is_some());
    assert!(
        stats_after - stats_before <= 8,
        "{} stats",
        stats_after - stats_before
    );
}

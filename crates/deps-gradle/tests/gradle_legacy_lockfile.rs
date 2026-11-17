//! #2039 / spec 092 FR-003 acceptance: the legacy `gradle/dependency-locks/<configuration>.lockfile`
//! layout supplies in-use versions, but only when neither `gradle.lockfile` nor
//! `buildscript-gradle.lockfile` exists (plan `18-35-26-architect` Track 2, `20-24-32-architect`
//! D3).
//!
//! Written tests-first. Assumed seam: `LockFileProvider::lock_set_root(&Path) -> Option<&Path>`
//! (default `path.parent()`; Gradle legacy files return the project directory).

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use deps_core::lockfile::{LockFileCache, LockFileProvider};
use deps_core::lsp_helpers::{NormalizeName, PackageNaming};
use deps_core::{LockScope, PackageName};
use deps_gradle::GradleLockParser;
use url::Url;

struct Plain;

impl PackageNaming for Plain {}

const COMPILE_LOCK: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.slf4j:slf4j-api:2.0.9
com.google.guava:guava:32.1.2-jre
empty=
";

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

fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

/// Compares after canonicalization: on Windows `locate_lockfile` yields a non-verbatim path while
/// the tempdir path is verbatim (`\\?\C:\...`).
fn assert_located(manifest: &Url, expected: &Path) {
    let found = GradleLockParser.locate_lockfile(manifest).unwrap();
    assert_eq!(
        std::fs::canonicalize(found).unwrap(),
        std::fs::canonicalize(expected).unwrap()
    );
}

/// Sets a directory's mtime; Windows needs write-attributes access and backup semantics to open one.
fn set_dir_modified(dir: &Path, time: SystemTime) {
    #[cfg(windows)]
    let handle = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(0x100)
            .custom_flags(0x0200_0000)
            .open(dir)
            .unwrap()
    };
    #[cfg(not(windows))]
    let handle = std::fs::File::open(dir).unwrap();
    handle.set_modified(time).unwrap();
}

fn key(name: &str) -> deps_core::NormalizedName {
    Plain.normalize_package_name(&PackageName::new(name))
}

#[test]
fn locate_legacy_returns_the_first_name_sorted_lockfile() {
    let (_g, p) = project();
    write_lock(&p, "runtimeClasspath.lockfile", COMPILE_LOCK);
    let first = write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    assert_located(&manifest_uri(&p), &first);
}

#[test]
fn locate_without_any_lock_files_is_none() {
    let (_g, p) = project();
    std::fs::create_dir_all(locks_dir(&p)).unwrap();
    assert_eq!(GradleLockParser.locate_lockfile(&manifest_uri(&p)), None);
    let (_g2, bare) = project();
    assert_eq!(GradleLockParser.locate_lockfile(&manifest_uri(&bare)), None);
}

#[test]
fn locate_ignores_non_lockfile_entries_in_the_directory() {
    let (_g, p) = project();
    write_lock(&p, "README.md", "notes");
    write_lock(&p, "compileClasspath.lock", COMPILE_LOCK);
    std::fs::create_dir(locks_dir(&p).join("a.lockfile")).unwrap();
    assert_eq!(GradleLockParser.locate_lockfile(&manifest_uri(&p)), None);
}

#[test]
fn unified_lockfile_wins_and_legacy_is_never_read() {
    let (_g, p) = project();
    let unified = p.join("gradle.lockfile");
    std::fs::write(&unified, "org.example:unified:1.0.0=runtimeClasspath\n").unwrap();
    write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    assert_located(&manifest_uri(&p), &unified);
}

#[tokio::test]
async fn unified_lockfile_present_means_legacy_entries_never_surface() {
    let (_g, p) = project();
    let unified = p.join("gradle.lockfile");
    std::fs::write(&unified, "org.example:unified:1.0.0=runtimeClasspath\n").unwrap();
    write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    let packages = GradleLockParser.parse_lockfile(&unified).await.unwrap();
    assert!(packages.all("org.slf4j:slf4j-api").is_none());
    assert!(packages.all("org.example:unified").is_some());
}

#[test]
fn buildscript_lockfile_alone_also_beats_legacy() {
    let (_g, p) = project();
    let buildscript = p.join("buildscript-gradle.lockfile");
    std::fs::write(&buildscript, "org.example:agp:8.0.0=classpath\n").unwrap();
    write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    assert_located(&manifest_uri(&p), &buildscript);
}

#[test]
fn version_catalog_in_gradle_dir_finds_the_project_legacy_locks() {
    let (_g, p) = project();
    let located = write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    let catalog = Url::from_file_path(p.join("gradle/libs.versions.toml")).unwrap();
    assert_located(&catalog, &located);
}

#[test]
fn version_catalog_outside_gradle_dir_does_not_borrow_a_sibling_projects_locks() {
    let (_g, workspace) = project();
    write_lock(&workspace, "compileClasspath.lockfile", COMPILE_LOCK);
    let sibling = workspace.join("project-b");
    std::fs::create_dir_all(&sibling).unwrap();
    let catalog = Url::from_file_path(sibling.join("libs.versions.toml")).unwrap();
    assert_eq!(GradleLockParser.locate_lockfile(&catalog), None);
}

#[tokio::test]
async fn parse_reads_coordinates_with_or_without_configuration_suffix_and_skips_comments() {
    let (_g, p) = project();
    let located = write_lock(
        &p,
        "compileClasspath.lockfile",
        &format!(
            "{COMPILE_LOCK}org.junit:junit-bom:5.10.0=testRuntimeClasspath,testCompileClasspath\n\nnot a coordinate\n"
        ),
    );
    let packages = GradleLockParser.parse_lockfile(&located).await.unwrap();
    let (versions, _) = packages.split_normalized(&Plain);
    assert_eq!(versions[&key("org.slf4j:slf4j-api")].as_str(), "2.0.9");
    assert_eq!(
        versions[&key("com.google.guava:guava")].as_str(),
        "32.1.2-jre"
    );
    assert_eq!(versions[&key("org.junit:junit-bom")].as_str(), "5.10.0");
    assert_eq!(
        versions.len(),
        3,
        "comments, `empty=` and malformed lines add nothing"
    );
}

#[tokio::test]
async fn parse_merges_every_configuration_file_of_the_set() {
    let (_g, p) = project();
    let compile = write_lock(
        &p,
        "compileClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    write_lock(
        &p,
        "runtimeClasspath.lockfile",
        "ch.qos.logback:logback-classic:1.4.11\n",
    );
    let packages = GradleLockParser.parse_lockfile(&compile).await.unwrap();
    assert!(packages.all("org.slf4j:slf4j-api").is_some());
    assert!(packages.all("ch.qos.logback:logback-classic").is_some());
}

#[tokio::test]
async fn parse_dedupes_the_same_scope_name_and_version_across_files() {
    let (_g, p) = project();
    let compile = write_lock(
        &p,
        "compileClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    write_lock(
        &p,
        "runtimeClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    write_lock(
        &p,
        "testRuntimeClasspath.lockfile",
        "org.slf4j:slf4j-api:1.7.36\n",
    );
    let packages = GradleLockParser.parse_lockfile(&compile).await.unwrap();
    let all = packages.all("org.slf4j:slf4j-api").unwrap();
    assert_eq!(all.len(), 2, "one entry per distinct version, got {all:?}");
}

#[tokio::test]
async fn buildscript_named_legacy_files_are_build_script_scope_and_settings_files_are_skipped() {
    let (_g, p) = project();
    let compile = write_lock(
        &p,
        "compileClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    write_lock(
        &p,
        "buildscript-classpath.lockfile",
        "com.android.tools.build:gradle:8.1.0\n",
    );
    write_lock(
        &p,
        "settings-classpath.lockfile",
        "org.settings:only:1.0.0\n",
    );
    let packages = GradleLockParser.parse_lockfile(&compile).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&Plain);
    let agp = key("com.android.tools.build:gradle");
    assert!(
        !versions.contains_key(&agp),
        "buildscript-only name is not collapsed"
    );
    assert!(candidates[&agp].has_scope(LockScope::BuildScript));
    assert_eq!(
        versions[&key("org.slf4j:slf4j-api")].as_str(),
        "2.0.9",
        "Project-only name collapses to its single version"
    );
    assert!(
        packages.all("org.settings:only").is_none(),
        "settings-* files are skipped"
    );
}

#[test]
fn companions_of_a_legacy_file_are_the_directory_and_every_other_eligible_file_sorted() {
    let (_g, p) = project();
    let compile = write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    let runtime = write_lock(&p, "runtimeClasspath.lockfile", COMPILE_LOCK);
    let test = write_lock(&p, "testRuntimeClasspath.lockfile", COMPILE_LOCK);
    let companions = GradleLockParser.companion_lockfiles(&compile);
    assert_eq!(companions, [locks_dir(&p), runtime, test]);
}

#[test]
fn companions_are_capped_at_128_files_and_the_scan_stays_bounded() {
    let (_g, p) = project();
    for i in 0..1100 {
        write_lock(&p, &format!("conf{i:04}.lockfile"), "org.a:b:1.0.0\n");
    }
    let located = GradleLockParser
        .locate_lockfile(&manifest_uri(&p))
        .expect("some lock file");
    let companions = GradleLockParser.companion_lockfiles(&located);
    assert!(
        companions.len() <= 129,
        "directory + at most 128 files, got {}",
        companions.len()
    );
}

#[test]
fn lock_set_root_of_a_legacy_file_is_the_project_directory() {
    let (_g, p) = project();
    let compile = write_lock(&p, "compileClasspath.lockfile", COMPILE_LOCK);
    assert_eq!(GradleLockParser.lock_set_root(&compile), Some(p.as_path()));
}

#[test]
fn lock_set_root_of_a_unified_file_is_its_parent_directory() {
    let (_g, p) = project();
    let unified = p.join("gradle.lockfile");
    assert_eq!(GradleLockParser.lock_set_root(&unified), Some(p.as_path()));
    let buildscript = p.join("buildscript-gradle.lockfile");
    assert_eq!(
        GradleLockParser.lock_set_root(&buildscript),
        Some(p.as_path())
    );
}

#[tokio::test]
async fn cache_reparses_when_a_new_lockfile_appears_in_the_directory() {
    let (_g, p) = project();
    let compile = write_lock(
        &p,
        "compileClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    let cache = LockFileCache::new();
    let first = cache
        .get_or_parse(&GradleLockParser, &compile)
        .await
        .unwrap();
    assert!(first.all("ch.qos.logback:logback-classic").is_none());

    write_lock(
        &p,
        "runtimeClasspath.lockfile",
        "ch.qos.logback:logback-classic:1.4.11\n",
    );
    let future = SystemTime::now() + Duration::from_secs(3600);
    set_dir_modified(&locks_dir(&p), future);

    let second = cache
        .get_or_parse(&GradleLockParser, &compile)
        .await
        .unwrap();
    assert!(
        second.all("ch.qos.logback:logback-classic").is_some(),
        "directory stamp must invalidate the cached set"
    );
}

#[tokio::test]
async fn cache_reparses_when_a_lockfile_is_removed_from_the_directory() {
    let (_g, p) = project();
    let compile = write_lock(
        &p,
        "compileClasspath.lockfile",
        "org.slf4j:slf4j-api:2.0.9\n",
    );
    let runtime = write_lock(
        &p,
        "runtimeClasspath.lockfile",
        "ch.qos.logback:logback-classic:1.4.11\n",
    );
    let cache = LockFileCache::new();
    let first = cache
        .get_or_parse(&GradleLockParser, &compile)
        .await
        .unwrap();
    assert!(first.all("ch.qos.logback:logback-classic").is_some());

    std::fs::remove_file(&runtime).unwrap();
    let future = SystemTime::now() + Duration::from_secs(3600);
    set_dir_modified(&locks_dir(&p), future);

    let second = cache
        .get_or_parse(&GradleLockParser, &compile)
        .await
        .unwrap();
    assert!(second.all("ch.qos.logback:logback-classic").is_none());
}

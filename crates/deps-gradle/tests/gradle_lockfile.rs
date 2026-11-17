//! Acceptance tests for the `gradle.lockfile` provider (#1925, spec 092 as amended:
//! `gradle.lockfile` only, manifest's own directory only).

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;

use deps_core::lockfile::{LockFileProvider, ResolvedPackages};
use deps_core::{EcosystemBase, HttpCache};
use deps_gradle::{GradleEcosystem, GradleLockParser};
use url::Url;

const LOCKFILE: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:32.1.2-jre=compileClasspath,runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.10=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.36=compileClasspath
org.slf4j:slf4j-api:2.0.9=runtimeClasspath
this is not a coordinate
only:two=compileClasspath
empty=annotationProcessor,testAnnotationProcessor
";

async fn parse(dir: &Path, content: &str) -> deps_core::Result<ResolvedPackages> {
    let path = dir.join("gradle.lockfile");
    tokio::fs::write(&path, content).await.unwrap();
    GradleLockParser.parse_lockfile(&path).await
}

fn uri(dir: &Path, file: &str) -> Url {
    Url::from_file_path(dir.join(file)).unwrap()
}

#[tokio::test]
async fn parse_lockfile_resolves_group_artifact_to_version() {
    let dir = tempfile::tempdir().unwrap();
    let packages = parse(dir.path(), LOCKFILE).await.unwrap();
    assert!(!packages.is_empty());
    assert_eq!(
        packages.version("com.google.guava:guava"),
        Some("32.1.2-jre")
    );
    assert_eq!(
        packages.version("org.jetbrains.kotlin:kotlin-stdlib"),
        Some("1.9.10")
    );
}

#[tokio::test]
async fn parse_lockfile_keeps_every_distinct_version_per_coordinate() {
    let dir = tempfile::tempdir().unwrap();
    let packages = parse(dir.path(), LOCKFILE).await.unwrap();
    let all = packages.all("org.slf4j:slf4j-api").expect("slf4j present");
    let mut versions: Vec<_> = all.iter().map(|p| p.version.as_str()).collect();
    versions.sort_unstable();
    assert_eq!(versions, ["1.7.36", "2.0.9"]);
}

#[tokio::test]
async fn parse_lockfile_skips_comments_empty_marker_and_malformed_lines() {
    let dir = tempfile::tempdir().unwrap();
    let packages = parse(dir.path(), LOCKFILE).await.unwrap();
    assert!(packages.get("empty").is_none());
    assert!(packages.get("only:two").is_none());
    assert!(packages.get("this is not a coordinate").is_none());
    assert_eq!(packages.iter_all().count(), 3);
}

#[tokio::test]
async fn parse_lockfile_comment_only_file_yields_empty_set() {
    let dir = tempfile::tempdir().unwrap();
    let content = "# comment\n\nempty=annotationProcessor\n";
    assert!(parse(dir.path(), content).await.unwrap().is_empty());
}

#[tokio::test]
async fn parse_lockfile_empty_file_yields_empty_set() {
    let dir = tempfile::tempdir().unwrap();
    assert!(parse(dir.path(), "").await.unwrap().is_empty());
}

#[tokio::test]
async fn parse_lockfile_never_panics_on_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = "=\n:::=\na:b:=x\n\u{0}\u{ffff}:x:y=z\n=====\n";
    assert!(parse(dir.path(), garbage).await.is_ok());
}

#[test]
fn locate_lockfile_for_build_scripts_uses_own_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gradle.lockfile"), LOCKFILE).unwrap();
    for manifest in [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    ] {
        assert_eq!(
            GradleLockParser.locate_lockfile(&uri(dir.path(), manifest)),
            Some(dir.path().join("gradle.lockfile")),
            "{manifest}"
        );
    }
}

#[test]
fn locate_lockfile_for_build_script_does_not_search_ancestors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gradle.lockfile"), LOCKFILE).unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&uri(&sub, "build.gradle.kts")),
        None
    );
}

#[test]
fn locate_lockfile_for_version_catalog_looks_one_level_up() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gradle.lockfile"), LOCKFILE).unwrap();
    let catalog_dir = dir.path().join("gradle");
    std::fs::create_dir_all(&catalog_dir).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&uri(&catalog_dir, "libs.versions.toml")),
        Some(dir.path().join("gradle.lockfile"))
    );
}

#[test]
fn locate_lockfile_for_version_catalog_does_not_search_two_levels_up() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gradle.lockfile"), LOCKFILE).unwrap();
    let deep = dir.path().join("a").join("gradle");
    std::fs::create_dir_all(&deep).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&uri(&deep, "libs.versions.toml")),
        None
    );
}

#[test]
fn locate_lockfile_absent_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&uri(dir.path(), "build.gradle")),
        None
    );
}

#[test]
fn lockfile_filenames_watch_every_lockfile() {
    let eco = GradleEcosystem::new(Arc::new(HttpCache::new()));
    assert_eq!(eco.lockfile_filenames(), &["*.lockfile"]);
    assert!(eco.lockfile_provider().is_some());
}

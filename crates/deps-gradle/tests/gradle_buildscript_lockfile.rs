//! `buildscript-gradle.lockfile` support (#2034): classpath dependencies resolve from the
//! build-script lock file, project dependencies from `gradle.lockfile`, never crossed.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use deps_core::lockfile::{LockFileCache, LockFileProvider};
use deps_core::lsp_helpers::{NormalizeName, PackageNaming};
use deps_core::{Dependency, LockScope, PackageName};
use deps_gradle::{GradleLockParser, parse_gradle};
use url::Url;

struct Plain;

impl PackageNaming for Plain {}

const APP_LOCK: &str = "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\n";
const BUILDSCRIPT_LOCK: &str = "\
org.slf4j:slf4j-api:1.7.36=classpath
com.android.tools.build:gradle:8.1.0=classpath
";

fn manifest_uri(dir: &Path) -> Url {
    Url::from_file_path(dir.join("build.gradle.kts")).unwrap()
}

#[test]
fn locate_falls_back_to_the_buildscript_lockfile() {
    let dir = tempfile::tempdir().unwrap();
    let buildscript = dir.path().join("buildscript-gradle.lockfile");
    std::fs::write(&buildscript, BUILDSCRIPT_LOCK).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&manifest_uri(dir.path())),
        Some(buildscript)
    );

    let app = dir.path().join("gradle.lockfile");
    std::fs::write(&app, APP_LOCK).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&manifest_uri(dir.path())),
        Some(app)
    );
}

#[test]
fn companion_is_the_other_lockfile_in_the_same_directory() {
    let dir = Path::new("/p");
    assert_eq!(
        GradleLockParser.companion_lockfiles(&dir.join("gradle.lockfile")),
        [dir.join("buildscript-gradle.lockfile")]
    );
    assert_eq!(
        GradleLockParser.companion_lockfiles(&dir.join("buildscript-gradle.lockfile")),
        [dir.join("gradle.lockfile")]
    );
}

#[tokio::test]
async fn parse_merges_both_files_with_their_scopes() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("gradle.lockfile");
    std::fs::write(&app, APP_LOCK).unwrap();
    std::fs::write(
        dir.path().join("buildscript-gradle.lockfile"),
        BUILDSCRIPT_LOCK,
    )
    .unwrap();

    let packages = GradleLockParser.parse_lockfile(&app).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&Plain);
    let slf4j = Plain.normalize_package_name(&PackageName::new("org.slf4j:slf4j-api"));
    let agp = Plain.normalize_package_name(&PackageName::new("com.android.tools.build:gradle"));

    assert_eq!(
        versions[&slf4j].as_str(),
        "2.0.9",
        "collapsed value is Project-only"
    );
    assert!(
        !versions.contains_key(&agp),
        "buildscript-only name is not collapsed"
    );
    assert!(candidates[&agp].has_scope(LockScope::BuildScript));
    assert!(candidates[&slf4j].has_scope(LockScope::Project));
    assert!(candidates[&slf4j].has_scope(LockScope::BuildScript));
}

#[tokio::test]
async fn buildscript_only_project_parses_from_the_located_buildscript_file() {
    let dir = tempfile::tempdir().unwrap();
    let located = dir.path().join("buildscript-gradle.lockfile");
    std::fs::write(&located, BUILDSCRIPT_LOCK).unwrap();

    let packages = GradleLockParser.parse_lockfile(&located).await.unwrap();
    let (versions, candidates) = packages.split_normalized(&Plain);

    assert!(versions.is_empty());
    assert_eq!(candidates.len(), 2);
}

#[tokio::test]
async fn non_file_companion_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("gradle.lockfile");
    std::fs::write(&app, APP_LOCK).unwrap();
    std::fs::create_dir(dir.path().join("buildscript-gradle.lockfile")).unwrap();

    let packages = GradleLockParser.parse_lockfile(&app).await.unwrap();
    assert!(
        !packages.is_empty(),
        "a directory is not a lock file and is skipped"
    );
}

#[tokio::test]
async fn cache_reparses_when_the_buildscript_lockfile_appears() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("gradle.lockfile");
    std::fs::write(&app, APP_LOCK).unwrap();
    let cache = LockFileCache::new();

    let first = cache.get_or_parse(&GradleLockParser, &app).await.unwrap();
    assert!(first.all("com.android.tools.build:gradle").is_none());

    std::fs::write(
        dir.path().join("buildscript-gradle.lockfile"),
        BUILDSCRIPT_LOCK,
    )
    .unwrap();
    let second = cache.get_or_parse(&GradleLockParser, &app).await.unwrap();
    assert!(second.all("com.android.tools.build:gradle").is_some());
}

#[test]
fn parser_tags_only_dependencies_inside_the_buildscript_block() {
    let content = "\
buildscript {
    dependencies {
        classpath(\"com.android.tools.build:gradle:8.1.0\")
    }
}
dependencies {
    implementation(\"org.slf4j:slf4j-api:2.0.9\")
    classpath(\"com.example:outside:1.0.0\")
}
";
    let uri = Url::parse("file:///p/build.gradle.kts").unwrap();
    let result = parse_gradle(content, &uri).unwrap();
    let scope_of = |name: &str| {
        result
            .dependencies
            .iter()
            .find(|d| d.name() == name)
            .unwrap_or_else(|| panic!("{name} parsed"))
            .lock_scope()
    };
    assert_eq!(
        scope_of("com.android.tools.build:gradle"),
        LockScope::BuildScript
    );
    assert_eq!(scope_of("org.slf4j:slf4j-api"), LockScope::Project);
    assert_eq!(scope_of("com.example:outside"), LockScope::Project);
}

#[tokio::test]
async fn oversized_companion_degrades_to_the_located_file_only() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("gradle.lockfile");
    std::fs::write(&app, APP_LOCK).unwrap();
    let companion = std::fs::File::create(dir.path().join("buildscript-gradle.lockfile")).unwrap();
    companion
        .set_len(deps_core::lockfile::MAX_LOCKFILE_BYTES + 1)
        .unwrap();

    let packages = GradleLockParser.parse_lockfile(&app).await.unwrap();

    assert!(packages.all("org.slf4j:slf4j-api").is_some());
    assert!(packages.all("com.android.tools.build:gradle").is_none());
}

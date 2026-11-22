//! A version catalog consults the project root's `gradle.lockfile` only in the standard
//! `<project>/gradle/libs.versions.toml` layout, never a sibling project's lock file.

#![expect(clippy::unwrap_used, reason = "test code")]

use deps_core::lockfile::LockFileProvider;
use deps_gradle::GradleLockParser;
use url::Url;

fn catalog_uri(dir: &std::path::Path) -> Url {
    Url::from_file_path(dir.join("libs.versions.toml")).unwrap()
}

#[test]
fn catalog_in_gradle_dir_uses_project_root_lockfile() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("gradle.lockfile"), "").unwrap();
    let gradle_dir = root.path().join("gradle");
    std::fs::create_dir_all(&gradle_dir).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&catalog_uri(&gradle_dir)),
        Some(root.path().join("gradle.lockfile"))
    );
}

#[test]
fn catalog_outside_gradle_dir_ignores_sibling_project_lockfile() {
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("gradle.lockfile"), "").unwrap();
    let project = workspace.path().join("project-b");
    std::fs::create_dir_all(&project).unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&catalog_uri(&project)),
        None
    );
}

#[test]
fn catalog_outside_gradle_dir_uses_its_own_directory_lockfile() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("gradle.lockfile"), "").unwrap();
    assert_eq!(
        GradleLockParser.locate_lockfile(&catalog_uri(project.path())),
        Some(project.path().join("gradle.lockfile"))
    );
}

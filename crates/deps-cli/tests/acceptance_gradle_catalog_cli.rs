//! Acceptance tests (tester-owned) for #2178, #2179 and #2182: settings-declared Gradle version
//! catalogs seen through the real `deps-cli` binary. Every catalog holds one invalid library, so
//! recognition is observable offline as a finding that names the alias.

#![cfg(feature = "gradle")]
#![expect(clippy::expect_used, reason = "test code")]

use std::path::{Path, PathBuf};
use std::process::Output;

const ALIAS: &str = "bad-alias";
const CATALOG: &str = "[libraries]\nbad-alias = \"not-a-coordinate\"\n";

fn settings(declared: &str) -> String {
    format!(
        "dependencyResolutionManagement {{ versionCatalogs {{ create(\"deps\") {{ from(files(\"{declared}\")) }} }} }}\n"
    )
}

fn write(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, content).expect("write");
}

fn tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    (dir, root)
}

fn check(cwd: &Path, target: &str) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["check", "--offline", "--format", "json", target])
        .current_dir(cwd)
        .output()
        .expect("run the real deps-cli binary")
}

fn assert_catalog_checked(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        output.status.code(),
        Some(2),
        "run aborted; stderr: {stderr}"
    );
    assert!(
        stdout.contains(ALIAS),
        "the declared catalog was not checked; stdout: {stdout}; stderr: {stderr}"
    );
}

// #2178
#[test]
fn check_explicit_catalog_declared_through_parent_dir_is_routed_to_gradle() {
    let (_dir, root) = tree();
    write(
        &root,
        "project/settings.gradle.kts",
        &settings("../shared/deps.toml"),
    );
    write(&root, "shared/deps.toml", CATALOG);

    assert_catalog_checked(&check(&root, "shared/deps.toml"));
}

// #2178
#[test]
fn check_walk_routes_catalog_declared_through_parent_dir() {
    let (_dir, root) = tree();
    write(
        &root,
        "project/settings.gradle.kts",
        &settings("../shared/deps.toml"),
    );
    write(&root, "shared/deps.toml", CATALOG);

    assert_catalog_checked(&check(&root, "."));
}

// #2179
#[test]
fn check_walk_includes_settings_declared_catalog_with_hidden_name() {
    let (_dir, root) = tree();
    write(&root, "settings.gradle.kts", &settings("gradle/.deps.toml"));
    write(&root, "gradle/.deps.toml", CATALOG);

    assert_catalog_checked(&check(&root, "."));
}

// #2182
#[test]
fn check_of_directory_holding_a_catalog_named_deps_toml_does_not_load_it_as_config() {
    let (_dir, root) = tree();
    write(&root, "settings.gradle.kts", &settings("gradle/deps.toml"));
    write(&root, "gradle/deps.toml", CATALOG);

    assert_catalog_checked(&check(&root, "gradle/"));
}

// #2182
#[test]
fn check_of_project_root_with_a_root_catalog_named_deps_toml_does_not_load_it_as_config() {
    let (_dir, root) = tree();
    write(&root, "settings.gradle.kts", &settings("deps.toml"));
    write(&root, "deps.toml", CATALOG);

    assert_catalog_checked(&check(&root, "."));
}

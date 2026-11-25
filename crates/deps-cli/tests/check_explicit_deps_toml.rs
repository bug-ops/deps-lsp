//! #2168: `deps-cli check <dir>/deps.toml` must not parse the checked file itself as CLI
//! configuration. A Gradle version catalog may legitimately be named `deps.toml`.
#![cfg(feature = "gradle")]
#![expect(clippy::expect_used, reason = "test code")]

use std::path::Path;
use std::process::Output;

const SETTINGS_DEPS: &str =
    "versionCatalogs { create(\"deps\") { from(files(\"gradle/deps.toml\")) } }\n";
const CATALOG: &str = "[versions]\njunit = \"4.12\"\n\n[libraries]\njunit = { module = \"junit:junit\", version.ref = \"junit\" }\n";
const INVALID_CONFIG: &str = "unknown_key = 1\n";
const CONFIG_ERROR: &str = "invalid configuration";

fn check(dir: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["check", "--offline"])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run the real deps-cli binary")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn project() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    std::fs::create_dir_all(root.join("gradle")).expect("gradle dir");
    (dir, root)
}

#[test]
fn check_of_a_declared_catalog_named_deps_toml_does_not_load_it_as_config() {
    let (_dir, root) = project();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS_DEPS).expect("settings");
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");

    let output = check(&root, &["gradle/deps.toml"]);

    let stderr = stderr(&output);
    assert!(
        !stderr.contains(CONFIG_ERROR),
        "the checked catalog was parsed as configuration: {stderr}"
    );
    assert_ne!(output.status.code(), Some(2), "{stderr}");
}

#[test]
fn check_of_a_deps_toml_without_settings_is_not_reported_as_a_config_error() {
    let (_dir, root) = project();
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");

    let output = check(&root, &["gradle/deps.toml"]);

    let stderr = stderr(&output);
    assert!(
        !stderr.contains(CONFIG_ERROR),
        "the checked file was parsed as configuration: {stderr}"
    );
}

#[test]
fn explicit_config_flag_still_loads_its_file_when_the_checked_file_is_named_deps_toml() {
    let (_dir, root) = project();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS_DEPS).expect("settings");
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");
    std::fs::write(root.join("broken.toml"), INVALID_CONFIG).expect("config");

    let output = check(&root, &["--config", "broken.toml", "gradle/deps.toml"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(
        stderr(&output).contains(CONFIG_ERROR),
        "{}",
        stderr(&output)
    );
}

#[test]
fn skipping_a_walked_default_file_declared_as_a_catalog_is_announced() {
    let (_dir, root) = project();
    std::fs::write(root.join("settings.gradle.kts"), SETTINGS_DEPS).expect("settings");
    std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");

    let output = check(&root, &["gradle/"]);

    let stderr = stderr(&output);
    assert!(
        stderr.contains("was not loaded as configuration"),
        "{stderr}"
    );
}

/// A project whose root `deps.toml` is a declared version catalog.
fn root_catalog_project() -> (tempfile::TempDir, std::path::PathBuf) {
    let (dir, root) = project();
    std::fs::write(
        root.join("settings.gradle.kts"),
        "versionCatalogs { create(\"deps\") { from(files(\"deps.toml\")) } }\n",
    )
    .expect("settings");
    std::fs::write(root.join("deps.toml"), CATALOG).expect("catalog");
    (dir, root)
}

fn assert_catalog_skipped_as_config(output: &Output) {
    let stderr = stderr(output);
    assert!(!stderr.contains(CONFIG_ERROR), "{stderr}");
    assert!(
        stderr.contains("was not loaded as configuration"),
        "{stderr}"
    );
    assert_ne!(output.status.code(), Some(2), "{stderr}");
}

#[test]
fn several_walk_paths_do_not_load_a_root_catalog_as_config() {
    let (_dir, root) = root_catalog_project();
    for sub in ["a", "b"] {
        std::fs::create_dir_all(root.join(sub)).expect("walk path");
        std::fs::write(
            root.join(sub).join("Cargo.toml"),
            "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n",
        )
        .expect("manifest");
    }

    assert_catalog_skipped_as_config(&check(&root, &["a", "b"]));
}

#[test]
fn a_single_manifest_path_does_not_load_a_root_catalog_as_config() {
    let (_dir, root) = root_catalog_project();

    assert_catalog_skipped_as_config(&check(&root, &["settings.gradle.kts"]));
}

#[test]
fn a_root_outside_the_working_directory_bounds_the_config_probe() {
    let (_dir, root) = project();
    std::fs::create_dir_all(root.join("proj/app")).expect("project");
    std::fs::create_dir_all(root.join("elsewhere")).expect("cwd");
    std::fs::write(
        root.join("proj/app/settings.gradle.kts"),
        "versionCatalogs { create(\"deps\") { from(files(\"../deps.toml\")) } }\n",
    )
    .expect("settings");
    std::fs::write(root.join("proj/deps.toml"), CATALOG).expect("catalog");

    assert_catalog_skipped_as_config(&check(&root.join("elsewhere"), &["../proj"]));
}

#[cfg(unix)]
mod unix_file_identity {
    use super::*;

    #[test]
    fn a_hard_link_to_the_default_config_file_is_the_checked_file_not_config() {
        let (_dir, root) = project();
        std::fs::write(
            root.join("settings.gradle.kts"),
            "versionCatalogs { create(\"c\") { from(files(\"gradle/Catalog.toml\")) } }\n",
        )
        .expect("settings");
        std::fs::write(root.join("gradle/deps.toml"), CATALOG).expect("catalog");
        std::fs::hard_link(
            root.join("gradle/deps.toml"),
            root.join("gradle/Catalog.toml"),
        )
        .expect("hard link");

        let output = check(&root, &["gradle/Catalog.toml"]);

        let stderr = stderr(&output);
        assert!(
            !stderr.contains(CONFIG_ERROR),
            "a hard link to deps.toml is the same file as the checked path: {stderr}"
        );
    }

    #[test]
    fn a_different_file_named_deps_toml_next_to_the_checked_file_is_still_config() {
        let (_dir, root) = project();
        std::fs::write(root.join("gradle/Deps.toml"), CATALOG).expect("catalog");
        std::fs::write(root.join("gradle/deps.toml"), INVALID_CONFIG).expect("config");
        if std::fs::read_to_string(root.join("gradle/Deps.toml")).expect("read back") != CATALOG {
            eprintln!("skipping: case-insensitive file system, the two names are one file");
            return;
        }
        std::fs::write(
            root.join("settings.gradle.kts"),
            "versionCatalogs { create(\"c\") { from(files(\"gradle/Deps.toml\")) } }\n",
        )
        .expect("settings");

        let output = check(&root, &["gradle/Deps.toml"]);

        assert_eq!(output.status.code(), Some(2));
        assert!(
            stderr(&output).contains(CONFIG_ERROR),
            "{}",
            stderr(&output)
        );
    }
}

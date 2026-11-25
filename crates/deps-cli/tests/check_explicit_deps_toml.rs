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

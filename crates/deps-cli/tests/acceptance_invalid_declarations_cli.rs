//! Acceptance tests (tester-owned) for #2181: a dependency entry a parser cannot read is reported
//! by `deps-cli check` instead of being dropped silently.

#![cfg(all(feature = "cargo", feature = "npm", feature = "composer"))]
#![expect(clippy::expect_used, reason = "test code")]

fn assert_reported(file: &str, content: &str, name: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    std::fs::write(root.join(file), content).expect("manifest");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["check", "--offline", "--format", "json", file])
        .current_dir(&root)
        .output()
        .expect("run the real deps-cli binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(name),
        "{file}: the unreadable entry `{name}` must be reported, got: {stdout}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_package_json_object_valued_dependency_is_reported() {
    assert_reported(
        "package.json",
        "{ \"dependencies\": { \"express\": { \"version\": \"4.0.0\" } } }\n",
        "express",
    );
}

#[test]
fn check_composer_json_object_valued_requirement_is_reported() {
    assert_reported(
        "composer.json",
        "{ \"require\": { \"monolog/monolog\": { \"version\": \"3.0\" } } }\n",
        "monolog/monolog",
    );
}

#[test]
fn check_cargo_toml_integer_valued_dependency_is_reported() {
    assert_reported(
        "Cargo.toml",
        "[package]\nname = \"fx\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = 5\n",
        "serde",
    );
}

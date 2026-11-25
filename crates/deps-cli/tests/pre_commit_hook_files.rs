//! #2167: the `files:` regex of the `deps-lsp-check` pre-commit hook selects every Gradle
//! `*.versions.toml` catalog besides the ecosystem manifests it always matched, and keeps the
//! documented limit that an arbitrarily named settings-declared catalog is not matched.
//!
//! Needs `regex` as a `deps-cli` dev-dependency.

#![expect(clippy::expect_used, reason = "test code")]

use std::path::PathBuf;

fn hook_files_regex() -> regex::Regex {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.pre-commit-hooks.yaml");
    let manifest = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let quoted = manifest
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("files: "))
        .expect("a `files:` line in .pre-commit-hooks.yaml");
    let pattern = quoted
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .expect("`files:` is a single-quoted YAML scalar");
    assert!(
        !pattern.contains("''"),
        "an escaped quote would need YAML unescaping before compiling"
    );
    regex::Regex::new(pattern).expect("`files:` compiles as a regex")
}

#[test]
fn files_regex_matches_every_ecosystem_manifest_and_every_versions_toml_catalog() {
    let files = hook_files_regex();
    let matched = [
        "Cargo.toml",
        "crates/a/Cargo.toml",
        "Gemfile",
        "composer.json",
        "pubspec.yaml",
        "deno.json",
        "deno.jsonc",
        "go.mod",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "Package.swift",
        "Directory.Packages.props",
        "packages.config",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        ".gitlab-ci.yml",
        "action.yml",
        "action.yaml",
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "base.requirements.txt",
        "constraints.txt",
        "src/App.csproj",
        ".github/workflows/ci.yml",
        ".gitlab/ci/build.yml",
        "requirements/base.txt",
        "libs.versions.toml",
        "gradle/libs.versions.toml",
        "gradle/plugins.versions.toml",
        "plugins.versions.toml",
    ];
    for path in matched {
        assert!(files.is_match(path), "{path} must be passed to the hook");
    }
}

#[test]
fn files_regex_does_not_match_arbitrary_toml_or_unrelated_files() {
    let files = hook_files_regex();
    for path in [
        "gradle/deps.toml",
        "rustfmt.toml",
        "gradle/libs.versions.toml.bak",
        "README.md",
        "src/main.rs",
    ] {
        assert!(
            !files.is_match(path),
            "{path} must not be passed to the hook"
        );
    }
}

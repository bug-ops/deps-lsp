//! Subprocess acceptance tests for `deps-cli update --open-pr` and `--group` (spec 104: FR-001,
//! FR-002, FR-003, FR-016), written tests-first.
//!
//! Every case here must fail before any network access or write, so none needs a registry:
//! the real binary refuses at the CLI boundary, in the preflight, or after the manifest walk.

#![allow(clippy::expect_used)]

use std::path::Path;
use std::process::Output;

const CARGO_MANIFEST: &str =
    "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n";

fn run(dir: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .arg("update")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run the real deps-cli binary")
}

fn git(dir: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A committed repository holding `manifest` (with `content`) and `README.md`.
fn repository(manifest: &str, content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("repository dir");
    git(dir.path(), &["init", "--initial-branch=main"]);
    for (key, value) in [
        ("user.name", "Fixture"),
        ("user.email", "fixture@example.test"),
        ("commit.gpgsign", "false"),
    ] {
        git(dir.path(), &["config", key, value]);
    }
    std::fs::write(dir.path().join(manifest), content).expect("write manifest");
    std::fs::write(dir.path().join("README.md"), "readme\n").expect("write readme");
    git(dir.path(), &["add", "--all"]);
    git(dir.path(), &["commit", "--message=initial"]);
    dir
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Exit 2 for a reason of the feature itself: a binary that does not know the flag also exits 2
/// ("unexpected argument"), which must not count as a pass.
fn assert_refused(output: &Output, context: &str) {
    let stderr = stderr(output);
    assert_eq!(output.status.code(), Some(2), "{context}: {stderr}");
    assert!(
        !stderr.contains("unexpected argument"),
        "{context}: the flag is not implemented: {stderr}"
    );
}

#[test]
fn test_update_open_pr_without_lockfile_regenerate_exits_2() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);

    let output = run(repo.path(), &["--open-pr", "github", "Cargo.toml"]);

    assert_refused(&output, "refusal");
    assert_eq!(
        std::fs::read_to_string(repo.path().join("Cargo.toml")).expect("read"),
        CARGO_MANIFEST
    );
}

#[test]
fn test_update_open_pr_with_dry_run_or_offline_exits_2() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);

    for flag in ["--dry-run", "--offline"] {
        let output = run(
            repo.path(),
            &[
                "--open-pr",
                "github",
                "--lockfile",
                "regenerate",
                flag,
                "Cargo.toml",
            ],
        );

        assert_refused(&output, flag);
    }
}

#[test]
fn test_update_open_pr_in_a_dirty_repository_exits_2_and_writes_nothing() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);
    std::fs::write(repo.path().join("README.md"), "edited\n").expect("dirty the tree");

    let output = run(
        repo.path(),
        &[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "Cargo.toml",
        ],
    );

    assert_refused(&output, "refusal");
    assert_eq!(
        std::fs::read_to_string(repo.path().join("Cargo.toml")).expect("read"),
        CARGO_MANIFEST
    );
}

#[test]
fn test_update_open_pr_outside_a_git_repository_exits_2() {
    let dir = tempfile::tempdir().expect("plain dir");
    std::fs::write(dir.path().join("Cargo.toml"), CARGO_MANIFEST).expect("write manifest");

    let output = run(
        dir.path(),
        &[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "Cargo.toml",
        ],
    );

    assert_refused(&output, "refusal");
}

#[cfg(feature = "composer")]
#[test]
fn test_update_open_pr_for_a_deferred_ecosystem_exits_2_naming_the_supported_ones() {
    let repo = repository(
        "composer.json",
        "{\"require\": {\"monolog/monolog\": \"1.0.0\"}}\n",
    );

    let output = run(
        repo.path(),
        &[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "composer.json",
        ],
    );

    assert_refused(&output, "deferred ecosystem");
    let stderr = stderr(&output);
    for supported in ["cargo", "npm", "go"] {
        assert!(
            stderr.contains(supported),
            "{supported} not named in: {stderr}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(repo.path().join("composer.json")).expect("read"),
        "{\"require\": {\"monolog/monolog\": \"1.0.0\"}}\n"
    );
}

#[test]
fn test_update_group_without_config_or_with_security_only_exits_2() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);
    std::fs::write(repo.path().join("deps.toml"), "[update.groups.g]\n").expect("write config");

    let without_config = run(repo.path(), &["--offline", "--group", "g", "Cargo.toml"]);
    let with_security_only = run(
        repo.path(),
        &[
            "--offline",
            "--group",
            "g",
            "--config",
            "deps.toml",
            "--security-only",
            "Cargo.toml",
        ],
    );

    assert_refused(&without_config, "--group without --config");
    assert_refused(&with_security_only, "--group with --security-only");
}

#[test]
fn test_update_group_not_defined_in_the_config_exits_2() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);
    std::fs::write(repo.path().join("deps.toml"), "[update.groups.other]\n").expect("write config");

    let output = run(
        repo.path(),
        &[
            "--offline",
            "--group",
            "missing",
            "--config",
            "deps.toml",
            "Cargo.toml",
        ],
    );

    assert_refused(&output, "refusal");
}

#[test]
fn test_update_group_defined_in_the_config_runs_like_a_plain_update() {
    let repo = repository("Cargo.toml", CARGO_MANIFEST);
    std::fs::write(repo.path().join("deps.toml"), "[update.groups.g]\n").expect("write config");

    let output = run(
        repo.path(),
        &[
            "--offline",
            "--group",
            "g",
            "--config",
            "deps.toml",
            "Cargo.toml",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("No eligible updates."));
}

/// Network-free end to end: with nothing to propose, `--open-pr` passes the preflight, opens
/// nothing, creates no branch and exits as a plain `update` does.
#[test]
fn test_update_open_pr_with_no_proposed_update_opens_nothing_and_exits_clean() {
    let repo = repository(
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );

    let output = run(
        repo.path(),
        &[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "Cargo.toml",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("No eligible updates."));
    let branches = std::process::Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(["branch", "--list"])
        .output()
        .expect("run git");
    assert_eq!(
        String::from_utf8_lossy(&branches.stdout).trim(),
        "* main",
        "no branch is created"
    );
}

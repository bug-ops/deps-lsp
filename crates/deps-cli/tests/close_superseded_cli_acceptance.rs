//! #2073 acceptance, CLI surface: `--close-superseded` is opt-in and requires `--open-pr`.
//!
//! The gate matrix (author, same repository, branch prefix, single commit, marker v1, target
//! `>=`, failure => warning) needs a fake `gh`/`glab` behind `pr::open` and is covered by the
//! developer's in-module `pr/acceptance_tests.rs`, because the close step has no public entry
//! point in the plan. Written tests-first; the flag does not exist yet.

#![expect(clippy::expect_used, reason = "test code")]

use std::process::Output;

const CARGO_MANIFEST: &str =
    "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n";

fn run(args: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("Cargo.toml"), CARGO_MANIFEST).expect("manifest");
    std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .arg("update")
        .args(args)
        .current_dir(dir.path())
        .output()
        .expect("run deps-cli")
}

#[test]
fn close_superseded_without_open_pr_exits_2_for_the_flags_own_reason() {
    let output = run(&["--close-superseded", "Cargo.toml"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        !stderr.contains("unexpected argument"),
        "the flag is not implemented: {stderr}"
    );
    assert!(
        stderr.contains("--open-pr"),
        "must name the missing flag: {stderr}"
    );
}

#[test]
fn close_superseded_is_listed_in_update_help() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args(["update", "--help"])
        .output()
        .expect("help");

    assert!(String::from_utf8_lossy(&output.stdout).contains("--close-superseded"));
}

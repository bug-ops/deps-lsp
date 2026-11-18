//! #2069 acceptance: every documented MSRV mirror agrees with the workspace `rust-version`, and
//! `CONTRIBUTING.md` carries the MSRV policy. Written tests-first; `CONTRIBUTING.md` still says
//! 1.85 and `deps-precommit`'s README has no requires-Rust line.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

fn workspace_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn msrv() -> String {
    workspace_file("Cargo.toml")
        .lines()
        .find_map(|line| {
            line.strip_prefix("rust-version = \"")
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .expect("rust-version in the root manifest")
        .to_owned()
}

#[test]
fn contributing_states_the_workspace_msrv_and_not_the_stale_one() {
    let contributing = workspace_file("CONTRIBUTING.md");

    assert!(
        contributing.contains(&format!("Rust {}+", msrv())),
        "{}",
        msrv()
    );
    assert!(!contributing.contains("Rust 1.85"));
}

#[test]
fn contributing_documents_the_msrv_policy() {
    let contributing = workspace_file("CONTRIBUTING.md");

    assert!(contributing.contains("MSRV policy"));
    assert!(contributing.contains("N-2"));
    assert!(contributing.contains("### Breaking"));
    assert!(contributing.contains("nightly"));
}

#[test]
fn deps_precommit_readme_states_the_msrv_like_the_other_crate_readmes() {
    let readme = workspace_file("crates/deps-precommit/README.md");

    assert!(readme.contains(&format!("Requires Rust {} or later", msrv())));
}

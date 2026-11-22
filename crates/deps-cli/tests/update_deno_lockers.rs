//! Deno locker regressions: the lock path is pinned, and an ancestor `package.json` workspace
//! makes the manifest a member (Deno would write the root `deno.lock`).

#![cfg(all(unix, feature = "deno"))]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const DENO_JSON: &str = "{\n  \"imports\": {\n    \"chalk\": \"npm:chalk@^4.0.0\"\n  }\n}\n";
const DENO_LOCK: &str = "{\n  \"version\": \"4\"\n}\n";

fn case<'a>(
    manifest: &'a str,
    files: Vec<(&'a str, &'a str)>,
    mode: &'a str,
    bumps: &'a str,
) -> Case<'a> {
    Case {
        ecosystem: "deno",
        manifest,
        files: files
            .into_iter()
            .map(|(path, body)| (path, body.as_bytes().to_vec()))
            .collect(),
        tools: vec![("deno", "exit 0")],
        mode,
        bumps,
        cooldown_fallback: false,
        unlistened: false,
    }
}

#[test]
fn deno_install_pins_the_lock_path() {
    let ran = run(&case(
        "deno.json",
        vec![("deno.json", DENO_JSON), ("deno.lock", DENO_LOCK)],
        "edit",
        "chalk|chalk|^4.0.0|^4.1.2|4.0.0|4.1.2",
    ));

    assert_eq!(
        ran.calls
            .iter()
            .filter(|call| call.starts_with("deno install --lockfile-only --lock=./deno.lock|"))
            .count(),
        1,
        "{:?}",
        ran.calls
    );
}

#[test]
fn deno_update_pins_the_lock_path() {
    let ran = run(&case(
        "deno.json",
        vec![("deno.json", DENO_JSON), ("deno.lock", DENO_LOCK)],
        "lockonly",
        "chalk|chalk|^4.0.0|^4.0.0|4.0.0|4.1.2",
    ));

    assert_eq!(
        ran.calls
            .iter()
            .filter(|call| call
                .starts_with("deno update --compatible --lockfile-only --lock=./deno.lock chalk|"))
            .count(),
        1,
        "{:?}",
        ran.calls
    );
}

#[test]
fn deno_update_filters_by_the_bare_package_name() {
    let ran = run(&case(
        "deno.json",
        vec![("deno.json", DENO_JSON), ("deno.lock", DENO_LOCK)],
        "lockonly",
        "npm:chalk|chalk|^4.0.0|^4.0.0|4.0.0|4.1.2",
    ));

    assert_eq!(
        ran.calls
            .iter()
            .filter(|call| call
                .starts_with("deno update --compatible --lockfile-only --lock=./deno.lock chalk|"))
            .count(),
        1,
        "{:?}",
        ran.calls
    );
}

#[test]
fn deno_manifest_under_an_ancestor_package_json_workspace_is_refused() {
    let ran = run(&case(
        "a/deno.json",
        vec![
            ("package.json", "{\n  \"workspaces\": [\"a\"]\n}\n"),
            ("a/deno.json", DENO_JSON),
            ("a/deno.lock", DENO_LOCK),
        ],
        "edit",
        "chalk|chalk|^4.0.0|^4.1.2|4.0.0|4.1.2",
    ));

    assert!(
        ran.outcome.contains("WorkspaceMemberLockfile"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

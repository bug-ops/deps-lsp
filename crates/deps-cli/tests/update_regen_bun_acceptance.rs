//! #2098 acceptance: Bun lock-file-only pins. `bun update --lockfile-only <names>` rewrites
//! `package.json`, so the run captures the manifest, writes the captured bytes back, and runs
//! `bun install --lockfile-only` before verifying the pins in `bun.lock`.
//!
//! Driven through fake tools in a re-executed test binary (see `common/regen_harness.rs`). The
//! fake `bun` mutates `package.json` on `update`, as the real one does. Not covered here: the
//! real tool's flag acceptance (live probes). `bun --version` calls are tolerated wherever they
//! happen, because the plan makes that probe conditional on the live evidence.

#![cfg(all(unix, feature = "npm"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const PACKAGE: &str = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.0\"\n  }\n}\n";
const PACKAGE_BUMPED: &str = "{\n  \"name\": \"p\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"minimist\": \"^1.2.8\"\n  }\n}\n";
const LOCK_OLD: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"p\",\n      \"dependencies\": {\n        \"minimist\": \"^1.2.0\",\n      },\n    },\n  },\n  \"packages\": {\n    \"minimist\": [\"minimist@1.2.0\", \"\", {}, \"sha512-aaa\"],\n  }\n}\n";
const LOCK_NEW: &str = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"p\",\n      \"dependencies\": {\n        \"minimist\": \"^1.2.8\",\n      },\n    },\n  },\n  \"packages\": {\n    \"minimist\": [\"minimist@1.2.8\", \"\", {}, \"sha512-bbb\"],\n  }\n}\n";
const LOCK_ONLY: &str = "minimist|minimist|^1.2.0|^1.2.0|1.2.0|1.2.8";

/// A Bun whose `update` bumps `package.json` and the lock file to `lock`.
fn bun_update_writing(lock: &str) -> String {
    format!(
        "case \"$1\" in\n  --version) echo 1.4.4; exit 0;;\n  update)\n    printf '%s' '{PACKAGE_BUMPED}' > ROOT/package.json\n    cat > ROOT/bun.lock <<'EOF'\n{lock}EOF\n    exit 0;;\nesac\nexit 0\n"
    )
}

fn run_lock_only(body: &str) -> Ran {
    run(&Case {
        ecosystem: "npm",
        manifest: "package.json",
        files: vec![
            ("package.json", PACKAGE.as_bytes().to_vec()),
            ("bun.lock", LOCK_OLD.as_bytes().to_vec()),
        ],
        tools: vec![("bun", body)],
        mode: "lockonly",
        bumps: LOCK_ONLY,
        cooldown_fallback: false,
        unlistened: false,
    })
}

fn writing_calls(ran: &Ran) -> Vec<&String> {
    ran.calls_of("bun")
        .into_iter()
        .filter(|call| !call.starts_with("bun --version|"))
        .collect()
}

fn text(ran: &Ran, rel: &str) -> String {
    String::from_utf8(ran.read(rel)).expect("utf-8")
}

#[test]
fn bun_lock_only_pin_updates_then_restores_the_manifest_and_installs_again() {
    let body = bun_update_writing(LOCK_NEW);

    let ran = run_lock_only(&body);

    let calls = writing_calls(&ran);
    assert_eq!(calls.len(), 2, "{:?}", ran.calls);
    assert!(
        calls[0].starts_with("bun update --lockfile-only "),
        "{}",
        calls[0]
    );
    let update_args = calls[0].split('|').next().expect("argv");
    assert!(update_args.ends_with(" minimist"), "{update_args}");
    assert!(
        calls[1].starts_with("bun install --lockfile-only --ignore-scripts|"),
        "{}",
        calls[1]
    );
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert_eq!(text(&ran, "package.json"), PACKAGE);
    assert!(text(&ran, "bun.lock").contains("minimist@1.2.8"));
}

#[test]
fn bun_lock_only_pin_runs_in_the_manifest_directory() {
    let body = bun_update_writing(LOCK_NEW);

    let ran = run_lock_only(&body);

    for call in writing_calls(&ran) {
        let cwd = call.split('|').nth(1).expect("cwd field");
        assert_eq!(cwd, ran.root.display().to_string(), "{call}");
    }
    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
}

#[test]
fn bun_lock_only_update_failure_puts_manifest_and_lock_back() {
    let body = format!(
        "case \"$1\" in\n  --version) echo 1.4.4; exit 0;;\n  update) printf '%s' '{PACKAGE_BUMPED}' > ROOT/package.json; exit 3;;\nesac\nexit 0\n"
    );

    let ran = run_lock_only(&body);

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_eq!(text(&ran, "package.json"), PACKAGE);
    assert_eq!(text(&ran, "bun.lock"), LOCK_OLD);
}

#[test]
fn bun_lock_only_pin_the_lock_does_not_reach_is_a_version_mismatch_and_restores_both_files() {
    let body = bun_update_writing(LOCK_OLD);

    let ran = run_lock_only(&body);

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
    assert_eq!(text(&ran, "package.json"), PACKAGE);
    assert_eq!(text(&ran, "bun.lock"), LOCK_OLD);
}

#[test]
fn bun_lock_only_pin_is_no_longer_refused_as_unsupported() {
    let body = bun_update_writing(LOCK_NEW);

    let ran = run_lock_only(&body);

    assert!(
        !ran.outcome.contains("LockfileOnlyUpdateUnsupported"),
        "{}",
        ran.outcome
    );
    assert!(!writing_calls(&ran).is_empty(), "{:?}", ran.calls);
}

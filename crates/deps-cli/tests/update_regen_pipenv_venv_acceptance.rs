//! #2099 acceptance: Pipenv reads a `.venv` file or symlink as the path of a virtualenv whose
//! `python` it runs, so those are refused as `SavedVirtualenv` before any spawn; a `.venv`
//! directory is ignored under `PIPENV_VENV_IN_PROJECT=0` and must not be refused. The regular
//! file case lives in `update_lockers_pcd_acceptance.rs`.

#![cfg(all(unix, feature = "pypi"))]
#![expect(clippy::expect_used, reason = "test code")]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, outcome_of, prepare};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const PIPFILE: &str = "[packages]\nrequests = \">=2.0\"\n";
const LOCK_OLD: &str = "{\"_meta\": {\"pipfile-spec\": 6}, \"default\": {\"requests\": {\"version\": \"==2.0.0\"}}, \"develop\": {}}\n";
const LOCK_NEW: &str = "{\"_meta\": {\"pipfile-spec\": 6}, \"default\": {\"requests\": {\"version\": \"==2.31.0\"}}, \"develop\": {}}\n";

fn case<'a>(body: &'a str, extra: Vec<(&'a str, Vec<u8>)>) -> Case<'a> {
    let mut files = vec![
        ("Pipfile", PIPFILE.as_bytes().to_vec()),
        ("Pipfile.lock", LOCK_OLD.as_bytes().to_vec()),
    ];
    files.extend(extra);
    Case {
        ecosystem: "pypi",
        manifest: "Pipfile",
        files,
        tools: vec![("pipenv", body)],
        mode: "lockonly",
        bumps: "requests|requests|>=2.0|>=2.0|2.0.0|2.31.0",
        cooldown_fallback: false,
        unlistened: false,
    }
}

/// Runs the case after `setup` adjusted the prepared project; returns the outcome and calls.
fn run_after(case: &Case<'_>, setup: impl FnOnce(&harness::Project)) -> (String, Vec<String>) {
    let project = prepare(case);
    setup(&project);
    let output = project.child(case).output().expect("run the child test");
    assert!(
        output.status.success(),
        "child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        outcome_of(&String::from_utf8_lossy(&output.stdout)),
        project.calls(),
    )
}

#[test]
fn pipenv_with_a_venv_symlink_is_refused_as_a_saved_virtualenv_without_a_spawn() {
    let body = format!("cat > ROOT/Pipfile.lock <<'EOF'\n{LOCK_NEW}EOF\n");

    let (outcome, calls) = run_after(&case(&body, vec![]), |project| {
        std::os::unix::fs::symlink("elsewhere", project.root.join(".venv")).expect("symlink");
    });

    assert!(outcome.contains("SavedVirtualenv"), "{outcome}");
    assert!(calls.is_empty(), "{calls:?}");
}

#[test]
fn pipenv_with_a_venv_directory_is_not_refused_as_a_saved_virtualenv() {
    let body = format!("cat > ROOT/Pipfile.lock <<'EOF'\n{LOCK_NEW}EOF\n");

    let (outcome, calls) = run_after(&case(&body, vec![(".venv/pyvenv.cfg", vec![])]), |_| {});

    assert!(!outcome.contains("SavedVirtualenv"), "{outcome}");
    assert!(outcome.starts_with("Regenerated"), "{outcome}");
    assert!(!calls.is_empty(), "{calls:?}");
}

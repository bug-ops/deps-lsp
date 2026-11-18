//! #2099 acceptance (conditional on the S0 pipenv probe passing): `Pipfile.lock` regeneration
//! with Pipenv driven through fake tools in a re-executed test binary (see
//! `common/regen_harness.rs`).
//!
//! The exact argv of `pipenv` is decided by the live probe, so these tests pin only the
//! behavioural contract: a writing spawn happens, the Pipfile is never left changed, the lock
//! file is verified and restored on failure, and the cooldown-fallback refusal holds. Not covered
//! here: real flag acceptance and the churn behaviour of the real tool (live probes).

#![cfg(all(unix, feature = "pypi"))]
#![allow(clippy::expect_used)]

#[path = "common/regen_harness.rs"]
mod harness;

use harness::{Case, Ran, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const PIPFILE: &str = "[packages]\nrequests = \">=2.0\"\n";
const PIPFILE_EDITED: &str = "[packages]\nrequests = \">=2.31.0\"\n";
const PIPFILE_REWRITTEN: &str = "[packages]\nrequests = \"*\"\n";
const LOCK_OLD: &str = "{\"_meta\": {\"pipfile-spec\": 6}, \"default\": {\"requests\": {\"version\": \"==2.0.0\"}}, \"develop\": {}}\n";
const LOCK_NEW: &str = "{\"_meta\": {\"pipfile-spec\": 6}, \"default\": {\"requests\": {\"version\": \"==2.31.0\"}}, \"develop\": {}}\n";
const EDIT: &str = "requests|requests|>=2.0|>=2.31.0|2.0.0|2.31.0";
const LOCK_ONLY: &str = "requests|requests|>=2.0|>=2.0|2.0.0|2.31.0";

fn pipenv_case<'a>(body: &'a str, mode: &'a str, fallback: bool) -> Case<'a> {
    Case {
        ecosystem: "pypi",
        manifest: "Pipfile",
        files: vec![
            ("Pipfile", PIPFILE.as_bytes().to_vec()),
            ("Pipfile.lock", LOCK_OLD.as_bytes().to_vec()),
        ],
        tools: vec![("pipenv", body)],
        mode,
        bumps: if mode == "edit" { EDIT } else { LOCK_ONLY },
        cooldown_fallback: fallback,
        unlistened: false,
    }
}

fn writing_lock(lock: &str) -> String {
    format!("cat > ROOT/Pipfile.lock <<'EOF'\n{lock}EOF\n")
}

fn text(ran: &Ran, rel: &str) -> String {
    String::from_utf8(ran.read(rel)).expect("utf-8")
}

#[test]
fn pipenv_manifest_edit_regenerates_the_lock_file_and_keeps_the_edited_pipfile() {
    let body = writing_lock(LOCK_NEW);

    let ran = run(&pipenv_case(&body, "edit", false));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(!ran.calls_of("pipenv").is_empty(), "{:?}", ran.calls);
    assert!(text(&ran, "Pipfile.lock").contains("==2.31.0"));
    assert_eq!(text(&ran, "Pipfile"), PIPFILE_EDITED);
}

#[test]
fn pipenv_lock_only_pin_regenerates_the_lock_file() {
    let body = writing_lock(LOCK_NEW);

    let ran = run(&pipenv_case(&body, "lockonly", false));

    assert!(ran.outcome.starts_with("Regenerated"), "{}", ran.outcome);
    assert!(!ran.calls_of("pipenv").is_empty(), "{:?}", ran.calls);
    assert_eq!(text(&ran, "Pipfile"), PIPFILE);
}

#[test]
fn pipenv_rewriting_the_pipfile_never_leaves_it_changed() {
    let body = format!(
        "printf '%s' '{PIPFILE_REWRITTEN}' > ROOT/Pipfile\n{}",
        writing_lock(LOCK_NEW)
    );

    let ran = run(&pipenv_case(&body, "lockonly", false));

    assert!(ran.outcome.contains("ManifestChanged"), "{}", ran.outcome);
    assert_eq!(text(&ran, "Pipfile"), PIPFILE);
    assert_eq!(text(&ran, "Pipfile.lock"), LOCK_OLD);
}

#[test]
fn pipenv_failure_restores_the_lock_file() {
    let ran = run(&pipenv_case("exit 3", "lockonly", false));

    assert!(ran.outcome.contains("ToolFailed"), "{}", ran.outcome);
    assert_eq!(text(&ran, "Pipfile.lock"), LOCK_OLD);
    assert_eq!(text(&ran, "Pipfile"), PIPFILE);
}

#[test]
fn pipenv_lock_without_the_applied_target_is_a_version_mismatch_and_restored() {
    let body = writing_lock(&LOCK_NEW.replace("2.31.0", "2.30.0"));

    let ran = run(&pipenv_case(&body, "lockonly", false));

    assert!(ran.outcome.contains("VersionMismatch"), "{}", ran.outcome);
    assert_eq!(text(&ran, "Pipfile.lock"), LOCK_OLD);
}

#[test]
fn pipenv_cooldown_fallback_target_is_refused_before_any_spawn() {
    let body = writing_lock(LOCK_NEW);

    let ran = run(&pipenv_case(&body, "lockonly", true));

    assert!(
        ran.outcome.contains("CooldownFallbackTarget"),
        "{}",
        ran.outcome
    );
    assert!(ran.calls.is_empty(), "{:?}", ran.calls);
}

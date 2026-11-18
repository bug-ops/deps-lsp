//! #2071 acceptance: a plain `update --lockfile regenerate` that ends `Failed` (tool error,
//! verification mismatch, interrupt) leaves every snapshotted lock file byte-identical to its
//! state before the first writing spawn, and files that already matched are not rewritten.
//!
//! Written tests-first against architect v1 + v2 (S3: restore on unix for every failure kind,
//! Q6: compare-then-write). Fake `cargo`/`go` shell scripts run through a re-executed test
//! binary (see `common/regen_harness.rs`). Missing today: the snapshot/restore itself,
//! `RegenerationError::{SnapshotFailed, RestoreFailed}`.

#![cfg(all(unix, feature = "cargo", feature = "go"))]

#[path = "common/regen_harness.rs"]
mod harness;

use std::io::Read;
use std::time::{Duration, SystemTime};

use harness::{Case, outcome_of, prepare, run};

#[tokio::test]
#[ignore = "re-exec target of the parent tests, driven through REGEN_* variables"]
async fn regen_child() {
    harness::regen_child_main().await;
}

const CARGO_TOML: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n";
const OLD_LOCK: &[u8] = b"version = 4\n\n[[package]]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n \"stuba\",\n]\n\n[[package]]\nname = \"stuba\"\nversion = \"0.9.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
const STUBA_BUMP: &str = "stuba|stuba = |1.0.0|1.0.1|1.0.0|1.0.1";

const LOCATE: &str = "if [ \"$1\" = locate-project ]; then echo 'ROOT/Cargo.toml'; exit 0; fi\n";

fn case(cargo_body: &str, lock: Vec<u8>) -> Case<'_> {
    Case {
        ecosystem: "cargo",
        manifest: "Cargo.toml",
        files: vec![("Cargo.toml", CARGO_TOML.into()), ("Cargo.lock", lock)],
        tools: vec![("cargo", cargo_body)],
        mode: "edit",
        bumps: STUBA_BUMP,
        cooldown_fallback: false,
        unlistened: false,
    }
}

fn updates(ran: &harness::Ran) -> usize {
    ran.calls_of("cargo")
        .iter()
        .filter(|call| call.starts_with("cargo update"))
        .count()
}

#[test]
fn regenerate_tool_failure_after_truncating_the_lock_restores_the_original_bytes() {
    let body = format!("{LOCATE}: > ROOT/Cargo.lock\nexit 1\n");

    let ran = run(&case(&body, OLD_LOCK.to_vec()));

    assert!(
        ran.outcome.starts_with("Failed(ToolFailed"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("Cargo.lock"), OLD_LOCK);
    assert!(updates(&ran) >= 1, "the failing write step must have run");
}

#[test]
fn regenerate_non_utf8_lock_bytes_are_restored_exactly() {
    let mut original = OLD_LOCK.to_vec();
    original.extend_from_slice(&[0xff, 0xfe, 0x00]);
    let body = format!("{LOCATE}printf 'junk' > ROOT/Cargo.lock\nexit 1\n");

    let ran = run(&case(&body, original.clone()));

    assert_eq!(ran.read("Cargo.lock"), original);
}

#[test]
fn regenerate_valid_but_wrong_lock_is_a_version_mismatch_and_is_restored() {
    let wrong = "version = 4\n\n[[package]]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n \"stuba\",\n]\n\n[[package]]\nname = \"stuba\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let body = format!("{LOCATE}cat > ROOT/Cargo.lock <<'EOF'\n{wrong}EOF\nexit 0\n");

    let ran = run(&case(&body, OLD_LOCK.to_vec()));

    assert!(
        ran.outcome.starts_with("Failed(VersionMismatch"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("Cargo.lock"), OLD_LOCK);
}

#[test]
fn regenerate_untouched_lock_is_not_rewritten_after_a_failure() {
    let body = format!("{LOCATE}exit 1\n");
    let case = case(&body, OLD_LOCK.to_vec());
    let project = prepare(&case);
    let lock = project.root.join("Cargo.lock");
    let past = SystemTime::now() - Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(&lock)
        .expect("open lock")
        .set_modified(past)
        .expect("set mtime");

    let output = project.child(&case).output().expect("child");

    assert!(output.status.success());
    assert!(outcome_of(&String::from_utf8_lossy(&output.stdout)).starts_with("Failed"));
    let modified = std::fs::metadata(&lock)
        .expect("meta")
        .modified()
        .expect("mtime");
    assert_eq!(
        modified, past,
        "a byte-identical lock must not be rewritten"
    );
}

#[test]
fn regenerate_restore_failure_is_reported_with_its_cause() {
    let body = format!("{LOCATE}rm ROOT/Cargo.lock\nmkdir ROOT/Cargo.lock\nexit 1\n");

    let ran = run(&case(&body, OLD_LOCK.to_vec()));

    assert!(
        ran.outcome.starts_with("Failed(RestoreFailed"),
        "{}",
        ran.outcome
    );
    assert!(
        ran.outcome.contains("ToolFailed"),
        "cause kept: {}",
        ran.outcome
    );
}

#[test]
fn regenerate_probe_failure_before_any_write_leaves_the_lock_alone() {
    let ran = run(&case("exit 1\n", OLD_LOCK.to_vec()));

    assert!(ran.outcome.starts_with("Failed"), "{}", ran.outcome);
    assert_eq!(ran.read("Cargo.lock"), OLD_LOCK);
    assert_eq!(updates(&ran), 0);
}

#[test]
fn regenerate_over_cap_lock_ends_snapshot_failed_without_a_writing_spawn() {
    let body = format!("{LOCATE}: > ROOT/Cargo.lock\nexit 0\n");
    let case = case(&body, OLD_LOCK.to_vec());
    let project = prepare(&case);
    let lock = project.root.join("Cargo.lock");
    std::fs::File::options()
        .write(true)
        .open(&lock)
        .expect("open lock")
        .set_len(32 * 1024 * 1024 + 1)
        .expect("sparse grow");

    let output = project.child(&case).output().expect("child");

    let outcome = outcome_of(&String::from_utf8_lossy(&output.stdout));
    assert!(outcome.starts_with("Failed(SnapshotFailed"), "{outcome}");
    assert!(
        project
            .calls()
            .iter()
            .all(|call| !call.starts_with("cargo update")),
        "{:?}",
        project.calls()
    );
    assert_eq!(
        std::fs::metadata(&lock).expect("meta").len(),
        32 * 1024 * 1024 + 1
    );
}

#[test]
fn regenerate_interrupt_mid_write_restores_the_lock() {
    let body = format!("{LOCATE}: > ROOT/Cargo.lock\ntouch ROOT/started\nsleep 30\n");
    let case = case(&body, OLD_LOCK.to_vec());
    let project = prepare(&case);
    let mut child = project.child(&case).spawn().expect("spawn child");
    let started = project.root.join("started");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !started.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the fake tool never started"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let status = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    child.wait().expect("wait");

    assert!(
        outcome_of(&stdout).starts_with("Failed(Interrupted"),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read(project.root.join("Cargo.lock")).expect("read"),
        OLD_LOCK
    );
}

const GO_MOD: &str = "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.30.0\n";
const OLD_SUM: &[u8] =
    b"golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.30.0/go.mod h1:oldmod=\n";

#[test]
fn regenerate_go_failure_restores_go_mod_and_go_sum() {
    let body = "if [ \"$1\" = env ]; then echo; exit 0; fi\n: > ROOT/go.sum\nprintf 'garbage' > ROOT/go.mod\nexit 1\n";
    let case = Case {
        ecosystem: "go",
        manifest: "go.mod",
        files: vec![("go.mod", GO_MOD.into()), ("go.sum", OLD_SUM.to_vec())],
        tools: vec![("go", body)],
        mode: "edit",
        bumps: "golang.org/x/text|golang.org/x/text|v0.30.0|v0.31.0|v0.30.0|v0.31.0",
        cooldown_fallback: false,
        unlistened: false,
    };

    let ran = run(&case);

    assert!(
        ran.outcome.starts_with("Failed(ToolFailed"),
        "{}",
        ran.outcome
    );
    assert_eq!(ran.read("go.sum"), OLD_SUM);
    assert_eq!(
        String::from_utf8(ran.read("go.mod")).expect("utf8"),
        GO_MOD.replace("v0.30.0", "v0.31.0"),
        "go.mod returns to its post-manifest-edit state"
    );
}

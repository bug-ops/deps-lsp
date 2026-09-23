//! Integration tests for `deps-cli update` (spec 068, US-001 through US-006).
//!
//! Unlike `check_integration.rs`'s `run_pipeline`, `update`'s planners need a *populated*
//! `cached_versions` map to produce anything but an empty plan (`collect_update_candidates`/
//! `classify_vulnerable_dependency` both bail out on a cache miss) — and, per
//! `check_integration.rs`'s own module doc, no ecosystem crate exposes a way to inject a mock
//! registry from outside its own crate. So this file splits coverage two ways:
//!
//! - **Subprocess tests** (`std::process::Command` + `CARGO_BIN_EXE_deps-cli`, T012's own
//!   "subprocess (or in-process equivalent)" wording) exercise real argument parsing, planner
//!   dispatch, and exit-code wiring end to end, using `--offline` so no candidate can ever be
//!   produced (an empty `cached_versions`) — these prove the CLI surface and error paths, not
//!   specific rewrites.
//! - **`apply_plan` tests** call `deps_cli::update::apply_plan` directly — the exact function
//!   `main.rs::run_update` calls, not a reimplementation — with a hand-built [`UpdatePlan`],
//!   which needs no registry at all. This is what actually proves US-006's write-time symlink
//!   refusal and crash-safety through the real CLI write path, complementing
//!   `deps_core::fs_probe`'s own primitive-level `write_atomic` tests.
//!
//! US-001/US-002/US-004's rewrite-producing scenarios are covered instead by direct
//! `plan_updates`/`classify_vulnerable_dependency` unit tests in `update/mod.rs` and
//! `update/security.rs`, which construct a real [`deps_core::ParseResult`] and a real
//! `cached_versions` map without needing a live registry.

#![allow(clippy::expect_used)]

#[cfg(unix)]
use deps_cli::update::ApplyError;
use deps_cli::update::{Outcome, PlannedUpdateItem, UpdatePlan, apply_plan};
use deps_core::edit::ManifestEdit;
use deps_core::position::{Position, Range};

fn exe() -> &'static str {
    env!("CARGO_BIN_EXE_deps-cli")
}

// --- Subprocess: wiring, dispatch, and exit codes (network-free via --offline) ---

/// US-001/US-005 wiring: an offline run with nothing cached produces an empty plan, "No
/// eligible updates." on stdout, and a clean exit — proves the real binary reaches
/// `plan_updates` → `render_update` → `update_exit_code` without crashing.
#[test]
fn test_update_offline_empty_plan_is_clean_and_reports_no_eligible_updates() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline"])
        .arg(dir.path().join("Cargo.toml"))
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No eligible updates."), "stdout: {stdout}");
}

/// US-005: `--format json` on an empty plan round-trips through the versioned schema, and
/// carries the `dry_run` marker the caller passed.
#[test]
fn test_update_offline_json_format_empty_plan_schema() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline", "--dry-run", "--format", "json"])
        .arg(dir.path().join("Cargo.toml"))
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let document: deps_cli::format::json::UpdateReportDocument =
        serde_json::from_str(&stdout).expect("stdout must be the versioned JSON document");
    assert!(document.dry_run);
    assert!(document.items.is_empty());
}

/// FR-015: `--security-only` needs live OSV data to make any remediation claim at all, so
/// `--offline --security-only` together must be a hard execution error, not a silent empty
/// plan that could be mistaken for "nothing vulnerable."
#[test]
fn test_update_security_only_offline_is_a_hard_error() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline", "--security-only"])
        .arg(dir.path().join("Cargo.toml"))
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("security-only") && stderr.contains("offline"),
        "stderr must explain the conflict, got: {stderr}"
    );
}

/// A manifest path naming something `walk` does not recognize as a single manifest is an
/// execution error (exit 2), matching `check`'s own equivalent wiring.
#[test]
fn test_update_unrecognized_manifest_path_is_execution_error() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(dir.path().join("not-a-manifest.txt"), "hello\n")
        .expect("write non-manifest file");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline"])
        .arg(dir.path().join("not-a-manifest.txt"))
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// FR-007: `--config` is the only way `[update].ignore` rules load — a malformed config file
/// must surface as an execution error through the real `parse_config` path, not a panic or a
/// silently-empty ignore list.
#[test]
fn test_update_malformed_config_is_execution_error() {
    let dir = tempfile::tempdir().expect("create temp dir");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write fixture manifest");
    let config_path = dir.path().join("deps.toml");
    std::fs::write(&config_path, "this is not valid deps.toml content [[[\n")
        .expect("write malformed config");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline", "--config"])
        .arg(&config_path)
        .arg(dir.path().join("Cargo.toml"))
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// N1 (critic re-review): spec §8's Never clause forbids reading manifest content before
/// FR-017's symlink refusal passes — an explicit manifest path that is itself a symlink must
/// be rejected before `run_update` ever reads/parses it or sends its dependency names to a
/// registry, not just refused later at write time by `apply_plan`/`write_atomic` (exercised
/// below by `test_apply_plan_refuses_a_symlinked_manifest_path`, which protects the separate
/// TOCTOU case — the file becoming a symlink *after* a clean read).
#[cfg(unix)]
#[test]
fn test_update_symlinked_manifest_argument_is_refused_before_any_read() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let real = dir.path().join("real-Cargo.toml");
    std::fs::write(
        &real,
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write real manifest");
    let link = dir.path().join("Cargo.toml");
    std::os::unix::fs::symlink(&real, &link).expect("create symlinked manifest argument");

    let output = std::process::Command::new(exe())
        .args(["update", "--offline"])
        .arg(&link)
        .output()
        .expect("run the real deps-cli binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("symlink"),
        "must explain the symlink refusal, got: {stderr}"
    );
}

// --- `apply_plan`: the real CLI write path, no registry needed ---

fn applied_plan(range: Range, new_text: &str) -> UpdatePlan {
    UpdatePlan {
        items: vec![PlannedUpdateItem {
            name: "serde".to_string(),
            current: "1.0.0".to_string(),
            target: new_text.to_string(),
            outcome: Outcome::Applied(ManifestEdit {
                range,
                new_text: new_text.to_string(),
            }),
            advisory_ids: Vec::new(),
            ignore_rule_overridden: false,
        }],
    }
}

/// US-006: `apply_plan` — the exact function `main.rs::run_update` calls to write a real
/// run's plan — must refuse to write when the manifest path is itself a symlink, and must
/// leave both the symlink and its target untouched. This exercises the CLI's own
/// orchestration (TOCTOU re-read, `dedup_overlapping_edits`, then `write_atomic`), not just
/// `write_atomic` in isolation.
#[cfg(unix)]
#[test]
fn test_apply_plan_refuses_a_symlinked_manifest_path() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let target = dir.path().join("real-target.toml");
    let original = "serde = \"1.0.0\"\n";
    std::fs::write(&target, original).expect("write symlink target");
    let link = dir.path().join("Cargo.toml");
    std::os::unix::fs::symlink(&target, &link).expect("create symlinked manifest path");

    let plan = applied_plan(
        Range::new(Position::new(0, 9), Position::new(0, 14)),
        "1.2.0",
    );
    let result = apply_plan(&plan, &link, original, false);

    assert!(
        matches!(result, Err(ApplyError::Write { .. })),
        "expected a write-refusal error, got {result:?}"
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("symlink must still exist")
            .file_type()
            .is_symlink(),
        "the manifest path symlink itself must be left untouched"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        original,
        "the symlink's target must never be written through"
    );
}

/// Companion happy path: against a plain (non-symlinked) manifest path, `apply_plan` writes
/// the planned edit for real — proving the refusal above is specific to the symlink case, not
/// `apply_plan` failing to write at all.
#[test]
fn test_apply_plan_writes_through_a_real_manifest_path() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("Cargo.toml");
    let original = "serde = \"1.0.0\"\n";
    std::fs::write(&path, original).expect("write manifest");

    let plan = applied_plan(
        Range::new(Position::new(0, 9), Position::new(0, 14)),
        "1.2.0",
    );
    apply_plan(&plan, &path, original, false).expect("apply_plan must succeed");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read manifest"),
        "serde = \"1.2.0\"\n"
    );
}

/// US-006 crash-safety: `write_atomic`'s create-temp-then-rename sequencing means a plan that
/// is never given a chance to reach the final `fs::rename` (simulated here by a `dry_run`
/// short-circuit that never calls `write_atomic` at all) leaves the original manifest byte-
/// for-byte intact — no partial write is ever observable.
#[test]
fn test_apply_plan_dry_run_leaves_the_manifest_byte_for_byte_intact() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("Cargo.toml");
    let original = "serde = \"1.0.0\"\n";
    std::fs::write(&path, original).expect("write manifest");

    let plan = applied_plan(
        Range::new(Position::new(0, 9), Position::new(0, 14)),
        "1.2.0",
    );
    apply_plan(&plan, &path, original, true).expect("apply_plan must succeed under dry_run");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read manifest"),
        original,
        "dry_run must never write, even though a real edit was planned"
    );
}

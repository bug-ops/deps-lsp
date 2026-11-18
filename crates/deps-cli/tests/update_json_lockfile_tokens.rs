//! #2071 / #2046 / #2047: JSON wire tokens of the lockfile section for the new refusal and failure
//! kinds (`yarn-classic`, `python-locker-deferred`, `snapshot-failed`, `restore-failed`).
//! The token spellings are a public contract, so they are pinned. Values are compared as
//! `serde_json::Value`, because key order depends on serde_json's `preserve_order` feature, which
//! only some feature combinations enable.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use deps_cli::format::DryRun;
use deps_cli::format::json::update_to_document;
use deps_cli::update::regen::{
    LockfileOutcome, Program, PythonLocker, RegenerationError, UnsupportedReason,
};
use deps_cli::update::{UpdatePlan, UpdateRun};
use serde_json::json;

fn lockfile_json(lockfile: LockfileOutcome) -> serde_json::Value {
    let run = UpdateRun {
        plan: UpdatePlan::default(),
        lockfile,
    };
    let document = serde_json::to_value(update_to_document(&run, DryRun::No)).expect("serialize");
    document.get("lockfile").cloned().expect("lockfile section")
}

#[test]
fn yarn_classic_token() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::YarnClassic,
        }),
        json!({
            "status": "unsupported",
            "reason": "yarn-classic",
            "path": null,
            "detail": null
        })
    );
}

#[test]
fn python_locker_deferred_token() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::PythonLockerDeferred(PythonLocker::Poetry),
        }),
        json!({
            "status": "unsupported",
            "reason": "python-locker-deferred",
            "path": null,
            "detail": "poetry"
        })
    );
}

#[test]
fn snapshot_failed_token() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Failed(RegenerationError::SnapshotFailed {
            path: PathBuf::from("Cargo.lock"),
        })),
        json!({
            "status": "failed",
            "kind": "snapshot-failed",
            "message": "could not snapshot Cargo.lock before regeneration",
            "package": null,
            "expected": null,
            "found": null
        })
    );
}

#[test]
fn restore_failed_token_keeps_the_cause_message() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Failed(RegenerationError::RestoreFailed {
            cause: Box::new(RegenerationError::ToolFailed {
                program: Program::Cargo,
                code: Some(101),
            }),
            path: PathBuf::from("Cargo.lock"),
            source: std::io::Error::other("denied"),
        })),
        json!({
            "status": "failed",
            "kind": "restore-failed",
            "message": "cargo exited with status 101; restoring Cargo.lock failed: denied",
            "package": null,
            "expected": null,
            "found": null
        })
    );
}

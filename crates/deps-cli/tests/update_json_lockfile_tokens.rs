//! #2071 / #2046 / #2047: JSON wire tokens of the lockfile section for the new refusal and failure
//! kinds (`yarn-classic`, `python-locker-deferred`, `snapshot-failed`, `restore-failed`).
//! The token spellings are a public contract, so they are pinned as snapshots.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use deps_cli::format::DryRun;
use deps_cli::format::json::update_to_document;
use deps_cli::update::regen::{
    LockfileOutcome, Program, PythonLocker, RegenerationError, UnsupportedReason,
};
use deps_cli::update::{UpdatePlan, UpdateRun};

fn lockfile_json(lockfile: LockfileOutcome) -> serde_json::Value {
    let run = UpdateRun {
        plan: UpdatePlan::default(),
        lockfile,
    };
    let document = serde_json::to_value(update_to_document(&run, DryRun::No)).expect("serialize");
    document.get("lockfile").cloned().expect("lockfile section")
}

#[test]
fn yarn_classic_token_snapshot() {
    insta::assert_json_snapshot!(lockfile_json(LockfileOutcome::Unsupported {
        lockfile: None,
        reason: UnsupportedReason::YarnClassic,
    }));
}

#[test]
fn python_locker_deferred_token_snapshot() {
    insta::assert_json_snapshot!(lockfile_json(LockfileOutcome::Unsupported {
        lockfile: None,
        reason: UnsupportedReason::PythonLockerDeferred(PythonLocker::Poetry),
    }));
}

#[test]
fn snapshot_failed_token_snapshot() {
    insta::assert_json_snapshot!(lockfile_json(LockfileOutcome::Failed(
        RegenerationError::SnapshotFailed {
            path: PathBuf::from("Cargo.lock"),
        }
    )));
}

#[test]
fn restore_failed_token_snapshot_keeps_the_cause_message() {
    insta::assert_json_snapshot!(lockfile_json(LockfileOutcome::Failed(
        RegenerationError::RestoreFailed {
            cause: Box::new(RegenerationError::ToolFailed {
                program: Program::Cargo,
                code: Some(101),
            }),
            path: PathBuf::from("Cargo.lock"),
            source: std::io::Error::other("denied"),
        }
    )));
}

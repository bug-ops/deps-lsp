//! #2071 / #2046 / #2047 / #2088: JSON wire tokens of the lockfile section for the refusal and
//! failure kinds (`yarn-classic`, `python-locker-deferred`, `snapshot-failed`, `restore-failed`,
//! the containment, lock-set and lock-only refusals, and the fallback and manifest failures).
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
use deps_core::{ConcreteVersion, PackageName};
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

#[test]
fn new_unsupported_reasons_serialize_their_wire_tokens() {
    for (reason, token, detail) in [
        (
            UnsupportedReason::LockfileOutsideRepository,
            "lockfile-outside-repository",
            json!(null),
        ),
        (
            UnsupportedReason::LegacyLockLayout,
            "legacy-lock-layout",
            json!(null),
        ),
        (
            UnsupportedReason::CentralPackageVersions,
            "central-package-versions",
            json!(null),
        ),
        (
            UnsupportedReason::LockfileSetTooLarge,
            "lockfile-set-too-large",
            json!(null),
        ),
        (
            UnsupportedReason::LockfileOnlyUpdateUnsupported(Program::Dotnet),
            "lockfile-only-update-unsupported",
            json!("dotnet"),
        ),
        (
            UnsupportedReason::ToolTooOld(Program::Poetry),
            "tool-too-old",
            json!("poetry"),
        ),
    ] {
        assert_eq!(
            lockfile_json(LockfileOutcome::Unsupported {
                lockfile: None,
                reason,
            }),
            json!({
                "status": "unsupported",
                "reason": token,
                "path": null,
                "detail": detail
            })
        );
    }
}

#[test]
fn fallback_pin_rejected_token_names_the_exit_code() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Failed(
            RegenerationError::FallbackPinRejected {
                package: PackageName::new("serde"),
                target: ConcreteVersion::from("1.0.1"),
                code: Some(101),
            }
        )),
        json!({
            "status": "failed",
            "kind": "fallback-pin-rejected",
            "message": "serde could not be pinned to the cooldown-fallback target 1.0.1 (tool exited with status 101): a dependent may require a newer version, or the version or registry is unavailable",
            "package": null,
            "expected": null,
            "found": null
        })
    );
}

#[test]
fn manifest_changed_token() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Failed(
            RegenerationError::ManifestChanged {
                path: PathBuf::from("package.json"),
            }
        )),
        json!({
            "status": "failed",
            "kind": "manifest-changed",
            "message": "package.json changed during regeneration",
            "package": null,
            "expected": null,
            "found": null
        })
    );
}

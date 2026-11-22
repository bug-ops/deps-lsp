//! #2071 / #2046 / #2047 / #2088: JSON wire tokens of the lockfile section for the refusal and
//! failure kinds (`yarn-classic`, `snapshot-failed`, `restore-failed`,
//! the containment, lock-set and lock-only refusals, and the fallback and manifest failures).
//! The token spellings are a public contract, so they are pinned. Values are compared as
//! `serde_json::Value`, because key order depends on serde_json's `preserve_order` feature, which
//! only some feature combinations enable.

#![expect(clippy::expect_used, reason = "test code")]

use std::path::PathBuf;

use deps_cli::format::DryRun;
use deps_cli::format::json::update_to_document;
use deps_cli::update::regen::{
    HeldVersion, LegacyLayoutConflict, LockfileOutcome, Program, RegenerationError,
    UnsupportedReason,
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
fn saved_virtualenv_token() {
    assert_eq!(
        lockfile_json(LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::SavedVirtualenv,
        }),
        json!({
            "status": "unsupported",
            "reason": "saved-virtualenv",
            "path": null,
            "detail": null
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
            UnsupportedReason::LegacyLockLayout(LegacyLayoutConflict::BesideUnifiedLock),
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
        (
            UnsupportedReason::OtherFloatingRequirements,
            "other-floating-requirements",
            json!(null),
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

fn held(package: &str, version: &str) -> HeldVersion {
    HeldVersion {
        package: PackageName::new(package),
        version: ConcreteVersion::from(version),
        target: ConcreteVersion::from("1.0.0"),
    }
}

#[test]
fn cooldown_held_version_lists_every_held_pin_first_included() {
    let document = lockfile_json(LockfileOutcome::Failed(
        RegenerationError::CooldownHeldVersion {
            first: held("react", "16.2.0"),
            rest: vec![held("lodash", "4.17.22")],
        },
    ));

    assert_eq!(document["package"], json!("react"));
    assert_eq!(document["found"], json!("16.2.0"));
    assert_eq!(
        document["held"],
        json!([
            {"package": "react", "found": "16.2.0"},
            {"package": "lodash", "found": "4.17.22"}
        ])
    );
}

#[test]
fn held_is_omitted_for_every_other_failure_kind() {
    let document = lockfile_json(LockfileOutcome::Failed(RegenerationError::SnapshotFailed {
        path: PathBuf::from("Cargo.lock"),
    }));

    assert!(document.get("held").is_none(), "{document}");
}

//! #2104 / #2097 acceptance: JSON wire tokens and messages of the new `RegenerationError::Io` and
//! `RegenerationError::FallbackPinNotKept` failures (plan rev 2, W0 types).
//!
//! The verb phrase of `IoOperation` is not pinned (only that it is a non-empty, distinct phrase
//! per operation); the `kind` tokens `io` and `fallback-pin-not-kept` are the wire contract.

#![expect(clippy::expect_used, reason = "test code")]

use std::collections::HashSet;
use std::path::PathBuf;

use deps_cli::format::DryRun;
use deps_cli::format::json::update_to_document;
use deps_cli::update::regen::{IoOperation, LockfileOutcome, RegenerationError, RekeyRefusal};
use deps_cli::update::{UpdatePlan, UpdateRun};
use deps_core::{ConcreteVersion, PackageName};

const OPERATIONS: [IoOperation; 6] = [
    IoOperation::WriteExactPinManifest,
    IoOperation::WriteBackManifest,
    IoOperation::RewriteLockfile,
    IoOperation::CreateScratchDirectory,
    IoOperation::MoveVendorAside,
    IoOperation::MoveVendorIntoPlace,
];

const REFUSALS: [RekeyRefusal; 4] = [
    RekeyRefusal::PinnedEntryMissing,
    RekeyRefusal::PinnedEntryAmbiguous,
    RekeyRefusal::DeclaredRangeAlreadyLocked,
    RekeyRefusal::UnparsableLock,
];

fn lockfile_json(error: RegenerationError) -> serde_json::Value {
    let run = UpdateRun {
        plan: UpdatePlan::default(),
        lockfile: LockfileOutcome::Failed(error),
    };
    let document = serde_json::to_value(update_to_document(&run, DryRun::No)).expect("serialize");
    document.get("lockfile").cloned().expect("lockfile section")
}

fn io_error(operation: IoOperation) -> RegenerationError {
    RegenerationError::Io {
        operation,
        path: PathBuf::from("package.json"),
        source: std::io::Error::other("denied"),
    }
}

fn not_kept(reason: RekeyRefusal) -> RegenerationError {
    RegenerationError::FallbackPinNotKept {
        package: PackageName::new("minimist"),
        target: ConcreteVersion::from("1.2.8"),
        path: PathBuf::from("yarn.lock"),
        reason,
    }
}

#[test]
fn io_failure_serializes_the_io_token_with_the_path_and_cause() {
    let json = lockfile_json(io_error(IoOperation::WriteExactPinManifest));

    assert_eq!(json["status"], "failed");
    assert_eq!(json["kind"], "io");
    assert_eq!(json["package"], serde_json::Value::Null);
    assert_eq!(json["expected"], serde_json::Value::Null);
    assert_eq!(json["found"], serde_json::Value::Null);
    let message = json["message"].as_str().expect("message");
    assert!(message.starts_with("could not "), "{message}");
    assert!(message.contains("package.json"), "{message}");
    assert!(message.contains("denied"), "{message}");
}

#[test]
fn io_operation_names_are_distinct_phrases_in_the_message() {
    let phrases: HashSet<String> = OPERATIONS
        .into_iter()
        .map(|operation| operation.to_string())
        .collect();

    assert_eq!(phrases.len(), OPERATIONS.len(), "{phrases:?}");
    assert!(phrases.iter().all(|phrase| !phrase.is_empty()));
    for operation in OPERATIONS {
        let phrase = operation.to_string();
        let message = io_error(operation).to_string();
        assert!(message.contains(&phrase), "{message}");
        assert!(!message.contains("manifest changed"), "{message}");
        assert!(!message.contains("failed to start"), "{message}");
    }
}

#[test]
fn fallback_pin_not_kept_serializes_its_token_and_names_package_target_lock_and_reason() {
    let json = lockfile_json(not_kept(RekeyRefusal::PinnedEntryMissing));

    assert_eq!(json["status"], "failed");
    assert_eq!(json["kind"], "fallback-pin-not-kept");
    assert_eq!(json["package"], serde_json::Value::Null);
    assert_eq!(json["expected"], serde_json::Value::Null);
    assert_eq!(json["found"], serde_json::Value::Null);
    let message = json["message"].as_str().expect("message");
    for needle in ["minimist", "1.2.8", "yarn.lock"] {
        assert!(message.contains(needle), "{needle} in {message}");
    }
}

#[test]
fn fallback_pin_not_kept_message_differs_per_refusal_reason() {
    let messages: HashSet<String> = REFUSALS
        .into_iter()
        .map(|reason| not_kept(reason).to_string())
        .collect();

    assert_eq!(messages.len(), REFUSALS.len(), "{messages:?}");
}

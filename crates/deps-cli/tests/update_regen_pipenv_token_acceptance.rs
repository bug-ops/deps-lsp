//! #2099 acceptance (conditional on the S0 pipenv probe passing): `Program::Pipenv` has the
//! `pipenv` wire token, so a too-old Pipenv is reported like the other lockers.

#![allow(clippy::expect_used)]

use deps_cli::format::DryRun;
use deps_cli::format::json::update_to_document;
use deps_cli::update::regen::{LockfileOutcome, Program, UnsupportedReason};
use deps_cli::update::{UpdatePlan, UpdateRun};
use serde_json::json;

#[test]
fn pipenv_tool_too_old_serializes_the_pipenv_detail_token() {
    let run = UpdateRun {
        plan: UpdatePlan::default(),
        lockfile: LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::ToolTooOld(Program::Pipenv),
        },
    };

    let document = serde_json::to_value(update_to_document(&run, DryRun::No)).expect("serialize");

    assert_eq!(
        document["lockfile"],
        json!({
            "status": "unsupported",
            "reason": "tool-too-old",
            "path": null,
            "detail": "pipenv"
        })
    );
}

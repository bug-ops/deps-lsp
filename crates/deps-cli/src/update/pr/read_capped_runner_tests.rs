//! #2155: `Runner::run` reports `truncated` only when output exceeds the step's cap, not when it
//! exactly fills it. Driven by a fake `gh` that prints a fixed number of bytes.

#![cfg(unix)]
#![expect(clippy::expect_used, reason = "test code")]

use std::os::unix::fs::PermissionsExt;

use super::git::{Runner, Step, Tool};
use crate::update::regen::ProcessGroup;

/// `LIST_REQUESTS_CAP`, restated as a literal so the test also pins the cap.
const LIST_REQUESTS_CAP: u64 = 8 * 1024 * 1024;

async fn run_listing(printed: u64) -> super::git::StepOutput {
    let tools = tempfile::tempdir().expect("tempdir");
    let script = tools.path().join("gh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nhead -c {printed} /dev/zero | tr '\\0' x\n"),
    )
    .expect("write shim");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let runner = Runner {
        group: ProcessGroup::Own,
        tool_dir: Some(tools.path().to_path_buf()),
    };
    runner
        .run(Tool::Gh, Step::ListRequests, tools.path(), ["list"])
        .await
        .expect("run")
}

#[tokio::test]
async fn runner_run_output_of_exactly_the_cap_is_not_truncated() {
    let output = run_listing(LIST_REQUESTS_CAP).await;
    assert!(!output.truncated);
    assert_eq!(output.raw.len() as u64, LIST_REQUESTS_CAP);
}

#[tokio::test]
async fn runner_run_output_one_byte_over_the_cap_is_truncated() {
    let output = run_listing(LIST_REQUESTS_CAP + 1).await;
    assert!(output.truncated);
    assert_eq!(output.raw.len() as u64, LIST_REQUESTS_CAP);
}

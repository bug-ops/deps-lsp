//! Acceptance tests for #2048 (a timed-out or dropped regeneration must not leave the tool's
//! process tree running), written tests-first against plan revision 3
//! (`.local/handoff/2026-11-18T00-57-21-architect.md`, M1/M3/M11).
//!
//! Drives `ToolRunner::run` with a shim tool that leaves a `sleep` tree behind, for both
//! `ProcessGroup::Own` (the whole group is killed) and `ProcessGroup::Inherit` (the leader is).
//!
//! #2066 adds the termination protocol: SIGTERM first, a grace period of `TERMINATION_GRACE` that
//! ends early when the leader exits (the leader is never reaped by the guard), then an
//! unconditional SIGKILL to the whole group (`Own`) or the leader (`Inherit`). Shims that must
//! outlive a TERM use `sleep N & wait` so the shell's trap runs promptly.
//!
//! The foreground-group predicate and the interrupt path are covered in `tests.rs`; the guard's
//! no-kill-after-reap case has no test.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::time::Instant as TokioInstant;

use super::RegenerationError;
use super::command::Invocation;
use super::run::{ProcessGroup, SearchPath, TERMINATION_GRACE, ToolRunner};

/// A `npm` shim that records its own pid and a `sleep` grandchild's pid, then blocks.
struct SleepingTool {
    dir: tempfile::TempDir,
}

impl SleepingTool {
    fn new() -> Self {
        Self::with_script(|dir| {
            format!(
                "#!/bin/sh\necho $$ > '{leader}'\nsleep 30 &\necho $! > '{grandchild}'\nsleep 30 &\necho $! > '{sibling}'\nwait\n",
                leader = dir.join("leader.pid").display(),
                grandchild = dir.join("grandchild.pid").display(),
                sibling = dir.join("sibling.pid").display(),
            )
        })
    }

    /// An `npm` shim whose script body is built from the shim directory.
    fn with_script(script: impl FnOnce(&Path) -> String) -> Self {
        let dir = tempfile::tempdir().expect("bin dir");
        let script = script(dir.path());
        let path = dir.path().join("npm");
        std::fs::write(&path, script).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    fn runner(&self, deadline: Duration, group: ProcessGroup) -> ToolRunner {
        ToolRunner {
            deadline,
            search_path: SearchPath::Override(self.dir.path().as_os_str().to_owned()),
            group,
        }
    }

    fn pid(&self, file: &str) -> u32 {
        let path: PathBuf = self.dir.path().join(file);
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("{file} was never written");
    }
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Polls until `pid` is gone or `within` passes; async so tokio can reap the killed child.
async fn gone_within(pid: u32, within: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < within {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    !alive(pid)
}

fn invocation(cwd: &Path) -> Invocation {
    Invocation::npm_lock(cwd)
}

#[tokio::test]
async fn test_run_timeout_with_own_group_kills_leader_and_grandchild() {
    let tool = SleepingTool::new();
    let runner = tool.runner(Duration::from_millis(300), ProcessGroup::Own);
    let cwd = tempfile::tempdir().expect("cwd");

    let result = runner
        .run(
            &invocation(cwd.path()),
            TokioInstant::now() + Duration::from_millis(300),
        )
        .await;

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    let leader = tool.pid("leader.pid");
    let grandchild = tool.pid("grandchild.pid");
    assert!(
        gone_within(leader, Duration::from_secs(2)).await,
        "leader {leader} survived"
    );
    assert!(
        gone_within(grandchild, Duration::from_secs(2)).await,
        "grandchild {grandchild} survived the group kill"
    );
}

#[tokio::test]
async fn test_run_dropped_future_with_own_group_kills_the_whole_tree() {
    let tool = SleepingTool::new();
    let runner = tool.runner(Duration::from_secs(60), ProcessGroup::Own);
    let cwd = tempfile::tempdir().expect("cwd");
    let invocation = invocation(cwd.path());

    let outcome = tokio::time::timeout(
        Duration::from_millis(400),
        runner.run(&invocation, TokioInstant::now() + Duration::from_secs(60)),
    )
    .await;

    assert!(
        outcome.is_err(),
        "the shim blocks, so the outer timeout drops the future"
    );
    let leader = tool.pid("leader.pid");
    let grandchild = tool.pid("grandchild.pid");
    assert!(
        gone_within(leader, Duration::from_secs(2)).await,
        "leader {leader}"
    );
    assert!(
        gone_within(grandchild, Duration::from_secs(2)).await,
        "grandchild {grandchild}"
    );
}

#[tokio::test]
async fn test_run_timeout_with_inherit_group_kills_at_least_the_leader() {
    let tool = SleepingTool::new();
    let runner = tool.runner(Duration::from_millis(300), ProcessGroup::Inherit);
    let cwd = tempfile::tempdir().expect("cwd");

    let result = runner
        .run(
            &invocation(cwd.path()),
            TokioInstant::now() + Duration::from_millis(300),
        )
        .await;

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    let leader = tool.pid("leader.pid");
    assert!(
        gone_within(leader, Duration::from_secs(2)).await,
        "leader {leader}"
    );
    // The documented limit: an inherited group is not signalled, so the grandchild may live on.
    for file in ["grandchild.pid", "sibling.pid"] {
        let pid = tool.pid(file);
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        let _ = gone_within(pid, Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn test_run_normal_exit_does_not_signal_unrelated_processes() {
    let dir = tempfile::tempdir().expect("bin dir");
    let path = dir.path().join("npm");
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let runner = ToolRunner {
        deadline: Duration::from_secs(10),
        search_path: SearchPath::Override(dir.path().as_os_str().to_owned()),
        group: ProcessGroup::Own,
    };
    let cwd = tempfile::tempdir().expect("cwd");

    let result = runner
        .run(
            &invocation(cwd.path()),
            TokioInstant::now() + Duration::from_secs(10),
        )
        .await;

    assert!(result.is_ok(), "{result:?}");
}

/// A shim that traps TERM (marker file), records its pid and a `sleep` grandchild, and waits.
fn term_trapping_tool() -> SleepingTool {
    SleepingTool::with_script(|dir| {
        format!(
            "#!/bin/sh\ntrap 'echo t > {marker}; exit 0' TERM\necho $$ > {leader}\nsleep 30 &\necho $! > {grandchild}\nwait\n",
            marker = dir.join("marker").display(),
            leader = dir.join("leader.pid").display(),
            grandchild = dir.join("grandchild.pid").display(),
        )
    })
}

async fn run_to_timeout(
    tool: &SleepingTool,
    group: ProcessGroup,
) -> (TokioInstant, Result<(), RegenerationError>) {
    let runner = tool.runner(Duration::from_millis(500), group);
    let cwd = tempfile::tempdir().expect("cwd");
    let deadline = TokioInstant::now() + Duration::from_millis(500);
    let result = runner.run(&invocation(cwd.path()), deadline).await;
    (deadline, result)
}

fn kill_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status();
}

#[tokio::test]
async fn test_run_timeout_with_own_group_sends_term_before_kill() {
    let tool = term_trapping_tool();

    let (_, result) = run_to_timeout(&tool, ProcessGroup::Own).await;

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    assert!(
        tool.dir.path().join("marker").exists(),
        "the leader's TERM trap never ran: the group was killed without a TERM"
    );
    let grandchild = tool.pid("grandchild.pid");
    assert!(
        gone_within(grandchild, Duration::from_secs(2)).await,
        "grandchild {grandchild} survived the group KILL that follows the grace period"
    );
}

#[tokio::test]
async fn test_run_timeout_with_inherit_group_sends_term_to_the_leader() {
    let tool = term_trapping_tool();

    let (_, result) = run_to_timeout(&tool, ProcessGroup::Inherit).await;

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    kill_pid(tool.pid("grandchild.pid"));
    assert!(
        tool.dir.path().join("marker").exists(),
        "the leader's TERM trap never ran: an inherited-group leader was killed without a TERM"
    );
    let leader = tool.pid("leader.pid");
    assert!(
        gone_within(leader, Duration::from_secs(2)).await,
        "leader {leader}"
    );
}

/// #2066 S1: a leader that exits on TERM must not end the wait early at the cost of a
/// TERM-ignoring descendant; the group KILL still reaches it, and the return is prompt.
#[tokio::test]
async fn test_run_timeout_leader_exits_on_term_returns_early_and_kills_term_ignoring_grandchild() {
    let tool = SleepingTool::with_script(|dir| {
        format!(
            r#"#!/bin/sh
trap 'echo t > {marker}; exit 0' TERM
echo $$ > {leader}
sh -c 'trap "" TERM; echo $$ > {gc}; exec sleep 30' &
wait
"#,
            marker = dir.join("marker").display(),
            leader = dir.join("leader.pid").display(),
            gc = dir.join("gc.pid").display(),
        )
    });

    let (deadline, result) = run_to_timeout(&tool, ProcessGroup::Own).await;
    let waited = deadline.elapsed();

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    assert!(
        tool.dir.path().join("marker").exists(),
        "the leader never received TERM"
    );
    assert!(
        waited < TERMINATION_GRACE / 2,
        "the leader exited on TERM, so the return must not wait out the grace period: {waited:?}"
    );
    let gc = tool.pid("gc.pid");
    assert!(
        gone_within(gc, Duration::from_secs(2)).await,
        "TERM-ignoring grandchild {gc} survived the group KILL"
    );
}

/// A leader that ignores TERM gets the full grace period, then the whole tree is killed.
#[tokio::test]
async fn test_run_timeout_term_ignoring_leader_waits_the_grace_period_then_kills_the_tree() {
    let tool = SleepingTool::with_script(|dir| {
        format!(
            "#!/bin/sh\ntrap '' TERM\necho $$ > {leader}\nsleep 30 &\necho $! > {grandchild}\nwait\n",
            leader = dir.join("leader.pid").display(),
            grandchild = dir.join("grandchild.pid").display(),
        )
    });

    let (deadline, result) = run_to_timeout(&tool, ProcessGroup::Own).await;
    let waited = deadline.elapsed();

    assert_matches!(
        result,
        Err(RegenerationError::TimedOut { .. }),
        "{result:?}"
    );
    assert!(
        waited >= TERMINATION_GRACE,
        "KILL came before the grace period ended: {waited:?}"
    );
    assert!(
        waited < TERMINATION_GRACE + Duration::from_secs(1),
        "the drop blocked far past the grace period: {waited:?}"
    );
    for file in ["leader.pid", "grandchild.pid"] {
        let pid = tool.pid(file);
        assert!(
            gone_within(pid, Duration::from_secs(2)).await,
            "{file} {pid}"
        );
    }
}

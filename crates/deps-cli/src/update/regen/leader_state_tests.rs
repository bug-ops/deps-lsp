//! Acceptance tests for the #2066 review round: a leader that was already reaped elsewhere
//! (`waitid` answers `ECHILD`) must not receive the final KILL, because its pid, and with it the
//! group id, may have been recycled for an unrelated process.
//!
//! Declared in `regen/mod.rs` as `#[cfg(all(test, unix))] mod leader_state_tests;`.

#![cfg(unix)]
#![allow(clippy::panic)]

use std::assert_matches;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{Pid, WaitOptions, waitpid};
use tokio::process::Command;

use super::run::{ChildGuard, LeaderState, ProcessGroup, leader_state};

#[test]
fn test_leader_state_classifies_each_waitid_result() {
    assert_matches!(leader_state::<()>(Ok(None)), LeaderState::Running);
    assert_matches!(leader_state(Ok(Some(()))), LeaderState::Exited);
    assert_matches!(leader_state::<()>(Err(Errno::CHILD)), LeaderState::Gone);
    assert_matches!(leader_state::<()>(Err(Errno::INVAL)), LeaderState::Unknown);
    assert_matches!(leader_state::<()>(Err(Errno::NOSYS)), LeaderState::Unknown);
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The leader exits at once and is reaped here, behind the guard's back; a TERM-ignoring
/// grandchild keeps the group alive. Dropping the guard sends TERM, sees `ECHILD`, and must
/// stop there: a KILL would also hit the grandchild (and, in the recycled-pid case, a stranger).
#[tokio::test]
async fn test_guard_drop_does_not_kill_when_the_leader_was_reaped_elsewhere() {
    let dir = tempfile::tempdir().expect("dir");
    let pid_file = dir.path().join("gc.pid");
    let script = format!(
        "sh -c 'trap \"\" TERM; echo $$ > {file}; exec sleep 30' &\nwhile [ ! -s {file} ]; do sleep 0.05; done\nexit 0\n",
        file = pid_file.display(),
    );
    let guard = ChildGuard::spawn(Command::new("sh").arg("-c").arg(&script), ProcessGroup::Own)
        .expect("spawn");
    let leader = Pid::from_raw(i32::try_from(guard.id().expect("pid")).expect("pid fits"))
        .expect("non-zero pid");
    waitpid(Some(leader), WaitOptions::empty()).expect("reap the leader behind the guard");
    let grandchild: u32 = std::fs::read_to_string(&pid_file)
        .expect("grandchild pid")
        .trim()
        .parse()
        .expect("pid");

    let started = Instant::now();
    drop(guard);
    let waited = started.elapsed();

    let survived = alive(grandchild);
    let _ = std::process::Command::new("kill")
        .args(["-KILL", &grandchild.to_string()])
        .status();
    assert!(
        survived,
        "the group was killed although its leader was already reaped"
    );
    assert!(
        waited < Duration::from_secs(1),
        "ECHILD must not wait out the grace: {waited:?}"
    );
}

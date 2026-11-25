//! Bounded, argv-only process runner for lockfile regeneration.
//!
//! Every spawned process shares one deadline, never sees stdin, and is killed when its future
//! is dropped; on unix a tool that leads its own process group is killed together with its
//! descendants. Run calls forward the tool's stdout to this process's stderr so the report on
//! stdout stays machine-readable; probes capture a small, capped stdout instead.

use std::io::ErrorKind;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

#[cfg(all(test, unix))]
use std::ffi::OsString;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout_at};

use super::RegenerationError;
use super::command::{Invocation, Program};

/// Largest probe stdout accepted; anything longer is not a path or a one-word answer.
const PROBE_OUTPUT_CAP: u64 = 4096;

/// Result of a bounded read: output of exactly the cap is complete, one byte more is over it.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::update) enum Capped {
    /// The reader ended within the cap.
    Complete(Vec<u8>),
    /// The reader held more than the cap; carries the first `cap` bytes.
    OverCap(Vec<u8>),
}

/// Reads `reader` up to `cap` bytes and reports whether more followed.
///
/// # Errors
///
/// Returns the reader's I/O error.
pub(in crate::update) async fn read_capped<R: AsyncRead + Unpin>(
    reader: &mut R,
    cap: u64,
) -> std::io::Result<Capped> {
    let mut buffer = Vec::new();
    // One byte past the cap tells an over-long answer from one that exactly fits.
    reader
        .take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .await?;
    if buffer.len() as u64 > cap {
        buffer.truncate(usize::try_from(cap).unwrap_or(usize::MAX));
        Ok(Capped::OverCap(buffer))
    } else {
        Ok(Capped::Complete(buffer))
    }
}

/// How long a tool gets to exit after SIGTERM before it is killed with SIGKILL.
#[cfg_attr(not(unix), allow(dead_code))]
pub(in crate::update) const TERMINATION_GRACE: Duration = Duration::from_secs(2);

/// How often the grace period checks whether the tool's leader has exited.
#[cfg(unix)]
const TERMINATION_POLL: Duration = Duration::from_millis(20);

/// What a capped probe read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Probed {
    /// The trimmed stdout.
    Text(String),
    /// More output than the cap allows; none of it is returned.
    OverCap,
}

/// Where child processes find their executables.
#[derive(Debug, Clone)]
pub(super) enum SearchPath {
    /// The inherited `PATH`.
    Inherit,
    /// Fake tools live in this directory: executables are resolved there only, and the child's
    /// `PATH` is this directory followed by the inherited one so scripts keep coreutils.
    #[cfg(all(test, unix))]
    #[cfg_attr(
        not(all(feature = "cargo", feature = "npm", feature = "go")),
        allow(dead_code)
    )]
    Override(OsString),
}

/// Whether a spawned tool leads its own process group or stays in deps-cli's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::update) enum ProcessGroup {
    /// The tool leads a new group, so a timeout or interrupt kills its whole process tree.
    Own,
    /// The tool stays in deps-cli's group. Chosen only for a foreground terminal run, where a
    /// new group would be background to the terminal (`/dev/tty` prompts would stop it).
    /// Process groups are a unix concept, so the variant exists only there (and in tests).
    #[cfg(any(unix, test))]
    Inherit,
}

impl ProcessGroup {
    /// Picks the policy for one regeneration: [`Self::Inherit`] only when deps-cli is in its
    /// controlling terminal's foreground group.
    #[cfg(unix)]
    pub(in crate::update) fn detect() -> Self {
        let foreground = std::fs::File::open("/dev/tty")
            .ok()
            .and_then(|tty| rustix::termios::tcgetpgrp(&tty).ok())
            .map(|pgid| pgid.as_raw_nonzero().get());
        Self::choose(
            foreground,
            rustix::process::getpgrp().as_raw_nonzero().get(),
        )
    }

    /// Without process groups the tool is a plain child.
    #[cfg(not(unix))]
    pub(in crate::update) const fn detect() -> Self {
        Self::Own
    }

    /// The pure decision: `foreground` is the terminal's foreground group when `/dev/tty` opened
    /// and answered, `own` is deps-cli's group.
    #[cfg(any(unix, test))]
    pub(in crate::update) const fn choose(foreground: Option<i32>, own: i32) -> Self {
        match foreground {
            Some(pgid) if pgid == own => Self::Inherit,
            Some(_) | None => Self::Own,
        }
    }
}

/// A spawned tool that is terminated, with its process group when it leads one, on drop.
///
/// Dropping sends SIGTERM, gives the leader up to [`TERMINATION_GRACE`] to exit, then sends
/// SIGKILL to the same target even when the leader has exited, so descendants that ignored
/// SIGTERM do not outlive it. The leader is never reaped during the grace period: gating on
/// [`Child::id`] is the "not yet reaped" proof, because tokio returns `None` once the child was
/// waited for, and until then the leader still holds the group id, so the group cannot have been
/// recycled for an unrelated process.
pub(in crate::update) struct ChildGuard {
    child: Child,
    #[cfg_attr(not(unix), allow(dead_code))]
    group: ProcessGroup,
}

impl ChildGuard {
    /// Spawns `command` under `group`'s policy and terminates it when the guard is dropped.
    ///
    /// With [`ProcessGroup::Own`] on unix the tool leads a new process group, so the drop
    /// terminates its whole process tree; with [`ProcessGroup::Inherit`] only the tool itself is
    /// signalled.
    ///
    /// # Errors
    ///
    /// The [`std::io::Error`] from spawning the process.
    pub(in crate::update) fn spawn(
        command: &mut Command,
        group: ProcessGroup,
    ) -> std::io::Result<Self> {
        #[cfg(unix)]
        if group == ProcessGroup::Own {
            command.process_group(0);
        }
        command.kill_on_drop(true);
        Ok(Self {
            child: command.spawn()?,
            group,
        })
    }

    #[cfg(unix)]
    fn signal(&self, leader: rustix::process::Pid, signal: rustix::process::Signal) {
        use rustix::io::Errno;
        use rustix::process::{kill_process, kill_process_group};

        let result = match self.group {
            ProcessGroup::Own => kill_process_group(leader, signal),
            ProcessGroup::Inherit => kill_process(leader, signal),
        };
        match result {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(error) => tracing::debug!(%error, ?signal, "could not signal the tool"),
        }
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        use rustix::process::{Pid, Signal};

        let Some(leader) = self
            .child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
        else {
            return;
        };
        if poll_leader(leader) == LeaderState::Gone {
            return;
        }
        self.signal(leader, Signal::TERM);
        if wait_for_leader_exit(leader, TERMINATION_GRACE) != LeaderState::Gone {
            self.signal(leader, Signal::KILL);
        }
    }
}

/// What a `waitid` poll learned about the tool's leader.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeaderState {
    /// Still running.
    Running,
    /// Exited but not reaped: its pid and group id are still reserved for it.
    Exited,
    /// Not our child any more (`ECHILD`): the pid may already belong to an unrelated process, so
    /// nothing may be signalled.
    Gone,
    /// The poll failed for another reason, so the leader's state is not observable.
    Unknown,
}

/// Classifies a `waitid(EXITED | NOHANG | NOWAIT)` result.
#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
pub(super) fn leader_state<T>(result: rustix::io::Result<Option<T>>) -> LeaderState {
    match result {
        Ok(None) => LeaderState::Running,
        Ok(Some(_)) => LeaderState::Exited,
        Err(rustix::io::Errno::CHILD) => LeaderState::Gone,
        Err(_) => LeaderState::Unknown,
    }
}

/// Blocks until `leader` has exited or `grace` has passed, and returns the last observed state
/// (`Running` when the grace expired). An unobservable leader sleeps out the whole grace.
/// `Drop` cannot await, and a short block in this teardown path of a short-lived CLI is cheaper
/// than threading cancellation through the runner.
#[cfg(unix)]
fn wait_for_leader_exit(leader: rustix::process::Pid, grace: Duration) -> LeaderState {
    let deadline = std::time::Instant::now() + grace;
    loop {
        let state = poll_leader(leader);
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match state {
            LeaderState::Exited | LeaderState::Gone => return state,
            LeaderState::Unknown => {
                std::thread::sleep(remaining);
                return state;
            }
            LeaderState::Running if remaining.is_zero() => return state,
            LeaderState::Running => std::thread::sleep(remaining.min(TERMINATION_POLL)),
        }
    }
}

/// Polls `leader` without reaping it: `WNOWAIT` leaves the zombie in place so tokio still owns
/// the exit status and the group id stays reserved for the final SIGKILL.
#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn poll_leader(leader: rustix::process::Pid) -> LeaderState {
    use rustix::io::Errno;
    use rustix::process::{WaitId, WaitIdOptions, waitid};

    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    match waitid(WaitId::Pid(leader), options) {
        Err(Errno::INTR) => LeaderState::Running,
        result => leader_state(result),
    }
}

/// Without `waitid` the exit cannot be observed without reaping, so the full grace is waited.
#[cfg(all(
    unix,
    any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    )
))]
const fn poll_leader(_leader: rustix::process::Pid) -> LeaderState {
    LeaderState::Unknown
}

/// Spawns the regeneration tools under one shared time budget.
#[derive(Debug, Clone)]
pub(super) struct ToolRunner {
    /// Total budget for every probe and run call, measured from the start of the regeneration.
    pub(super) deadline: Duration,
    /// Where the tools are looked up.
    pub(super) search_path: SearchPath,
    /// Process-group policy for every spawned tool.
    pub(super) group: ProcessGroup,
}

impl ToolRunner {
    fn command(&self, invocation: &Invocation) -> Command {
        let executable = invocation.program().executable();
        let mut command = match &self.search_path {
            SearchPath::Inherit => Command::new(executable),
            #[cfg(all(test, unix))]
            SearchPath::Override(dir) => {
                let mut command = Command::new(std::path::Path::new(dir).join(executable));
                let inherited = std::env::var_os("PATH").unwrap_or_default();
                let path = std::env::join_paths(
                    std::iter::once(std::path::PathBuf::from(dir))
                        .chain(std::env::split_paths(&inherited)),
                )
                .unwrap_or_else(|_| dir.clone());
                command.env("PATH", path);
                command
            }
        };
        command
            .args(invocation.args())
            .current_dir(invocation.cwd())
            .stdin(Stdio::null());
        command.envs(invocation.env().iter().copied());
        command
    }

    /// Runs `invocation` to completion, forwarding its stdout to this process's stderr.
    ///
    /// # Errors
    ///
    /// [`RegenerationError::ToolchainMissing`], [`RegenerationError::Spawn`],
    /// [`RegenerationError::TimedOut`] or [`RegenerationError::ToolFailed`].
    pub(super) async fn run(
        &self,
        invocation: &Invocation,
        deadline: Instant,
    ) -> Result<(), RegenerationError> {
        let program = invocation.program();
        let mut child = self.spawn(
            self.command(invocation)
                .stdout(Stdio::from(std::io::stderr())),
            program,
        )?;
        let status = timeout_at(deadline, child.wait())
            .await
            .map_err(|_| self.timed_out())?
            .map_err(|source| spawn_error(program, source))?;
        check_status(program, status)
    }

    /// Runs `invocation` and returns its trimmed, capped, UTF-8 stdout.
    ///
    /// # Errors
    ///
    /// Everything [`Self::run`] returns, plus [`RegenerationError::UnexpectedProbeOutput`] for
    /// output over the cap or not valid UTF-8.
    pub(super) async fn probe(
        &self,
        invocation: &Invocation,
        deadline: Instant,
    ) -> Result<String, RegenerationError> {
        match self
            .probe_capped(invocation, deadline, PROBE_OUTPUT_CAP)
            .await?
        {
            Probed::Text(text) => Ok(text),
            Probed::OverCap => Err(RegenerationError::UnexpectedProbeOutput {
                program: invocation.program(),
            }),
        }
    }

    /// [`Self::probe`] with an explicit output cap of `cap` bytes, for a listing that is
    /// legitimately longer than a path or a one-word answer. Output over `cap` is reported as
    /// [`Probed::OverCap`] and never read further; non-UTF-8 output is an error.
    pub(super) async fn probe_capped(
        &self,
        invocation: &Invocation,
        deadline: Instant,
        cap: u64,
    ) -> Result<Probed, RegenerationError> {
        let program = invocation.program();
        let mut child = self.spawn(self.command(invocation).stdout(Stdio::piped()), program)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(RegenerationError::UnexpectedProbeOutput { program })?;

        let capped = timeout_at(deadline, read_capped(&mut stdout, cap))
            .await
            .map_err(|_| self.timed_out())?
            .map_err(|source| spawn_error(program, source))?;
        let Capped::Complete(buffer) = capped else {
            return Ok(Probed::OverCap);
        };
        let status = timeout_at(deadline, child.wait())
            .await
            .map_err(|_| self.timed_out())?
            .map_err(|source| spawn_error(program, source))?;
        check_status(program, status)?;
        String::from_utf8(buffer)
            .map(|text| Probed::Text(text.trim().to_owned()))
            .map_err(|_| RegenerationError::UnexpectedProbeOutput { program })
    }

    fn spawn(
        &self,
        command: &mut Command,
        program: Program,
    ) -> Result<ChildGuard, RegenerationError> {
        ChildGuard::spawn(command, self.group).map_err(|source| spawn_error(program, source))
    }

    const fn timed_out(&self) -> RegenerationError {
        RegenerationError::TimedOut {
            after: self.deadline,
        }
    }
}

fn spawn_error(program: Program, source: std::io::Error) -> RegenerationError {
    if source.kind() == ErrorKind::NotFound {
        RegenerationError::ToolchainMissing { program }
    } else {
        RegenerationError::Spawn { program, source }
    }
}

fn check_status(program: Program, status: ExitStatus) -> Result<(), RegenerationError> {
    status
        .success()
        .ok_or_else(|| RegenerationError::ToolFailed {
            program,
            code: status.code(),
        })
}

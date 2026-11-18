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

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::time::{Instant, timeout_at};

use super::RegenerationError;
use super::command::{Invocation, Program};

/// Largest probe stdout accepted; anything longer is not a path or a one-word answer.
const PROBE_OUTPUT_CAP: u64 = 4096;

/// How long a tool gets to exit after SIGTERM before its process group is killed.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::update) const TERMINATION_GRACE: Duration = Duration::from_secs(2);

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

/// A spawned tool that is killed, with its process group when it leads one, on drop.
///
/// Gating on [`Child::id`] is the "not yet reaped" proof: tokio returns `None` once the child
/// was waited for, and until then the leader still holds the group id, so the group cannot have
/// been recycled for an unrelated process.
struct ChildGuard {
    child: Child,
    #[cfg_attr(not(unix), allow(dead_code))]
    group: ProcessGroup,
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
        use rustix::io::Errno;
        use rustix::process::{Pid, Signal, kill_process_group};

        if self.group != ProcessGroup::Own {
            return;
        }
        let Some(leader) = self
            .child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw)
        else {
            return;
        };
        match kill_process_group(leader, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => {}
            Err(error) => tracing::debug!(%error, "could not kill the tool's process group"),
        }
    }
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
        #[cfg(unix)]
        if self.group == ProcessGroup::Own {
            command.process_group(0);
        }
        command
            .args(invocation.args())
            .current_dir(invocation.cwd())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        if let Some((key, value)) = invocation.env() {
            command.env(key, value);
        }
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
        let program = invocation.program();
        let mut child = self.spawn(self.command(invocation).stdout(Stdio::piped()), program)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(RegenerationError::UnexpectedProbeOutput { program })?;

        let mut buffer = Vec::new();
        // One byte past the cap tells an over-long answer from one that exactly fits.
        timeout_at(
            deadline,
            (&mut stdout)
                .take(PROBE_OUTPUT_CAP + 1)
                .read_to_end(&mut buffer),
        )
        .await
        .map_err(|_| self.timed_out())?
        .map_err(|source| spawn_error(program, source))?;
        if buffer.len() as u64 > PROBE_OUTPUT_CAP {
            return Err(RegenerationError::UnexpectedProbeOutput { program });
        }

        let status = timeout_at(deadline, child.wait())
            .await
            .map_err(|_| self.timed_out())?
            .map_err(|source| spawn_error(program, source))?;
        check_status(program, status)?;
        String::from_utf8(buffer)
            .map(|text| text.trim().to_owned())
            .map_err(|_| RegenerationError::UnexpectedProbeOutput { program })
    }

    fn spawn(
        &self,
        command: &mut Command,
        program: Program,
    ) -> Result<ChildGuard, RegenerationError> {
        let child = command
            .spawn()
            .map_err(|source| spawn_error(program, source))?;
        Ok(ChildGuard {
            child,
            group: self.group,
        })
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
    if status.success() {
        Ok(())
    } else {
        Err(RegenerationError::ToolFailed {
            program,
            code: status.code(),
        })
    }
}

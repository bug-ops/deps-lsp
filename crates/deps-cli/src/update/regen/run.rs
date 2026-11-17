//! Bounded, argv-only process runner for lockfile regeneration.
//!
//! Every spawned process shares one deadline, never sees stdin, and is killed when its future
//! is dropped. Run calls forward the tool's stdout to this process's stderr so the report on
//! stdout stays machine-readable; probes capture a small, capped stdout instead.

use std::io::ErrorKind;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

#[cfg(all(test, unix))]
use std::ffi::OsString;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{Instant, timeout_at};

use super::RegenerationError;
use super::command::{Invocation, Program};

/// Largest probe stdout accepted; anything longer is not a path or a one-word answer.
const PROBE_OUTPUT_CAP: u64 = 4096;

/// Where child processes find their executables.
#[derive(Debug, Clone)]
pub(super) enum SearchPath {
    /// The inherited `PATH`.
    Inherit,
    /// Fake tools live in this directory: executables are resolved there only, and the child's
    /// `PATH` is this directory followed by the inherited one so scripts keep coreutils.
    #[cfg(all(test, unix))]
    Override(OsString),
}

/// Spawns the regeneration tools under one shared time budget.
#[derive(Debug, Clone)]
pub(super) struct ToolRunner {
    /// Total budget for every probe and run call, measured from the start of the regeneration.
    pub(super) deadline: Duration,
    /// Where the tools are looked up.
    pub(super) search_path: SearchPath,
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
        let mut child = self
            .command(invocation)
            .stdout(Stdio::from(std::io::stderr()))
            .spawn()
            .map_err(|source| spawn_error(program, source))?;
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
        let mut child = self
            .command(invocation)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|source| spawn_error(program, source))?;
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

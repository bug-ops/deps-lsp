//! Step runner for the `--open-pr` git phase: `git`, `gh` and `glab` run argv-only through the
//! lock file tools' terminate-on-drop child guard.
//!
//! Every step gets a null stdin, a captured and capped stdout, an inherited stderr, the
//! non-interactive environment and its own time limit that also covers the hooks git runs.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use super::PrError;
use crate::update::regen::{ChildGuard, ProcessGroup};

/// Time limit of one step, including the hooks it triggers.
pub(super) const STEP_TIMEOUT: Duration = Duration::from_mins(2);

/// Largest stdout kept by a step that prints a URL or one git answer.
const STDOUT_CAP: u64 = 64 * 1024;

/// Largest stdout kept when reading one request: its body can be long.
const READ_REQUEST_CAP: u64 = 1024 * 1024;

/// Largest stdout kept when listing requests: full objects of up to a few hundred requests.
const LIST_REQUESTS_CAP: u64 = 8 * 1024 * 1024;

/// The external program a step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `git`.
    Git,
    /// GitHub CLI.
    Gh,
    /// GitLab CLI.
    Glab,
}

impl Tool {
    const fn executable(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Gh => "gh",
            Self::Glab => "glab",
        }
    }
}

impl fmt::Display for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.executable())
    }
}

/// One command of the git phase, named for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `git rev-parse --show-toplevel`.
    Locate,
    /// `git rev-parse --show-prefix`.
    Prefix,
    /// `git symbolic-ref --quiet --short HEAD`.
    Head,
    /// `git var GIT_COMMITTER_IDENT`.
    Identity,
    /// `git status --porcelain`.
    Status,
    /// `git ls-remote` for the update branch.
    RemoteBranch,
    /// `git rev-parse --verify` for the update branch.
    LocalBranch,
    /// `git restore` of the manifest's directory.
    Restore,
    /// `git diff --name-only -z HEAD`.
    Diff,
    /// `git ls-files` or `git ls-tree` over the published paths.
    ListFiles,
    /// `git switch --create`.
    Switch,
    /// `git add -- <paths>`.
    Stage,
    /// `git commit`.
    Commit,
    /// `git push`.
    Push,
    /// `gh pr create` or `glab mr create`.
    CreateRequest,
    /// `git switch` back to the base branch.
    SwitchBack,
    /// Listing the open requests of the same author.
    ListRequests,
    /// Reading one request's author, branch, commit count and body.
    ReadRequest,
    /// Closing a superseded request with its comment.
    CloseRequest,
}

impl Step {
    /// The most stdout the step keeps; longer output is reported as truncated.
    const fn stdout_cap(self) -> u64 {
        match self {
            Self::ReadRequest => READ_REQUEST_CAP,
            Self::ListRequests => LIST_REQUESTS_CAP,
            Self::Locate
            | Self::Prefix
            | Self::Head
            | Self::Identity
            | Self::Status
            | Self::RemoteBranch
            | Self::LocalBranch
            | Self::Restore
            | Self::Diff
            | Self::ListFiles
            | Self::Switch
            | Self::Stage
            | Self::Commit
            | Self::Push
            | Self::CreateRequest
            | Self::SwitchBack
            | Self::CloseRequest => STDOUT_CAP,
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Locate => "locating the repository",
            Self::Prefix => "locating the manifest directory",
            Self::Head => "reading the current branch",
            Self::Identity => "reading the committer identity",
            Self::Status => "checking the working tree",
            Self::RemoteBranch => "looking up the branch on origin",
            Self::LocalBranch => "looking up the local branch",
            Self::Restore => "restoring the manifest directory",
            Self::Diff => "listing changed files",
            Self::ListFiles => "listing tracked files",
            Self::Switch => "creating the update branch",
            Self::Stage => "staging the changes",
            Self::Commit => "committing",
            Self::Push => "pushing the branch",
            Self::CreateRequest => "creating the pull request",
            Self::SwitchBack => "switching back to the base branch",
            Self::ListRequests => "listing the open requests",
            Self::ReadRequest => "reading a request",
            Self::CloseRequest => "closing a superseded request",
        })
    }
}

/// What a finished step reported.
#[derive(Debug)]
pub(super) struct StepOutput {
    /// The exit code, `None` when a signal ended the process.
    pub(super) code: Option<i32>,
    /// Captured stdout, lossily decoded and trimmed.
    pub(super) stdout: String,
    /// The captured bytes as written, for NUL-separated output.
    pub(super) raw: Vec<u8>,
    /// Whether the output reached the capture cap, so it may be incomplete.
    pub(super) truncated: bool,
}

/// Runs steps under one process-group policy.
#[derive(Debug, Clone)]
pub(super) struct Runner {
    pub(super) group: ProcessGroup,
    /// Directory holding fake `gh`/`glab` executables; `git` always comes from `PATH`.
    #[cfg(test)]
    pub(super) tool_dir: Option<PathBuf>,
}

impl Runner {
    fn program(&self, tool: Tool) -> OsString {
        #[cfg(test)]
        if let (Some(dir), Tool::Gh | Tool::Glab) = (&self.tool_dir, tool) {
            return dir.join(tool.executable()).into_os_string();
        }
        OsString::from(tool.executable())
    }

    /// Runs one step to completion and returns its exit code and stdout.
    ///
    /// # Errors
    ///
    /// [`PrError::ToolMissing`], [`PrError::Spawn`], [`PrError::TimedOut`] or
    /// [`PrError::UnexpectedOutput`].
    pub(super) async fn run<I, S>(
        &self,
        tool: Tool,
        step: Step,
        cwd: &Path,
        args: I,
    ) -> Result<StepOutput, PrError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(self.program(tool));
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GH_PROMPT_DISABLED", "1");
        let mut child = ChildGuard::spawn(&mut command, self.group).map_err(|source| {
            if source.kind() == ErrorKind::NotFound {
                PrError::ToolMissing { tool }
            } else {
                PrError::Spawn { tool, source }
            }
        })?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(PrError::UnexpectedOutput { tool, step })?;

        let cap = step.stdout_cap();
        let finished = timeout(STEP_TIMEOUT, async {
            let mut kept = Vec::new();
            (&mut stdout).take(cap).read_to_end(&mut kept).await?;
            // Keep draining so a chatty child never blocks on a full pipe.
            tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await?;
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((kept, status))
        })
        .await
        .map_err(|_| PrError::TimedOut { tool, step })?;
        let (kept, status) = finished.map_err(|source| PrError::Spawn { tool, source })?;
        Ok(StepOutput {
            code: status.code(),
            stdout: String::from_utf8_lossy(&kept).trim().to_owned(),
            truncated: kept.len() as u64 >= cap,
            raw: kept,
        })
    }

    /// Runs a step that must exit with 0 and returns its stdout.
    ///
    /// # Errors
    ///
    /// Everything [`Self::run`] returns, plus [`PrError::ToolFailed`] for any other exit.
    pub(super) async fn succeed<I, S>(
        &self,
        tool: Tool,
        step: Step,
        cwd: &Path,
        args: I,
    ) -> Result<String, PrError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run(tool, step, cwd, args).await?;
        match output.code {
            Some(0) => Ok(output.stdout),
            code => Err(PrError::ToolFailed { tool, step, code }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_steps_keep_more_output_than_the_default() {
        assert_eq!(Step::Status.stdout_cap(), 64 * 1024);
        assert_eq!(Step::ReadRequest.stdout_cap(), 1024 * 1024);
        assert_eq!(Step::ListRequests.stdout_cap(), 8 * 1024 * 1024);
    }
}

//! `update --open-pr` (#1117): commits the update on a content-addressed branch, pushes it and
//! opens a pull or merge request through `git` plus `gh` or `glab`. deps-cli never reads a token.

pub mod git;

#[cfg(all(test, unix))]
mod acceptance_tests;

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

use deps_core::EcosystemId;
use deps_core::lsp_helpers::EcosystemFormatter;

use self::git::{Step, Tool};
use super::group::UpdateGroup;
use super::regen::{Interrupts, ProcessGroup};
use super::{UpdatePlan, UpdateRun};

/// The hosting service whose CLI creates the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PrHost {
    /// GitHub, through `gh`.
    Github,
    /// GitLab, through `glab`.
    Gitlab,
}

/// What the preflight learned about the repository.
#[derive(Debug)]
pub struct RepoContext {
    group: ProcessGroup,
    #[cfg(test)]
    tool_dir: Option<PathBuf>,
}

/// A sanitized `deps-cli/...` branch name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchName(String);

impl BranchName {
    /// The branch name as passed to git.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A branch that was verified absent locally and on the remote; only [`check_branch`] makes one.
#[derive(Debug)]
pub struct FreeBranch(BranchName);

/// Result of looking for the update branch.
#[derive(Debug)]
pub enum BranchCheck {
    /// Neither the remote nor the local repository has the branch.
    Free(FreeBranch),
    /// The remote already has the branch: this exact update set was proposed before.
    AlreadyProposed(BranchName),
}

/// Title, body and commit message body of the request.
#[derive(Debug)]
pub struct PullRequestText {
    title: String,
    body: String,
    commit_body: String,
}

/// How the publish phase ended.
#[derive(Debug)]
pub enum PrOutcome {
    /// The request was created.
    Opened {
        /// The URL the host CLI printed.
        url: String,
    },
    /// The update left the tracked files unchanged.
    NothingToCommit,
}

/// The phase a signal arrived in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrPhase {
    /// Before the update.
    Preflight,
    /// During planning, applying and regeneration.
    Update,
    /// During the git phase.
    Publish,
}

/// Why the `--open-pr` flow stopped.
#[derive(Debug, thiserror::Error)]
pub enum PrError {
    /// The manifest is not inside a git work tree.
    #[error("not inside a git repository")]
    NotARepository,
    /// `HEAD` is detached.
    #[error("HEAD is detached")]
    DetachedHead,
    /// `HEAD` is on a branch deps-cli created.
    #[error("HEAD is on the update branch {branch}")]
    OnUpdateBranch {
        /// The current branch.
        branch: String,
    },
    /// No committer identity is configured.
    #[error("no git committer identity is configured")]
    MissingIdentity,
    /// Tracked files differ from `HEAD`.
    #[error("the working tree has uncommitted changes to tracked files")]
    DirtyWorkingTree,
    /// The ecosystem cannot regenerate its lock file yet.
    #[error("{0:?} cannot be used with --open-pr yet")]
    UnsupportedEcosystem(EcosystemId),
    /// A local branch with this name exists but the remote has none.
    #[error("a local branch {branch} already exists")]
    StaleLocalBranch {
        /// The conflicting branch.
        branch: String,
    },
    /// The lock file was not regenerated.
    #[error("the lock file was not regenerated")]
    LockfileNotRegenerated,
    /// A signal arrived.
    #[error("interrupted")]
    Interrupted {
        /// The phase it arrived in.
        phase: PrPhase,
    },
    /// The program is not installed.
    #[error("{tool:?} was not found")]
    ToolMissing {
        /// The missing program.
        tool: Tool,
    },
    /// A step exited unsuccessfully.
    #[error("{tool:?} {step:?} failed")]
    ToolFailed {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
        /// Its exit code, when it had one.
        code: Option<i32>,
    },
    /// A step exceeded its time limit.
    #[error("{tool:?} {step:?} timed out")]
    TimedOut {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
    /// A program could not be started.
    #[error("could not start {tool:?}")]
    Spawn {
        /// The program.
        tool: Tool,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// A step printed something unparsable.
    #[error("{tool:?} {step:?} printed unexpected output")]
    UnexpectedOutput {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
}

/// Listens for SIGINT and SIGTERM from before the preflight to the end of the flow.
#[derive(Debug)]
pub struct PrSignals(Option<Interrupts>);

impl PrSignals {
    /// Installs the handlers; must run inside a tokio runtime before the first git process.
    #[must_use]
    pub fn install() -> Self {
        todo!()
    }

    /// Runs `future` unless a signal arrives first, which drops it.
    ///
    /// # Errors
    ///
    /// [`PrError::Interrupted`] naming `phase` when a signal won.
    pub async fn guard<T>(
        &mut self,
        _phase: PrPhase,
        _future: impl Future<Output = T>,
    ) -> Result<T, PrError> {
        todo!()
    }
}

/// Checks that the repository is ready for `--open-pr`.
///
/// # Errors
///
/// A [`PrError`] for the first failed precondition.
pub async fn preflight(_manifest: &Path) -> Result<RepoContext, PrError> {
    todo!()
}

/// The branch this update set is proposed on; `None` when nothing would change.
#[must_use]
pub fn branch_for(
    _ctx: &RepoContext,
    _ecosystem: EcosystemId,
    _plan: &UpdatePlan,
    _formatter: &dyn EcosystemFormatter,
    _group: Option<&UpdateGroup>,
) -> Option<BranchName> {
    todo!()
}

/// Looks the branch up on the remote and locally.
///
/// # Errors
///
/// [`PrError::StaleLocalBranch`] or a failed git step.
pub async fn check_branch(_ctx: &RepoContext, _branch: BranchName) -> Result<BranchCheck, PrError> {
    todo!()
}

/// Reverts tracked files in the manifest's directory to `HEAD`.
///
/// # Errors
///
/// A failed git step.
pub async fn restore(_ctx: &RepoContext) -> Result<(), PrError> {
    todo!()
}

/// Renders the request text for the applied items of `run`.
#[must_use]
pub fn describe(
    _ctx: &RepoContext,
    _run: &UpdateRun,
    _group: Option<&UpdateGroup>,
) -> PullRequestText {
    todo!()
}

/// Commits, pushes and opens the request.
///
/// # Errors
///
/// A [`PrError`] from the first failing step.
pub async fn open(
    _ctx: &RepoContext,
    _host: PrHost,
    _branch: FreeBranch,
    _run: &UpdateRun,
    _text: &PullRequestText,
) -> Result<PrOutcome, PrError> {
    todo!()
}

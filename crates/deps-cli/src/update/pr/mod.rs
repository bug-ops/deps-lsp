//! `update --open-pr` (#1117): commits the update on a content-addressed branch, pushes it and
//! opens a pull or merge request through `git` plus `gh` or `glab`. deps-cli never reads a token.
//!
//! The flow is driven from `main.rs`: [`preflight`] before the manifest is walked,
//! [`branch_for`] and [`check_branch`] once the plan is known, [`restore`] when the lock file
//! could not be regenerated, and [`describe`] plus [`open`] after the report is printed. One
//! [`PrSignals`] listener covers every phase, so an interrupt drops the running phase and the
//! child guards terminate the process trees of whatever it spawned.

pub mod git;

#[cfg(all(test, unix))]
mod acceptance_tests;
#[cfg(all(test, unix))]
mod publish_safety_tests;

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

use deps_core::EcosystemId;
use deps_core::edit::UpdateKind;
use deps_core::lsp_helpers::{EcosystemFormatter, NormalizeName};
use deps_core::{ConcreteVersion, PackageName};

use self::git::{Runner, Step, Tool};
use super::group::UpdateGroup;
use super::regen::{Interrupts, LockfileOutcome, LockfileSupport, ProcessGroup, lockfile_support};
use super::{Outcome, UpdatePlan, UpdateRun};

const BRANCH_PREFIX: &str = "deps-cli/";
const BRANCH_PART_MAX_CHARS: usize = 48;
const TITLE_MAX_BYTES: usize = 250;
const TITLE_NAME_MAX_CHARS: usize = 80;
const BODY_NAME_MAX_CHARS: usize = 200;
const BODY_MAX_ROWS: usize = 50;
const BODY_MAX_BYTES: usize = 60_000;

/// The hosting service whose CLI creates the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PrHost {
    /// GitHub, through `gh`.
    Github,
    /// GitLab, through `glab`.
    Gitlab,
}

/// A directory relative to the repository root: empty at the root, otherwise `a/b` without a
/// trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoRelativeDir(String);

impl RepoRelativeDir {
    fn from_prefix(prefix: &str) -> Self {
        Self(prefix.trim_end_matches('/').to_owned())
    }

    const fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    fn join(&self, file: &str) -> String {
        if self.is_root() {
            file.to_owned()
        } else {
            format!("{}/{file}", self.0)
        }
    }
}

/// The branch `HEAD` was on when the run started; never one deps-cli created and never one
/// a command line could read as an option.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseBranch(String);

impl BaseBranch {
    fn new(name: String) -> Result<Self, PrError> {
        if name.starts_with(BRANCH_PREFIX) {
            Err(PrError::OnUpdateBranch { branch: name })
        } else if name.starts_with('-') {
            Err(PrError::UnsafeBaseBranch { branch: name })
        } else {
            Ok(Self(name))
        }
    }
}

/// What the preflight learned about the repository.
#[derive(Debug)]
pub struct RepoContext {
    root: PathBuf,
    manifest_dir: RepoRelativeDir,
    manifest_file: String,
    base: BaseBranch,
    group: ProcessGroup,
    #[cfg(test)]
    tool_dir: Option<PathBuf>,
}

impl RepoContext {
    fn runner(&self) -> Runner {
        Runner {
            group: self.group,
            #[cfg(test)]
            tool_dir: self.tool_dir.clone(),
        }
    }

    fn manifest_path(&self) -> String {
        self.manifest_dir.join(&self.manifest_file)
    }
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
    /// Repo-relative files the commit may contain: the manifest and a regenerated lock file.
    publishable_paths: Vec<String>,
}

/// How the publish phase ended.
#[derive(Debug)]
pub enum PrOutcome {
    /// The request was created; `HEAD` is still on the update branch.
    Opened(OpenedRequest),
    /// None of the publishable files changed.
    NothingToCommit,
}

/// The URL a host CLI printed: its last non-empty line, control characters removed, at most
/// 2,048 characters, so a hostile server cannot inject terminal escape sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestUrl(String);

impl RequestUrl {
    const MAX_CHARS: usize = 2048;

    fn from_output(stdout: &str) -> Option<Self> {
        let line = stdout
            .lines()
            .rev()
            .map(str::trim)
            .find(|line| !line.is_empty())?;
        let url: String = line
            .chars()
            .filter(|ch| !ch.is_control())
            .take(Self::MAX_CHARS)
            .collect();
        (!url.is_empty()).then_some(Self(url))
    }
}

/// A created pull or merge request, with `HEAD` still on the update branch.
///
/// Print [`Self::url`] first, then call [`Self::switch_back`]: a failed switch-back must not
/// lose the URL of a request that already exists.
#[derive(Debug)]
#[must_use = "switch back to the base branch after printing the URL"]
pub struct OpenedRequest {
    url: RequestUrl,
    base: BaseBranch,
}

impl OpenedRequest {
    /// The request's URL, free of control characters.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url.0
    }

    /// Switches back to the branch the run started on.
    ///
    /// # Errors
    ///
    /// [`PrError::ToolFailed`] for the switch-back step; its message carries the cleanup hint.
    pub async fn switch_back(self, ctx: &RepoContext) -> Result<(), PrError> {
        ctx.runner()
            .succeed(
                Tool::Git,
                Step::SwitchBack,
                &ctx.root,
                ["switch", self.base.0.as_str()],
            )
            .await
            .map(drop)
    }
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

impl PrPhase {
    const fn label(self) -> &'static str {
        match self {
            Self::Preflight => "the repository preflight",
            Self::Update => "the update",
            Self::Publish => "publishing the pull request",
        }
    }
}

/// Why the `--open-pr` flow stopped.
#[derive(Debug, thiserror::Error)]
pub enum PrError {
    /// The manifest is not inside a git work tree.
    #[error("--open-pr needs the manifest to be inside a git repository")]
    NotARepository,
    /// `HEAD` is detached.
    #[error("--open-pr needs HEAD on a named branch, but HEAD is detached")]
    DetachedHead,
    /// `HEAD` is on a branch deps-cli created.
    #[error(
        "HEAD is on the update branch {branch}, left by an earlier run; switch back with \
         `git switch <base branch>`, delete it with `git branch -D {branch}` and, if it was \
         pushed, with `git push origin --delete {branch}`"
    )]
    OnUpdateBranch {
        /// The current branch.
        branch: String,
    },
    /// `HEAD` is on a branch whose name a command line could read as an option.
    #[error("--open-pr cannot use the branch {branch}: its name starts with '-'")]
    UnsafeBaseBranch {
        /// The current branch.
        branch: String,
    },
    /// No committer identity is configured.
    #[error("--open-pr needs a git committer identity (set user.name and user.email)")]
    MissingIdentity,
    /// Tracked files differ from `HEAD`.
    #[error(
        "--open-pr needs a clean working tree, but tracked files are modified; commit or discard \
         them (an interrupted earlier run may have left a manifest edit: `git restore <manifest \
         directory>`)"
    )]
    DirtyWorkingTree,
    /// The ecosystem cannot regenerate its lock file yet.
    #[error(
        "--open-pr does not support {0} yet; supported ecosystems: {supported}",
        supported = supported_ecosystems()
    )]
    UnsupportedEcosystem(EcosystemId),
    /// A local branch with this name exists but the remote has none.
    #[error(
        "the local branch {branch} already exists but is not on origin; delete it with \
         `git branch -D {branch}` and run again"
    )]
    StaleLocalBranch {
        /// The conflicting branch.
        branch: String,
    },
    /// The lock file was not regenerated.
    #[error("the lock file was not regenerated, so the manifest edit was reverted")]
    LockfileNotRegenerated,
    /// Tracked files other than the manifest and its lock file changed during the run.
    #[error("{}", unexpected_changes_text(paths, *more))]
    UnexpectedChanges {
        /// Up to ten of the changed paths.
        paths: Vec<String>,
        /// How many more changed paths were not listed.
        more: usize,
    },
    /// A signal arrived.
    #[error("interrupted during {}", phase.label())]
    Interrupted {
        /// The phase it arrived in.
        phase: PrPhase,
    },
    /// The program is not installed.
    #[error("{tool} was not found on PATH{}", missing_tool_hint(*tool))]
    ToolMissing {
        /// The missing program.
        tool: Tool,
    },
    /// A step exited unsuccessfully.
    #[error("{tool} failed while {step} ({}){}", exit_text(*code), cleanup_hint(*step))]
    ToolFailed {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
        /// Its exit code, when it had one.
        code: Option<i32>,
    },
    /// A step exceeded its time limit.
    #[error(
        "{tool} timed out while {step} after {} seconds{}",
        git::STEP_TIMEOUT.as_secs(),
        cleanup_hint(*step)
    )]
    TimedOut {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
    /// A program could not be started.
    #[error("could not start {tool}: {source}")]
    Spawn {
        /// The program.
        tool: Tool,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// A step printed something unusable.
    #[error("{tool} printed unexpected output while {step}{}", cleanup_hint(*step))]
    UnexpectedOutput {
        /// The program.
        tool: Tool,
        /// The step.
        step: Step,
    },
}

fn supported_ecosystems() -> String {
    EcosystemId::ALL
        .iter()
        .filter(|id| lockfile_support(**id) != LockfileSupport::Deferred)
        .map(|id| id.id())
        .collect::<Vec<_>>()
        .join(", ")
}

fn exit_text(code: Option<i32>) -> String {
    code.map_or_else(
        || "terminated by a signal".to_owned(),
        |code| format!("exit status {code}"),
    )
}

fn cleanup_hint(step: Step) -> &'static str {
    match step {
        Step::CreateRequest => {
            "; the branch was already pushed: open the request manually or delete the remote \
             branch with `git push origin --delete <branch>`, then switch back with \
             `git switch <base branch>`"
        }
        Step::Push | Step::SwitchBack => {
            "; HEAD may still be on the update branch and the push may have happened: switch back \
             with `git switch <base branch>`, then delete the branch with `git branch -D <branch>` \
             and `git push origin --delete <branch>`"
        }
        Step::Stage | Step::Commit => {
            "; HEAD may still be on the update branch: switch back with \
             `git switch <base branch>` and delete the branch with `git branch -D <branch>`"
        }
        Step::Locate
        | Step::Prefix
        | Step::Head
        | Step::Identity
        | Step::Status
        | Step::RemoteBranch
        | Step::LocalBranch
        | Step::Restore
        | Step::Diff
        | Step::Switch => "",
    }
}

/// `gh` and `glab` only run after the branch was pushed, so their absence needs the same
/// cleanup as a failed request creation; `git` is checked before anything changed.
fn missing_tool_hint(tool: Tool) -> &'static str {
    match tool {
        Tool::Git => "",
        Tool::Gh | Tool::Glab => cleanup_hint(Step::CreateRequest),
    }
}

fn unexpected_changes_text(paths: &[String], more: usize) -> String {
    let mut text = String::from(
        "tracked files other than the manifest and its lock file changed during the run, so \
         nothing was committed or pushed",
    );
    if paths.is_empty() && more == 0 {
        text.push_str(" (too many changed files to list)");
    } else {
        text.push_str(": ");
        text.push_str(&paths.join(", "));
        if more > 0 {
            let _ = write!(text, " and {more} more");
        }
    }
    text
}

/// Listens for SIGINT and SIGTERM from before the preflight to the end of the flow.
#[derive(Debug)]
pub struct PrSignals(Option<Interrupts>);

impl PrSignals {
    /// Installs the handlers; must run inside a tokio runtime before the first git process.
    ///
    /// When the OS refuses a handler a warning is logged and no signal is ever reported: the
    /// signal then ends deps-cli itself, as it would without the listener.
    #[must_use]
    pub fn install() -> Self {
        match Interrupts::install() {
            Ok(interrupts) => Self(Some(interrupts)),
            Err(error) => {
                tracing::warn!(%error, "could not install signal handlers for --open-pr");
                Self(None)
            }
        }
    }

    /// Runs `future` unless a signal arrives first, which drops it.
    ///
    /// Dropping the future drops every child guard it holds, which terminates their process
    /// trees.
    ///
    /// # Errors
    ///
    /// [`PrError::Interrupted`] naming `phase` when a signal won.
    pub async fn guard<T>(
        &mut self,
        phase: PrPhase,
        future: impl Future<Output = T>,
    ) -> Result<T, PrError> {
        let signal = async {
            match &mut self.0 {
                Some(interrupts) => interrupts.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            output = future => Ok(output),
            () = signal => Err(PrError::Interrupted { phase }),
        }
    }
}

/// Checks that the repository is ready for `--open-pr`.
///
/// The manifest must be inside a work tree, `HEAD` a named branch deps-cli did not create, a
/// committer identity must exist and no tracked file may be modified. Writes nothing and uses
/// no network.
///
/// # Errors
///
/// A [`PrError`] for the first failed precondition.
pub async fn preflight(manifest: &Path) -> Result<RepoContext, PrError> {
    let runner = Runner {
        group: ProcessGroup::detect(),
        #[cfg(test)]
        tool_dir: None,
    };
    let manifest_dir = manifest
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // A missing directory would make the spawn fail with `NotFound`, which reads as a missing git.
    if !manifest_dir.is_dir() {
        return Err(PrError::NotARepository);
    }

    let toplevel = runner
        .run(
            Tool::Git,
            Step::Locate,
            manifest_dir,
            ["rev-parse", "--show-toplevel"],
        )
        .await?;
    if toplevel.code != Some(0) {
        return Err(PrError::NotARepository);
    }
    let root = PathBuf::from(toplevel.stdout);
    let prefix = runner
        .succeed(
            Tool::Git,
            Step::Prefix,
            manifest_dir,
            ["rev-parse", "--show-prefix"],
        )
        .await?;

    let head = runner
        .run(
            Tool::Git,
            Step::Head,
            &root,
            ["symbolic-ref", "--quiet", "--short", "HEAD"],
        )
        .await?;
    let base = match head.code {
        Some(0) => BaseBranch::new(head.stdout)?,
        Some(1) => return Err(PrError::DetachedHead),
        code => {
            return Err(PrError::ToolFailed {
                tool: Tool::Git,
                step: Step::Head,
                code,
            });
        }
    };

    let identity = runner
        .run(
            Tool::Git,
            Step::Identity,
            &root,
            ["var", "GIT_COMMITTER_IDENT"],
        )
        .await?;
    if identity.code != Some(0) {
        return Err(PrError::MissingIdentity);
    }

    let status = runner
        .succeed(
            Tool::Git,
            Step::Status,
            &root,
            ["status", "--porcelain", "--untracked-files=no"],
        )
        .await?;
    if !status.is_empty() {
        return Err(PrError::DirtyWorkingTree);
    }

    Ok(RepoContext {
        root,
        manifest_dir: RepoRelativeDir::from_prefix(&prefix),
        manifest_file: manifest
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        base,
        group: runner.group,
        #[cfg(test)]
        tool_dir: None,
    })
}

/// One proposed update: the `Applied` or `RequiresLockfileUpdate` items of a plan.
fn proposed_updates(
    plan: &UpdatePlan,
    formatter: &dyn EcosystemFormatter,
) -> Vec<(String, ConcreteVersion)> {
    let mut proposed: Vec<(String, ConcreteVersion)> = plan
        .items
        .iter()
        .filter_map(|item| match &item.outcome {
            Outcome::Applied { target, .. } | Outcome::RequiresLockfileUpdate { target } => {
                let normalized =
                    formatter.normalize_package_name(&PackageName::new(item.name.as_str()));
                Some((normalized.into_string(), target.clone()))
            }
            Outcome::AppliedViaLockfile { .. }
            | Outcome::Skipped { .. }
            | Outcome::Unfixable(_) => None,
        })
        .collect();
    proposed.sort_by(|a, b| (&a.0, a.1.as_str()).cmp(&(&b.0, b.1.as_str())));
    proposed
}

/// FNV-1a 64: stable across Rust versions and platforms, unlike `DefaultHasher`.
fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Lossy, human-readable slice of a branch name; identity lives in the hash, not here.
fn sanitize_part(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.to_lowercase().chars() {
        let ch = if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        {
            ch
        } else {
            '-'
        };
        if matches!(ch, '.' | '-') && out.ends_with(ch) {
            continue;
        }
        out.push(ch);
    }
    let trim = |text: &str| text.trim_matches(['.', '-']).to_owned();
    let cut: String = trim(&out).chars().take(BRANCH_PART_MAX_CHARS).collect();
    let mut part = trim(&cut);
    if part.ends_with(".lock") {
        part.truncate(part.len() - ".lock".len());
        part.push_str("-lock");
    }
    if part.is_empty() {
        part.push('x');
    }
    part
}

/// The branch this update set is proposed on; `None` when nothing would change.
///
/// The name is `deps-cli/<ecosystem>/[<dir>/]<label>-<h8>`; `<h8>` hashes the ecosystem, the raw
/// manifest path, the group and the sorted `(name, target)` pairs, so two update sets never
/// share a branch even when their readable parts collide after sanitizing.
#[must_use]
pub fn branch_for(
    ctx: &RepoContext,
    ecosystem: EcosystemId,
    plan: &UpdatePlan,
    formatter: &dyn EcosystemFormatter,
    group: Option<&UpdateGroup>,
) -> Option<BranchName> {
    let proposed = proposed_updates(plan, formatter);
    let [first, rest @ ..] = proposed.as_slice() else {
        return None;
    };

    let group_name = group.map_or("", |group| group.name().as_str());
    let mut identity = format!(
        "{}\n{}\n{group_name}\n",
        ecosystem.id(),
        ctx.manifest_path()
    );
    for (name, target) in &proposed {
        let _ = writeln!(identity, "{name}\t{target}");
    }
    let hash = format!("{:08x}", fnv1a64(identity.as_bytes()) >> 32);

    let label = match (group, rest.is_empty()) {
        (Some(group), _) => sanitize_part(group.name().as_str()),
        (None, true) => sanitize_part(&format!("{}-{}", first.0, first.1)),
        (None, false) => "all".to_owned(),
    };
    let dir = if ctx.manifest_dir.is_root() {
        String::new()
    } else {
        format!("{}/", sanitize_part(&ctx.manifest_dir.0))
    };
    Some(BranchName(format!(
        "{BRANCH_PREFIX}{}/{dir}{label}-{hash}",
        ecosystem.id()
    )))
}

/// Looks the branch up on `origin` and locally.
///
/// # Errors
///
/// [`PrError::StaleLocalBranch`] when only a local branch of that name exists, or a failed git
/// step.
pub async fn check_branch(ctx: &RepoContext, branch: BranchName) -> Result<BranchCheck, PrError> {
    let runner = ctx.runner();
    let reference = format!("refs/heads/{}", branch.0);
    let remote = runner
        .run(
            Tool::Git,
            Step::RemoteBranch,
            &ctx.root,
            [
                "ls-remote",
                "--exit-code",
                "--heads",
                "origin",
                reference.as_str(),
            ],
        )
        .await?;
    match remote.code {
        Some(0) => return Ok(BranchCheck::AlreadyProposed(branch)),
        Some(2) => {}
        code => {
            return Err(PrError::ToolFailed {
                tool: Tool::Git,
                step: Step::RemoteBranch,
                code,
            });
        }
    }
    let local = runner
        .run(
            Tool::Git,
            Step::LocalBranch,
            &ctx.root,
            ["rev-parse", "--verify", "--quiet", reference.as_str()],
        )
        .await?;
    match local.code {
        Some(0) => Err(PrError::StaleLocalBranch { branch: branch.0 }),
        Some(1) => Ok(BranchCheck::Free(FreeBranch(branch))),
        code => Err(PrError::ToolFailed {
            tool: Tool::Git,
            step: Step::LocalBranch,
            code,
        }),
    }
}

/// Escapes the characters git's glob pathspec magic would read as patterns.
fn escape_glob(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        if matches!(ch, '*' | '?' | '[' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// Whether the finished run may be published.
#[derive(Debug)]
pub enum Readiness<'a> {
    /// The lock file is ready and at least one item was settled.
    Ready(Publishable<'a>),
    /// The lock file was not regenerated (`skipped`, `unsupported` or `failed`).
    LockfileNotRegenerated,
    /// The lock file is ready but no item is `applied`, so nothing proven could be proposed.
    NothingSettled,
}

/// A run that carries at least one `applied` item and a usable lock file; only [`readiness`]
/// makes one, so a request text cannot be built for an empty update.
#[derive(Debug, Clone, Copy)]
pub struct Publishable<'a>(&'a UpdateRun);

/// Decides whether `run` may be published.
///
/// The lock file outcome is checked first; a run whose only items are unproven lock file moves
/// (`RequiresLockfileUpdate`) is [`Readiness::NothingSettled`].
#[must_use]
pub fn readiness(run: &UpdateRun) -> Readiness<'_> {
    match &run.lockfile {
        LockfileOutcome::Regenerated { .. } | LockfileOutcome::NotApplicable(_) => {}
        LockfileOutcome::Skipped(_)
        | LockfileOutcome::Unsupported { .. }
        | LockfileOutcome::Failed(_) => return Readiness::LockfileNotRegenerated,
    }
    if applied_bumps(run).is_empty() {
        Readiness::NothingSettled
    } else {
        Readiness::Ready(Publishable(run))
    }
}

/// Reverts the tracked files directly inside the manifest's directory (the manifest and any
/// lock file a regeneration may have written) to `HEAD`, in the index and the work tree.
///
/// Edits elsewhere in the repository and untracked files are left alone; an edit made beside
/// the manifest while the run was going is reverted too.
///
/// # Errors
///
/// A failed git step.
pub async fn restore(ctx: &RepoContext) -> Result<(), PrError> {
    let pathspec = if ctx.manifest_dir.is_root() {
        ":(top,glob)*".to_owned()
    } else {
        format!(":(top,glob){}/*", escape_glob(&ctx.manifest_dir.0))
    };
    ctx.runner()
        .succeed(
            Tool::Git,
            Step::Restore,
            &ctx.root,
            [
                "restore",
                "--source=HEAD",
                "--staged",
                "--worktree",
                "--",
                pathspec.as_str(),
            ],
        )
        .await
        .map(drop)
}

/// One applied dependency as shown in the request text.
struct Bump<'a> {
    name: &'a str,
    from: String,
    to: &'a ConcreteVersion,
    kind: UpdateKind,
}

fn applied_bumps(run: &UpdateRun) -> Vec<Bump<'_>> {
    run.plan
        .items
        .iter()
        .filter_map(|item| match &item.outcome {
            Outcome::Applied { target, .. } | Outcome::AppliedViaLockfile { target } => {
                Some(Bump {
                    name: item.name.as_str(),
                    from: item.current.render_text(),
                    to: target,
                    kind: item.current.update_kind_to(target),
                })
            }
            Outcome::Skipped { .. }
            | Outcome::RequiresLockfileUpdate { .. }
            | Outcome::Unfixable(_) => None,
        })
        .collect()
}

const fn kind_label(kind: UpdateKind) -> &'static str {
    match kind {
        UpdateKind::Major => "major",
        UpdateKind::Minor => "minor",
        UpdateKind::Patch => "patch",
        UpdateKind::Unknown => "unknown",
    }
}

/// Plain text for a title or commit line: control characters dropped, backticks removed, cut to
/// `max` characters.
fn plain(text: &str, max: usize) -> String {
    text.chars()
        .filter(|ch| !ch.is_control() && *ch != '`')
        .take(max)
        .collect()
}

/// A Markdown code span that cannot mention anyone or break a table row.
fn code_span(text: &str) -> String {
    let mut span = String::from("`");
    for ch in text
        .chars()
        .filter(|ch| !ch.is_control() && *ch != '`')
        .take(BODY_NAME_MAX_CHARS)
    {
        if ch == '|' {
            span.push('\\');
        }
        span.push(ch);
    }
    span.push('`');
    span
}

fn title_for(ctx: &RepoContext, bumps: &[Bump<'_>], group: Option<&UpdateGroup>) -> String {
    let count = bumps.len();
    let mut title = match (group, bumps) {
        (Some(group), _) => format!(
            "Bump the {} group with {count} update{} in {}",
            group.name().as_str(),
            if count == 1 { "" } else { "s" },
            plain(&ctx.manifest_path(), usize::MAX)
        ),
        (None, [only]) => {
            let from = if only.from.is_empty() {
                String::new()
            } else {
                format!(" from {}", plain(&only.from, TITLE_NAME_MAX_CHARS))
            };
            let location = if ctx.manifest_dir.is_root() {
                String::new()
            } else {
                format!(" in {}", plain(&ctx.manifest_dir.0, usize::MAX))
            };
            format!(
                "Bump {}{from} to {}{location}",
                plain(only.name, TITLE_NAME_MAX_CHARS),
                plain(only.to.as_str(), TITLE_NAME_MAX_CHARS)
            )
        }
        (None, _) => format!(
            "Bump {count} dependencies in {}",
            plain(&ctx.manifest_path(), usize::MAX)
        ),
    };
    if title.len() <= TITLE_MAX_BYTES {
        return title;
    }
    title.truncate(title.floor_char_boundary(TITLE_MAX_BYTES - "...".len()));
    title.push_str("...");
    title
}

fn body_for(run: &UpdateRun, bumps: &[Bump<'_>]) -> String {
    let mut body = String::from("| Package | From | To | Kind |\n|---|---|---|---|\n");
    for bump in bumps.iter().take(BODY_MAX_ROWS) {
        let from = if bump.from.is_empty() {
            "-".to_owned()
        } else {
            code_span(&bump.from)
        };
        let _ = writeln!(
            body,
            "| {} | {from} | {} | {} |",
            code_span(bump.name),
            code_span(bump.to.as_str()),
            kind_label(bump.kind)
        );
    }
    if bumps.len() > BODY_MAX_ROWS {
        let _ = writeln!(body, "\nand {} more", bumps.len() - BODY_MAX_ROWS);
    }
    match &run.lockfile {
        LockfileOutcome::Regenerated { lockfile, tool, .. } => {
            let _ = writeln!(
                body,
                "\nThe lock file {} was regenerated with {}.",
                code_span(&lockfile.to_string()),
                code_span(&tool.to_string())
            );
        }
        LockfileOutcome::Skipped(_)
        | LockfileOutcome::NotApplicable(_)
        | LockfileOutcome::Unsupported { .. }
        | LockfileOutcome::Failed(_) => {}
    }
    let unresolved = run
        .plan
        .items
        .iter()
        .filter(|item| item.is_unresolved())
        .count();
    if unresolved > 0 {
        let _ = writeln!(
            body,
            "\n{unresolved} dependenc{} could not be updated automatically.",
            if unresolved == 1 { "y" } else { "ies" }
        );
    }
    body.push_str("\n---\nOpened by deps-cli.\n");
    body.truncate(body.floor_char_boundary(BODY_MAX_BYTES));
    body
}

fn commit_body_for(bumps: &[Bump<'_>]) -> String {
    let mut body = String::new();
    for bump in bumps.iter().take(BODY_MAX_ROWS) {
        let from = if bump.from.is_empty() {
            "?"
        } else {
            bump.from.as_str()
        };
        let _ = writeln!(
            body,
            "- {} {} -> {}",
            plain(bump.name, TITLE_NAME_MAX_CHARS),
            plain(from, TITLE_NAME_MAX_CHARS),
            plain(bump.to.as_str(), TITLE_NAME_MAX_CHARS)
        );
    }
    if bumps.len() > BODY_MAX_ROWS {
        let _ = writeln!(body, "and {} more", bumps.len() - BODY_MAX_ROWS);
    }
    body
}

/// Renders the request text for the applied items of `run`.
///
/// The title (also the commit subject) is plain text of at most 250 bytes, the body is Markdown
/// with every name and version as a code span, and the text also carries the commit message
/// body and the files the commit may contain.
#[must_use]
pub fn describe(
    ctx: &RepoContext,
    run: &Publishable<'_>,
    group: Option<&UpdateGroup>,
) -> PullRequestText {
    let run = run.0;
    let bumps = applied_bumps(run);
    let mut publishable_paths = vec![ctx.manifest_path()];
    if let LockfileOutcome::Regenerated { lockfile, .. } = &run.lockfile
        && let Some(name) = lockfile.file_name()
    {
        publishable_paths.push(ctx.manifest_dir.join(&name.to_string_lossy()));
    }
    PullRequestText {
        title: title_for(ctx, &bumps, group),
        body: body_for(run, &bumps),
        commit_body: commit_body_for(&bumps),
        publishable_paths,
    }
}

/// The tracked paths that differ from `HEAD`, or the error when they cannot all be published.
async fn changed_publishable_paths(
    runner: &Runner,
    ctx: &RepoContext,
    text: &PullRequestText,
) -> Result<Vec<String>, PrError> {
    const LISTED: usize = 10;

    let diff = runner
        .run(
            Tool::Git,
            Step::Diff,
            &ctx.root,
            ["diff", "--name-only", "-z", "HEAD"],
        )
        .await?;
    if diff.code != Some(0) {
        return Err(PrError::ToolFailed {
            tool: Tool::Git,
            step: Step::Diff,
            code: diff.code,
        });
    }
    let changed: Vec<String> = diff
        .raw
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect();
    let (publishable, foreign): (Vec<String>, Vec<String>) = changed
        .into_iter()
        .partition(|path| text.publishable_paths.contains(path));
    if diff.truncated || !foreign.is_empty() {
        return Err(PrError::UnexpectedChanges {
            more: foreign.len().saturating_sub(LISTED),
            paths: foreign.into_iter().take(LISTED).collect(),
        });
    }
    Ok(publishable)
}

/// Commits the manifest and regenerated lock file changes on the update branch, pushes it and
/// opens the request.
///
/// Returns [`PrOutcome::NothingToCommit`] without touching any branch when none of the
/// publishable files differs from `HEAD`. When another tracked file differs it stops with
/// [`PrError::UnexpectedChanges`] before anything is staged. On success `HEAD` is still on the
/// update branch: print the URL, then call [`OpenedRequest::switch_back`]. Run it inside
/// [`PrSignals::guard`]: dropping the future terminates the running tool's process tree.
///
/// # Errors
///
/// A [`PrError`] from the first failing step; the repository is left as that step left it.
pub async fn open(
    ctx: &RepoContext,
    host: PrHost,
    branch: FreeBranch,
    text: &PullRequestText,
) -> Result<PrOutcome, PrError> {
    let runner = ctx.runner();
    let root = ctx.root.as_path();
    let name = branch.0.as_str();

    let paths = changed_publishable_paths(&runner, ctx, text).await?;
    if paths.is_empty() {
        return Ok(PrOutcome::NothingToCommit);
    }

    let git = |step, args: Vec<String>| runner.succeed(Tool::Git, step, root, args);
    git(
        Step::Switch,
        vec!["switch".into(), "--create".into(), name.into()],
    )
    .await?;
    let mut stage = vec!["add".to_owned(), "--".to_owned()];
    stage.extend(paths);
    git(Step::Stage, stage).await?;
    git(
        Step::Commit,
        vec![
            "commit".into(),
            format!("--message={}", text.title),
            format!("--message={}", text.commit_body),
        ],
    )
    .await?;
    git(
        Step::Push,
        vec![
            "push".into(),
            "--set-upstream".into(),
            "origin".into(),
            name.into(),
        ],
    )
    .await?;

    let base = ctx.base.0.as_str();
    let (tool, request_args) = match host {
        PrHost::Github => (
            Tool::Gh,
            vec![
                "pr".to_owned(),
                "create".to_owned(),
                format!("--base={base}"),
                format!("--head={name}"),
                format!("--title={}", text.title),
                format!("--body={}", text.body),
            ],
        ),
        PrHost::Gitlab => (
            Tool::Glab,
            vec![
                "mr".to_owned(),
                "create".to_owned(),
                format!("--source-branch={name}"),
                format!("--target-branch={base}"),
                format!("--title={}", text.title),
                format!("--description={}", text.body),
                "--yes".to_owned(),
            ],
        ),
    };
    let printed = runner
        .succeed(tool, Step::CreateRequest, root, request_args)
        .await?;
    let url = RequestUrl::from_output(&printed).ok_or(PrError::UnexpectedOutput {
        tool,
        step: Step::CreateRequest,
    })?;
    Ok(PrOutcome::Opened(OpenedRequest {
        url,
        base: ctx.base.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_missing_host_cli_names_the_remote_branch_cleanup() {
        for tool in [Tool::Gh, Tool::Glab] {
            let message = PrError::ToolMissing { tool }.to_string();
            assert!(message.contains("git push origin --delete"), "{message}");
        }
        let git = PrError::ToolMissing { tool: Tool::Git }.to_string();
        assert!(!git.contains("--delete"), "{git}");
    }
}

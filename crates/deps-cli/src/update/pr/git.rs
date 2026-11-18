//! Step runner for the `--open-pr` git phase: `git`, `gh` and `glab` run argv-only through the
//! lock file tools' terminate-on-drop child guard.

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
    /// `git diff --quiet`.
    Diff,
    /// `git switch --create`.
    Switch,
    /// `git add --update`.
    Stage,
    /// `git commit`.
    Commit,
    /// `git push`.
    Push,
    /// `gh pr create` or `glab mr create`.
    CreateRequest,
    /// `git switch` back to the base branch.
    SwitchBack,
}

---
aliases:
  - deps-cli update --open-pr Plan
tags:
  - sdd
  - plan
  - deps-cli
  - git
created: 2026-11-18
status: shipped
related:
  - "[[spec]]"
  - "[[tasks]]"
---

# Technical Plan: deps-cli update opens a pull request, optionally for one update group

## 1. Architecture

### Approach

A new `deps_cli::update::pr` module runs git and `gh`/`glab` through the lock file tools' terminate-on-drop guard (`regen::run::ChildGuard`, which #2066 extends with SIGTERM, a bounded grace and a group SIGKILL). `main.rs` calls it at three points of the existing `update` flow: preflight before the walk, the branch check between planning and `apply_plan`, and the git phase after the report is printed. Group selection is a post-plan demotion pass in `update::group`, beside `dedup_applied_items`.

```
run_update_command
 ├─ CLI boundary: FR-001 / FR-016 checks
 ├─ PrSignals::install()                                     (FR-012, before any git process)
 ├─ signals.guard(Preflight, pr::preflight(manifest)) -> RepoContext   (FR-002)
 ├─ signals.guard(Update, run_update(..))
 │   ├─ walk -> regen::lockfile_support(id) == Deferred ?    (FR-003)
 │   ├─ analyze, plan, dedup, group::demote_outside_group    (FR-017)
 │   ├─ pr::branch_for(..) -> pr::check_branch(..)           (FR-004..006)
 │   │     Free(FreeBranch) | AlreadyProposed(BranchName)
 │   └─ apply_plan + regenerate_lockfile (dry-run when AlreadyProposed)
 ├─ pr::readiness(&run):                                     (exhaustive)
 │     LockfileNotRegenerated -> pr::restore, dry-run render, exit 2      (FR-007)
 │     NothingSettled         -> pr::restore, dry-run render, update code (FR-020)
 │     Ready(Publishable)     -> continue
 ├─ render report
 ├─ signals.guard(Publish, pr::open(ctx, host, FreeBranch, &text))       (FR-008, FR-009)
 │     Opened(OpenedRequest) -> print opened.url()  (before switching back)
 └─ signals.guard(Publish, opened.switch_back(ctx))                       (FR-009, FR-013)
```

The branch check runs inside `run_update`, so it is covered by the `Update` guard and an interrupt there reports `Update`.

### Key Design Decisions

| Decision | Rationale |
|---|---|
| Reuse `ChildGuard` (made reachable as `pub(in crate::update)`), not a second runner | One terminate-on-drop policy for every child; `git push` spawns `ssh`, `gh` spawns `git` (critic M4) |
| `FreeBranch` proof token | `open` cannot be called without the branch check |
| Content-addressed branch | Scheduled re-runs of the same update set are a no-op instead of an error (critic S4) |
| Static deferred-ecosystem refusal | `regen::strategy` is a pure function of `EcosystemId`; refusing early avoids a written manifest with no pull request (critic S2) |
| Restore on lock file refusal, limited to the manifest's directory | Dynamic `unsupported` reasons (workspace member, symlink, vendoring) are only known after the write; restoring keeps the next run's clean-tree preflight passing. The pathspec `:(top,glob)<dir>/*` covers the manifest and every lock file a regeneration may write (`unsupported` never runs the tool; workspace-member and Go-workspace layouts are `unsupported`), and leaves edits elsewhere untouched |
| One `PrSignals` listener from before the preflight to the end | Preflight, `ls-remote` and the git phase spawn children; without a listener a SIGTERM kills deps-cli before any `Drop` runs (critic S3, M-b). It also closes the window between regeneration and the publish phase |
| FNV-1a 64 for `<h8>`, always appended, input = ecosystem + raw manifest path + group + raw sorted `(name, target)` | Stable across Rust versions and platforms (unlike `DefaultHasher`), no dependency. The sanitized human parts are lossy and cut to 48 characters; identity lives only in the hash (critic N1) |
| `Publishable` proof token from `readiness` | `describe` takes it, so a "Bump 0 dependencies" request cannot be built (impl-critic S1); no pull request for an unproven lock file move |
| Stage only the publishable paths, refuse any other changed tracked path | `git add --update` would commit and push any tracked edit made during the run (security MEDIUM, CWE-538) |
| `OpenedRequest` with `url()` and a consuming `switch_back` | The URL is printed before the switch-back and survives its failure (impl-critic S2); `#[must_use]` keeps the switch-back from being forgotten |

## 2. Project Structure

| Path | Change |
|---|---|
| `crates/deps-cli/src/update/pr/mod.rs` | new: public types, `preflight`, `branch_for`, `check_branch`, `describe`, `open`, `restore` |
| `crates/deps-cli/src/update/pr/git.rs` | new: step runner over `ChildGuard`, `Tool`, `Step` |
| `crates/deps-cli/src/update/pr/acceptance_tests.rs` | new, tester |
| `crates/deps-cli/src/update/pr/publish_safety_tests.rs` | new, tester (review round: FR-009 staging, FR-020, URL, base branch, caps) |
| `crates/deps-cli/src/update/regen/leader_state_tests.rs` | new, tester (#2066 track, `waitid` classifier) |
| `crates/deps-cli/src/update/group.rs` | new: `UpdateGroup`, `demote_outside_group` |
| `crates/deps-cli/src/update/group_tests.rs` | new, tester |
| `crates/deps-cli/src/update/mod.rs` | `pub mod pr; pub mod group;`, `SkipReason::NotInGroup`, `reason()` arm |
| `crates/deps-cli/src/update/regen/mod.rs` | `pub(in crate::update) use` of `ChildGuard`, `ProcessGroup`, `Interrupts`; `pub enum LockfileSupport` + `pub const fn lockfile_support`; doc at `interrupt_listener` |
| `crates/deps-cli/src/update/regen/interrupt.rs` | `Interrupts`, `install`, `recv` become `pub(in crate::update)`; module doc |
| `crates/deps-cli/src/update/regen/run.rs` | (#2066 track) `ChildGuard::spawn`, `pub(in crate::update)` on `ChildGuard`, `ProcessGroup`, `detect` |
| `crates/deps-cli/src/config.rs` | `GroupName`, `GroupRule`, `UpdateConfig::groups` |
| `crates/deps-cli/src/exit.rs` | `update_exit_code` as an exhaustive match, `NotInGroup` exit-neutral |
| `crates/deps-cli/src/cli.rs`, `src/main.rs` | flags and wiring |
| `book/src/cli.md`, `crates/deps-cli/README.md` | docs |

No new dependency: tokio `process`/`time`/`io-util` and rustix `process` are already enabled.

## 3. Data Model

```rust
// update/pr/mod.rs
pub enum PrHost { Github, Gitlab }                 // clap::ValueEnum
pub struct RepoContext {                            // private fields
    root: PathBuf, manifest_dir: RepoRelativeDir, base: BaseBranch, group: ProcessGroup,
    #[cfg(test)] tool_dir: Option<PathBuf>,         // gh/glab shims; git always from PATH
}
struct BaseBranch(String);                          // rejects `deps-cli/` and a leading `-`
pub struct BranchName(String);                      // sanitized, `deps-cli/` prefix
pub struct FreeBranch(BranchName);                  // only from check_branch
pub enum BranchCheck { Free(FreeBranch), AlreadyProposed(BranchName) }
pub enum Readiness<'a> { Ready(Publishable<'a>), LockfileNotRegenerated, NothingSettled }
pub struct Publishable<'a>(&'a UpdateRun);          // only from readiness: >= 1 applied item
pub struct PullRequestText { title: String, body: String, commit_body: String,
                             publishable_paths: Vec<String> }   // repo-relative manifest [+ lock file]
pub enum PrOutcome { Opened(OpenedRequest), NothingToCommit }
#[must_use] pub struct OpenedRequest { url: RequestUrl, base: String }  // url(), switch_back(self, &RepoContext)
pub struct RequestUrl(String);                      // last non-empty stdout line, control chars removed, <= 2,048 chars
pub enum PrError {
    NotARepository, DetachedHead, OnUpdateBranch { branch: String }, MissingIdentity,
    DirtyWorkingTree, UnsupportedEcosystem(EcosystemId), StaleLocalBranch { branch: String },
    LockfileNotRegenerated, UnexpectedChanges { paths: Vec<String> /* <= 10 shown */, more: usize },
    Interrupted { phase: PrPhase },
    ToolMissing { tool: Tool }, ToolFailed { tool: Tool, step: Step, code: Option<i32> },
    TimedOut { tool: Tool, step: Step }, Spawn { tool: Tool, source: io::Error },
    UnexpectedOutput { tool: Tool, step: Step },
}
pub enum PrPhase { Preflight, Update, Publish }
pub struct PrSignals(Option<Interrupts>);           // None when the OS refused a handler (warned)
// update/pr/git.rs
pub enum Tool { Git, Gh, Glab }                    // Display: "git", "gh", "glab"
pub enum Step { Locate, Prefix, Head, Identity, Status, RemoteBranch, LocalBranch,
                Restore, Diff, Switch, Stage, Commit, Push, CreateRequest, SwitchBack }
                                                    // Display: plain words ("pushing the branch")

// update/regen/mod.rs
pub enum LockfileSupport { Regenerates, NoLockfileFormat, Deferred }
impl DisplayLockPath { pub fn file_name(&self) -> Option<&OsStr> }  // the regenerated lock file beside the manifest

// config.rs
pub struct GroupName(String);                       // serde try_from String, FromStr
pub struct GroupRule { pub dependencies: Option<Vec<String>>,
                       pub update_types: Option<Vec<UpdateTypeToken>> } // deny_unknown_fields
pub struct UpdateConfig { pub ignore: Vec<IgnoreRule>, pub groups: BTreeMap<GroupName, GroupRule> }

// update/group.rs
pub struct UpdateGroup { name: GroupName, dependencies: Option<Vec<NormalizedName>>,
                         update_types: Option<Vec<UpdateTypeToken>> }
// update/mod.rs
SkipReason::NotInGroup
```

## 4. Contracts

| Function | Preconditions | Postconditions | Undefined |
|---|---|---|---|
| `pr::preflight(manifest: &Path) -> Result<RepoContext, PrError>` | tokio runtime | Ok only for FR-002's four checks passing; no write, no network; `ProcessGroup::detect()` recorded | — |
| `regen::lockfile_support(EcosystemId) -> LockfileSupport` | — | exhaustive over `EcosystemId` through `strategy`; `Deferred` exactly for PyPI, Bundler, Dart, Composer, Gradle, Swift, NuGet, Deno | — |
| `PrSignals::install() -> PrSignals` | tokio runtime; called before the first git process | handlers for SIGINT/SIGTERM (Ctrl-C on Windows) installed; on refusal a warning and a listener that never fires | — |
| `PrSignals::guard<T>(&mut self, PrPhase, impl Future<Output = T>) -> Result<T, PrError>` | — | `Ok(output)` when the future finishes first; on a signal the future is dropped (its `ChildGuard`s terminate their trees) and `Err(Interrupted { phase })` | — |
| `pr::branch_for(&RepoContext, EcosystemId, &UpdatePlan, &dyn EcosystemFormatter, Option<&UpdateGroup>) -> Option<BranchName>` | plan already deduplicated and group-demoted | `None` iff no item is `Applied`/`RequiresLockfileUpdate`; else spec §5 grammar, always ending in `-<h8>`; `<h8>` input = ecosystem id, raw repo-relative manifest path, group name, raw sorted `(normalized name, target)` lines; deterministic regardless of item order; different inputs differ in `<h8>` (up to a 32-bit collision); valid for `git check-ref-format --branch`, ≤ 140 bytes | 32-bit hash collision |
| `pr::check_branch(&RepoContext, BranchName) -> Result<BranchCheck, PrError>` | — | remote exists → `AlreadyProposed`; remote absent and local exists → `StaleLocalBranch`; both absent → `Free`; no write | remote reachability races with a concurrent pusher |
| `pr::restore(&RepoContext) -> Result<(), PrError>` | preflight passed (tracked tree equalled `HEAD`) | tracked files directly inside the manifest's directory equal `HEAD`; every other path and every untracked file untouched | an edit someone made beside the manifest during the run is reverted (documented) |
| `pr::readiness(&UpdateRun) -> Readiness<'_>` | — | exhaustive on `LockfileOutcome`: `Skipped(_)`, `Unsupported { .. }`, `Failed(_)` → `LockfileNotRegenerated`; otherwise no `Applied`/`AppliedViaLockfile` item → `NothingSettled`; otherwise `Ready` | — |
| `pr::describe(&RepoContext, &Publishable, Option<&UpdateGroup>) -> PullRequestText` | — | title per spec §5 in plain text, ≤ 250 bytes (names and versions cut to 80 characters, then a character-boundary cut plus `...`); commit subject = title; count ≥ 1; covers exactly `Applied`/`AppliedViaLockfile`; body: names/versions as code spans, ≤ 50 rows plus `and N more`, then cut to ≤ 60,000 bytes at a character boundary; `publishable_paths` = repo-relative manifest path, plus `<manifest dir>/<DisplayLockPath::file_name()>` for a `Regenerated` outcome | — |
| `pr::open(&RepoContext, PrHost, FreeBranch, &PullRequestText) -> Result<PrOutcome, PrError>` | report already printed; called inside `PrSignals::guard(Publish, ..)` | `git diff --name-only -z HEAD`: a changed path outside `publishable_paths`, or output that reaches the 64 KiB cap → `UnexpectedChanges` with nothing staged; no publishable path changed → `NothingToCommit` without touching a branch; otherwise Switch, `git add -- <changed publishable paths>`, Commit, Push, CreateRequest → `Opened(OpenedRequest)` with `HEAD` still on the update branch | repository state after a failed or interrupted step |
| `OpenedRequest::url(&self) -> &str` / `OpenedRequest::switch_back(self, &RepoContext) -> Result<(), PrError>` | — | `url` has no control characters; `switch_back` runs `git switch <base>`; on failure `ToolFailed { step: SwitchBack }` whose message carries the cleanup hint | — |
| `group::UpdateGroup::new(GroupName, GroupRule, &dyn EcosystemFormatter)` | — | names normalized once | — |
| `group::UpdateGroup::contains(&NormalizedName, UpdateKind) -> bool` | — | FR-018 | — |
| `group::demote_outside_group(&mut [PlannedUpdateItem], &UpdateGroup, &dyn EcosystemFormatter)` | — | only `Applied` items change, to `Skipped { reason: NotInGroup, target: Some(target) }` | — |
| `exit::update_exit_code` | — | exhaustive `match` on `Outcome` and `SkipReason`, no wildcard; the same code as before for every pre-existing variant (equivalence test per variant); `NotInGroup` → clean | — |
| `ChildGuard::spawn(&mut Command, ProcessGroup) -> io::Result<ChildGuard>` (#2066 track) | tokio runtime | `process_group(0)` when `Own` (unix), `kill_on_drop(true)`; drop: TERM → wait ≤ grace for the leader without reaping → KILL (group for `Own`, leader for `Inherit`). The poll classifies each `waitid` result as `Running` (`Ok(None)`), `Exited` (`Ok(Some)`), `Gone` (`Err(ECHILD)`: reaped elsewhere, so the pid may be recycled: no KILL is sent) or `Unknown` (other error: stop polling, sleep out the grace, then KILL). The early-exit poll uses `rustix::process::waitid` under exactly rustix's own predicate `cfg(not(any(target_os = "cygwin", target_os = "horizon", target_os = "openbsd", target_os = "redox", target_os = "wasi")))` (`rustix-1.1.6/src/process/wait.rs:480`); elsewhere on unix it sleeps the full grace | — |

`main.rs` holds `Publish::Propose { repo: &RepoContext, branch: FreeBranch }`, so a proposal without a repository is not representable (impl-critic M8).

`regen::regenerate_lockfile_unlistened(UpdatePlan, &ManifestTarget, RegenerationGate) -> UpdateRun`: precondition, the caller drops the future on a signal (`PrSignals::guard`); postcondition, the same as `regenerate_lockfile` (both delegate to one private `regenerate_with_interrupt`) but no listener is installed. Only `--open-pr` runs use it, so exactly one listener exists.

`PrError::UnsafeBaseBranch { branch }`: `HEAD` on a branch starting with `-` (FR-002).

### Argv per step

| Step | Command (cwd = repository root unless noted) | Success / meaning |
|---|---|---|
| Locate | `git rev-parse --show-toplevel` (cwd: manifest dir) | 0 |
| Prefix | `git rev-parse --show-prefix` (cwd: manifest dir) | 0 |
| Head | `git symbolic-ref --quiet --short HEAD` | 0; 1 → `DetachedHead` |
| Identity | `git var GIT_COMMITTER_IDENT` | 0; else `MissingIdentity` |
| Status | `git status --porcelain --untracked-files=no` | 0 and empty stdout |
| RemoteBranch | `git ls-remote --exit-code --heads origin refs/heads/<b>` | 0 exists, 2 absent |
| LocalBranch | `git rev-parse --verify --quiet refs/heads/<b>` | 0 exists, 1 absent |
| Restore | `git restore --source=HEAD --staged --worktree -- ':(top,glob)<dir>/*'` (`':(top,glob)*'` at the root) | 0 |
| Diff | `git diff --name-only -z HEAD` | 0; NUL-separated repo-relative paths |
| Switch | `git switch --create <b>` | 0 |
| Stage | `git add -- <changed publishable paths>` | 0 |
| Commit | `git commit --message=<title> --message=<commit_body>` | 0 |
| Push | `git push --set-upstream origin <b>` | 0 |
| CreateRequest | `gh pr create --base=<base> --head=<b> --title=<t> --body=<body>` or `glab mr create --source-branch=<b> --target-branch=<base> --title=<t> --description=<body> --yes` | 0 |
| SwitchBack | `git switch <base>` | 0 |

Each step: stdin null, stdout captured up to 64 KiB, stderr inherited, env `GIT_TERMINAL_PROMPT=0`, `GH_PROMPT_DISABLED=1`, timeout `STEP_TIMEOUT = Duration::from_mins(2)` (including the hooks the step triggers); `NotFound` on spawn → `ToolMissing`. Requires git 2.23+. glab flag names are verified against `glab mr create --help` during implementation.

## 5. Security

- No token is read; credentials stay with git, `gh` and `glab`.
- No shell; branch names start with `deps-cli/` and the base branch cannot start with `-`, so no name can be read as an option; free text is passed as `--flag=value`.
- Names in Markdown are code spans, so `@scope/pkg` creates no mention and no table can be broken.
- Only the manifest and its regenerated lock file are staged; any other changed tracked path aborts the publish (CWE-538).
- The printed URL has control characters removed (CWE-150).

## 6. Testing Strategy

| Layer | Cases |
|---|---|
| Pure | branch grammar over hostile names; every branch ends in `-<h8>`; distinctness: `@scope/x` vs `scope-x`, `a/b/Cargo.toml` vs `a-b/Cargo.toml`, a 64-character group with two update sets, a 200-character single name at two targets, same set with and without a group; determinism under item order; FNV-1a known answers (`""` → `cbf29ce484222325`, `"a"` → `af63dc4c8601ec8c`); title ≤ 250 bytes for a 300-character name; body escaping and caps with 1,000 items; readiness mapping |
| CLI | `--open-pr` with `--dry-run`/`--offline` rejected; without `regenerate` exit 2; `--group` without `--config`, with `--security-only`, unknown name |
| Exit code | one case per `Outcome`/`SkipReason` variant: `update_exit_code` equals the pre-change result (table taken from `exit.rs:157-177` on main); `NotInGroup` → 0 |
| Git phase (unix, real git) | fixture repo with local `user.name`, `user.email`, `commit.gpgsign=false`, bare `origin`, fake `gh`/`glab` that record argv and print a URL: opened (branch on origin, commit message, argv, `HEAD` back on base); already proposed; stale local branch; nothing to commit; dirty tree; detached `HEAD`; `HEAD` on `deps-cli/x`; missing identity; restore after refusal reverts the manifest's directory and leaves a modified tracked file in another directory untouched; interrupted `Publish` (a fake `gh` that blocks with `sleep N & wait`, the guard's future dropped) |
| Groups | parse incl. unknown key and invalid name; FR-018 truth table incl. `Unknown`; only `Applied` demoted |
| Publish safety (new file `update/pr/publish_safety_tests.rs`) | `readiness` truth table (only `RequiresLockfileUpdate` + `Regenerated` → `NothingSettled`; `AppliedViaLockfile` → `Ready`; `Failed` → `LockfileNotRegenerated`); a tracked edit outside the manifest's files during the run → `UnexpectedChanges`, nothing committed or pushed; an ignored `Cargo.lock` → only the manifest committed; `open` returns `Opened` with `HEAD` on the update branch and the URL survives a failing `switch_back`; a URL line with ESC/BEL is printed without them; `HEAD` on `-x` → preflight refuses; body from 1,000 four-byte names ≤ 60,000 bytes; title plain text |
| Leader state (#2066 track, new file `regen/leader_state_tests.rs`) | the classifier maps `Ok(None)` → `Running`, `Ok(Some(_))` → `Exited`, `Err(ECHILD)` → `Gone`, `Err(EINVAL)` → `Unknown` |

## 7. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| glab flags differ between versions, glab not live-tested | the docs list the exact flags and say glab is not covered by live testing |
| A failed `gh pr create`, or an interrupt after the push, leaves a branch that later reads as "already proposed" | the error and the `OnUpdateBranch` hint name `git push origin --delete <branch>` or opening the request by hand |
| `--group` run aborted by an out-of-group OSV latest-check failure | fail-closed, documented |
| A slow commit or pre-push hook | bounded by `STEP_TIMEOUT`, exit 2, documented |
| A title over the host limit (GitHub 256, GitLab 255) would fail after the push | title capped at 250 bytes (FR-014) |
| Superseded pull requests accumulate | out of scope, documented |

## See Also

- [[spec]]
- [[tasks]]
- [[068-cli-update-subcommand/plan]]

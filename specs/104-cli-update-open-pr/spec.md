---
aliases:
  - deps-cli update --open-pr
  - Update Pull Requests and Groups
tags:
  - sdd
  - spec
  - deps-cli
  - git
created: 2026-11-18
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[068-cli-update-subcommand/spec]]"
---

# Feature: deps-cli update opens a pull request, optionally for one update group

> [!info] Metadata
> **Author**: team-develop session
> **Branch**: `feat/2065-deps-core-osv-record-cache`
> **Resolves**: #1117 (branch, commit and pull request creation), #1118 (update grouping config)
> **Epic**: #1114 (deps-cli as a full Dependabot replacement)
> **Type**: enhancement, P4
> **Design provenance**: architect/critic review, `.local/handoff/2026-11-18T07-52-20-architect.md`, `2026-11-18T08-00-08-critic.md` and the revision that follows them

> [!abstract] Summary
> `deps-cli update --open-pr github|gitlab` commits the manifest and lock file change of one run on a new branch, pushes it to `origin` and opens a pull request (GitHub, via `gh`) or a merge request (GitLab, via `glab`). `--group <name>` narrows the run to one `[update.groups.<name>]` rule from an explicit `--config`, so one pull request carries exactly that group's updates.

## 1. Overview

### Problem Statement

`deps-cli update` (spec [[068-cli-update-subcommand/spec|068]]) edits a manifest and, with `--lockfile regenerate`, its lock file, but it stops at the working tree. Spec 068 §1 left the git side out of scope. A scheduled CI job that wants Dependabot-style pull requests has to script branch naming, commit messages, pushes and the pull request call itself, and has to solve re-runs while an earlier pull request is still open.

### Goal

- One `update` run produces at most one pull request, carrying every change that run made to one manifest and its lock file.
- A run is safe to schedule: the same update set never opens a second pull request, and a run never commits anything it did not change itself.
- A run never touches a token: `gh` and `glab` read their own credentials.
- `[update.groups]` selects which updates a run carries, so separate runs can open "minor and patch" and "major" pull requests.

### Decisions

| Question (from #1117) | Decision |
|---|---|
| API client or CLI | `gh` / `glab` CLI, argv only. deps-cli reads no token; `GH_TOKEN`/`GITHUB_TOKEN` and `GITLAB_TOKEN` are read by those tools |
| One pull request per dependency or batched | One per run (one manifest, all its changes). Per-dependency pull requests: one run per `--package <name>` |
| Branch naming | `deps-cli/<ecosystem>/[<dir>/]<label>-<h8>`, the hash always appended and covering the manifest path and the update set, see §5 |
| Re-run while the pull request is open | The same update set maps to the same branch; an existing remote branch means "already proposed": nothing is written, exit as for a dry run |

### Out of Scope

- Updating or rebasing earlier deps-cli pull requests. Closing superseded ones is opt-in via `--close-superseded` (§10, #2073); without it a superseded pull request stays open.
- Several pull requests from one run, or runs over several manifests.
- A direct GitHub/GitLab REST client, configurable remote (`origin` is fixed), branch prefix, commit-message prefix, labels, reviewers, assignees.
- `--open-pr` for lock file formats whose regeneration is refused (Yarn Classic and the other `unsupported` reasons of the regeneration module). Pipenv and Bun lock-file-only pins and NuGet mixed plans regenerate since #2114; NuGet lock-file-only pins stay refused (§10).
- Groups under `--security-only`. Group rules by dependency type and by `*` name pattern ship since #2072 (§10).
- Windows-specific testing (the code path has no shell and is expected to work; acceptance tests are unix-only).

## 2. User Stories

### US-001: A scheduled job opens one pull request per new update set

**As a** maintainer running `deps-cli update --lockfile regenerate --open-pr github Cargo.toml` nightly,
**I want** a pull request with the manifest and `Cargo.lock` change,
**so that** I review dependency updates like Dependabot's.

**Acceptance criteria:**
1. WHEN the run applies at least one update THE SYSTEM SHALL push a new `deps-cli/cargo/...` branch with one commit and print the pull request URL on stderr.
2. WHEN the next night finds the same update set THE SYSTEM SHALL write nothing, open nothing and exit as a dry run would.
3. WHEN a newer release changes the update set THE SYSTEM SHALL open a new pull request on a new branch.

### US-002: A run never commits foreign changes or leaves a poisoned tree

1. WHEN tracked files are modified before the run THE SYSTEM SHALL exit 2 before reading the network or writing anything.
2. WHEN the lock file could not be regenerated THE SYSTEM SHALL restore the tracked files it modified and exit 2.
3. WHEN a run is interrupted (SIGINT/SIGTERM) at any point after it started THE SYSTEM SHALL stop every running git, lock file tool or `gh`/`glab` process tree and exit 2.

### US-003: Groups split the update set into reviewable pull requests

**Given** `[update.groups.minor-patch] update_types = ["minor", "patch"]` in `deps.toml`,
**when** `deps-cli update --config deps.toml --group minor-patch --lockfile regenerate --open-pr github Cargo.toml` runs,
**then** only minor and patch updates are written, every other outdated dependency is reported `skipped (outside the selected --group)`, and the pull request title names the group.

## 3. Functional Requirements

| ID | Type | Requirement | Priority |
|----|------|-------------|----------|
| FR-001 | O | WHERE `--open-pr <github\|gitlab>` is given THE SYSTEM SHALL require `--lockfile regenerate` and reject `--dry-run` and `--offline`; a violation exits 2 before any analysis | must |
| FR-002 | E | WHEN `--open-pr` is given THE SYSTEM SHALL, before walking the manifest, verify: the manifest is inside a git work tree; `HEAD` is a named branch not starting with `deps-cli/` or `-`; a committer identity is configured (`git var GIT_COMMITTER_IDENT`); `git status --porcelain --untracked-files=no` is empty. Any failure exits 2 with a reason naming the check; a `HEAD` branch starting with `-` is its own error (`UnsafeBaseBranch`), distinct from one starting with `deps-cli/` (`OnUpdateBranch`) | must |
| FR-003 | E | WHEN `--open-pr` is given and the manifest's lock file regeneration is refused (`unsupported`, for example Yarn Classic) THE SYSTEM SHALL restore the manifest edit (FR-007) and exit 2, naming the reason; only a Go module whose `vendor` tree is not tracked in `HEAD` is refused before analysis | must |
| FR-004 | E | WHEN planning finishes THE SYSTEM SHALL derive the branch name (§5) from the proposed items (outcome `applied` or `requires-lockfile-update` after dedup and group demotion); with no proposed item THE SYSTEM SHALL open nothing and continue as `update` does today | must |
| FR-005 | E | WHEN the branch exists on `origin` THE SYSTEM SHALL write nothing, skip lock file regeneration, render the report as a dry run, print `already proposed on <branch>` on stderr and exit with the code `update` computes for that report | must |
| FR-006 | E | WHEN the branch exists locally but not on `origin` THE SYSTEM SHALL exit 2 before any write, naming the branch to delete | must |
| FR-007 | E | WHEN the lock file outcome is `failed`, `unsupported` or `skipped` after the manifest was written THE SYSTEM SHALL restore the tracked files directly inside the manifest's directory to `HEAD` (`git restore --source=HEAD --staged --worktree -- ':(top,glob)<repo-relative dir>/*'`), print why on stderr, render the report as a dry run and exit 2. This covers everything the run can write: `unsupported` means the tool never ran (only the manifest changed), and a tool that ran was only started for a lock file beside the manifest (workspace-member and Go-workspace layouts are `unsupported`) | must |
| FR-020 | E | WHEN the lock file is ready (FR-007 passes) but no item is `applied` (neither `Applied` nor `AppliedViaLockfile`; e.g. a `--security-only` run whose only fix stays `requires-lockfile-update` because the regenerated lock moved to a version not proven outside the advisory ranges) THE SYSTEM SHALL restore as in FR-007, print `no update was settled; no pull request opened` on stderr, render the report as a dry run and exit with the code `update` computes for that report (1, since the unsettled item is unresolved) | must |
| FR-008 | E | WHEN none of the publishable paths (FR-009) differs from `HEAD` THE SYSTEM SHALL open nothing and print `nothing to commit` | must |
| FR-009 | E | WHEN publishing THE SYSTEM SHALL in order: list the tracked paths that differ from `HEAD` (`git diff --name-only -z HEAD`); if any of them is not a publishable path — the manifest, or the lock file named by a `regenerated` outcome — exit 2 naming up to 10 such paths, with nothing restored, staged or committed; otherwise create and switch to the branch, stage exactly the changed publishable paths (`git add -- <paths>`; an untracked or ignored lock file is never added), commit with the generated message, push with upstream to `origin`, create the pull request (`gh pr create`) or merge request (`glab mr create`) against the base branch, print its URL on stderr (control characters removed), and only then switch back to the base branch | must |
| FR-010 | U | THE SYSTEM SHALL pass every argument as its own argv element, pass every value derived from a manifest or a registry as one `--flag=value` element, give no process a stdin, set `GIT_TERMINAL_PROMPT=0` and `GH_PROMPT_DISABLED=1`, and bound each step by its own timeout | must |
| FR-011 | U | THE SYSTEM SHALL never read, log, store or pass a token | must |
| FR-012 | E | WHEN `--open-pr` is given THE SYSTEM SHALL install one SIGINT/SIGTERM listener before the preflight and run the preflight, the update (analysis, branch check, write and lock file regeneration) and the publish phase each under it; WHEN a signal arrives THE SYSTEM SHALL drop the current phase, so every running child's process tree is terminated (SIGTERM, 2 s grace, SIGKILL, #2066), and exit 2 naming the phase. The FR-007 restore runs outside the listener, bounded by its step timeout | must |
| FR-013 | E | WHEN any git, `gh` or `glab` step fails or times out THE SYSTEM SHALL exit 2 naming the step in plain words and leave the repository state as it is; when the failure happened after the branch switch the message names the cleanup commands, and after the push it also names the remote branch (`git push origin --delete <branch>`) or opening the request by hand; a failed switch-back after the request was created still exits 2, with the URL already printed | must |
| FR-014 | U | THE SYSTEM SHALL write package names and versions in the title and commit subject as plain text (control characters and backticks removed, each cut to 80 characters) and in the body as code spans (backticks and control characters removed, `\|` escaped); keep the title at most 250 bytes, cutting at a character boundary and appending `...` when longer; list at most 50 updates in the body followed by `and N more`; and cut the body to at most 60,000 bytes at a character boundary | must |
| FR-015 | E | WHEN `[update.groups.<name>]` tables are present in an explicit `--config` THE SYSTEM SHALL parse them with unknown keys rejected; `<name>` is 1 to 64 characters of `[a-z0-9-]`, not starting or ending with `-` | must |
| FR-016 | O | WHERE `--group <name>` is given THE SYSTEM SHALL require `--config`, reject `--security-only`, and exit 2 before analysis when `<name>` is not defined | must |
| FR-017 | E | WHEN `--group` is given THE SYSTEM SHALL demote every `applied` item outside the group to `skipped` with reason `outside the selected --group`, before anything is written; such items do not raise the exit code | must |
| FR-018 | U | THE SYSTEM SHALL count an item as inside a group only if its normalized name is listed in `dependencies` or matches a `patterns` glob (or neither selector is set) AND its update kind is listed in `update_types` (or `update_types` is absent) AND its dependency role is admitted by `dependency_type` (or `dependency_type` is absent); an unclassifiable kind or unknown role is inside only a group without the respective field (amended by #2072) | must |
| FR-019 | U | THE SYSTEM SHALL leave `update` without `--open-pr` and `--group` byte-for-byte unchanged | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | No shell, no token handling, no value that can be read as an option (branch names always start with `deps-cli/`; free text is passed as `--flag=value`) |
| NFR-002 | Reliability | Every child process (git, `gh`, `glab`) runs under the same terminate-on-drop guard as the lock file tools, and every phase that spawns one runs under the FR-012 listener, so a timeout or interrupt never leaves a `git push` or `ssh` grandchild running |
| NFR-003 | Bounded time | Each step, including the git hooks it triggers (`pre-commit`, `commit-msg`, `pre-push`), is bounded by 2 minutes; the publish phase has at most 7 steps |
| NFR-005 | Compatibility | git 2.23 or newer (`git switch`, `git restore`); the docs list the exact `gh pr create` and `glab mr create` flags used and say which host CLI was exercised by live testing |
| NFR-004 | Opt-in | Both flags are opt-in; defaults are unchanged |

## 5. Data Model

### CLI

| Flag | Values | Constraints |
|---|---|---|
| `--open-pr` | `github`, `gitlab` | requires `--lockfile regenerate`; conflicts with `--dry-run`, `--offline` |
| `--group` | group name | requires `--config`; conflicts with `--security-only` |

### Config schema (#1118)

```toml
[update.groups.minor-patch]
update_types = ["minor", "patch"]

[update.groups.tokio-stack]
dependencies = ["tokio", "tokio-util", "tracing"]
```

All keys (`dependencies`, `patterns`, `update_types`, `dependency_type`) are optional; a group without keys matches every update. Groups are honored only from an explicit `--config` (as `[update].ignore`, spec 068 FR-007).

### Branch name

`deps-cli/<ecosystem id>/[<dir>/]<label>-<h8>`

- `<ecosystem id>`: `EcosystemId::id()` (`cargo`, `npm`, `go`, `github-actions`, ...).
- `<dir>` (human-readable only): the manifest's directory relative to the repository root, `/` replaced by `-`; omitted at the root.
- `<label>` (human-readable only): with `--group G`, `G`; with exactly one proposed item, `<name>-<target>`; otherwise `all`.
- `<h8>` (identity): the first 8 hex digits of FNV-1a 64 over the UTF-8 bytes of
  `<ecosystem id>\n<repo-relative manifest path>\n<group name or empty>\n` followed by the sorted lines `<normalized name>\t<target>\n` of the proposed items. It is always appended, also for a single item, and is never truncated.
- Sanitizing applies to `<dir>` and `<label>` only: lowercase; characters outside `[a-z0-9._-]` become `-`; runs of `-` and of `.` collapse; leading and trailing `.`/`-` are trimmed; a trailing `.lock` becomes `-lock`; an empty part becomes `x`; each part is then cut to 48 characters (and re-trimmed). The cut never reaches `-<h8>`.
- Sanitizing is lossy (`@scope/x` and `scope-x`, `a/b` and `a-b` read alike); distinctness comes from `<h8>`, whose input keeps the raw names and the raw path. The result is a valid `git check-ref-format --branch` name of at most 140 characters.

### Commit and pull request text

| | One update | Several updates | Group |
|---|---|---|---|
| Title / commit subject (plain text) | `Bump <name> from <current> to <target>` (`from` omitted when unknown), plus ` in <dir>` outside the root | `Bump <n> dependencies in <manifest>` (n ≥ 2) | `Bump the <group> group with <n> update(s) in <manifest>` (n ≥ 1) |

`n` counts `applied` items and is never 0: a run with none opens no pull request (FR-020).

The pull request body is a Markdown table (package, from, to, kind) plus a line naming the regenerated lock file and tool, a line counting items that could not be updated, and a footer naming deps-cli. The commit body lists the same updates as `- <name> <from> -> <to>`.

### Exit codes

| Situation | Exit |
|---|---|
| Pull request opened | as `update` (0, or 1 for a mixed run, spec 068 §5) |
| No proposed item, or nothing to commit | as `update` |
| Already proposed (FR-005) | as `update` for the dry-run report |
| No update settled (FR-020) | as `update` for the dry-run report (1 in practice) |
| Flag violation, preflight failure, untracked Go vendor tree, stale local branch, lock file not regenerated, changed paths outside the publishable set, git/`gh`/`glab` failure or timeout (including a failed switch-back after the request was created), interrupt in any phase | 2 |

## 6. Edge Cases and Error Handling

| Case | Behavior |
|---|---|
| Lock file `unsupported` (symlinked lock file, a lock file outside the repository root, Yarn Classic, a saved `.venv` file beside a Pipfile) | FR-007: restore, exit 2 |
| Workspace member whose lock file is in the workspace root, inside the repository | allowed: the root lock file is published with the manifest |
| Go module with `vendor/modules.txt` | regenerated; `vendor` must be tracked in `HEAD` and is published and restored as a tree |
| Pull request creation fails after the push | exit 2; the remote branch exists, so the next run reports "already proposed": the message says to open the pull request manually or delete the remote branch |
| Run interrupted after the branch switch | exit 2; the next run refuses in FR-002 (`HEAD` on `deps-cli/...`) with the cleanup commands, which include deleting the remote branch when the push may have happened |
| A tracked file outside the manifest and its lock file changes during the run (editor, formatter, another tool) | FR-009: exit 2 naming it; nothing is committed or pushed |
| The lock file is untracked or ignored (a Cargo library that ignores `Cargo.lock`) | only the manifest is committed |
| `--security-only` run whose regenerated lock moved but no fix was proven | FR-020: restore, no pull request, exit 1 |
| `HEAD` on a branch whose name starts with `-` | FR-002 refuses it (`UnsafeBaseBranch`), so no branch name can be read as an option |
| SIGINT/SIGTERM during lock file regeneration in an `--open-pr` run | the regeneration runs without its own listener (`regen::regenerate_lockfile_unlistened`), so the FR-012 listener is the only one: the outcome is always `interrupted in the update`, exit 2, never a race with a `failed` lock file outcome |
| Run interrupted in the update phase after the manifest was written | exit 2 without a restore; the next run refuses in FR-002 (dirty tree); the message names `git restore` for the manifest's directory |
| Several git remotes and no `gh` default repository | `gh` fails; documented: keep one remote or run `gh repo set-default` |
| Pull requests opened with the GitHub Actions `GITHUB_TOKEN` | do not trigger workflows (GitHub behavior); documented |
| A pull request closed without merging | its branch stays; the same update set is not proposed again until the branch is deleted (documented) |
| `--group` and a dependency outside the group fails the OSV latest-check | the run aborts (spec 068 issue #1517 gate is not group-aware); documented |
| Name with `@` (`@types/node`) | rendered as code, so no mention is created |
| A slow commit or pre-push hook | the step times out after 2 minutes, exit 2 (FR-013); documented |
| Someone edits a tracked file beside the manifest during the run, then FR-007 restores | that edit is reverted; files elsewhere in the repository are untouched; documented |
| Long package names or a long group name | the human-readable parts of the branch are cut, `-<h8>` is not, so different update sets never share a branch |
| git older than 2.23 | the first `switch`/`restore` step fails, exit 2; documented minimum |

## 7. Success Criteria

- Acceptance tests drive the git phase against a real git repository with a bare `origin` and fake `gh`/`glab` scripts: opened, already proposed, stale local branch, nothing to commit, dirty tree, detached `HEAD`, missing identity, interrupted phase, restore limited to the manifest's directory.
- Branch-name tests cover hostile names (`@scope/x`, `g:a`, `..`, `a.lock`, `-x`, `@{`, spaces, non-ASCII), and distinctness: `@scope/x` vs `scope-x`, manifests in `a/b` vs `a-b`, a 64-character group name with two different update sets, and a single item with a 200-character name at two targets all give different branches, each ending in `-<h8>`.
- A title built from a 300-character name stays at most 250 bytes; a body built from 1,000 four-byte-character names stays at most 60,000 bytes.
- No pull request is opened for a run with zero applied items (FR-020); a tracked edit outside the publishable paths is never committed (FR-009); the URL is printed even when the switch-back fails.
- `update` without the new flags passes the existing suite unchanged, and `update_exit_code` returns the same code as before for every `Outcome`/`SkipReason` variant.

## 8. Agent Boundaries

### Always
- Argv-only processes; terminate-on-drop guard for every child.
- Exhaustive `match` on `LockfileOutcome`, `SkipReason`, `PrHost` (no wildcard arm).

### Ask First
- Any new dependency, any REST client, any change to the update JSON schema.

### Never
- Read or pass a token; run a shell; force-push; delete a branch; commit untracked files.

## 9. Open Questions

None.

## 10. As Shipped

> [!success] Status
> Shipped in PR #2075 (issues #1117, #1118), together with #2065 and #2066 in the same PR.

### Deltas from the plan (approved)

| Item | Delta |
|---|---|
| `PrError::UnsafeBaseBranch { branch }` | Separate error for `HEAD` on a branch starting with `-` (FR-002), distinct from `OnUpdateBranch` |
| `regen::regenerate_lockfile_unlistened` | `--open-pr` regenerates without regeneration's own signal listener, so the FR-012 listener is the only one and an interrupt during regeneration always ends as `interrupted in the update` (§6); shares `regenerate_with_interrupt` with `regenerate_lockfile` |
| `warn_if_latest_unchecked` | Extracted from `run_update` in `main.rs` to stay under the line limit; behavior unchanged (FR-019) |
| `pr::open` | Takes no `&UpdateRun` (the parameter was unused) |
| `PlannedUpdateItem::is_unresolved` | One exhaustive predicate in `update/mod.rs`, shared by `update_exit_code` and the PR body's "could not be updated" count |
| #2066 terminate-on-drop | `ChildGuard::drop` probes the leader with `waitid` before sending TERM; `ECHILD` (already reaped elsewhere, so the pid may be recycled) skips both TERM and KILL |
| OSV record cache (#2065) | The raw record cache now also fills on the ServerSide path (bounded by `MAX_CACHE_ENTRIES`), so a second package of one advisory reuses the record without a second request |

### Live-test limits

- `gh pr create` and `glab mr create` were exercised only through fake host CLIs; neither ran against a real GitHub or GitLab host. The docs list the exact flags and say so.
- FR-020 (no update settled) was not reachable in a live run when the spec shipped; the operator-only `DEPS_OSV_BASE_URL` override (#2074, PR #2096) now lets a hermetic advisory scenario be staged.

### Follow-ups

- #2071 — plain `update --lockfile regenerate` leaves a truncated lock file after a failed or interrupted run. Fixed in PR #2096: the lock file, `go.mod` and `go.sum` are restored after a failed or interrupted run
- #2072 — groups lacked dependency-name patterns and dependency-type groups. Fixed in PR #2096 (see below)
- #2073 — superseded update pull requests were neither closed nor updated. Fixed in PR #2096 (see below)
- #2074 — OSV API base URL override for hermetic live tests. Fixed in PR #2096: `DEPS_OSV_BASE_URL`

### Shipped after the original PR

| PR | Change |
|---|---|
| #2096 | `[update.groups.<name>]` accepts `patterns` (`*`-only globs, 1 to 214 bytes, no whitespace; a union with `dependencies`) and `dependency_type` (`production`, `development`, `build`, `peer`, `optional`); a group without a name selector admits every name, and an unknown role matches no `dependency_type`. FR-018 reads: inside only if the name matches `dependencies` or `patterns` (or neither is set), the update kind is in `update_types` (or unset) and the role is admitted by `dependency_type` (or unset) |
| #2096 | `--close-superseded` (requires `--open-pr`): after opening a request, closes this author's open `deps-cli/<eco>/` requests only when six gates hold: same author, same repository, a `deps-cli/<eco>/` branch (narrowed to the manifest's directory part), exactly one commit, a hidden request marker of the same scope (same manifest, group and mode), and every target at or below the new one. At most 50 candidates are read per run, oldest first; any failed step is a warning and closes nothing |
| #2096, #2106 | Lock files of workspace members and companion trees are staged and restored under `--open-pr` (member lock files allowed with repo-root containment) |
| #2114 | GitLab superseded notes use `glab api` instead of the deprecated `mr note` flag |

## 11. See Also

- [[068-cli-update-subcommand/spec]] — the `update` subcommand this extends
- [[plan]] — technical plan and contracts
- [[tasks]] — implementation tasks

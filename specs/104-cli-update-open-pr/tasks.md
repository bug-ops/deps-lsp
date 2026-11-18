---
aliases:
  - deps-cli update --open-pr Tasks
tags:
  - sdd
  - tasks
  - deps-cli
  - git
created: 2026-11-18
status: shipped
related:
  - "[[spec]]"
  - "[[plan]]"
---

# Implementation Tasks: deps-cli update opens a pull request, optionally for one update group

> [!info] References
> **Spec**: [[spec]]
> **Plan**: [[plan]]
> **Total tasks**: 11

## Commit groups

The PR is committed per track; each task's files belong to exactly one group.

| Commit | Tasks | Files |
|---|---|---|
| #2066 track | T001, T010 | `crates/deps-cli/src/update/regen/run.rs`, `crates/deps-cli/src/update/regen/process_group_tests.rs`, `crates/deps-cli/src/update/regen/leader_state_tests.rs` |
| spec | — | `specs/104-cli-update-open-pr/{spec,plan,tasks}.md`, `specs/MOC-specs.md` |
| C1 (#1117) | T002–T006, T011 | `crates/deps-cli/src/update/regen/mod.rs`, `crates/deps-cli/src/update/regen/interrupt.rs`, `crates/deps-cli/src/update/pr/{mod.rs,git.rs,acceptance_tests.rs,publish_safety_tests.rs}`, `crates/deps-cli/src/update/mod.rs`, `crates/deps-cli/src/cli.rs`, `crates/deps-cli/src/main.rs` |
| C2 (#1118) | T007–T008 | `crates/deps-cli/src/config.rs`, `crates/deps-cli/src/update/group.rs`, `crates/deps-cli/src/update/group_tests.rs`, `crates/deps-cli/src/update/mod.rs`, `crates/deps-cli/src/exit.rs`, `crates/deps-cli/src/cli.rs`, `crates/deps-cli/src/main.rs`, `crates/deps-cli/src/update/pr/mod.rs` |
| docs | T009 | `book/src/cli.md`, `crates/deps-cli/README.md` |

## Progress

- [x] T001: (#2066 track) `ChildGuard::spawn`, `pub(in crate::update)` on `ChildGuard`, `ProcessGroup`, `ProcessGroup::detect`, `TERMINATION_GRACE`
- [x] T002: regen seams — re-exports, `LockfileSupport`/`lockfile_support`, `Interrupts` visibility and docs
- [x] T003: `update::pr::git` step runner
- [x] T004: `update::pr` preflight, `PrSignals`, branch naming, branch check, restore
- [x] T005: `update::pr` text rendering and `open`
- [x] T006: `--open-pr` CLI and `main.rs` wiring
- [x] T007: `[update.groups]` config, `UpdateGroup`, `SkipReason::NotInGroup`, exhaustive `update_exit_code`
- [x] T008: `--group` CLI and wiring, group-aware branch and title
- [x] T009: docs
- [x] T010: (#2066 track, review round) `waitid` result classifier; no KILL on `ECHILD`
- [x] T011: (C1, review round) `readiness`/`Publishable`, explicit staging, `OpenedRequest`, `RequestUrl`, `BaseBranch` `-` refusal, body byte cut, plain-word errors, `Publish::Propose { repo, branch }`

## T001: ChildGuard reachable from `update`

**Files**: `crates/deps-cli/src/update/regen/run.rs` (tests: `regen/process_group_tests.rs`)
**Depends on**: —
**Acceptance**: `ChildGuard::spawn(&mut Command, ProcessGroup) -> io::Result<ChildGuard>` sets `process_group(0)` for `Own` on unix and `kill_on_drop(true)`; `ToolRunner` spawns through it; the items are `pub(in crate::update)`; the `waitid` poll uses rustix's exact predicate (plan §4); existing regen tests pass.

## T002: regen seams

**Files**: `crates/deps-cli/src/update/regen/mod.rs`, `crates/deps-cli/src/update/regen/interrupt.rs`
**Depends on**: T001
**Acceptance**: `pub(in crate::update) use run::{ChildGuard, ProcessGroup}` and `interrupt::Interrupts`; `pub const fn lockfile_support(EcosystemId) -> LockfileSupport` built on `strategy`; the "swallowed for the rest of the short-lived process" doc names the `--open-pr` listener.

## T003: step runner

**Files**: `crates/deps-cli/src/update/pr/git.rs`
**Depends on**: T002
**Acceptance**: plan §4 argv table; stdin null, 64 KiB stdout cap, inherited stderr, `STEP_TIMEOUT`, env vars; `Tool`/`Step` exhaustive; `NotFound` → `ToolMissing`.

## T004: preflight, signals, branch, restore

**Files**: `crates/deps-cli/src/update/pr/mod.rs` (tests: `update/pr/acceptance_tests.rs`)
**Depends on**: T003
**Acceptance**: FR-002, FR-004 to FR-007, FR-012's `PrSignals`; spec §5 branch grammar: human parts cut to 48 characters, `-<h8>` always appended, hash input includes the ecosystem, the raw manifest path and the group; restore limited to `:(top,glob)<dir>/*`; `FreeBranch` only from `check_branch`.

## T005: text and open

**Files**: `crates/deps-cli/src/update/pr/mod.rs` (tests: `update/pr/acceptance_tests.rs`)
**Depends on**: T004
**Acceptance**: FR-008 to FR-011, FR-013, FR-014 (title ≤ 250 bytes, body caps); readiness is an exhaustive match.

## T006: `--open-pr` wiring

**Files**: `crates/deps-cli/src/cli.rs`, `crates/deps-cli/src/main.rs`, `crates/deps-cli/src/update/mod.rs` (`pub mod pr;`)
**Depends on**: T005
**Acceptance**: FR-001; `PrSignals` installed before the preflight, phases `Preflight`/`Update`/`Publish` guarded (FR-012); FR-003 after the walk and before analysis; FR-005 dry-run rendering; FR-007 restore before rendering, outside the guard; exit codes per spec §5; FR-019.

## T007: groups model

**Files**: `crates/deps-cli/src/config.rs`, `crates/deps-cli/src/update/group.rs`, `crates/deps-cli/src/update/mod.rs`, `crates/deps-cli/src/exit.rs` (tests: `update/group_tests.rs`)
**Depends on**: T006
**Acceptance**: FR-015, FR-017, FR-018; `reason()` arm; `update_exit_code` is an exhaustive match with no wildcard, with one equivalence case per `Outcome`/`SkipReason` variant against the pre-change table.

## T008: `--group` wiring

**Files**: `crates/deps-cli/src/cli.rs`, `crates/deps-cli/src/main.rs`, `crates/deps-cli/src/update/pr/mod.rs` (tests: `update/group_tests.rs`)
**Depends on**: T007
**Acceptance**: FR-016; demotion after `dedup_applied_items` and before the branch check; the group name feeds the branch label, the hash input and the title.

## T009: docs

**Files**: `book/src/cli.md`, `crates/deps-cli/README.md`
**Depends on**: T008
**Acceptance**: `--open-pr` section (supported ecosystems; token scopes: GitHub `contents: write` + `pull-requests: write`, GitLab `api` + push access; `GITHUB_TOKEN` does not trigger workflows; one remote or `gh repo set-default`; git 2.23+; hooks run under the 2-minute step timeout; exit codes; re-run behavior; restore scope; cleanup after a failed or interrupted step, including `git push origin --delete <branch>` after a push; the exact `gh pr create` / `glab mr create` flags and that glab is not covered by live testing; no pull request when nothing was settled; a tracked edit outside the manifest and its lock file aborts the publish), `[update.groups]` section, and the #2066 timeout paragraph.

## T010: waitid classifier (#2066 track, review round)

**Files**: `crates/deps-cli/src/update/regen/run.rs` (tests: new `regen/leader_state_tests.rs`)
**Depends on**: T001
**Acceptance**: a pure classifier `Ok(None)` → `Running`, `Ok(Some(_))` → `Exited`, `Err(ECHILD)` → `Gone`, any other `Err` → `Unknown`; `Gone` skips the final KILL; `Unknown` stops polling, sleeps out the grace, then KILLs; plan §4 `ChildGuard::spawn` row.

## T011: publish safety (C1, review round)

**Files**: `crates/deps-cli/src/update/pr/mod.rs`, `crates/deps-cli/src/update/pr/git.rs`, `crates/deps-cli/src/update/regen/mod.rs` (`DisplayLockPath::file_name`), `crates/deps-cli/src/main.rs` (tests: new `update/pr/publish_safety_tests.rs`)
**Depends on**: T008
**Acceptance**: FR-002 (leading `-`), FR-009 (explicit staging, `UnexpectedChanges`, URL before switch-back), FR-013 (plain-word step names, remote-branch hint), FR-014 (plain title, body byte cut), FR-020 (`NothingSettled`); `open` loses its unused `&UpdateRun` parameter; `describe` takes `&Publishable`; `Publish::Propose { repo, branch }` in `main.rs`.

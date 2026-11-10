---
aliases:
  - Change During Initial Fetch
  - Aborted Open Fetch Never Reissued
tags:
  - sdd
  - spec
  - lsp
  - lifecycle
  - cross-ecosystem
  - bug
created: 2026-11-09
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: A didChange during the initial registry fetch must not lose the fetch

> [!info] Metadata
> **Author**: live-testing session
> **Branch**: `feat/1987-didchange-initial-fetch` (issue #1987)
> **Type**: bug, P1, cross-ecosystem
> **Observed on**: HEAD 971ae08ae, identical on 713d6368e (not a regression of the recent refactors)

> [!bug] Summary
> A `textDocument/didChange` that arrives while the open task's registry fetch is still in flight aborts that task. The change task then diffs against the already-parsed but never-fetched dependency set, concludes `added=0 removed=0 version_changed=0`, skips the fetch, and marks the document loaded. Every dependency keeps no registry data for the rest of the session.

## 1. Overview

### Problem Statement

Editors commonly format or type immediately after opening a manifest. In that window the server loses the initial registry fetch permanently:

- Diagnostics report `Unknown package 'express'` (npm), `Unknown package 'regex'` (Cargo), `Unknown package 'actions/checkout'` (GitHub Actions). These are false claims for real packages.
- Inlay hints are empty and hover returns nothing on dependencies.
- A whitespace-only second edit does not repair it. Editing a dependency's requirement text repairs only that dependency.
- In the later part of the window (edit at 300 to 600 ms) the inlay data recovers but the OSV result is lost: the diagnostic stays `Newer version available: 5.3.0 (not yet verified against OSV)` and the `vulnerability data was not checked for N dependencies` notice is missing, so the user is told neither that the data is verified nor that it is not.

Root cause as observed in the `RUST_LOG=debug` log of the broken case:

1. The open task logs `starting registry fetch count=2`.
2. The change task logs `dependency diff added=0 removed=0 version_changed=0`, then `no added or version-changed dependencies, skipping registry fetch`, then calls `set_loaded()`.
3. `ServerState::spawn_background_task` aborts the previous task for the URI, so the open fetch result is never committed.
4. The change task's diff baseline is the previous parse result, not the set of dependencies that have committed registry data.

An analogous mechanism already exists for aborted predecessor edits: `typosquat_checked_names` (see `crates/deps-lsp/src/document/typosquat.rs` and the doc on `PackageSignals::typosquat_checked_names`), and `crates/deps-lsp/src/document/resolved.rs` already documents a related `deps_to_fetch.is_empty()` early-return hazard. The same self-correcting principle applies here: decide what to fetch by comparing against persisted committed state, not against the previous parse.

### Goal

For an unchanged dependency set, diagnostics, hover, inlay hints and the OSV outcome are identical whether or not an edit arrived during the initial fetch.

### Out of Scope

- Redesigning the background-task abort model for edits that change dependencies (those already fetch the added or changed entries).
- Debounce or coalescing of rapid `didChange` events.
- Changing registry cache TTLs, the circuit breaker, or the fetch concurrency limits.
- Edits during a refresh of an already-loaded document (this spec covers the first load only, but FR-006 requires the fix not to regress that path).
- Zed extension changes (`crates/deps-zed` is a separate repository).

## 2. User Stories

### US-001: Format on open does not poison the document

AS A developer whose editor formats a manifest right after opening it
I WANT the same hover, inlay hints and diagnostics I would get from a calm open
SO THAT valid packages are never reported as unknown.

**Acceptance criteria:**
```
GIVEN a package.json with express ^4.18.0 and left-pad ^1.3.0 and no lock file
WHEN the document is opened and one whitespace-only didChange arrives 20 ms later
THEN within the normal fetch latency the diagnostics are "Newer version available: 5.3.0" for express and the deprecation diagnostic for left-pad
AND inlay hints are present for both dependencies
AND no "Unknown package" diagnostic is published
```

### US-002: Verification status is truthful

AS A developer
I WANT either an OSV-verified result or the explicit "vulnerability data was not checked" notice
SO THAT a missing OSV result never silently looks like a clean result.

**Acceptance criteria:**
```
GIVEN the open fetch was interrupted by a didChange at 300 ms or 600 ms
WHEN the registry data and the OSV lookup eventually complete
THEN the OSV outcome is committed for every dependency
OR the "not checked" notice is shown for the dependencies without an outcome
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a change task computes which dependencies to fetch THE SYSTEM SHALL include every dependency that has no committed registry data for its current requirement, in addition to added and version-changed dependencies | must |
| FR-002 | WHEN an open-task fetch is aborted by a newer task for the same URI THE SYSTEM SHALL ensure its uncommitted dependencies are fetched by the successor task or by an equivalent re-issue | must |
| FR-003 | WHEN the dependency set after a change equals the set before it AND all dependencies have committed registry data THE SYSTEM SHALL skip the fetch (no extra registry traffic for ordinary whitespace edits on a loaded document) | must |
| FR-004 | WHEN a change task skips the fetch THE SYSTEM SHALL call `set_loaded()` only if every current dependency has a committed registry outcome (data, or a recorded failure or miss) | must |
| FR-005 | WHEN the OSV lookup of an aborted task did not commit THE SYSTEM SHALL re-run the OSV lookup for the dependencies lacking an OSV outcome, or publish the "vulnerability data was not checked" notice for them | must |
| FR-006 | WHEN several didChange events arrive during the initial fetch THE SYSTEM SHALL converge to the same final state as a single calm open, with at most one in-flight fetch per URI | must |
| FR-007 | WHEN a dependency's registry lookup definitively returned not-found THE SYSTEM SHALL keep reporting `Unknown package`, and SHALL NOT refetch it on every edit (a recorded miss counts as a committed outcome) | must |
| FR-008 | WHEN a change commit leaves at least one dependency without a committed registry outcome THE SYSTEM SHALL call `set_loading()` right after that commit, so `Unknown package` is not emitted for a dependency whose lookup has not been attempted or committed | should |
| FR-009 | THE SYSTEM SHALL apply FR-001 to FR-008 identically for every ecosystem through shared lifecycle code, with no per-ecosystem branch | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Handlers stay non-blocking: the re-issued fetch is spawned, never awaited inside a handler |
| NFR-002 | Efficiency | A whitespace edit on a fully loaded document performs zero registry requests |
| NFR-003 | Type safety | "No committed registry data" is expressed through an existing typed state (or a new exhaustive enum), not a bool flag or string comparison; no `_ =>` catch-all on exhaustive enums |
| NFR-004 | Consistency | The fix lives in shared lifecycle code in `deps-lsp`, per the cross-ecosystem consistency rule; no ecosystem-local workaround |
| NFR-005 | Robustness | No new `unsafe`; no panics on abort at any await point |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Parsed dependency set | Dependencies from the latest parse | name, requirement text, position |
| Committed registry data | Per-dependency fetched outcome stored on the document state (cached versions, recorded failure or miss) | dependency key, outcome |
| Committed OSV outcome | Per-dependency vulnerability lookup result or explicit "not checked" | dependency key, outcome |
| Background task slot | Single task per URI, replaced (and the predecessor aborted) by `spawn_background_task` | URI, join handle |

> [!success] Data-model decision (resolved)
> "Committed registry data" is a new typed record, `PackageSignals::registry_baseline` (`RegistryBaseline`, a newtype over the per-package declared requirements as of the last committed outcome). `cached_versions` cannot serve: it has no entry for a recorded miss, failure, non-resolvable or collided package, which FR-007 requires to count as committed. User-approved.
>
> - `pending(declared)` is the added and requirement-changed names of `DependencyDiff::compute(baseline, declared)`; the change task derives its fetch list from it after the debounce and the pre-fetch re-parse, instead of receiving a parse-to-parse diff from the handler.
> - Written by: the open commit (`replace`), the change merge (`record`, every requested name, including failures, misses, non-resolvable and collided ones), a version-changing commit (`invalidate`), a forced refetch (`clear`), and pruning of removed packages.
> - Carried across edits by `preserve_cache`.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Change adds a dependency while the open fetch is in flight | Successor fetches the added dependency and all dependencies still lacking committed data |
| Change removes a dependency while the open fetch is in flight | Removed dependency is dropped; the rest still fetched if uncommitted |
| Change alters a requirement while the open fetch is in flight | That dependency is fetched for the new requirement; others fetched if uncommitted |
| Three whitespace edits at 20, 40, 60 ms | Each aborts its predecessor; the last task fetches everything uncommitted exactly once (FR-006) |
| Edit arrives after the open fetch has partly committed (some dependencies done) | Only the uncommitted dependencies are fetched |
| Registry returns 404 for a dependency | Recorded as a committed miss; not refetched on later whitespace edits (FR-007) |
| Registry unreachable (offline) | Failure recorded per existing failure-memo rules; no tight refetch loop on each edit |
| Document closed while the re-issued fetch runs | Task is cancelled with the document; no commit to a closed document |
| Edit arrives between registry fetch commit and OSV commit | OSV lookup re-run or "not checked" notice shown (FR-005) |
| didChange carries an older document version than the loaded state | Existing version-ordering rules apply unchanged |
| An edit with pending dependencies commits (FR-008) | `set_loading()` runs right after the commit. `commit_parsed_document` always builds a fresh `Idle` state, so the loading start instant resets on every edit. While someone keeps typing with pending names, diagnostics stay suppressed and the loading ceiling cannot fire; the first debounced task that is not aborted fetches and settles the state. Accepted. |
| Lock-file change arrives during the initial fetch | `handle_lockfile_change` runs a detached rescan and never aborts the open task, so it cannot lose the fetch. A lock-file-triggered re-parse goes through the same `pending` computation as an edit. |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live matrix: edit at 20, 100, 300, 600, 1000 ms after open, for each of npm, Cargo, GitHub Actions (15 cells) | All 15 cells match the calm-open baseline: correct diagnostics, inlay hints present, hover present |
| SC-002 | `Unknown package` diagnostics for existing packages in the matrix | 0 |
| SC-003 | OSV outcome in the matrix | Committed for every dependency, or the "not checked" notice present; never silently absent |
| SC-004 | Registry requests for a whitespace edit on a fully loaded document | 0 |
| SC-005 | Convergence time after the last edit (matrix cells) | Within the calm-open fetch latency plus 2 s, observed at 15 s and 60 s with no further change |
| SC-006 | Regression tests added | Present and failing on HEAD 971ae08ae, passing after the fix |

### Live scenario matrix

Baseline per ecosystem is the calm open (no edit during the first second). Each cell: one full-text didChange adding a trailing newline, then observe diagnostics, inlay hints and hover at 15 s and 60 s. Use a per-agent `session-<agent>.log` path.

| Edit delay | npm (`package.json`: express ^4.18.0, left-pad ^1.3.0) | Cargo (`Cargo.toml`: regex) | GitHub Actions (workflow using `actions/checkout`) |
|-----------:|------|------|------|
| 20 ms | expected = baseline | expected = baseline | expected = baseline |
| 100 ms | expected = baseline | expected = baseline | expected = baseline |
| 300 ms | expected = baseline, OSV outcome present | expected = baseline, OSV outcome present | expected = baseline, OSV outcome present |
| 600 ms | expected = baseline, OSV outcome present | expected = baseline, OSV outcome present | expected = baseline, OSV outcome present |
| 1000 ms | expected = baseline | expected = baseline | expected = baseline |

npm baseline: `Newer version available: 5.3.0` for express, inlay `5.3.0` marker, deprecation diagnostic for left-pad, and the OSV result (or the "not checked" notice). Cargo and GitHub Actions baselines are captured from a calm open at test time.

Additional rows to run once: three rapid edits (20, 40, 60 ms); edit that changes one requirement (`^4.18.0` to `^4.17.0`) at 20 ms; whitespace edit on a fully loaded document (assert zero registry requests via log).

### Regression-test requirement

- RT-001: a deterministic `deps-lsp` integration test (mock registry, no wall-clock sleeps where avoidable, using a gate to hold the open fetch in flight) that opens a document, delivers a whitespace-only change while the fetch is gated, releases the gate, and asserts cached versions are present for every dependency and no `Unknown package` diagnostic is produced. It MUST fail on HEAD 971ae08ae.
- RT-002: the same test parametrized over at least npm, Cargo and GitHub Actions manifests (FR-009).
- RT-003: a test for a change that arrives after a partial commit asserts only uncommitted dependencies are fetched (mock request counter).
- RT-004: a test asserting zero registry requests for a whitespace edit on a fully loaded document (FR-003, NFR-002).
- RT-005: a test for the aborted-OSV case (FR-005).
- RT-006: a test for a committed 404 miss not being refetched on a later edit (FR-007).
- Add the minimal repro manifest and timing to `.local/testing/regressions.md` and extend the relevant ecosystem playbooks in `.local/testing/playbooks/` per the branching rules.

## 8. Agent Boundaries

### Always (without asking)
- Reproduce on a debug build first and keep the repro log (`RUST_LOG=debug`, per-agent session log path).
- Run the full pre-PR check suite from `.claude/rules/branching.md`.
- Put the fix in shared lifecycle code and cover it with the tests in section 7.
- Update `CHANGELOG.md` `[Unreleased]` with a one-line entry and PR link.

### Ask First
- Adding a new field to document state or a new public type (confirm the typed shape per NFR-003).
- Changing the abort semantics of `spawn_background_task` for all callers.
- Any change to registry cache or circuit-breaker behavior.

### Never
- Add a per-ecosystem workaround.
- Use sleeps as the fix (delaying the change task until the open task finishes).
- Weaken exhaustive matches with `_ =>` or add `#[non_exhaustive]`.
- Edit files under `crates/deps-zed`.

## 9. Open Questions

> [!success] Resolved items
> - Mechanism: (a). The change task compares the current declaration against the committed registry baseline, so uncommitted dependencies enter its fetch list; the abort model of `spawn_background_task` is unchanged.
> - The committed key includes the requirement text: the baseline stores the requirements, and a changed requirement is pending again.
> - OSV (FR-005): the change task owns the re-run. `osv_scan_plan_is_stale` (the check `rescan_osv_if_tag_index_now_warm` already used) is ORed into the OSV phase A gate, so a plan never committed by an aborted predecessor triggers phase A and B; it is false for an unchanged, fully scanned document.
> - Lock-file path: no hazard from `handle_lockfile_change` (detached rescan, never aborts the open task); the re-parse path uses the same `pending` computation. See the edge-case table.
> - Issue: #1987.
> - Cargo and GitHub Actions regression tests run against a mock sparse index (`.cargo/config.toml` alias) and a mock GitHub API (`GithubActionsEcosystem::for_test`, `test-util` feature of `deps-github-actions`, dev-dependency only); their calm-open expectations are the same cached-versions and no-`Unknown package` assertions.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[097-inlay-hints-fetch-failure-lookup-miss-marker/spec|097]] — related outcome marking for lookup misses and failures
- `crates/deps-lsp/src/document/lifecycle.rs` — `run_document_open_background_task`, change path `deps_to_fetch.is_empty()` early return
- `crates/deps-lsp/src/document/state.rs` — `ServerState::spawn_background_task`
- `crates/deps-lsp/src/document/typosquat.rs` — `typosquat_checked_names` self-correcting precedent
- `crates/deps-lsp/src/document/resolved.rs` — related early-return hazard documentation

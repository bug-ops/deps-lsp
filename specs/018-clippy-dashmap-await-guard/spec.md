---
aliases:
  - Clippy DashMap Await-Hold Guard
tags:
  - sdd
  - spec
  - enhancement
  - tooling
  - ci
created: 2026-08-24
status: draft
related:
  - "[[constitution]]"
---

# Feature: Add `clippy.toml` `await-holding-invalid-types` config for DashMap `Ref` guards

> [!info] Metadata
> **Author**: continuous-improvement research cycle
> **Branch**: fix/clippy-dashmap-await-guard (no issue filed yet)

## 1. Overview

### Problem Statement

Holding a `dashmap::mapref::one::Ref` / `RefMut` (or their `Mapped*` /
`RefMulti` counterparts) across an `.await` suspension point is a liveness
hazard: the guard pins a lock on the DashMap shard for the lifetime of the
awaited future, so any concurrent access to the same shard (e.g. another LSP
request calling `documents.get_mut` for the same `Uri`) blocks — or, in the
worst case observed so far, blocks for up to the full duration of a
network-bound fetch or a multi-second timeout.

This exact bug class has already been found and fixed **three separate
times** in this project's history, across five different LSP handlers:

- Issue #317 (found during #227's security audit): `inlay_hints.rs` and
  `diagnostics.rs` held a `Ref` across `full_config.read().await` and a
  `generate_*(...).await` call.
- PR #318: fixed `inlay_hints.rs` by reordering (snapshot config before
  document lookup). Left a second, then-inert `Ref`-hold across
  `generate_*(...).await` itself, marked with `TODO` comments in
  `crates/deps-core/src/ecosystem.rs` (around `generate_inlay_hints`,
  line 406) noting the hazard is currently benign only because
  `deps-core`'s default trait methods never actually yield today
  (`Box::pin(async move { sync_fn() })`) — an implementation detail that
  could silently change if a future override adds real I/O.
- PR #325 (closing issue #319, the follow-up): found the *live* version of
  the identical hazard in `hover.rs` (`Ref` held across a network-bound
  `registry.get_versions_with(...)` fetch), `code_actions.rs` (same, via
  `generate_code_actions`), and worst of all `completion.rs` (`Ref` held
  across `tokio::time::timeout(COMPLETION_SEARCH_TIMEOUT, ...)`, up to 2
  seconds of a blocking guard pinned on a tokio worker thread — a
  concurrent `documents.get_mut` on the same shard would block outright).
  Fixed via `DocumentState.parse_result: Box<dyn ParseResult>` →
  `Arc<dyn ParseResult>` so handlers can clone-and-drop the `Ref` before the
  await, plus regression tests asserting the guard is not reintroduced.

Despite three occurrences, the codebase has **no compile-time or lint-time
enforcement** preventing a fourth. The only remaining guardrails are:

1. `TODO(#317-followup)`-style code comments on two `deps-core` default
   trait methods (`generate_inlay_hints`, and similarly-worded comments near
   `generate_diagnostics`/`generate_code_lenses`) noting the hazard is latent
   rather than fixed.
2. Handler-specific regression tests (`crates/deps-lsp/src/handlers/completion.rs`
   line ~1064, `hover.rs`, `code_actions.rs`) that only cover the exact
   handlers already fixed.

A new handler, or a future override of one of the two `deps-core` default
trait methods that adds real I/O (turning the currently-inert hazard live),
could silently reintroduce the exact same class of bug — with nothing
catching it short of another manual security/code audit.

Clippy already ships the exact mechanism needed:
`clippy::await_holding_invalid_type` (part of the same lint family as
`await_holding_lock`, already active project-wide via
`[workspace.lints.clippy] all = "warn"` in the root `Cargo.toml`) reads a
`clippy.toml` (or `.clippy.toml`) config key `await-holding-invalid-types`
that accepts arbitrary type paths — not just `std`/`parking_lot`
`Mutex`/`RwLock` — to flag when held across an `.await` point.

Verified facts:
- `find /Users/rabax/Dev/deps-lsp -maxdepth 1 -iname "clippy.toml"` returns
  no output — this project has **no `clippy.toml` at all** today.
- `ServerState::get_document`
  (`crates/deps-lsp/src/document/state.rs:518-521`) returns
  `Option<dashmap::mapref::one::Ref<'_, Uri, DocumentState>>`.
- The pinned workspace `dashmap` version is `6.2` (`Cargo.toml:16`); the
  `dashmap::mapref::one` module exports `Ref`, `RefMut`, `MappedRef`,
  `MappedRefMut`. This project does not currently construct `MappedRef` /
  `MappedRefMut` values, but registering them preempts the same hazard for
  future code that does.
- `dashmap::mapref::multiple` additionally exports `RefMulti` / `RefMutMulti`
  for multi-key iteration guards, which carry the identical liveness
  hazard if ever held across an `.await`.
- `grep -rn "dashmap::mapref::one::Ref"` in the current tree shows exactly
  one live `Ref`-returning API (`ServerState::get_document`); the rest of
  the codebase already routes through the clone-and-drop
  (`Arc<dyn ParseResult>`) pattern established by PR #325.

### Goal

`cargo clippy --workspace --all-targets --all-features -- -D warnings` fails
automatically, on every PR, if any future code holds a
`dashmap::mapref::one::{Ref, RefMut, MappedRef, MappedRefMut}` or
`dashmap::mapref::multiple::{RefMulti, RefMutMulti}` guard across an
`.await` suspension point — turning this recurring bug class from "requires
a human security/code audit to catch" into "CI catches it automatically."

### Out of Scope

- Refactoring any existing handler code. The three prior fixes (#318, #325)
  already resolved every currently-live occurrence; this feature adds
  *detection*, not remediation.
- Removing or rewording the existing `TODO(#317-followup)`-style comments in
  `crates/deps-core/src/ecosystem.rs` — those stay as human-readable context;
  the new lint config is a second, independent guardrail, not a replacement.
- Adding new regression tests for already-fixed handlers (covered by #325).
- Configuring `await_holding_invalid_type` for lock types outside the
  DashMap family (`std::sync::Mutex`, `parking_lot`, etc. are already
  covered by clippy's built-in defaults without any config).
- Any change to `dashmap` itself or to `ServerState`'s public API
  (`get_document`'s `Ref`-returning signature is unchanged by this feature).

## 2. User Stories

### US-001: Automatic detection of a reintroduced DashMap-guard-across-await hazard
AS A contributor (human or coding agent) adding a new LSP handler or
overriding a `deps-core` default trait method
I WANT the CI clippy gate to fail immediately if my code holds a DashMap
`Ref`/`RefMut` guard across an `.await` point
SO THAT I catch the liveness hazard at compile-check time, in my own PR,
instead of it silently shipping and later requiring a dedicated security
audit or bug report to discover (as happened three times already: #317,
the #318 follow-up, #319/#325).

**Acceptance criteria:**
```
GIVEN a new or modified function anywhere in the workspace that binds a
      dashmap::mapref::one::Ref (or RefMut/MappedRef/MappedRefMut/
      RefMulti/RefMutMulti) to a local variable and then awaits a future
      while that variable is still in scope
WHEN `cargo clippy --workspace --all-targets --all-features -- -D warnings`
     is run
THEN the build fails with a clippy::await_holding_invalid_type diagnostic
     pointing at the offending await point
```

### US-002: No new false positives on the existing, already-fixed codebase
AS A maintainer running CI on the current `main` branch after this change
I WANT the added `clippy.toml` config to produce zero new clippy warnings
SO THAT the config addition itself does not block unrelated PRs or require
immediate remediation work.

**Acceptance criteria:**
```
GIVEN the current state of the workspace (post #325, all three prior
      occurrences already fixed)
WHEN `clippy.toml` with the `await-holding-invalid-types` entries is added
     and `cargo clippy --workspace --all-targets --all-features -- -D
     warnings` is run
THEN the command exits successfully with no new await_holding_invalid_type
     warnings
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL provide a `clippy.toml` file at the workspace root containing an `await-holding-invalid-types` array | must |
| FR-002 | THE `await-holding-invalid-types` array SHALL register `dashmap::mapref::one::Ref` and `dashmap::mapref::one::RefMut` (the two types with confirmed live usage in the codebase today) | must |
| FR-003 | THE `await-holding-invalid-types` array SHALL also register `dashmap::mapref::one::MappedRef` and `dashmap::mapref::one::MappedRefMut` (not currently used, registered preemptively per the Goal) | must |
| FR-004 | THE `await-holding-invalid-types` array SHALL also register `dashmap::mapref::multiple::RefMulti` and `dashmap::mapref::multiple::RefMutMulti` (multi-key iteration guards carrying the identical hazard) | must |
| FR-005 | WHEN `cargo clippy --workspace --all-targets --all-features -- -D warnings` is run after the config is added THE SYSTEM SHALL report zero new `clippy::await_holding_invalid_type` violations against the current (post-#325) codebase | must |
| FR-006 | IF the clippy run in FR-005 surfaces one or more `await_holding_invalid_type` violations against existing code THE SYSTEM SHALL treat this as a distinct finding (a real, previously-undetected occurrence of the bug class) rather than silently suppressing or working around it — see Decision Point in the accompanying plan | must |
| FR-007 | Each entry in the `await-holding-invalid-types` array SHALL use each type's fully qualified path as required by clippy's config schema (`clippy::await_holding_invalid_type` documentation), verified against `dashmap 6.2` docs.rs module layout | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Maintainability | The `clippy.toml` config change must be self-documenting: each registered type path is accompanied by a short comment (or the file has a header comment) explaining why DashMap guards are singled out, referencing #317/#319/#325 so future contributors understand the intent without needing to reread this spec |
| NFR-002 | CI cost | Adding the config must not measurably change `cargo clippy` run time — `clippy.toml` type-path config lookups are a constant-cost addition to an already-running lint, no new lint passes are introduced |
| NFR-003 | Compatibility | The config must be valid for the clippy toolchain version currently pinned/used in CI (verify `await-holding-invalid-types` key is supported by the installed clippy version before merging; this key has been stable in clippy for multiple releases but must be confirmed, not assumed) |
| NFR-004 | Scope precision | The config must NOT globally disable or downgrade `await_holding_invalid_type` (already active via `clippy::all`) — it only *extends* the set of types the existing, already-warn-level lint checks for |

## 5. Data Model

No new runtime data entities — this is a static-analysis configuration
change. The only "entity" is the lint configuration itself:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `clippy.toml` | Workspace-root static-analysis config file consumed by `cargo clippy` | `await-holding-invalid-types: Vec<String>` (fully-qualified type paths) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A type path string in the config is misspelled or doesn't match dashmap's actual module layout | Clippy silently ignores unmatched type paths rather than erroring (per clippy's documented behavior for this lint) — mitigated by verifying each path against dashmap 6.2's docs.rs module tree before merging (FR-007), not by runtime validation |
| Running `cargo clippy` against the current, already-fixed codebase surfaces a *new* violation not covered by #317/#318/#319/#325 | Per FR-006: do not fix it as part of this config PR. Document the finding and file a separate P1/P2 bug issue per the project's Anomaly Detection process, referencing the new violation's file/line; this config PR proceeds once the violation is either accepted as a documented follow-up or trivially not a real hazard (e.g. a false positive worth a targeted `#[allow]` with justification) |
| A future `dashmap` major-version bump changes the `mapref` module layout (e.g. renames `MappedRef`) | Out of scope for this spec — covered by the project's existing Dependency Monitoring process (`cargo outdated`, changelog review) when `dashmap` is next upgraded; the config's type paths will need a matching update at that time, called out here as residual risk only |
| A handler correctly clones a value out of a `Ref` and explicitly drops the guard before an `.await` (the pattern already used post-#325 via `Arc<dyn ParseResult>`) | No lint trigger — the guard is no longer in scope at the await point, which is exactly the pattern this config is meant to keep enforced |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `clippy.toml` exists at workspace root with all six required type paths (FR-002/003/004) | 1 file, 6 entries, present after merge |
| SC-002 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit code after config is added | 0 (clean), OR a documented follow-up issue filed per FR-006/Edge Cases if new violations surface |
| SC-003 | Time added to `cargo clippy --workspace --all-targets --all-features` wall-clock run | No measurable increase (informal check: compare a local run before/after) |
| SC-004 | Recurrence of the DashMap-guard-across-await bug class after this change ships | 0 further manual-audit-discovered occurrences (leading indicator to monitor across future continuous-improvement cycles; not verifiable at merge time) |

## 8. Agent Boundaries

### Always (without asking)
- Add `clippy.toml` at the workspace root with the six type paths from
  FR-002/003/004, each with a short explanatory comment referencing
  #317/#319/#325
- Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  after adding the file and report the result (clean, or list of new
  violations) — do not silently proceed past a non-clean result
- Run the project's full pre-commit check suite (`cargo +nightly fmt
  --all -- --check`, the clippy command above, `cargo nextest run
  --workspace --all-features --no-fail-fast`) before proposing the PR
- Update `CHANGELOG.md` under `[Unreleased]` with a one-line entry

### Ask First
- Filing a new bug issue if FR-006/the Edge Cases table's second row is
  triggered (a genuinely new violation surfaces) — confirm severity
  classification (P0-P4) and whether it should block this PR or ship as a
  parallel follow-up before creating the issue
- Adding an `#[allow(clippy::await_holding_invalid_type)]` suppression
  anywhere, even with justification — this defeats the purpose of the
  feature and must be a deliberate, reviewed decision, not a default
  workaround for a newly-surfaced violation

### Never
- Modify `ServerState::get_document`'s signature or any other DashMap
  access pattern as part of this change (that's remediation, explicitly
  out of scope — see Out of Scope)
- Remove or weaken the existing `TODO(#317-followup)`-style comments in
  `crates/deps-core/src/ecosystem.rs`
- Suppress a newly-surfaced violation (per Edge Cases) without first
  raising it as a separate tracked issue

## 9. Open Questions

- [NEEDS CLARIFICATION: confirm the exact clippy toolchain version pinned in
  CI (`.github/workflows/*.yml`) supports the `await-holding-invalid-types`
  clippy.toml key — expected to be stable across recent clippy releases but
  not yet independently verified against this project's pinned version as
  part of this spec.]
- [NEEDS CLARIFICATION: if FR-006 triggers (a new violation surfaces when the
  config is added), should the config-addition PR still merge with the
  violation documented as a follow-up issue, or should it block on fixing
  the violation first? Spec defaults to "ship the config, file the follow-up
  separately" per the Edge Cases table, but this is a judgment call for
  whoever runs the plan's verification step.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issue #317, PR #318, Issue #319, PR #325 — the three prior occurrences of
  this exact bug class this feature is meant to prevent from recurring a
  fourth time
- `crates/deps-lsp/src/document/state.rs` (`ServerState::get_document`,
  lines 518-521) — the one confirmed live `Ref`-returning API in the
  current codebase
- `crates/deps-core/src/ecosystem.rs` (around line 406, `generate_inlay_hints`)
  — the `TODO(#317-followup)`-style comment this config's Goal statement
  references as the currently-latent hazard

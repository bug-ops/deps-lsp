---
aliases:
  - Workspace Diagnostics Pull Support
  - workspace/diagnostic
tags:
  - sdd
  - spec
  - lsp-protocol
  - diagnostics
  - research
created: 2026-09-03
status: draft
related:
  - "[[constitution]]"
  - "[[015-lsp-3-18-diagnostic-markup-tooltip-gap/spec|LSP 3.18 diagnostic markup / command-tooltip gap]]"
---

# Feature: Workspace Diagnostics Pull Support (`workspace/diagnostic`)

> [!info] Metadata
> **Author**: research/continuous-improvement cycle
> **Branch**: (none yet — specify-only, no implementation scheduled)
> **Priority**: P4
> **Type**: research/enhancement
> **Issue**: #547

## 1. Overview

### Problem Statement

deps-lsp already implements the LSP 3.17 per-document pull model:
`crates/deps-lsp/src/server.rs:338-343` advertises `textDocument/diagnostic`
support via `DiagnosticServerCapabilities::Options` (`identifier: "deps"`,
`inter_file_dependencies: false`). The sibling flag `workspace_diagnostics`
is hardcoded to `false` in the same struct literal, with no code comment
explaining the decision and no linked issue — `gh issue list --search
"workspace_diagnostics OR workspace diagnostics" --state all` returns zero
hits. Two tests (`server.rs:1029`, `server.rs:1095-1099`) assert the current
"off" state, so it is at least intentionally pinned rather than accidentally
regressed, but the *rationale* exists nowhere on record.

LSP 3.17 also defines `workspace/diagnostic`
([spec](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#workspace_diagnostic)),
which lets a client pull diagnostics for **every file in the workspace in one
request**, including manifests the user has never opened in the editor. This
is disproportionately valuable for deps-lsp's specific domain compared to a
typical language server: a monorepo may contain many `Cargo.toml` /
`package.json` / `pyproject.toml` files, and today a user only sees
outdated/vulnerable/deprecated-dependency diagnostics for manifests they
happen to have opened. `workspace/diagnostic` would let a supporting client
surface the full dependency-health picture of a repository up front, which is
a natural differentiator for a dependency-checking LSP versus general-purpose
language servers where the per-file pull dominates the use case.

The counterweight (confirmed via web research, September 2026): client-side
adoption of the LSP 3.17 pull model is already uneven —
[!warning] `textDocument/diagnostic` has landed in VS Code and some servers
built on Roslyn/`ruby-lsp`, but other clients (e.g. Helix) are still catching
up — and `workspace/diagnostic` (the multi-file variant) has **less**
consistent client support than the per-document variant. Shipping this today
may deliver limited user-visible value until editor adoption widens.

### Goal

Produce a specification (WHAT and WHY only) for whether and how deps-lsp
should implement `workspace/diagnostic`: scanning every known manifest file
across all workspace folders, aggregating results into a
`WorkspaceDiagnosticReport`, and respecting existing per-ecosystem
diagnostic suppression and user configuration — so that a client which does
support the workspace pull model receives full-monorepo dependency
diagnostics without the user needing to open every manifest individually.
HOW (concrete Rust types, whether the implementation reuses or further
decomposes `generate_diagnostics_from_cache`, incremental result IDs,
workspace-folder enumeration strategy) is explicitly deferred to a future
`/sdd plan`.

### Out of Scope

- Any code change to `crates/deps-lsp/src/server.rs` or elsewhere — this spec
  is research/planning only; `workspace_diagnostics` stays `false` until a
  follow-up implementation phase is explicitly scheduled.
- `workspace/diagnostic/refresh` server-initiated refresh semantics beyond
  what's needed to describe the capability contract (full HOW deferred to
  `/sdd plan`).
- Non-manifest workspace files (source code, CI config already covered by
  ecosystem-specific specs such as [[030-gitlab-ci-ecosystem/spec|GitLab
  CI]] or [[014-github-actions-ecosystem/spec|GitHub Actions]]) — this spec
  only concerns dependency-manifest diagnostics, the existing domain of
  `textDocument/diagnostic` in this project.
- Editor/client-side UI decisions (e.g., how VS Code renders a "Problems"
  panel aggregated from workspace diagnostics) — outside deps-lsp's control.
- Redesigning `generate_diagnostics_from_cache` itself for its own sake;
  any refactor is justified only insofar as this feature's aggregation
  requirements demand it (see FR-004 and Open Question 2).

## 2. User Stories

### US-001: See dependency health across an entire monorepo without opening every manifest

AS A developer working in a Cargo/npm/PyPI monorepo with many manifest files
I WANT my editor to show outdated/vulnerable/deprecated dependency
diagnostics for every manifest in the workspace, not just the ones I have
open
SO THAT I can catch dependency issues in parts of the repository I'm not
actively editing, without manually opening and closing dozens of files

**Acceptance criteria:**
```
GIVEN a workspace containing 5 Cargo.toml files, of which 1 is currently open in the editor
WHEN a client that supports `workspace/diagnostic` sends a `workspace/diagnostic` request
THEN the server SHALL return a diagnostic report entry for all 5 Cargo.toml files, not just the 1 open one
```

### US-002: Client without workspace-pull support is unaffected

AS A developer using an editor/client that does not implement
`workspace/diagnostic`
I WANT deps-lsp to continue working exactly as it does today (per-document
pull via `textDocument/diagnostic`, plus any existing push-based fallback)
SO THAT enabling this capability server-side never breaks or degrades my
existing experience

**Acceptance criteria:**
```
GIVEN a client that does not send `workspace/diagnostic` requests
WHEN the server advertises `workspace_diagnostics: true` in its capabilities
THEN the server's behavior for `textDocument/diagnostic`, `didOpen`/`didChange` push diagnostics, hover, completion, and code lenses SHALL be unchanged
```

### US-003: Large workspace pull does not degrade responsiveness

AS A developer in a large monorepo (hundreds of manifest files)
I WANT the workspace diagnostic pull to avoid re-fetching registry data or
re-parsing every manifest on every single request
SO THAT the editor doesn't stall or spam registries on every workspace pull

**Acceptance criteria:**
```
GIVEN a workspace with 200 manifest files already cached from a prior scan
WHEN the client re-issues `workspace/diagnostic` shortly after, with `previous_result_ids` matching the server's last-reported result IDs for unchanged files
THEN the server SHALL report those unchanged files as `WorkspaceUnchangedDocumentDiagnosticReport` rather than recomputing and re-transmitting their full diagnostic list
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the client sends `initialize` and declares (or omits, per LSP defaults) `workspace.diagnostics` capabilities THE SYSTEM SHALL decide, based on a documented rationale, whether to advertise `workspace_diagnostics: true` in the `DiagnosticOptions` returned from `initialize` | must (decision), should (flip to `true`, pending Open Question 1) |
| FR-002 | WHEN `workspace_diagnostics` is advertised as `true` and the client sends `workspace/diagnostic` THE SYSTEM SHALL enumerate every manifest file matching a registered ecosystem's `manifest_filenames()` (`crates/deps-core/src/ecosystem.rs:399`) across all workspace folders known to the server | must |
| FR-003 | WHEN enumerating manifest files for a workspace/diagnostic response THE SYSTEM SHALL include manifests that are not currently open as an LSP text document, loading them from disk the same way `ensure_document_loaded` (cold-start path, `crates/deps-lsp/src/document/lifecycle.rs`) already loads an unopened document for a `textDocument/diagnostic` request | must |
| FR-004 | WHEN generating the diagnostic list for each manifest in a workspace pull THE SYSTEM SHALL apply the same suppression rules, severities, and configuration (`DiagnosticsConfig`, freshness/offline settings) as `textDocument/diagnostic` uses today, so a manifest's diagnostics are identical whether returned via the per-document or workspace pull path | must |
| FR-005 | WHEN the client includes `previous_result_ids` in a `WorkspaceDiagnosticParams` request THE SYSTEM SHALL return `WorkspaceUnchangedDocumentDiagnosticReport` for any manifest whose content and resolved dependency data have not changed since the referenced result ID, instead of recomputing that manifest's diagnostics | should |
| FR-006 | WHEN a manifest file cannot be parsed, its ecosystem cannot be resolved, or a registry fetch fails during a workspace pull THE SYSTEM SHALL report that manifest's own diagnostics (e.g. a parse-error or fetch-failure diagnostic) without aborting the aggregation of diagnostics for the other manifests in the same `workspace/diagnostic` response | must |
| FR-007 | WHEN the client declares `workspace.diagnostics.refreshSupport: true` THE SYSTEM SHALL be able to send `workspace/diagnostic/refresh` following the same client-capability-gating pattern already used for `inlay_hint_refresh_supported` and `code_lens_refresh_supported` (`crates/deps-lsp/src/server.rs:279-309`) | should |
| FR-008 | WHEN `workspace_diagnostics` is advertised as `false` (current and possibly permanent state, pending Open Question 1) THE SYSTEM SHALL continue rejecting `workspace/diagnostic` requests with `method_not_found`, matching `tower-lsp-server`'s default trait implementation | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | A `workspace/diagnostic` request for a workspace already warm in cache SHALL NOT trigger a full re-fetch of registry data for every dependency in every manifest — see FR-005 and Open Question 3 |
| NFR-002 | Performance | Manifest enumeration and per-manifest diagnostic generation SHALL run without blocking the LSP request-handling loop, consistent with the existing constraint that "all LSP handler methods must be non-blocking — spawn heavy work with `tokio::spawn`" (`.claude/rules/rust-code.md`) |
| NFR-003 | Consistency | Diagnostics returned for a given manifest via `workspace/diagnostic` SHALL be identical in content and severity to diagnostics returned for the same manifest via `textDocument/diagnostic`, absent an explicit, documented reason for divergence (FR-004) |
| NFR-004 | Compatibility | Advertising `workspace_diagnostics: true` SHALL be backward compatible — clients that never send `workspace/diagnostic` SHALL observe no behavior change (US-002) |
| NFR-005 | Scalability | The design SHALL state an explicit approach (even if "out of scope for v1, revisit if a real monorepo user reports pain") for workspaces with a very large manifest count, rather than silently assuming small workspace size |

## 5. Data Model

No new persistent entities — this reuses existing manifest-parsing and
diagnostic types. The relevant *protocol* types (already available via the
pinned `ls-types = "0.0.6"` dependency, confirmed present in
`ls-types-0.0.6/src/workspace_diagnostic.rs` and
`ls-types-0.0.6/src/request.rs:917`, and already exposed as a default
`workspace_diagnostic` hook on `tower-lsp-server = "0.23"`'s `LanguageServer`
trait) are:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `WorkspaceDiagnosticParams` | Client request payload for `workspace/diagnostic` | `identifier`, `previous_result_ids: Vec<PreviousResultId>`, partial-result/work-done tokens |
| `PreviousResultId` | Client-reported last-known result ID per document URI | `uri`, `value` (opaque result-id string) |
| `WorkspaceDocumentDiagnosticReport` | Per-manifest entry in the aggregated response | Either `WorkspaceFullDocumentDiagnosticReport` (URI + version + full `items: Vec<Diagnostic>` + new `result_id`) or `WorkspaceUnchangedDocumentDiagnosticReport` (URI + version + `result_id` only, per FR-005) |
| `WorkspaceDiagnosticReport` | Full response body | `items: Vec<WorkspaceDocumentDiagnosticReport>` |
| Manifest enumeration result *(new, HOW deferred to plan)* | Server-internal list of manifest URIs discovered across workspace folders, keyed by ecosystem | Not yet designed — see Open Question 4 |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Client sends `workspace/diagnostic` but server advertised `workspace_diagnostics: false` | Per FR-008, unreachable in practice (well-behaved clients only send requests the server advertised support for), but if it happens the default `tower-lsp-server` trait implementation returns `method_not_found` |
| Workspace has zero manifest files matching any registered ecosystem | Server SHALL return an empty `WorkspaceDiagnosticReport.items` list, not an error |
| A manifest file exists on disk but was deleted between enumeration and diagnostic generation (race with a concurrent `didChangeWatchedFiles` delete event) | Server SHALL skip the missing manifest for this response rather than erroring the whole request; the next pull (or a server-initiated `workspace/diagnostic/refresh`, FR-007) reflects the deletion |
| Multi-root workspace (multiple `WorkspaceFolder` entries at `initialize`) | Server SHALL enumerate manifests across every declared workspace folder, not only the first/primary one — deps-lsp currently has no code that enumerates `WorkspaceFolder`s at all (confirmed: no `workspace_folders`/`WorkspaceFolder` usage found in `crates/deps-lsp/src/*.rs`), so this is new surface area, not a reuse of an existing mechanism |
| Workspace contains an unopened manifest with syntax the parser rejects | Per FR-006, that manifest's entry in the report carries a parse-error diagnostic; other manifests are unaffected |
| Very large workspace (hundreds/thousands of manifests) and a client that does not send `previous_result_ids` on repeat calls | Server recomputes everything on every call — acceptable per NFR-005's "explicit, even if deferred" scalability stance, but SHALL NOT crash, deadlock, or exceed a documented time budget (budget itself is a plan-phase decision) |
| Client cancels an in-flight `workspace/diagnostic` (partial-result token, work-done progress cancellation) | Server SHALL honor LSP cancellation semantics already used elsewhere in the codebase (existing `CancellationToken`/request-cancellation patterns, if any — verify in plan phase) rather than continuing to compute a discarded response |

## 7. Success Criteria

Measurable metrics that prove the feature (if implemented) works — for the
spec itself, "success" means the open design questions below are resolved
enough to proceed to `/sdd plan`.

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Existing capability tests (`server.rs:1029`, `server.rs:1095-1099`) updated to reflect the chosen `workspace_diagnostics` value with an explanatory comment/doc-link, replacing the current unexplained `false` | Comment present, no unexplained hardcoded booleans in `server_capabilities()` |
| SC-002 | If implemented: a `workspace/diagnostic` request against a fixture workspace with N manifests (N ≥ 3) across at least 2 ecosystems returns exactly N diagnostic report entries with correct per-manifest diagnostics | 100% manifest coverage, 0 missing/duplicate entries |
| SC-003 | If implemented: diagnostics for a manifest returned via `workspace/diagnostic` are byte-identical (same `Diagnostic` fields, ignoring `result_id`) to the same manifest's `textDocument/diagnostic` response | Exact match in a comparison test |
| SC-004 | Open Questions 1-4 below are resolved (answered or explicitly deferred with rationale) before `/sdd plan` is run for this feature | 0 unresolved blocking questions at plan time |

## 8. Agent Boundaries

### Always (without asking)
- Treat this spec as research/planning only — no source file under `crates/`
  is touched while this spec is in `specify` status
- Cross-reference the current (2026-09-03) state of
  `generate_diagnostics_from_cache` when this spec is later picked up for
  `/sdd plan` — issue #500 (function had grown to ~500 lines) was closed as
  completed on 2026-09-02 and the function is now ~87 lines
  (`crates/deps-core/src/lsp_helpers/diagnostics.rs:501`), so any
  plan-phase assumption that reuse requires "unwinding a 500-line function"
  is stale and must be re-verified against the code at plan time, not
  against this spec's original finding text

### Ask First
- Flipping `workspace_diagnostics` to `true` in `server_capabilities()` —
  requires resolving Open Question 1 (adoption tradeoff) with the user/team
  first, since it's a user-visible protocol capability change
- Any refactor of `generate_diagnostics_from_cache` or its call sites
  undertaken specifically to support this feature — confirm scope with the
  user before touching a function already flagged once for complexity

### Never
- Implement `workspace/diagnostic` handler logic directly from this spec
  without an intervening `/sdd plan` — the HOW (result-ID caching strategy,
  manifest enumeration mechanism, concurrency model) is explicitly
  undecided
- Silently drop or weaken existing `textDocument/diagnostic` suppression
  rules in the name of "reuse" for the workspace path (violates NFR-003)

## 9. Open Questions

- [NEEDS CLARIFICATION: Given confirmed uneven client-side support for
  `workspace/diagnostic` as of September 2026 (narrower than the already
  patchy `textDocument/diagnostic` adoption), should deps-lsp implement this
  now as a differentiator bet, or wait for broader editor adoption and
  revisit in a future research cycle? Affects FR-001's "should" and whether
  this spec proceeds to `/sdd plan` at all.]
- [NEEDS CLARIFICATION: Should the workspace-pull diagnostic generation path
  reuse `generate_diagnostics_from_cache` as-is (now ~87 lines post-#500
  refactor, called once per manifest), or does aggregating results across
  many manifests warrant a new thin wrapper/orchestration layer in
  `deps-lsp` rather than `deps-core`? Where does manifest-enumeration
  concern live — `deps-lsp` (LSP-protocol-aware) or a new shared helper in
  `deps-core`?]
- [NEEDS CLARIFICATION: What is the result-ID / caching strategy for FR-005
  (avoid re-scanning every manifest on every `workspace/diagnostic` call in
  a large workspace)? Candidates: hash of manifest content + resolved
  dependency versions; reuse of existing per-document cache invalidation
  hooks in `crates/deps-lsp/src/document/lifecycle.rs`; a new workspace-level
  result-ID table. Needs investigation of what state is already tracked
  per-document today and whether it's sufficient.]
- [NEEDS CLARIFICATION: How does workspace-folder / multi-root enumeration
  interact with deps-lsp's current single-document-centric caching model?
  Confirmed via grep that no code today enumerates `WorkspaceFolder`s from
  `InitializeParams` — this would be genuinely new surface area. Does
  enumeration walk the filesystem directly from each workspace folder's
  root URI, or does the server ask the client (e.g. via
  `workspace/workspaceFolders` + some file-listing capability) — and if the
  latter, does the client even support the needed capability consistently?]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[015-lsp-3-18-diagnostic-markup-tooltip-gap/spec|LSP 3.18 diagnostic markup / command-tooltip support blocked by ls-types 0.0.6]] — related LSP-capability research; that spec is blocked on a dependency version gap, this one is not (the needed `WorkspaceDiagnosticParams`/`WorkspaceDiagnosticReport` types already exist in `ls-types = "0.0.6"`)
- [GitHub issue #308](https://github.com/bug-ops/deps-lsp/issues/308) — LSP 3.18 diagnostic markup research, adjacent LSP-capability territory but does not cover this gap
- [LSP 3.17 specification — `workspace/diagnostic`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#workspace_diagnostic)

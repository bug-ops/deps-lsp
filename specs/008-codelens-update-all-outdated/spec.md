---
aliases:
  - CodeLens Update All Outdated Dependencies
  - Workspace-wide Update All
tags:
  - sdd
  - spec
  - research
  - parity-gap
  - lsp-protocol
  - priority/p2
created: 2026-08-20
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: CodeLens support for "update all outdated dependencies" action

> [!info] Metadata
> **Author**: continuous-improvement cycle 005 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-codelens-update-all`]
> **Type**: research / competitive-parity gap — this spec documents WHAT is missing and WHY;
> the HOW (exact wiring, placement, batching strategy) is deferred to a future `/sdd plan` session.

## 1. Overview

### Problem Statement

deps-lsp implements only a subset of the LSP 3.17 surface relevant to dependency tooling:
`hover`, `completion`, `inlay_hint`, `code_action` (per-line), `diagnostic` (pull model), and
`execute_command`. It does **not** implement `textDocument/codeLens` (or `workspace/codeLens`),
`workspace/symbol`, or `textDocument/semanticTokens`.

Verified this cycle (2026-08-20) via:
```
rg -n "code_lens|codeLens|CodeLens|workspace_symbol|workspaceSymbol|semantic_tokens|semanticTokens" crates/deps-lsp/src/ --type rust
# => no output (zero hits)
```
`ServerCapabilities` construction in `crates/deps-lsp/src/server.rs:194-220` sets
`text_document_sync`, `completion_provider`, `hover_provider`, `inlay_hint_provider`,
`code_action_provider`, and `execute_command_provider` — there is no `code_lens_provider` field
set.

IDE-native dependency-update UIs (VS Code's built-in npm/Cargo tooling patterns, JetBrains
package-update panels, GitHub Dependabot-adjacent editor integrations) commonly surface an
**aggregate** "N dependencies are outdated — update all" affordance at the top of a manifest
file, in addition to per-dependency hints. deps-lsp currently only offers the per-line
interaction: a user must act on each outdated dependency individually via hover-triggered code
action / `deps-lsp.updateVersion` command.

This gap has been observed in the competitive-parity research playbook
(`.local/testing/playbooks/competitive-parity.md`) across three consecutive prior continuous-
improvement cycles (002, 003, 004) but was never spec'd or filed as an issue — each cycle
deferred it in favor of a higher-confidence finding. The most recent research handoff
(`.local/handoff/2026-08-20T03-50-54-researcher.md`) explicitly recommended acting on it this
cycle (005) instead of deferring a fourth time.

### Goal

deps-lsp advertises `textDocument/codeLens` capability and, for any open manifest with one or
more outdated dependencies, renders at least one CodeLens entry summarizing the aggregate count
and offering a single action that updates all outdated dependencies in that manifest, reusing
the existing per-dependency version-comparison data and `WorkspaceEdit` update mechanism.

### Out of Scope

- Redesigning or replacing the existing per-line `code_action` / `deps-lsp.updateVersion`
  interaction — CodeLens is additive, not a replacement.
- `workspace/symbol` and `textDocument/semanticTokens` — separate, unrelated LSP-surface gaps
  noted by the same grep sweep; not covered by this spec.
- Vulnerability-severity-aware batching (e.g., "update only vulnerable deps") — that depends on
  the separate OSV vulnerability-diagnostics effort ([[002-osv-vulnerability-diagnostics/spec]])
  and is not assumed to exist yet.
- Cross-file / true `workspace/codeLens` aggregation (e.g., one CodeLens summarizing outdated
  counts across an entire multi-manifest workspace) — this spec scopes to per-document
  `textDocument/codeLens` only; workspace-wide aggregation is a possible future extension.
- Exact UI placement, resolve-lazy vs eager CodeLens computation, and batching/undo semantics
  for the bulk edit — these are HOW decisions for `/sdd plan`.

## 2. User Stories

### US-001: See and act on an aggregate outdated count

AS A developer with a manifest file containing many outdated dependencies (e.g., a `Cargo.toml`
or `package.json` with 20+ dependencies, several of which are outdated)
I WANT a single, visible annotation showing how many dependencies are outdated and a way to
update them all at once
SO THAT I don't have to hover and trigger the update command individually for each outdated
dependency, one at a time.

**Acceptance criteria:**
```
GIVEN an open manifest file with N outdated dependencies (N >= 1)
WHEN the editor requests textDocument/codeLens for that document
THEN the server SHALL return at least one CodeLens entry whose title communicates the count
     (e.g., "Update N outdated dependencies") and whose command, when invoked, updates all N
     outdated dependencies in that manifest via a WorkspaceEdit
```

### US-002: No noise when everything is current

AS A developer with a manifest file where all dependencies are already up to date
I WANT no "update all" CodeLens to appear
SO THAT the CodeLens surface doesn't add visual clutter when there is nothing actionable.

**Acceptance criteria:**
```
GIVEN an open manifest file with zero outdated dependencies
WHEN the editor requests textDocument/codeLens for that document
THEN the server SHALL return an empty CodeLens list (or omit the aggregate entry) for that
     document
```

### US-003: Consistent behavior across every supported ecosystem

AS A developer using deps-lsp with any of the 10 supported ecosystems (Cargo, npm, PyPI, Go,
Bundler, Dart, Maven, Composer, Gradle, Swift, NuGet manifest formats)
I WANT the "update all outdated dependencies" CodeLens to behave identically regardless of which
manifest format I'm editing
SO THAT I don't have to learn ecosystem-specific quirks in the update workflow.

**Acceptance criteria:**
```
GIVEN two open manifests from different ecosystems (e.g., Cargo.toml and package.json), each
     with an equivalent number of outdated dependencies
WHEN textDocument/codeLens is requested for each
THEN the CodeLens title format, aggregate-count logic, and update-all command behavior SHALL be
     equivalent across both, per the project's cross-ecosystem-consistency rule
     (`.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing`)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL advertise `code_lens_provider` in `ServerCapabilities` (`crates/deps-lsp/src/server.rs`, alongside the existing `inlay_hint_provider` / `code_action_provider` / `execute_command_provider` entries around line 194) | must |
| FR-002 | WHEN the client sends `textDocument/codeLens` for an open manifest THE SYSTEM SHALL compute the count of outdated dependencies in that document by reusing the existing version-comparison logic already used for diagnostics and inlay hints (not a duplicate implementation) | must |
| FR-003 | WHEN the outdated-dependency count for a manifest is greater than zero THE SYSTEM SHALL return at least one CodeLens entry whose command title communicates the count (e.g., "Update N outdated dependencies") | must |
| FR-004 | WHEN the outdated-dependency count for a manifest is zero THE SYSTEM SHALL return no aggregate "update all" CodeLens entry for that document | must |
| FR-005 | THE SYSTEM SHALL expose a workspace/document-scoped command (new, or an extension of the existing `deps-lsp.updateVersion` command defined in `crates/deps-lsp/src/server.rs` `mod commands`) that, when invoked, applies a `WorkspaceEdit` updating all outdated dependencies in the target manifest to their latest resolvable version | must |
| FR-006 | THE SYSTEM SHALL produce equivalent CodeLens behavior (capability advertisement, count computation, command wiring) across all 10 supported ecosystem crates (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-go`, `deps-bundler`, `deps-dart`, `deps-maven`, `deps-composer`, `deps-gradle`, `deps-swift`, `deps-nuget`), per the cross-ecosystem-consistency rule | must |
| FR-007 | THE SYSTEM SHALL route the update-all command through the existing `execute_command` handler pathway (`crates/deps-lsp/src/server.rs`, around line 450-460) rather than introducing a parallel execution mechanism | should |
| FR-008 | WHEN a manifest is edited after CodeLens was computed (e.g., a dependency version line changes) THE SYSTEM SHALL recompute the CodeLens on the next `textDocument/codeLens` request rather than serving stale counts | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Computing the CodeLens SHALL NOT trigger additional registry (network) fetches beyond what diagnostics/inlay hints already perform for the same document — it SHALL reuse already-cached per-dependency version-comparison state |
| NFR-002 | Performance | `textDocument/codeLens` response time SHALL be dominated by in-memory aggregation over already-computed per-dependency state, not by new I/O; target latency in the same order of magnitude as the existing `textDocument/inlayHint` handler for an equivalently sized manifest |
| NFR-003 | Consistency | CodeLens title format and update-all semantics SHALL be identical across all 10 ecosystems — any ecosystem-specific divergence is a first-class bug per `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` |
| NFR-004 | Compatibility | Advertising `code_lens_provider` SHALL NOT alter existing `hover`, `completion`, `inlay_hint`, `code_action`, `diagnostic`, or `execute_command` behavior — this is an additive capability |
| NFR-005 | Reliability | If the update-all command partially fails (e.g., one dependency's latest version cannot be resolved), the system SHALL NOT leave the manifest in a corrupted/partially-edited state — [NEEDS CLARIFICATION: exact atomicity/rollback guarantee for partial-failure batch edits] |

## 5. Data Model

No new persistent entities. This feature aggregates existing per-dependency version-comparison
results (already computed for diagnostics/inlay hints) into a document-level summary.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Outdated dependency count (derived) | Per-document aggregate of dependencies whose current version is behind the latest resolvable version | document URI, count of outdated deps, [NEEDS CLARIFICATION: does the count include yanked/unknown-status deps or only strictly "outdated"?] |
| Update-all command payload | Input to the workspace-scoped update command | document URI, list of (dependency identifier, target version) pairs to apply as a single `WorkspaceEdit` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Manifest has zero dependencies | No CodeLens returned (empty list) |
| Manifest has zero outdated dependencies | No aggregate "update all" CodeLens returned (per US-002 / FR-004) |
| Manifest has one outdated dependency | CodeLens SHALL still appear (singular vs plural title wording is a HOW detail for `/sdd plan`) — [NEEDS CLARIFICATION: singular phrasing, e.g. "Update 1 outdated dependency"] |
| Registry/version data for some dependencies is stale or unavailable (e.g., offline) | CodeLens count SHALL reflect only dependencies with resolvable comparison state; system SHALL degrade gracefully, consistent with how diagnostics/inlay hints already degrade under the same condition |
| User invokes update-all while manifest has unsaved edits | [NEEDS CLARIFICATION: does the update-all command operate on the last-synced document state via `WorkspaceEdit`, consistent with how `deps-lsp.updateVersion` already handles this for single updates?] |
| Manifest contains a mix of outdated + yanked + unknown-status dependencies | [NEEDS CLARIFICATION: does "update all outdated" only target strictly-outdated entries, or also attempt to resolve yanked/unknown entries?] |
| Very large manifest (hundreds of dependencies, many outdated) | CodeLens computation SHALL NOT introduce new registry calls (NFR-001); update-all command SHALL apply as a single batched `WorkspaceEdit`, not N sequential edits |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `code_lens_provider` present in `ServerCapabilities` | Advertised for all supported manifest file types |
| SC-002 | CodeLens count matches diagnostic/inlay-hint outdated count | 100% agreement between the CodeLens aggregate count and the count of "outdated" diagnostics for the same document at the same point in time |
| SC-003 | No duplicate registry fetches introduced by CodeLens computation | 0 additional outbound registry HTTP calls attributable to `textDocument/codeLens` beyond what diagnostics/inlay hints already perform, verified via debug log inspection per the project's live-testing protocol |
| SC-004 | Cross-ecosystem consistency | CodeLens title format and update-all command behavior verified equivalent across all 10 ecosystem manifest types in a live-testing session, logged in `.local/testing/coverage.md`'s LSP Feature Matrix |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing patterns in `crates/deps-lsp/src/server.rs` for capability advertisement and
  command wiring (reuse `execute_command` pathway, `mod commands` constants).
- Reuse `deps-core`'s existing version-comparison logic; do not duplicate it in a new module.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets
  --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`)
  before considering any implementation of this spec complete.

### Ask First
- Introducing a new LSP command identifier distinct from `deps-lsp.updateVersion` (vs. extending
  the existing one with a batch mode).
- Any change to the `WorkspaceEdit` batching/atomicity strategy that could affect the existing
  single-dependency update command's behavior.
- Adding a new dependency to support CodeLens rendering, if one is deemed necessary.

### Never
- Modify the existing per-line `code_action` / `updateVersion` interaction as a side effect of
  adding CodeLens — it must remain fully functional and unchanged in behavior.
- Introduce ecosystem-specific CodeLens behavior that diverges from the other 9 ecosystems
  without an explicit, documented rationale.

## 9. Open Questions

- [NEEDS CLARIFICATION: Exact CodeLens placement — top of file (single document-level CodeLens)
  vs. per-dependency-block (e.g., one per `[dependencies]` table in Cargo.toml, one per
  `dependencies`/`devDependencies` object in package.json)? The finding does not prescribe this;
  it is a `/sdd plan` decision.]
- [NEEDS CLARIFICATION: Should the update-all command target only strictly "outdated" status, or
  also include "yanked" / "unknown" status dependencies where a safe upgrade target exists?]
- [NEEDS CLARIFICATION: Atomicity/rollback guarantee when the batch update partially fails
  (NFR-005) — should the `WorkspaceEdit` be all-or-nothing, or best-effort with a follow-up
  diagnostic listing what couldn't be resolved?]
- [NEEDS CLARIFICATION: Should CodeLens support `workspace/codeLens` (cross-file aggregation)
  in a later iteration, or remain strictly per-document (`textDocument/codeLens`) as scoped
  here?]
- [NEEDS CLARIFICATION: Singular vs. plural title wording for the N=1 case.]
- [NEEDS CLARIFICATION: Should this feature be gated behind a client capability check (i.e.,
  only advertise `code_lens_provider` if the connecting client declares CodeLens support in
  `ClientCapabilities`), consistent with how other optional capabilities are or aren't
  negotiated in `crates/deps-lsp/src/server.rs`?]
- [NEEDS CLARIFICATION: No project constitution exists yet at `.local/specs/constitution.md`
  — this spec cannot yet be checked against project-wide architectural principles. Recommend
  running `/sdd init` before `/sdd plan` for this feature.]

## 10. See Also

- `crates/deps-lsp/src/server.rs` — `ServerCapabilities` construction (~line 194), `mod commands`
  and `UPDATE_VERSION` constant (~line 22-24), `execute_command_provider` /
  `ExecuteCommandOptions` wiring (~line 214), `execute_command` handler (~line 450-460)
- [LSP 3.17 specification — `textDocument/codeLens`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_codeLens)
- `.local/testing/playbooks/competitive-parity.md` — original finding, unfiled across cycles
  002, 003, 004
- `.local/handoff/2026-08-20T03-50-54-researcher.md` — prior cycle's handoff recommending this
  finding be acted on in cycle 005
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec]] — related diagnostics work using the same
  per-dependency version-comparison data
- [[007-lightweight-registry-metadata/spec]] — related registry-metadata work affecting the same
  version-comparison pipeline this feature reuses

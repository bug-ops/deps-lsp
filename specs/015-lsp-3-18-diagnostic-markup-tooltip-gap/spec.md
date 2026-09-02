---
aliases:
  - LSP 3.18 Diagnostic Markup Gap
  - Command Tooltip Gap
tags:
  - sdd
  - spec
  - research
  - lsp-protocol
  - dependency-gap
created: 2026-08-24
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: LSP 3.18 Diagnostic Markup / Command Tooltip Support (Blocked on `ls-types`)

> [!info] Metadata
> **Author**: Continuous Improvement cycle (research finding)
> **Branch**: N/A — research finding, not implementation-ready
> **Priority**: P4
> **Status**: Blocked on upstream dependency

> [!warning] Not implementation-ready
> This spec documents a **research finding** produced during a continuous-improvement
> cycle. It captures WHAT capability is currently unavailable and WHY it matters, so
> the requirement is not lost. Per project policy, no `/sdd plan` should be created
> for this spec until the upstream blocker (see [[#9. Open Questions]]) is resolved.
> The continuous-improvement workflow is read-only with respect to code — no
> implementation was attempted or should be attempted from this finding alone.

## 1. Overview

### Problem Statement

[Language Server Protocol](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/)
version 3.18 (draft) extends two capabilities that `deps-lsp` already implements —
diagnostics and code-action commands — with richer content types:

1. **Diagnostic markup content**: `Diagnostic.message` can now be either a plain
   `string` or a `MarkupContent` object (plain text or Markdown), enabling bold text,
   inline code spans, and hyperlinks directly inside a diagnostic message rendered in
   an editor's Problems panel, gutter hover, or inline diagnostic overlay.
2. **Command tooltips**: the `Command` interface gains an optional `tooltip: string`
   field, letting a code action or CodeLens command display explanatory text on hover,
   before the user invokes it.

`deps-lsp` surfaces dependency version intelligence (outdated, yanked, unsatisfiable
requirement, prerelease-only-match, license-policy, deprecation, etc.) almost entirely
through diagnostics and quick-fix commands (e.g. `deps-lsp.updateVersion`). Currently
these are plain, unformatted strings — the project cannot use bold/monospace/links to
distinguish version numbers, registry names, or CVE identifiers from surrounding text,
nor can it explain a quick-fix's effect before the user applies it. This is a pure
content-richness gap on existing capabilities, not a missing LSP method.

The gap is **not** a `deps-lsp` implementation choice — it is enforced by the
underlying LSP type-definition crate the project depends on transitively.
`deps-lsp` depends on `tower-lsp-server = "0.23"`, which depends on `ls-types v0.0.6`
for its Rust LSP type definitions. Live inspection of `ls-types-0.0.6` confirms the
3.18 types are absent (see [[#Reproduction / Evidence]] below).

### Goal

When `tower-lsp-server`/`ls-types` (or a successor crate) exposes LSP 3.18's
`Diagnostic` markup content and `Command.tooltip` types, `deps-lsp` SHALL be able to
opt into richer diagnostic and quick-fix presentation for all diagnostic categories
and the existing `deps-lsp.updateVersion` command, without introducing any new LSP
methods or breaking editors that only understand the 3.17 plain-string forms.

### Out of Scope

- `SnippetTextEdit` / `StringValue` (interactive snippet edits with tab stops) —
  lower relevance, since `deps-lsp`'s quick-fixes perform literal version-string
  replacement, not multi-cursor/tab-stop editing. Not part of this finding's scope.
- LSP 3.18 changes unrelated to `deps-lsp`'s feature surface: regex engine capability
  negotiation, document filter unions, D/Pascal language IDs, workspace edit metadata.
- Any client-side (editor extension) rendering work — this spec covers only the
  server-side capability to emit richer content once the dependency unblocks it.
- Actual code changes to diagnostics or commands — this spec is a readiness/tracking
  document, not an implementation plan. No `/sdd plan` follows from this spec until
  unblocked.

## 2. User Stories

### US-001: Distinguish version/registry identifiers in diagnostic text

AS A developer viewing a `deps-lsp` diagnostic in the Problems panel
I WANT the outdated/yanked/unsatisfiable-requirement message to render version
numbers, package names, and registry names in monospace, and any relevant advisory
or documentation reference as a clickable link
SO THAT I can distinguish structured data from prose at a glance and jump to more
detail without leaving the editor

**Acceptance criteria:**
```
GIVEN the client advertises support for MarkupContent in Diagnostic.message
  (per LSP 3.18 capability negotiation)
WHEN deps-lsp emits an outdated-dependency diagnostic
THEN the diagnostic message SHALL render the current and available version numbers
  in inline code spans, and SHALL degrade gracefully to an equivalent plain-text
  message for clients that do not advertise this capability
```

### US-002: Preview a quick-fix's effect before applying it

AS A developer hovering over the `deps-lsp.updateVersion` code action
I WANT a tooltip explaining which version the manifest entry will be updated to and
any caveat (e.g. "this crosses a major version boundary")
SO THAT I can decide whether to invoke the quick-fix without first opening a diff or
running it speculatively

**Acceptance criteria:**
```
GIVEN the client advertises support for Command.tooltip (per LSP 3.18)
WHEN deps-lsp returns a deps-lsp.updateVersion code action
THEN the Command SHALL include a tooltip field summarizing the version change and any
  semver-boundary caveat, and SHALL omit the field (falling back to title-only
  presentation) for clients that do not advertise this capability
```

## 3. Functional Requirements

These requirements apply **once the upstream dependency blocker is resolved**
(see [[#9. Open Questions]]). They are not actionable today and MUST NOT be
scheduled into a `/sdd plan`/`/sdd tasks` cycle while the blocker remains open.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the underlying LSP type crate exposes `Diagnostic.message` as a `MarkupContent`-capable union type THE SYSTEM SHALL be able to emit Markdown-formatted diagnostic messages for all existing diagnostic categories (outdated, yanked, unsatisfiable-requirement, prerelease-only-match, license-policy, deprecation) | should |
| FR-002 | WHEN a client's `textDocument.publishDiagnostics.markupSupport` (or equivalent 3.18 capability) is absent or `false` THE SYSTEM SHALL fall back to the existing plain-string diagnostic message format, unchanged from current behavior | must |
| FR-003 | WHEN the underlying LSP type crate exposes `Command.tooltip` THE SYSTEM SHALL populate a tooltip on the `deps-lsp.updateVersion` command summarizing the version transition | should |
| FR-004 | WHEN a client does not advertise `Command.tooltip` support THE SYSTEM SHALL omit the field, matching current behavior exactly (no functional regression for existing clients) | must |
| FR-005 | WHEN Markdown diagnostic content is emitted THE SYSTEM SHALL sanitize/escape any interpolated package names or version strings that could otherwise be interpreted as Markdown control characters, to prevent malformed rendering | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Compatibility | Adoption of 3.18 markup/tooltip types MUST NOT break editors/clients pinned to LSP 3.17 capability negotiation — plain-string fallback is mandatory, not optional |
| NFR-002 | Dependency hygiene | The upgrade path MUST go through the project's existing dependency-monitoring cadence (`cargo outdated --workspace`, `cargo deny check advisories`) — no ad-hoc pinning to an unreleased/pre-release `ls-types`/`tower-lsp-server` version |
| NFR-003 | Performance | Markdown formatting of diagnostic messages MUST NOT introduce measurable latency regression in diagnostic publish time (current baseline: diagnostics computed synchronously per manifest parse) |
| NFR-004 | Maintainability | Diagnostic message construction SHOULD be centralized in `deps-core` (per the project's cross-ecosystem consistency principle) so that markup formatting, once available, is applied uniformly across all ecosystem crates rather than ecosystem-by-ecosystem |

## 5. Data Model

No new persistent data model — this finding concerns the **output typing** of
existing in-memory diagnostic and command structures produced by `deps-core` and
consumed by `deps-lsp`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Diagnostic message | Existing per-diagnostic explanatory text (outdated/yanked/unsatisfiable/etc.) | Currently `String`; would become `String \| MarkupContent` once `ls-types` exposes the 3.18 union type |
| Command tooltip | New optional field on the existing `deps-lsp.updateVersion` command | `Option<String>`, populated only once `ls-types::Command` exposes a `tooltip` field |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Client omits 3.18 markup capability in `initialize` | `deps-lsp` continues emitting current plain-string diagnostic messages (no behavior change) |
| Client advertises markup support but only for `kind: plaintext`, not `markdown` | `deps-lsp` SHOULD emit plain-text `MarkupContent` rather than Markdown, to respect the negotiated `MarkupKind` |
| Package name or version string contains Markdown-significant characters (`*`, `_`, `` ` ``, `[`) | Interpolated values MUST be escaped before embedding in a Markdown message, per FR-005 |
| `ls-types`/`tower-lsp-server` ships 3.18 types but with a different shape than currently drafted in the spec (draft spec is not final) | Re-evaluate this spec against the crate's actual released types before opening `/sdd plan` — draft LSP spec fields are not guaranteed stable |

## 7. Success Criteria

This finding has no measurable runtime success criteria yet, since it is not
implementable. Readiness criteria for exiting the blocked state:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `ls-types` (or successor crate) release exposing `Diagnostic.message` as a markup-capable type | Released and adopted in `Cargo.toml` |
| SC-002 | `ls-types` (or successor crate) release exposing `Command.tooltip` | Released and adopted in `Cargo.toml` |
| SC-003 | Re-verification via live `cargo tree -p deps-lsp \| grep ls-types` | Confirms version ≥ the release satisfying SC-001/SC-002 |

## 8. Agent Boundaries

### Always (without asking)
- Re-check `ls-types`/`tower-lsp-server` version during each continuous-improvement
  dependency-monitoring pass (`cargo outdated --workspace`)
- Keep this spec's status as `draft — blocked` until the upstream types ship

### Ask First
- Pinning to a pre-release/beta version of `tower-lsp-server` or `ls-types` to get
  early access to 3.18 types
- Opening a `/sdd plan` for this feature once unblocked (confirm scope hasn't drifted
  from the 3.18 draft spec first, since it may still change before finalization)

### Never
- Implement diagnostic markup or command tooltips against the 3.18 **draft** spec
  fields without first confirming the released `ls-types` API surface matches
- Modify diagnostic message formatting in ways that break plain-string clients, even
  experimentally, outside a dedicated feature branch with capability negotiation

## 9. Open Questions

- [NEEDS CLARIFICATION: upstream crate release timeline unknown] — no published
  timeline exists for when `tower-lsp-server`/`ls-types` will adopt LSP 3.18 types;
  this must be re-checked each continuous-improvement dependency-monitoring cycle
  rather than assumed
- [NEEDS CLARIFICATION: LSP 3.18 is still in draft status as of this writing] —
  field names/shapes for `Diagnostic.message` union and `Command.tooltip` may change
  before the spec is finalized; re-validate against the released spec text at
  implementation time, not against this snapshot
- [NEEDS CLARIFICATION: which editors' clients would actually surface Markdown
  diagnostic content] — capability adoption also depends on client-side rendering
  support (e.g. VS Code, Zed, Neovim LSP clients); worth a parity check once the
  server-side type is available

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [LSP 3.18 specification (draft)](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/) — source of the `Diagnostic` markup content, `Command.tooltip`, and `SnippetTextEdit` changes referenced in this finding
- [`ls-types` crate on crates.io](https://crates.io/crates/lsp-types) — the transitive dependency currently blocking adoption (verify current version before re-evaluating this spec)
- `.claude/rules/continuous-improvement.md` — Research & Innovation and Dependency Monitoring sections governing how this finding was produced and how it should be re-checked

> [!note] Reproduction / Evidence
> Live-verified 2026-08-24, continuous-improvement cycle:
> - `cargo tree -p deps-lsp | grep ls-types` confirms `ls-types v0.0.6` is pulled in
>   transitively via `tower-lsp-server = "0.23"`
> - `ls-types-0.0.6/src/lib.rs` line 319: `Diagnostic::message` is typed `pub message:
>   String` — no `MarkupContent`/union variant
> - `ls-types-0.0.6/src/lib.rs` lines 439-448: `Command` struct has only `title:
>   String`, `command: String`, `arguments: Option<Vec<Value>>` — no `tooltip` field
> - `grep -rln "SnippetTextEdit"` across `ls-types-0.0.6/src/*.rs` returned no matches
> - `cargo outdated --workspace` and `cargo deny check advisories` both clean this
>   cycle (2026-08-24, 4th consecutive clean cycle) — no newer major version of
>   `tower-lsp-server` is available yet that bundles 3.18 types

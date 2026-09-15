---
aliases:
  - deps-cli tower-lsp-server Isolation
  - Protocol-Agnostic Diagnostics Domain Type
tags:
  - sdd
  - spec
  - deps-core
  - deps-cli
  - architecture
created: 2026-09-15
status: draft
related:
  - "[[constitution]]"
  - "[[../063-deps-core-domain-boundary-hardening/spec]]"
---

# Feature: deps-cli tower-lsp-server Isolation

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: feat/1083-deps-cli-lsp-isolation (to be created at implementation time)
> **Resolves**: #1083 (descoped from #1071 / spec 063)

## 1. Overview

### Problem Statement

Spec 063 (issue #1071, PR #1087) decoupled `deps_core::Dependency` /
`deps_core::lockfile::LockFileCache` / `ParseResult` from
`tower_lsp_server::ls_types` by introducing `deps_core::position::{Position,
Range}` and using `url::Url` for file identity. That removed one source of
`deps-cli`'s `tower-lsp-server` dependency, but not the whole thing — the
original FR-005/SC-001 goal ("`cargo tree -p deps-cli -e features,no-dev` does
not contain `tower-lsp-server`") was descoped mid-implementation and tracked
as this issue, for two independent reasons documented in spec 063's Out of
Scope section:

1. `deps-core::lsp_helpers` (`hover.rs`, `diagnostics.rs`, `code_actions.rs`,
   `code_lenses.rs`, `inlay_hints.rs`) directly constructs real
   `tower_lsp_server::ls_types::{Hover, Diagnostic, CodeAction, WorkspaceEdit,
   CodeLens, InlayHint}` response objects. `deps-core/src/lib.rs`'s "LSP type
   stability" doc section (issue #832) records this as a deliberate design
   choice — `deps-lsp` is documented as "the only crate expected to call
   them" — so `deps-core`'s `Cargo.toml` keeps `tower-lsp-server` as an
   unconditional, non-optional dependency.
2. `deps-cli` itself already directly imports and constructs
   `tower_lsp_server::ls_types::{Diagnostic, DiagnosticSeverity, Range, Uri,
   NumberOrString, CodeDescription}` in its own `report.rs`, `config.rs`,
   `exit.rs`, and `format/{mod,table,json,sarif}.rs` (shipped in PR
   #1072/#1078), and its `lib.rs` calls `deps_core::Ecosystem::
   generate_diagnostics` directly to reuse the exact same diagnostic-
   generation logic `deps-lsp` uses for its own diagnostics — which
   contradicts the "only `deps-lsp` calls them" claim in `lib.rs`'s doc
   comment above. `deps-cli`'s `check` subcommand's finding/reporting type
   is built directly on `ls_types::Diagnostic`.

Investigation for this spec found the reuse in point 2 goes deeper than the
issue's original text: `generate_diagnostics_from_cache`
(`crates/deps-core/src/lsp_helpers/diagnostics.rs`) is the single function
both `deps-lsp` (via `Ecosystem::generate_diagnostics`'s default method) and
`deps-cli` (via the same trait method, called from `deps-cli/src/lib.rs`) go
through to build diagnostics — including the three ecosystem-specific
overrides in `deps-npm`, `deps-github-actions`, and `deps-gitlab-ci`'s own
`generate_diagnostics`, which all call
`deps_core::lsp_helpers::generate_diagnostics_from_cache` and then append
their own ecosystem-specific `Diagnostic`s (deprecated-package / mutable-ref
findings) to the result. Simply feature-gating `lsp_helpers` out of
`deps-cli`'s dependency tree — as the issue's original "Suggested approach"
proposed — would force `deps-cli` to reimplement this diagnostic-generation
logic on its own, duplicating it instead of sharing it and violating this
project's constitution principle 1 ("one fix, one place").

The correct isolation boundary is therefore one level deeper than the issue
text: the diagnostic-generation *logic* (`generate_diagnostics_from_cache`
and the four call sites that use it) must produce a `deps-core` domain type
by default, with conversion to `tower_lsp_server::ls_types::Diagnostic`
happening only at `deps-lsp`'s adapter boundary (or behind a `deps-core`
feature flag deps-lsp alone enables) — the same shape of solution #1071
already applied to `Dependency`'s range data and `ParseResult`'s URI.
`hover.rs` / `code_actions.rs` / `code_lenses.rs` / `inlay_hints.rs` /
`generate_document_links` are **not** called by `deps-cli` at all (confirmed:
no `generate_hover`/`generate_code_actions`/`generate_code_lenses`/
`generate_inlay_hints`/`generate_document_links` reference exists anywhere
under `crates/deps-cli/src/` or `crates/deps-engine/src/`), so they do not
need the same domain-type treatment — they only need to stay compiled out
when `deps-cli`/`deps-engine` build `deps-core` without the feature that
still requires `tower-lsp-server`.

### Goal

`cargo tree -p deps-cli -e features,no-dev` no longer contains
`tower-lsp-server`, and `cargo tree -p deps-engine -e features,no-dev
--no-default-features --features cargo,npm,...<deps-cli's feature list>`
(the subset `deps-cli` actually activates) does not either, **without**
duplicating diagnostic-generation logic between `deps-lsp` and `deps-cli`,
and **without** changing `deps-cli`'s existing table/JSON/SARIF output
schema or content for any existing fixture.

### Out of Scope

- Feature-gating or otherwise changing `hover.rs`, `code_actions.rs`,
  `code_lenses.rs`, `inlay_hints.rs`, or `generate_document_links`'s *return
  types* — `deps-cli` never calls these, so they keep constructing real
  `ls_types` objects directly. They only need to compile conditionally (see
  FR-001) so the crate-level `tower-lsp-server` dependency can become
  optional; their public signatures and behavior are unaffected.
- Issue #851 (whether `deps-core`'s public API should stop naming
  third-party dependency types generally — `reqwest::Error`,
  `yaml_rust2::Yaml`, `semver::VersionReq`, ...) — this spec only resolves
  the `tower-lsp-server` / diagnostics subset for the reasons #1071 already
  scoped out.
- Any `deps-lsp`-visible wire-format or behavior change. Every existing
  `insta` snapshot fixture for hover/diagnostics/code actions/code
  lenses/inlay hints in `deps-lsp` and per-ecosystem crates must stay
  byte-identical.
- Changing `deps-cli`'s user-facing output (table/JSON/SARIF schema,
  column order, message text) — only the internal Rust type carrying the
  data changes; see FR-006.
- Publishing `deps-cli`/`deps-mcp` to crates.io, or making the `deps-mcp`
  (#710) decision — this spec only removes a blocker for that, as spec 063
  already noted for its own scope.
- Correcting every other place `deps-core/src/lib.rs`'s "LSP type stability"
  doc section's "deps-lsp is the only crate expected to call them" claim may
  now be stale beyond the diagnostics methods this spec touches (see Open
  Question below).

## 2. User Stories

### US-001: `deps-cli` does not link `tower-lsp-server`

AS A maintainer building `deps-cli` (#711) or the planned `deps-mcp` (#710)
I WANT `deps-core`'s diagnostic-generation path to carry no
`tower-lsp-server` type in its default (feature-independent) public API
SO THAT a non-LSP adapter can depend on `deps-core`/`deps-engine` and run
`check` without compiling or linking `tower-lsp-server`'s jsonrpc/`Client`/
notification machinery

**Acceptance criteria:**
```
GIVEN deps-cli's Cargo.toml depends on deps-core/deps-engine with default-features = false
WHEN `cargo tree -p deps-cli -e features,no-dev` is run
THEN tower-lsp-server does not appear in the dependency tree
```

### US-002: `deps-lsp`'s LSP-visible behavior is unchanged

AS A `deps-lsp` maintainer
I WANT every existing hover/diagnostic/code-action/code-lens/inlay-hint
response `deps-lsp` sends to an LSP client to stay byte-identical
SO THAT this refactor is invisible to editors and does not require
re-verifying end-to-end LSP behavior beyond the existing regression suite

**Acceptance criteria:**
```
GIVEN the full existing insta snapshot suite for lsp_helpers and per-ecosystem
  generate_diagnostics overrides (deps-npm, deps-github-actions, deps-gitlab-ci)
WHEN the diagnostic-generation path is changed to produce a domain type by
  default and convert to ls_types at deps-lsp's boundary
THEN every snapshot passes unchanged, with no `cargo insta accept` needed
```

### US-003: Ecosystem crate maintainers keep one diagnostic representation

AS A contributor adding a new ecosystem-specific diagnostic (mirroring the
existing `deps-npm`/`deps-github-actions`/`deps-gitlab-ci` overrides)
I WANT to construct exactly one diagnostic representation, shared by both
`deps-lsp` and `deps-cli`
SO THAT a bug fix or a new field only needs to be made in one place, per
constitution principle 1

**Acceptance criteria:**
```
GIVEN deps-npm/deps-github-actions/deps-gitlab-ci's generate_diagnostics
  overrides, which call generate_diagnostics_from_cache and append their own
  findings
WHEN this spec's change lands
THEN all four call sites (the default method + 3 overrides) construct the
  same deps-core domain type, with no ecosystem-crate-local duplicate of the
  ls_types-conversion logic
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `deps-core` is compiled with `default-features = false` (i.e. without the `lsp-responses` feature) THE SYSTEM SHALL NOT require `tower-lsp-server` to appear anywhere in the resulting dependency graph | must |
| FR-002 | WHEN `generate_diagnostics_from_cache` (or its renamed equivalent) runs THE SYSTEM SHALL produce a `deps-core`-local domain type as its return value, independent of whether the `lsp-responses` feature is enabled | must |
| FR-003 | WHEN `deps-lsp` needs an LSP-protocol `Diagnostic`/`DiagnosticRelatedInformation`/`CodeDescription` response THE SYSTEM SHALL convert the domain type into the matching `tower_lsp_server::ls_types` type at a single, named conversion boundary (not duplicated per call site) | must |
| FR-004 | WHEN `deps-npm`, `deps-github-actions`, or `deps-gitlab-ci` append ecosystem-specific findings after calling the shared diagnostics helper THE SYSTEM SHALL construct them using the same domain type as the shared helper's output, not a second parallel representation | must |
| FR-005 | WHEN `deps-cli`/`deps-engine` depend on `deps-core` with the `lsp-responses` feature disabled THE SYSTEM SHALL still be able to call the diagnostics-generation entry point (`Ecosystem::generate_diagnostics` or a renamed equivalent) to produce its `check` output | must |
| FR-006 | WHEN `deps-cli` formats table/JSON/SARIF output from the domain diagnostic type THE SYSTEM SHALL produce output identical to the current `ls_types::Diagnostic`-based output for every existing fixture (`crates/deps-cli`'s insta/jsonschema test fixtures) | must |
| FR-007 | WHEN CI runs THE SYSTEM SHALL have an automated guard (mirroring the existing `test-util` leak-guard step in `.github/workflows/ci.yml`) that fails if `tower-lsp-server` reappears in `cargo tree -p deps-cli -e features,no-dev` | must |
| FR-008 | WHEN `deps-lsp`'s own `Cargo.toml` enables the `lsp-responses` feature (directly or transitively via `deps-engine`) THE SYSTEM SHALL retain unchanged hover/completion/diagnostics/code-action/code-lens/inlay-hint behavior visible to an LSP client | must |
| FR-009 | WHEN `deps-core/src/lib.rs`'s "LSP type stability" doc section is read after this change THE SYSTEM SHALL accurately describe which methods still couple to `ls_types` and which now use the domain diagnostic type, replacing the now-inaccurate "deps-lsp is the only crate expected to call them" claim for the methods this spec touches | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Compatibility | Pre-1.0 clean break is acceptable per constitution principle 7 — no deprecation shim required for the domain-type rename, but the change must be documented as `Breaking` in `CHANGELOG.md` per constitution principle 8's changelog obligation (applies regardless of pre/post-1.0 status of the documentation requirement itself) |
| NFR-002 | Performance | Converting the domain type to `ls_types` at `deps-lsp`'s boundary must not add observable latency to the diagnostics request path (diagnostics generation is not on the hover-latency-critical path per `deps-lsp`'s non-blocking-surface principle, but should not regress existing benchmarks if any cover this path) |
| NFR-003 | API stability | The new domain diagnostic type's public fields follow the same `#[non_exhaustive]` + constructor convention already used by `deps_core::position::{Position, Range}` (see spec 063), for consistency |
| NFR-004 | Test coverage | Every existing `deps-lsp`/ecosystem-crate insta snapshot for diagnostics stays unchanged; new unit tests cover the domain-type ↔ `ls_types::Diagnostic` conversion directly |

## 5. Data Model

No storage/persistence entities — this is a Rust type-boundary change. Types
live in a new `deps_core::diagnostic` module (see §9 Resolved Design
Decisions), mirroring `deps_core::position`'s existing pattern:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `diagnostic::Diagnostic` | Protocol-agnostic replacement for `tower_lsp_server::ls_types::Diagnostic`, returned by `generate_diagnostics_from_cache` and the `Ecosystem::generate_diagnostics` default/overrides | range (`deps_core::position::Range`), severity, code, message, related information, optional code description URL |
| `diagnostic::Severity` | Protocol-agnostic replacement for `tower_lsp_server::ls_types::DiagnosticSeverity`, used by both `diagnostic::Diagnostic` and `DiagnosticSeverities`'s fields (currently typed directly as `ls_types::DiagnosticSeverity`, including in `deps-cli/src/config.rs`'s user-facing severity config) | Error / Warning / Information / Hint, `From`/`Into` conversion to/from `ls_types::DiagnosticSeverity` |
| `diagnostic::RelatedInformation` | Protocol-agnostic replacement for `ls_types::DiagnosticRelatedInformation`'s `Location` (currently `{ uri: ls_types::Uri, range: ls_types::Range }`) | `url::Url` (matching #1071's URI approach) + `deps_core::position::Range` + message |
| `diagnostic::CodeDescription` | Protocol-agnostic replacement for `ls_types::CodeDescription` (an advisory/rule URL, e.g. OSV pages) | `url::Url` href |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `deps-npm`/`deps-github-actions`/`deps-gitlab-ci` override appends a finding after the shared call | Appended finding uses the same domain type; conversion to `ls_types` happens once, after all appends, at `deps-lsp`'s boundary — not per append site |
| `deps-cli`'s `config.rs` lets a user configure severity thresholds via CLI flags/config file | Config parsing produces the domain severity type directly (or converts once at the config boundary), never requiring `deps-cli` to name `ls_types::DiagnosticSeverity` |
| A future ecosystem crate needs a diagnostic-only field `ls_types::Diagnostic` doesn't have an equivalent for (e.g. a new tag) | Extend the domain type first (per constitution principle 1), then extend the `ls_types` conversion — never add ecosystem-crate-local `ls_types` construction as a shortcut |
| `deps-lsp`'s `lsp-responses`-gated code path is accidentally reachable from `deps-cli`'s non-dev dependency tree | Caught by FR-007's CI guard, mirroring the existing `test-util` leak-guard pattern already in `.github/workflows/ci.yml` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `cargo tree -p deps-cli -e features,no-dev` contains `tower-lsp-server` | Absent |
| SC-002 | Existing `deps-lsp`/ecosystem-crate insta snapshots changed by this PR | 0 |
| SC-003 | Existing `deps-cli` table/JSON/SARIF fixture tests changed by this PR | 0 |
| SC-004 | Diagnostic-generation logic duplicated between `deps-lsp` and `deps-cli` after this change | 0 call sites (still exactly the 4 that exist today: default + 3 ecosystem overrides) |
| SC-005 | New CI guard step (FR-007) | Added and passing |

## 8. Agent Boundaries

### Always (without asking)
- Run the full check suite (`fmt`, `clippy --all-features`, `nextest --all-features`, rustdoc gate) before considering any task in the resulting plan/tasks done, per this project's `branching.md`
- Keep every existing insta snapshot byte-identical; if a snapshot would need to change, stop and flag it rather than `cargo insta accept`ing a behavior change
- Follow the existing `deps_core::position::{Position, Range}` pattern (`#[non_exhaustive]` + `new()`/`with_*` constructors, doc comments with runnable examples) for any new domain type

### Ask First
- Renaming or restructuring `Ecosystem::generate_diagnostics`'s public signature beyond what's needed for the domain-type return value
- Changing the `lsp-responses` feature's default-on/default-off status for `deps-core` itself (affects any external, non-workspace consumer building `deps-core` directly)
- Any change to `deps-cli`'s user-facing output schema (table/JSON/SARIF) — out of scope per FR-006/this spec's Out of Scope section

### Never
- Duplicate `generate_diagnostics_from_cache`'s logic in `deps-cli` or any ecosystem crate as a way to avoid the domain-type conversion
- Silently change diagnostic message text, severity defaults, or code values as a side effect of the type change

## 9. Resolved Design Decisions

These were raised as open questions during `specify` and resolved before
`/sdd plan`, based on existing conventions already established elsewhere in
this codebase:

- **Module/type naming**: a new `deps_core::diagnostic` module, mirroring
  `deps_core::position`'s existing symmetric-naming pattern (`position::Range`
  vs. `ls_types::Range`, same name, disambiguated by path). The domain type is
  `diagnostic::Diagnostic` (plus `diagnostic::Severity`,
  `diagnostic::RelatedInformation`, `diagnostic::CodeDescription`), not
  `Finding` — `deps-cli` already has an unrelated, higher-level
  `report::CheckFinding` (one per classified/aggregated issue, not 1:1 with a
  raw diagnostic), and reusing "Finding" for this lower-level type would
  collide conceptually across crates.
- **Feature default status**: `deps-core` gains `lsp-responses = ["dep:tower-lsp-server"]`
  and adds it to a new `default = ["lsp-responses"]` list (today `deps-core`
  has no `default` key — `test-util` is the only feature, opt-in), so any
  bare `cargo add deps-core` or existing `deps-core = { workspace = true }`
  declaration keeps today's behavior unchanged with zero edits.
  `deps-engine` — already following exactly this shape for its 14
  per-ecosystem features (`cargo = ["dep:deps-cargo"]`, deliberately no
  `default` list, each adapter forwards explicitly, per issue #1058's
  documented Cargo feature-unification-per-adapter finding) — adds its own
  `lsp-responses = ["deps-core/lsp-responses"]` and switches its own
  `deps-core` dependency to `default-features = false` (forwarding
  everything explicitly, consistent with its existing philosophy).
  `deps-lsp`'s Cargo.toml explicitly adds `features = ["lsp-responses"]` to
  its `deps-engine`/`deps-core` dependency declarations; `deps-cli`'s does
  not. This is the same enforcement shape already proven for the `test-util`
  leak guard (`cargo tree -p <crate> -e features,no-dev` correctly reports a
  crate's own feature-resolved dependency tree even inside a workspace).
- **FR-009 (doc-comment accuracy fix)**: in scope for this PR, not a
  follow-up — `/sdd plan`/`/sdd tasks` include a task updating
  `deps-core/src/lib.rs`'s "LSP type stability" section once the plan fixes
  the exact method list this change touches, since the section's current
  "deps-lsp is the only crate expected to call them" claim is what this spec
  directly disproves.

## 10. See Also

- [[constitution]] — project principles, especially principle 1 (one fix, one place) and principle 8 (breaking-change policy)
- [[../063-deps-core-domain-boundary-hardening/spec|Spec 063]] — the prior, related decoupling (`Dependency`/`ParseResult`/`position::{Position,Range}`) this spec continues and reuses
- [[MOC-specs]] — all specifications
- Issue #1083 (this spec's source), #1071 / spec 063 (where this was descoped from)
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` (`generate_diagnostics_from_cache`, ~17 `Diagnostic { .. }` construction sites)
- `crates/deps-core/src/ecosystem.rs` (`Ecosystem::generate_diagnostics` default method)
- `crates/deps-npm/src/ecosystem.rs`, `crates/deps-github-actions/src/ecosystem.rs`, `crates/deps-gitlab-ci/src/ecosystem.rs` (`generate_diagnostics` overrides)
- `crates/deps-cli/src/{lib.rs,report.rs,config.rs,exit.rs,format/{mod,table,json,sarif}.rs}` (existing direct `ls_types` usage)
- `crates/deps-core/src/lib.rs` ("LSP type stability" doc section, issue #832)
- `crates/deps-core/src/position.rs` — the `#[non_exhaustive]` + constructor pattern to mirror

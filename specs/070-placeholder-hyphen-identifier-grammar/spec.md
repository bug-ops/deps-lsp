---
aliases:
  - Placeholder $(VAR) Hyphen Identifier Grammar
  - $(MOD-VERSION) MSBuild Hyphenated Property Gap
tags:
  - sdd
  - spec
  - bug
  - security-adjacent
  - cross-ecosystem
  - lsp-diagnostics
  - lsp-code-actions
created: 2026-09-24
status: draft
related:
  - "[[constitution]]"
  - "[[069-template-placeholder-dollar-paren-guard/spec]]"
---

# Feature: Extend `$(VAR)` template-placeholder identifier grammar to accept hyphens (`$(MOD-VERSION)`)

> [!info] Metadata
> **Author**: continuous-improvement research cycle (ci-084)
> **Branch**: no branch yet — see issue #1421
> **Related upstream work**: spec [[069-template-placeholder-dollar-paren-guard/spec|069]] / issue
> #1417 / PR #1419 (merged, commit `8f876da48`) — the spec and PR this one directly follows up on;
> issue #1385 (prevalence-survey methodology this spec reuses); issue #1421 (tracking issue for this
> spec)

## 1. Overview

### Problem Statement

Spec [[069-template-placeholder-dollar-paren-guard/spec|069]] (issue #1417, PR #1419, merged as
commit `8f876da48`) extended
`deps_core::lsp_helpers::requirement_contains_template_placeholder`
(`crates/deps-core/src/lsp_helpers/mod.rs`, function starts at line 1762) to recognize
`$(IDENT)`-shaped Makefile/MSBuild-style placeholders, guarding `deps-cli update` and the LSP's
diagnostics/code-actions against silently rewriting an unresolved variable reference to a literal
resolved version. That spec's FR-001 deliberately restricted the identifier grammar inside `$(...)`
to `[a-zA-Z_][a-zA-Z0-9_]*` — the same strict grammar `template_placeholder_identifier_end`
(line 1626) already used for the `$VAR`/`${VAR}`/`%VAR%` forms.

During PR #1419's implementation, the developer explicitly flagged — and left an inline comment
documenting (lines 1768-1770 of `crates/deps-core/src/lsp_helpers/mod.rs`) — a known, deliberate
scope boundary: a hyphen or dot inside the identifier (`$(MOD-VERSION)`, `$(A.VERSION)`) does not
match `template_placeholder_identifier_end`'s strict grammar and is therefore **not** detected as a
placeholder — it is still silently rewritten to a resolved literal version. The PR body said a
follow-up issue would be filed separately if this gap needed closing. This spec is that follow-up:
this research cycle (ci-084) performed the prevalence research the PR deferred, live-verified the
bug still reproduces on current `main`, and — following the same per-candidate-form evidence
methodology issue #1385 used for `%{VAR}`/`#{VAR}` — assessed the hyphen and dot forms
independently rather than as one bundled gap.

**Prevalence research (per candidate form, mirroring #1385's methodology):**

- **Hyphen** (`$(MOD-VERSION)`): real, official-doc-backed evidence. Per Microsoft Learn's MSBuild
  name-value properties documentation
  (<https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-properties>), valid MSBuild
  property names begin with a letter or underscore and MAY contain hyphens in subsequent
  positions — hyphens are legal, native MSBuild property-name syntax, usable in
  `Directory.Packages.props`/`Directory.Build.props` centrally-managed version properties. GNU
  Make variable names also technically permit hyphens (any character except `:`, `#`, `=`, or
  whitespace, per the POSIX/GNU Make manual), though it is a discouraged convention there.
  **Verdict: extend** — real native MSBuild syntax, the same justification tier that motivated the
  original `$(VAR)` extension itself in spec 069.
- **Dot** (`$(A.VERSION)`): weak evidence. The same Microsoft Learn documentation states MSBuild
  property names do **not** allow periods in subsequent positions (only alphanumeric, underscore,
  and hyphen are permitted) — so `$(A.VERSION)` is not valid native MSBuild syntax at all. GNU
  Make's tolerance of dots in variable names is also unconventional and undocumented as a real,
  intentional pattern. **Verdict: reject / document as a residual gap**, the same disposition
  #1385 gave `%{VAR}`/`#{VAR}` — no real generator tool was found emitting this form as legitimate
  syntax (see [[#3-out-of-scope|Out of Scope]]).

This spec extends only the `$(...)` form's own identifier grammar. It does not touch
`${VAR}`/`{{ }}`/`{% %}`/`@VAR@`/`%VAR%`/`<%= %>`'s own grammars — none of those forms' real-world
identifier sources (shell/environment variable names, Windows env vars, Liquid/Jinja2/ERB template
expressions, autoconf/CMake `configure_file` tokens) legitimately contain hyphens the way MSBuild
property names do, so widening them is out of scope and unjustified by this cycle's research.

### Reproduction / Evidence {#evidence-reproduction}

Live-verified this cycle against `main` @ `8f876da48` (2026-09-24), via
`./target/debug/deps-cli update <manifest> --format json --dry-run`:

| Manifest | Requirement | Result | Outcome |
|---|---|---|---|
| `Cargo.toml` | `serde = "$(SERDE-VERSION)"` (hyphenated) | rewritten to `"1.0.229"` | `applied` — bug, should be skipped/unresolved |
| `Cargo.toml` | `serde = "$(SERDE.VERSION)"` (dotted) | rewritten to `"1.0.229"` | `applied` — same bug shape, weaker evidence bar for fixing (see prevalence research above) |

### Goal

`requirement_contains_template_placeholder`'s `$(...)`-branch classifies any `$(IDENT)`-shaped
substring whose identifier matches `[a-zA-Z_][a-zA-Z0-9_-]*` (i.e. the existing grammar plus `-` as
an allowed subsequent character) as an unresolved template placeholder — receiving the exact same
never-rewritten, never-flagged-outdated/unsatisfiable treatment the underlying identifier already
gets, across every ecosystem that inherits the shared default (Cargo, npm, PyPI, Deno, Go, Dart,
Maven, GitHub Actions), while NuGet's independent, pre-existing `is_msbuild_reference` guard
(`crates/deps-nuget/src/parser.rs:159`) — which already tolerates hyphens/dots via a plain
`s.contains("$(")` substring check with no identifier grammar at all — remains unaffected and
unregressed.

### Out of Scope

> [!danger] Explicitly excluded from this spec
> - **Dot in the `$(...)` identifier** (`$(A.VERSION)`) — per this cycle's prevalence research
>   above, not valid native MSBuild syntax and not a real, documented GNU Make convention either.
>   Documented as a residual, accepted gap, same disposition as #1385's `%{VAR}`/`#{VAR}` forms —
>   not fixed here. `dotted_identifier_end` (line 1648) already exists and already allows `.`/`-`
>   for the `@VAR@` form, but reusing it verbatim for `$(...)` would also silently admit the dot
>   case this spec rejects — see [[#4-functional-requirements|FR-002]] for why a new, narrower
>   grammar function is required instead of reusing `dotted_identifier_end`.
> - Any change to `${VAR}`/`$VAR`/`{{ }}`/`{% %}`/`@VAR@`/`%VAR%`/`<%= %>`'s own identifier
>   grammars — this spec only widens the `$(...)` branch.
> - Any change to NuGet's own `is_msbuild_reference` function or its independent code path — it
>   already tolerates hyphens and dots via its unconditional substring check and must remain
>   untouched, only re-verified via a regression test (see [[#4-functional-requirements|FR-005]]).
> - Any change to the both-delimiters-required rule for `$(...)` established by spec 069 (an
>   unclosed `$(` is still not treated as a placeholder) — this spec only widens which characters
>   are legal *inside* the delimiters, not the closing-paren requirement itself.

## 2. User Stories

### US-001: .NET / cross-tooling manifest author using a hyphenated MSBuild property name

AS A developer whose `Directory.Packages.props`-style centrally-managed version property (or a
hand-rolled Makefile variable) uses a hyphen in its name (`$(MOD-VERSION)`, `$(SERDE-VERSION)`)
before that manifest reaches an ecosystem other than NuGet (e.g. it is copy-templated into a
`Cargo.toml`, `package.json`, or `go.mod` by shared build tooling)
I WANT `deps-lsp`/`deps-cli update` to recognize the un-expanded, hyphenated `$(...)` placeholder
SO THAT my checked-in template is never silently, destructively overwritten with a resolved literal
version, and never misreported as outdated/unsatisfiable

**Acceptance criteria:**
```
GIVEN a Cargo.toml dependency requirement of `$(SERDE-VERSION)`
WHEN deps-cli update (or the LSP diagnostics/code-actions/hover path) evaluates that requirement
THEN the requirement is classified as an unresolved placeholder and is neither rewritten to a
     literal version nor flagged as outdated or unsatisfiable
```

### US-002: Residual dot-form gap remains documented, not silently forgotten

AS A maintainer triaging future template-placeholder reports
I WANT the dot-identifier gap (`$(A.VERSION)`) to be explicitly recorded as an accepted, researched
residual gap rather than rediscovered from scratch
SO THAT future reports of `$(A.VERSION)` being rewritten are recognized as already-triaged and
intentionally out of scope, not treated as a new, unresearched bug

**Acceptance criteria:**
```
GIVEN this spec is implemented and shipped
WHEN a future contributor searches for "$(A.VERSION)" or "dotted $(...) placeholder"
THEN this spec's Out of Scope section and evidence are discoverable as the disposition record,
     consistent with how issue #1385 documents %{VAR}/#{VAR}'s disposition
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `requirement_contains_template_placeholder`'s `$(...)`-branch is evaluated against a string containing a `$(IDENT)`-shaped substring where `IDENT` matches `[a-zA-Z_][a-zA-Z0-9_-]*` (i.e. letters/digits/underscore, plus `-` as an allowed subsequent — never leading — character), immediately followed by a closing `)`, THE SYSTEM SHALL return `true` for that requirement | must |
| FR-002 | WHEN the substring after `$(` contains a `.` anywhere before the next `)` (e.g. `$(A.VERSION)`, `$(MOD.SUB-VERSION)`), THE SYSTEM SHALL NOT treat that occurrence as a `$(...)`-shaped placeholder match on this basis alone — the new grammar function introduced for this branch must diverge from `dotted_identifier_end` (which already permits `.`) rather than reuse it verbatim, since reuse would silently admit the dot case this spec's research rejected | must |
| FR-003 | WHEN a requirement contains `$(IDENT)` (hyphenated or plain) embedded anywhere within a larger string, not only as the whole value, THE SYSTEM SHALL still detect it, consistent with the existing embedded-detection behavior spec 069 already established (e.g. `"1.0.0-$(BUILD-SUFFIX)"` must be detected) | must |
| FR-004 | WHEN the widened `$(...)` grammar is exercised via each affected ecosystem's `unresolved_requirement_conformance!` macro (Cargo, npm, PyPI, Deno, Go, Dart, Maven, GitHub Actions), THE SYSTEM SHALL classify a `$(MOD-VERSION)`-shaped (hyphenated) requirement fixture as an unresolved placeholder in every one of those ecosystems | must |
| FR-005 | WHEN NuGet's own, independent `is_msbuild_reference` function (`crates/deps-nuget/src/parser.rs:159`) evaluates a `.csproj`/`.fsproj`/`.vbproj`/`Directory.Packages.props` requirement containing `$(MOD-VERSION)` or `$(A.VERSION)`, THE SYSTEM SHALL continue to skip that requirement exactly as before this change (NuGet's plain substring check already tolerates both forms, unaffected by this spec) | must |
| FR-006 | WHEN a requirement contains a `$(...)` substring whose bracketed content is empty, starts with a digit, starts with a hyphen, or is not immediately followed by a closing `)`, THE SYSTEM SHALL NOT classify it as a placeholder on that basis alone, preserving all of spec 069's existing edge-case exclusions (`$()`, `$(123)`, `$(-x)`, unclosed `$(SERDE_VERSION`) unchanged by this widened grammar | must |

### Detection grammar decision

The new `$(...)`-branch grammar is `[a-zA-Z_][a-zA-Z0-9_-]*` — `template_placeholder_identifier_end`
(line 1626) widened by exactly one allowed subsequent character (`-`), applied only inside the
`$(...)` branch of `requirement_contains_template_placeholder`. This is deliberately narrower than
`dotted_identifier_end` (line 1648, already allows both `.` and `-` for the `@VAR@` form): reusing
`dotted_identifier_end` verbatim would also silently admit the dot form this spec's prevalence
research explicitly rejected (FR-002). The cleanest implementation is therefore a new, dedicated
helper (or an inline hyphen-only variant) rather than a call-site reuse of either existing
identifier-end helper — see [[#8-agent-boundaries|Agent Boundaries]].

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The widened grammar must reuse the existing byte-scan structure (no additional heap allocation, no ecosystem-specific configuration parsing) — pure in-memory string scanning on the same hot path as before, consistent with spec 069's NFR-001 |
| NFR-002 | Correctness | Zero regression in the existing `test_requirement_contains_template_placeholder_*` unit test suite (`crates/deps-core/src/lsp_helpers/mod.rs`) — every existing assertion, including the doctest's `$(five` unclosed-form and `$(LODASH_VERSION)` plain-form cases, must continue to hold unchanged |
| NFR-003 | Consistency | Cross-ecosystem consistency is a first-class rule for this project (`.claude/rules/continuous-improvement.md`): the fix must land once in `deps-core` and be inherited by all affected ecosystems via the shared default, not reimplemented per-crate |
| NFR-004 | Testability | Every ecosystem crate whose formatter inherits the shared default (Cargo, npm, PyPI, Deno, Go, Dart, Maven) plus GitHub Actions (which ORs the shared default with its own check) must gain a hyphenated `$(MOD-VERSION)` conformance fixture in its existing `unresolved_requirement_conformance!` invocation, alongside spec 069's existing plain-identifier fixture |

## 5. Data Model

No new persistent data model — this is a narrow widening of an existing pure-function predicate's
internal character grammar. No new types are introduced; `RequirementStatus`
(`crates/deps-core/src/lsp_helpers/mod.rs`, around line 1800) is unaffected — a `$(MOD-VERSION)`-shaped
requirement continues to resolve to `RequirementStatus::Unresolved` via the same existing predicate
call site spec 069 already wired up, not a new variant.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `requirement_contains_template_placeholder` | Shared pure-function predicate over a requirement string; this spec widens only its `$(...)`-branch grammar | Input: `requirement: &str`; Output: `bool` |
| `is_msbuild_reference` (NuGet, unaffected) | NuGet's own independent predicate, out of scope for edits, already tolerant of hyphens/dots | Input: `s: &str`; Output: `bool` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `$(MOD-VERSION)` (hyphenated, well-formed) | Detected as placeholder (FR-001) |
| `"1.0.0-$(BUILD-SUFFIX)"` (hyphenated, embedded in a larger string) | Detected as placeholder (FR-003) |
| `$(A.VERSION)` (dotted) | NOT detected — residual, researched, accepted gap (FR-002, Out of Scope) |
| `$(MOD.SUB-VERSION)` (mixed dot + hyphen) | NOT detected — any `.` before the closing `)` disqualifies the match (FR-002) |
| `$(-VERSION)` (leading hyphen) | NOT detected — hyphen is only a valid subsequent character, never the leading one, consistent with spec 069's `$(123)`/`$(-x)` carve-outs (FR-006) |
| `$()` / `$(123)` / unclosed `$(SERDE_VERSION` | NOT detected — unchanged from spec 069 (FR-006) |
| `.csproj` `Version="$(Mod-VersionProp)"` or `Version="$(A.VersionProp)"` | Skipped via NuGet's own independent `is_msbuild_reference`, unaffected by this spec either way (FR-005) |
| Requirement containing both a widened `$(MOD-VERSION)` form and an already-supported form (e.g. `${OTHER}$(MOD-VERSION)`) | Detected as placeholder via short-circuit OR, same as any other multi-form combination |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `unresolved_requirement_conformance!` fixtures updated with a `$(MOD-VERSION)` hyphenated case | 8/8 affected ecosystems (Cargo, npm, PyPI, Deno, Go, Dart, Maven, GitHub Actions) pass |
| SC-002 | Existing `requirement_contains_template_placeholder` unit test suite | 100% pass, zero regressions |
| SC-003 | New unit test confirming `$(A.VERSION)` (dotted) remains NOT detected, documenting the accepted residual gap | Added and passing |
| SC-004 | New NuGet regression test confirming `is_msbuild_reference` still handles both hyphenated and dotted `$(...)` forms unaffected | Added and passing |
| SC-005 | Live re-verification of the `Cargo.toml` hyphenated-requirement manifest from the Evidence table, via `deps-cli update <manifest> --format json` | Reports the dependency as skipped/unresolved, not `applied` |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo nextest run --workspace --all-features --no-fail-fast` after implementation, per `.claude/rules/branching.md`
- Add a dedicated, narrower identifier-end helper (or an inline hyphen-only check) for the `$(...)` branch rather than reusing `dotted_identifier_end` verbatim — reuse would silently regress FR-002's dot exclusion
- Update the doc comment (`///`) on `requirement_contains_template_placeholder`, including its `# Examples` doctest block, to cover the new hyphenated `$(MOD-VERSION)` case and to explicitly assert the dotted `$(A.VERSION)` case remains `false`
- Remove or update the now-superseded inline comment at lines 1768-1770 (`crates/deps-core/src/lsp_helpers/mod.rs`) that currently documents the hyphen/dot gap as unfixed — it should instead note only the dot form remains a deliberate exclusion
- Add/extend `unresolved_requirement_conformance!` fixtures for every affected ecosystem crate with a hyphenated case

### Ask First
- Any change to the `RequirementStatus` enum or its variants
- Any change to NuGet's `is_msbuild_reference` function itself (only a regression test should be added there, not a logic change)
- Reconsidering the dot-form exclusion later (e.g. if future prevalence research finds real dot-using tooling) — that would need its own spec, not a silent scope creep of this one

### Never
- Widen `${VAR}`/`{{ }}`/`{% %}`/`@VAR@`/`%VAR%`/`<%= %>`'s own identifier grammars as part of this change — out of scope per this spec
- Admit the dot form (`$(A.VERSION)`) as a side effect of implementing the hyphen widening (e.g. by reusing `dotted_identifier_end` without adjustment) — this is the primary implementation pitfall this spec's Detection grammar decision section exists to prevent
- Regress NuGet's existing independent `$(...)`/`%(...)`/`@(...)` handling
- Weaken spec 069's both-delimiters-required rule for `$(...)` (this spec only widens allowed characters between the delimiters, not the closing-paren requirement)

## 9. Open Questions

None — this is a small, narrowly-scoped grammar extension to an already-shipped predicate (spec
069, now shipped as PR #1419), with live-verified reproduction evidence and a research-backed
per-form disposition (hyphen: extend; dot: reject as residual gap) completed in this research
cycle. Per this spec's own scoping note, `plan`/`tasks` phases are not required; implementation can
proceed directly from this spec via `/rust-team` once linked to a tracking issue.

## 10. See Also

- [[069-template-placeholder-dollar-paren-guard/spec]] — the spec this one directly follows up on;
  introduced the `$(...)` branch this spec widens
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-core/src/lsp_helpers/mod.rs` — `requirement_contains_template_placeholder` (line
  1762), `template_placeholder_identifier_end` (line 1626, strict grammar to widen with `-`),
  `dotted_identifier_end` (line 1648, existing `.`/`-` grammar — NOT to be reused verbatim, see
  FR-002)
- `crates/deps-nuget/src/parser.rs:159` — `is_msbuild_reference` (independent NuGet guard, out of
  scope for edits, in scope for a regression test covering both hyphenated and dotted forms)
- `crates/deps-core/src/conformance.rs` — `unresolved_requirement_conformance!` macro definition
- Issue #1417 / PR #1419 (commit `8f876da48`) — spec 069's implementation, source of the
  known-scope-boundary comment this spec resolves for the hyphen case
- Issue #1385 — prevalence-survey methodology this spec reuses per-candidate-form

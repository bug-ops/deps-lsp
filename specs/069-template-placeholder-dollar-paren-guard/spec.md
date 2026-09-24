---
aliases:
  - Template Placeholder $(VAR) Guard
  - Makefile/MSBuild-Style Placeholder Detection Gap
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
---

# Feature: Extend `requirement_contains_template_placeholder` to recognize `$(VAR)` (Makefile/MSBuild-style) placeholders

> [!info] Metadata
> **Author**: continuous-improvement live-testing cycle
> **Branch**: no branch yet — see issue #1417
> **Related upstream work**: issue #1374 (original predicate), PR #1383 / issue #1379
> (generalized delimiter forms), issue #1385 (prevalence survey that produced this spec),
> issue #1417 (tracking issue for this spec)

## 1. Overview

### Problem Statement

`deps_core::lsp_helpers::requirement_contains_template_placeholder`
(`crates/deps-core/src/lsp_helpers/mod.rs`, function starts at line 1740) is the shared,
cross-ecosystem predicate that guards `deps-cli update` and the LSP's diagnostics/code-actions
against destructively rewriting a dependency requirement that actually contains an unresolved
external-templating placeholder — `envsubst`/CI-templating/`cookiecutter`-style generator output
such as `${VAR}`, `$VAR`, `{{ VAR }}`, `{% ... %}`, `@VAR@`, `%VAR%`, `<%= VAR %>`.

This predicate is the **default** `requirement_is_placeholder` implementation directly inherited
(with no override) by the Cargo, npm, PyPI, Deno, Go, Dart, and Maven ecosystem formatters, and it
is `||`-combined with GitHub Actions' own additional check in
`crates/deps-github-actions/src/formatter.rs`. It is exercised per-ecosystem in each crate's
`deps_core::unresolved_requirement_conformance!` macro invocation (e.g.
`crates/deps-cargo/src/ecosystem.rs:394`, `crates/deps-npm/src/ecosystem.rs:451`,
`crates/deps-pypi/src/ecosystem.rs:694`, `crates/deps-deno/src/ecosystem.rs:337`,
`crates/deps-go/src/ecosystem.rs:341`, `crates/deps-dart/src/ecosystem.rs:243`,
`crates/deps-maven/src/ecosystem.rs:916`, `crates/deps-github-actions/src/ecosystem.rs:1317`).

Issue #1385 requested a prevalence survey of three additional, less-common external-templating
forms deliberately left out of #1383's scope: `$(VAR)` (Makefile-style/shell command/variable
substitution), `%{VAR}` (RPM spec macro), and `#{VAR}` (Ruby-interpolation-adjacent, distinct from
the Bundler-specific forms issue #1367 already guards independently). Research for #1385 concluded
that only `$(VAR)` clears the evidence bar for extending the shared predicate — real-world
prevalence and an unambiguous grammar. `%{VAR}` and `#{VAR}` are being documented as a residual,
accepted, out-of-scope gap on #1385 and are explicitly **not** addressed by this spec (see
[[#3-out-of-scope|Out of Scope]]).

`$(VAR)` matters for two independent, converging reasons:

1. **MSBuild Central Package Management**: `$(VAR)` is the native MSBuild variable-reference
   syntax used by Microsoft's own Central Package Management feature
   (`Directory.Build.props`/`Directory.Packages.props`) for centrally-defined `.csproj` package
   versions — a very common real-world .NET convention
   (<https://learn.microsoft.com/en-us/nuget/consume-packages/central-package-management>).
   `crates/deps-nuget/src/parser.rs`'s `is_msbuild_reference` (line 159:
   `s.contains("$(") || s.contains("%(") || s.contains("@(")`) already guards this natively and
   independently for NuGet — **live-verified NuGet is NOT part of this gap** (see
   [[#evidence-reproduction|Evidence]]). The gap is specifically in the ~8 other ecosystems that
   inherit the shared default and have no native `$(...)` handling of their own.
2. **GNU Make variable references**: `$(VAR)` is also classic Makefile variable-reference syntax
   — the same shell-substitution family that originally motivated this predicate (issue #1374:
   `envsubst`, CI templating, `cookiecutter`-style generators). Makefile-orchestrated codegen is
   common tooling around all 14 supported ecosystems (e.g. `cargo-make`'s `Makefile.toml`, Go's
   `go-makefile-maker`), making a stray, unexpanded `$(VAR)` in a checked-in manifest a realistic
   accident produced by such tooling.

**Collision risk assessment**: none of the 14 supported ecosystems use `$(VAR)` as legitimate
syntax inside a dependency-*version* slot other than NuGet/MSBuild, which is already independently
guarded and unaffected by this change. Cargo semver, npm semver, Go module versions, GitLab/GitHub
Actions variable syntax (`$VAR`/`${VAR}`/`${{ }}`, already covered by the existing `$`-form check),
Gradle Kotlin/Groovy interpolation (`${expr}`/`$expr`), and Swift string interpolation (`\(expr)`)
have no legitimate `$(...)` form that could be mistaken for a real version requirement.

### Goal

`requirement_contains_template_placeholder` classifies any requirement containing a `$(IDENT)`
shaped substring as an unresolved template placeholder — receiving the exact same treatment as the
existing `$VAR`/`${VAR}`/`@VAR@`/`%VAR%`/`{{ }}`/`{% %}`/`<%= %>` forms: never rewritten to a
literal resolved version by `deps-cli update`, never flagged as outdated/unsatisfiable by
diagnostics or code actions — across every ecosystem that inherits the shared default (Cargo, npm,
PyPI, Deno, Go, Dart, Maven, GitHub Actions), while NuGet's independent, pre-existing
`is_msbuild_reference` guard continues to handle `$(...)`/`%(...)`/`@(...)` for `.csproj`/
`.fsproj`/`.vbproj`/`Directory.Packages.props` unchanged and unregressed.

### Out of Scope

> [!danger] Explicitly excluded from this spec
> - **`%{VAR}` (RPM spec macro syntax)** — per #1385's research decision, prevalence does not
>   clear the bar for extending the shared predicate. Documented as a residual gap on #1385, not
>   fixed here.
> - **`#{VAR}` (Ruby-interpolation-adjacent syntax outside Bundler-specific forms)** — same
>   disposition as `%{VAR}`; issue #1367 already covers Bundler-specific interpolation forms
>   separately, and this spec does not extend that further.
> - Any change to NuGet's own `is_msbuild_reference` function or its independent code path — it
>   already handles `$(...)` correctly and must remain untouched, only re-verified via a
>   regression test (see [[#4-functional-requirements|FR-004]]).
> - Any change to the `%VAR%`/`@VAR@` delimited-form helpers, or to the bracketed `{{ }}`/`{% %}`/
>   `<%= %>` forms — this spec adds a new `$(...)`-shaped branch, it does not modify existing
>   branches.

## 2. User Stories

### US-001: Manifest author using Makefile-orchestrated codegen

AS A developer whose build pipeline uses a `Makefile`/`Makefile.toml` (`cargo-make`,
`go-makefile-maker`, or a hand-rolled `Makefile`) to template dependency versions with `$(VAR)`
before a manifest is checked in or resolved
I WANT `deps-lsp`/`deps-cli update` to recognize an un-expanded `$(VAR)` left in a `Cargo.toml`,
`package.json`, `requirements.txt`/`pyproject.toml`, `go.mod`, `pubspec.yaml`, `pom.xml`, or GitHub
Actions workflow as a template placeholder
SO THAT my checked-in template is never silently, destructively overwritten with a resolved literal
version, and never misreported as outdated/unsatisfiable

**Acceptance criteria:**
```
GIVEN a Cargo.toml dependency requirement of `$(SERDE_VERSION)`
WHEN deps-cli update (or the LSP diagnostics/code-actions/hover path) evaluates that requirement
THEN the requirement is classified as an unresolved placeholder and is neither rewritten to a
     literal version nor flagged as outdated or unsatisfiable
```

### US-002: .NET developer relying on Central Package Management

AS A .NET developer using MSBuild Central Package Management (`Directory.Packages.props` +
`$(SomePackageVersion)` references in `.csproj`)
I WANT the existing, independent NuGet guard to keep working exactly as before
SO THAT this spec's cross-ecosystem fix introduces zero behavior change for NuGet manifests

**Acceptance criteria:**
```
GIVEN a .csproj PackageReference with Version="$(NewtonsoftJsonVersion)"
WHEN deps-cli update evaluates that requirement, both before and after this change
THEN the requirement is skipped (unchanged) in both cases, via NuGet's own is_msbuild_reference
     check, independent of the shared requirement_contains_template_placeholder predicate
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `requirement_contains_template_placeholder` is evaluated against a string containing a `$(IDENT)`-shaped substring (`$(` immediately followed by an identifier matching the existing `[a-zA-Z_][a-zA-Z0-9_]*` grammar used by `template_placeholder_identifier_end`, immediately followed by a closing `)`) THE SYSTEM SHALL return `true` for that requirement | must |
| FR-002 | WHEN the substring after `$(` does not form a valid identifier (e.g. `$()`, `$(123)`, `$(-x)`) OR the identifier is not immediately followed by a closing `)` (e.g. an unclosed `$(SERDE_VERSION` with no `)` anywhere later, or `$(SERDE VERSION)` with an embedded space breaking the identifier) THE SYSTEM SHALL NOT treat that substring alone as a `$(...)`-shaped placeholder match | must |
| FR-003 | WHEN a requirement contains `$(IDENT)` embedded anywhere within a larger string (not only as the whole value), THE SYSTEM SHALL still detect it, consistent with the existing embedded-detection behavior for `$VAR`/`${VAR}` (e.g. `"1.0.0-$(BUILD_SUFFIX)"` must be detected) | must |
| FR-004 | WHEN the extended predicate is exercised via each affected ecosystem's `unresolved_requirement_conformance!` macro (Cargo, npm, PyPI, Deno, Go, Dart, Maven, GitHub Actions), THE SYSTEM SHALL classify a `$(VAR)`-shaped requirement fixture as an unresolved placeholder in every one of those ecosystems | must |
| FR-005 | WHEN NuGet's own, independent `is_msbuild_reference` function (`crates/deps-nuget/src/parser.rs:159`) evaluates a `.csproj`/`.fsproj`/`.vbproj`/`Directory.Packages.props` requirement containing `$(VAR)`, THE SYSTEM SHALL continue to skip that requirement exactly as before this change, unaffected by the shared predicate's extension (NuGet does not call the shared `requirement_contains_template_placeholder` for this case; both code paths must independently agree the requirement is unresolved) | must |
| FR-006 | WHEN a requirement contains only a bare, unmatched `$(` with no valid identifier/closing-paren pairing anywhere in the string (e.g. `"price-is-$(five"`, a literal shell-unrelated use of `$(` in prose), THE SYSTEM SHALL NOT classify it as a placeholder on that basis alone, preserving the existing false-positive-avoidance behavior of the analogous `@VAR@`/`%VAR%` both-delimiters-required forms | must |

### Detection grammar decision (documented in-line per the finding's suggested remediation)

Unlike the `$VAR`/`${VAR` fail-open precedent (an *unclosed* `${VAR` is still treated as a
placeholder), `$(` requires the closing `)` — mirroring the `@VAR@`/`%VAR%` both-delimiters-required
rule, not the `${`/`{{`/`{%`/`<%` fail-open rule. Rationale: an unclosed `$(` is far more likely to
be a real, unrelated `$` character immediately followed by literal `(text...` (parenthetical prose,
shell command-substitution snippets pasted into a comment/description field) than an actual
unterminated Makefile reference — differing from `${VAR` (unclosed), where `${` alone is already a
strong, low-false-positive signal of intentional variable-expansion syntax.

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The added `$(...)` check must reuse the existing byte-scan structure (a single additional `O(n)` pass or an extension of the existing dollar-form scan) — no additional heap allocation or ecosystem-specific configuration parsing on the hover/completion/diagnostics hot path (per `crates/deps-lsp` handlers-must-stay-non-blocking constraint; this is pure in-memory string scanning, not I/O, so no async change is needed) |
| NFR-002 | Correctness | Zero regression in the existing `test_requirement_contains_template_placeholder_*` unit test suite (`crates/deps-core/src/lsp_helpers/mod.rs`, tests starting at line 3528) — all existing assertions must continue to hold unchanged |
| NFR-003 | Consistency | Cross-ecosystem consistency is a first-class rule for this project (`.claude/rules/continuous-improvement.md`): the fix must land once in `deps-core` and be inherited by all affected ecosystems via the shared default, not reimplemented per-crate |
| NFR-004 | Testability | Every ecosystem crate whose formatter inherits the shared default (Cargo, npm, PyPI, Deno, Go, Dart, Maven) plus GitHub Actions (which OR's the shared default with its own check) must gain a `$(VAR)` conformance fixture in its existing `unresolved_requirement_conformance!` invocation |

## 5. Data Model

No new persistent data model — this is a pure predicate-logic extension over an existing `&str`
input/`bool` output function. No new types are introduced; the existing `RequirementStatus` enum
(`crates/deps-core/src/lsp_helpers/mod.rs`, around line 1773) is unaffected — a `$(VAR)`-shaped
requirement continues to resolve to `RequirementStatus::Unresolved` via the existing predicate
call site, not a new variant.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `requirement_contains_template_placeholder` | Shared pure-function predicate over a requirement string | Input: `requirement: &str`; Output: `bool` |
| `is_msbuild_reference` (NuGet, unaffected) | NuGet's own independent predicate, out of scope for edits | Input: `s: &str`; Output: `bool` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `$(SERDE_VERSION)` (well-formed, standalone) | Detected as placeholder (FR-001) |
| `"1.0.0-$(BUILD_SUFFIX)"` (embedded in a larger string) | Detected as placeholder (FR-003) |
| `$(SERDE_VERSION` (unclosed, no `)` anywhere) | NOT detected on this basis alone (FR-002/FR-006 — closing paren required, unlike `${VAR`) |
| `$()` (empty parens) | NOT detected — no valid identifier between the delimiters, consistent with the existing `${}`/`empty-${}` carve-out for the `${VAR}` form |
| `$(123)` (identifier starting with a digit) | NOT detected — fails the `[a-zA-Z_][a-zA-Z0-9_]*` identifier grammar, consistent with the existing `${123}` carve-out |
| `$(SERDE VERSION)` (embedded space breaks the identifier) | NOT detected as a `$(...)` match — the identifier scan stops at the space and no `)` immediately follows the identifier end |
| `price-is-$(five` (unrelated literal `$(` in prose) | NOT detected — preserves existing false-positive avoidance (analogous to the existing `price-is-$5` carve-out for the bare `$` form) |
| `.csproj` `Version="$(NewtonsoftJsonVersion)"` | Skipped via NuGet's own independent `is_msbuild_reference`, unchanged by this spec (FR-005) |
| Requirement containing both a `$(VAR)` form and an already-supported form (e.g. `${OTHER}$(VAR)`) | Detected as placeholder via short-circuit OR, same as any other multi-form combination today |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `unresolved_requirement_conformance!` fixtures updated with a `$(VAR)` case | 8/8 affected ecosystems (Cargo, npm, PyPI, Deno, Go, Dart, Maven, GitHub Actions) pass |
| SC-002 | Existing `requirement_contains_template_placeholder` unit test suite | 100% pass, zero regressions |
| SC-003 | New NuGet regression test confirming `is_msbuild_reference` is unaffected/still independently exercised | Added and passing |
| SC-004 | Live re-verification of the three previously-broken manifests from the Evidence table (package.json, Cargo.toml, go.mod) with `$(VAR)`-style requirements, via `deps-cli update <manifest> --format json` | All three report the dependency as skipped/unresolved, not `applied` |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo nextest run --workspace --all-features --no-fail-fast` after implementation, per `.claude/rules/branching.md`
- Follow the existing code pattern of `template_placeholder_identifier_end` / `contains_delimited_identifier_placeholder` when adding the `$(...)` check, reusing shared helpers rather than duplicating identifier-scanning logic
- Update the doc comment (`///`) on `requirement_contains_template_placeholder`, including its `# Examples` doctest block, to cover the new `$(VAR)` form (per this project's mandatory public-API-doc rule)
- Add/extend `unresolved_requirement_conformance!` fixtures for every affected ecosystem crate

### Ask First
- Any change to the `RequirementStatus` enum or its variants
- Any change to NuGet's `is_msbuild_reference` function itself (only a regression test should be added there, not a logic change)

### Never
- Modify the `%{VAR}`/`#{VAR}` handling (out of scope per this spec — leave for #1385's documented residual-gap disposition)
- Regress NuGet's existing independent `$(...)`/`%(...)`/`@(...)` handling
- Weaken the both-delimiters-required rule for `$(...)` to a fail-open unclosed-`$(`-only match (explicitly rejected per the FR-006/detection-grammar-decision rationale above)

## 9. Open Questions

None — this is a small, well-scoped, already-diagnosed bug fix (a one-more-delimiter-form
extension to an existing, well-understood predicate) with live-verified reproduction evidence and a
research-backed scope decision (#1385) for what is explicitly excluded. Per this spec's own
scoping note, `plan`/`tasks` phases are not required; implementation can proceed directly from this
spec via `/rust-team` once linked to a tracking issue.

## Evidence: Reproduction {#evidence-reproduction}

Live-verified against `main` @ `071eea2a3` (2026-09-24), via `deps-cli update <manifest> --format json`:

| Manifest | Before | After | Outcome |
|---|---|---|---|
| `package.json` | `"lodash": "$(LODASH_VERSION)"` | `"4.18.1"` | `applied` (bug — should be skipped) |
| `Cargo.toml` | `serde = "$(SERDE_VERSION)"` | `"1.0.229"` | `applied` (bug — should be skipped) |
| `go.mod` | `require golang.org/x/net $(NET_VERSION)` | `require golang.org/x/net v0.59.0` | `applied` (bug — should be skipped) |
| `.csproj` (control) | `Version="$(NewtonsoftJsonVersion)"` | unchanged | correctly skipped — NuGet's independent `is_msbuild_reference` guard already handles this; must not regress |

PyPI, Deno, Dart, Maven, and GitHub Actions were not individually re-tested in this cycle but share
the identical code path (`requirement_contains_template_placeholder` as the inherited/OR'd default)
and are expected to be equally affected until this spec is implemented.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-core/src/lsp_helpers/mod.rs` — `requirement_contains_template_placeholder` (line
  1740) and its supporting helpers (`template_placeholder_identifier_end`,
  `dotted_identifier_end`, `contains_delimited_identifier_placeholder`,
  `contains_bracketed_placeholder`)
- `crates/deps-nuget/src/parser.rs:159` — `is_msbuild_reference` (independent NuGet guard, out of
  scope for edits, in scope for a regression test)
- `crates/deps-core/src/conformance.rs:1166` — `unresolved_requirement_conformance!` macro
  definition
- Issue #1374 — original predicate motivation (`envsubst`, CI templating, `cookiecutter`)
- Issue #1379 / PR #1383 — generalized delimiter forms (`{{ }}`, `{% %}`, `@VAR@`, `%VAR%`,
  `<%= %>`)
- Issue #1385 — prevalence survey that scoped this spec's `$(VAR)` extension in and `%{VAR}`/
  `#{VAR}` out
- Issue #1367 — Bundler-specific Ruby-interpolation forms (separate, unaffected by this spec)

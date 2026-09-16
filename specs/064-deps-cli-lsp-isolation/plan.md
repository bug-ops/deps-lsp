---
aliases:
  - deps-cli tower-lsp-server Isolation Plan
tags:
  - sdd
  - plan
  - deps-core
  - deps-cli
  - architecture
created: 2026-09-15
status: draft
related:
  - "[[spec]]"
  - "[[constitution]]"
  - "[[../063-deps-core-domain-boundary-hardening/plan]]"
---

# Technical Plan: deps-cli tower-lsp-server Isolation

> [!info] References
> **Spec**: [[spec]]

## 1. Architecture

### Approach

Two independent parts, landed as one PR (unlike spec 063's two-PR split —
here both parts are small enough, and part 2 cannot be tested end-to-end
without part 1, so splitting would leave an intermediate state that doesn't
build for `deps-cli`):

- **Part A — protocol-agnostic diagnostic domain type.** New
  `deps_core::diagnostic::{Diagnostic, Severity, RelatedInformation,
  CodeDescription}` module (field-for-field mirrors of the
  `tower_lsp_server::ls_types` equivalents it replaces, no
  `tower-lsp-server` dependency), following `deps_core::position`'s existing
  `#[non_exhaustive]` + constructor pattern from spec 063. Retype
  `deps-core/src/lsp_helpers/diagnostics.rs` (`generate_diagnostics_from_cache`
  and all ~17 `Diagnostic { .. }` construction sites) and `DiagnosticSeverities`
  to build/hold this domain type instead of `ls_types` types. Retype
  `Ecosystem::generate_diagnostics`'s trait signature (default method +
  the 3 ecosystem overrides in `deps-npm`, `deps-github-actions`,
  `deps-gitlab-ci`) to return `Vec<diagnostic::Diagnostic>`. **This module
  and this trait method need no feature gate at all** — the conversion to
  `ls_types::Diagnostic` moves entirely to `deps-lsp`'s existing
  `lsp_types_interop.rs` (the file spec 063 already designated for
  orphan-rule-constrained `ls_types` conversions, e.g. `url::Url ⇄
  ls_types::Uri`), which `deps-lsp/src/handlers/diagnostics.rs` calls after
  getting the domain `Vec<diagnostic::Diagnostic>` back from
  `Ecosystem::generate_diagnostics`.
- **Part B — make `tower-lsp-server` optional, all the way down.** The
  original estimate below (`hover.rs`/`code_actions.rs`/`code_lenses.rs`/
  `inlay_hints.rs`/`generate_document_links` in `deps-core` alone) proved
  incomplete once implementation started: `Ecosystem::complete_version`/
  `complete_package_name`/`complete_feature` (required, no default) return
  `Completions`, which wraps `Vec<tower_lsp_server::ls_types::CompletionItem>`
  — forcing every one of the 14 ecosystem crates to name `ls_types`
  regardless of whether `deps-cli` ever calls `generate_completions`. Worse,
  each of the 14 ecosystem crates has its own **direct**, unconditional
  `tower-lsp-server` Cargo.toml dependency (not routed through `deps-core`'s
  re-export), and 3 of them (`deps-npm`, `deps-github-actions`,
  `deps-gitlab-ci`) override `generate_hover`/`generate_code_actions`/
  `generate_code_lenses` with real `ls_types`-typed bodies. Satisfying
  FR-001/SC-001 therefore requires the feature gate to extend through
  `deps-core`'s `completion` module and every ecosystem crate's own
  Cargo.toml and `ecosystem.rs`, not just `deps-core`'s own
  `lsp_helpers`. Concretely:
  - `deps-core`: gate `hover.rs`/`code_actions.rs`/`code_lenses.rs`/
    `inlay_hints.rs`/`generate_document_links`, the `completion` module,
    and `generate_completions`/`complete_version`/`complete_package_name`/
    `complete_feature`/`collect_pin_all_to_sha_edits`/`pin_all_to_sha_noun`
    behind a new `lsp-responses` feature, gating `tower-lsp-server` itself
    as `optional = true`.
  - Each of the 14 `deps-<ecosystem>` crates gets an identically-named
    `lsp-responses = ["dep:tower-lsp-server", "deps-core/lsp-responses"]`
    feature, with its own `tower-lsp-server` dependency made `optional =
    true`; their `generate_completions`/`complete_version`/
    `complete_package_name` overrides (every crate has one) and, for
    `deps-npm`/`deps-github-actions`/`deps-gitlab-ci`, their
    `generate_hover`/`generate_code_actions`/`generate_code_lenses`
    overrides are gated the same way. `deps-deno`/`deps-gradle` additionally
    forward `deps-npm/lsp-responses`/`deps-maven/lsp-responses`
    respectively, since they depend on those crates directly (not
    optionally).
  - **Not default.** Cargo does not allow a `workspace = true` dependency
    edge to turn off a feature the workspace-inherited crate defaults on —
    the exact problem `deps-engine`'s own per-ecosystem `dep:`-optional
    features already hit (issue #1058). Making `lsp-responses` `deps-core`'s
    default (as originally planned below) would make it inescapable for
    `deps-engine`'s `deps-cargo = { workspace = true, optional = true }`-
    shaped dependency edges: `default-features` cannot be turned off there,
    only added to (`features = [...]` can always be added). So `deps-core`
    and every ecosystem crate leave `lsp-responses` **out** of `default`
    entirely, and every consumer that wants it requests it explicitly.
  - `deps-engine` gets its own `lsp-responses` feature using
    weak-dependency-feature syntax — `["deps-core/lsp-responses",
    "deps-cargo?/lsp-responses", "deps-npm?/lsp-responses", ...]` for all 14
    optional ecosystem deps — so it only forwards to an ecosystem crate
    already enabled via that ecosystem's own `cargo = ["dep:deps-cargo"]`-
    shaped feature, never pulling one in that wasn't otherwise selected.
    `deps-lsp`'s `Cargo.toml` requests `deps-core`'s and `deps-engine`'s
    `lsp-responses` unconditionally (it always needs the full surface); its
    unconditional `[dev-dependencies]` on `deps-npm`/`deps-deno`/
    `deps-github-actions`/`deps-gitlab-ci` (compiled for every
    `cargo-hack --each-feature` slice regardless of which ecosystem feature
    is toggled) request it explicitly too, since `deps-engine`'s
    weak-dependency forwarding only covers ecosystems `deps-engine` itself
    optionally enables. `deps-cli`'s `Cargo.toml` requests none of this and
    drops its own direct `tower-lsp-server` line.

`deps-cli`'s own `report.rs`/`config.rs`/`exit.rs`/`format/{mod,table,json,sarif}.rs`
are retyped in the same PR to consume `deps_core::diagnostic::{Diagnostic,
Severity}` + `deps_core::position::Range` + `url::Url` instead of `ls_types`
directly — this is what actually removes `deps-cli`'s last `ls_types`
imports (Part A alone only stops `deps-core` from *forcing* the dependency;
`deps-cli`'s own source still names `ls_types` types today and must be
migrated too, per spec FR-006).

### Component Diagram

```mermaid
graph TD
    subgraph "Part A: protocol-agnostic diagnostic domain type (no feature gate)"
        Diag["deps_core::diagnostic::{Diagnostic, Severity,<br/>RelatedInformation, CodeDescription}<br/>(new)"]
        GenDiag["generate_diagnostics_from_cache<br/>(diagnostics.rs, retyped)"]
        Trait["Ecosystem::generate_diagnostics<br/>(default method, retyped)"]
        Overrides["deps-npm / deps-github-actions / deps-gitlab-ci<br/>generate_diagnostics overrides (retyped)"]
        Sev["DiagnosticSeverities<br/>(fields retyped to diagnostic::Severity)"]

        Diag --> GenDiag
        GenDiag --> Trait
        GenDiag --> Overrides
        Diag --> Sev
    end

    subgraph "Part B: tower-lsp-server optional (lsp-responses feature, non-default)"
        Hover["hover.rs / code_actions.rs / code_lenses.rs /<br/>inlay_hints.rs / generate_document_links / completion module /<br/>generate_completions+complete_version+complete_package_name<br/>(now feature-gated in deps-core)"]
        Cargo["deps-core/Cargo.toml:<br/>tower-lsp-server optional,<br/>lsp-responses NOT in default"]
        EcoCrates["each deps-&lt;ecosystem&gt; crate:<br/>own lsp-responses feature,<br/>own tower-lsp-server optional,<br/>generate_completions/complete_version overrides gated<br/>(+ generate_hover/code_actions/code_lenses for npm/github-actions/gitlab-ci)"]
        Engine["deps-engine:<br/>lsp-responses = [deps-core/lsp-responses,<br/>deps-cargo?/lsp-responses, ...] (weak-dep forwarding)"]
    end

    Trait --> Boundary
    Overrides --> Boundary
    Boundary["deps-lsp/src/lsp_types_interop.rs<br/>(new: diagnostic::Diagnostic -> ls_types::Diagnostic, etc.)"]
    Boundary --> Handlers["deps-lsp/src/handlers/diagnostics.rs"]

    DepsCli["deps-cli: report.rs / config.rs / exit.rs /<br/>format/{mod,table,json,sarif}.rs<br/>(retyped to diagnostic::{Diagnostic,Severity});<br/>requests no lsp-responses anywhere"]
    Trait --> DepsCli
    Overrides --> DepsCli

    DepsLsp["deps-lsp Cargo.toml:<br/>deps-core + deps-engine features = [\"lsp-responses\"]<br/>(unconditional, plus explicit on dev-deps)"] --> Hover
    Engine --> EcoCrates
    EcoCrates --> Cargo
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| Diagnostic-generation trait method return type | `Ecosystem::generate_diagnostics` returns `Vec<diagnostic::Diagnostic>` unconditionally (no feature gate on the trait method itself) | It's the one method both `deps-lsp` and `deps-cli` must call to reuse the shared logic (confirmed: `deps-cli/src/lib.rs` already calls it directly) — gating it would force `deps-cli` to lose access entirely, reintroducing the duplication this spec exists to avoid | Feature-gating the whole `Ecosystem::generate_diagnostics` method (two differently-typed versions depending on `lsp-responses`) — rejected: doubles the method's maintenance surface for no benefit, since the domain type works for both callers already |
| `ls_types::Diagnostic` conversion location | Free functions/`From` impls in `deps-lsp/src/lsp_types_interop.rs` (existing file, already the designated home for `url::Url ⇄ ls_types::Uri` per spec 063) | `diagnostic::Diagnostic`/`Severity`/`RelatedInformation`/`CodeDescription` are local to `deps-core`, so a `From<diagnostic::Diagnostic> for ls_types::Diagnostic` impl *could* legally live in `deps-core` (no orphan-rule issue, same shape as `position::Range`'s existing `From` impl) — but putting it there would still require `tower-lsp-server` as at least an optional dependency reachable from a non-`lsp-responses` build only if mis-cfg'd; keeping it entirely in `deps-lsp` (which already unconditionally depends on `tower-lsp-server`) needs zero `deps-core` feature-gating for this conversion at all, and consolidates every `ls_types` conversion in one file | `From` impls inside `deps-core` gated `#[cfg(feature = "lsp-responses")]` — rejected: works, but spreads `ls_types` conversion logic across two crates (`deps-core`'s gated impls and `deps-lsp`'s existing `lsp_types_interop.rs`) instead of one, for no benefit since `deps-lsp` already owns this pattern |
| `tower-lsp-server` optional-dependency scope | `hover.rs`/`code_actions.rs`/`code_lenses.rs`/`inlay_hints.rs`/`generate_document_links`, the `completion` module, and `generate_completions`/`complete_version`/`complete_package_name`/`complete_feature`/`collect_pin_all_to_sha_edits`/`pin_all_to_sha_noun` all move behind `lsp-responses` in `deps-core` **and** in every one of the 14 ecosystem crates' own Cargo.toml/`ecosystem.rs` — `diagnostics.rs` does not need the feature at all after Part A | Confirmed empirically only *after* attempting FR-001/SC-001's `cargo tree` check: `deps-cli` never calls the hover/code-action/code-lens/inlay-hint methods, but `Completions`'s `CompletionItem` wrapping and each ecosystem crate's own unconditional `tower-lsp-server` dependency meant the original, `deps-core`-only scope left `tower-lsp-server` fully reachable from `deps-cli` regardless | Gating `lsp_helpers` as a single all-or-nothing unit including `diagnostics.rs` — rejected: would force the domain-type conversion machinery itself behind the feature too, more surface to keep in sync for no isolation benefit, since `diagnostics.rs` already needs no `tower-lsp-server` symbol after Part A. Retyping `generate_completions`'s `Position` parameter to the domain type instead of gating the whole method (an earlier idea) — rejected: `Completions`/`CompletionItem` itself is still `ls_types`-shaped, so retyping only the parameter would leave the return type coupled anyway |
| `lsp-responses` feature default status | **Not** in `default` on `deps-core` or any ecosystem crate (reversed from the original plan below) | Cargo does not allow a `workspace = true` dependency edge to turn off a feature the workspace-inherited crate defaults on (confirmed empirically: `deps-core = { workspace = true, default-features = false }` in an ecosystem crate's Cargo.toml is a hard `cargo metadata` error when the workspace doesn't already declare `default-features = false` for that entry) — making it default would make it inescapable for `deps-engine`'s `deps-cargo = { workspace = true, optional = true }`-shaped edges, the exact class of problem issue #1058 already hit. `features = [...]` can always be *added* to such an edge, so every consumer that wants it (each ecosystem crate's own `lsp-responses`, `deps-engine`'s weak-dependency forwarding, `deps-lsp`'s explicit request) adds it explicitly instead | Originally planned: `default = ["lsp-responses"]` on `deps-core`, `deps-engine` switching its `deps-core` dependency to `default-features = false` — rejected once implementation hit the Cargo restriction above; not merely a stylistic alternative but a design that does not compile |
| `DiagnosticSeverities` field type | Retyped from `ls_types::DiagnosticSeverity` to `diagnostic::Severity`, with `From`/`Into` conversions both ways | `deps-cli/src/config.rs` already constructs `DiagnosticSeverities` directly from user-facing CLI/config-file severity values — keeping it `ls_types`-typed would leave exactly the leak this spec exists to close | Two parallel `DiagnosticSeverities`-shaped structs (one per type) — rejected: duplicates a `#[non_exhaustive]` struct with 6 fields and its builder methods for no reason; a `From`/`Into` pair between `Severity` and `ls_types::DiagnosticSeverity` is enough |
| `Diagnostic.code` domain type | `Option<String>` (not a `NumberOrString`-equivalent enum) | Confirmed empirically: every one of the ~17 construction sites in `diagnostics.rs` (and the 3 ecosystem overrides) already uses `NumberOrString::String(..)` — no site ever uses `NumberOrString::Number`. A domain enum mirroring `NumberOrString` would be dead complexity | Mirroring `NumberOrString` exactly for forward-compatibility — rejected per this project's MVP principle (no speculative generality); if a future site genuinely needs a numeric code, extend then |

## 2. Project Structure

```
crates/deps-core/
├── Cargo.toml                    (tower-lsp-server: optional = true;
│                                   lsp-responses = ["dep:tower-lsp-server"];
│                                   NOT in default — see Key Design Decisions)
├── src/
│   ├── diagnostic.rs              (new — Diagnostic, Severity, RelatedInformation,
│   │                                CodeDescription; no tower-lsp-server; always compiled)
│   ├── lib.rs                     ("LSP type stability" doc section rewritten — FR-009)
│   ├── completion.rs               (module declaration in lib.rs gated
│   │                                #[cfg(feature = "lsp-responses")]; utf16_to_byte_offset/
│   │                                byte_to_utf16_offset moved to lsp_helpers/mod.rs, re-exported
│   │                                here, since LineOffsetTable needs them ungated)
│   ├── ecosystem.rs                (Ecosystem::generate_diagnostics retyped, unconditional;
│   │                                generate_hover/generate_code_actions/generate_code_lenses/
│   │                                generate_inlay_hints/generate_document_links/
│   │                                generate_completions/complete_version/complete_package_name/
│   │                                complete_feature/collect_pin_all_to_sha_edits/
│   │                                pin_all_to_sha_noun gated #[cfg(feature = "lsp-responses")];
│   │                                fallback_completion_prefix/fallback_completion_is_bare
│   │                                retyped to domain Position, stay ungated)
│   ├── position.rs                 (ls_types From impls + roundtrip tests gated
│   │                                #[cfg(feature = "lsp-responses")]; Position/Range
│   │                                themselves stay ungated)
│   ├── ecosystem_registry.rs        (test-module mock Ecosystem impls: generate_completions/
│   │                                complete_version gated to match the trait)
│   ├── conformance.rs               (assert_completion_guard/AlwaysHasResultsRegistry/
│   │                                completion_guard_conformance! macro gated — only
│   │                                meaningful when lsp-responses is on)
│   └── lsp_helpers/
│       ├── mod.rs                  (feature-gate hover/code_actions/code_lenses/inlay_hints
│       │                            module declarations; position_in_range/LineOffsetTable/
│       │                            byte_span_to_range retyped to domain Position/Range,
│       │                            stay ungated; to_ls_uri/single_file_edit gated)
│       ├── diagnostics.rs          (retyped: generate_diagnostics_from_cache and all
│       │                            Diagnostic { .. } sites -> diagnostic::Diagnostic)
│       ├── hover.rs                 (unchanged, now #[cfg(feature = "lsp-responses")])
│       ├── code_actions.rs          (unchanged, now #[cfg(feature = "lsp-responses")])
│       ├── code_lenses.rs           (unchanged, now #[cfg(feature = "lsp-responses")])
│       ├── inlay_hints.rs           (unchanged, now #[cfg(feature = "lsp-responses")])
│       ├── test_support.rs          (fixtures used only by hover.rs/code_actions.rs — e.g.
│       │                            MockGoFormatter, vulnerable_dep, quickfix_titles — gated
│       │                            to match; fixtures shared with diagnostics.rs stay ungated)
│       └── formatter.rs             (is_position_on_dependency retyped to domain Position,
│                                      stays ungated — used by both gated and ungated callers)

crates/deps-<ecosystem>/ (all 14: bundler, cargo, composer, dart, deno, github-actions,
                          gitlab-ci, go, gradle, maven, npm, nuget, pypi, swift)
├── Cargo.toml                    (own lsp-responses feature, forwarding to deps-core's
│                                   [+ deps-npm's/deps-maven's for deno/gradle, which depend
│                                   on them directly]; own tower-lsp-server: optional = true;
│                                   NOT in default, same Cargo restriction as deps-core)
├── src/ecosystem.rs                (generate_completions/complete_version/complete_package_name
│                                    override — every crate has one — gated
│                                    #[cfg(feature = "lsp-responses")]; deps-npm/
│                                    deps-github-actions/deps-gitlab-ci additionally gate their
│                                    generate_hover/generate_code_actions/generate_code_lenses
│                                    overrides and any free-function helpers used only by them;
│                                    deps-maven/deps-gradle additionally gate their full
│                                    generate_completions override, since they dispatch on their
│                                    own manifest-position context rather than the shared default)

crates/deps-engine/
├── Cargo.toml                    (lsp-responses = ["deps-core/lsp-responses",
│                                   "deps-cargo?/lsp-responses", ... for all 14] —
│                                   weak-dependency-feature syntax, NOT default-features=false
│                                   on the ecosystem deps, which Cargo disallows)

crates/deps-lsp/
├── Cargo.toml                    (deps-core/deps-engine: features = ["lsp-responses"],
│                                   unconditional [dependencies] entries, not tied to any
│                                   deps-lsp feature toggle; [dev-dependencies] on deps-npm/
│                                   deps-deno/deps-github-actions/deps-gitlab-ci also request
│                                   it explicitly — they're compiled for every
│                                   cargo-hack --each-feature slice regardless of which
│                                   ecosystem feature is selected)
├── src/
│   ├── lsp_types_interop.rs       (extended: diagnostic::{Diagnostic,Severity,
│   │                                RelatedInformation,CodeDescription} -> ls_types equivalents)
│   └── handlers/diagnostics.rs    (calls Ecosystem::generate_diagnostics, then converts
│                                    via lsp_types_interop before building the LSP response)

crates/deps-cli/
├── Cargo.toml                    (no deps-core/deps-engine feature overrides needed — neither
│                                   defaults to lsp-responses, so a bare `{ workspace = true }`
│                                   is already clean; own direct tower-lsp-server dependency
│                                   line removed)
├── src/
│   ├── lib.rs                     (doc comment referencing generate_diagnostics updated)
│   ├── report.rs                  (CheckFinding: severity/range/code retyped to
│   │                                diagnostic::Severity / position::Range / String)
│   ├── config.rs                  (severity config retyped to diagnostic::Severity)
│   ├── exit.rs                    (retyped)
│   └── format/
│       ├── mod.rs                 (severity_str retyped)
│       ├── table.rs               (retyped)
│       ├── json.rs                (retyped)
│       └── sarif.rs                (retyped)

.github/workflows/ci.yml           (new guard step, mirroring the test-util leak guard:
                                     cargo tree -p deps-cli -e features,no-dev must not
                                     contain tower-lsp-server; self-check against deps-lsp's
                                     own tree, which always contains it)
```

## 3. Data Model

```rust
// crates/deps-core/src/diagnostic.rs

/// Protocol-agnostic replacement for `tower_lsp_server::ls_types::Diagnostic`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    pub range: crate::position::Range,
    pub severity: Option<Severity>,
    pub code: Option<String>,
    pub code_description: Option<CodeDescription>,
    pub message: String,
    pub related_information: Option<Vec<RelatedInformation>>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(range: crate::position::Range, message: impl Into<String>) -> Self { .. }
    // with_severity / with_code / with_code_description / with_related_information
}

/// Protocol-agnostic replacement for `ls_types::DiagnosticSeverity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Error, Warning, Information, Hint }

/// Protocol-agnostic replacement for `ls_types::DiagnosticRelatedInformation`
/// (its `Location` field flattened in, matching #1071's file-identity approach).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct RelatedInformation {
    pub uri: url::Url,
    pub range: crate::position::Range,
    pub message: String,
}

/// Protocol-agnostic replacement for `ls_types::CodeDescription`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct CodeDescription {
    pub href: url::Url,
}
```

`DiagnosticSeverities` (`lsp_helpers/diagnostics.rs`) keeps its existing 6
fields/builder shape, retyped from `tower_lsp_server::ls_types::DiagnosticSeverity`
to `crate::diagnostic::Severity`.

### Migrations

None — no persisted/serialized state; this is an in-process Rust type change.
`deps-cli`'s JSON/SARIF *output* schema is explicitly unchanged (FR-006):
`format/json.rs`/`format/sarif.rs` serialize from `CheckFinding`'s fields the
same way regardless of `CheckFinding`'s internal `severity`/`range` field
types, as long as their `Display`/formatting logic is preserved verbatim.

## 4. API Design

Not a network API — this is a Rust trait/type API change. Summary of
signature changes (full list is `tasks.md`'s job):

| Item | Before | After |
|------|--------|-------|
| `Ecosystem::generate_diagnostics` | `-> BoxFuture<'a, Vec<ls_types::Diagnostic>>` | `-> BoxFuture<'a, Vec<diagnostic::Diagnostic>>` |
| `lsp_helpers::generate_diagnostics_from_cache` | `-> Vec<ls_types::Diagnostic>` | `-> Vec<diagnostic::Diagnostic>` |
| `lsp_helpers::DiagnosticSeverities` fields | `ls_types::DiagnosticSeverity` | `diagnostic::Severity` |
| New: `deps-lsp::lsp_types_interop` | n/a | `fn to_lsp_diagnostic(diagnostic::Diagnostic) -> ls_types::Diagnostic` (+ `Severity`/`RelatedInformation`/`CodeDescription` equivalents) |
| `deps-cli::report::CheckFinding` | `severity: ls_types::DiagnosticSeverity`, `range: ls_types::Range` | `severity: deps_core::diagnostic::Severity`, `range: deps_core::position::Range` |

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| `deps-lsp` handlers | inbound (consumer of `Ecosystem::generate_diagnostics`) | in-process Rust call | Converts domain type to `ls_types::Diagnostic` via `lsp_types_interop` immediately before building the `PublishDiagnosticsParams`/pull-diagnostics response; no other change to `handlers/diagnostics.rs`'s control flow |
| `deps-cli` `check` | inbound (consumer of `Ecosystem::generate_diagnostics`) | in-process Rust call | No longer converts to/from `ls_types` at all; `report::classify` (or equivalent) builds `CheckFinding` directly from `diagnostic::Diagnostic` |
| `deps-npm`/`deps-github-actions`/`deps-gitlab-ci` | outbound (call `generate_diagnostics_from_cache`, append own findings) | in-process Rust call | Their appended `Diagnostic { .. }` literals (deprecated-package / mutable-ref findings) retyped to `diagnostic::Diagnostic { .. }` |

## 6. Security

No new attack surface — this is an internal type-boundary refactor with no
change to what data crosses a trust boundary (registry responses, manifest
contents) or how it's redacted (`Redacted<T>`/`expose_secret()` usage is
unaffected; no diagnostic ever carries a credential per issue #993's
existing, separate hardening work). `url::Url` continues to be the file-
identity type for `RelatedInformation.uri`, consistent with #1071's existing
choice — no new URI-normalization surface introduced (issue #1086's
canonicalization concern is out of scope here, tracked separately).

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|-------------|-----------------|
| Unit | `cargo nextest` | New `diagnostic::{Diagnostic, Severity, RelatedInformation, CodeDescription}` constructors; `lsp_types_interop`'s domain-to-`ls_types` conversion functions (round-trip a representative `Diagnostic` through every field, including `None`/`Some` variants of optional fields) | Every field, every `Severity` variant |
| Snapshot (insta) | `cargo insta test` | Every existing `deps-lsp`/`deps-npm`/`deps-github-actions`/`deps-gitlab-ci` diagnostics snapshot must produce byte-identical output after the retype — this is the primary regression gate (spec SC-002) | 0 changed/new snapshots; run `cargo insta test --workspace --all-features` and confirm the diff is empty before considering any task done, never `cargo insta accept` a diagnostics-path change |
| Fixture | `cargo nextest` (`deps-cli`) | `deps-cli`'s existing table/JSON/SARIF fixture tests must produce identical output (spec SC-003) | 0 changed fixtures |
| Dependency-tree guard | CI (`.github/workflows/ci.yml`) | New step (mirroring the existing `test-util` leak guard): `cargo tree -p deps-cli -e features,no-dev \| grep -q tower-lsp-server` must fail the job if it matches (spec FR-007/SC-001) | Added, passing |
| Live | Manual (`RUST_LOG=debug cargo run -p deps-lsp -- --stdio`) | Confirm a real hover/diagnostics session in an editor is visually unchanged for a manifest with several diagnostic categories (outdated, unknown, yanked, unsatisfiable, deprecated, vulnerability); confirm `deps-cli check` on the same manifest produces unchanged table/JSON/SARIF output | Per this project's "verify live, not just in CI" constitution principle 5 |

## 8. Performance Considerations

Diagnostics generation already runs off the hover-latency-critical path
(constitution principle 3) — background/periodic, not inline on a request
handler. The domain-type → `ls_types` conversion adds one extra allocation
pass per diagnostic (building a new `ls_types::Diagnostic` from a
`diagnostic::Diagnostic` instead of constructing it directly), which is
negligible relative to the registry I/O and version-comparison work already
dominating that path. No new benchmark required; if an existing
`deps-core` benchmark exercises `generate_diagnostics_from_cache`, confirm
it doesn't regress materially (informal check, not a hard gate).

## 9. Rollout Plan

Single PR, no feature flag needed at the *user* level (this is an internal
refactor with `FR-006`-guaranteed output parity). Land in this order within
the PR to keep it reviewable as staged commits:

1. `diagnostic.rs` (new module) + retype `diagnostics.rs`/`DiagnosticSeverities`
   + retype the `Ecosystem::generate_diagnostics` trait default + 3
   ecosystem overrides — compiles and passes existing tests with
   `lsp_types_interop`-based conversion added at every current `ls_types`
   consumption site as a mechanical bridge (so `deps-lsp`/`deps-cli` need no
   changes yet).
2. `deps-lsp/src/lsp_types_interop.rs` conversion functions +
   `handlers/diagnostics.rs` updated to call them.
3. `deps-core/Cargo.toml`'s `tower-lsp-server` optional +
   `lsp-responses` feature + `deps-engine`/`deps-lsp`/`deps-cli` Cargo.toml
   updates (Part B) — this step is when `cargo tree -p deps-cli` first stops
   showing `tower-lsp-server`, once step 4 also removes `deps-cli`'s own
   direct usage.
4. `deps-cli`'s `report.rs`/`config.rs`/`exit.rs`/`format/*.rs` retyped off
   `ls_types` entirely; remove `deps-cli`'s direct `tower-lsp-server`
   `Cargo.toml` dependency line.
5. CI guard step (FR-007) + `lib.rs` doc-comment fix (FR-009) +
   `CHANGELOG.md` `Breaking` entry.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| 1. One fix, one place | Compliant | This is the whole point of the plan — Part A specifically exists to keep diagnostic-generation logic shared instead of duplicated between `deps-lsp` and `deps-cli` |
| 2. `EcosystemId` exhaustive matches | N/A | No `EcosystemId` match sites touched |
| 3. Non-blocking LSP surface | Compliant | Diagnostics generation is already off the hover-latency-critical path; unaffected |
| 4. No hand-rolled version comparison | N/A | Not touched |
| 5. Verify live | Planned | Testing Strategy §7's Live row |
| 6. Secrets never touch plaintext | N/A | No secret-carrying data in the diagnostic domain type |
| 7. Pre-1.0 clean breaks | Compliant | `Ecosystem::generate_diagnostics`'s signature change is a direct break, documented in `CHANGELOG.md`, no deprecation shim |
| 8. Post-1.0 breaking-change policy | N/A (pre-1.0) | `CHANGELOG.md` `Breaking` entry still added per NFR-001, ahead of the post-1.0 policy taking effect |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| A snapshot silently changes and gets `cargo insta accept`ed instead of investigated | High (silent LSP-visible regression) | Low | Testing Strategy §7 explicitly forbids blind `insta accept` for this change; any diff must be explained field-by-field against the old `ls_types`-based output before accepting |
| `deps-engine`'s single `deps-core` dependency line can't actually differ per-adapter within one `cargo build --workspace` invocation (Cargo feature unification) | Medium (guard reports false negative) | Low | Same enforcement shape already proven for `test-util`'s leak guard (`cargo tree -p <crate> -e features,no-dev`) in this exact workspace — verify FR-007's new guard step the same way before considering it done, not assumed to work by analogy alone |
| One of the ~17 `Diagnostic { .. }` construction sites in `diagnostics.rs` is missed during the mechanical retype, leaving a stray `ls_types` reference | Medium (compile error, not a silent bug — cheap to catch) | Low | `cargo check --workspace --all-features` after Part A catches every missed site as a type error before any test runs |
| `deps-cli`'s SARIF/JSON output subtly changes because a formatting function relied on `ls_types::DiagnosticSeverity`'s `Display`/ordering behavior rather than an explicit mapping | Medium (silent CLI-output regression, harder to catch than an LSP snapshot) | Medium | Testing Strategy §7's Fixture row is a hard gate — 0 changed fixtures; if a fixture must change, treat it as a bug in the retype, not an accepted `Breaking` change, since FR-006 explicitly requires output parity |

## See Also

- [[spec]] — feature specification
- [[tasks]] — implementation tasks (after this phase)
- [[MOC-specs]] — all specifications
- [[../063-deps-core-domain-boundary-hardening/plan|Spec 063's plan]] — the `deps_core::position` pattern and `lsp_types_interop.rs` precedent this plan reuses

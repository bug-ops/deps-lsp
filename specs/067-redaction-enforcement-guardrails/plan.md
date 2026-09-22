---
aliases:
  - Redaction Enforcement Guardrails Plan
tags:
  - sdd
  - plan
  - security
  - testing-infra
  - deps-core
created: 2026-09-23
status: draft
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: Redaction Enforcement Guardrails

> [!info] References
> **Spec**: [[spec]]
> **Issues**: #1238, #1250

## 1. Architecture

### Approach

Two independent, additive changes land in the same PR because they share root cause and review
context, but have no code dependency on each other and can be implemented/tested in either
order:

1. **`ParseError` guard** — pure `deps-core::error` change: add variant-level
   `#[non_exhaustive]` to `DepsError::ParseError` and a `DepsError::parse_error(...)`
   constructor, mirroring the already-shipped `DepsError::rate_limited(...)` /
   `RateLimited` pattern exactly. Then migrate every external `ParseError { .. }` construction
   site to the constructor — this is the change that actually proves the guard (the crate
   won't compile until every site is migrated).
2. **`RedactingDebug` derive** — new proc-macro crate `deps-core-macros`, re-exported through
   `deps-core::redact_debug::RedactingDebug` (using `pub use`). Chosen over a clippy lint /
   dylint plugin because a `#[derive(...)]` macro produces an ordinary compile error through
   `cargo build` alone — no separate lint-runner invocation, no nightly toolchain requirement,
   and it directly replaces the hand-written `impl Debug` rather than just checking it.

### Component Diagram

```mermaid
graph TD
    subgraph "deps-core-macros (new proc-macro crate)"
        DM[RedactingDebug derive macro]
    end
    subgraph "deps-core"
        RD[redact_debug module: re-export + field-redactor fns]
        NP["redact:: (post-#1316) / net_policy:: url_for_tracing, redact_declaration_key"]
        ERR["error::DepsError::ParseError #[non_exhaustive] + parse_error() constructor"]
        PES[net_policy::parse_error_source]
    end
    subgraph "Consumer crates"
        CARGO["deps-cargo::config::AuthToken"]
        GH["deps-core::github::AuthToken"]
        GITLAB["deps-gitlab-ci::client::AuthToken, types::HostRef"]
        NUGET["deps-nuget::config::NuGetAuth, RedactedSecret, PackageSourceEntry"]
        PYPI["deps-pypi::config::ResolvedChain"]
        GITREF["deps-core::lsp_helpers::git_ref::ResolvedShaPin"]
        ECOS[all 14 ecosystem crates: ParseError construction sites]
    end

    DM -->|derive expansion calls| RD
    RD --> NP
    CARGO -->|#[derive(RedactingDebug)]| DM
    GH -->|#[derive(RedactingDebug)]| DM
    GITLAB -->|#[derive(RedactingDebug)]| DM
    NUGET -->|#[derive(RedactingDebug)]| DM
    PYPI -->|#[derive(RedactingDebug)]| DM
    GITREF -->|#[derive(RedactingDebug)]| DM
    ECOS -->|DepsError::parse_error(..)| ERR
    ERR --> PES
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| `ParseError` guard mechanism | Variant-level `#[non_exhaustive]` + constructor | Exact precedent already shipped (`RateLimited`, #1295); zero new tooling; forces migration at compile time | `xtask`/grep source-scan (#1250 Option 2) — test-time only, ongoing maintenance burden, rejected per user decision |
| `RedactingDebug` scope | Named-field structs only, v1 | Matches every impl in the migration batch; enums need per-variant/branch logic the attribute model doesn't fit | Full enum support — deferred, tracked as a follow-up issue rather than blocking this feature |
| New crate name | `deps-core-macros` | No existing collision; matches workspace's `deps-<thing>` naming convention (this is infrastructure for `deps-core`, not an ecosystem) | `deps-macros` (too generic, could be confused with a future public-facing macro surface) |
| Derive re-export path | `deps_core::redact_debug::RedactingDebug` (new module) re-exporting the proc-macro crate's derive | Consumers depend on `deps-core` only, never add `deps-core-macros` directly — matches how `tower-lsp-server` types are re-exported through `deps-core::lsp_helpers` today | Consumers add `deps-core-macros` as a direct dependency — rejected, duplicates the version-pinning surface for no benefit |
| Compile-fail test tooling | `trybuild` (dev-dependency of `deps-core-macros` only) | Standard, widely-used crate for exactly this (`.rs`/`.stderr` fixture pairs); zero runtime footprint since it's dev-only | Hand-rolled `compile_fail` doctests — noisier `# Examples` sections, harder to assert exact diagnostic text |
| Redactor call target | Call `deps_core::redact::{url_for_tracing, redact_declaration_key}` (post-#1316 paths) from generated code, with a fallback to `net_policy::` re-exports if #1316 hasn't merged first | `#1316` (redact module extraction) is a currently-open, unrelated PR; this feature must not hard-depend on its merge order | Blocking this feature on #1316 merging first — rejected, needlessly couples two independent PRs; #1317 (further redact-module cleanup) is explicitly deferred behind #1316 already, this feature is not |

## 2. Project Structure

```
crates/
├── deps-core-macros/              (NEW — proc-macro = true)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                 (RedactingDebug derive entry point + field-attr parsing)
├── deps-core/
│   ├── Cargo.toml                 (+ deps-core-macros, dev-dep on trybuild)
│   └── src/
│       ├── error.rs                (ParseError: #[non_exhaustive] + parse_error() ctor)
│       ├── redact_debug.rs         (NEW — re-exports RedactingDebug, holds the runtime
│       │                            helper fns the derive's generated code calls)
│       └── tests/
│           └── redacting_debug_compile_fail.rs  (NEW — trybuild harness)
│               └── fixtures/
│                   ├── missing_attribute.rs
│                   └── missing_attribute.stderr
├── deps-cargo/src/config.rs        (AuthToken: derive instead of hand-written impl)
├── deps-core/src/github.rs         (AuthToken: derive)
├── deps-gitlab-ci/src/client.rs    (AuthToken: derive)
├── deps-gitlab-ci/src/types.rs     (HostRef: derive)
├── deps-nuget/src/config.rs        (NuGetAuth, RedactedSecret, PackageSourceEntry: derive)
├── deps-pypi/src/config.rs         (ResolvedChain: derive)
├── deps-core/src/lsp_helpers/git_ref.rs  (ResolvedShaPin: derive)
└── <all 14 ecosystem crates + deps-lsp/deps-cli>  (ParseError { .. } -> DepsError::parse_error(..))
```

`crates/deps-core-macros` is added to root `Cargo.toml`'s `members = ["crates/*"]` glob
automatically (no `exclude` entry needed, unlike `deps-zed`/`github-action`).

## 3. Data Model

### `deps-core-macros/src/lib.rs` (sketch)

```rust
#[proc_macro_derive(RedactingDebug, attributes(redact, raw))]
pub fn derive_redacting_debug(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let Data::Struct(data) = &input.data else {
        return syn::Error::new_spanned(&input, "RedactingDebug only supports structs with named fields")
            .to_compile_error()
            .into();
    };
    let Fields::Named(fields) = &data.fields else {
        return syn::Error::new_spanned(&data.fields, "RedactingDebug requires named fields (no tuple/unit structs)")
            .to_compile_error()
            .into();
    };

    let field_treatments = fields.named.iter().map(|f| {
        match field_redaction_kind(f) {
            // exactly one of #[redact(url)], #[redact(key)], #[raw] — anything else is a
            // syn::Error::new_spanned(...).to_compile_error() naming the field (FR-005)
            Ok(kind) => Ok((f, kind)),
            Err(e) => Err(e),
        }
    });
    // ... collect errors (report all missing/duplicate attributes at once, not just the first)
    // ... emit `impl std::fmt::Debug for #ident { fn fmt(...) { f.debug_struct(...)
    //         .field(name, &RedactionKind::render(&self.#field)) ... .finish() } }`
}

enum FieldRedaction { Url, Key, Raw }
```

### `deps-core/src/redact_debug.rs` (sketch)

```rust
//! Compile-time-enforced `Debug` redaction (#1238) — see [`RedactingDebug`].

/// Derives a `Debug` impl that requires every field to declare `#[redact(url)]`,
/// `#[redact(key)]`, or `#[raw]` — an unannotated field fails to compile.
pub use deps_core_macros::RedactingDebug;

// Runtime helpers the derive's generated code calls — thin wrappers so the derive crate
// itself has zero dependency on deps-core's redaction internals (keeps the proc-macro crate
// free of feature-flag coupling; it only emits calls to these paths as tokens).
#[doc(hidden)]
pub fn __redact_url_field(v: &impl std::fmt::Display) -> impl std::fmt::Debug { /* -> crate::redact::url_for_tracing / net_policy::RedactedUrl */ }
#[doc(hidden)]
pub fn __redact_key_field(v: &impl std::fmt::Display) -> impl std::fmt::Debug { /* -> crate::redact::redact_declaration_key */ }
```

### `deps-core/src/error.rs` (`DepsError::ParseError`, exact diff shape)

```rust
#[non_exhaustive]
#[error("failed to parse {file_type}: {source}")]
ParseError {
    file_type: String,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
},
```
```rust
impl DepsError {
    /// Constructs a [`Self::ParseError`], routing `source` through
    /// [`crate::net_policy::parse_error_source`] so a credential-shaped parser error can
    /// never reach `Debug`/`Display` unredacted (#1250).
    ///
    /// The only way to build this `#[non_exhaustive]` variant from outside this crate —
    /// mirrors [`Self::rate_limited`]'s precedent exactly.
    #[must_use]
    pub fn parse_error(file_type: impl Into<String>, source: &dyn std::fmt::Display) -> Self {
        Self::ParseError {
            file_type: file_type.into(),
            source: crate::net_policy::parse_error_source(source),
        }
    }
}
```

### Migrations

None (no persisted data/schema; this is source-level only).

## 4. API Design

N/A — no HTTP/LSP-facing API surface changes. The "API" here is the new public Rust items:

| Item | Kind | Crate |
|------|------|-------|
| `DepsError::parse_error(file_type, source)` | associated fn | `deps-core` |
| `deps_core::redact_debug::RedactingDebug` | derive macro (re-export) | `deps-core` (from `deps-core-macros`) |
| `#[redact(url)]` / `#[redact(key)]` / `#[raw]` | field attributes | consumed by the derive |

## 5. Integration Points

| System | Direction | Notes |
|--------|-----------|-------|
| All 14 ecosystem crates + `deps-lsp`/`deps-cli` | inbound (this feature is consumed by them) | Every external `DepsError::ParseError { .. }` construction site (~20+ per #1243's audit) must migrate to `DepsError::parse_error(..)` or the workspace fails to compile — this is the mechanism, not a side effect. |
| `deps-nuget` (`PackageSourceEntry`), `deps-core::lsp_helpers::git_ref` (`ResolvedShaPin`) | inbound | **Revised during implementation**: only these 2 of the originally-planned 9 types are genuine named-field structs with unconditional per-field redaction; they adopt `#[derive(RedactingDebug)]`, deleting their hand-written `impl Debug` blocks. The other 7 (`AuthToken` ×3, `NuGetAuth`, `RedactedSecret`, `HostRef`, `ResolvedChain`) turned out to be tuple structs, an enum, or conditionally-redacted — see spec's Out of Scope. |
| `#1316` (open PR, `deps_core::redact` module extraction) | soft dependency | Generated code calls whichever path (`net_policy::` or `redact::`) is canonical at merge time; implementation checks `main` at start of work, not this plan's fixed snapshot. |

## 6. Security

- **Redaction correctness**: unchanged from today — the derive calls the same
  `url_for_tracing`/`redact_declaration_key` (or `net_policy` equivalents) functions the
  hand-written impls called; this is a mechanical Debug-impl-generation change, not a new
  redaction algorithm.
- **Enforcement boundary**: `#[non_exhaustive]` on `ParseError` only blocks construction
  *outside* `deps-core`'s own crate boundary — `deps-core`'s own internal code (e.g.
  `parser.rs`'s own error-mapping paths) can still construct the variant directly, and should
  continue doing so via the same `parse_error()` constructor for consistency, not because it's
  forced to.
- **Negative testing**: `trybuild` compile-fail fixtures for (a) a `RedactingDebug` struct
  with an unannotated field, (b) a field carrying two conflicting attributes, (c) an external
  crate's `ParseError { .. }` literal (this one via a `doc(hidden)` compile-fail doctest in
  `error.rs` itself, since `trybuild` fixtures live inside `deps-core-macros` and can't easily
  reach across the crate boundary the negative test needs to prove).

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|---------------|------------------|
| Compile-fail | `trybuild` (new dev-dep, `deps-core-macros`) | Unannotated field, conflicting attributes, non-struct/tuple-struct input | Every FR-005 failure mode listed in the spec |
| Compile-fail (doctest) | `compile_fail` doctest in `error.rs` | External `ParseError { .. }` literal does not compile | SC-001 |
| Unit / conformance | existing `debug_redaction_conformance!` (unchanged macro) | Both actually-migrated types (`PackageSourceEntry`, `ResolvedShaPin`) keep passing with byte-identical probe assertions (revised down from 9 — see spec) | SC-003 |
| Unit | `cargo nextest` | `DepsError::parse_error(..)` output matches `parse_error_source(..)` byte-for-byte for both credential-shaped and benign inputs | FR-002 |
| Doctest | `cargo test --doc --all-features` | `RedactingDebug`'s own `# Examples` doctest (mirrors `debug_redaction_conformance!`'s existing `mod example` pattern) | Rustdoc gate |
| Full workspace | `cargo nextest run --workspace --all-features --no-fail-fast` | No regression anywhere; migration compiles workspace-wide | SC-004 |

## 8. Performance Considerations

- Proc-macro expansion adds a small, one-time incremental-compile cost to `deps-core-macros`
  itself and to each of the 9 migrated struct definitions — negligible relative to existing
  build times (this workspace already compiles `tower-lsp-server`, `reqwest`, `quick-xml`).
- No runtime cost: `Debug` output shape and redaction logic are unchanged, only *generated*
  instead of hand-written.

## 9. Rollout Plan

1. Land `ParseError` guard + full-workspace call-site migration first (self-contained, no new
   crate) — can ship even if `RedactingDebug` needed more review time.
2. Land `deps-core-macros` + `redact_debug` module + the 9-type migration batch.
3. Both land in the same PR per this spec's scoping (single #1250/#1238 issue pair), but are
   independently revertable commits if review surfaces a problem with one half.
4. File the remaining-~26-struct follow-up issue at PR-creation time (per spec's resolved
   Open Question), P4 + `testing-infra` + `type/refactor` labels.
5. Update `.local/testing/coverage.md` / `regressions.md` per `.claude/rules/branching.md`'s
   PR checklist — add a `RedactingDebug` conformance row and a `ParseError` construction-guard
   regression entry (minimal repro: an external-crate literal, expected: compile error).

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| Testing (nextest, real deps over mocks) | Compliant | `trybuild` fixtures are the standard mechanism for testing compile errors — no mocking involved. |
| Code Style / doc comments | Compliant | Every new `pub` item gets a `///` doc + `# Examples` per workspace convention. |
| Simplicity / no premature abstraction | Compliant | Derive scoped to structs only; enum support explicitly deferred rather than over-engineered now. |
| `unsafe_code = "forbid"` | Compliant | Proc-macro code generation requires no `unsafe`; `deps-core-macros` inherits the workspace lint table. |
| Git Workflow (branch naming, checks) | Compliant | Branch `feat/1250-redaction-enforcement-guard`; full check suite run before PR per `.claude/rules/branching.md`. |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|--------------|------------|
| `#1316` merges mid-implementation, moving `net_policy::` redaction fns to `redact::` | low (rename only) | medium (PR is open, active) | Generated code path checked against `main` at implementation start, not hardcoded from this plan's snapshot; both paths are re-exported during #1316's transition window per its own PR description. |
| Migrating a `ParseError` call site changes an existing error's exact `Display`/log text in a way a snapshot (`insta`) test depends on | low | low | `parse_error_source`'s output is unchanged by this feature (only the construction path changes) — `Display` text is provably identical; run `cargo insta test --workspace --all-features` before PR regardless. |
| `syn` 3.0 API surface differs from commonly-referenced `syn` 2.x examples/tutorials | medium (implementation friction) | medium | Pin `syn = "3.0.6"`, `quote = "1.0.47"`, `proc-macro2 = "1.0.107"` (versions confirmed via `cargo add --dry-run` at plan time, context7 unavailable per project memory); consult `syn` 3.0's own docs.rs during implementation rather than assuming 2.x API shapes. |
| Migration batch (9 types) turns out to include a field whose "redacted" treatment isn't a clean url/key split (e.g. a conditional redaction) | medium | low | **Materialized**: 7 of 9 didn't fit — 5 turned out to be single-field tuple structs (not even a field-shape question, a structural one), 1 an enum, 1 a conditionally-redacted field. Dropped all 7 per this mitigation exactly as planned; batch shrank to 2 (`PackageSourceEntry`, `ResolvedShaPin`). Root cause: the original batch was selected by grepping for "manual Debug impl + redaction helper usage" without checking each type's actual field shape — a lesson for scoping future batches (verify shape, not just helper usage, before committing to a migration table). |

## See Also

- [[spec]] — feature specification
- [[tasks]] — implementation tasks (next phase)
- [[MOC-specs]] — all specifications

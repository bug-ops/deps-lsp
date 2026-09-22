---
aliases:
  - Redaction Enforcement Guardrails Tasks
tags:
  - sdd
  - tasks
  - security
  - testing-infra
  - deps-core
created: 2026-09-23
status: draft
related:
  - "[[spec]]"
  - "[[plan]]"
---

# Implementation Tasks: Redaction Enforcement Guardrails

> [!info] References
> **Spec**: [[spec]]
> **Plan**: [[plan]]
> **Total tasks**: 13

## Progress

- [ ] T000: `ParseError` guard — variant `#[non_exhaustive]` + constructor
- [ ] T001: Migrate `deps-core`'s own internal `ParseError` construction sites
- [ ] T002: Migrate `deps-cargo`, `deps-composer`, `deps-dart` call sites
- [ ] T003: Migrate `deps-deno`, `deps-github-actions`, `deps-gitlab-ci`, `deps-gradle` call sites
- [ ] T004: Migrate `deps-maven`, `deps-npm`, `deps-nuget` call sites
- [ ] T005: Migrate `deps-pypi`, `deps-swift` call sites
- [ ] T006: `deps-core-macros` crate scaffold + `RedactingDebug` derive skeleton
- [ ] T007: `RedactingDebug` field-attribute enforcement + Debug-impl generation
- [ ] T008: `deps-core::redact_debug` module + re-export wiring
- [ ] T009: `trybuild` compile-fail fixtures + `ParseError` compile-fail doctest
- [ ] T010: Migrate `AuthToken`/`HostRef` batch to `RedactingDebug`
- [ ] T011: Migrate `NuGetAuth`/`RedactedSecret`/`PackageSourceEntry` batch
- [ ] T012: Migrate `ResolvedChain`/`ResolvedShaPin` batch + full workspace verification

---

## Dependency Graph

```mermaid
graph TD
    T000[T000: ParseError guard] --> T001[T001: deps-core internal migration]
    T000 --> T002[T002: cargo/composer/dart]
    T000 --> T003[T003: deno/gh-actions/gitlab-ci/gradle]
    T000 --> T004[T004: maven/npm/nuget]
    T000 --> T005[T005: pypi/swift]
    T006[T006: macro crate scaffold] --> T007[T007: attribute enforcement + codegen]
    T007 --> T008[T008: redact_debug module]
    T008 --> T009[T009: compile-fail tests]
    T008 --> T010[T010: AuthToken/HostRef batch]
    T008 --> T011[T011: NuGet batch]
    T008 --> T012[T012: ResolvedChain/ResolvedShaPin + full verification]
    T001 --> T012
    T002 --> T012
    T003 --> T012
    T004 --> T012
    T005 --> T012
    T009 --> T012
    T010 --> T012
    T011 --> T012
```

---

### T000: `ParseError` guard — variant `#[non_exhaustive]` + constructor

**Context**: The forcing mechanism for #1250 — everything else in this feature's `ParseError`
half depends on this compiling first (it will *break* every external construction site until
T001-T005 migrate them, which is the point).
**Spec reference**: [[spec#FR-001]], [[spec#FR-002]], [[spec#US-002]]
**Acceptance criteria**:
- [ ] `DepsError::ParseError` carries `#[non_exhaustive]` (mirrors `RateLimited`, `error.rs`)
- [ ] `DepsError::parse_error(file_type: impl Into<String>, source: &dyn std::fmt::Display) -> Self` added, calling `net_policy::parse_error_source` (or `redact::` if #1316 has merged to `main` by the time this task starts — check `main` first)
- [ ] `# Examples` doctest added to `parse_error`, mirroring `rate_limited`'s existing doctest
- [ ] `cargo check -p deps-core` passes; every other crate now fails to compile (expected — resolved by T001-T005)
**Dependencies**: none
**Files**: `crates/deps-core/src/error.rs`
**Complexity**: low

---

### T001: Migrate `deps-core`'s own internal `ParseError` construction sites

**Context**: `deps-core`'s own `lockfile.rs`/`ecosystem.rs`/`parser.rs` construct `ParseError`
directly today. Same-crate construction isn't blocked by `#[non_exhaustive]`, but the plan
calls for using the new constructor here too for consistency, not because it's forced.
**Spec reference**: [[spec#FR-002]]
**Acceptance criteria**:
- [ ] Every `ParseError { .. }` literal in `crates/deps-core/src/{lockfile.rs,ecosystem.rs,parser.rs}` replaced with `DepsError::parse_error(..)`
- [ ] `cargo check -p deps-core --all-features` passes
- [ ] `cargo nextest run -p deps-core --all-features` passes unchanged
**Dependencies**: T000
**Files**: `crates/deps-core/src/lockfile.rs`, `crates/deps-core/src/ecosystem.rs`, `crates/deps-core/src/parser.rs`
**Complexity**: low

---

### T002: Migrate `deps-cargo`, `deps-composer`, `deps-dart` call sites

**Context**: First external-crate migration batch — proves the constructor works from outside
`deps-core` and unblocks these three crates' compilation.
**Spec reference**: [[spec#FR-003]], [[spec#US-002]]
**Acceptance criteria**:
- [ ] Every `ParseError { .. }` literal in the listed files replaced with `DepsError::parse_error(file_type, &e)` (or the crate's existing error variable), preserving the exact `file_type` string previously used
- [ ] `cargo check -p deps-cargo -p deps-composer -p deps-dart --all-features` passes
- [ ] `cargo nextest run -p deps-cargo -p deps-composer -p deps-dart --all-features` passes unchanged (parse-error test cases still assert the same `Display` text)
**Dependencies**: T000
**Files**: `crates/deps-cargo/src/parser.rs`, `crates/deps-cargo/src/lockfile.rs`, `crates/deps-composer/src/lockfile.rs`, `crates/deps-dart/src/lockfile.rs`, `crates/deps-dart/src/parser.rs`
**Complexity**: low

---

### T003: Migrate `deps-deno`, `deps-github-actions`, `deps-gitlab-ci`, `deps-gradle` call sites

**Context**: Second external-crate migration batch.
**Spec reference**: [[spec#FR-003]], [[spec#US-002]]
**Acceptance criteria**:
- [ ] Every `ParseError { .. }` literal in the listed files replaced with `DepsError::parse_error(..)`
- [ ] `cargo check -p deps-deno -p deps-github-actions -p deps-gitlab-ci -p deps-gradle --all-features` passes
- [ ] `cargo nextest run -p deps-deno -p deps-github-actions -p deps-gitlab-ci -p deps-gradle --all-features` passes unchanged
**Dependencies**: T000
**Files**: `crates/deps-deno/src/parser.rs`, `crates/deps-github-actions/src/parser.rs`, `crates/deps-gitlab-ci/src/parser.rs`, `crates/deps-gradle/src/parser/catalog.rs`
**Complexity**: low

---

### T004: Migrate `deps-maven`, `deps-npm`, `deps-nuget` call sites

**Context**: Third external-crate migration batch — includes `deps-nuget/src/registry.rs`, the
only non-`parser.rs`/`lockfile.rs` call site found, worth double-checking manually.
**Spec reference**: [[spec#FR-003]], [[spec#US-002]]
**Acceptance criteria**:
- [ ] Every `ParseError { .. }` literal in the listed files replaced with `DepsError::parse_error(..)`
- [ ] `cargo check -p deps-maven -p deps-npm -p deps-nuget --all-features` passes
- [ ] `cargo nextest run -p deps-maven -p deps-npm -p deps-nuget --all-features` passes unchanged
**Dependencies**: T000
**Files**: `crates/deps-maven/src/parser.rs`, `crates/deps-npm/src/lockfile.rs`, `crates/deps-nuget/src/registry.rs`, `crates/deps-nuget/src/lockfile.rs`, `crates/deps-nuget/src/parser.rs`
**Complexity**: low

---

### T005: Migrate `deps-pypi`, `deps-swift` call sites

**Context**: Final external-crate migration batch — after this, the full workspace compiles
again with the guard active everywhere.
**Spec reference**: [[spec#FR-003]], [[spec#US-002]], [[spec#SC-001]]
**Acceptance criteria**:
- [ ] Every `ParseError { .. }` literal in the listed files replaced with `DepsError::parse_error(..)`
- [ ] `cargo check --workspace --all-features` passes (first point at which the *entire* workspace compiles again)
- [ ] `cargo nextest run -p deps-pypi -p deps-swift --all-features` passes unchanged
- [ ] A `compile_fail` doctest added near `DepsError::ParseError`'s own doc comment in `error.rs`, demonstrating an external-crate-style `ParseError { .. }` literal fails to compile (SC-001) — written as a doctest here since it's the natural place once every real call site is migrated and the guard is proven live
**Dependencies**: T000, T002, T003, T004
**Files**: `crates/deps-pypi/src/ecosystem.rs`, `crates/deps-pypi/src/error.rs`, `crates/deps-pypi/src/lockfile.rs`, `crates/deps-pypi/src/parser/pyproject.rs`, `crates/deps-swift/src/lockfile.rs`, `crates/deps-core/src/error.rs` (doctest only)
**Complexity**: medium (the compile_fail doctest needs care to fail for the *right* reason — E0639, not an unrelated type error)

---

### T006: `deps-core-macros` crate scaffold + `RedactingDebug` derive skeleton

**Context**: First piece of the #1238 half — establishes the new proc-macro crate before any
real logic is written.
**Spec reference**: [[spec#FR-004]]
**Acceptance criteria**:
- [ ] `crates/deps-core-macros/Cargo.toml` created: `name = "deps-core-macros"`, `[lib] proc-macro = true`, workspace-inherited `version`/`edition`/`rust-version`/`authors`/`license`/`repository`, `publish = true`, `[lints] workspace = true`
- [ ] Root `Cargo.toml`'s `[workspace.dependencies]` gains `deps-core-macros = { version = "1.2.0", path = "crates/deps-core-macros" }` (alphabetically sorted) and `syn = "3.0.6"`, `quote = "1.0.47"`, `proc-macro2 = "1.0.107"` (versions confirmed live via `cargo add --dry-run` at plan time — re-verify at implementation time in case newer patch/minor versions shipped since)
- [ ] `deps-core-macros/src/lib.rs` exports `#[proc_macro_derive(RedactingDebug, attributes(redact, raw))] pub fn derive_redacting_debug(...)` that currently just parses input and re-emits an empty `impl Debug` stub (logic lands in T007)
- [ ] `cargo build -p deps-core-macros` succeeds
- [ ] Crate-level `//!` doc comment explaining the macro's purpose and pointing to issue #1238
**Dependencies**: none (can run in parallel with T000-T005)
**Files**: `crates/deps-core-macros/Cargo.toml`, `crates/deps-core-macros/src/lib.rs`, root `Cargo.toml`
**Complexity**: low

---

### T007: `RedactingDebug` field-attribute enforcement + Debug-impl generation

**Context**: The actual compile-time guarantee — this is where FR-005/FR-006 get implemented.
**Spec reference**: [[spec#FR-005]], [[spec#FR-006]], [[spec#US-001]]
**Acceptance criteria**:
- [ ] Only `Data::Struct` with `Fields::Named` accepted; anything else (`enum`, tuple struct, unit struct) produces a `syn::Error::new_spanned(...).to_compile_error()` naming the type and why (per spec's Edge Cases table)
- [ ] Every named field must carry exactly one of `#[redact(url)]`, `#[redact(key)]`, `#[raw]`; zero or 2+ matching attributes on one field is a compile error naming the field and the struct (FR-005)
- [ ] Generated `impl std::fmt::Debug` calls `f.debug_struct(...)`.`field(name, &...)` per field, dispatching to the field-attribute's runtime helper (T008) for `#[redact(*)]` fields and the field's own `Debug` for `#[raw]`
- [ ] `# Examples` doctest on the derive itself (in `deps-core-macros/src/lib.rs` or re-exported doc in `deps-core`), following the same `mod example { ... }` wrapping pattern `debug_redaction_conformance!`'s own doc uses (see `conformance.rs`'s doc comment for why)
**Dependencies**: T006
**Files**: `crates/deps-core-macros/src/lib.rs`
**Complexity**: high

---

### T008: `deps-core::redact_debug` module + re-export wiring

**Context**: Consumers must depend on `deps-core` alone, never `deps-core-macros` directly
(plan's Key Design Decisions). This module is that seam, and holds the runtime helper
functions the derive's generated code calls into.
**Spec reference**: [[spec#FR-006]]
**Acceptance criteria**:
- [ ] `deps-core/Cargo.toml` gains `deps-core-macros = { workspace = true }` as a normal dependency
- [ ] New `crates/deps-core/src/redact_debug.rs`: `pub use deps_core_macros::RedactingDebug;` plus `#[doc(hidden)]` helper fns wrapping the URL/key redactors (check `main` at implementation time for whether these live at `net_policy::{RedactedUrl, redact_declaration_key}` or the post-#1316 `redact::` path — plan's risk table)
- [ ] Module registered in `deps-core/src/lib.rs`
- [ ] `cargo doc -p deps-core --no-deps` builds clean (rustdoc gate)
**Dependencies**: T007
**Files**: `crates/deps-core/Cargo.toml`, `crates/deps-core/src/redact_debug.rs`, `crates/deps-core/src/lib.rs`
**Complexity**: low

---

### T009: `trybuild` compile-fail fixtures for `RedactingDebug`

**Context**: Proves FR-005's compile errors actually fire, per the plan's Testing Strategy —
without this, a future regression in T007's macro logic could silently start accepting
unannotated fields again.
**Spec reference**: [[spec#SC-002]]
**Acceptance criteria**:
- [ ] `trybuild = "1.0.121"` added to `deps-core-macros`'s (or `deps-core`'s, whichever crate hosts the harness — `deps-core` is the natural home since that's where real usages live) `[dev-dependencies]`
- [ ] `tests/redacting_debug_compile_fail.rs` harness + `tests/redacting_debug_compile_fail/fixtures/missing_attribute.rs` (+ matching `.stderr`) proving an unannotated field fails to compile
- [ ] A second fixture proving a field with two conflicting attributes (`#[redact(url)] #[raw]`) fails to compile
- [ ] A third fixture proving a tuple struct / enum input fails to compile with a clear message
- [ ] `cargo nextest run -p deps-core --all-features -E 'test(redacting_debug_compile_fail)'` passes
**Dependencies**: T008
**Files**: `crates/deps-core/Cargo.toml`, `crates/deps-core/tests/redacting_debug_compile_fail.rs`, `crates/deps-core/tests/redacting_debug_compile_fail/fixtures/*.rs`, `.stderr`
**Complexity**: medium

---

### T010: Migrate `AuthToken`/`HostRef` batch to `RedactingDebug` — **RESOLVED AS NOT APPLICABLE**

**Outcome (found during implementation)**: none of these four types fit the derive.
`deps-cargo::config::AuthToken`, `deps-core::github::AuthToken`,
`deps-gitlab-ci::client::AuthToken`, and `deps-nuget::config::NuGetAuth`/`RedactedSecret`
(T011) are single-field tuple structs (`Self(Redacted)`), not named-field structs —
FR-004/FR-005 only accept named-field structs. `deps-gitlab-ci::types::HostRef` is a
4-variant enum, not a struct at all (misidentified when this task was originally written from
a grep that didn't check field shape). All four left unchanged on their existing hand-written
`impl Debug`, per tasks.md's own Gotchas guidance ("drop a mismatched type from the batch
rather than force it"). Tracked in the spec's Open Questions / follow-up issue, categorized by
gap shape (tuple-struct-wrapper vs. enum).
**Spec reference**: [[spec#FR-007]], [[spec#FR-008]], [[spec#US-001]], [[spec#9-open-questions]]
**Acceptance criteria**:
- [x] Verified against actual source (not assumed from the original migration table) that none of the 4 types are named-field structs
- [x] No source changes made to any of the 4 files — hand-written impls and their `debug_redaction_conformance!` tests remain untouched and passing
- [x] Finding documented in spec.md's migration table and Out of Scope section
**Dependencies**: T008
**Files**: none changed (verification only)
**Complexity**: low (once discovered)

---

### T011: Migrate `PackageSourceEntry` (revised — `NuGetAuth`/`RedactedSecret` not applicable)

**Context**: All three types live in `deps-nuget/src/config.rs`. **Outcome (found during
implementation)**: `NuGetAuth` and `RedactedSecret` are single-field tuple structs wrapping
`Redacted` (same shape as T010's `AuthToken`s) — not applicable to the derive, left unchanged.
Only `PackageSourceEntry` is a genuine named-field struct and was migrated.
**Spec reference**: [[spec#FR-007]], [[spec#FR-008]]
**Acceptance criteria**:
- [x] `PackageSourceEntry` gets `#[derive(RedactingDebug)]` with field attributes (`#[redact(key)]` on `key`, `#[raw]` on `value`/`tier`/etc.) matching current behavior
- [x] Its hand-written `impl Debug` block deleted
- [x] Its `debug_redaction_conformance!` invocation passes unchanged
- [x] `NuGetAuth`/`RedactedSecret` verified as tuple structs, left untouched, documented in spec's Out of Scope
- [x] `cargo check -p deps-nuget --all-features` passes
**Dependencies**: T008
**Files**: `crates/deps-nuget/src/config.rs`
**Complexity**: medium

---

### T012: Migrate `ResolvedShaPin` (revised — `ResolvedChain` not applicable) + full workspace verification

**Context**: Final migration-batch task, plus the point where every other task's work is
verified together as a whole (this is the "does everything actually compile and pass as one
PR" checkpoint). **Outcome (found during implementation)**: `ResolvedChain`'s `key` field
redaction is conditional on its sibling `key_shape` field's runtime value (URL-redact only
when `KeyShape::Url`, left as-is when `KeyShape::Opaque`) — the derive's static per-field
model can't express this branch. Left unchanged; only `ResolvedShaPin` (a genuine
unconditional named-field struct) is migrated.
**Spec reference**: [[spec#FR-007]], [[spec#FR-008]], [[spec#SC-003]], [[spec#SC-004]], [[spec#SC-005]]
**Acceptance criteria**:
- [ ] `deps-core::lsp_helpers::git_ref::ResolvedShaPin` gets `#[derive(RedactingDebug)]` (`#[redact(key)]` on `display_name`, `#[raw]` on `version_range`/`replacement`); hand-written impl deleted
- [ ] `ResolvedChain` verified as conditionally-redacted, left untouched, documented in spec's Out of Scope
- [ ] Both actually-migrated types' (`PackageSourceEntry`, `ResolvedShaPin`) `debug_redaction_conformance!` tests pass (revised SC-003)
- [ ] `cargo +nightly fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo nextest run --workspace --all-features --no-fail-fast` passes
- [ ] `cargo test --workspace --doc --all-features` passes (including the T005 `compile_fail` doctest and T007's derive doctest)
- [ ] `RUSTFLAGS="-D warnings" RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` passes
- [ ] SC-005 retracted (see spec) — no tree-shape check needed; `deps-core-macros` presence in every crate's tree is expected and accepted
- [ ] `CHANGELOG.md`'s `[Unreleased]` section gets one line for this feature
- [ ] Follow-up issue filed (P4, `testing-infra` + `type/refactor` labels) per spec's revised Open Question — covering the remaining ~26 plain structs, the tuple-struct-wrapper types (`AuthToken` ×3, `NuGetAuth`, `RedactedSecret`), and the enum/conditional-field types (`HostRef`, `ResolvedChain`, `DepsError` and siblings), each flagged with which future derive extension it would need
**Dependencies**: T001, T002, T003, T004, T005, T009, T010, T011
**Files**: `crates/deps-core/src/lsp_helpers/git_ref.rs`, `CHANGELOG.md`
**Complexity**: medium

---

## Implementation Notes

### Order of execution

The `ParseError` half (T000-T005) and the `RedactingDebug` half (T006-T011) have no code
dependency on each other and can run in parallel work-streams if split across two
implementers; T012 is the join point that verifies both halves together. Within the
`ParseError` half, T002-T005 are independent of each other once T000 lands and can run in any
order or in parallel.

### Common patterns

- Mirror `DepsError::rate_limited`'s existing doc-comment and doctest shape exactly for
  `DepsError::parse_error` (T000) — reviewers will expect the same shape for the same pattern.
- Mirror `debug_redaction_conformance!`'s own doc comment's `mod example { ... }` wrapping
  pattern for the new derive's doctest (T007) — see that macro's doc for why a bare `#[test]`
  fn body would be silently elided in a doctest otherwise.
- Every `ParseError { .. }` -> `DepsError::parse_error(..)` substitution (T001-T005) should be
  a pure syntactic swap — same `file_type` string, same underlying error value passed as
  `&e`/`&err` (whatever the local binding is named) instead of pre-wrapped in `Box::new(...)`.

### Gotchas

- T005's `compile_fail` doctest must fail for the *right* reason (E0639, not-visible-outside-crate
  construction) — a doctest that merely fails to compile for an unrelated reason (e.g. a typo)
  would still "pass" trybuild/doctest tooling's compile-fail check without proving anything.
  Include the expected error text in the doctest's surrounding prose if the doctest harness
  supports asserting on it, or add a plain-English comment stating the intended failure mode
  for a human reviewer to verify.
- T007/T009: `syn` 3.0's API differs from widely-copied `syn` 2.x tutorial code online — consult
  `syn = "3.0.6"`'s own docs.rs page during implementation rather than assuming an older API
  shape (plan's Risks table).
- T010/T011/T012: if a field's redaction turns out not to cleanly fit `#[redact(url)]`/
  `#[redact(key)]`/`#[raw]` once actually attempted, drop that type from the batch and add it
  to the follow-up-issue list (T012's last acceptance criterion) rather than forcing an
  ill-fitting attribute choice — this was anticipated in the plan's Risks table.

## See Also

- [[spec]] — feature specification
- [[plan]] — technical plan
- [[MOC-specs]] — all specifications

---
aliases:
  - Redaction Enforcement Guardrails
  - RedactingDebug Derive
  - ParseError Constructor Guard
tags:
  - sdd
  - spec
  - security
  - testing-infra
  - deps-core
created: 2026-09-23
status: draft
related:
  - "[[constitution]]"
  - "[[041-credential-redaction-hardening/spec|Credential Redaction Hardening]]"
  - "[[045-secret-accessor-auditable-naming/spec|Secret Accessor Auditable Naming]]"
  - "[[054-redacted-url-structural-chokepoint/spec|RedactedUrl Structural Chokepoint]]"
---

# Feature: Redaction Enforcement Guardrails (compile-time `Debug` redaction + `ParseError` construction guard)

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: `feat/1250-redaction-enforcement-guard`
> **Issues**: #1238 (Debug-redaction enforcement gap), #1250 (`ParseError` construction gap)
> **Priority**: P4 (testing-infra / security hardening — no live leak today, closes a
> recurrence-prone gap)

## 1. Overview

### Problem Statement

This project has swept the same CWE-532 (cleartext credential exposure via `Debug`/error
text) leak class **nine times**: #936, #935, #1217, #1219, #1220, #1221, #1225, #1222, and
most recently the `ParseError`-construction variant found independently twice (#1243, #1249)
after the original fix (#1240/#1241). Both recurring gaps share one root cause — *a safe
helper exists, but nothing forces a new call site to use it* — at two different layers:

1. **`Debug`-derive layer (#1238).** `deps_core::conformance::debug_redaction_conformance!`'s
   exhaustive-literal invocation contract forces a new field to be *named* in the test, but
   does not force it to be *redacted correctly* — a field can be named and left raw, and the
   macro's `$planted` count is a manually-maintained aggregate that does not verify *which*
   field produced a redacted occurrence. Each of the ~35 manual `Debug` impls found across the
   workspace during this spec's research (`grep -rn 'impl std::fmt::Debug for' crates/*/src`)
   hand-writes its own `debug_struct`/`debug_tuple` chain, so a fix to one does not propagate.
2. **`ParseError`-construction layer (#1250), one layer below #1238.** `DepsError::ParseError`'s
   `source: Box<dyn std::error::Error + Send + Sync>` field compiles with any construction —
   nothing stops a new ecosystem crate from hand-rolling
   `Box::new(std::io::Error::other(e.to_string()))` instead of routing through
   `parse_error_source(&e)`/`redact_parse_error_for_log`. This is not hypothetical: `#1243` and
   `#1249` are two independent sweeps that found this exact pattern reintroduced at new call
   sites (`quick_xml`) after the original fix shipped.

The codebase already has a **precedented, working answer for gap 2's shape**: the
`DepsError::RateLimited` variant (added in #1295) carries its own variant-level
`#[non_exhaustive]`, and the only way to construct it from outside `deps-core` is the public
`DepsError::rate_limited(message, verified)` constructor — an external `RateLimited { .. }`
struct literal does not compile. `ParseError` currently has no such guard.

Gap 1 has no equivalent precedent in this workspace: there is no proc-macro crate anywhere in
the dependency tree (`syn`/`quote`/`proc-macro2` — zero hits workspace-wide), and the entire
`conformance.rs` test-scaffolding layer is deliberately built on `macro_rules!` alone. Per this
spec's clarification round, the project has chosen to accept that one-time tooling cost anyway
in exchange for a genuine compile-time guarantee (a `#[derive(RedactingDebug)]` proc-macro)
rather than a further-strengthened but still test-time-only `macro_rules!` check.

### Goal

1. `DepsError::ParseError` cannot be hand-constructed with a raw, unredacted `source` from
   outside `deps-core` — mirroring the `RateLimited` pattern exactly: variant-level
   `#[non_exhaustive]` + a public `DepsError::parse_error(file_type, source) -> Self`
   constructor that internally calls `parse_error_source`. Every existing external `ParseError { .. }`
   construction site (~20+ across ecosystem crates per #1243's audit) is migrated to the new
   constructor.
2. A new `#[derive(RedactingDebug)]` proc-macro exists (new crate, see [[#3-data-model]]) that:
   - Requires every field of a struct it's applied to to carry exactly one of
     `#[redact(url)]`, `#[redact(key)]`, or `#[raw]` — an unannotated field is a **compile
     error**, closing #1238 Finding 1 for real (not just "named in a test").
   - Generates the struct's `Debug` impl itself, so the hand-written `debug_struct` chain is
     deleted at each migrated call site — closing #1238 Finding 2 for the migrated subset.
3. The derive is applied to an initial batch of plain-struct manual `Debug` impls identified in
   this spec's research (see [[#3-data-model]]'s migration table) as a proof of the mechanism
   and to retire that many hand-written impls immediately. Enum types with branch-conditional
   redaction logic are explicitly deferred (see Out of Scope) — the original #1236 review
   judgment that a generic macro would add indirection for these still holds, and this spec's
   research confirms most of the ~35 impls found are structs, not enums.
4. `debug_redaction_conformance!` keeps working unchanged for any type not yet migrated to the
   derive (including the deferred enums) — this spec does not remove or weaken the existing
   test-time safety net, it adds a compile-time one on top for the migrated subset.

### Out of Scope

- **Enum types** with per-variant or branch-conditional redaction (e.g. `DepsError` itself,
  `ResolvedSource`, `DependencySource`, `BlockedSourceClass`, `CatalogOutcome`, `ScanTarget`,
  `CatalogOrigin`, and — found during implementation — `deps-gitlab-ci::types::HostRef`, a
  4-variant enum originally miscategorized as a struct in this spec's first draft) — the
  derive's per-field attribute model does not fit a type whose redaction depends on which
  variant is active. Left on the existing `debug_redaction_conformance!` test-time path. A
  follow-up issue should be filed if a future sweep shows this is still not enough for
  enum-shaped types.
- **Migrating every one of the ~35 existing manual struct `Debug` impls** in one PR — this spec
  scopes an initial batch (see migration table) sized to prove the mechanism without an
  omnibus PR; remaining structs are tracked as a follow-up (a new low-priority issue, filed at
  PR time) rather than blocking this feature's ship.
- **Applying `#[non_exhaustive]` + a constructor to any `DepsError` variant other than
  `ParseError`** — `RateLimited` already has this; other variants are out of scope for this
  spec unless a future issue documents the same construction-bypass risk for them specifically.
- **A workspace-level clippy lint or `xtask` source-scan** (#1250's Option 2) — superseded by
  the constructor-based compile-time fix; not pursued in parallel.
- **Generic/tuple-struct support in the derive's first version** — scoped to structs with named
  fields only. Tuple structs (`RedactedUrl`/`RedactedName`, already collapsed into
  `RedactedText<K>` per #1316) are not migration targets here.
- **Fields whose redaction treatment is conditional on another field's runtime value** (found
  during implementation, not anticipated when this migration table was first drafted) — e.g.
  `deps-pypi::config::ResolvedChain`'s `key` field is redacted as a URL only when its sibling
  `key_shape` field is `KeyShape::Url`, left as-is (never `RedactedUrl`-wrapped) when
  `KeyShape::Opaque`, since redacting an opaque routing token would collapse it to an
  information-free `"pypi-chain:***"`. The derive's static per-field attribute model has no way
  to express this branch. Same category of gap as the enum case above, just surfacing on a
  struct. Left on `debug_redaction_conformance!`.
- **Single-field tuple structs wrapping `deps_core::secret::Redacted`** (found during
  implementation) — `AuthToken` (×3: `deps-cargo`, `deps-core::github`, `deps-gitlab-ci`),
  `NuGetAuth`, `RedactedSecret` (`deps-nuget`) are all `Self(Redacted)`, not named-field
  structs, so FR-004's "named fields" requirement excludes them outright (they were
  incorrectly assumed to be named-field structs when this spec was first drafted, from a grep
  for "manual Debug impl + redaction helper" without checking field shape). A future
  `#[derive(RedactingDebug)]` extension for single-field tuple structs wrapping an
  already-safe type could pick these up cheaply, but that is new derive scope, not a
  migration-batch adjustment — left as a follow-up idea, not committed here.

## 2. User Stories

### US-001: A new credential-shaped field cannot silently ship unredacted

AS A developer adding a new field to a struct already covered by `#[derive(RedactingDebug)]`
I WANT the build to fail until I annotate the field's redaction treatment
SO THAT the ninth-sweep-shaped bug (a field silently missing redaction) cannot recur for any
type migrated to the derive

**Acceptance criteria:**
```
GIVEN a struct annotated `#[derive(RedactingDebug)]`
WHEN a new field is added without a `#[redact(url)]`, `#[redact(key)]`, or `#[raw]` attribute
THEN `cargo build` fails with a clear compile error naming the field
```
```
GIVEN a struct annotated `#[derive(RedactingDebug)]` with a field marked `#[redact(url)]`
WHEN that field holds a `user:pass@host` credential and the value is formatted with `{:?}`
THEN the rendered output redacts the credential the same way `RedactedUrl`'s existing `Debug`
     does today (`***@host`), with no regression vs. the hand-written impl it replaces
```

### US-002: A new ecosystem crate cannot hand-construct an unredacted `ParseError`

AS A developer implementing a new ecosystem crate (or a new parse-error site in an existing one)
I WANT `DepsError::ParseError` to be unconstructable except through a helper that always
redacts
SO THAT the #1240/#1243/#1249 pattern (copying an old, unfixed `Box::new(...)` shape) cannot
compile

**Acceptance criteria:**
```
GIVEN external code outside the `deps-core` crate
WHEN it attempts `DepsError::ParseError { file_type, source }` as a struct literal
THEN this fails to compile (E0639, `#[non_exhaustive]` variant construction outside its
     defining crate)
```
```
GIVEN external code outside `deps-core`
WHEN it calls `DepsError::parse_error(file_type, &e)`
THEN the returned error's `source` is redacted exactly as `parse_error_source(&e)` produces
     today, and every existing internal call site that previously hand-built the variant now
     goes through this constructor
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `DepsError::ParseError` SHALL carry `#[non_exhaustive]` at the variant level. | must |
| FR-002 | `deps-core` SHALL expose `pub fn DepsError::parse_error(file_type: impl Into<String>, source: &dyn std::fmt::Display) -> Self` that internally calls `parse_error_source`. | must |
| FR-003 | WHEN an existing call site constructs `DepsError::ParseError { .. }` directly with a manually-redacted or already-safe source THE SYSTEM SHALL migrate that call site to `DepsError::parse_error(..)` wherever it is a `deps-core`-external crate (all ecosystem crates, `deps-lsp`, `deps-cli`). | must |
| FR-004 | A new proc-macro crate SHALL provide `#[derive(RedactingDebug)]`, usable on structs with named fields. | must |
| FR-005 | WHEN `#[derive(RedactingDebug)]` is applied to a struct THE SYSTEM SHALL require every field to carry exactly one of `#[redact(url)]`, `#[redact(key)]`, `#[raw]` — an unannotated field, or a field with more than one such attribute, SHALL fail to compile with a `syn`/`proc-macro2` diagnostic naming the field and the struct. | must |
| FR-006 | `#[redact(url)]` SHALL delegate the field's rendering to the same logic `RedactedUrl`/`net_policy::redact_userinfo` uses today (or their post-#1316 `redact::` successors); `#[redact(key)]` SHALL delegate to `redact_declaration_key`'s equivalent; `#[raw]` SHALL render the field with its ordinary `Debug` impl unchanged. | must |
| FR-007 | Every type in the migration batch (see [[#migration-table]]) that is actually a named-field struct with no cross-field conditional redaction SHALL be replaced by `#[derive(RedactingDebug)]`, with its hand-written `impl Debug` block deleted. | must |
| FR-008 | Every migrated struct SHALL keep passing its existing `debug_redaction_conformance!` test unchanged (same probes, same assertions) — the derive is a drop-in replacement for the hand-written impl's output, not a change to what "correctly redacted" means. | must |
| FR-009 | `debug_redaction_conformance!` SHALL remain available and unchanged for any type not migrated to the derive (deferred enums, and any struct left for the follow-up issue). | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Compile time | The new proc-macro crate is a normal (non-dev) dependency of `deps-core` (needed unconditionally by the `redact_debug` module, not feature-gated). **Revised during implementation**: since `deps-core` is a mandatory dependency of every workspace crate, `deps-core-macros` is unavoidably transitive into `deps-lsp`/`deps-cli` too — this is accepted as a compile-time-only cost (zero runtime footprint), not gated behind a feature, unlike the `test-util`/`lsp-responses` precedents this NFR originally modeled itself on (those gate genuinely optional behavior; the derive's re-export is not optional once any consumer anywhere in the workspace uses it). |
| NFR-002 | Dependency hygiene | New dependencies (`syn`, `quote`, `proc-macro2`) SHALL be pinned in root `[workspace.dependencies]` per project convention, with current versions checked directly against crates.io (context7 MCP is not configured in this project — see project memory). |
| NFR-003 | Security | No migrated type's redacted `Debug` output SHALL regress vs. its current hand-written behavior — verified by keeping every existing `debug_redaction_conformance!` invocation for migrated types passing byte-for-byte equivalent probe assertions. |
| NFR-004 | Backward compatibility | `DepsError::ParseError`'s existing `#[error("failed to parse {file_type}: {source}")]` `Display` text SHALL be unchanged; only construction changes. |
| NFR-005 | Workspace lints | The new proc-macro crate SHALL comply with workspace-level `unsafe_code = "forbid"` — proc-macro code generation itself requires no `unsafe`. |

## 5. Data Model

### `DepsError::ParseError` (gap 2)

```rust
#[non_exhaustive]
ParseError {
    file_type: String,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
},

impl DepsError {
    pub fn parse_error(file_type: impl Into<String>, source: &dyn std::fmt::Display) -> Self {
        Self::ParseError {
            file_type: file_type.into(),
            source: parse_error_source(source),
        }
    }
}
```

### `#[derive(RedactingDebug)]` (gap 1) {#migration-table}

New crate (name: `deps-core-macros`, `proc-macro = true`, path
`crates/deps-core-macros`), re-exported from `deps-core` (e.g.
`pub use deps_core_macros::RedactingDebug;`) so consumers depend on `deps-core` alone, not the
macro crate directly — mirrors how `tower-lsp-server`-style re-exports already work elsewhere
in this workspace.

Field-attribute contract:

| Attribute | Behavior |
|-----------|----------|
| `#[redact(url)]` | Field rendered via the URL-shaped redactor (`RedactedUrl`/`redact::url_for_tracing` post-#1316). |
| `#[redact(key)]` | Field rendered via the key-shaped redactor (`redact_declaration_key` post-#1316). |
| `#[raw]` | Field rendered with its own `Debug` impl, unchanged — explicit opt-out for fields that are genuinely safe (e.g. `bool`, `Option<u16>` status codes). |

Initial migration batch as originally drafted (before implementation verified each type's
actual field shape) and the outcome:

| Type | File | Outcome |
|------|------|---------|
| `AuthToken` (`deps-cargo`) | `crates/deps-cargo/src/config.rs:74` | **Not migrated** — single-field tuple struct wrapping `Redacted`, not a named-field struct (FR-004 excludes it); see Out of Scope |
| `AuthToken` (`deps-core`) | `crates/deps-core/src/github.rs:236` | **Not migrated** — same reason |
| `AuthToken` (`deps-gitlab-ci`) | `crates/deps-gitlab-ci/src/client.rs:52` | **Not migrated** — same reason |
| `NuGetAuth` | `crates/deps-nuget/src/config.rs:270` | **Not migrated** — same reason |
| `RedactedSecret` | `crates/deps-nuget/src/config.rs:312` | **Not migrated** — same reason |
| `PackageSourceEntry` | `crates/deps-nuget/src/config.rs:352` | **Migrated** — genuine named-field struct, fits cleanly |
| `HostRef` | `crates/deps-gitlab-ci/src/types.rs:112` | **Not migrated** — 4-variant enum, misidentified as a struct in the original draft; see Out of Scope |
| `ResolvedShaPin` | `crates/deps-core/src/lsp_helpers/git_ref.rs:687` | **Migrated** — genuine named-field struct, fits cleanly |
| `ResolvedChain` | `crates/deps-pypi/src/config.rs:166` | **Not migrated** — named-field struct, but `key`'s redaction is conditional on the sibling `key_shape` field's runtime value; see Out of Scope |

**Actual migration batch this feature ships: 2 types (`PackageSourceEntry`, `ResolvedShaPin`)**
— still a real proof of the mechanism (FR-004 through FR-006 hold; both types' hand-written
`impl Debug` are deleted and their `debug_redaction_conformance!` tests still pass), just
smaller than originally scoped. The 7 dropped types, plus every other manual struct/enum
`Debug` impl in the workspace, are tracked by a follow-up issue filed alongside this feature's
PR — see [[#9-open-questions]], which now also captures the three distinct *shapes* of gap
found (tuple-struct wrapper, enum, conditional-field) as separate future derive-extension
ideas rather than one undifferentiated backlog.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A field's type already returns a pre-redacted value (e.g. a `RedactedUrl`-typed field) | Use `#[raw]` — the field's own `Debug` is already safe; double-redaction is not the derive's job to detect (documented in the derive's doc comment as author responsibility, same trust boundary `debug_redaction_conformance!` already has today). |
| A struct has zero fields, or is a tuple struct | Derive macro emits a compile error directing the author to a hand-written impl or `#[raw]`-only named-field struct; tuple structs are out of scope (see Out of Scope). |
| A struct field is itself another `#[derive(RedactingDebug)]` struct (nesting) | Supported transitively — nested field renders via its own derived `Debug`, no special-casing needed since the derive only ever calls `Debug::fmt` on the field's rendered form. |
| An ecosystem crate outside `deps-core` still has an old, un-migrated `ParseError { .. }` construction after this ships | Fails to compile (E0639) — this is the intended forcing function; migration must be complete for every external call site before merge (FR-003). |
| External code obtains `&mut DepsError::ParseError` and mutates `source` directly (found during security review, #1250) | `#[non_exhaustive]` blocks a struct-literal *construction* (E0639) but not a `&mut`-destructure *mutation* of an already-constructed value's `pub` fields — `if let DepsError::ParseError { source, .. } = &mut e { *source = ... }` still compiles and can install an unredacted source. Accepted as a residual gap: the accident this guard exists to prevent is a `map_err`-style struct-literal copy-paste, which is blocked; a deliberate `&mut` destructure to inject an unredacted value is not the failure mode observed in #1240/#1243/#1249 and matches the `RateLimited` precedent's own residual surface. Not fixed in this PR. |
| A future PR adds a tenth `ParseError`-like variant to `DepsError` needing the same guard | Not this spec's scope — documented as a pattern to replicate (`RateLimited`, now `ParseError`) rather than generalized into shared machinery, consistent with MVP/no-premature-abstraction project convention. |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | External construction of `DepsError::ParseError { .. }` outside `deps-core` | Does not compile (verified by a `trybuild`-style compile-fail test or doc-test with `compile_fail`) |
| SC-002 | `#[derive(RedactingDebug)]` struct with an unannotated field | Does not compile (verified by a `trybuild` compile-fail test in the new macro crate) |
| SC-003 | Both actually-migrated types' (`PackageSourceEntry`, `ResolvedShaPin`) `debug_redaction_conformance!` tests | Pass unchanged after migration (revised down from the originally-planned 9 — see [[#migration-table]]) |
| SC-004 | Full check suite (`fmt --check`, `clippy -D warnings`, `nextest`, doc gate per `.claude/rules/branching.md`) | Green |
| SC-005 | ~~`cargo tree -p deps-lsp -e features,no-dev` / `-p deps-cli` excludes `deps-core-macros`~~ | **Retracted during implementation**: `deps-core-macros` is a normal (non-optional, non-feature-gated) dependency of `deps-core` itself (T008), and `deps-core` is mandatory for every crate in the workspace, so this criterion was unsatisfiable as written — verified empirically. Acceptable because it is a proc-macro/build-time-only dependency (zero runtime cost), same category as `deps-core`'s other always-on deps (`thiserror`, `serde`). NFR-001 is revised accordingly (see below). |

## 8. Agent Boundaries

### Always (without asking)
- Run the full check suite (`fmt`, `clippy -D warnings`, `nextest`, rustdoc gate) before
  proposing the PR, per `.claude/rules/branching.md`.
- Keep every existing `debug_redaction_conformance!` invocation for migrated types passing.
- Follow existing code style and doc-comment conventions (`///` on every `pub` item, `#
  Examples` doctest on non-trivial public APIs).

### Ask First
- Adding the new proc-macro crate's dependencies (`syn`, `quote`, `proc-macro2`) to root
  `[workspace.dependencies]` — confirm versions against crates.io directly (context7 not
  configured for this project).
- Expanding the migration batch beyond the 9 types listed here.
- Renaming or relocating the new macro crate from `deps-core-macros` if a better name surfaces
  during `/sdd plan`.

### Never
- Modify `debug_redaction_conformance!`'s existing assertions for a type this spec does not
  migrate.
- Touch `crates/deps-zed` (separate submodule/repo).
- Change `DepsError::ParseError`'s `Display` text or any other variant's construction.

## 9. Open Questions

Both prior open items are resolved below (no unresolved `[NEEDS CLARIFICATION]` markers
remain):

- **Migration-batch follow-up**: filed as #1325 (P4, `testing-infra` + `type/refactor`
  labels), linking back to #1238, covering all
  not-yet-migrated redaction-sensitive `Debug` impls found across this feature's research and
  implementation, broken out by the three distinct gap shapes discovered (each needs different
  future derive work, not just "apply the existing derive"):
  1. Remaining plain named-field structs (the ~26 not in the original 9-type batch) — these fit
     the *existing* v1 derive as-is, just weren't migrated in this PR's scope.
  2. Single-field tuple structs wrapping `Redacted` (`AuthToken` ×3, `NuGetAuth`,
     `RedactedSecret`) — would need a future tuple-struct extension to the derive.
  3. Enums with per-variant redaction (`DepsError`, `HostRef`, `ResolvedSource`,
     `DependencySource`, `BlockedSourceClass`, `CatalogOutcome`, `ScanTarget`, `CatalogOrigin`)
     and structs with cross-field conditional redaction (`ResolvedChain`) — would need a
     fundamentally different (non-purely-per-field-static) derive design; likely warrants its
     own `/sdd specify` pass rather than a quick extension, given the design space is genuinely
     open (a match-arm-aware attribute syntax? per-variant sub-derives? not scoped here).
- **Crate name**: `deps-core-macros`, confirmed — no existing crate name collision
  (`crates/*` glob scan shows no such directory today).

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issues: #1238, #1250, #1236, #1240, #1241, #1243, #1249, #1295, #1316, #1325

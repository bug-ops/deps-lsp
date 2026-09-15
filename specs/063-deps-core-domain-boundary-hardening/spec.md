---
aliases:
  - deps-core Domain Boundary Hardening
  - Protocol-Agnostic Domain Types + policy_config Extensibility
tags:
  - sdd
  - spec
  - deps-core
  - architecture
created: 2026-09-15
status: draft
related:
  - "[[constitution]]"
  - "[[../062-cli-check-mode/architecture-decision]]"
---

# Feature: deps-core Domain Boundary Hardening

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: feat/1071-core-domain-boundary-hardening
> **Resolves**: #1071, #1064 (spec 062 §9 O-6)

## 1. Overview

### Problem Statement

Two open architectural questions were deliberately deferred from spec 062
(`specs/062-cli-check-mode/architecture-decision.md` §9) and its follow-up PR
#1070, both explicitly "routed to the user" rather than decided by an
implementing agent:

- **#1071**: `deps_core::Dependency` and `deps_core::lockfile::LockFileCache`
  key their domain data on `tower_lsp_server::ls_types::{Uri, Range,
  Position}`. This forces every consumer of `deps-core` — including the
  upcoming `deps-cli` (#711, already shipping a `check` subcommand as of
  PR #1072/#1078) and the planned `deps-mcp` (#710) — to compile and link the
  full `tower-lsp-server` crate (jsonrpc, `Client`, notification machinery)
  even though neither has an LSP client. `deps-engine`'s own module doc
  frames its classification layer as adapter-agnostic; the domain model it
  wraps is not.
- **#1064 (spec 062 O-6)**: `deps_core::policy_config`'s 7 structs
  (`DiagnosticsConfig`, `CacheConfig`, `FreshnessConfig`,
  `SupplyChainConfig`, `RegistriesConfig`, `NetworkConfig`,
  `LicensePolicyConfig`) are deliberately **not** `#[non_exhaustive]` — every
  other field-heavy config type in this project's `deps-core`/`deps-lsp`
  layers ships that way. The exception exists to keep
  `deps_lsp::config::reparse_scope`'s exhaustive-destructuring security
  guard (issue #592 M1) alive: `#[non_exhaustive]` on a cross-crate type
  would force a `..` rest pattern at the destructure site in `deps-lsp`,
  which would silently defeat the guard. The accepted cost: any future field
  added to one of these 7 structs is a `deps-core` breaking change, when
  before the spec-062 extraction it was a `deps-lsp`-internal edit. Config
  sections here have grown often historically (many `CHANGELOG.md` entries),
  so this is a real, recurring cost.

Both questions were left open rather than guessed at, per this project's
`/sdd` workflow for non-trivial, non-obviously-scoped design decisions. The
user has since decided both:

1. Decouple `deps-core`'s domain model from `tower_lsp_server::ls_types` —
   introduce protocol-agnostic file-identity and position/range types,
   translating to/from LSP types only at the `deps-lsp` adapter boundary.
2. Make `policy_config`'s 7 structs `#[non_exhaustive]` with `new()`/
   `with_*` constructors, replacing `reparse_scope`'s destructuring-refusal
   guarantee with an explicit, compile-time-checked field list that
   preserves the same fail-closed property (a field nobody classified must
   not silently compile).

This spec captures the WHAT/WHY and acceptance criteria for both changes so
`/sdd plan` and `/sdd tasks` can proceed without re-litigating the decision.

### Goal

`deps-core`'s public API no longer requires any consumer to link
`tower-lsp-server` to use its domain types, **and** `deps_core::policy_config`
can gain a new field in a minor release without breaking downstream code,
**without** weakening `reparse_scope`'s existing fail-closed guarantee that a
newly added config field cannot silently ship as "not parse-affecting" by
compiler-forced omission.

### Out of Scope

- Issue #851 (whether third-party dependency types in general — `reqwest::Error`,
  `yaml_rust2::Yaml`, `semver::VersionReq`, ... — should be wrapped across all of
  `deps-core`'s public API) is a broader, separate design question this spec does
  not prejudge; #1071 only covers the LSP-protocol type subset.
- Issue #710 (`deps-mcp` binary vs. `deps-lsp --mcp`) — this spec only removes a
  blocker for that decision, it does not make it.
- Changing `reparse_scope`'s actual scope-classification *decisions* for any
  existing field (which fields map to `ReparseScope::All` vs. a named
  `Ecosystems` set) — only the mechanism that forces every field to be
  classified is being replaced.
- Any `deps-lsp` runtime/wire-format behavior change: `initializationOptions`
  JSON shape is unaffected by both changes; only Rust-level types and
  compile-time guarantees change.
- Actually publishing `deps-cli`/`deps-mcp` on crates.io — this spec only
  removes the `tower-lsp-server` dependency they would otherwise inherit.
- **Fully eliminating `tower-lsp-server` from `deps-cli`'s dependency tree**
  (originally FR-005/SC-001 in the first draft of this spec, before
  implementation began). Discovered empirically during T000: (a)
  `deps-core::lsp_helpers` independently builds real
  `ls_types::{Hover,Diagnostic,CodeAction,...}` response objects — this is
  `deps-core`'s actual LSP-response-generation job and is not being
  redesigned here, so `deps-core`'s `Cargo.toml` keeps `tower-lsp-server`
  unconditionally; (b) `deps-cli` itself, independent of `deps-core`'s domain
  model, already directly imports `ls_types::{Diagnostic,DiagnosticSeverity,
  NumberOrString,Range,Uri}` in its own `report.rs`/`config.rs`/`exit.rs`/
  `walk.rs` (pre-existing, shipped in PR #1072/#1078) — its `check`
  subcommand's finding type is built directly on `ls_types::Diagnostic`.
  Achieving the original FR-005 would require feature-gating
  `deps-core::lsp_helpers`/the `Ecosystem` trait's `generate_*` methods AND
  redesigning `deps-cli::report`'s already-shipped finding type — a much
  larger, separate initiative. The user chose to descope rather than expand
  this PR; tracked as issue #1083.

## 2. User Stories

### US-001: `deps-cli`/`deps-mcp` do not link `tower-lsp-server`

AS A maintainer building `deps-cli` (#711) or the planned `deps-mcp` (#710)
I WANT `deps-core`'s domain types (`Dependency`, `LockFileCache`, hover/diagnostic
position data) to carry no `tower-lsp-server` type in their public signature
SO THAT a non-LSP adapter can depend on `deps-core`/`deps-engine` without compiling
or linking `tower-lsp-server`'s jsonrpc/`Client`/notification machinery

**Acceptance criteria:**
```
GIVEN deps-cli's Cargo.toml depends on deps-core and deps-engine
WHEN `cargo tree -p deps-cli -e features,no-dev` is run
THEN tower-lsp-server does not appear in the dependency tree
```
```
GIVEN deps-lsp still needs to answer real LSP requests with real positions
WHEN a hover/diagnostic/completion response is constructed
THEN deps-lsp converts deps-core's protocol-agnostic position/range/file-identity
     types to tower_lsp_server::ls_types at the deps-lsp adapter boundary,
     with no behavior change visible to an LSP client
```

### US-002: `policy_config` grows without a `deps-core` major bump

AS A developer adding a new policy-relevant config option (e.g. a hypothetical
`network.proxy_url`)
I WANT to add a field to one of `policy_config`'s 7 structs without that alone
forcing a `deps-core` major version bump
SO THAT routine, additive config growth (historically frequent per `CHANGELOG.md`)
stays a normal minor-release change

**Acceptance criteria:**
```
GIVEN a new field is added to any of the 7 policy_config structs
WHEN deps-lsp::config::reparse_scope is not updated to classify it
THEN the build fails to compile (fail-closed), exactly as it does today
```
```
GIVEN the same new field IS explicitly classified in reparse_scope's replacement guard
WHEN deps-core's version is bumped
THEN only a minor bump is required (not major), because the struct's field addition
     alone is not a breaking change under #[non_exhaustive]
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL define file-identity and position/range types in `deps-core` that do not name any `tower-lsp-server`/`tower_lsp_server::ls_types` type in their public signature | must |
| FR-002 | WHEN `deps_core::Dependency`, `deps_core::lockfile::LockFileCache`, and any other public `deps-core` domain type currently typed on `ls_types::{Uri,Range,Position}` are constructed or read THE SYSTEM SHALL use the new protocol-agnostic types instead | must |
| FR-003 | WHEN `deps-lsp` builds an LSP response (hover, diagnostic, completion, code action, code lens, inlay hint) from `deps-core`/`deps-engine` domain data THE SYSTEM SHALL convert the protocol-agnostic types to `tower_lsp_server::ls_types` at that boundary, with no observable change to the wire-level LSP response | must |
| FR-004 | THE SYSTEM SHALL remove `tower-lsp-server` from `deps-engine`'s `Cargo.toml` entirely, since `classify::{resolved,fetch,osv}`'s only use of `ls_types` was the domain-type coupling this spec removes | must |
| FR-005 | ~~WHEN `deps-cli`... SHALL NOT pull `tower-lsp-server`~~ — **descoped** (see "Scope correction" below): `deps-core`'s `Cargo.toml` keeps `tower-lsp-server` as an unconditional dependency after this PR, because `deps-core::lsp_helpers` independently builds real `ls_types::{Hover,Diagnostic,CodeAction,...}` response objects (out of scope to redesign here), and `deps-cli` itself (pre-existing, shipped in PR #1072/#1078) already directly imports `ls_types::{Diagnostic,DiagnosticSeverity,NumberOrString,Range,Uri}` in its own `report.rs`/`config.rs`/`exit.rs`/`walk.rs` independent of `deps-core`'s domain model. Fully removing `tower-lsp-server` from `deps-cli`'s dependency tree requires feature-gating `deps-core::lsp_helpers`/the `Ecosystem` trait's `generate_*` methods AND redesigning `deps-cli::report`'s already-shipped `ls_types`-based finding type — both out of scope for #1071/#1064; tracked as a new follow-up issue instead (not a `[NEEDS CLARIFICATION]` — the user explicitly chose to descope rather than expand this PR) | descoped |
| FR-006 | THE SYSTEM SHALL add `#[non_exhaustive]` to `DiagnosticsConfig`, `CacheConfig`, `FreshnessConfig`, `SupplyChainConfig`, `RegistriesConfig`, `NetworkConfig`, and `LicensePolicyConfig` | must |
| FR-007 | THE SYSTEM SHALL provide a `new()` and/or `with_*` builder-style constructor for each of the 7 structs in FR-006, following this project's existing `#[non_exhaustive]` config pattern (e.g. `deps-lsp::config::InlayHintsConfig`) | must |
| FR-008 | THE SYSTEM SHALL replace `reparse_scope`'s reliance on exhaustive-destructuring-without-`..`  as its completeness guard with an explicit mechanism that still causes a compile-time failure when a field on any of the 7 structs (or `PolicyConfig`/`DepsConfig` themselves) is added without an explicit reparse-scope classification | must |
| FR-009 | THE SYSTEM SHALL preserve `reparse_scope`'s current fail-closed property: an unclassified field must block compilation, not silently default to "not parse-affecting" or `ReparseScope::All` | must |
| FR-010 | THE SYSTEM SHALL keep `initializationOptions`' accepted JSON shape unchanged for both changes (FR-001..FR-009) — this is a Rust-API-only and compile-time-guarantee-only change set | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Compatibility | Both changes are breaking changes to `deps-core`'s public API. Since the project has not yet cut the v1.0.0 release (`CHANGELOG.md` still under `[Unreleased]`), no major-version bump is required now; each change gets a clearly labeled "Breaking" `CHANGELOG.md` entry per the project's pre-1.0 batching convention (see spec 062's own precedent) |
| NFR-002 | Performance | The protocol-agnostic file-identity/position types must not add a measurable hover/completion latency regression — conversion at the `deps-lsp` boundary is O(1) per request, no additional allocation beyond what `ls_types` construction already requires |
| NFR-003 | Cross-ecosystem consistency | Every one of the 14 ecosystem crates constructing `Dependency` (or any other affected domain type) must be updated in the same change — a partial migration leaving some ecosystems on `ls_types` directly is a constitution principle-1 violation |
| NFR-004 | Security | The replacement completeness guard for `reparse_scope` (FR-008) must be exercised by a test that adds a field to a stand-in/real config struct and asserts a compile failure (or an equivalent guaranteed-detection mechanism) occurs when that field is not classified — mirroring the existing `reparse_scope_tests` module's intent (issue #592 security M1) |
| NFR-005 | Documentation | `deps-core/src/lib.rs`'s "API stability (issue #769)" section and `policy_config.rs`'s module doc (which currently explains *why* these 7 structs are exhaustive) must both be updated to reflect the new state instead of left describing the superseded design |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `url::Url` | Replaces `ls_types::Uri` as the domain-level file identity in `Dependency`/`LockFileCache` | Already a workspace dependency (2.5); `Hash`/`Eq`/`Ord`/`Display`/`FromStr`/`from_file_path`/`to_file_path` all already exist — no new type needed. Conversion to/from `tower_lsp_server::ls_types::Uri` is a pair of free functions in `deps-lsp` (not a trait impl — avoids the orphan-rule conflict a `From` impl would hit, since neither `url::Url` nor `ls_types::Uri` is local to `deps-lsp`) |
| `deps_core::position::{Position, Range}` | New protocol-agnostic replacement for `ls_types::{Position,Range}` | Same `line`/`character` (`u32`) shape `ls_types::Position` already exposes; conversion to/from `ls_types` types is likewise a pair of free functions in `deps-lsp` |
| `PolicyConfig` and its 7 sections | Existing entity, gains `#[non_exhaustive]` + constructors | No new fields introduced by this spec — only the attribute and constructor API surface change |
| `PolicyConfig::diff`/`PolicyConfigDiff` (naming TBD in plan.md's data model) | Replaces `reparse_scope`'s cross-crate exhaustive destructuring | A `deps-core`-internal, same-crate exhaustive destructuring (unaffected by `#[non_exhaustive]`, which only restricts *other* crates) produces a small, deliberately non-`#[non_exhaustive]` diff/signal value that `deps-lsp::config::reparse_scope` consumes and maps to a `ReparseScope` — preserving the fail-closed compile error (E0027) when a new field is added to `deps-core` without updating this same-crate diff function |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| An ecosystem crate constructs `Dependency` with a raw `ls_types::Uri` it obtained some other way (e.g. from a cached value) | Must go through the new protocol-agnostic type's conversion path; no ecosystem crate should gain a second, ad hoc way to embed an `ls_types::Uri` into domain data (constitution principle 1) |
| A future contributor adds an 8th field to one of the 7 `policy_config` structs and does not touch `reparse_scope` at all | Compilation must fail — this is the primary regression this spec must not introduce |
| A future contributor adds a field to `policy_config` and classifies it in the new guard mechanism, but picks the wrong `ReparseScope` (e.g. `Ecosystems(["cargo"])` for a field that actually affects all ecosystems) | Out of scope for this spec (same limitation `reparse_scope`'s doc already calls out: "the compile error forces *a* decision, it does not make the *safe* decision for you") |
| `deps-cli`/`deps-mcp` need to construct a domain `Dependency` from a filesystem path with no LSP context at all (no editor open) | Must be possible using only the new protocol-agnostic type, with no `tower_lsp_server::ls_types::Uri` roundtrip required |
| CI's existing `deps-lsp` "no ecosystem crate is a direct non-dev dependency" guard (added for #1073, PR #1079) | Joined by an equivalent guard asserting `deps-engine` does not pull in `tower-lsp-server`, per FR-004 (descoped from `deps-cli`/`deps-mcp` — see FR-005) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `cargo tree -p deps-engine -e features,no-dev \| grep tower-lsp-server` (descoped from `deps-cli` — see FR-005) | No match |
| SC-002 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passes with zero warnings after both changes land |
| SC-003 | `cargo nextest run --workspace --all-features --no-fail-fast` | All existing tests pass; `reparse_scope_tests` (or its renamed/relocated equivalent) still proves the fail-closed property |
| SC-004 | A compile-fail test/trybuild case (or equivalent) proves an unclassified new `policy_config` field breaks the build | Present and passing |
| SC-005 | Manual live-test: hover/diagnostics for at least 2 ecosystems (e.g. Cargo, npm) produce byte-identical LSP responses before/after the domain-type change | Confirmed via `RUST_LOG=debug` live session per `.claude/rules/continuous-improvement.md` |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing `#[non_exhaustive]` + constructor conventions already used elsewhere in this codebase (e.g. `InlayHintsConfig`)
- Update all 14 ecosystem crates in the same change set for FR-002/NFR-003 — no partial migration
- Update `CHANGELOG.md` with clearly labeled "Breaking" entries for both changes
- Run the full local check suite (`fmt --check`, `clippy -D warnings`, `nextest`, rustdoc gate) before considering either change done

### Ask First
- Any deviation from the type/mechanism decisions recorded in `plan.md` (`url::Url` for file identity, `deps_core::position::{Position,Range}`, the `deps-core`-internal diff API for `reparse_scope`, folding `deps-engine` into the same PR) — these were resolved with the user before planning and should not be silently re-decided during implementation

### Never
- Silently pick a `ReparseScope` classification for a config field this spec does not explicitly name — every existing field keeps its current, already-shipped classification
- Weaken or remove `reparse_scope`'s fail-closed guarantee to make the refactor easier
- Touch `crates/deps-zed` (separate submodule/repo) as part of this change

## 9. Open Questions

All three plan-level questions raised in the initial draft of this spec were
resolved with the user before `/sdd plan`; see `plan.md` for the resulting
design:

- ~~exact type names/shapes for the protocol-agnostic file-identity and
  position/range types~~ → resolved: `url::Url` (already a workspace
  dependency) for file identity, a new `deps_core::position::{Position,
  Range}` pair for LSP position data.
- ~~exact mechanism for `reparse_scope`'s replacement completeness guard~~ →
  resolved: a `PolicyConfig::diff`/`DepsConfig`-level diff API inside
  `deps-core` that performs the exhaustive, `..`-free destructuring
  same-crate (where `#[non_exhaustive]` does not restrict it), exposing a
  small, deliberately non-`#[non_exhaustive]` diff/signal type that
  `deps-lsp::config::reparse_scope` consumes.
- ~~whether `deps-engine`'s direct `tower-lsp-server` dependency is folded
  into this same PR~~ → resolved: yes, same PR (it is a direct consequence
  of `Dependency`'s field types changing).

## 10. See Also

- [[../062-cli-check-mode/architecture-decision|spec 062 architecture decision]] — §9 O-6, the origin of #1064
- [[constitution]] — project principles (1, 2, 7, 8 all bear on this spec)
- [[MOC-specs]] — all specifications
- Issue #1071, #1064, #592, #711, #710, #769, #851, #1073

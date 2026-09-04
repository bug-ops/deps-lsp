---
aliases:
  - Auditable Secret Accessor Naming
  - expose_secret() Rename
tags:
  - sdd
  - spec
  - security
  - deps-core
  - deps-cargo
  - deps-nuget
created: 2026-09-04
status: draft
related:
  - "[[constitution]]"
  - "[[041-credential-redaction-hardening/spec|Redact user:pass@ credentials from registry-index logs and errors]]"
---

# Feature: Rename Secret-Exposing `as_str()` Accessors to an Auditable Name

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Priority**: P3
> **Type**: enhancement (research-driven, best-practice parity)

## 1. Overview

### Problem Statement

PR #577 (commit `5d4d2682`) consolidated four hand-rolled secret-redaction wrapper types
into a single `deps_core::secret::Redacted<T>` (`crates/deps-core/src/secret.rs`), backed
by `zeroize::Zeroizing<T>`. The module's own doc comment (lines 1-17) frames its purpose as
preventing a credential from "leak[ing] via a log line" and being "the one place that
pattern is implemented, so ... call sites cannot silently diverge on it."

The one method that actually exposes the raw secret plaintext — `Redacted::as_str()` — is
named identically to the workspace's most common string-conversion method. Verified via
direct inspection (2026-09-04) of every type embedding `Redacted`
(`grep -rn "secret::Redacted" crates/*/src/*.rs`), four wrapper types embed it:

| Type | Location | Accessor name | Visibility |
|------|----------|----------------|------------|
| `deps_core::secret::Redacted<T>` | `crates/deps-core/src/secret.rs:54` | `as_str()` | `pub` |
| `deps_core::github::AuthToken` | `crates/deps-core/src/github.rs:154` | `as_str()` | private (module-internal) |
| `deps_cargo::config::AuthToken` | `crates/deps-cargo/src/config.rs:69` | `as_str()` | `pub(crate)` |
| `deps_nuget::config::RedactedSecret` | `crates/deps-nuget/src/config.rs:275` | `as_str()` | private (module-internal) |
| `deps_nuget::config::NuGetAuth` | `crates/deps-nuget/src/config.rs:233` | `header_value()` | `pub(crate)` |

`NuGetAuth` already deviates from `as_str()` (it uses `header_value()`), which is
independent precedent that a distinctive accessor name is both feasible and already
tolerated by the codebase's own conventions — it just was not applied consistently to the
other three secret-wrapper accessors.

> [!note] Correction to the initiating finding
> The finding that triggered this spec counted "5 total definitions" via
> `grep -n "fn as_str" crates/deps-core/src/github.rs crates/deps-cargo/src/config.rs
> crates/deps-nuget/src/config.rs`. That grep also matches two **non-secret** `as_str()`
> methods that happen to live in the same files: `deps_cargo::config::RegistryIndex::as_str`
> (`config.rs:241`, returns a validated registry-index URL) and
> `deps_nuget::config::NuGetFeedUrl::as_str` (`config.rs:152`, returns a normalized feed
> URL) — neither wraps a `Redacted<T>` or returns credential plaintext. Verified scope is
> **4** secret-exposing accessors named `as_str()` (the table above, excluding
> `NuGetAuth::header_value`), not 5. This does not change the finding's core claim: three of
> the four are indistinguishable-by-name from the 496 unrelated `.as_str()` calls elsewhere
> in the workspace (`grep -rn "\.as_str()" crates/*/src/*.rs | wc -l`, verified 2026-09-04).

This defeats the auditability goal the module doc implies exists: a reviewer or a future
automated check (e.g. a CI grep-based lint, or a `clippy` disallowed-method-with-exception
rule) cannot isolate "every place a secret's plaintext crosses a wrapper boundary" by name
alone.

### Goal

Every accessor that returns a wrapped secret's raw plaintext is named distinctly from
ordinary string-conversion methods, so a single workspace-wide search (grep, IDE
"find usages", or a future automated lint) finds every secret-exposure boundary crossing
without also matching unrelated `.as_str()` call sites.

### Out of Scope

- Adopting the `secrecy` crate itself. `deps-lsp` deliberately built its own `Redacted<T>`
  rather than depending on `secrecy` (per #573/#574/#577's history) — this spec proposes
  adopting only `secrecy`'s `ExposeSecret::expose_secret()` **naming convention**, not the
  crate or its trait mechanics.
- Renaming `NuGetAuth::header_value()` — it is already distinctly named and out of the
  naming-collision problem this spec addresses; renaming it is optional polish, not part of
  the acceptance criteria (see Open Questions).
- Any change to `Redacted<T>`'s `Debug`/`Display`/`Hash`/`Eq`/zeroize behavior — this spec
  is a rename only, no behavioral change.
- Introducing a CI lint/grep gate that enforces the naming convention going forward — worth
  a follow-up spec once the rename lands, not bundled here.

## 2. User Stories

### US-001: Reviewer can grep for every secret-exposure boundary crossing

AS A code reviewer or security auditor of `deps-lsp`
I WANT the method that returns a wrapped secret's raw plaintext to have a name that is
unique across the workspace (not shared with ordinary string conversions)
SO THAT `grep -rn "expose_secret\(\)"` (or equivalent) returns exactly the set of places a
secret's plaintext leaves its wrapper, with no manual filtering of unrelated hits

**Acceptance criteria:**
```
GIVEN the renamed accessor(s) are in place
WHEN a reviewer runs a workspace-wide grep for the new accessor name
THEN the result set is exactly the secret-exposure call sites (four, per the table above,
  or however many remain in scope per the Open Questions) and contains zero unrelated
  ordinary-string-conversion hits
```

### US-002: Existing call sites keep compiling with no behavioral change

AS A maintainer of `deps-core`, `deps-cargo`, and `deps-nuget`
I WANT the rename to be a pure signature/name change
SO THAT no caller's runtime behavior, redaction guarantee, or zeroize-on-drop behavior
changes as a side effect of this refactor

**Acceptance criteria:**
```
GIVEN all call sites of the renamed accessor(s) are updated in the same change
WHEN the workspace is built and tested
THEN `cargo build --workspace --all-features` and
  `cargo nextest run --workspace --all-features` pass with no behavioral test changes
  required beyond the rename itself
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `deps_core::secret::Redacted::as_str` SHALL be renamed to `expose_secret()`, mirroring the `secrecy` crate's `ExposeSecret::expose_secret()` naming convention — the most discoverable, "borrowed convention, not reinvented" choice (resolved, see Open Questions) | must |
| FR-002 | Every wrapper type's `as_str()` accessor that delegates to `Redacted::as_str` (`deps_core::github::AuthToken`, `deps_cargo::config::AuthToken`, `deps_nuget::config::RedactedSecret`) SHALL be renamed to `expose_secret()` (FR-001), for naming consistency across the workspace | must |
| FR-003 | All call sites of the renamed accessor(s) SHALL be updated in the same change — no dual old/deprecated-name period (per this project's pre-v1.0.0 no-backward-compatibility convention) | must |
| FR-004 | The rename SHALL NOT alter `Redacted<T>`'s `Debug`, `Display`, `PartialEq`, `Eq`, `Hash`, or `ZeroizeOnDrop` behavior | must |
| FR-005 | `deps_nuget::config::NuGetAuth::header_value` SHALL be left as-is, not renamed — it is already distinctly named, sits outside the naming-collision problem this spec addresses, and its name additionally documents *how* the value must be used (resolved, see Open Questions) | should |
| FR-006 | The doc comment on the renamed accessor SHALL state explicitly that its name is chosen for auditability/greppability, mirroring the rationale given in `secrecy::ExposeSecret`'s documentation | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Auditability | A single workspace-wide grep for the new accessor name returns exactly the secret-exposure call sites, with zero false positives from unrelated `.as_str()` usage |
| NFR-002 | Consistency | All wrapper types embedding `Redacted<T>` use the identical accessor name (excluding any explicitly-scoped exception per FR-005) |
| NFR-003 | No behavioral regression | Existing redaction (`Debug`/`Display` → `***`) and zeroize-on-drop guarantees are unaffected; verified by the existing `secret.rs` unit tests continuing to pass unmodified except for the renamed method call |
| NFR-004 | Compile-time safety | Rename is enforced by the compiler (every call site must be updated to build) — no runtime-only convention that could silently regress |

## 5. Data Model

No new entities. This is a rename of existing accessor methods; no field, struct, or trait
shape changes.

| Entity | Description | Change |
|--------|-------------|--------|
| `Redacted<T>::as_str` (existing) | Returns the wrapped secret's raw `&str` | Renamed to the chosen auditable name (FR-001) |
| `deps_core::github::AuthToken::as_str` (existing) | Delegates to `Redacted::as_str` for the GitHub bearer-token header value | Renamed in lockstep (FR-002) |
| `deps_cargo::config::AuthToken::as_str` (existing) | Delegates to `Redacted::as_str` for the Cargo registry-token header value | Renamed in lockstep (FR-002) |
| `deps_nuget::config::RedactedSecret::as_str` (existing) | Delegates to `Redacted::as_str` for a pre-`%ENV_VAR%`-expansion literal | Renamed in lockstep (FR-002) |
| `deps_nuget::config::NuGetAuth::header_value` (existing) | Delegates to `Redacted::as_str` for the pre-formatted `Basic` auth header | Unchanged, or renamed per FR-005's open decision |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A call site outside the four in-scope files calls `Redacted::as_str` today | None found — verified via `grep -rn "secret::Redacted" crates/*/src/*.rs`; the rename's blast radius is limited to the four files listed in section 1's table plus their respective call sites within `deps-core`, `deps-cargo`, `deps-nuget` |
| Doc-test in `secret.rs`'s module doc (`# Examples` block, line ~35) references `token.as_str()` | Must be updated in the same change — `cargo test --doc` would otherwise fail to compile |
| A future fifth ecosystem crate adds its own `Redacted`-wrapping type before this rename lands | Out of scope for this spec's acceptance criteria, but should adopt the new name directly rather than `as_str()`, per the constitution's DRY/consistency principle |
| `NuGetAuth::header_value()` is left unrenamed (FR-005 resolved as "leave as-is") | Acceptable — it is already distinctly named and does not collide with the 496 unrelated `.as_str()` hits; the auditability goal (US-001) is still met by renaming the other four |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `grep -rn "fn as_str" crates/deps-core/src/secret.rs crates/deps-core/src/github.rs crates/deps-cargo/src/config.rs crates/deps-nuget/src/config.rs` | Zero hits for the four in-scope secret-exposing accessors after rename (the two non-secret `as_str()` methods — `RegistryIndex::as_str`, `NuGetFeedUrl::as_str` — are correctly excluded and remain unchanged) |
| SC-002 | Full CI suite (`cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate) | Green after rename, no behavioral test changes needed beyond updating the renamed method name in existing test bodies |
| SC-003 | `grep -rn "<chosen-name>\(\)" crates/*/src/*.rs \| wc -l` | Equals the number of in-scope accessor definitions plus their call sites — a small, auditable count, in contrast to today's 496 `.as_str()` hits |

## 8. Agent Boundaries

### Always (without asking)
- Update every call site of a renamed accessor in the same commit/PR — no partial rename.
- Update the doc-test example in `secret.rs`'s module doc to use the new name.
- Run the full local CI-matching check suite before proposing the change is complete.

### Ask First
- Whether to also rename `NuGetAuth::header_value()` (FR-005) — confirm with the maintainer
  before deciding, since it is already outside the naming-collision problem.
- Introducing any new public API surface beyond a rename (e.g. a new trait mirroring
  `secrecy::ExposeSecret` instead of a plain inherent method) — this spec assumes an
  inherent-method rename, not a trait, unless discussed.

### Never
- Depend on the `secrecy` crate as part of this change — explicitly out of scope (see
  section 1, Out of Scope).
- Leave a deprecated/dual-named `as_str()` alias around "for compatibility" — this project
  does not maintain backward compatibility pre-v1.0.0.
- Rename any of the two non-secret `as_str()` methods identified in the correction note
  (`RegistryIndex::as_str`, `NuGetFeedUrl::as_str`) — they are unrelated string conversions,
  not secret accessors, and renaming them would be scope creep.

## 9. Open Questions

- [NEEDS CLARIFICATION: exact chosen accessor name — `expose_secret()` (mirrors `secrecy`'s
  `ExposeSecret` trait method, most discoverable to anyone familiar with that ecosystem
  convention), or a shorter in-house alternative (`reveal()`, `secret_str()`, `expose()`).
  `expose_secret()` is the more obviously "borrowed convention, not reinvented" choice, but
  final naming is a maintainer call.]
- [NEEDS CLARIFICATION: rename all four in-scope sites atomically in one PR (simplest,
  smallest possible diff, no risk of half-migrated state) versus spreading across
  incremental PRs per crate (`deps-core` first, then `deps-cargo`, then `deps-nuget`). Given
  the total blast radius is four accessor definitions plus a small, grep-countable set of
  call sites, an atomic single-PR rename appears low-risk and is the tentative default absent
  a reason to split it.]
- [NEEDS CLARIFICATION: should `NuGetAuth::header_value()` also be renamed to the chosen
  name for full consistency (FR-005), or is a domain-specific name like `header_value()`
  preferable there since it additionally documents *how* the value must be used (as a header),
  not just that it is secret? Both are defensible; no strong signal either way from the
  existing codebase.]
- No tracking GitHub issue filed yet for this finding — file one if/when this spec is picked
  up for implementation, per this project's `research/parity` convention (see
  `specs/044-precommit-hooks-ecosystem/spec.md` for the analogous "no tracking issue filed
  yet" pattern).

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[041-credential-redaction-hardening/spec|Redact user:pass@ credentials from registry-index logs and errors]] — the adjacent "credential must not leak via a log line" concern for URLs, owned by `deps_core::net_policy::redact_userinfo`; this spec's `Redacted<T>` owns the same concern for an owned secret value held in memory (per `secret.rs`'s own module doc)
- `crates/deps-core/src/secret.rs` — `Redacted<T>`, the accessor in scope for FR-001
- `crates/deps-core/src/github.rs` — `AuthToken::as_str`, in scope for FR-002
- `crates/deps-cargo/src/config.rs` — `AuthToken::as_str`, in scope for FR-002; `RegistryIndex::as_str`, explicitly out of scope (non-secret)
- `crates/deps-nuget/src/config.rs` — `RedactedSecret::as_str`, in scope for FR-002; `NuGetAuth::header_value`, subject to FR-005's open decision; `NuGetFeedUrl::as_str`, explicitly out of scope (non-secret)
- [secrecy crate on crates.io](https://crates.io/crates/secrecy) — source of the `expose_secret()` naming convention this spec proposes adopting (not the crate itself)
- PR #577 (commit `5d4d2682`) — consolidated the four wrapper types into `Redacted<T>`, the change this spec builds on

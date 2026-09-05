---
aliases:
  - Cargo Renamed-Dependency Lockfile Resolution
  - Per-Occurrence resolved_versions
tags:
  - sdd
  - spec
  - bug
  - deps-core
  - deps-cargo
  - lockfile
created: 2026-09-06
status: draft
related:
  - "[[constitution]]"
  - "[[023-cargo-custom-registries/spec|Cargo custom/private registry & source-replacement resolution]]"
---

# Feature: Per-occurrence lockfile version resolution for renamed/aliased dependencies

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: no branch yet — file/reference issue #649 before starting implementation
> **Priority**: P1
> **Type**: bug (architectural fix to shared `deps-core::lockfile` resolution)

## 1. Overview

### Problem Statement

PR #650 (issue #648) fixed `deps-cargo` to resolve Cargo's `package = "..."`
dependency-rename syntax against the real crate name instead of the local
alias, so `Dependency::name()` now returns the real registry name for a
renamed dependency. That fix exposed a pre-existing limitation in the shared
lockfile-resolution pipeline (`crates/deps-core/src/lockfile.rs`), tracked as
issue #649, in the same limitation class as #394 (`HashMap`-by-name collapse
of duplicate occurrences — that one for parsed manifest dependencies, this
one for lock-file-resolved versions).

`ResolvedPackages` (`crates/deps-core/src/lockfile.rs:280`) already stores
*all* lock-file entries per name internally (`packages: HashMap<String,
Vec<ResolvedPackage>>`, populated by `insert()` at line 308) — so a
`Cargo.lock` holding both `serde 0.9.15` and `serde 1.0.219` is not itself
information the parser discards. The information loss happens at the two
read paths every caller actually uses:

- `ResolvedPackages::iter()` (line 341) and `into_map()` (line 350) both
  route through `best_package()` (line 285), which reduces each name's
  `Vec<ResolvedPackage>` down to the single highest-semver entry.
- `deps-lsp`'s `load_resolved_versions()`
  (`crates/deps-lsp/src/document/lifecycle.rs:2736-2776`) consumes exactly
  that collapsed `iter()`, building
  `resolved_versions: HashMap<PackageName, ConcreteVersion>` — one
  `ConcreteVersion` per package name, full stop.
- `in_use_version()` (`crates/deps-core/src/lsp_helpers/in_use_version.rs:304-326`)
  looks the dependency's name up in that already-collapsed map
  (`resolved_versions.get(normalized_name).or_else(|| resolved_versions.get(dep.name()))`,
  lines 316-318) — it has no way to distinguish "the `serde` occurrence with
  `version = "1.0"`" from "the `serde_old` occurrence with
  `package = "serde", version = "0.9"`"; both now share `dep.name() ==
  "serde"` post-#648 and both receive the same collapsed `1.0.219`.
- `vulnerability_keys()` (`crates/deps-core/src/osv/types.rs:623-663`) builds
  its per-occurrence OSV cache-key signature (`format!("v:{v}")`, line 645)
  from that same `in_use_version()` call, so both occurrences also collapse
  to the same OSV vulnerability-lookup signature.

Pre-#648, this scenario produced an honest "no data" result
(`SkipReason::NoConcreteVersion`), because the alias name (`serde_old`) never
matched any lock-file entry at all. Post-#648, both occurrences resolve to
the real name (`serde`) and silently receive the *same* wrong data instead:
an advisory affecting the `1.0.219` occurrence renders as a diagnostic
anchored on the `serde_old` (0.9-pinned) line — a false positive on the
wrong line — while an advisory affecting only the `0.9.x` line is never
queried at all — a false negative. Hover/inlay hints report "in use:
1.0.219" on both lines regardless of which one is actually pinned to 0.9.

PR #650 deliberately left this unresolved (added a regression test pinning
the current known-limitation behavior rather than fixing it) and filed
issue #649 for the architectural follow-up this spec covers. `[NEEDS CLARIFICATION:
should this spec also account for #394's original scenario (duplicate names
across `[target.'cfg(...)'.dependencies]` blocks in deps-lsp's own manifest-side
HashMap), or is that a separate, already-closed concern (#394/PR #404) that
should stay out of scope here? See Open Questions.]`

### Goal

A dependency occurrence's in-use lock-file version (and, downstream, its OSV
vulnerability-lookup signature) is resolved using that occurrence's own
`version_requirement()`, not a single value collapsed across every
lock-file entry sharing the resolved package name — so two manifest
occurrences of the same real package name, pinned to different majors via a
rename/alias mechanism, each get their own correct in-use version and OSV
data instead of one silently overwriting the other.

### Out of Scope

- Any change to how `ResolvedPackages::insert()` collects lock-file entries
  — the underlying `Vec<ResolvedPackage>` per name already retains every
  entry; this spec only changes how callers *read* it.
- Extending `deps-cargo`'s `package = "..."` parsing itself (already shipped
  in #648/PR #650) — this spec is scoped to the lockfile-resolution
  consumption side only.
- Adding rename/alias parsing support to any other ecosystem (e.g. npm's
  `"name": "npm:<pkg>@<version>"` alias form is deliberately not parsed
  today per `crates/deps-npm/src/catalog.rs:541`'s comment) — out of scope;
  this spec only fixes the shared `deps-core` consumption path so that if/when
  another ecosystem adds a similar rename mechanism, it does not inherit this
  same mis-attribution bug.
- Any UI/wording change to hover or diagnostic messages beyond what's needed
  to reflect the corrected version (no new severity category, no new message
  copy beyond an accurate version number).

## 2. User Stories

### US-001: Correct in-use version per renamed occurrence

AS A developer with two manifest entries for the same crate — one direct,
one via `package = "..."` rename to a different major version — pinned
against the same `Cargo.lock`
I WANT each occurrence's hover/inlay "in use" version to reflect its own
resolved lock-file version
SO THAT I don't see the wrong installed version reported on the renamed line

**Acceptance criteria:**
```
GIVEN a Cargo.toml with `serde = "1.0"` and `serde_old = { package = "serde", version = "0.9" }`
  and a Cargo.lock holding both `serde 0.9.15` and `serde 1.0.219`
WHEN hover/inlay hints are generated for both dependency lines
THEN `serde` reports in-use version 1.0.219 and `serde_old` reports in-use version 0.9.15
```

### US-002: Correct OSV vulnerability attribution per renamed occurrence

AS A developer relying on vulnerability diagnostics
I WANT an OSV advisory affecting one major version of a renamed/aliased
crate to be attributed only to the manifest occurrence actually pinned to
that version
SO THAT I don't get a false-positive diagnostic on a line pinned to an
unaffected version, or a silently-missed false negative on the line that
actually is affected

**Acceptance criteria:**
```
GIVEN the two-occurrence scenario from US-001, with an OSV advisory that
  affects only serde 1.0.x
WHEN diagnostics are generated
THEN the advisory anchors on the `serde` (1.0) line and not on the
  `serde_old` (0.9) line, and a separate advisory affecting only 0.9.x
  (if one exists) is independently queried and anchored on the `serde_old` line
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN resolving a dependency occurrence's in-use lock-file version, THE SYSTEM SHALL select among all lock-file entries sharing that occurrence's resolved package name the one whose version satisfies the occurrence's own `version_requirement()`, instead of a single collapsed highest-semver value shared by every occurrence of that name | must |
| FR-002 | WHEN more than one lock-file entry for a name satisfies an occurrence's `version_requirement()` (e.g. two matching patch releases were both present in the lock file, which should not normally happen for a resolver-produced lock file but must not panic if seen), THE SYSTEM SHALL fall back to the existing highest-semver tiebreak among the satisfying subset | must |
| FR-003 | WHEN no lock-file entry for a name satisfies an occurrence's `version_requirement()`, THE SYSTEM SHALL return the existing "no concrete version" outcome for that occurrence (matching pre-#648 honest-skip behavior) rather than falling back to an arbitrary non-matching entry | must |
| FR-004 | WHEN `vulnerability_keys()` computes a per-occurrence OSV cache-key signature, THE SYSTEM SHALL derive it from the per-occurrence resolved version produced by FR-001, so two occurrences of the same name pinned to different satisfying versions receive distinct signatures | must |
| FR-005 | WHEN only a single manifest occurrence exists for a given resolved package name (the common case, no rename/alias involved), THE SYSTEM SHALL produce identical in-use-version and OSV-signature results to the current behavior — this is a correctness fix for the multi-occurrence case, not a behavior change for the single-occurrence case | must |
| FR-006 | WHEN a downstream ecosystem/caller still needs "the single best version for this name regardless of any specific occurrence" (e.g. `[NEEDS CLARIFICATION: does any current caller of `ResolvedPackages::get_version`/`into_map` need this collapsed semantics preserved, or can every current caller be migrated to the per-occurrence lookup? see Open Questions]`), THE SYSTEM SHALL continue to expose that collapsed lookup as a distinct, explicitly-named API rather than removing it | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Backward compatibility | Every existing `LockFileProvider` implementation (10 ecosystem crates: `deps-bundler`, `deps-cargo`, `deps-composer`, `deps-dart`, `deps-go`, `deps-npm`, `deps-nuget`, `deps-pypi`, `deps-swift`, plus any future one) must keep compiling and passing its existing tests unchanged — `ResolvedPackages`'s public API is shared across the whole workspace, not just Cargo |
| NFR-002 | Cross-ecosystem consistency | The fix lives in `deps-core::lockfile` / `deps-core::lsp_helpers::in_use_version` / `deps-core::osv`, not in `deps-cargo` — per this project's cross-ecosystem-consistency rule, a fix needed for one ecosystem's rename mechanism must not be special-cased to Cargo alone, since the underlying `resolved_versions` collapse is a shared-infrastructure limitation |
| NFR-003 | Performance | The per-occurrence lookup must not turn what is currently an O(1) `HashMap` lookup per dependency into an operation whose cost scales with lock-file size for the common (single-occurrence-per-name) case — see NFR-005 in [[023-cargo-custom-registries/spec]] for this project's existing latency-budget precedent on hover/completion paths |
| NFR-004 | Test coverage | The existing regression test added by PR #650 that pins the current known-limitation behavior must be updated to assert the corrected per-occurrence behavior once this fix lands, not left asserting the old (wrong) behavior indefinitely |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `ResolvedPackages` (existing, `crates/deps-core/src/lockfile.rs:280`) | Per-lockfile collection of resolved packages, already `Vec`-per-name internally | `packages: HashMap<String, Vec<ResolvedPackage>>`; `get_all()` (line 326) already exposes the full per-name `Vec` — likely the primary building block for the fix |
| `resolved_versions: HashMap<PackageName, ConcreteVersion>` (existing, threaded through `deps-lsp::document::lifecycle` and `deps-core::lsp_helpers::in_use_version`/`deps-core::osv::vulnerability_keys`) | The collapsed one-value-per-name shape causing this bug | `[NEEDS CLARIFICATION: does this type change shape entirely (e.g. `HashMap<PackageName, Vec<ConcreteVersion>>`, or `HashMap<PackageName, ResolvedPackages>`-like), or does `load_resolved_versions()` keep building this exact type for the single-occurrence fast path while a new, separate lookup handles the multi-occurrence/version_req-aware case? See Open Questions — this is the central design decision of this spec.]` |
| `Dependency::version_requirement()` (existing, `crates/deps-core/src/ecosystem.rs` trait method) | Already available per-occurrence, already used elsewhere in `in_use_version()` for the concrete-pin fallback path (line 321-323) | Returns `Option<&VersionReq>` — the natural filter key for FR-001's per-occurrence match |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Two occurrences of the same resolved name, both with a `version_requirement()` satisfied by the same single lock-file entry (i.e. no actual rename scenario, just two manifest sections referencing the same crate at compatible versions — the common/default case) | Both occurrences resolve to that one entry; behavior identical to today (FR-005) |
| A renamed occurrence's `version_requirement()` is `None` (no version specified, relying on the lock file entirely) | `[NEEDS CLARIFICATION: with no version_requirement to filter by, is falling back to the collapsed highest-semver entry (today's behavior) acceptable here, or does this need its own honest "ambiguous — cannot disambiguate without a stated requirement" skip reason? See Open Questions.]` |
| A workspace-inherited dependency (`workspace = true`) combined with a rename (`package = "..."` is already discarded when `workspace = true` is present per #648's fix) | Not a multi-occurrence-same-name scenario introduced by this bug — `package` is ignored in that case already, so only one occurrence's worth of resolution applies; no special handling needed beyond what #648 already does |
| Lock file has only one entry for a name, but two manifest occurrences both reference it (no actual version conflict, just aliasing to the same version) | Both occurrences correctly resolve to that single entry — FR-001's per-occurrence filter degenerates to the current single-value lookup when there is nothing to disambiguate |
| `ResolvedPackages::get_all()` returns entries whose versions fail to parse as semver (non-semver lock-file version string) | Reuse `best_package()`'s existing fallback ordering (lexicographic string compare) for the tiebreak among non-parseable versions — do not introduce a second, divergent version-comparison policy |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live-verified two-major rename scenario (`serde`/`serde_old` example from US-001/US-002, or an equivalent real crate pair) | Each occurrence's hover "in use" version matches its own lock-file-resolved version, not a shared collapsed value |
| SC-002 | OSV diagnostic attribution for the same scenario | An advisory affecting only one major is anchored only on the occurrence actually pinned to that major; no false positive on the other occurrence, no false negative for an advisory on the other major |
| SC-003 | Regression | PR #650's pinned known-limitation test is updated to assert the corrected behavior; all other existing `lockfile.rs`, `in_use_version.rs`, and `osv/types.rs` tests continue to pass unchanged |
| SC-004 | Cross-ecosystem regression | Full workspace test suite (`cargo nextest run --workspace --all-features --no-fail-fast`) passes for all 10 `LockFileProvider` implementations, confirming no single-occurrence-per-name behavior regressed for any other ecosystem |

## 8. Agent Boundaries

### Always (without asking)
- Read `crates/deps-core/src/lockfile.rs`, `crates/deps-core/src/lsp_helpers/in_use_version.rs`,
  and `crates/deps-core/src/osv/types.rs` (`vulnerability_keys`) in full before editing —
  each is shared infrastructure consumed by every ecosystem crate
- Preserve `ResolvedPackages::get`/`get_version`/`into_map`'s existing collapsed
  semantics as a still-available, explicitly-named API if any caller genuinely
  needs "best version regardless of occurrence" (FR-006) rather than deleting
  it outright
- Update PR #650's pinned regression test to assert corrected behavior once
  the fix lands (NFR-004)
- Run the full CI check suite (`cargo +nightly fmt --check`, clippy
  `--workspace --all-targets --all-features -- -D warnings`, `cargo nextest
  run --workspace --all-features --no-fail-fast`, rustdoc gate) before any PR —
  this touches shared `deps-core` code exercised by all 10 `LockFileProvider`
  implementations
- Live-test against a real `Cargo.lock` with a genuine two-major rename
  scenario per the project's Live Testing Principle — do not conclude
  correctness from unit tests alone

### Ask First
- The central data-model decision: whether `resolved_versions`'s type/shape
  changes, or a new parallel version-req-aware lookup path is added
  alongside it (Data Model section's `[NEEDS CLARIFICATION]`, Open Questions)
- Whether to also address #394's original manifest-side duplicate-name
  scenario in the same pass, or keep this fix strictly scoped to lock-file
  resolution (Overview's `[NEEDS CLARIFICATION]`)
- Any change to `LockFileProvider`'s trait surface itself (as opposed to
  `ResolvedPackages`'s inherent methods) — a trait signature change affects
  all 10 implementations' call sites

### Never
- Silently change `ResolvedPackages::get`/`get_version`/`into_map`'s existing
  return value for the single-occurrence-per-name case (NFR-001, FR-005) —
  any behavior change here must be additive (a new method/path) unless a
  workspace-wide audit confirms every caller is migrating together in the
  same PR
- Ship this without live-testing the two-major rename reproduction from
  issue #649, per the project's Live Testing Principle

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the fix change `resolved_versions`'s shape
  (e.g. `HashMap<PackageName, Vec<ConcreteVersion>>` or storing
  `ResolvedPackages` itself further downstream instead of pre-collapsing at
  `load_resolved_versions()`), or add a new, separate version-req-aware
  lookup function that callers (`in_use_version`, `vulnerability_keys`) opt
  into, leaving `resolved_versions`'s current shape as a fast-path default
  for the overwhelmingly common single-occurrence case? The former is more
  uniform but touches more call sites; the latter is lower-risk but adds a
  second lookup path callers must remember to use correctly.]
- [NEEDS CLARIFICATION: Is #394's original scenario (duplicate dependency
  names across `[target.'cfg(...)'.dependencies]` blocks, fixed in
  PR #404 at the `deps-lsp` manifest-parsing layer, not the lockfile layer)
  actually the same underlying limitation this spec should also revisit, or
  a fully separate, already-closed concern? The issue explicitly calls out
  "same limitation class as #394" — worth confirming whether #404's fix
  already solved the manifest side and this spec is purely the lockfile
  side, or whether there's remaining overlap.]
- [NEEDS CLARIFICATION: When a renamed occurrence has no `version_requirement()`
  at all (relying entirely on the lock file), what should the per-occurrence
  filter do — fall back to the collapsed highest-semver entry (today's
  behavior, potentially still wrong but no worse than before), or introduce
  a new explicit "ambiguous, cannot disambiguate" skip outcome distinct from
  `SkipReason::NoConcreteVersion`?]
- [NEEDS CLARIFICATION: Should this fix be implemented as a single PR, or
  does the FR-006/NFR-001 backward-compatibility surface (10 `LockFileProvider`
  implementations, multiple `deps-core` call sites) warrant splitting into
  staged PRs the way #023 (Cargo custom registries) or #041 (credential
  redaction hardening) were staged?]

## 10. References

- Issue #648 / PR #650 — the `package = "..."` rename fix that exposed this
  gap (deliberately left unfixed there, regression-tested as a known
  limitation)
- Issue #649 — this spec's source issue, with a live reproduction
  (`serde`/`serde_old` two-major scenario) and root-cause sketch
- Issue #394 / PR #404 — prior, related-class fix for manifest-side
  duplicate-name `HashMap` collapse (different layer: parsed dependencies,
  not lock-file resolution)

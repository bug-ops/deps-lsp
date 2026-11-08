---
aliases:
  - Deno Lock File Provider
  - deno.lock Resolution
tags:
  - sdd
  - spec
  - deno
  - lockfile
  - cross-ecosystem
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[052-pnpm-lockfile-provider/spec|pnpm-lock.yaml Lock File Provider]]"
---

# Feature: `deno.lock` Lock File Provider (Deno ecosystem)

> [!info] Metadata
> **Author**: research cycle (enhancement, P4)
> **Branch**: (none yet — spec stage)

## 1. Overview

### Problem Statement

`crates/deps-deno` has no `LockFileProvider`. Its ecosystem documentation
(`crates/deps-deno/src/ecosystem.rs:43`) states "No lock file support in the MVP (D9):
`deno.lock` resolved-version parsing is a follow-up increment"; the ecosystem declares no
`lockfile_filenames()`, and the conformance macro is invoked with `no_lockfile_support: true`.
As a result, Deno projects get no in-use-version column (hover, inlay hints), and OSV
vulnerability matching runs only against the manifest requirement of a `jsr:` / `npm:`
specifier rather than the version Deno actually resolved. Every other lock-file-capable
ecosystem already shows the resolved version, so this is a cross-ecosystem consistency gap
(a first-class bug class per `.claude/rules/continuous-improvement.md`).

Verified 2026-11-08. History: issue #709 (closed 2026-09-09) listed `deno.lock` among seven
missing lock formats; only `pnpm-lock.yaml` shipped ([[052-pnpm-lockfile-provider/spec]]) and
no follow-up issue was filed for `deno.lock`.

### Goal

When a `deno.json` or `deno.jsonc` has an adjacent or ancestor `deno.lock`, the Deno ecosystem
resolves it as a lock file so that hover, inlay hints, and OSV vulnerability matching use the
Deno-resolved version for both `jsr:` and `npm:` dependencies, with no ecosystem-visible
difference from other lock-file-backed ecosystems.

### Out of Scope

- `remote` section entries (plain `https://` module integrity hashes): no registry versions to
  resolve.
- Integrity hash / registry URL population on resolved packages.
- Writing, regenerating, or validating `deno.lock` (the server is read-only with respect to it).
- `deno.lock` schema versions below 3 and any version above the highest one this spec
  enumerates (see FR-006).
- Resolution of specifiers inside `import_map` files or `package.json` used by Deno (only
  manifests the Deno ecosystem already routes).
- Any configurable lock-file precedence setting.
- Changes to `crates/deps-zed` (separate repository).

## 2. User Stories

### US-001: Hover shows the Deno-resolved version

AS A developer using Deno
I WANT hover to show the version Deno resolved for a `jsr:` or `npm:` import
SO THAT I see what is actually in use, not only the range in `deno.json`

**Acceptance criteria:**
```
GIVEN a deno.json importing "@std/path": "jsr:@std/path@^1.0.0" and a sibling deno.lock
  resolving jsr:@std/path@^1.0.0 to 1.0.8
WHEN the user hovers the "@std/path" dependency
THEN the hover shows 1.0.8 as the in-use version
```

### US-002: npm specifiers are resolved too

AS A developer mixing `jsr:` and `npm:` imports
I WANT both registries resolved from the lock file
SO THAT the in-use column is consistent across all my imports

**Acceptance criteria:**
```
GIVEN a deno.json with "chalk": "npm:chalk@^5" and a deno.lock whose specifiers map
  npm:chalk@^5 to 5.3.0
WHEN inlay hints are requested
THEN the hint shows 5.3.0
```

### US-003: OSV matching uses the resolved version

AS A developer
I WANT vulnerability diagnostics to check the resolved version
SO THAT a patched resolved version is not flagged merely because the range admits a
vulnerable one

**Acceptance criteria:**
```
GIVEN a requirement satisfied by both a vulnerable and a patched version, with deno.lock
  resolving to the patched version
WHEN diagnostics are generated
THEN the vulnerability diagnostic reflects the patched (lock-resolved) version
```

### US-004: Both manifest flavors and all supported schema versions work

AS A developer
I WANT `deno.json` and `deno.jsonc` projects, on lock schema versions 3, 4 and 5, to behave
identically
SO THAT upgrading Deno does not silently remove the in-use column

**Acceptance criteria:**
```
GIVEN equivalent projects using deno.json and deno.jsonc, each with deno.lock at
  version "3", "4" and "5"
WHEN hover is requested on the same dependency
THEN every combination shows the same resolved version
```

### US-005: Lock edits refresh the view

AS A developer
I WANT the resolved version to update when `deno.lock` changes on disk
SO THAT running `deno install` or `deno cache` is reflected without reopening the file

**Acceptance criteria:**
```
GIVEN an open deno.json whose deno.lock is rewritten by an external command
WHEN the file watcher reports the change
THEN the document is re-parsed and the new resolved versions are shown
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the Deno ecosystem is queried for lock file support THE SYSTEM SHALL expose a `LockFileProvider` that locates `deno.lock` in the manifest's directory and ancestors using the shared first-match-wins helper `locate_lockfile_for_manifest` | must |
| FR-002 | WHEN the manifest is either `deno.json` or `deno.jsonc` THE SYSTEM SHALL locate and parse the same `deno.lock` | must |
| FR-003 | WHEN `parse_lockfile` reads `deno.lock` THE SYSTEM SHALL read through `deps_core::lockfile::read_lockfile_content` (size-capped via `fs_probe::read_to_string_capped`, offloaded with `spawn_blocking`) and SHALL NOT perform any ad-hoc blocking read | must |
| FR-004 | WHEN parsing `deno.lock` THE SYSTEM SHALL use the shared JSON AST layer (`deps-core::json_ast`) and its nesting-depth guard, reporting over-deep input as the same `NestingTooDeep`-class error used for other JSON inputs (see #1906) | must |
| FR-005 | WHEN the top-level `version` field is `"3"`, `"4"` or `"5"` THE SYSTEM SHALL parse the file using the section layout of that version (`specifiers`, `jsr`, `npm`, `workspace`; `remote` ignored) | must |
| FR-006 | WHEN `version` is missing, non-string, or not a supported value THE SYSTEM SHALL return `DepsError::ParseError` naming the unsupported version rather than misparse | must |
| FR-007 | WHEN a `specifiers` entry maps a `jsr:` request (e.g. `jsr:@std/path@^1.0.0`) to a resolved version THE SYSTEM SHALL record a `ResolvedPackage` for the package name with that exact version | must |
| FR-008 | WHEN a `specifiers` entry maps an `npm:` request to a resolved `name@version` THE SYSTEM SHALL record a `ResolvedPackage` with the version stripped of any peer-dependency suffix (`_` separated segments in v3/v4 npm keys) | must |
| FR-009 | WHEN the same package name resolves to different versions through different requests THE SYSTEM SHALL record every distinct version using the existing multi-version `ResolvedPackages` support, leaving per-occurrence selection to existing semver matching | must |
| FR-010 | WHEN the lock file has a `workspace` section THE SYSTEM SHALL use it only to associate member-specific requests where required to pick the correct resolution; it SHALL NOT fail if the section is absent or contains unknown keys | should |
| FR-011 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the file watcher THE SYSTEM SHALL return `["deno.lock"]` so a change triggers a re-parse of affected Deno documents | must |
| FR-012 | WHEN `deno.lock` is looked up through the LSP lock file cache THE SYSTEM SHALL rely on `LockFileCache::get_or_parse` mtime caching without a provider-level override | should |
| FR-013 | WHEN the lock file is empty, has no `specifiers`, or contains only `remote` entries THE SYSTEM SHALL return an empty `ResolvedPackages`, not an error | must |
| FR-014 | WHEN the lock file is syntactically invalid JSON THE SYSTEM SHALL return `DepsError::ParseError` with the underlying error as source | must |
| FR-015 | WHEN the conformance macro is invoked for `deps-deno` THE SYSTEM SHALL drop `no_lockfile_support: true` in favor of the lock-file-capable conformance variant | must |
| FR-016 | THE SYSTEM SHALL provide a fuzz target for `deno.lock` parsing alongside the existing lockfile targets (`fuzz/fuzz_targets/json_lockfiles.rs` or a dedicated target) with seed corpus entries for versions 3, 4 and 5 | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Reading and parsing up to the 32 MiB `MAX_LOCKFILE_BYTES` cap must not block the async executor; reuse the `spawn_blocking` path already in `read_lockfile_content` |
| NFR-002 | Security | `deno.lock` is untrusted repository input: bounded size, bounded nesting depth, no panics on any input (fuzz-verified), no path reads outside the ancestor walk |
| NFR-003 | Consistency | Reuse `deps-core` helpers (`json_ast`, `json_helpers` non-string-value guards, `fs_probe`) rather than ecosystem-local reimplementation; no new `DepsError` variant |
| NFR-004 | Type safety | Lock schema version modelled as an exhaustive enum (no stringly-typed version branching, no catch-all arm) so adding a schema version forces compile-time updates |
| NFR-005 | Backward compatibility | Projects without `deno.lock` behave identically to today |

## 5. Data Model

No new public resolution types; reuses `deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `deno.lock` root | Versioned JSON document | `version` (`"3"`/`"4"`/`"5"`), `specifiers`, `jsr`, `npm`, `remote`, `workspace` |
| `specifiers` | Map of requested specifier to resolved specifier | key like `jsr:@std/path@^1.0.0`; value the concrete resolved version (shape differs by schema version) |
| `jsr` / `npm` | Per-package resolved metadata | keyed by `name@version`; integrity and dependency lists (not read in this spec) |
| `workspace` | Workspace member dependency declarations | member-scoped request lists |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `deno.lock` absent | No resolution; behavior unchanged |
| Lock `version` `"2"` or unknown future value | `ParseError` naming the version (FR-006) |
| `remote`-only lock | Empty `ResolvedPackages` (FR-013) |
| npm key with peer suffix (`pkg@1.2.3_peer@4.5.6`) | Suffix stripped to `1.2.3` (FR-008) |
| Same package at two versions | Both recorded (FR-009) |
| Specifier value is not a string, or `specifiers` is not an object | Entry skipped via shared non-string guards; no panic |
| Over-deep JSON | `NestingTooDeep`-class error (FR-004) |
| File above the size cap, symlink, FIFO | Rejected by `read_lockfile_content` (FR-003) |
| `deno.lock` in an ancestor of a nested workspace member | Located by the ancestor walk (FR-001) |
| `jsr:` request without a version range (`jsr:@std/path`) | Resolved by exact request key match; `[NEEDS CLARIFICATION: how v3/v4/v5 key unversioned and `@^` shorthand requests so the manifest specifier can be matched to the lock key]` |
| Manifest specifier written with a subpath (`jsr:@std/path@^1/posix`) | `[NEEDS CLARIFICATION: confirm whether lock keys retain the subpath in each schema version]` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Resolved version matches `deno cache`/`deno install` output on fixtures (jsr, npm, mixed, workspace) for schema versions 3, 4, 5 | 100% |
| SC-002 | Existing `deps-deno` tests | 0 regressions |
| SC-003 | New unit tests: each schema version, peer suffix, multi-version, empty, malformed, unsupported version, over-deep, `deno.json` and `deno.jsonc` | all pass |
| SC-004 | Fuzz target runs a bounded session with seeds without panic or timeout | pass |
| SC-005 | Live check against a real Deno project: hover and inlay hints show resolved versions for `jsr:` and `npm:` | pass |
| SC-006 | Full CI-matching check suite per `.claude/rules/branching.md` | green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the `NpmLockParser` / pnpm provider patterns for provider structure and tests
- Check `deps-core::json_ast`, `json_helpers`, `fs_probe` before writing any local helper
- Update `CHANGELOG.md` `[Unreleased]` (one line + PR link), the Deno page in `book/src/ecosystems/`, the crate README if affected, and the `.local/testing` coverage and playbook entries
- Generate real `deno.lock` fixtures with the Deno CLI for each schema version rather than hand-writing them

### Ask First
- Any change to `deps_core::lockfile` shared trait or helper signatures
- Adding a new third-party dependency
- Supporting additional schema versions beyond 3, 4, 5

### Never
- Read `deno.lock` outside `read_lockfile_content` or add a blocking read on the async path
- Add a catch-all arm to the schema-version enum
- Touch `crates/deps-zed` or recreate `.local/specs/`

## 9. Open Questions

- [NEEDS CLARIFICATION: exact `specifiers` value shape per schema version (3: `jsr:` / `npm:` keys mapping to `jsr:name@ver` / `npm:name@ver`; 4 and 5: value-only versions and changed npm peer-suffix encoding). Must be confirmed from real lock files generated by the Deno versions that emit each schema.]
- [NEEDS CLARIFICATION: semantics of the `workspace` section across versions and whether member-scoped matching is needed for correctness (FR-010) or whole-file aggregation (as in spec 052 FR-007) suffices.]
- [NEEDS CLARIFICATION: how to map a manifest specifier (including `^`/`~` ranges, bare names, and subpaths) to its lock `specifiers` key, and whether the existing `ParsedSpecifier` in `crates/deps-deno/src/specifier.rs` already normalizes to the same form.]
- [NEEDS CLARIFICATION: whether a Deno project can also carry `package.json` + `node_modules` lock semantics that overlap with the npm ecosystem's `package-lock.json` provider.]
- [NEEDS CLARIFICATION: dedicated fuzz target versus extending `json_lockfiles.rs`.]

## 10. See Also

- [[052-pnpm-lockfile-provider/spec]] — precedent for adding a lock format to an existing ecosystem
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issue #709 — origin issue (closed; `deno.lock` never followed up)
- `crates/deps-core/src/lockfile.rs` — `LockFileProvider`, `read_lockfile_content`, `ResolvedPackages`
- `crates/deps-core/src/json_ast.rs` — shared JSON AST parsing
- `crates/deps-deno/src/ecosystem.rs` — current "no lock file support" note (line 43) and `no_lockfile_support: true` conformance flag
- `fuzz/fuzz_targets/json_lockfiles.rs`, `fuzz/fuzz_targets/pnpm_lockfile.rs` — existing lockfile fuzz precedents

---
aliases:
  - pnpm Lock File Provider
  - pnpm-lock.yaml Resolution
tags:
  - sdd
  - spec
  - npm
  - pnpm
  - cross-ecosystem
created: 2026-09-09
status: shipped
related:
  - "[[constitution]]"
  - "[[046-pnpm-catalogs/spec|pnpm Catalogs + workspace: Protocol Resolution Support]]"
---

# Feature: `pnpm-lock.yaml` Lock File Provider (npm ecosystem)

> [!info] Metadata
> **Author**: triage-and-solve cycle, issue #709
> **Branch**: (none yet — spec stage)

## 1. Overview

### Problem Statement

`crates/deps-npm`'s `LockFileProvider` (`NpmLockParser`, `crates/deps-npm/src/lockfile.rs`)
resolves in-use dependency versions only from `package-lock.json`. Projects
that use pnpm as their package manager have no `package-lock.json` at all —
their lock file is `pnpm-lock.yaml` — so for those projects deps-lsp's
"in-use version" column (hover, inlay hints) and the resolved-version basis
for OSV vulnerability matching silently fall back to the manifest's semver
*requirement* instead of the actually-installed version, exactly the class
of inconsistency `.claude/rules/continuous-improvement.md` treats as a
first-class bug class. Verified 2026-09-09: `NpmLockParser::LOCKFILE_NAMES`
is `&["package-lock.json"]` only (`crates/deps-npm/src/lockfile.rs:67-72`),
and `docs/ECOSYSTEM_GUIDE.md:236-240` already documents this as a known
limitation.

This gap sits alongside pnpm catalog support ([[046-pnpm-catalogs/spec]],
already shipped), which resolves the *manifest-declared* version for
`catalog:`/`catalog:<name>` entries but not the *lock-file-confirmed*
resolved version — the two features are complementary, not overlapping.

Issue #709 originally scoped seven missing lock formats across four
ecosystems (pnpm, yarn, bun, Deno, Gradle, Pipfile, pdm). Per this spec's
own scoping decision (see Out of Scope below), only `pnpm-lock.yaml` is in
scope here; the rest remain tracked on #709 as follow-up work, in the order
already proposed there.

### Goal

When a `package.json` in a pnpm-managed project (workspace root or single
package) has an adjacent or ancestor `pnpm-lock.yaml`, `NpmLockParser`
resolves it as a lock file: hover, inlay hints, and OSV vulnerability
matching use the pnpm-resolved version exactly as they already do for
`package-lock.json`, with no ecosystem-visible behavioral difference between
the two lock formats.

### Out of Scope

- `yarn.lock` (v1 and Berry), `bun.lock`, `deno.lock`, `gradle.lockfile`,
  `Pipfile.lock`, `pdm.lock` — remain open on issue #709 as separate,
  individually-spec'd follow-ups.
- Changing pnpm catalog resolution ([[046-pnpm-catalogs/spec]]) — this spec
  only adds lock-file confirmation on top of the already-resolved manifest
  requirement/catalog reference.
- A configurable or user-overridable lock-file precedence — the precedence
  decided in [[#4. Functional Requirements|FR-002]] is fixed or
  fallback-only wiring, not a `deps-lsp` setting.
- Reading the `packages`/`snapshots` section of `pnpm-lock.yaml` for
  integrity hashes or peer-dependency graphs — only enough of that section
  is read to strip peer-dependency-suffixed version strings down to a plain
  semver (see FR-004). Registry checksum/URL population (`ResolvedSource::Registry`
  fields) is deferred; `NpmLockParser` already does not populate a checksum for
  every `package-lock.json` entry either, so this is not a regression.
- pnpm's `lockfileVersion` values older than `'6.0'` (pre-pnpm-8 shape,
  where `packages` keys are unprefixed and peer-suffix syntax differs) — see
  FR-006.

## 2. User Stories

### US-001: Hover shows the pnpm-resolved version

AS A developer using pnpm in a project
I WANT deps-lsp's hover to show the version pnpm actually installed for a
dependency, not just the semver range in `package.json`
SO THAT I can trust the "in-use version" the same way I already do on an npm
or yarn... (today: npm-only) project

**Acceptance criteria:**
```
GIVEN a package.json with "react": "^18.0.0" and a sibling pnpm-lock.yaml
  resolving react to 18.2.0
WHEN the user hovers the "react" dependency line
THEN the hover shows 18.2.0 as the in-use/resolved version, identically to
  how package-lock.json-resolved versions are shown today
```

### US-002: OSV vulnerability matching uses the resolved version

AS A developer using pnpm
I WANT vulnerability diagnostics to check the version pnpm actually
installed
SO THAT I am not shown a false "no known vulnerabilities" for a vulnerable
resolved version that happens to satisfy a broad manifest range, nor a false
positive for a version range that was never actually installed

**Acceptance criteria:**
```
GIVEN a package.json requirement satisfied by both a vulnerable and a
  patched version, with pnpm-lock.yaml resolving to the patched version
WHEN diagnostics are generated for that dependency
THEN the vulnerability diagnostic reflects the patched (lock-resolved)
  version, matching the existing package-lock.json-driven behavior
```

### US-003: Monorepo workspace members are covered

AS A developer in a pnpm workspace (multiple `package.json` files under one
root `pnpm-lock.yaml`)
I WANT every workspace member's dependencies resolved from the shared lock
file
SO THAT opening any package in the monorepo — not just the root — gets
correct in-use versions

**Acceptance criteria:**
```
GIVEN a pnpm workspace with root pnpm-lock.yaml containing importers "."
  and "packages/foo", and packages/foo/package.json depends on "lodash"
WHEN the user hovers "lodash" in packages/foo/package.json
THEN the hover shows the version resolved for "lodash" in the
  packages/foo importer entry
```

### US-004: package-lock.json is not disturbed

AS A maintainer of the npm ecosystem crate
I WANT the existing `package-lock.json` resolution path to keep behaving
exactly as before
SO THAT this addition cannot regress the far more common npm-lock case

**Acceptance criteria:**
```
GIVEN a project with only package-lock.json (no pnpm-lock.yaml)
WHEN any hover/inlay-hint/diagnostic request is made
THEN behavior is byte-for-byte identical to before this feature (same
  resolved versions, same code path)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `NpmLockParser::locate_lockfile` searches a manifest's directory and ancestors THE SYSTEM SHALL check for `package-lock.json` before `pnpm-lock.yaml` at each directory level, via `LOCKFILE_NAMES = ["package-lock.json", "pnpm-lock.yaml"]` passed to the existing `locate_lockfile_for_manifest` first-match-wins helper | must |
| FR-002 | WHEN both `package-lock.json` and `pnpm-lock.yaml` exist in the same directory THE SYSTEM SHALL resolve versions from `package-lock.json` only, per FR-001's ordering — this is the fixed precedence decision this spec makes for issue #709's "decided once and documented" requirement | must |
| FR-003 | WHEN `parse_lockfile` is called with a `pnpm-lock.yaml` path THE SYSTEM SHALL parse the YAML via `yaml-rust2` (already a `deps-npm` dependency, used today for `pnpm-workspace.yaml` catalogs) guarded by the same `deps_core::check_yaml_nesting_depth`/`check_yaml_expansion` bounds `deps-npm/src/catalog.rs` already applies, and SHALL route the file read through `deps_core::lockfile::read_lockfile_content(path, "pnpm-lock.yaml")` (32 MiB cap, consistent `ParseError` formatting) exactly as `package-lock.json` parsing does | must |
| FR-004 | WHEN reading the `importers` map THE SYSTEM SHALL iterate every importer key (not just `"."`) and, for each, read `dependencies`, `devDependencies`, and `optionalDependencies` sub-maps, extracting each entry's `version` field, stripping any parenthesized peer-dependency suffix (e.g. `1.2.3(react@18.2.0)` → `1.2.3`) to obtain a plain semver string | must |
| FR-005 | WHEN an importer dependency's `version` field starts with `link:` (a workspace-local sibling package, not a registry package) THE SYSTEM SHALL skip that entry — it contributes no `ResolvedPackage` | must |
| FR-006 | WHEN the lock file's top-level `lockfileVersion` is present and its major version component (parsed as the portion before `.`) is below `6` THE SYSTEM SHALL treat the file as unparseable and return `DepsError::ParseError` with a message naming the unsupported version, rather than silently misparsing an incompatible shape | must |
| FR-007 | WHEN a dependency name appears with different resolved versions across multiple importers (monorepo, differing workspace-member pins) THE SYSTEM SHALL record every distinct version as a candidate for that name in the returned `ResolvedPackages`, using its existing multi-version-per-name support (`ResolvedPackages::insert`/`get_version`) — no importer-to-manifest correlation is performed; the existing semver-range-based `get_version` selection (already used for `package-lock.json`'s multi-version node_modules entries) picks the right candidate per occurrence | must |
| FR-008 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the LSP file watcher (`crates/deps-npm/src/ecosystem.rs`) THE SYSTEM SHALL include `"pnpm-lock.yaml"` alongside `"package-lock.json"` so edits to either file trigger a re-resolve | must |
| FR-009 | WHEN `is_lockfile_stale` is called for a located `pnpm-lock.yaml` THE SYSTEM SHALL use `LockFileProvider`'s existing default mtime-comparison implementation (no override needed) | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing a `pnpm-lock.yaml` up to the existing 32 MiB `MAX_LOCKFILE_BYTES` cap must not block the async executor — reuse the same `spawn_blocking` path `read_lockfile_content` already provides; no new blocking I/O introduced |
| NFR-002 | Security | YAML parsing must go through `check_yaml_nesting_depth`/`check_yaml_expansion` exactly as `deps-npm/src/catalog.rs` does today — a `pnpm-lock.yaml` is untrusted, repo-sourced input in the same threat class as any other parsed manifest/lockfile |
| NFR-003 | Consistency | No new `DepsError` variant — reuse `ParseError { file_type, source }` exactly as `package-lock.json` parsing does, so error handling and logging at call sites needs no changes |
| NFR-004 | Backward compatibility | Zero behavioral change for any project without a `pnpm-lock.yaml` (US-004) |

## 5. Data Model

No new public types. Reuses `deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}` exactly as `package-lock.json` parsing does.

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `pnpm-lock.yaml` `importers` map | Per-workspace-member dependency version resolutions | key: relative path (e.g. `"."`, `"packages/foo"`); value: `dependencies`/`devDependencies`/`optionalDependencies` maps of `name -> { specifier, version }` |
| `pnpm-lock.yaml` `packages`/`snapshots` sections | Global package metadata (integrity, resolution, peer graph) | Not read by this spec's MVP (see Out of Scope) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `pnpm-lock.yaml` present, `package-lock.json` absent | Resolved via `pnpm-lock.yaml` (FR-001/FR-002 ordering falls through) |
| Both lock files present | `package-lock.json` wins per FR-002; `pnpm-lock.yaml` is never read |
| `pnpm-lock.yaml` exists but is empty or has no `importers` key | Returns an empty `ResolvedPackages` (mirrors `package-lock.json`'s handling of a lockfile with no `packages` key) — not a parse error |
| Malformed YAML (unparseable) | `DepsError::ParseError` with `yaml-rust2`'s underlying error as `source`, same shape as `deps-npm/src/catalog.rs`'s existing error handling |
| `lockfileVersion` below `'6.0'` | `DepsError::ParseError` naming the unsupported version (FR-006) — deliberately refuses to guess at an incompatible shape rather than silently returning wrong/empty data |
| Dependency version with peer suffix, e.g. `"5.0.0(typescript@5.3.0)"` | Suffix stripped; resolves to `5.0.0` (FR-004) |
| Dependency version `"link:../shared-lib"` (workspace-local sibling) | Skipped entirely (FR-005) — not reported as an unresolvable or missing version, simply absent from `ResolvedPackages`, matching how a workspace-local package is not a registry lookup target elsewhere in the ecosystem |
| Same package name resolved to different versions in different importers | Both recorded as candidates; per-occurrence resolution already handled by existing `get_version` semver matching (FR-007) |
| `pnpm-lock.yaml` larger than the 32 MiB cap | `read_lockfile_content` returns `None`/error per its existing capped-read contract — same behavior as an oversized `package-lock.json` today |
| Symlink or non-regular file at the `pnpm-lock.yaml` path | Rejected by `read_lockfile_content`'s existing stat pre-filter, same as any other lock file |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover/inlay-hint resolved version for a dependency in a pnpm-only project matches the version pnpm actually installed | 100% on the test fixtures in [[#9. Open Questions\|§9]]'s test plan (single package, workspace, peer-suffix, `link:` entry) |
| SC-002 | Existing `package-lock.json` test suite (`crates/deps-npm/src/lockfile.rs` `#[cfg(test)]`) | 0 regressions, 0 changed assertions |
| SC-003 | New unit tests for `pnpm-lock.yaml` parsing (single-package, monorepo multi-importer, peer suffix, `link:` skip, malformed YAML, unsupported `lockfileVersion`, empty file) | all pass, following the existing inline-`r#"..."#`-fixture + `tempfile::tempdir()` pattern in `crates/deps-npm/src/lockfile.rs` |
| SC-004 | `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo +nightly fmt --all -- --check`, `cargo nextest run -p deps-npm` | all green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the existing `NpmLockParser`/`LockFileProvider` code patterns in `crates/deps-npm/src/lockfile.rs` (inline test fixtures, `read_lockfile_content`, `ParseError` shape)
- Run the full pre-commit check suite per `.claude/rules/branching.md` before opening the PR
- Update `docs/ECOSYSTEM_GUIDE.md`'s known-limitations note (`ECOSYSTEM_GUIDE.md:236-240`) to remove the now-resolved `pnpm-lock.yaml` gap
- Update `CHANGELOG.md`'s `[Unreleased]` section (one line + PR link once known)

### Ask First
- Any change to `deps_core::lockfile`'s shared trait/helpers beyond what FR-001/FR-008 require (e.g. touching `locate_lockfile_for_manifest`'s signature) — this spec assumes the existing helper is reused unmodified
- Adding a new third-party YAML/lockfile-specific dependency — `yaml-rust2` is already available and should be sufficient; if it proves insufficient, confirm before adding anything else

### Never
- Change `package-lock.json` resolution behavior or its precedence ranking relative to `pnpm-lock.yaml` (FR-002 is fixed, not configurable, per this spec's scoping)
- Touch `crates/deps-zed` (submodule, separate repo/PR per `.claude/rules/branching.md`)
- Start work on the other six lock formats from issue #709 — those remain separate, unscoped follow-ups

## 9. Open Questions

None outstanding. Both design decisions issue #709 left open were resolved during spec drafting:
- Precedence when both lock files coexist: `package-lock.json` first (FR-001/FR-002).
- Monorepo `importers` handling: aggregate all importers into one `ResolvedPackages`, relying on existing multi-version-per-name semver matching (FR-007), consistent with how `package-lock.json`'s own multi-version entries are already handled.

## 10. See Also

- [[046-pnpm-catalogs/spec]] — resolves `catalog:`/`catalog:<name>` manifest values; this spec adds lock-file confirmation on top
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issue #709 — origin issue (scoped down to `pnpm-lock.yaml` only here; other formats remain open on the issue)
- `crates/deps-core/src/lockfile.rs` — `LockFileProvider` trait, `locate_lockfile_for_manifest`, `ResolvedPackages`
- `crates/deps-npm/src/lockfile.rs` — `NpmLockParser`, the pattern this spec extends
- `crates/deps-npm/src/catalog.rs` — existing `yaml-rust2` + nesting/expansion-guard usage precedent
- `docs/ECOSYSTEM_GUIDE.md:236-240` — known-limitations note this spec resolves

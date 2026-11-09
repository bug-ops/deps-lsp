---
aliases:
  - yarn Lock File Provider
  - yarn.lock Resolution
tags:
  - sdd
  - spec
  - npm
  - yarn
  - cross-ecosystem
created: 2026-11-08
status: implemented
related:
  - "[[constitution]]"
  - "[[052-pnpm-lockfile-provider/spec|pnpm-lock.yaml Lock File Provider]]"
---

# Feature: `yarn.lock` Lock File Provider (npm ecosystem)

> [!info] Metadata
> **Author**: research/parity cycle
> **Type / priority**: enhancement/parity, P3
> **Branch**: (none yet - spec stage)

## 1. Overview

### Problem Statement

`NpmLockParser` (`crates/deps-npm/src/lockfile.rs`) resolves in-use versions from `package-lock.json` and `pnpm-lock.yaml` only; `Ecosystem::lockfile_filenames()` (`crates/deps-npm/src/ecosystem.rs:149`) returns exactly those two names. Projects managed with Yarn have neither file, so the in-use version column (hover, inlay hints) and the resolved-version basis for OSV matching fall back to nothing.

Verified live 2026-11-08: a `package.json` with `"request": "^2.88.2"` next to a valid yarn v1 `yarn.lock` pinning request 2.88.2 produces the diagnostic "vulnerability data was not checked for 1 dependency: no resolved or exact version was available". The same manifest with an equivalent `package-lock.json` produces the real `GHSA-p8p7-x288-28g6` vulnerability diagnostic against the locked version. Yarn projects therefore silently lose a security signal that npm and pnpm projects get.

History: issue #709 (closed 2026-09-09) listed `yarn.lock`, `bun.lock`, `deno.lock`, `gradle.lockfile`, `Pipfile.lock`, `pdm.lock` as missing. Only `pnpm-lock.yaml` shipped ([[052-pnpm-lockfile-provider/spec]]), whose Out of Scope section lists the rest; no follow-up issues were filed for the remainder. This spec is the yarn follow-up.

Parity: `mpiton/zed-depsy` v2.1.2 (2026-11-03) added "Read Yarn Berry lockfiles in the npm lock graph" (`mpiton/zed-depsy` PR #425). The Stack Overflow 2025 developer survey reports Yarn used by 21.1% of respondents ([survey](https://survey.stackoverflow.co/2025/technology)).

### Goal

When a `package.json` has an adjacent or ancestor `yarn.lock` (v1 or Berry) and no higher-precedence lock file, `NpmLockParser` resolves it: hover, inlay hints, and OSV matching use the yarn-resolved version exactly as they do for `package-lock.json` and `pnpm-lock.yaml`.

### Out of Scope

- `bun.lock`, `deno.lock`, `gradle.lockfile`, `Pipfile.lock`, `pdm.lock` - separate follow-ups.
- Yarn Plug'n'Play files (`.pnp.cjs`), `.yarnrc.yml` registry configuration, Yarn `resolutions`/`catalog:` manifest-side handling.
- Reading integrity checksums, `resolved` URLs, or peer/dependency graphs from `yarn.lock` beyond what resolved-version extraction requires (mirrors spec 052).
- A user-configurable lock-file precedence setting.
- Yarn Berry `patch:` resolutions as a source of a distinct "patched" version (see FR-008: patches resolve to their underlying registry version only).

## 2. User Stories

### US-001: Hover and inlay hints show the yarn-resolved version

AS A developer using Yarn
I WANT the in-use version shown for each dependency
SO THAT I get the same information npm and pnpm users already get

**Acceptance criteria:**
```
GIVEN a package.json with "react": "^18.0.0" and a sibling yarn.lock
  (v1 or Berry) resolving react to 18.2.0
WHEN the user hovers the "react" dependency
THEN the hover shows 18.2.0 as the in-use version
```

### US-002: OSV matching uses the resolved version

AS A developer using Yarn
I WANT vulnerability diagnostics evaluated against the locked version
SO THAT a vulnerable pinned version is flagged instead of "not checked"

**Acceptance criteria:**
```
GIVEN package.json "request": "^2.88.2" and a yarn v1 yarn.lock pinning 2.88.2
WHEN diagnostics are generated
THEN the GHSA-p8p7-x288-28g6 vulnerability diagnostic is reported, and the
  "vulnerability data was not checked" diagnostic is absent
```

### US-003: Berry lock files and monorepos

AS A developer on Yarn Berry (2+) with workspaces
I WANT every workspace member's dependencies resolved from the shared root `yarn.lock`
SO THAT opening any member's package.json gives correct versions

**Acceptance criteria:**
```
GIVEN a Berry yarn.lock with __metadata, a workspace entry, and an entry whose
  resolution is "lodash@npm:4.17.21"
WHEN the user hovers "lodash" in a workspace member's package.json
THEN the hover shows 4.17.21
```

### US-004: Existing lock files are not disturbed

AS A maintainer
I WANT projects with package-lock.json or pnpm-lock.yaml to behave unchanged
SO THAT this addition cannot regress them

**Acceptance criteria:**
```
GIVEN a directory containing package-lock.json (and optionally yarn.lock)
WHEN any request is made
THEN results are identical to behavior before this feature
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `NpmLockParser::locate_lockfile` searches a manifest's directory and ancestors THE SYSTEM SHALL recognize `yarn.lock` as an npm lock file via the existing `locate_lockfile_for_manifest` helper | must |
| FR-002 | WHEN more than one npm lock file exists in the same directory THE SYSTEM SHALL select exactly one using a single fixed precedence defined once in `deps-core` (not per-crate), documented in the ecosystem reference. Proposed order: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, preserving specs 052 behavior for existing files | must |
| FR-003 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the file watcher THE SYSTEM SHALL include `yarn.lock` so edits trigger a re-parse of affected documents, including dependents resolved via an ancestor directory | must |
| FR-004 | WHEN a located lock file is `yarn.lock` THE SYSTEM SHALL detect its format (v1 vs Berry) from content - Berry files contain a top-level `__metadata` key, v1 files carry the `# yarn lockfile v1` header - and dispatch to the matching parser; classification SHALL be a typed enum, not a filename or string comparison | must |
| FR-005 | WHEN parsing yarn v1 THE SYSTEM SHALL read the custom line format: entry headers listing one or more comma-separated `name@range` specifiers (quoted when needed, scoped names included), followed by an indented `version "x.y.z"` field, and SHALL record the resolved version under each distinct package name | must |
| FR-006 | WHEN parsing Yarn Berry THE SYSTEM SHALL parse the file as YAML through the existing bounded-YAML guards (`check_yaml_nesting_depth`, `check_yaml_expansion`), skip the `__metadata` key, and for each entry derive the package name and version from the `resolution` field (`name@npm:x.y.z`), falling back to the entry's `version` field | must |
| FR-007 | WHEN a Berry entry's `resolution` uses a non-registry protocol (`workspace:`, `link:`, `portal:`, `file:`, `git`/`github` URLs, `exec:`) THE SYSTEM SHALL NOT report it as a registry-resolved package; workspace and link entries contribute no registry `ResolvedPackage`, and git/file sources SHALL map to the matching non-registry `ResolvedSource` variants as `package-lock.json` parsing does | must |
| FR-008 | WHEN a specifier is an npm alias (`alias@npm:real-pkg@range`, in v1 or Berry) THE SYSTEM SHALL record the resolved version under the real package name, consistent with the `package-lock.json` alias handling (issue #654); WHEN a Berry resolution is a `patch:` wrapping an npm package THE SYSTEM SHALL resolve to the underlying registry name and version | must |
| FR-009 | WHEN the same package name resolves to several versions in one lock file THE SYSTEM SHALL record every distinct version in `ResolvedPackages` so existing semver-range-based selection picks the right one per occurrence (as in spec 052 FR-007) | must |
| FR-010 | WHEN reading `yarn.lock` THE SYSTEM SHALL use the shared capped, TOCTOU-safe path (`deps_core::lockfile::read_lockfile_content`, which wraps `deps_core::fs_probe::read_to_string_capped` with the 32 MiB cap) and SHALL execute parsing off the async executor via `spawn_blocking` | must |
| FR-011 | WHEN `yarn.lock` is empty, contains only comments/`__metadata`, or has no resolvable entries THE SYSTEM SHALL return an empty `ResolvedPackages`, not an error | must |
| FR-012 | WHEN the content is malformed or exceeds parser bounds THE SYSTEM SHALL return `DepsError::ParseError` (no new error variant) with credential-bearing URLs redacted as the existing pnpm/package-lock paths do, and SHALL NOT panic | must |
| FR-013 | THE SYSTEM SHALL key all yarn-derived output by `NormalizedName` (via the same name-normalization path the npm ecosystem already uses) so lookups match manifest dependency names regardless of spelling variants | must |
| FR-014 | WHEN a lock file's yarn format version is unrecognized (e.g. a future Berry `__metadata.version` beyond those supported) THE SYSTEM SHALL return a `ParseError` naming the version rather than silently returning wrong data | should |
| FR-015 | WHEN an entry's header (v1) or key (Berry) lists several declared requirements for one package name THE SYSTEM SHALL record every one of them, as written (a Berry default `npm:` protocol prefix removed, an alias reduced to its real range), as that entry's descriptors; WHEN a manifest's own declared requirement text equals a descriptor of a satisfying entry THE SYSTEM SHALL select that entry as the dependency's version before falling back to the highest satisfying entry; non-registry entries carry no descriptors (#1993) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing a `yarn.lock` at the 32 MiB cap must not block the executor; the lock file cache's mtime comparison is reused with no provider override |
| NFR-002 | Security | `yarn.lock` is untrusted repo-sourced input: bounded size, bounded YAML depth/expansion, hand-written v1 parser must be linear-time and allocation-bounded relative to input size |
| NFR-003 | Testing | A libFuzzer target for yarn lock parsing (v1 and Berry) SHALL be added under `fuzz/fuzz_targets/` following `pnpm_lockfile.rs`, with a seed corpus under `fuzz/seeds/`, and a public `fuzz_parse_*` entry point in `crates/deps-npm/src/lockfile.rs` as the existing parsers expose |
| NFR-004 | Consistency | Behavior parity with `package-lock.json` / `pnpm-lock.yaml` for hover, inlay hints and OSV matching; shared logic lives in `deps-core` where more than one ecosystem could use it |
| NFR-005 | Backward compatibility | Zero behavioral change for projects whose directory has a higher-precedence lock file or no `yarn.lock` |

## 5. Data Model

No new public types beyond a private lock-format classification enum. Reuses `deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| yarn v1 entry | Header of comma-separated `name@range` specifiers plus indented fields | `version`, `resolved`, `integrity`, `dependencies` |
| Berry entry | YAML mapping keyed by a comma-joined specifier string | `version`, `resolution` (`name@protocol:ref`), `checksum`, `linkType`, `languageName` |
| Berry `__metadata` | File-level header | `version`, `cacheKey` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `yarn.lock` and `package-lock.json` in same directory | Higher-precedence file per FR-002 wins; `yarn.lock` is not read |
| `yarn.lock` only in an ancestor directory (workspace root) | Located via ancestor search; resolves member manifests |
| Header with multiple specifiers (`"a@^1.0.0", a@~1.2.0:`) | One resolved version recorded for name `a`; duplicate specifiers do not create duplicate candidates, and both specifiers are kept as that entry's descriptors (FR-015) |
| Scoped package `"@scope/pkg@^1.0.0":` | Name extracted as `@scope/pkg` |
| Alias `"my-react@npm:react@^18.0.0"` | Recorded under `react` (FR-008) |
| Berry `workspace:` / `link:` entry | Skipped (FR-007) |
| Berry `patch:` entry (`typescript@patch:typescript@npm%3A5.3.3#...`) | Resolved to underlying `typescript` 5.3.3 (FR-008); URL-encoded `%3A` handled |
| Berry git dependency | Non-registry source; not treated as registry version |
| Empty file / comments only | Empty `ResolvedPackages` (FR-011) |
| Truncated or corrupt v1 entry (header without `version`) | Entry skipped with a sanitized log line, parse continues, as `package-lock.json` handles a missing `version` |
| Malformed Berry YAML | `ParseError` (FR-012) |
| CRLF line endings, BOM, tabs in v1 | Parsed identically to LF input |
| File over 32 MiB, symlink, or non-regular file | Rejected by the shared capped read, same as other lock files |
| File replaced between stat and read | TOCTOU-safe read path handles it (FR-010) |
| Non-semver `version` value | Logged sanitized and skipped, consistent with issue #1505 handling |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live probe from the Problem Statement (request 2.88.2, yarn v1) | Emits `GHSA-p8p7-x288-28g6`; no "not checked" diagnostic |
| SC-002 | Same probe with a Berry lock file | Identical diagnostic outcome |
| SC-003 | Existing `package-lock.json` / `pnpm-lock.yaml` tests | 0 regressions, 0 changed assertions |
| SC-004 | New unit tests: v1 simple/multi-specifier/scoped/alias, Berry registry/workspace/patch/alias/git, empty, malformed, precedence, ancestor lookup | all pass |
| SC-005 | Fuzz target runs for the CI smoke duration without crash or timeout | pass |
| SC-006 | Cross-ecosystem live check | yarn, npm and pnpm fixtures give the same hover/inlay/diagnostic shape |
| SC-007 | `cargo clippy --workspace --all-targets --all-features -- -D warnings`, fmt check, `cargo nextest run --workspace --all-features`, rustdoc `-D warnings` gate | all green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the `NpmLockParser` patterns in `crates/deps-npm/src/lockfile.rs` and reuse `deps-core` helpers (`read_lockfile_content`, `fs_probe`, YAML bound guards) before writing local code
- Verify against live probes, including both yarn formats, per `.claude/rules/continuous-improvement.md`
- Update CHANGELOG `[Unreleased]` (one line plus PR link), the mdBook Ecosystem Reference, `docs/ECOSYSTEM_GUIDE.md` limitation note, and the `.local/testing` coverage/playbook/regressions entries

### Ask First
- Adding a third-party dependency for yarn v1 parsing (preference: small in-tree parser)
- Changing shared `deps-core` lock-file helper signatures to host the precedence decision (FR-002)
- Changing existing precedence between `package-lock.json` and `pnpm-lock.yaml`

### Never
- Use `std::fs` reads that bypass the capped TOCTOU-safe path, or block the async executor
- Add `#[non_exhaustive]` or catch-all arms to the lock-format enum
- Touch `crates/deps-zed` or start work on other lock formats from #709

## 9. Open Questions

- [NEEDS CLARIFICATION: Precedence when `yarn.lock` coexists with `package-lock.json` or `pnpm-lock.yaml`. Proposed `package-lock.json` > `pnpm-lock.yaml` > `yarn.lock`; alternative is preferring the file matching `packageManager` in `package.json` or the most recently modified. Needs a decision recorded once in `deps-core`.]
- [NEEDS CLARIFICATION: Berry `__metadata.version` range to support (e.g. 6 through current) and the policy for newer values (FR-014).]
- [NEEDS CLARIFICATION: Whether Berry `patch:` entries should surface the patched state in hover, or only the underlying version (current proposal: underlying version only).]
- [NEEDS CLARIFICATION: Whether precedence/dispatch logic should be generalized in `deps-core` now so a later `bun.lock` follow-up reuses it.]
- [NEEDS CLARIFICATION: Whether a follow-up issue for the remaining #709 formats (bun, deno, gradle, Pipfile, pdm) should be filed alongside this work.]

## 10. See Also

- [[052-pnpm-lockfile-provider/spec]] - sibling spec this extends
- [[constitution]] - project principles
- [[MOC-specs]] - all specifications
- `crates/deps-npm/src/lockfile.rs` - `NpmLockParser`, `NpmLockfileKind`, `fuzz_parse_pnpm_lock_yaml`
- `crates/deps-npm/src/ecosystem.rs` - `lockfile_filenames()`
- `crates/deps-core/src/lockfile.rs` - `LockFileProvider`, `read_lockfile_content`, `locate_lockfile_for_manifest`
- `fuzz/fuzz_targets/pnpm_lockfile.rs` - fuzz target pattern
- Issue #709 - origin issue (closed; pnpm only shipped)

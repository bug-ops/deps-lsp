---
aliases:
  - bun.lock Lock File Provider
  - Bun Lockfile Resolution
tags:
  - sdd
  - spec
  - npm
  - bun
  - cross-ecosystem
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[052-pnpm-lockfile-provider/spec|pnpm-lock.yaml Lock File Provider]]"
---

# Feature: `bun.lock` Lock File Provider (npm ecosystem)

> [!info] Metadata
> **Author**: research/parity scan, follow-up to issue #709
> **Category**: enhancement/parity, P3
> **Branch**: (none yet — spec stage)

## 1. Overview

### Problem Statement

`crates/deps-npm`'s `LockFileProvider` (`NpmLockParser`, `crates/deps-npm/src/lockfile.rs`)
resolves in-use dependency versions from `package-lock.json` and `pnpm-lock.yaml`
only. Verified 2026-11-08: `Ecosystem::lockfile_filenames()` in
`crates/deps-npm/src/ecosystem.rs:149` returns `["package-lock.json", "pnpm-lock.yaml"]`.
A Bun project has neither file, so the "in-use version" column (hover, inlay hints)
and the resolved-version basis for OSV vulnerability matching fall back to the
manifest's semver *requirement*. A live probe of a manifest with an unsupported
lock file (`yarn.lock`) shows the failure mode Bun users see today: the
vulnerability diagnostic reports "vulnerability data was not checked ... no
resolved or exact version was available".

Issue #709 (closed 2026-09-09) listed `bun.lock` among the missing providers. Only
`pnpm-lock.yaml` shipped ([[052-pnpm-lockfile-provider/spec]]); no follow-up was
filed for the rest, so the `bun.lock` gap is currently untracked.

Since Bun 1.2, `bun.lock` is a text lock file in JSONC (JSON with comments and
trailing commas allowed), per the [Bun lockfile docs](https://bun.sh/docs/install/lockfile).
Issue #709's data counted about 237k `bun.lock` files on GitHub. Dependabot core
v0.400.0 added "Support Bun 1.4 and lockfile versions 2 and 3"
(`dependabot/dependabot-core` PR #16485), so the format carries a `lockfileVersion`
that must be handled explicitly. The older binary `bun.lockb` is not parseable as
text.

> [!warning] Assumption
> The exact `bun.lock` layout (a `workspaces` map keyed by workspace path and a
> `packages` map whose values are tuples led by a `name@version` identifier) is
> taken from Bun's documentation and public examples, not yet verified against
> real Bun 1.2-1.4 output. See [[#9. Open Questions]].

### Goal

When a `package.json` in a Bun-managed project (workspace root or single package)
has an adjacent or ancestor `bun.lock`, `NpmLockParser` resolves it as a lock file:
hover, inlay hints, and OSV matching use the Bun-resolved version exactly as they
do for `package-lock.json` and `pnpm-lock.yaml`, with no ecosystem-visible
difference between lock formats.

### Out of Scope

- `bun.lockb` (binary lock file, Bun below 1.2 and the opt-in legacy mode). Not
  detected and not parsed; see FR-011 for the user-visible behavior.
- `yarn.lock` (v1 and Berry), `deno.lock`, `gradle.lockfile`, `Pipfile.lock`,
  `pdm.lock` — separate follow-ups, to be tracked individually.
- A user-configurable lock file precedence setting — precedence is fixed (FR-002).
- Reading integrity hashes, tarball URLs, or the peer-dependency graph from
  `bun.lock` entries beyond what is needed to obtain name and version.
- Bun-specific manifest features (`catalog:` handling for Bun workspaces is
  governed by the existing catalog spec, not this one).
- Writing or modifying any lock file.

## 2. User Stories

### US-001: Hover shows the Bun-resolved version

AS A developer using Bun
I WANT hover to show the version Bun actually installed for a dependency
SO THAT I can trust the in-use version as I do on npm and pnpm projects

**Acceptance criteria:**
```
GIVEN a package.json with "react": "^18.0.0" and a sibling bun.lock resolving
  react to 18.2.0
WHEN the user hovers the "react" dependency line
THEN the hover shows 18.2.0 as the in-use version, identically to a
  package-lock.json-resolved version
```

### US-002: OSV matching uses the resolved version

AS A developer using Bun
I WANT vulnerability diagnostics to check the installed version
SO THAT I do not see "vulnerability data was not checked" for every dependency in my project

**Acceptance criteria:**
```
GIVEN a package.json whose requirement is satisfied by a vulnerable and a patched
  version, and a bun.lock resolving to the patched version
WHEN diagnostics are generated
THEN the vulnerability diagnostic is evaluated against the lock-resolved version
  and no "not checked" notice is emitted for that dependency
```

### US-003: Bun workspaces are covered

AS A developer in a Bun workspace (several `package.json` files under one root `bun.lock`)
I WANT every member's dependencies resolved from the shared lock file
SO THAT opening any member package gets correct in-use versions

**Acceptance criteria:**
```
GIVEN a root bun.lock with workspaces "" and "packages/foo", and
  packages/foo/package.json depends on "lodash"
WHEN the user hovers "lodash" in packages/foo/package.json
THEN the hover shows the version resolved for lodash in the shared lock file
```

### US-004: Trailing commas and comments do not break parsing

AS A Bun user
I WANT a normal Bun-written `bun.lock` (which uses trailing commas) to parse
SO THAT the feature works on real files and not only on hand-cleaned fixtures

**Acceptance criteria:**
```
GIVEN a bun.lock whose objects and arrays end with trailing commas
WHEN the lock file is parsed
THEN resolution succeeds and returns the same packages as the comma-free equivalent
```

### US-005: Existing lock formats are not disturbed

AS A maintainer of the npm ecosystem crate
I WANT `package-lock.json` and `pnpm-lock.yaml` behavior unchanged
SO THAT this addition cannot regress the more common cases

**Acceptance criteria:**
```
GIVEN a project with only package-lock.json or only pnpm-lock.yaml
WHEN any hover, inlay hint, or diagnostic request is made
THEN results and code path are identical to before this feature
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `NpmLockParser::locate_lockfile` searches a manifest's directory and ancestors THE SYSTEM SHALL also consider `bun.lock`, using the existing first-match-wins `locate_lockfile_for_manifest` helper | must |
| FR-002 | WHEN more than one npm-ecosystem lock file exists in the same directory THE SYSTEM SHALL resolve from exactly one, chosen by a single fixed precedence defined once in the shared lock file location code, not per file type in `deps-npm` call sites | must |
| FR-003 | WHEN parsing a `bun.lock` THE SYSTEM SHALL accept JSONC, including trailing commas and comments, and SHALL NOT fail on input that Bun itself writes | must |
| FR-004 | WHEN parsing a `bun.lock` THE SYSTEM SHALL read the file through `deps_core::fs_probe::read_to_string_capped` (via the shared lock file read path) with the existing lock file size cap, and run the CPU-bound parse inside `spawn_blocking` | must |
| FR-005 | WHEN parsing a `bun.lock` THE SYSTEM SHALL bound nesting depth with the same limit used for JSON lock files, returning the same nesting-too-deep error shape | must |
| FR-006 | WHEN the lock file's `lockfileVersion` is a version this feature supports THE SYSTEM SHALL parse it; WHEN it is absent, unknown, or newer than the highest supported version THE SYSTEM SHALL return `DepsError::ParseError` naming the version rather than guess at the layout | must |
| FR-007 | WHEN reading the `packages` map THE SYSTEM SHALL emit one resolved package per registry entry, taking name and version from the entry's resolved identifier (`name@version`), correctly handling scoped names (`@scope/name@version`) and `npm:` aliases (the real registry name, not the alias key) | must |
| FR-008 | WHEN a `packages` entry resolves to a non-registry source (workspace member, `file:`, `link:`, git, tarball) THE SYSTEM SHALL record it with the matching `ResolvedSource` kind or skip it, consistently with `package-lock.json` handling, and SHALL NOT report it as a registry version | must |
| FR-009 | WHEN the same package name resolves to several versions (nested or per-workspace) THE SYSTEM SHALL record every distinct version as a candidate in `ResolvedPackages`, relying on existing semver-based per-occurrence selection | must |
| FR-010 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the LSP file watcher THE SYSTEM SHALL include `bun.lock` so edits to it re-parse and refresh dependent manifests | must |
| FR-011 | WHEN a `bun.lockb` exists with no usable text lock file THE SYSTEM SHALL behave as if no lock file exists and SHOULD log a single debug-level note that the binary format is unsupported | should |
| FR-012 | WHEN a `bun.lock` is looked up through the lock file cache THE SYSTEM SHALL rely on the existing mtime-keyed `LockFileCache` behavior, with no provider override | should |
| FR-013 | THE SYSTEM SHALL provide a fuzz target for the `bun.lock` content parser, following the existing `fuzz_parse_*` entry-point and `fuzz/fuzz_targets/` pattern | should |
| FR-014 | WHEN the lock file output is keyed by package name THE SYSTEM SHALL use the same `NormalizedName`-keyed convention as the other npm lock parsers, with no stringly-typed key introduced | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing a `bun.lock` at the lock file size cap must not block the async executor; no new blocking I/O outside `spawn_blocking` |
| NFR-002 | Security | `bun.lock` is untrusted repository input: size cap, nesting-depth cap, and bounded memory apply; error messages and logs must not echo credential-bearing URLs (reuse the existing redaction used for lock file errors) |
| NFR-003 | Consistency | No new `DepsError` variant; reuse `ParseError { file_type, source }` with file type `bun.lock` |
| NFR-004 | Type safety | Lock file kind dispatch uses the existing typed `NpmLockfileKind` enum (new variant, exhaustive match), not filename string comparison |
| NFR-005 | Backward compatibility | Zero behavioral change for projects without a `bun.lock` |
| NFR-006 | Dependencies | Prefer the JSONC parser already in the workspace (`jsonc-parser`, used by `deps-core::json_ast`); any new third-party dependency requires prior approval |

## 5. Data Model

No new public lock types. Reuses `deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `bun.lock` root | JSONC document | `lockfileVersion`, `workspaces`, `packages` |
| `workspaces` map | Per-workspace-member declared dependencies | key: workspace path (`""` for root); value: name, dependency maps |
| `packages` map | Resolved packages | key: install key; value: tuple led by `name@version` identifier, followed by registry/metadata fields |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `bun.lock` only, no other lock file | Resolved via `bun.lock` |
| Several lock files in one directory | Single fixed precedence from FR-002; the others are never read |
| `bun.lock` in an ancestor directory (workspace root) | Found by ancestor search, same depth bound as other lock files |
| Trailing commas / comments | Accepted (FR-003) |
| Empty file or no `packages` key | Empty `ResolvedPackages`, not a parse error |
| Malformed JSONC | `DepsError::ParseError` with the underlying error as source |
| Unknown or newer `lockfileVersion` | `ParseError` naming the version (FR-006) |
| Scoped or aliased package | Real registry name used (FR-007) |
| Workspace-member or `link:`/`file:` entry | Not a registry version (FR-008) |
| Same name, several versions | All candidates recorded (FR-009) |
| Over the size cap, symlink, or non-regular file | Rejected by the existing capped-read contract, as for other lock files |
| Over-deep nesting | Nesting-too-deep error shape shared with JSON lock files |
| Only `bun.lockb` present | Treated as no lock file (FR-011) |
| Lock file edited while the editor is open | Watcher triggers re-parse (FR-010) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Resolved version for dependencies in Bun-only fixtures (single package, workspace, scoped, alias, multi-version) | 100% match with the version Bun recorded |
| SC-002 | Real-file coverage: `bun.lock` files generated by Bun 1.2 and the current Bun 1.4 for each supported `lockfileVersion` parse without error | all pass |
| SC-003 | Existing `package-lock.json` and `pnpm-lock.yaml` tests | 0 regressions, 0 changed assertions |
| SC-004 | Live check: a Bun-only project's OSV diagnostics | no "not checked, no resolved version" notice for dependencies present in the lock file |
| SC-005 | Fuzz target runs without crashes for the CI smoke budget | pass |
| SC-006 | `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo +nightly fmt --all -- --check`, `cargo nextest run -p deps-npm` | all green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the existing `NpmLockParser` patterns (typed kind enum, shared capped read, `ParseError` shape, inline fixtures)
- Check `deps-core::json_ast`, `json_helpers`, `fs_probe`, and `lockfile` for existing shared helpers before writing npm-local code
- Verify behavior live against real Bun-generated lock files per `.claude/rules/continuous-improvement.md`
- Update `CHANGELOG.md` `[Unreleased]` (one line plus PR link) and the ecosystem docs known-limitations note

### Ask First
- Adding any new third-party dependency (including a different JSONC parser)
- Changing `deps_core::lockfile` shared helper signatures to implement FR-002
- Changing precedence of existing `package-lock.json` versus `pnpm-lock.yaml`

### Never
- Change existing `package-lock.json` or `pnpm-lock.yaml` resolution behavior
- Touch `crates/deps-zed` (separate submodule repository)
- Add a catch-all `_ =>` arm to the lock kind match
- Start work on `bun.lockb` or other lock formats under this spec

## 9. Open Questions

> [!question] Open items
> - [NEEDS CLARIFICATION: Is `jsonc-parser` (already used by `deps-core::json_ast`) tolerant of trailing commas under its default `ParseOptions`, and can its value tree feed a typed lock structure without an intermediate `serde_json::Value`? Today `parse_json_checked` is strict `serde_json` and rejects trailing commas, so it cannot be reused as is. Decide whether to add a shared JSONC-to-typed helper in `deps-core`, since other ecosystems may need it.]
> - [NEEDS CLARIFICATION: Which `lockfileVersion` values must be supported at launch (0, 1, 2, 3)? Confirm the `packages` tuple layout is stable across them using real files from Bun 1.2 through 1.4.]
> - [NEEDS CLARIFICATION: Cross-format precedence when `bun.lock` coexists with `package-lock.json` and/or `pnpm-lock.yaml` in one directory. Candidates: fixed order with `package-lock.json` first (consistent with spec 052); or prefer the lock file matching the `packageManager` field in `package.json` when present. Decide once in `deps-core`.]
> - [NEEDS CLARIFICATION: How does Bun encode workspace-member and `catalog:` dependencies in `packages`, and should they map to `ResolvedSource` local kinds or be skipped?]
> - [NEEDS CLARIFICATION: Should `bun.lockb`-only projects get a user-visible hint (diagnostic or log) suggesting `bun install --save-text-lockfile`, or stay silent per FR-011?]

## 10. See Also

- [[052-pnpm-lockfile-provider/spec|052 pnpm-lock.yaml Lock File Provider]] — sibling spec and the pattern this extends
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issue #709 — origin issue that listed `bun.lock` among missing providers
- `crates/deps-npm/src/lockfile.rs` — `NpmLockParser`, `NpmLockfileKind`
- `crates/deps-npm/src/ecosystem.rs` — `lockfile_filenames()`
- `crates/deps-core/src/lockfile.rs` — `LockFileProvider`, `locate_lockfile_for_manifest`, `read_and_parse_lockfile`
- `crates/deps-core/src/json_ast.rs` — shared `jsonc-parser` usage
- [Bun lockfile documentation](https://bun.sh/docs/install/lockfile)

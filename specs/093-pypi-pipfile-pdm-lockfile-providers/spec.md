---
aliases:
  - PyPI Pipfile.lock and pdm.lock Providers
  - pipenv and PDM Lock File Resolution
tags:
  - sdd
  - spec
  - pypi
  - pipenv
  - pdm
  - cross-ecosystem
  - enhancement
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[052-pnpm-lockfile-provider/spec|pnpm-lock.yaml Lock File Provider]]"
---

# Feature: `Pipfile.lock` and `pdm.lock` Lock File Providers (PyPI ecosystem)

> [!info] Metadata
> **Author**: research cycle, follow-up to issue #709
> **Branch**: (none yet - spec stage)
> **Category / priority**: enhancement, P4

## 1. Overview

### Problem Statement

`PypiLockParser` (`crates/deps-pypi/src/lockfile.rs`) resolves in-use dependency
versions only from `poetry.lock` and `uv.lock`. Verified 2026-11-08:
`PypiLockParser::LOCKFILE_NAMES` and `Ecosystem::lockfile_filenames()`
(`crates/deps-pypi/src/ecosystem.rs:179`) both return exactly
`["poetry.lock", "uv.lock"]`. Projects managed with pipenv (`Pipfile.lock`) or
PDM (`pdm.lock`) therefore get no in-use version column (hover, inlay hints),
and OSV vulnerability matching falls back to the manifest's requirement range
instead of the version actually installed. This is the same inconsistency class
that [[052-pnpm-lockfile-provider/spec]] closed for pnpm.

`Pipfile.lock` appears in the repo only inside a file-watcher unit test
(`crates/deps-lsp/src/file_watcher.rs`, `extract_lockfile_name`); it is never
parsed and is not a registered lock file name.

History: issue #709 (closed 2026-09-09) listed both formats among seven missing
lock formats. Only `pnpm-lock.yaml` shipped (spec 052) and no follow-up issue
was filed for the PyPI formats. This spec is that follow-up.

> [!warning] Manifest asymmetry between the two formats
> The two lock files have very different practical reach today:
> - **`pdm.lock`** pairs with `pyproject.toml` (PDM uses PEP 621 metadata),
>   which the PyPI ecosystem already parses. Adding the lock provider is
>   sufficient for end-to-end value.
> - **`Pipfile.lock`** pairs with `Pipfile`. Verified 2026-11-08: the PyPI
>   ecosystem registers no `Pipfile` manifest (`PypiManifestKind` has only
>   `PyProject` and `Requirements`; no `Pipfile` match exists in
>   `crates/deps-pypi`). A pipenv project that has only a `Pipfile` and
>   `Pipfile.lock` gets no deps-lsp features at all, so a `Pipfile.lock`
>   provider alone helps only pipenv projects that also keep a
>   `pyproject.toml` or `requirements*.txt`. See FR-010 and Open Questions.

### Goal

When a PyPI manifest has an adjacent or ancestor `pdm.lock` or `Pipfile.lock`,
`PypiLockParser` resolves it as a lock file, so hover, inlay hints, and OSV
matching use the locked version exactly as they already do for `poetry.lock`
and `uv.lock`, with no user-visible difference between lock formats.

### Out of Scope

- `Pipfile` as a manifest type (parsing `[packages]`/`[dev-packages]`,
  hover/completion/diagnostics on it) - separate decision, see FR-010 and §9.
- Other lock formats from issue #709 (`yarn.lock`, `bun.lock`, `deno.lock`,
  `gradle.lockfile`) - separate follow-ups.
- `pip-tools` outputs, `pylock.toml` (PEP 751), and Hatch/Rye lock files.
- Reading hashes, markers, or dependency edges beyond what the shared
  `ResolvedPackage` already carries for Poetry/uv (checksum population for
  registry entries is optional, not required).
- A user-configurable lock-file precedence setting.
- Touching `crates/deps-zed` (submodule, separate repo).

## 2. User Stories

### US-001: PDM project shows locked versions

AS A developer using PDM
I WANT hover and inlay hints to show the version recorded in `pdm.lock`
SO THAT I see what is installed, not just the range in `pyproject.toml`

**Acceptance criteria:**
```
GIVEN a pyproject.toml with "requests>=2.0" and a sibling pdm.lock resolving
  requests to 2.31.0
WHEN the user hovers the requests dependency
THEN the hover shows 2.31.0 as the in-use version, identically to a
  poetry.lock-resolved dependency
```

### US-002: pipenv project shows locked versions

AS A developer using pipenv
I WANT the version from `Pipfile.lock` used as the in-use version
SO THAT outdated and vulnerable diagnostics reflect what pipenv installed

**Acceptance criteria:**
```
GIVEN a manifest recognised by the PyPI ecosystem and a sibling Pipfile.lock
  whose default section pins flask to "==3.0.0"
WHEN diagnostics and hover are generated for flask
THEN the in-use version is 3.0.0 and OSV matching uses 3.0.0
```

### US-003: Deterministic choice when several lock files coexist

AS A maintainer of a repository migrating between tools
I WANT one documented, fixed lock-file precedence
SO THAT results do not change depending on directory listing order

**Acceptance criteria:**
```
GIVEN a directory containing both poetry.lock and pdm.lock (or uv.lock and
  Pipfile.lock, etc.)
WHEN the lock file is located for a manifest in that directory
THEN exactly one file is chosen according to the documented precedence, on
  every platform and every run
```

### US-004: Existing Poetry/uv behaviour is undisturbed

AS A maintainer of the PyPI crate
I WANT `poetry.lock` and `uv.lock` resolution unchanged
SO THAT the more common cases cannot regress

**Acceptance criteria:**
```
GIVEN a project with only poetry.lock or only uv.lock
WHEN any hover, inlay hint, or diagnostic request is made
THEN results are identical to before this feature
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `PypiLockParser::locate_lockfile` searches a manifest's directory and ancestors THE SYSTEM SHALL also consider `pdm.lock` and `Pipfile.lock`, in the precedence order fixed by FR-002, using the existing first-match-wins `locate_lockfile_for_manifest` semantics (all names checked per directory before moving to the parent) | must |
| FR-002 | WHEN more than one supported PyPI lock file exists in the same directory THE SYSTEM SHALL select exactly one by a single fixed order recorded in one place in `deps-core` (shared constant or helper, not re-derived per crate). Proposed order: `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`. The existing relative order of `poetry.lock` before `uv.lock` MUST NOT change unless the open question in §9 resolves otherwise | must |
| FR-003 | WHEN `parse_lockfile` receives a `pdm.lock` path THE SYSTEM SHALL parse it as TOML through `deps_core::parse_toml_checked`, read each `[[package]]` entry's `name` and `version`, and ignore entries missing either field with a bounded, redacted log line | must |
| FR-004 | WHEN `parse_lockfile` receives a `Pipfile.lock` path THE SYSTEM SHALL parse it as JSON through the shared JSON parsing path (`deps-core::json_ast` / `parse_json_checked` depth guard), read the `default` and `develop` sections, and strip the leading `==` from each entry's `version` to obtain the plain version | must |
| FR-005 | WHEN a `Pipfile.lock` entry has no `version` field (VCS, path, or editable entries, which carry `git`, `path`, or `editable` keys instead) THE SYSTEM SHALL record it with a non-registry `ResolvedSource` where one exists, or skip it, but SHALL NOT emit a fabricated version string | must |
| FR-006 | WHEN a package name is read from either file THE SYSTEM SHALL normalise it with the PyPI formatter's PEP 503 `NormalizedName` (`crate::name::normalize`) before insertion, so lookups are case, `_`, `-`, and `.` insensitive exactly as for Poetry/uv | must |
| FR-007 | WHEN a `pdm.lock` or `Pipfile.lock` declares a format version this feature does not understand (`pdm.lock` `lock_version` outside the supported range; `Pipfile.lock` `_meta.pipfile-spec` other than the known value) THE SYSTEM SHALL return `DepsError::ParseError` naming the unsupported version rather than silently misparsing. The supported ranges are an Open Question | should |
| FR-008 | WHEN the same package name appears more than once in a lock file (PDM per-group or per-marker duplicates; `default` and `develop` both pinning the same name) THE SYSTEM SHALL record every distinct version via `ResolvedPackages::insert` using the existing multi-version-per-name behaviour, with no importer or group correlation performed | must |
| FR-009 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the LSP file watcher THE SYSTEM SHALL include `pdm.lock` and `Pipfile.lock` so edits to either file trigger a re-resolve, using the same FR-002 constant so the watcher list and locator list cannot drift | must |
| FR-010 | WHEN a directory contains `Pipfile` and `Pipfile.lock` but no other PyPI manifest THE SYSTEM SHALL behave as it does today (no features on `Pipfile`) unless the §9 decision to add a `Pipfile` manifest type is taken, in which case that work is specified separately | should |
| FR-011 | WHEN a lock file is read THE SYSTEM SHALL read it through the capped read path (`deps_core::fs_probe::read_to_string_capped`, via the existing `read_and_parse_lockfile` helper) and run the parse closure on the `spawn_blocking` pool, with no new unbounded or blocking I/O | must |
| FR-012 | WHEN a located lock file is requested repeatedly THE SYSTEM SHALL rely on `LockFileCache::get_or_parse`'s existing mtime-keyed caching with no provider-side override | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing either format up to the existing lock file size cap must not block the async executor (FR-011) |
| NFR-002 | Security | Both lock files are untrusted, repo-sourced input. TOML and JSON parsing must use the existing depth-guarded entry points; package names taken from the file are attacker-controlled and must be truncated/redacted in logs as the Poetry/uv parser already does |
| NFR-003 | Consistency | No new `DepsError` variant; reuse `ParseError` shape. Name normalisation, multi-version handling, and precedence logic live in shared code or follow the Poetry/uv implementation, not ecosystem-local reimplementations |
| NFR-004 | Type safety | Lock file kinds are represented by an exhaustive enum (not string matching on file names) wherever the parser dispatches on format; no catch-all `_ =>` arm |
| NFR-005 | Robustness | Each new parser has a fuzz target (or extends the existing `toml_lockfiles` / `json_lockfiles` targets) with seed corpus entries, gated on the `fuzzing` feature like `fuzz_parse_pypi_lock` |
| NFR-006 | Backward compatibility | Zero behavioural change for projects with no `pdm.lock` or `Pipfile.lock` (US-004) |

## 5. Data Model

No new public result types; reuses `deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `pdm.lock` | TOML; top-level `[metadata]` (`lock_version`, `groups`, `content_hash`) and `[[package]]` array | per package: `name`, `version`, optional `groups`, `summary`, `files`, optional git/path source keys |
| `Pipfile.lock` | JSON; `_meta` (`hash`, `pipfile-spec`, `sources`), `default` and `develop` maps | per entry: `version` (`"==x.y.z"`), `hashes`, `index`, optional `markers`, or `git`/`path`/`editable` for non-registry entries |
| Lock file precedence | Single ordered list of supported PyPI lock file names | shared in `deps-core`, consumed by locator and watcher |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Only `pdm.lock` present next to `pyproject.toml` | Resolved via `pdm.lock` |
| Several PyPI lock files in one directory | Exactly one chosen per FR-002; the others are never read |
| Lock file in an ancestor directory, none adjacent | Found via the existing ancestor search depth |
| `Pipfile.lock` entry `"version": "==2.31.0"` | Stored as `2.31.0` |
| `Pipfile.lock` entry with no `version` (git/path/editable) | Not given a fabricated version (FR-005) |
| `Pipfile.lock` entry `version` not starting with `==` | [NEEDS CLARIFICATION: pipenv always writes `==`; decide whether to store verbatim or skip and log] |
| Same name in `default` and `develop` with different versions | Both recorded (FR-008) |
| Name with mixed case, `_`, or `.` (`Django_Rest.Framework`) | Normalised per PEP 503 (FR-006) |
| Empty file, or missing `[[package]]` / `default` / `develop` | Empty `ResolvedPackages`, not a parse error (mirrors Poetry/uv behaviour) |
| Malformed TOML or JSON | `DepsError::ParseError` with redacted source |
| Over-deep nesting | Reported as the shared nesting-too-deep error, same as other parsers |
| File larger than the size cap, symlink, or non-regular file | Rejected by the capped read path, same as other lock files |
| Unsupported `lock_version` / `pipfile-spec` | `DepsError::ParseError` naming the version (FR-007) |
| `Pipfile.lock` present but no recognised manifest | No features, as today (FR-010) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | In-use version for a dependency in a PDM project and in a pipenv project (with a recognised manifest) matches the lock file | 100% on test fixtures (single package, multiple groups, duplicates, VCS/path entry, normalised names) |
| SC-002 | Existing Poetry/uv lock tests | 0 regressions, 0 changed assertions |
| SC-003 | New unit tests per format (happy path, empty, malformed, unsupported version, multi-version, missing fields) | all pass, following the existing fixture and `tempfile` pattern in `crates/deps-pypi/src/lockfile.rs` |
| SC-004 | Precedence test: every ordered pair of coexisting lock files | resolves to the FR-002 winner deterministically |
| SC-005 | Fuzz targets run for a fixed smoke duration | no panics or timeouts |
| SC-006 | Live check against a real pipenv and a real PDM project | hover and OSV use locked versions (per `.claude/rules/continuous-improvement.md` live testing rule) |
| SC-007 | `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo +nightly fmt --all -- --check`, `cargo nextest run -p deps-pypi`, rustdoc gate | all green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the existing `PypiLockParser` / `read_and_parse_lockfile` patterns and reuse `deps-core` helpers (`json_ast`, `fs_probe`, `parse_toml_checked`) before writing ecosystem-local code
- Run the full pre-commit check suite per `.claude/rules/branching.md`
- Update `CHANGELOG.md` `[Unreleased]` (one line plus PR link), the mdBook PyPI ecosystem page, and the testing knowledge base (`coverage.md`, PyPI playbook, `regressions.md` if a bug is found)

### Ask First
- Changing `deps_core::lockfile` shared trait or helper signatures to host the FR-002 precedence
- Reordering the existing `poetry.lock` / `uv.lock` precedence
- Adding any new third-party dependency
- Adding a `Pipfile` manifest type (§9)

### Never
- Change Poetry or uv resolution behaviour
- Duplicate precedence, name-normalisation, or JSON-depth logic per crate
- Fabricate a version for an entry that has none
- Touch `crates/deps-zed`

## 9. Open Questions

- [NEEDS CLARIFICATION: Add a `Pipfile` manifest type? Without it, `Pipfile.lock` only benefits pipenv projects that also keep `pyproject.toml` or `requirements*.txt`. If yes, it should be its own spec; if no, should `Pipfile.lock` support still ship given its limited reach, or be deferred behind `pdm.lock`?]
- [NEEDS CLARIFICATION: Final precedence when several lock files coexist. Proposed `uv.lock`, `poetry.lock`, `pdm.lock`, `Pipfile.lock`; but the current order is `poetry.lock` then `uv.lock`, and changing it alters behaviour for repos holding both. Alternative: keep `poetry.lock`, `uv.lock` first and append `pdm.lock`, `Pipfile.lock`. Should precedence ever follow the manifest (e.g. `[tool.pdm]` / `[tool.poetry]` tables in `pyproject.toml`) instead of a fixed order?]
- [NEEDS CLARIFICATION: Supported `lock_version` range for `pdm.lock` (2.x in current PDM) and the `_meta.pipfile-spec` value(s) for `Pipfile.lock`; verify against current PDM and pipenv releases before planning.]
- [NEEDS CLARIFICATION: Should lock-file `develop` / non-default PDM `groups` entries be distinguished from runtime ones, or all treated as candidates (current proposal: all candidates, FR-008)?]
- [NEEDS CLARIFICATION: Ship as one PR or two (`pdm.lock` first, as it needs no manifest work)?]

## 10. See Also

- [[052-pnpm-lockfile-provider/spec]] - sibling lock provider spec; same shape, same origin issue #709
- [[constitution]] - project principles
- [[MOC-specs]] - all specifications
- Issue #709 - origin issue (closed 2026-09-09; PyPI formats never followed up)
- `crates/deps-pypi/src/lockfile.rs` - `PypiLockParser`, `parse_pypi_lock`, `fuzz_parse_pypi_lock`
- `crates/deps-pypi/src/ecosystem.rs` - `lockfile_filenames()`, `PypiManifestKind`
- `crates/deps-core/src/lockfile.rs` - `LockFileProvider`, `locate_lockfile_for_manifest`, `ResolvedPackages`
- `crates/deps-lsp/src/file_watcher.rs` - watcher lock file name handling
- `fuzz/fuzz_targets/toml_lockfiles.rs`, `fuzz/fuzz_targets/json_lockfiles.rs` - existing lock fuzz targets

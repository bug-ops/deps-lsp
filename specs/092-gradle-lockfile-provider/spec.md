---
aliases:
  - Gradle Lock File Provider
  - gradle.lockfile Resolution
  - Gradle Dependency Locking
tags:
  - sdd
  - spec
  - enhancement
  - ecosystem/gradle
  - cross-ecosystem
  - priority/p4
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[052-pnpm-lockfile-provider/spec|pnpm-lock.yaml Lock File Provider]]"
  - "[[080-gradle-deps-dev-maven-system-routing/spec|Gradle coordinates via deps.dev Maven system]]"
---

# Feature: Gradle Dependency-Locking Lock File Provider

> [!info] Metadata
> **Author**: continuous-improvement cycle finding (enhancement, P4)
> **Branch**: (none yet — spec stage)

## 1. Overview

### Problem Statement

`crates/deps-gradle`'s `Ecosystem::lockfile_filenames()` returns `&[]`
(`crates/deps-gradle/src/ecosystem.rs:192`) and the crate declares
`no_lockfile_support: true` in its trait-conformance tests. Gradle projects
that use dependency locking, Gradle's standard reproducibility mechanism,
therefore get no in-use-version column (hover, inlay hints), and OSV
vulnerability matching runs only against the declared version or range rather
than the version Gradle actually resolved. This is the same inconsistency
class already closed for pnpm ([[052-pnpm-lockfile-provider/spec]]) and which
`.claude/rules/continuous-improvement.md` treats as a cross-ecosystem bug
class. Gradle is 14.4% of respondents in the Stack Overflow 2025 survey.

Verified 2026-11-08. Issue #709 (closed 2026-09-09) listed `gradle.lockfile`;
only `pnpm-lock.yaml` shipped and no follow-up was filed. Related:
commit 8518ce18e routed Gradle coordinates through deps.dev's Maven system
([[080-gradle-deps-dev-maven-system-routing/spec]]), so resolved Maven coordinates
are already the identity used for supply-chain lookups.

### Goal

When a Gradle manifest has an adjacent Gradle dependency-locking file,
`deps-gradle` exposes it through `LockFileProvider`: hover, inlay hints and
OSV matching use the locked version for each Maven coordinate, with no
user-visible difference from how other ecosystems' lock files behave.

### Out of Scope

- Generating or updating lock files (`gradle dependencies --write-locks`) —
  deps-lsp is read-only with respect to project state.
- Gradle version catalogs (`libs.versions.toml`) lock semantics; the catalog
  remains a manifest. Only locked resolutions for coordinates are read.
- Per-configuration semantics beyond union-of-versions: the configuration
  list on each line is not surfaced to users in this spec.
- Gradle verification metadata (`gradle/verification-metadata.xml`) and
  checksums — no integrity data is read.
- Other lock formats from #709 (yarn, bun, Deno, Pipfile, pdm) — separate specs.
- Changing deps.dev / Maven coordinate routing ([[080-gradle-deps-dev-maven-system-routing/spec]]).
- Configurable lock file precedence or location overrides.

## 2. User Stories

### US-001: Hover shows the locked version

AS A developer on a Gradle build with dependency locking enabled
I WANT hover and inlay hints to show the version recorded in the lock file
SO THAT I see what is actually resolved rather than a dynamic or ranged
declaration

**Acceptance criteria:**
```
GIVEN build.gradle.kts declaring "com.google.guava:guava:32.+" and a sibling
  gradle.lockfile containing "com.google.guava:guava:32.1.3-jre=compileClasspath"
WHEN the user hovers the guava dependency
THEN the hover shows 32.1.3-jre as the in-use version
```

### US-002: OSV matching uses the locked version

AS A developer
I WANT vulnerability diagnostics evaluated against the locked version
SO THAT a range or dynamic declaration does not produce false positives or
false negatives

**Acceptance criteria:**
```
GIVEN a dynamic declaration and a lock file pinning a patched version
WHEN diagnostics are generated
THEN the vulnerability result reflects the locked (patched) version
```

### US-003: Multi-module builds resolve per module

AS A developer on a multi-module Gradle build
I WANT each module's manifest to use that module's own lock file
SO THAT modules pinning different versions of the same coordinate are shown correctly

**Acceptance criteria:**
```
GIVEN root and app/ modules each with their own gradle.lockfile pinning
  different versions of the same coordinate
WHEN the user hovers the coordinate in app/build.gradle.kts
THEN the hover shows the version from app/gradle.lockfile
```

### US-004: Legacy per-configuration lock files are honoured

AS A developer on an older Gradle project
I WANT lock files under `gradle/dependency-locks/` to be read
SO THAT projects predating the single-file format also get in-use versions

**Acceptance criteria:**
```
GIVEN gradle/dependency-locks/compileClasspath.lockfile and
  runtimeClasspath.lockfile and no gradle.lockfile
WHEN a hover request is made for a coordinate present in either file
THEN the locked version from the matching file is shown
```

### US-005: Projects without locking are undisturbed

AS A maintainer
I WANT builds without lock files to behave exactly as today
SO THAT this addition cannot regress the common case

**Acceptance criteria:**
```
GIVEN a Gradle project with no lock file
WHEN any LSP request is made
THEN output is identical to before this feature
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `Ecosystem::lockfile_filenames()` is consulted by the file watcher THE SYSTEM SHALL return `gradle.lockfile` and `buildscript-gradle.lockfile` so edits to either trigger a re-resolve | must |
| FR-002 | WHEN a Gradle manifest is opened THE SYSTEM SHALL locate the lock file by searching the manifest's own project directory first, using the shared `deps-core` locate helper and ancestor-depth bound, and SHALL NOT use a lock file from a different module's directory when the manifest's own directory has one | must |
| FR-003 | WHEN a project directory has no `gradle.lockfile` THE SYSTEM SHALL fall back to the legacy `gradle/dependency-locks/*.lockfile` per-configuration files in that project directory and merge their entries | should |
| FR-004 | WHEN parsing a lock file line of the form `group:artifact:version=config1,config2` THE SYSTEM SHALL produce one resolved package keyed by the Maven coordinate `group:artifact` with the given version | must |
| FR-005 | WHEN a line is blank or begins with `#` THE SYSTEM SHALL skip it | must |
| FR-006 | WHEN a line is `empty=` (optionally followed by configuration names) THE SYSTEM SHALL treat it as a marker of locked-but-empty configurations and contribute no packages | must |
| FR-007 | WHEN a line does not match the expected shape (missing `=`, wrong number of coordinate segments, empty group, artifact or version) THE SYSTEM SHALL skip that line without failing the whole file and SHALL log it at debug level | must |
| FR-008 | WHEN the same coordinate appears on multiple lines with different versions THE SYSTEM SHALL record every distinct version as a candidate via the existing multi-version `ResolvedPackages` support, so per-occurrence selection follows existing semantics | must |
| FR-009 | WHEN resolved package keys are produced THE SYSTEM SHALL use the same package-identity normalization the Gradle ecosystem uses for manifest dependencies, so lock entries match manifest lookups for the same coordinate | must |
| FR-010 | WHEN reading a lock file THE SYSTEM SHALL use `deps_core::fs_probe::read_to_string_capped` (via the shared lockfile read helper) so reads are size-capped and TOCTOU-safe | must |
| FR-011 | WHEN a lock file is parsed THE SYSTEM SHALL offload blocking I/O and parsing from the async executor via `spawn_blocking` | must |
| FR-012 | WHEN a located lock file changes on disk THE SYSTEM SHALL re-parse it through the existing mtime-keyed `LockFileCache` and the watched-file re-parse path with no Gradle-specific cache override | should |
| FR-013 | WHEN `Ecosystem::lockfile_provider()` is consulted THE SYSTEM SHALL return a Gradle `LockFileProvider`, and the `no_lockfile_support: true` conformance marker SHALL be replaced by the standard lockfile conformance checks | must |
| FR-014 | WHEN a lock file contains a coordinate with a Gradle dynamic/status suffix or non-semver version string (e.g. `1.0-SNAPSHOT`, `r05`) THE SYSTEM SHALL record the version string verbatim and defer comparison to existing version-comparison fallbacks | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Lock files are untrusted repo-sourced input: reads are size-capped (FR-010), symlinks and non-regular files are rejected by the shared probe, and the parser has no panics or unbounded allocation on arbitrary bytes |
| NFR-002 | Performance | Parsing a lock file at the shared cap must not block the async executor (FR-011); handlers remain non-blocking and use cached state |
| NFR-003 | Consistency | No new `DepsError` variant; reuse the existing `ParseError` shape and shared helpers in `deps-core::lockfile`, introducing no Gradle-local reimplementation of capped reads or ancestor search |
| NFR-004 | Robustness | A fuzz target for the lock file parser exists in `fuzz/fuzz_targets/`, following the `*_lockfile.rs` precedent, with seed corpus entries for the formats in FR-003 to FR-006 |
| NFR-005 | Backward compatibility | Zero behavioural change for projects without lock files (US-005) |
| NFR-006 | Type safety | Coordinates are parsed into typed group/artifact/version values rather than passed around as raw strings; no stringly-typed configuration handling |

## 5. Data Model

No new public cross-crate types are required; resolved data reuses
`deps_core::lockfile::{ResolvedPackage, ResolvedPackages, ResolvedSource}`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `gradle.lockfile` | Per-project single-file lock, one line per locked coordinate | `group:artifact:version=configs`, `empty=` marker, `#` comment header |
| `buildscript-gradle.lockfile` | Same format, locking the build script classpath | same as above |
| `gradle/dependency-locks/<config>.lockfile` | Legacy per-configuration files | one coordinate per line, configuration implied by file name |
| Resolved package | Locked version for a Maven coordinate | name (`group:artifact`), version, source = registry |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Lock file absent | No resolution; behaviour unchanged (US-005) |
| `gradle.lockfile` and legacy `dependency-locks/` both present | `gradle.lockfile` wins; legacy files ignored for that directory (FR-003) |
| `gradle.lockfile` and `buildscript-gradle.lockfile` both present | [NEEDS CLARIFICATION: merge both (buildscript classpath coordinates can overlap with app coordinates) or resolve only `gradle.lockfile` for application manifests and `buildscript-gradle.lockfile` for `buildSrc`/plugin entries?] |
| Multi-module: module has no lock file but root has one | [NEEDS CLARIFICATION: Gradle locks per project, so a root lock file does not describe a submodule; should ancestor fallback be disabled for Gradle to avoid showing root versions for a module?] |
| Lock file contains only `empty=` | Empty `ResolvedPackages`, not an error |
| Malformed line | Line skipped, debug log, rest of file parsed (FR-007) |
| Empty file or comment-only file | Empty `ResolvedPackages` |
| Windows line endings (`\r\n`) | Parsed identically to `\n` |
| Coordinate with classifier or extension segments | [NEEDS CLARIFICATION: Gradle lock lines are three-part; confirm no four-part forms occur and decide skip vs strip] |
| Same coordinate, different versions across configurations | All distinct versions recorded (FR-008) |
| File over size cap, symlink, or non-regular file | Rejected by the shared capped-read helper, same as other ecosystems |
| Non-UTF-8 content | Treated as unreadable via the shared helper's error path; no panic |
| Manifest is `settings.gradle(.kts)` or `libs.versions.toml` | [NEEDS CLARIFICATION: which manifest kinds should resolve a lock file, and does a version catalog consult the lock file of the project that consumes it?] |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | In-use version for a coordinate in a locked Gradle fixture matches the lock file | 100% on fixtures: single module, multi-module, legacy `dependency-locks/`, `empty=`, malformed line, multi-version |
| SC-002 | Existing `deps-gradle` tests | 0 regressions, 0 changed assertions |
| SC-003 | Fuzz target runs over seed corpus and a bounded run | no panics, no timeouts |
| SC-004 | Live check against a real locked Gradle project: hover and OSV diagnostic for a locked coordinate | version and diagnostic match the lock file |
| SC-005 | `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo +nightly fmt --all -- --check`, `cargo nextest run -p deps-gradle`, rustdoc gate per `.claude/rules/branching.md` | all green |

## 8. Agent Boundaries

### Always (without asking)
- Follow the existing `LockFileProvider` patterns in other ecosystem crates and reuse `deps-core::lockfile` helpers
- Run the full pre-commit suite per `.claude/rules/branching.md`
- Update `CHANGELOG.md` `[Unreleased]` (one line plus PR link), `book/src/ecosystems/` Gradle page, and the testing knowledge base (`coverage.md`, Gradle playbook)

### Ask First
- Any change to shared `deps-core::lockfile` trait or helper signatures
- Adding a dependency (none is expected; the format is line-based)
- Resolving the `[NEEDS CLARIFICATION]` items in section 9 in a way that changes ancestor-search semantics for other ecosystems

### Never
- Touch `crates/deps-zed` (submodule)
- Write or regenerate lock files in user projects
- Reimplement capped reads or ancestor search locally in `deps-gradle`
- Add a catch-all arm that sidesteps an exhaustive `EcosystemId` match

## 9. Open Questions

> [!question] Open items
> - [NEEDS CLARIFICATION: `gradle.lockfile` vs `buildscript-gradle.lockfile` precedence or merge, see section 6]
> - [NEEDS CLARIFICATION: ancestor-directory fallback for submodules without their own lock file, see section 6]
> - [NEEDS CLARIFICATION: classifier or four-part coordinate handling]
> - [NEEDS CLARIFICATION: manifest kinds eligible for lock resolution (`settings.gradle*`, `libs.versions.toml`)]
> - [NEEDS CLARIFICATION: how Gradle package keys are represented today (`NormalizedName` vs Maven `group:artifact` string) and whether version-catalog aliases need a mapping step before lookup; confirm against `crates/deps-gradle/src/parser/` during planning]
> - [NEEDS CLARIFICATION: custom lock file locations (`lockFile` property set in build logic) are undiscoverable without evaluating the build; confirm they stay unsupported]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[052-pnpm-lockfile-provider/spec]] — sibling lock file provider spec and structure precedent
- [[080-gradle-deps-dev-maven-system-routing/spec]] — Gradle coordinates routed through the Maven system
- Issue #709 — origin issue (closed; Gradle portion never shipped)
- `crates/deps-gradle/src/ecosystem.rs` — `lockfile_filenames()` returning `&[]`
- `crates/deps-core/src/lockfile.rs` — `LockFileProvider`, `locate_lockfile_for_manifest`, `read_lockfile_content`, `ResolvedPackages`
- `crates/deps-core/src/fs_probe.rs` — `read_to_string_capped`
- `fuzz/fuzz_targets/` — `*_lockfile.rs` fuzz target precedents

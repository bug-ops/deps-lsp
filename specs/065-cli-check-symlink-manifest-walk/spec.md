---
aliases:
  - deps-cli Symlink Manifest Walk
  - Symlink Bypass Fix
tags:
  - sdd
  - spec
  - deps-cli
  - security
created: 2026-09-16
status: draft
related:
  - "[[constitution]]"
---

# Feature: deps-cli Symlink Manifest Walk

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: fix/1112-symlink-manifest-bypass
> **Resolves**: #1112 (same fail-open class as #1109/#1108, closed by #1111)

## 1. Overview

### Problem Statement

`deps-cli check`'s walk (`crates/deps-cli/src/walk.rs`) routes a directory
entry through `EcosystemRegistry::for_uri` only when
`entry.file_type().is_some_and(|t| t.is_file())` is true. The underlying
`ignore::WalkBuilder` does not follow symlinks by default, so `file_type()`
reports the symlink's own type, not its target's — a manifest committed to a
repository as a symlink to a real file is silently never recognized as a
manifest candidate. No entry lands in `WalkOutcome::walk_errors` or
`WalkOutcome::ignored_manifests`; the scan reports `exit 0`.

This is the third instance of the same fail-open class this project already
hardened against in #1109 (`.gitignore`/`.ignore` suppression) and #1108
(relative-path silent drop), both closed by PR #1111 — the identical
CI-security-gate-bypass threat model: `git checkout && deps-cli check .`
against an untrusted fork PR. Git stores symlinks as first-class objects and
`actions/checkout` restores them by default, so this is directly reachable
the same way #1109's `.gitignore` vector was.

The explicit single-file invocation path (`deps-cli check evil/Cargo.toml`)
already follows the symlink correctly via `std::path::Path::is_file()`
(which does follow symlinks) — the asymmetry is specific to directory-walk
discovery (`ignore::DirEntry::file_type()`, which does not), not manifest
parsing. This was deliberately not fixed alongside #1109/#1108/#1111:
enabling symlink-following in the `ignore`-crate walk carries its own
security implications (symlink loops, escaping the walked root onto
unintended parts of the filesystem) that need their own considered design,
not a one-line flip of `WalkBuilder::follow_links(true)`.

### Goal

`check`'s default invocation (no flag) never silently drops a symlinked
manifest to `exit 0`: a symlink whose target is manifest-shaped is detected
and reported the same way an existing manifest excluded by
`PRUNED_DIRECTORIES` already is — via `WalkOutcome::ignored_manifests`,
which already drives a non-zero exit code (`EXIT_EXECUTION_ERROR`)
independent of `--fail-on`. A new opt-in `--follow-symlinks` flag lets a
caller who trusts the scanned tree have `check` resolve such a manifest and
include it in the scan directly, bounded so it can never loop forever or
escape the walked root onto arbitrary filesystem paths.

### Out of Scope

- Making symlink-following the new default for `check` — unlike #1109's
  `.gitignore` case (where the *existing* default was itself the attacker
  surface), here the safer behavior (not following symlinks) is already the
  `ignore` crate's default; this spec only adds visibility (warn) plus an
  opt-in resolution path, not a default-behavior flip.
- Symlinks encountered anywhere other than manifest discovery (e.g. a
  symlinked directory, a symlink appearing inside a lockfile's own resolved
  paths) — only file-entry manifest discovery in `walk.rs` is in scope.
- Changing the explicit single-file invocation path
  (`deps-cli check evil/Cargo.toml`) — it already follows symlinks
  correctly via `Path::is_file()` and is unaffected by this spec.
- A symlink whose target is unreadable, broken, or points outside the
  filesystem entirely — already surfaced today via `ignore`'s own
  `Err(error)` walk-entry variant into `WalkOutcome::walk_errors`; this
  spec only adds handling for the previously-unhandled "valid symlink,
  target looks like a manifest" case.
- `respect_gitignore`'s existing `.gitignore`/`.ignore`/pruned-directory
  behavior (#1109) — unrelated axis, unchanged by this spec.

## 2. User Stories

### US-001: A CI gate is not silently bypassed by a symlinked manifest

AS A maintainer running `deps-cli check --fail-on vulnerable` as a CI gate
over an untrusted fork PR
I WANT a manifest reachable only through a symlink to be visible in the
report (as a warning with a non-zero exit code) instead of silently
disappearing
SO THAT an attacker cannot defeat the vulnerability gate by replacing a
manifest with a symlink to a byte-identical file

**Acceptance criteria:**
```
GIVEN a directory `evil/` containing `Cargo.toml` as a symlink to a real,
  vulnerable `Cargo.toml` elsewhere in the walked tree
WHEN `deps-cli check --fail-on vulnerable evil` runs with no extra flags
THEN the run exits with a non-zero exit code and stderr names
  `evil/Cargo.toml` as a manifest-shaped path excluded from the scan
```

### US-002: An opt-in flag resolves symlinked manifests in a trusted tree

AS A user scanning a trusted local monorepo that legitimately uses symlinked
manifests (e.g. a shared `Cargo.toml` symlinked into multiple package
directories)
I WANT an opt-in flag that makes `check` follow such symlinks and include
their target's findings in the report
SO THAT I don't have to manually enumerate every symlinked manifest as an
explicit path argument

**Acceptance criteria:**
```
GIVEN the same `evil/Cargo.toml` -> vulnerable-real-file symlink as US-001
WHEN `deps-cli check --follow-symlinks --fail-on vulnerable evil` runs
THEN the vulnerable dependency in the resolved target is reported as a
  finding, and the run's exit code reflects `--fail-on` the same way it
  would for a byte-identical non-symlinked manifest
```

### US-003: Symlink-following cannot loop or escape the walked root

AS A maintainer running `check --follow-symlinks` over an untrusted tree
I WANT symlink resolution bounded to the walked root, with loops detected
SO THAT a malicious symlink (a self-referential loop, or a symlink pointing
outside the walked root such as `/etc/passwd`-shaped content) cannot hang
the scan or pull in files the caller never asked to scan

**Acceptance criteria:**
```
GIVEN a symlink loop (`a -> b`, `b -> a`) inside a walked directory
WHEN `deps-cli check --follow-symlinks` runs over that directory
THEN the walk terminates (does not hang or crash), the loop path is
  reported via `WalkOutcome::walk_errors`, and the run's exit code is
  non-zero

GIVEN a symlink inside the walked root whose target resolves (after
  canonicalization) to a path outside the walked root
WHEN `deps-cli check --follow-symlinks` runs over that root
THEN the target is not read or routed to any ecosystem, and the path is
  reported via `WalkOutcome::ignored_manifests` the same as an unresolved
  symlink under the default (non-`--follow-symlinks`) mode
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a directory-walk entry's `file_type()` is a symlink (not a regular file) AND its target, resolved via `std::fs::metadata` (which follows symlinks), is a regular file whose path is manifest-shaped (`EcosystemRegistry::for_uri` on the target path returns `Some`) THE SYSTEM SHALL record the entry's display path onto `WalkOutcome::ignored_manifests`, regardless of `--follow-symlinks` | must |
| FR-002 | WHEN `--follow-symlinks` is not passed (the default) THE SYSTEM SHALL NOT read or route the symlink target's content — FR-001's detection uses only `std::fs::metadata`'s file-type/existence check, never a full read | must |
| FR-003 | WHEN `--follow-symlinks` is passed THE SYSTEM SHALL configure the directory walk to follow symlinks (`ignore::WalkBuilder::follow_links(true)`) and route a resolved symlink target that is a regular file through `EcosystemRegistry::for_uri` exactly as a non-symlinked file already is | must |
| FR-004 | WHEN `--follow-symlinks` is passed AND a symlink's canonicalized target path does not start with the walked root's own canonicalized absolute path THE SYSTEM SHALL NOT route that target to any ecosystem, and SHALL record its display path onto `WalkOutcome::ignored_manifests` instead | must |
| FR-005 | WHEN `--follow-symlinks` is passed AND the walk encounters a symlink loop THE SYSTEM SHALL terminate the walk without hanging or crashing and SHALL record the loop onto `WalkOutcome::walk_errors` | must |
| FR-006 | WHEN `--follow-symlinks` is passed THE SYSTEM SHALL continue to enforce `PRUNED_DIRECTORIES` pruning and `MAX_WALKED_FILES` (`WalkOutcome::truncated`) exactly as it already does for the non-symlink-following walk | must |
| FR-007 | WHEN a manifest is discovered by following a symlink under `--follow-symlinks` THE SYSTEM SHALL use the resolved target's real path for reading manifest content, while `display_path` continues to reflect the symlink's own path as encountered during the walk (matching this project's existing `display_path`-vs-`path` convention) | must |
| FR-008 | WHEN the explicit single-file invocation path (`root.is_file()` branch in `walk_with_limit`) is used THE SYSTEM SHALL be unaffected by this spec — it already follows symlinks via `Path::is_file()` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security | Symlink resolution under `--follow-symlinks` never escapes the walked root's canonicalized absolute path (FR-004) and never loops indefinitely (FR-005) — see US-003 |
| NFR-002 | Performance | FR-001's detection (`std::fs::metadata` on a symlink entry that already failed `is_file()`) adds at most one extra stat syscall per symlink entry encountered; it must not measurably regress `walk`'s existing `MAX_WALKED_FILES`-bounded cost for a tree with few or no symlinks |
| NFR-003 | Compatibility | Default (no-flag) `check` behavior for every existing non-symlink fixture/snapshot stays unchanged — this is an additive detection, not a change to already-passing paths |
| NFR-004 | Test coverage | Each of US-001/US-002/US-003's acceptance criteria has a corresponding `walk.rs` unit test, following the existing `#[cfg(test)] mod tests` pattern and `tempfile::TempDir` fixture convention already used throughout that file (including `#[cfg(unix)]`/platform gating for `std::os::unix::fs::symlink` construction, since the test fixtures create real symlinks) |

## 5. Data Model

No new persisted entities. `WalkOutcome`'s existing fields (`ignored_manifests`,
`walk_errors`) are reused (FR-001, FR-004, FR-005) — this spec adds no new
field to that struct. `crate::cli::CheckArgs` gains one new field:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CheckArgs::follow_symlinks` | New opt-in CLI flag (`#[arg(long)]`), mirroring `respect_gitignore`'s existing shape and doc-comment convention | `bool`, default `false` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| Symlink target does not exist (broken symlink) | `std::fs::metadata` (FR-001) fails; not manifest-shaped by definition, no `ignored_manifests` entry — matches today's silent (and correct) skip of a broken symlink that clearly isn't a manifest |
| Symlink target exists but is a directory, not a file | Not manifest-shaped under FR-001's regular-file check; no `ignored_manifests` entry, no traversal into it even under `--follow-symlinks` beyond what `ignore`'s own `follow_links` already does for a symlinked directory |
| Symlink target is manifest-shaped but explicitly given as a CLI path argument (not discovered via directory walk) | Already handled by the pre-existing `root.is_file()` branch (FR-008) — `Path::is_file()` already follows the symlink, so this path is unaffected by FR-001-FR-006 |
| `--follow-symlinks` passed together with `--respect-gitignore` | Independent, orthogonal flags — both apply simultaneously with no special-cased interaction; a symlinked manifest excluded by `.gitignore` under `--respect-gitignore` is still reported via the existing `.gitignore`-suppression path once resolved, exactly as a non-symlinked manifest would be |
| Symlink resolves inside the walked root but through a chain that transiently leaves and re-enters it (e.g. `root/a -> ../root/b`) | Only the final canonicalized target path is checked against the canonicalized root (FR-004) — an intermediate chain hop is not separately validated, matching `std::fs::canonicalize`'s own semantics |
| `PRUNED_DIRECTORIES`-excluded directory contains a symlink to a manifest-shaped file directly at its own root | Same one-level-deep check `warn_on_pruned_directory_manifest` already performs for regular files (existing #1109 reviewer follow-up) is extended to also match a symlink whose target is manifest-shaped, via the same FR-001 detection helper — not a second, separate implementation |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `deps-cli check --fail-on vulnerable evil` (issue #1112's repro, no flag) exit code | Non-zero (was `0`) |
| SC-002 | `deps-cli check --follow-symlinks --fail-on vulnerable evil` exit code | Matches the byte-identical non-symlinked positive control (`1`, `EXIT_POLICY_VIOLATION`) |
| SC-003 | New `walk.rs` unit tests covering FR-001 through FR-008 | All added and passing |
| SC-004 | Existing `walk.rs`/`deps-cli` test suite and insta/fixture snapshots | 0 changed |
| SC-005 | `--follow-symlinks` symlink-loop fixture (US-003) | Walk terminates in bounded time, no crash/hang |

## 8. Agent Boundaries

### Always (without asking)
- Run the full check suite (`cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`) per `.claude/rules/branching.md` before considering any resulting task done
- Reuse `WalkOutcome::ignored_manifests`/`walk_errors` and the existing `EcosystemRegistry::for_uri` routing helper (`route_file`) rather than introducing a parallel manifest-shape check (constitution principle 1)
- Keep every existing `walk.rs`/`deps-cli` test and fixture passing unchanged (NFR-003)

### Ask First
- Making symlink-following the default for `check` instead of opt-in (explicitly out of scope per this spec's Out of Scope section — would need its own follow-up spec if reconsidered)
- Any change to `respect_gitignore`'s existing behavior or flag semantics

### Never
- Read a symlink target's file content before FR-004's canonicalize-and-prefix-check passes
- Follow a symlink whose resolved target falls outside the walked root's canonicalized path, under any flag combination

## 9. Open Questions

None — the remaining design choices (warn-only default plus opt-in bounded
following, canonicalize-and-prefix-check for escape prevention, reuse of
`ignored_manifests`/`walk_errors`) were resolved during `specify` based on
the existing `respect_gitignore` flag precedent and this project's "one fix,
one place" constitution principle.

## 10. See Also

- [[constitution]] — project principles, especially principle 1 (one fix, one place)
- [[MOC-specs]] — all specifications
- Issue #1112 (this spec's source), #1109/#1108 (same fail-open class, closed by #1111)
- `crates/deps-cli/src/walk.rs` (`walk_directory`, `route_file`, `warn_on_pruned_directory_manifest`, `WalkOutcome`)
- `crates/deps-cli/src/cli.rs` (`CheckArgs::respect_gitignore` — the flag pattern this spec's `follow_symlinks` mirrors)
- `crates/deps-cli/src/main.rs` (`run_check` — where `WalkOutcome::ignored_manifests`/`walk_errors` already drive `had_execution_error`)
- `crates/deps-cli/src/exit.rs` (`exit_code` — `had_execution_error` -> `EXIT_EXECUTION_ERROR`, independent of `--fail-on`)

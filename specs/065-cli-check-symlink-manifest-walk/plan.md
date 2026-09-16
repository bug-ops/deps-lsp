---
aliases:
  - deps-cli Symlink Manifest Walk Plan
tags:
  - sdd
  - plan
  - deps-cli
  - security
created: 2026-09-16
status: draft
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: deps-cli Symlink Manifest Walk

> [!info] References
> **Spec**: [[spec]]

## 1. Architecture

### Approach

Two independent, additive changes inside `crates/deps-cli/src/walk.rs`, both
gated by a new `follow_symlinks: bool` parameter threaded through
`walk`/`walk_with_limit`/`walk_directory` (mirroring how `respect_gitignore`
is already threaded today):

1. **Detection (always on, FR-001/FR-002)**: in `walk_directory`'s entry
   match loop, a directory entry whose `file_type()` is *not* a regular file
   (i.e. `entry.file_type().is_some_and(|t| t.is_file())` is `false`) is
   currently silently dropped via the `Ok(_) => {}` arm. Add a check: if
   `entry.path_is_symlink()` is `true`, call `std::fs::metadata(entry.path())`
   (which follows the symlink) and, if that resolves to a regular file whose
   path is manifest-shaped per `registry.for_uri`, push the entry's display
   path onto `WalkOutcome::ignored_manifests`. This never reads file
   *content* — only a `metadata()` stat call — so it costs nothing extra for
   the overwhelming majority of non-symlink entries (the `path_is_symlink()`
   check short-circuits first) and is independent of `follow_symlinks`,
   since a warning is correct in both modes (it's superseded by an actual
   `manifests` entry when `follow_symlinks` successfully resolves and routes
   the same file — see decision below).
2. **Resolution (opt-in via `--follow-symlinks`, FR-003/FR-004/FR-006/FR-007)**:
   `walk_directory`'s `WalkBuilder` gets `.follow_links(follow_symlinks)`.
   With this on, `ignore`'s own walker (confirmed by reading
   `ignore` 0.4.x's `walk.rs`) already performs symlink-loop detection
   internally (`check_symlink_loop`, comparing a `same_file::Handle` against
   every ancestor `Ignore` in the walk's parent chain) and yields a
   `Err(ignore::Error::Loop { .. })` entry for a detected loop — which the
   existing `Err(error) => ctx.outcome.walk_errors.push(error.to_string())`
   arm already handles with zero new code (FR-005 is satisfied by wiring
   `follow_links(true)` alone). What `ignore` does *not* do is bound a
   resolved symlink target to the walked root, so FR-004's escape check is
   added explicitly. **Revised during implementation** (impl-critic finding
   C1): checking only entries where the *leaf* `path_is_symlink()` is true
   is insufficient — `ignore`/`walkdir` reports `path_is_symlink() == false`
   for an entry reached by following a symlinked *directory*, so a
   symlinked directory anywhere in the walked path let a resolved target
   escape the walked root undetected. The actual, shipped check instead
   canonicalizes *every* routed file entry's path when `follow_symlinks` is
   `true` (not gated on `path_is_symlink()`) and compares it against the
   walk's own canonicalized absolute root (`absolute_root`, still computed
   once per root, not per entry). The same generalized check is also
   applied to each hidden-ecosystem sub-root (e.g. `.github`) before it is
   walked, in *every* mode — `ignore`/`walkdir` always follows a walk's own
   root symlink regardless of `follow_links`, so an unguarded symlinked
   `.github` escaped containment even without `--follow-symlinks` (impl-critic
   finding S1, same root cause as C1). If the canonicalized target does not
   start with the canonicalized root, skip routing and push onto
   `ignored_manifests` instead — but only when the target is itself
   manifest-shaped (impl-critic finding S4: an out-of-root symlink to a
   non-manifest file, e.g. `notes.txt -> /etc/hosts`, must not produce a
   false "looks like a manifest" warning). This supersedes NFR-002's
   original "one extra stat only for symlink entries" framing: the shipped
   design costs one canonicalize per *file* entry under `--follow-symlinks`
   (not just symlink entries), an accepted, documented trade-off for
   closing C1/S1 with one general mechanism instead of two narrower,
   harder-to-verify ones (constitution principle 1).

Detection and resolution share one small helper
(`symlink_is_manifest_shaped`, see §3) so the "does this path look like a
manifest" check is written once, not duplicated between the two code paths
— per constitution principle 1.

### Component Diagram

```mermaid
graph TD
    A[walk_directory entry loop] --> B{entry.file_type is_file?}
    B -- yes --> C[route_file: existing behavior, unchanged]
    B -- no --> D{entry.path_is_symlink?}
    D -- no --> E[Ok(_) => {} : ignored, unchanged]
    D -- yes --> F[std::fs::metadata target]
    F -- not a manifest-shaped regular file --> E
    F -- manifest-shaped regular file --> G{follow_symlinks enabled?}
    G -- no --> H[push to ignored_manifests: FR-001]
    G -- yes --> I[canonicalize target vs canonicalized root: FR-004]
    I -- outside root --> H
    I -- inside root --> C
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| Loop detection (FR-005) | Rely on `ignore`'s built-in `check_symlink_loop`, surfaced as `Err` into the existing `walk_errors` arm | Confirmed present in `ignore` 0.4.x's `walk.rs` (`check_symlink_loop`, `Error::Loop`) — already tested by `ignore`'s own `symlink_loop` unit test. Duplicating loop detection in `deps-cli` would violate constitution principle 1 and risks disagreeing with `ignore`'s own semantics | A custom canonicalized-realpath visited-set per walk — rejected: redundant with `ignore`'s existing guarantee, and this project's own walk logic doesn't control the per-directory recursion order the way `ignore`'s internal `Worker` does, making an equivalent guard error-prone to reimplement correctly |
| Escape prevention (FR-004) | `std::fs::canonicalize` the entry path and prefix-compare against the walk root's own canonicalized absolute path, only for entries where `path_is_symlink()` is `true` | Matches spec's FR-004 wording exactly; cheap (one extra `canonicalize` call, only for the symlink subset of entries, not every entry) | Checking every entry regardless of `path_is_symlink()` — rejected: unnecessary syscall overhead for the common non-symlink case, since a non-symlinked entry's canonical path is trivially under the root already |
| Detection helper reuse | One `symlink_is_manifest_shaped(path, registry) -> Option<PathBuf>`-shaped helper (resolves via `metadata`, checks `registry.for_uri`) called from both the detection and `warn_on_pruned_directory_manifest`'s existing one-level-deep pruned-directory check (spec §6 edge case) | Constitution principle 1 — the "is this a manifest-shaped file, possibly behind a symlink" check must exist in exactly one place | Leaving `warn_on_pruned_directory_manifest` as regular-file-only (not extended for symlinks) — rejected: spec §6 explicitly requires the pruned-directory case to reuse the same detection |
| Flag plumbing | New `follow_symlinks: bool` parameter added to `walk`, `walk_with_limit`, `walk_directory` — same shape as the existing `respect_gitignore: bool` parameter | Consistent with the file's existing convention; avoids introducing a new options struct for a single new boolean | A `WalkOptions` struct bundling both booleans — rejected as unnecessary scope expansion; two booleans do not yet justify a struct, and `walk`'s public signature is already exercised by existing tests that would all need updating for no behavioral gain |

## 2. Project Structure

No new files. All changes are inside existing files:

```
crates/deps-cli/src/
├── cli.rs      (+1 field: CheckArgs::follow_symlinks)
├── main.rs     (thread CheckArgs::follow_symlinks into walk::walk's new parameter)
└── walk.rs     (walk/walk_with_limit/walk_directory gain follow_symlinks param;
                 new symlink_is_manifest_shaped helper; WalkBuilder gets
                 .follow_links(follow_symlinks); FR-004 canonicalize+prefix-check;
                 warn_on_pruned_directory_manifest reuses the new helper;
                 new unit tests)
```

## 3. Data Model

No new persisted entities (spec §5 already notes this — `WalkOutcome` is
unchanged). One new private helper function in `walk.rs`:

```rust
/// Resolves `path` (which failed the regular `is_file()` check) as a
/// possible symlink to a manifest-shaped file, without reading its
/// content. Returns `None` for anything that isn't a symlink resolving to
/// a manifest-shaped regular file — a broken symlink, a symlink to a
/// directory, or a target no ecosystem's `for_uri` claims.
fn symlink_is_manifest_shaped(
    path: &Path,
    registry: &EcosystemRegistry,
) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let Ok(uri) = url::Url::from_file_path(path) else {
        return false;
    };
    registry.for_uri(&uri).is_some()
}
```

`CheckArgs` (in `cli.rs`) gains:

```rust
/// Follow symlinks during the directory walk and resolve a symlinked
/// manifest's target for scanning (issue #1112). A symlink whose
/// resolved, canonicalized target falls outside the walked root is never
/// followed regardless of this flag — see `walk::walk`'s doc. When this
/// flag is not passed (the default), a symlink to a manifest-shaped file
/// is still detected and reported via a warning (non-zero exit code), it
/// is simply not resolved and scanned.
#[arg(long)]
pub follow_symlinks: bool,
```

`walk`'s public signature changes from:

```rust
pub fn walk(roots: &[PathBuf], registry: &EcosystemRegistry, respect_gitignore: bool) -> WalkOutcome
```

to:

```rust
pub fn walk(
    roots: &[PathBuf],
    registry: &EcosystemRegistry,
    respect_gitignore: bool,
    follow_symlinks: bool,
) -> WalkOutcome
```

(and `walk_with_limit`/`walk_directory` symmetrically) — a breaking change
to an internal, non-published-crate function; acceptable pre-1.0 per
constitution principle 7, and `deps-cli` is the only caller (`main.rs`).

## 4. API Design

Not applicable — no HTTP/RPC surface. The only user-facing surface change is
the new `--follow-symlinks` CLI flag on `deps-cli check`, documented above.

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| `ignore` crate (`WalkBuilder::follow_links`) | internal call | Rust API | Existing dependency, already in use; only a new builder call plus reliance on its already-existing loop-detection behavior |
| `EcosystemRegistry::for_uri` | internal call | Rust API | Already used by `route_file`/`warn_on_pruned_directory_manifest`; reused unchanged by the new `symlink_is_manifest_shaped` helper |

## 6. Security

- **Threat model**: same as #1109/#1108 — `git checkout && deps-cli check .`
  over an untrusted fork PR. This spec closes the symlink-shaped variant of
  that fail-open class.
- **Escape prevention (FR-004)**: a symlink is only ever resolved and
  scanned under `--follow-symlinks` when its canonicalized target starts
  with the walk root's own canonicalized absolute path. This is checked
  before any content read, so a symlink pointing at `/etc/passwd`-shaped
  content outside the walked root is never opened.
- **Loop safety (FR-005)**: delegated to `ignore`'s own, already-tested
  `check_symlink_loop`; no new loop-prone code is added by this change.
- **Default behavior unchanged**: `--follow-symlinks` is opt-in
  (`default = false`), so a caller who does not pass it gets exactly
  today's `ignore`-crate default (no symlink-following) plus the new,
  purely additive detection warning (FR-001/FR-002) — no existing `check`
  invocation without the new flag can regress from working to broken.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|---------------|-------------------|
| Unit | `cargo nextest`, existing `#[cfg(test)] mod tests` in `walk.rs`, `tempfile::TempDir` fixtures | US-001/US-002/US-003 acceptance criteria (FR-001 through FR-008), following the file's existing fixture style | Every new FR has at least one dedicated test |

Symlink-creation fixtures use `std::os::unix::fs::symlink`, gated behind
`#[cfg(unix)]`. **Decision on Windows**: `.github/workflows/ci.yml`'s `test`
job matrix does include `windows-latest` (confirmed by reading the
workflow). Creating a symlink on Windows requires either Developer Mode or
elevated privileges, which CI runners do not reliably have — the existing
project has no prior symlink-related test precedent to follow either way.
This plan scopes new symlink-creation tests to `#[cfg(unix)]` only, and
non-symlink-related behavior (e.g. `--follow-symlinks` being a no-op on a
tree with no symlinks) needs no platform-specific test since it exercises
no new code path on Windows. This is an explicit, accepted scope
boundary — not silently skipped: Windows CI still runs the full
`walk.rs` suite, just without the new `#[cfg(unix)]`-gated symlink cases,
identical in kind to how `test_walk_never_descends_into_dot_git` and other
existing tests already run cross-platform without special-casing.

Planned new tests (illustrative names, `#[cfg(unix)]` unless noted):

- `test_walk_default_detects_symlinked_manifest_without_following` (FR-001/FR-002, US-001)
- `test_walk_follow_symlinks_resolves_and_routes_manifest` (FR-003, US-002)
- `test_walk_follow_symlinks_does_not_read_target_when_flag_disabled` — asserts `ignored_manifests` contains the path and `manifests` does not, when `follow_symlinks: false` (FR-002)
- `test_walk_follow_symlinks_rejects_target_outside_root` (FR-004, US-003)
- `test_walk_follow_symlinks_reports_symlink_loop_via_walk_errors` (FR-005, US-003)
- `test_walk_follow_symlinks_still_prunes_node_modules` (FR-006)
- `test_walk_follow_symlinks_still_enforces_max_walked_files` (FR-006) — reuses `walk_with_limit`'s existing small-limit pattern
- `test_walk_follow_symlinks_display_path_is_symlink_path_not_target` (FR-007)
- `test_walk_broken_symlink_is_not_reported_as_manifest` (spec §6 edge case)
- `test_walk_symlink_to_directory_is_not_reported_as_manifest` (spec §6 edge case)
- `test_walk_pruned_directory_symlinked_manifest_is_still_warned` (spec §6 edge case, extends `warn_on_pruned_directory_manifest` coverage)

No changes to any existing test are expected — all additions, no
modifications to current assertions (NFR-003/SC-004).

## 8. Performance Considerations

- FR-001/FR-002's detection adds one `std::fs::metadata` call only for
  entries where `path_is_symlink()` is already `true` — negligible for a
  typical tree with few or no symlinks (NFR-002).
- FR-004's canonicalize check similarly only runs for symlink entries when
  `--follow-symlinks` is passed; the walk root's own canonicalization
  happens once per root, not once per entry.
- `MAX_WALKED_FILES`/`PRUNED_DIRECTORIES` continue to bound total walk cost
  identically regardless of `follow_symlinks` (FR-006).

## 9. Rollout Plan

Single PR, no feature flag beyond the CLI flag itself (which is inherently
opt-in). No migration or phased rollout needed — pre-1.0, additive change.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| 1. One fix, one place | Compliant | `symlink_is_manifest_shaped` is written once and reused by both the walk-loop detection and `warn_on_pruned_directory_manifest` |
| 5. Verify live, not just in CI | Compliant (planned) | `/rust-team`'s live-testing step (or a manual `deps-cli check --follow-symlinks` run against the issue's own repro) must reproduce SC-001/SC-002 before considering this done |
| 7. Pre-1.0 clean breaks | Compliant | `walk`/`walk_with_limit`/`walk_directory`'s signature changes directly, no deprecation shim; `deps-cli` is the only caller |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|--------------|------------|
| `ignore`'s loop detection behaves differently across crate versions/platforms than assumed from reading `ignore` 0.4.32's source (workspace pins 0.4.33) | Medium (FR-005 could silently rely on unconfirmed behavior) | Low | `test_walk_follow_symlinks_reports_symlink_loop_via_walk_errors` empirically verifies the behavior against the actual pinned version during implementation, not just via source reading |
| Extra `metadata`/`canonicalize` syscalls regress walk performance on a pathological tree with many symlinks | Low | Low | Both checks are gated behind `path_is_symlink()` first, so cost scales with symlink count, not total entries; `MAX_WALKED_FILES` remains the backstop either way |
| A future ecosystem or caller assumes `walk`'s 3-argument signature | Low | Low | Only caller is `deps-cli`'s own `main.rs`, updated in the same PR |

## See Also

- [[spec]] — feature specification
- [[tasks]] — implementation tasks (after this phase)
- [[MOC-specs]] — all specifications
- `crates/deps-cli/src/walk.rs` — file this plan modifies
- `ignore` crate source (`walk.rs`, `check_symlink_loop`, `Error::Loop`) — confirmed loop-detection behavior this plan relies on for FR-005

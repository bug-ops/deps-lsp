---
aliases:
  - Feature Matrix Test Sharding
tags:
  - sdd
  - spec
  - enhancement
  - tooling
  - ci
created: 2026-09-14
status: draft
related:
  - "[[constitution]]"
---

# Feature: Shard `feature-matrix-test` CI job across parallel runners

> [!info] Metadata
> **Author**: rust-cicd-devops (CI slowness investigation)
> **Branch**: fix/1030-shard-feature-matrix-test
> **Issue**: #1030

## 1. Overview

### Problem Statement

PR #1018 split `feature-matrix-test` out of the combined `feature-matrix`
job so nextest execution across deps-lsp's feature matrix
(`cargo hack nextest run -p deps-lsp --each-feature --keep-going --profile
ci --no-fail-fast`) would no longer block clippy. Now that it runs on its
own, it has become the slowest job in the pipeline: a live run
(`34850655299`, 2026-09-14) shows `feature-matrix-test` taking **10m47s**,
versus 8m47s for the longest `cross-check` leg and well under that for
every other job — it now sits on the pipeline's critical path.

`--each-feature` runs deps-lsp's `[features]` table serially, one `cargo
nextest run` invocation per entry, on a single `ubuntu-latest` runner.
`deps-lsp`'s `[features]` table (`crates/deps-lsp/Cargo.toml`) declares 14
ecosystem features (`cargo`, `npm`, `pypi`, `go`, `bundler`, `dart`,
`maven`, `gradle`, `swift`, `composer`, `nuget`, `deno`, `github-actions`,
`gitlab-ci`) plus a `default` feature equal to all 14 combined. Verified via
`cargo hack check -p deps-lsp --each-feature --keep-going`: this produces
**17 invocations** — 14 individual ecosystem features, `default`,
`--all-features`, and `--no-default-features`.

Per-invocation timing pulled from the live run's log (`gh run view
34850655299 --log`):

| Invocation | Duration |
|---|---|
| `--all-features` | ~50.8s |
| `--no-default-features` | ~38.5s |
| 14 individual ecosystem features | ~23.7s–36.3s each (avg ~26.5s) |
| `--features default` | ~18.1s |

**Verified redundancy**: `--features default` activates the exact same 14
ecosystem features as `--all-features` (the `default` feature *is* all 14,
per `[features] default = ["cargo", "npm", ...]`). Confirmed empirically:

```
$ cargo clean -p deps-lsp
$ cargo check -p deps-lsp --all-features
   Compiling deps-lsp v1.0.0 ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.50s
$ cargo check -p deps-lsp --no-default-features --features default
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
```

The second command recompiles nothing (no `Compiling` line — a pure
cache-hit fingerprint match). In the live run, the `default` slice's ~18.1s
cost is entirely a redundant re-run of the same 571 tests already exercised
by `--all-features`, with zero new coverage.

### Goal

Reduce `feature-matrix-test`'s wall-clock time from ~10m47s to roughly
3-4 minutes by:
1. Dropping the redundant `--features default` slice.
2. Distributing the remaining 16 invocations across a `strategy: matrix` so
   they run in parallel instead of serially on one runner.

Every ecosystem feature must continue to get its own isolated `cargo
nextest run` — the guarantee this job exists for (issue #1005: a test that
compiles fine but panics at runtime once its feature is disabled must still
be caught under every reduced feature set, not just `--all-features`).

### Out of Scope

- The `feature-matrix` job (clippy-only, `--each-feature --no-dev-deps` +
  `-p deps-lsp --each-feature --all-targets`) — not part of this ask, and
  its `--no-dev-deps` sweep is already comparatively cheap; sharding it is
  a separate, independently justified change if ever needed.
- Reducing `--each-feature` to a smaller/sampled subset of ecosystem
  features (e.g. skipping some ecosystems) — every ecosystem feature still
  gets tested individually; only the one *provably duplicate* slice
  (`default` == `--all-features`) is removed.
- Changing `feature-matrix-test`'s job id, or `ci-success`'s `needs:`
  list / `check_job` calls — GitHub Actions matrix legs share one job id,
  so `needs.feature-matrix-test.result` continues to reflect all legs
  without any change to `ci-success`.
- Any change to test content, `cargo-nextest` profiles, or the `ci` nextest
  profile itself.

## 2. User Stories

### US-001: Faster CI feedback without losing per-feature isolation
AS A contributor opening a PR that touches `deps-lsp` or its ecosystem
crates
I WANT `feature-matrix-test` to finish in a few minutes instead of ~11
SO THAT the overall CI pipeline's critical path shortens without weakening
the per-feature runtime-panic guard `feature-matrix-test` exists for
(issue #1005).

**Acceptance criteria:**
```
GIVEN a PR that changes deps-lsp or an ecosystem crate
WHEN the `feature-matrix-test` job runs
THEN each of deps-lsp's 14 ecosystem features, plus --all-features and
     --no-default-features, is still exercised by its own
     `cargo nextest run` invocation, in parallel across matrix legs, and
     the slowest leg's wall-clock time is materially lower than the
     previous serial job's ~10m47s
```

### US-002: No coverage loss from removing the redundant slice
AS A maintainer relying on `feature-matrix-test` as a merge gate
I WANT the removal of the `--features default` slice to be provably
zero-risk
SO THAT the speedup doesn't quietly drop real coverage.

**Acceptance criteria:**
```
GIVEN --features default activates the identical feature set as
      --all-features (verified: `[features] default = [...all 14...]`,
      and a --all-features build followed by a --no-default-features
      --features default build recompiles nothing)
WHEN the `default` invocation is dropped via `cargo hack ... --exclude-features default`
THEN the set of (feature-combination, test) pairs exercised by the job is
     unchanged except for the one exact duplicate removed
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE `feature-matrix-test` job SHALL exclude the `default` feature from its `--each-feature` iteration (`--exclude-features default`, or by only ever invoking `--include-features` lists that omit `default`), since it duplicates `--all-features` byte-for-byte | must |
| FR-002 | THE `feature-matrix-test` job SHALL run as a `strategy: matrix` with `fail-fast: false`, keeping a single job id (`feature-matrix-test`) so `ci-success`'s existing `needs`/`check_job` wiring requires no change | must |
| FR-003 | ONE matrix leg SHALL run `--all-features` and `--no-default-features` as two explicit `cargo nextest run -p deps-lsp` invocations (no `cargo-hack` needed for exactly two fixed cases) | must |
| FR-004 | THE remaining 14 ecosystem features SHALL be split across the other matrix legs via `cargo hack nextest run -p deps-lsp --each-feature --include-features <comma-separated subset> --keep-going --profile ci --no-fail-fast`, so each ecosystem feature still gets its own isolated nextest invocation | must |
| FR-005 | EACH matrix leg SHALL use a distinct `cache-extra-identifier` (incorporating the leg's matrix name) so parallel legs' `moonrepo/setup-rust` caches do not clobber each other | must |
| FR-006 | THE job's `timeout-minutes` SHALL be reduced from 25 to a value sized for a single shard's expected runtime with reasonable safety margin, not the old full-serial budget | must |
| FR-007 | `ci-success`'s `needs` list and `check_job "${{ needs.feature-matrix-test.result }}" ...` line SHALL remain unchanged (per FR-002, the job id is not renamed or split into multiple job ids) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Slowest matrix leg's wall-clock time should be materially below the previous serial job's ~10m47s; based on measured per-invocation timing, a 4-leg split (baseline pair + 3 alphabetical ecosystem-feature groups) is estimated at roughly 3-3.5 minutes for the slowest leg, not independently verified by an actual GitHub Actions run at spec-writing time |
| NFR-002 | Maintainability | Ecosystem-feature groups must be plain, readable comma-separated lists in the matrix definition (not computed/generated) so a future 15th ecosystem (per the project's "Adding a new ecosystem" workflow) can be added to the shortest group with a one-line diff |
| NFR-003 | Coverage parity | No ecosystem feature may end up untested by any leg — the union of all legs' `--include-features` lists plus the baseline leg's `--all-features`/`--no-default-features` must exactly reproduce the pre-change invocation set minus only the `default` duplicate |
| NFR-004 | CI minutes | `deps-lsp` is a public repository (GitHub Actions minutes are unmetered for public repos), so the modest runner-minutes increase from parallel legs each paying their own fixed per-job overhead (checkout, toolchain setup, tool install; ~50s per leg observed) is an acceptable trade for wall-clock reduction |

## 5. Data Model

No runtime data entities — this is a CI workflow configuration change. The
"entities" are the `.github/workflows/ci.yml` job definition and its
matrix:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `feature-matrix-test` job | GitHub Actions job, now matrix-parallelized | `strategy.matrix.include: [{name, run}]`, `timeout-minutes`, per-leg `cache-extra-identifier` |
| Matrix leg | One parallel runner executing a subset of the feature matrix | `name` (shard label), `run` (shell command: either the two baseline nextest invocations, or one `cargo hack nextest run --include-features ...`) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| A 15th ecosystem feature is added to `deps-lsp/Cargo.toml` in the future | Must be added to exactly one matrix leg's `--include-features` list (the shortest group, per NFR-002); omitting it from every leg would silently drop coverage — not automatically enforced, but the plain comma-separated-list format makes the omission easy to spot in review |
| One matrix leg fails (e.g. a real `#1005`-class panic under a specific reduced feature set) | `fail-fast: false` (FR-002) ensures the other legs still complete and report their own results, matching `--keep-going`'s existing "report every failing slice" intent from before this change |
| `--include-features` is combined with `--each-feature` for a leg | Verified empirically (`cargo hack check -p deps-lsp --each-feature --include-features bundler,cargo,composer --keep-going`) to iterate each listed feature individually (one invocation per feature), not all-at-once — matching the pre-change per-feature isolation exactly |
| GitHub Actions cache is cold for a given leg's `cache-extra-identifier` (e.g. first run after this PR merges) | That leg's compile time is higher on its first run only; subsequent runs restore its own cache same as any other job. Not expected to threaten `timeout-minutes` (FR-006 sizes in a safety margin) but flagged as the one part of this change not verifiable without a real Actions run |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `feature-matrix-test` invocation count (post `default` removal) | 16 (down from 17): `--all-features`, `--no-default-features`, 14 ecosystem features |
| SC-002 | Coverage parity | Union of all matrix legs' invocations == pre-change invocation set minus exactly one (`default`) |
| SC-003 | `feature-matrix-test` wall-clock time on the PR's own CI run | Materially below ~10m47s (target: under 5 minutes); to be confirmed by watching the PR's first real run, since GitHub Actions cannot be executed locally |
| SC-004 | `ci-success` wiring | No change to `needs:` list or `check_job` calls required |

## 8. Agent Boundaries

### Always (without asking)
- Remove the redundant `default` slice via `--exclude-features default` (or
  equivalent `--include-features` restriction that omits it)
- Restructure `feature-matrix-test` into a `strategy: matrix` with
  `fail-fast: false`, keeping the job id unchanged
- Give each leg its own `cache-extra-identifier`
- Reduce `timeout-minutes` to a per-leg-appropriate value
- Run the project's full pre-commit check suite (this touches CI config,
  treated as source per `.claude/rules/branching.md`) before opening the PR
- Update `CHANGELOG.md` under `[Unreleased]`
- Call out in the PR description that the new job's real-world timing is
  unverified by an actual GitHub Actions run and ask the user to watch the
  first run

### Ask First
- Any change to the `feature-matrix` (clippy) job — out of scope per this
  spec unless a genuine consistency need is found during implementation
- Any change to `ci-success`'s `needs`/`check_job` wiring — should not be
  needed per FR-002/FR-007, but confirm before touching it if it turns out
  to be necessary

### Never
- Skip or sample ecosystem features to hit a speed target — every ecosystem
  feature keeps its own isolated nextest invocation
- Remove or weaken the `--keep-going`/`--no-fail-fast`/`fail-fast: false`
  "report every failure, don't stop at the first" behavior

## 9. Open Questions

- [NEEDS CLARIFICATION: none — matrix grouping, redundancy removal, and
  per-leg command syntax are all verified empirically above. The only
  residual unknown is real-world GitHub Actions wall-clock time (SC-003),
  which cannot be checked without an actual CI run and is called out as a
  residual risk in NFR-001 and the Edge Cases table rather than blocking
  implementation.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- Issue #1030 — this job's slowness, filed with the timing breakdown above
- Issue #1005, PR #1014, PR #1018 — the job's origin and the guarantee this
  change preserves
- `.github/workflows/ci.yml` — `feature-matrix-test` (and `feature-matrix`,
  unchanged) job definitions
- `crates/deps-lsp/Cargo.toml` — `[features]` table this job iterates over

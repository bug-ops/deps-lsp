---
aliases:
  - Wall-clock test assertions
  - Linear-time test flakiness
  - Deterministic complexity guards
tags:
  - sdd
  - spec
  - testing-infra
  - ci
  - flaky-tests
  - deps-core
  - deps-gradle
  - deps-swift
created: 2026-10-07
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Replace wall-clock bounds in linear-time tests with a load-independent check

> [!info] Metadata
> **Author**: continuous-improvement cycle (spec session, 2026-10-07)
> **Branch**: N/A (no implementation branch yet)
> **Priority**: P3 (testing-infra; CI reliability, no user-visible product behavior)
> **Category**: enhancement (testing-infra)
> **Issue**: #1824

## 1. Overview

### Problem Statement

A family of unit tests protects a real security and robustness invariant: parsers, scanners and redactors
must stay **linear-time on adversarial input** (resource-exhaustion class, CWE-407). Each test builds a
large adversarial input, runs the function, and asserts an absolute wall-clock bound such as
`start.elapsed() < Duration::from_secs(10)`.

An absolute wall-clock bound makes the test outcome a function of runner load rather than of algorithmic
complexity. PR #1823 (merged 2026-10-07) records the symptom: three timing-based parser tests
(`*_flood_on_one_line_is_linear`) "failed once under heavy machine load and pass in isolation". The
failure mode is a false positive (a correct linear implementation fails CI), and the opposite risk also
exists: a bound loose enough to survive load (10s, 20s, 30s) may be too generous to catch a modest
complexity regression on a small input.

Exposure factors in this repository:

- `cargo nextest` runs tests in parallel across all cores, so heavy single-threaded adversarial tests
  compete with each other and with unrelated tests.
- The CI test matrix includes macOS and Windows runners (slower, noisier than Ubuntu), plus coverage
  (`llvm-cov`) and cross-compilation legs that add instrumentation overhead.
- `.config/nextest.toml` sets `retries = 2` for the `ci` profile, which hides a flake by re-running it
  silently. It does not remove the cause, and a genuine regression that fails intermittently could also
  pass on retry.

> [!info] Verified call sites (grep of `crates/`, 2026-10-07)
> The finding that prompted this spec counted 9 sites for `elapsed() < Duration`. A broader grep that also
> matches the saved-variable form (`elapsed < Duration`) finds roughly **30** wall-clock assertions in
> tests. The classification below is a starting point, not a verified audit (see OQ-1).
>
> | Cluster | Sites | Bounds | Shape |
> |---------|-------|--------|-------|
> | Gradle parsers | `deps-gradle/src/parser/groovy.rs:561`, `parser/kotlin.rs:544` (`test_versioned_and_versionless_flood_on_one_line_is_linear`) | 10s | flood of 100,000 repeated forms on one line |
> | Swift parser | `deps-swift/src/parser.rs:2145` (`test_overlapping_forms_flood_on_one_line_is_linear`), `:2131` (`test_path_flood_parses_in_bounded_time`) | 10s, 30s | 50,000 overlapping forms; 200,000 path entries |
> | `deps-core` scanners | `lsp_helpers/git_ref.rs` (4 sites incl. `:3561` saved-variable form), `lsp_helpers/mod.rs:5088,:5110`, `matched_spans.rs:217` | 100ms to 20s | multi-megabyte single-line haystacks, 300,000-span flood |
> | `deps-core` redactor | `redact/url.rs` (10 sites, `:3385` through `:4377`; test names ending `_is_linear_time`) | 300ms to 10s | 200,000 to 400,000-segment adversarial URLs |
> | Other crates | `deps-pypi` (`pyproject.rs:2115`, `requirements.rs:820`), `deps-github-actions/src/parser.rs:1356`, `deps-bundler/src/version.rs:1035`, `deps-go/src/config.rs:1400`, `deps-gradle/src/ecosystem.rs:1278` | 1s to 2s | per-ecosystem adversarial input |
> | Possibly not complexity guards | `deps-lsp/tests/common/mod.rs:672`, `deps-engine/src/classify/fetch.rs:1968` | 2s, 3s | likely concurrency or latency checks; classify before including |
>
> Production uses of `elapsed() <` (TTL checks in `deps-maven/src/registry.rs`, `deps-core/src/osv/mod.rs`,
> `deps_dev/memo.rs`, `deps-swift/src/keychain.rs`) are **not** tests and are out of scope.

> [!info] Existing infrastructure relevant to the options
> - `criterion = "0.8"` is a workspace dependency and nine crates already carry `benches/`.
> - The CI `benchmark` job (`.github/workflows/ci.yml`) only **builds** benchmarks
>   (`cargo build --workspace --benches ...`). It does not run them and gates nothing on results.
> - `.config/nextest.toml` has a `default`, `ci` and `coverage` profile and one per-test override
>   (`slow-timeout`). It defines no `test-groups`.
> - Each affected test also asserts deterministic correctness (for example
>   `dependencies.len() == MAX_DEPENDENCIES_PER_DOCUMENT`); only the timing assertion is non-deterministic.

### Goal

A regression of a guarded function from linear to super-linear time fails the test suite reliably, and a
correct linear implementation does not fail it regardless of runner load, parallelism or platform.

### Out of Scope

- Changing the guarded production code (parsers, scanners, redactors); this spec covers how their
  complexity is verified, not their behavior.
- Replacing the algorithmic fixes themselves (#862, #882, #885 and related); those stay as the source of
  truth for why each guard exists.
- Production TTL and cache logic that happens to use `Instant::elapsed()`.
- Latency or throughput SLOs for hover, completion or registry fetches.
- General CI-speed or test-suite-redundancy work.
- Implementation design (helper shape, crate layout, nextest group names); that belongs in `plan`.
- Edits under `crates/deps-zed` (separate repository).

### Candidate directions (to be chosen, not decided here)

| Opt | Direction | Determinism | Main trade-off |
|-----|-----------|-------------|----------------|
| a | In-process **scaling-ratio** check: time the same function at N and 2N (or N, 2N, 4N) and compare the ratio, with no absolute bound | Statistical; load affects both measurements, but noise at small timings can still flip the ratio | No production change; needs repetitions or a min-of-k policy to be stable; weak when per-run time is near timer resolution |
| b | **Deterministic work counter or step budget** exposed through a test-only hook; the test asserts operation count is `<= c * n` | Fully deterministic | Touches production code paths; must stay out of the non-dev dependency tree (the repo's `test-util` leak guard); not applicable to opaque third-party code such as the `regex` crate |
| c | Move the tests into a dedicated **serial nextest test-group** (`.config/nextest.toml`) with a generous absolute bound | Reduces self-inflicted contention only; external runner noise remains | Lowest effort; keeps an absolute bound, so sensitivity stays poor and neighbor-VM noise is untouched |
| d | **criterion or divan benchmark** with a CI regression gate (the `benchmark` job already exists) | Statistical, with baseline comparison | Needs baseline storage and a runner-noise policy; the current job only builds benches, so the gate is new infrastructure |

These are not mutually exclusive: different clusters may suit different options (for example counters for
hand-rolled scanners, a ratio check for third-party-backed parsers).

## 2. User Stories

### US-001: No false CI failures from load
AS A contributor opening a PR
I WANT complexity-guard tests to pass whenever the code is linear, whatever the runner load
SO THAT I do not re-run CI or chase a failure unrelated to my change.

**Acceptance criteria:**
```
GIVEN a correct linear implementation and a CI runner under heavy parallel load or on macOS/Windows
WHEN the complexity-guard tests run
THEN every guard passes without relying on nextest retries
```

### US-002: Reliable detection of a complexity regression
AS A maintainer
I WANT a reintroduced quadratic (or worse) behavior to fail the guard every time
SO THAT the CWE-407 protections these tests encode cannot silently erode.

**Acceptance criteria:**
```
GIVEN a guarded function deliberately modified to be quadratic on its adversarial input
WHEN the guard tests run on an otherwise idle machine and on a loaded machine
THEN the corresponding guard fails in both cases
```

### US-003: Visible, uniform convention
AS A developer adding a new adversarial-input test
I WANT one documented, reusable way to assert linear time
SO THAT I do not copy a hard-coded `Duration` bound into yet another test.

**Acceptance criteria:**
```
GIVEN a developer adding a new linear-time guard
WHEN they follow the project's testing guidance
THEN the guidance points to the single shared mechanism and no new hard-coded Duration bound is needed
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a test guards a function against super-linear behavior on adversarial input, THE SYSTEM SHALL decide pass or fail without comparing measured wall-clock time against an absolute `Duration` constant. | must |
| FR-002 | WHEN a guarded function regresses from linear to quadratic (or worse) on its adversarial input, THE SYSTEM SHALL fail the corresponding test deterministically, with no dependence on a nextest retry succeeding. | must |
| FR-003 | WHEN the guard tests run under the CI parallel test runner on any matrix platform (ubuntu, macos, windows) and under coverage instrumentation, THE SYSTEM SHALL NOT fail a correct linear implementation because of runner load. | must |
| FR-004 | THE SYSTEM SHALL cover at least the sites named in the finding: Gradle (`groovy.rs`, `kotlin.rs`), Swift (`parser.rs`, both tests), and the `deps-core` sites in `lsp_helpers/git_ref.rs`, `matched_spans.rs` and `lsp_helpers/mod.rs`. | must |
| FR-005 | THE SYSTEM SHOULD cover the remaining wall-clock complexity guards found by repo-wide classification (OQ-1), including `redact/url.rs` and the per-ecosystem parser tests. | should |
| FR-006 | THE SYSTEM SHALL keep every existing deterministic correctness assertion in the affected tests (for example dependency-count truncation and redaction output) unchanged. | must |
| FR-007 | WHEN a shared helper or hook is introduced for the check, THE SYSTEM SHALL place it in a single shared location so ecosystem crates do not each carry their own copy (cross-ecosystem consistency rule). | must |
| FR-008 | WHERE the chosen mechanism needs a test-only hook in production code, THE SYSTEM SHALL ensure the hook is unreachable from `deps-lsp`'s non-dev dependency tree and from release binaries (compiled out or gated so the existing `test-util` leak guard stays green). | must |
| FR-009 | WHEN a guard fails, THE SYSTEM SHALL report the observed measure (counter value, ratio, or timings at each input size) and the input size, so a regression is diagnosable without re-running. | should |
| FR-010 | THE SYSTEM SHALL document the convention (when a test is a complexity guard and how to write one) in contributor-facing guidance, and SHALL record the change as one line with the PR link in `CHANGELOG.md` `[Unreleased]`. | must |
| FR-011 | WHEN tests that are not complexity guards (latency or concurrency checks, see OQ-1) are encountered during classification, THE SYSTEM SHALL leave them out of this change or handle them under their own rationale. | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | Over at least [NEEDS CLARIFICATION: N runs, see OQ-3] consecutive CI-like runs under induced load (for example a stress run alongside the full suite), the guards SHALL show zero false failures. |
| NFR-002 | Sensitivity | The check SHALL distinguish linear from quadratic behavior at the adversarial input sizes the tests already use; it SHALL NOT be less sensitive than the current absolute bounds. |
| NFR-003 | Speed | The guard tests SHALL NOT materially increase total suite time; if the mechanism repeats runs (option a), the added cost SHALL be bounded and stated. |
| NFR-004 | Type safety | Any work counter, budget or measurement result SHALL be a dedicated type (newtype or enum), not a bare `u64`, `f64` or stringly-typed value; any ratio threshold SHALL be a named constant of a purpose-built type. No `unsafe` (`unsafe_code = "forbid"` stays in force). |
| NFR-005 | Simplicity | The mechanism SHOULD be the smallest that satisfies FR-001 to FR-003 (pre-1.0 MVP rule); no new dependency SHALL be added unless justified, and any new dependency SHALL follow the workspace-pinning rule. |
| NFR-006 | Portability | The check SHALL behave identically on ubuntu, macos and windows runners and on the `i686` cross-check, with no platform-specific timer assumptions. |
| NFR-007 | Maintainability | Adding a new complexity guard SHALL require at most one call to the shared mechanism plus the adversarial input generator. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Complexity guard test | A test that feeds an adversarial input to a function and asserts it stays linear | function under test, adversarial generator, input size(s), correctness assertions |
| Scaling measurement | Result of running a guarded function at two or more input sizes (option a) | input sizes, per-size cost, derived ratio |
| Work counter | Deterministic count of operations performed by a guarded function (option b) | unit of work, input size, allowed linear coefficient |
| Test-group | nextest construct limiting concurrency for selected tests (option c) | member filter, `max-threads` |
| Benchmark baseline | Stored reference timings compared on CI (option d) | benchmark id, baseline source, tolerance |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Runner is heavily loaded during one measurement but not the other (option a) | Ratio check tolerates it via repetition or min-of-k policy, or the mechanism is not offered for that site (OQ-3) |
| Function is so fast at the chosen N that time is near timer resolution (option a) | Input sizes are raised or option a is rejected for that site; a ratio of noise SHALL NOT be asserted |
| Function is a regex or third-party scanner with no counter hook (option b) | Fall back to another option for that site (OQ-2) |
| Linearity depends on a fixed cap (for example `MAX_DEPENDENCIES_PER_DOCUMENT` truncation) | The guard exercises input sizes both below and above the cap, or documents which regime it covers (OQ-4) |
| Tests run under `llvm-cov` instrumentation | Guard behavior is unaffected; instrumentation overhead scales both sizes equally (option a) or does not change counts (option b) |
| A guard test is retried by nextest `ci` profile (`retries = 2`) | A deterministic guard never needs the retry; a retried-then-passed guard is visible and not treated as healthy (OQ-5) |
| Counter hook compiled into a release build | Not allowed (FR-008); the leak guard step in CI `check` must catch it |
| Windows `Instant` granularity is coarser than on Linux | The mechanism does not rely on sub-millisecond timing |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | False failures of the in-scope guards across a stress run (full suite in parallel plus induced CPU load) | 0 over [NEEDS CLARIFICATION: N] runs |
| SC-002 | Mutation check: each in-scope guard, run against a deliberately quadratic variant of its function | 100% fail |
| SC-003 | In-scope tests still asserting an absolute `Duration` bound on a complexity guard | 0 |
| SC-004 | Copies of the linear-time check mechanism outside the single shared location | 0 |
| SC-005 | Release-build or non-dev dependency tree reachability of any test-only hook (`cargo tree -p deps-lsp -e features,no-dev` guard) | none |
| SC-006 | Added wall time of the guard tests in the full nextest run | [NEEDS CLARIFICATION: budget, see OQ-3] |

## 8. Agent Boundaries

### Always (without asking)
- Reproduce a flake or a mutation result live (run the guard under induced load, run the quadratic variant) before concluding a mechanism works; code reading alone is not evidence.
- Keep the existing deterministic correctness assertions in every affected test.
- Run the full CI-matching check suite (fmt, clippy `-D warnings`, nextest, rustdoc gate) before declaring done, and run the guards under parallel load.
- Check `deps-core` for an existing shared helper before writing a new one (DRY, cross-ecosystem rule).

### Ask First
- Choosing between options a, b, c and d, or mixing them per cluster (OQ-2).
- Adding any dependency (for example `divan`, a statistics crate) or a new CI job or baseline store.
- Adding a test-only hook to production code, or changing a production function signature to expose a counter.
- Changing the `ci` nextest profile `retries` value or adding `test-groups` that affect unrelated tests.
- Including the non-complexity timing tests (`deps-lsp/tests/common/mod.rs`, `deps-engine/.../fetch.rs`) in scope.

### Never
- Raise an absolute `Duration` bound as the sole fix (it hides the flake and lowers sensitivity).
- Add `#[ignore]` to, or delete, a complexity guard to make CI green.
- Weaken or remove the algorithmic fix or the correctness assertions the guards accompany.
- Let a test-only hook become reachable from `deps-lsp`'s non-dev dependency tree or release binaries.
- Edit files under `crates/deps-zed`.
- Use a bare numeric, string or `bool`-flag type where a dedicated type can express the measure.

## 9. Open Questions

> [!question] Open items (7)
> Resolve before moving to `plan`.

- [NEEDS CLARIFICATION: OQ-1 Scope and classification. The finding lists 9 sites; a broader grep finds about 30 wall-clock assertions (10 of them in `redact/url.rs`). Which are true complexity guards versus latency or concurrency checks, and is the in-scope set the 9 named sites, all complexity guards repo-wide, or a phased subset (named sites first)? A live audit of each site (what is the input, what bound is asserted, what is the typical measured time) is needed before deciding.]
- [NEEDS CLARIFICATION: OQ-2 Mechanism. Option a (scaling ratio), b (deterministic counter or step budget), c (serial nextest group with a generous bound), d (criterion/divan benchmark with a CI gate), or a per-cluster mix? Research view: b is the only fully deterministic option but cannot cover third-party-backed code; a needs no production change; c alone does not remove external runner noise and keeps a loose bound; d adds the most infrastructure. Confirm direction, and whether c is acceptable as a stop-gap alongside a longer-term a or b.]
- [NEEDS CLARIFICATION: OQ-3 If option a is chosen: which input sizes and ratio threshold (for example time at 2N must be below some multiple of time at N), how many repetitions or what min-of-k policy, and what stress-run length and added-time budget define "no false failures" (NFR-001, SC-001, SC-006)? Must be validated empirically on ubuntu, macOS and under `llvm-cov`, since the quoted flake was observed only once and its load profile is unknown.]
- [NEEDS CLARIFICATION: OQ-4 If option b is chosen: where can a counter or budget live without a production signature change or a leak into the non-dev tree (a `cfg(test)`-only field, a `test-util`-gated hook, or a generic instrumented-iterator seam)? Also, several guards depend on a truncation cap (`MAX_DEPENDENCIES_PER_DOCUMENT`); should the linearity assertion target the pre-cap scan work, the post-cap total, or both?]
- [NEEDS CLARIFICATION: OQ-5 Retries. The `ci` profile uses `retries = 2`, which masks timing flakes. Should flaky-pass (retried) results of guard tests be surfaced, should the guards be pinned to `retries = 0` via a nextest override, or is that out of scope for this spec?]
- [NEEDS CLARIFICATION: OQ-6 If option d is chosen: the CI `benchmark` job only builds benches today. Is a run-and-compare gate wanted, where does the baseline live (committed file, cache, artifact, external service), and what tolerance is acceptable on shared runners? Is a statistical gate even desirable given the same noise problem?]
- [NEEDS CLARIFICATION: OQ-7 Where does the convention live (a section in contributor docs, `.claude/rules/`, a `deps-core` test-util module doc), and should a lint-style check (for example a CI grep for `elapsed() < Duration`/`elapsed < Duration` in test code outside an allowlist) prevent new hard-coded bounds from appearing (US-003)?]

## 10. See Also

- [[constitution]] — project principles (testing is non-negotiable; type safety is a core principle)
- [[MOC-specs]] — all specifications
- PR #1823 — merged 2026-10-07; records the three `*_flood_on_one_line_is_linear` failures under heavy load
- Issues #862, #882, #885 — the original super-linear defects whose regression guards are in scope
- `crates/deps-gradle/src/parser/groovy.rs`, `crates/deps-gradle/src/parser/kotlin.rs` — `test_versioned_and_versionless_flood_on_one_line_is_linear`
- `crates/deps-swift/src/parser.rs` — `test_overlapping_forms_flood_on_one_line_is_linear`, `test_path_flood_parses_in_bounded_time`
- `crates/deps-core/src/lsp_helpers/git_ref.rs`, `lsp_helpers/mod.rs`, `matched_spans.rs`, `redact/url.rs` — `deps-core` wall-clock guards
- `.config/nextest.toml` — profiles (`default`, `ci` with `retries = 2`, `coverage`); no `test-groups` yet
- `.github/workflows/ci.yml` — `benchmark` job (build-only) and `check` job `test-util` leak guard

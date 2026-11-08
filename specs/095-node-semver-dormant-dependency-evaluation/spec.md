---
aliases:
  - node-semver replacement evaluation
  - npm range engine dependency health
tags:
  - sdd
  - spec
  - research
  - dependencies
  - deps-core
  - deps-npm
  - deps-deno
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Evaluate the dormant node-semver range engine and decide keep, replace, or in-house

> [!info] Metadata
> **Author**: research session, 2026-11-08
> **Branch**: N/A (research finding, no implementation branch)
> **Priority**: P3 (dependency health; no user-visible defect today)
> **Type**: research / dependency health

## 1. Overview

### Problem Statement

The npm and Deno range grammar is evaluated by the external crate `node-semver` (`node-semver = "2.2"` in the root `Cargo.toml`). It is used by `deps-npm`, `deps-deno` and `deps-core` (`interval.rs`, `lsp_helpers/*`, `edit.rs` paths that gate on `MAX_REQUIREMENT_LEN`).

> [!info] Evidence (verified 2026-11-08 against crates.io and GitHub)
>
> | Signal | Value |
> |--------|-------|
> | Latest release | 2.2.0, 2025-02-07 (about 21 months ago) |
> | Repository | `felipesere/node-semver-rs`, last push 2025-02-07 |
> | Open issues | 5 |
> | MSRV | 1.70 |
> | Dependencies | `nom 7`, `miette 7`, `thiserror 1.0.69`, `bytecount`, `serde` |
> | Duplicate chain | `cargo tree --duplicates` shows it is the only source of `thiserror 1.0.69` (and `thiserror-impl 1`) and of `unicode-width 0.1.14` (via `miette`) in the normal tree, duplicating `thiserror 2.0.21` and `unicode-width 0.2.3` |

Two consequences follow. First, the crate is a single point of failure with no active upstream to take a fix: any parser panic or grammar bug must be absorbed locally. The project already does this: #1630 (Critical, unhandled `node_semver` panic on npm ranges, CWE-248) and #1657 (fuzz target aborting on `node_semver` panics that `parse_range_safe` already catches) show the engine is wrapped in `catch_unwind`-style guards rather than trusted. Second, the dormant crate pins an older dependency generation, inflating the build graph and the supply-chain surface for no functional gain.

A candidate replacement exists but is not a clear win:

| Signal | `nodejs-semver` |
|--------|-----------------|
| Source | `cijiugechu/nodejs-semver` (GitHub), crates.io `nodejs-semver` |
| Latest | 7.0.0, published 2026-09-25 |
| Recent downloads | about 255k |
| MSRV / license | 1.85 / Apache-2.0 |
| Dependencies | `smallvec`, `thiserror 2`, optional `serde` |
| Risk signals | majors 6.0.0 (2026-09-19) and 7.0.0 (2026-09-25) six days apart indicate API churn; about 8 stars |

Alternatives are to keep `node-semver` (optionally vendored or forked) or to implement the range grammar in-house on top of `deps-core::interval`.

This spec does not choose. It fixes what must remain true after any change and the criteria and gate used to decide.

### Goal

A maintainer can reach a documented, evidence-backed decision (keep, replace with a named crate, vendor/fork, or in-house) such that, whichever is chosen, npm and Deno range behavior is provably unchanged on the agreed corpus and untrusted input cannot panic or abort the process.

### Out of Scope

- Performing the replacement itself (belongs to a follow-up spec/plan and its own PR).
- Implementation design: adapter shape, module layout, migration order (belongs to `plan`).
- Other semver engines (`semver` for Cargo, `pep440_rs`, etc.) and their dependency health.
- Changing user-visible range semantics beyond fixing demonstrated divergence from the npm reference behavior.
- Edits under `crates/deps-zed` (separate repository).

## 2. User Stories

### US-001: Behavioral parity
AS A user editing `package.json` or a Deno specifier
I WANT hover, diagnostics, code actions and completions to give the same results after any engine change
SO THAT a dependency housekeeping change does not alter my outdated/unsatisfiable verdicts.

**Acceptance criteria:**
```
GIVEN the agreed parity corpus of npm and Deno ranges and versions
WHEN each (range, version) pair is evaluated by the current engine and by the candidate
THEN satisfies(), parse success/failure, and range-to-interval output are identical
AND every intentional difference is listed, justified, and recorded in CHANGELOG.md
```

### US-002: Safe on untrusted input
AS A maintainer
I WANT no manifest content to be able to panic or abort the server through the range engine
SO THAT the LSP process survives hostile or malformed files.

**Acceptance criteria:**
```
GIVEN arbitrary UTF-8 as a range or version string (including inputs at and above MAX_REQUIREMENT_LEN)
WHEN it is parsed and evaluated through the shared entry points
THEN no panic or abort occurs, and over-length input is rejected before reaching the engine
```

### US-003: Evidence-based decision
AS A maintainer
I WANT a scored comparison of every option against fixed criteria with a decision gate
SO THAT the choice is reproducible and not driven by download counts or novelty.

**Acceptance criteria:**
```
GIVEN the option list in Section 5
WHEN the evaluation is complete
THEN each option has a recorded value for every criterion in FR-008 and the gate in FR-011 yields exactly one outcome
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN any engine other than the current `node-semver` 2.2 is adopted, THE SYSTEM SHALL accept and reject the same npm range grammar, including comparators, hyphen ranges, `x`/`X`/`*` wildcards, caret and tilde, `||` unions, and whitespace variants. | must |
| FR-002 | WHEN a range contains the `~*` or `=*` wildcard forms, THE SYSTEM SHALL preserve the handling established by #1639 (same parse outcome and same interval). | must |
| FR-003 | WHEN a version carries a prerelease tag, THE SYSTEM SHALL apply npm prerelease exclusion semantics unchanged: a prerelease satisfies a range only if a comparator in the same `major.minor.patch` tuple carries a prerelease tag. | must |
| FR-004 | THE SYSTEM SHALL ensure no input string, however malformed or large, causes a panic or process abort through the range engine, either natively or via a retained panic-containment guard. | must |
| FR-005 | WHEN a requirement string exceeds `MAX_REQUIREMENT_LEN`, THE SYSTEM SHALL reject it before it reaches the engine, as it does today. | must |
| FR-006 | WHEN a parsed range is converted for edit and diagnostic logic, THE SYSTEM SHALL produce the same `deps-core::interval` representation as today for every range in the parity corpus. | must |
| FR-007 | THE SYSTEM SHALL keep the engine behind a single shared seam in `deps-core`, so `deps-npm` and `deps-deno` do not each reimplement or directly depend on engine specifics. | must |
| FR-008 | THE SYSTEM SHALL evaluate every option against these criteria: (a) maintenance signals (last release, last commit, open-issue triage, bus factor); (b) MSRV at or below the workspace `rust-version` (1.98); (c) transitive dependency weight and duplicate crates in `cargo tree --duplicates`; (d) `unsafe` surface (the workspace forbids `unsafe_code`; dependency `unsafe` is counted and reviewed); (e) license compatibility with `deny.toml`; (f) panic behavior under fuzzing; (g) differential-fuzz result against the current engine; (h) API stability (breaking-release cadence). | must |
| FR-009 | THE SYSTEM SHALL run a differential fuzz (and a curated corpus) comparing the current engine and each candidate on parse outcome, `satisfies`, and interval conversion, and SHALL record every divergence with a minimal repro. | must |
| FR-010 | IF a divergence is found, THEN THE SYSTEM SHALL classify it as candidate bug, current-engine bug, or intentional-compatible difference, and SHALL add each non-intentional case to `.local/testing/regressions.md`. | should |
| FR-011 | THE SYSTEM SHALL apply a decision gate: an option is eligible only if it passes FR-001 to FR-006 with zero unclassified divergences, meets MSRV, adds no `unsafe` in its normal tree beyond an explicitly approved allowance, and shows an actively maintained release line; among eligible options the lowest dependency weight and API churn wins; if none is eligible, the decision is keep (with documented mitigation). | must |
| FR-012 | WHEN the decision is to keep the current crate, THE SYSTEM SHALL record the accepted risk and the trigger conditions for revisiting (for example a new advisory, an unfixable panic, or a toolchain break). | should |
| FR-013 | WHEN the decision changes a dependency, THE SYSTEM SHALL record it in `CHANGELOG.md` `[Unreleased]` as a one-line entry with the PR link, and SHALL pin the new version only in root `[workspace.dependencies]`. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | Fuzz runs of the shared range entry points on 2 MiB-stack threads SHALL produce zero panics or aborts. |
| NFR-002 | Security | The normal dependency tree SHALL NOT gain new advisories (`cargo deny check`, `cargo audit`) and SHALL NOT introduce `openssl-sys`. |
| NFR-003 | Maintainability | Duplicate crate versions attributable solely to the range engine (`thiserror 1`, `unicode-width 0.1`) SHALL be eliminated or explicitly justified. |
| NFR-004 | Performance | Range parse and `satisfies` cost on the existing `deps-npm` benchmarks SHALL NOT regress by more than an agreed threshold [NEEDS CLARIFICATION: acceptable regression threshold for npm benchmarks]. |
| NFR-005 | Type safety | Engine errors SHALL surface as typed enums; no stringly-typed discrimination and no catch-all `_ =>` arms on exhaustive project enums. |
| NFR-006 | Consistency | Behavior SHALL be identical across npm and Deno for shared grammar, implemented once in `deps-core`. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Option | A candidate resolution of the dormant dependency | keep as-is, keep vendored/fork, `nodejs-semver`, in-house on `deps-core::interval` |
| Criterion | A measured evaluation axis (FR-008) | name, measurement method, threshold |
| Parity corpus | Curated (range, version) pairs plus fuzz-discovered cases | npm grammar coverage, #1639 wildcards, prerelease cases, length-boundary cases |
| Divergence record | One observed difference between engines | input, per-engine result, classification, resolution |
| Decision gate | Rule combining criteria into one outcome | outcome in {keep, vendor/fork, replace(crate), in-house} |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `~*` / `=*` ranges | Same outcome as #1639 handling |
| Prerelease version against a range without prerelease comparators | Not satisfied (FR-003) |
| Requirement exactly `MAX_REQUIREMENT_LEN` vs `MAX_REQUIREMENT_LEN + 1` | At-cap accepted by the guard; over-cap rejected before the engine (FR-005) |
| Deeply repeated `||` or very long comparator lists under the cap | No panic, no unbounded latency |
| Non-ASCII, NUL, or control characters in a range | Clean parse error, no panic |
| Engine panics on some input | Contained by the retained guard or absent natively; process survives (FR-004) |
| Candidate publishes another breaking major during evaluation | Evaluation pins an exact version; the churn is recorded under API stability (FR-008h) |
| Candidate accepts a range the current engine rejects (or the reverse) | Recorded as a divergence and classified (FR-010) |
| Deno specifier ranges (`npm:` / `jsr:` specifiers) | Evaluated through the same parity corpus, not separately reimplemented |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Unclassified divergences between current engine and chosen option on the parity corpus | 0 |
| SC-002 | Panics or aborts across differential and shared-entry-point fuzz | 0 |
| SC-003 | Duplicate crates attributable only to the range engine (if replaced) | 0 |
| SC-004 | Options with a recorded value for every FR-008 criterion | 100% |
| SC-005 | Crates outside `deps-core` containing their own range-engine logic | 0 |
| SC-006 | Decision recorded with gate outcome and rationale | 1 |

## 8. Agent Boundaries

### Always (without asking)
- Verify engine behavior with live runs (scratch crate or the fuzz harness), not code reading alone.
- Reuse `deps-core::interval` and existing shared helpers before adding ecosystem-local code.
- Keep the existing panic guard and `MAX_REQUIREMENT_LEN` check in place until replacement parity is demonstrated.

### Ask First
- Adding or replacing a workspace dependency, or vendoring/forking `node-semver`.
- Adopting an in-house range parser.
- Accepting any intentional behavior difference.
- Removing the panic-containment guard.

### Never
- Edit source code as part of the research session that produced this spec.
- Decide on download counts or version recency alone, without the differential result.
- Add a catch-all `_ =>` arm to sidestep exhaustive matching.
- Touch files under `crates/deps-zed`.

## 9. Open Questions

> [!question] Open items
> - [NEEDS CLARIFICATION: acceptable benchmark regression threshold (NFR-004)]
> - [NEEDS CLARIFICATION: is an `unsafe` allowance in a dependency's normal tree ever acceptable, and if so under what review?]
> - [NEEDS CLARIFICATION: minimum maintenance bar for "actively maintained" (for example a release or commit within 12 months, and at least two maintainers)]
> - [NEEDS CLARIFICATION: does the Deno path need a reference semantics other than npm's for any specifier form?]
> - [NEEDS CLARIFICATION: issue number tracking this finding]
> - [NEEDS CLARIFICATION: whether `deps-npm` benches at `crates/deps-npm/benches/npm_benchmarks.rs` are the right regression baseline]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-npm/src/` — npm parsing, types, catalog, lockfile, formatter
- `crates/deps-deno/src/specifier.rs` — Deno specifier ranges
- `crates/deps-core/src/interval.rs` — range-to-interval conversion
- `crates/deps-core/src/lsp_helpers/` — `MAX_REQUIREMENT_LEN` and in-use version logic
- Related history: #1630 (unhandled `node_semver` panic), #1657 (fuzz abort on `node_semver` panics), #1639 (`~*` / `=*` wildcard handling)
- Candidate: `nodejs-semver` (`cijiugechu/nodejs-semver`); current: `node-semver` (`felipesere/node-semver-rs`)

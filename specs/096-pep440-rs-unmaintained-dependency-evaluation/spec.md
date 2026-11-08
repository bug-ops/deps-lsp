---
aliases:
  - pep440_rs maintenance evaluation
  - PEP 440 engine replacement decision
tags:
  - sdd
  - spec
  - research
  - dependencies
  - deps-pypi
  - supply-chain
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Evaluate the unmaintained `pep440_rs` dependency and decide keep, replace, or vendor

> [!info] Metadata
> **Author**: rust-researcher (research session, 2026-11-08)
> **Branch**: N/A (research finding, no implementation branch)
> **Priority**: P3 (dependency health; no user-visible defect today)
> **Related issue**: `pep508_rs` malformed-name panic, #703 (open)

## 1. Overview

### Problem Statement

`deps-pypi` relies on `pep440_rs` (workspace requirement `pep440_rs = "0.7"`, root `Cargo.toml`) as its
PEP 440 engine: version parsing, ordering, and specifier matching used to classify PyPI dependencies as
up to date, outdated, or unsatisfiable. The same types are used outside `deps-pypi` in `deps-core`
(`package.rs`, `osv/mod.rs`) and in the `deps-pypi` registry, formatter and type modules.

The dependency's health has degraded, verified on 2026-11-08:

| Signal | Evidence |
|--------|----------|
| Latest release | 0.7.3, published 2024-12-04 (about 11 months old) |
| Author statement | Upstream README (`konstin/pep440-rs`, README updated 2026-10-20): "This library is feature-complete, but it also isn't actively maintained anymore." |
| Repository activity | Since 2025-03 only Dependabot removal and lint fixes (2026-10-20) |
| Sibling crate | `pep508_rs` 0.9.2 already required a `catch_unwind` workaround for a malformed-name panic (open upstream issue #703) |

This is a risk signal, not a bug: no incorrect result from `pep440_rs` is known. The cost of inaction is
latent: a future PEP 440 clarification, a Rust edition or MSRV change, or a security report against an
unmaintained crate would have no upstream to fix it, and the project's 1.98 MSRV may eventually exclude it.

One candidate replacement exists, `uv-pep440` (crates.io; 0.0.99 published 2026-11-03; about 121k recent
downloads; maintained inside `astral-sh/uv`). It is versioned `0.0.x`, so it offers no semver stability
promise. It is one option to evaluate, not a decision. The other options are to keep the current pin, or
to vendor the needed subset.

### Goal

A written, evidence-backed decision on the PEP 440 engine (keep, replace, or vendor), reached through an
explicit decision gate, such that whichever option is chosen preserves every PEP 440 behavior deps-pypi
users depend on and introduces no new panic or abort on untrusted input.

### Out of Scope

- Performing the migration or vendoring itself; this spec constrains what must hold after any change and
  how the choice is made. Implementation design belongs in `plan`.
- Re-implementing PEP 440 from scratch inside `deps-core`.
- PEP 508 marker evaluation semantics, except where the joint evaluation question (OQ-1) applies.
- Other ecosystems' version engines (`semver`, `node-semver`, Maven, NuGet interval grammar in
  `deps-core::interval`); they are only a reference for the shared-helper rule (see NFR-005).
- Edits under `crates/deps-zed` (separate repository).

> [!warning] Assumptions
> - "Feature-complete" per upstream means the PEP 440 surface used here is stable; the risk is
>   maintenance, not missing functionality.
> - `uv-pep440` is API-compatible enough to be a candidate; its actual public surface (version type,
>   specifier type, error types) has not been compared against current call sites.

## 2. User Stories

### US-001: Maintainer needs a defensible dependency decision
AS A maintainer of deps-lsp
I WANT a documented keep, replace, or vendor decision for the PEP 440 engine
SO THAT the dependency's maintenance status is a conscious, recorded risk rather than a surprise.

**Acceptance criteria:**
```
GIVEN the evaluation criteria in Section 3 have been measured for each option
WHEN the decision gate is run
THEN exactly one option is selected with the measured evidence recorded
AND any option other than "keep" has a follow-up implementation issue filed
```

### US-002: Python user sees no behavioral change
AS A user of deps-lsp editing `pyproject.toml` or `requirements.txt`
I WANT outdated, up-to-date and unsatisfiable verdicts to stay identical after any engine change
SO THAT diagnostics, hover and code actions do not change because of a dependency swap.

**Acceptance criteria:**
```
GIVEN a corpus of version strings and specifiers (including those from real uv.lock and poetry.lock files)
WHEN each is evaluated by the current engine and by the candidate
THEN ordering and matching results are identical, or every difference is classified and approved
```

### US-003: Security reviewer needs panic-free parsing
AS A security reviewer
I WANT no PEP 440 or PEP 508 input to panic or abort the server
SO THAT a hostile manifest cannot crash the language server.

**Acceptance criteria:**
```
GIVEN arbitrary UTF-8 as a version string, specifier set, or requirement line
WHEN it is parsed by the selected engine through deps-pypi
THEN the result is Ok or a typed error, never a panic or process abort
```

## 3. Functional Requirements

### 3.1 Behavior that must hold after any change

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN two valid PEP 440 versions are compared, THE SYSTEM SHALL order them per PEP 440: epochs, release segments with implicit trailing zeros, then `dev` < `a` < `b` < `rc` < final < `post`, plus local-version ordering. | must |
| FR-002 | WHEN a version string uses a PEP 440 normalization alias (`alpha`, `beta`, `c`, `pre`, `preview`, `rev`, `r`, leading `v`, mixed separators, uppercase), THE SYSTEM SHALL treat it as equal to its canonical form. | must |
| FR-003 | WHEN a specifier uses `==`, `!=`, `<=`, `>=`, `<`, `>`, `~=`, `===`, or a `.*` wildcard, THE SYSTEM SHALL match candidates exactly as PEP 440 defines, including the compatible-release `~=` rule (`~=2.2` is `>=2.2, ==2.*`; `~=2.2.0` is `>=2.2.0, ==2.2.*`). | must |
| FR-004 | WHEN `===` (arbitrary equality) is used, THE SYSTEM SHALL compare the strings case-insensitively without PEP 440 normalization and SHALL NOT panic on a non-PEP-440 operand. | must |
| FR-005 | WHEN a candidate has a local version label (`+local`), THE SYSTEM SHALL apply PEP 440 rules: a specifier without a local part ignores the candidate's local label for `==`; with a local part it requires a local match. | must |
| FR-006 | WHEN a candidate is a pre-release, dev release, or post-release, THE SYSTEM SHALL apply PEP 440 inclusion rules: pre-releases are excluded unless the specifier set names one or no final release satisfies it, and the exclusive-ordered comparisons (`<V`, `>V`) SHALL NOT admit pre-releases of V or local or post versions of V as PEP 440 prescribes. | must |
| FR-007 | WHEN the version strings come from PyPI's own metadata or from `uv.lock` / `poetry.lock`, THE SYSTEM SHALL parse every such string that the current engine parses, and SHALL produce the same ordering and the same "in-use vs latest" verdict. | must |
| FR-008 | WHEN an input is not valid PEP 440, THE SYSTEM SHALL return a typed error that carries no attacker-controlled content into logs, consistent with the existing redaction conventions in `deps-pypi`. | must |
| FR-009 | WHEN any PEP 440 or PEP 508 input of any length or shape is parsed, THE SYSTEM SHALL NOT panic, abort, or recurse unboundedly. | must |
| FR-010 | THE SYSTEM SHALL keep the third-party version and specifier types out of `deps-pypi` and `deps-core` public signatures, so a later engine change does not break downstream signatures (existing precedent: `Pep508ParseError` wrapping `pep508_rs::Pep508Error`, #835). | should |

### 3.2 Evaluation criteria

| ID | Requirement | Priority |
|----|------------|----------|
| FR-011 | WHEN each option (keep `pep440_rs` 0.7.x, `uv-pep440`, vendored subset) is evaluated, THE SYSTEM SHALL record these maintenance signals with dates: last release, release cadence, last commit, open-issue triage state, and the maintainer's own stated status. | must |
| FR-012 | WHEN each option is evaluated, THE SYSTEM SHALL record API stability: semver promise (or absence of one), history of breaking changes in the last 12 months, and the number of call sites in deps-lsp affected by the public surface differences. | must |
| FR-013 | WHEN each option is evaluated, THE SYSTEM SHALL verify its MSRV is at most the workspace `rust-version` (currently 1.98) and that it builds on the CI matrix (ubuntu, macos, windows; stable and beta). | must |
| FR-014 | WHEN each option is evaluated, THE SYSTEM SHALL record dependency weight: the added transitive crate count and notable heavy crates versus the current tree, using `cargo tree`, and confirm no `openssl-sys` and no licence rejected by `cargo deny check`. | must |
| FR-015 | WHEN a replacement candidate is evaluated, THE SYSTEM SHALL run a differential test against the current engine over a shared corpus covering ordering, normalization, every specifier operator, local versions, and pre/dev/post cases, and SHALL classify every disagreement as a bug in one engine, an intentional spec reading difference, or an input one engine rejects. | must |
| FR-016 | WHEN a replacement candidate is evaluated, THE SYSTEM SHALL fuzz its parse entry points on the same inputs as the current `fuzz/fuzz_targets/pypi_requirement.rs` and `requirement_matcher.rs` targets and record any panic or abort. | must |
| FR-017 | WHERE the candidate lives inside a larger repository (`uv`), THE SYSTEM SHALL record how the crate is published and versioned (independent release vs lock-step with `uv`), its breaking-change history on the 0.0.x line, and whether pinning an exact version (`=0.0.N`) is required for reproducibility. | should |

### 3.3 Decision gate

| ID | Requirement | Priority |
|----|------------|----------|
| FR-018 | THE SYSTEM SHALL select "replace" only IF all must-priority behavior requirements (FR-001 to FR-009) hold for the candidate with zero unclassified differential disagreements, MSRV, licence and dependency-weight checks pass (FR-013, FR-014), and no fuzz panic is open (FR-016). | must |
| FR-019 | THE SYSTEM SHALL select "keep" IF no candidate passes FR-018, and in that case SHALL record a re-evaluation trigger (see FR-021). | must |
| FR-020 | THE SYSTEM SHALL select "vendor" only IF no external candidate passes FR-018 AND the vendored surface is confined to the operations in FR-001 to FR-006, with the licence of the copied code permitting it and a recorded owner for ongoing PEP 440 conformance. | should |
| FR-021 | WHEN the decision is "keep", THE SYSTEM SHALL name concrete re-evaluation triggers: a RUSTSEC advisory against `pep440_rs`, an MSRV or edition incompatibility, a PEP 440 correctness bug reproduced live, or a candidate reaching a stable (at least 0.1 or 1.0) version. | must |
| FR-022 | WHEN the decision is recorded, THE SYSTEM SHALL state whether `pep440_rs` and `pep508_rs` were decided together or separately and why (see OQ-1). | must |
| FR-023 | WHEN user-visible behavior changes as a result of any chosen option, THE SYSTEM SHALL record it in `CHANGELOG.md` `[Unreleased]` as a one-line entry with the PR link. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | No PEP 440 or PEP 508 input within or outside the accepted grammar SHALL abort the process, in debug or release builds, including on a 2 MiB-stack thread. |
| NFR-002 | Security | The chosen engine SHALL have no open RUSTSEC advisory; `cargo deny check` and `cargo audit` SHALL pass. Error text reaching logs SHALL stay free of attacker-controlled content. |
| NFR-003 | Compatibility | The chosen engine SHALL build with `rust-version = "1.98"`, edition 2024, on all CI targets, with rustls only. |
| NFR-004 | Maintainability | The pinned requirement SHALL be declared once in root `[workspace.dependencies]` with no features, alphabetically sorted, per workspace convention. |
| NFR-005 | Consistency | Any PEP 440 comparison logic needed by more than one crate SHALL live in one shared place (`deps-core`), not be reimplemented per crate; this applies equally to a vendored subset. |
| NFR-006 | Type safety | The outcome SHALL keep illegal states unrepresentable: typed version and specifier newtypes at crate boundaries, typed `thiserror` errors, no stringly-typed version comparison, and no new catch-all `_ =>` arms on exhaustive project enums. |
| NFR-007 | Performance | Version parsing and specifier matching SHALL NOT add measurable latency to hover or completion paths relative to the current engine on the existing benchmark inputs. |
| NFR-008 | Supply chain | A replacement SHALL NOT add a dependency that fails `cargo deny check` bans or licences, and SHALL pin an exact version if the crate gives no semver compatibility promise. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| PEP 440 engine | The crate providing version and specifier types to `deps-pypi` and `deps-core` | current: `pep440_rs` 0.7.x; candidate: `uv-pep440` 0.0.x |
| Differential corpus | Shared set of version strings, specifiers, and (candidate, specifier-set) pairs | sourced from PEP 440 examples, existing deps-pypi test fixtures, `uv.lock` / `poetry.lock` samples, fuzz seeds |
| Disagreement record | One engine-vs-engine difference on one corpus entry | input, result A, result B, classification (bug A, bug B, spec ambiguity, rejected-by-one) |
| Decision record | Outcome of the gate | option, evidence table, re-evaluation triggers, follow-up issue |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Empty string, whitespace-only, or very long (over 1 MiB) version string | Typed error or bounded rejection, no panic, no quadratic blow-up |
| Version with many release segments (for example 10,000 `.0` components) | Parses or rejects in bounded time and memory |
| `~=1` (single segment) | Rejected as invalid per PEP 440, not matched |
| `==1.0.*` against `1.0.post1`, `1.0.dev1`, `1.0+local` | Wildcard prefix rules per PEP 440, identical across engines |
| `===` with a non-PEP-440 operand (for example `===foobar`) | String comparison, no panic |
| `>1.0` against `1.0.post1` and `<2.0` against `2.0.dev1` or `2.0rc1` | Exclusive-ordered rules per PEP 440 (post and pre-release exclusion) |
| Local version on both sides (`1.0+abc.5` vs `1.0+abc.10`) | Numeric segments compare numerically, alphanumeric lexically, per spec |
| Version string from a lock file with a non-canonical form (`1.0.0-rc.1`, `V1.0`) | Normalized and equal to canonical form, or rejected identically by both engines |
| Candidate engine accepts input the current one rejects (or vice versa) | Recorded as a disagreement; deps-pypi behavior for that input (diagnostic or skip) stays explicit |
| `pep508_rs` malformed-name panic (#703) | Remains guarded until the engine providing PEP 508 parsing is replaced or the upstream fix lands; replacement must not remove the guard without a proving test |
| Candidate crate yanked or its `0.0.N` pin disappears | Build breakage detected in CI; lock file keeps the pinned artifact; re-evaluation trigger |
| Network unavailable during evaluation | Evaluation uses vendored registry snapshots and local corpora; registry live checks follow the existing Registry Integration Gate |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Decision record exists with all FR-011 to FR-014 evidence for every option considered | 100% of options |
| SC-002 | Unclassified differential disagreements at the time of a "replace" decision | 0 |
| SC-003 | Panics or aborts found by fuzzing the selected engine's parse paths | 0 open |
| SC-004 | Behavior change observable in deps-pypi snapshot (insta) and integration tests caused by the decision | 0 unapproved changes |
| SC-005 | Public signatures in `deps-pypi` and `deps-core` exposing a third-party PEP 440 type after the change | 0 new exposures |
| SC-006 | Re-evaluation triggers recorded when the decision is "keep" | at least 3 concrete triggers |

## 8. Agent Boundaries

### Always (without asking)
- Verify every claim about either crate with a live scratch-crate run against the exact pinned version, not by reading code alone.
- Run the differential corpus and the fuzz targets before recommending a replacement.
- Route any shared PEP 440 logic through `deps-core`.

### Ask First
- Adding any new dependency (`uv-pep440` or others) to the workspace.
- Vendoring third-party code into the repository.
- Changing the `pep440_rs` or `pep508_rs` requirement, or `rust-version`.
- Deciding the PEP 440 and PEP 508 engines jointly rather than separately.

### Never
- Edit source code as part of the continuous-improvement research session that produced this spec.
- Remove the existing `pep508_rs` panic guard (#703) without a test proving the replacement does not panic.
- Weaken typing (stringly-typed versions, untyped maps, `_ =>` arms on exhaustive enums) to ease a migration.
- Touch files under `crates/deps-zed`.

## 9. Open Questions

> [!question] Open items (6)

- [NEEDS CLARIFICATION: OQ-1 Should `pep440_rs` and `pep508_rs` (#703) be evaluated together? `pep508_rs` 0.9.2 depends on the same author's PEP 440 types, so replacing one in isolation may force duplicate PEP 440 types or a lock-step swap (`uv-pep508` pairs with `uv-pep440`). Joint evaluation avoids an intermediate state but widens scope and risk; a staged decision keeps each reviewable. Needs a dependency-tree check (`cargo tree -i pep440_rs`) before deciding.]
- [NEEDS CLARIFICATION: OQ-2 What is the exact public API difference between `pep440_rs` 0.7.3 and `uv-pep440` 0.0.99 for the types and functions deps-lsp uses (Version, VersionSpecifiers, operators, error types)? Not yet measured; determines the FR-012 call-site count.]
- [NEEDS CLARIFICATION: OQ-3 Is `uv-pep440` published independently of `uv` releases, what is its breaking-change cadence on 0.0.x, and is an exact `=0.0.N` pin acceptable under the project's "pin in root `[workspace.dependencies]`, no features" convention?]
- [NEEDS CLARIFICATION: OQ-4 What is the `uv-pep440` MSRV, edition, and licence (and those of its transitive crates)? Workspace requires `rust-version = "1.98"`, edition 2024, and `cargo deny` licence compliance.]
- [NEEDS CLARIFICATION: OQ-5 Where does the differential corpus come from? Candidates: PEP 440 spec examples, existing deps-pypi test fixtures and fuzz seeds, version lists from a sample of PyPI packages, and lock files from real projects. Corpus size and sampling strategy are undecided.]
- [NEEDS CLARIFICATION: OQ-6 Should the decision gate also weigh keeping `pep440_rs` as-is but adding a thin typed adapter in `deps-core` now (a cheap seam making a later swap a one-crate change), independently of which engine wins? This overlaps with FR-010 and may be the lowest-risk first step.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-pypi/src/` — `types.rs`, `registry.rs`, `formatter.rs`, `error.rs` (PEP 440 / PEP 508 usage and error wrapping)
- `crates/deps-core/src/package.rs`, `crates/deps-core/src/osv/mod.rs` — other `pep440_rs` consumers
- `crates/deps-core/src/interval.rs` — precedent for a shared, generic version-range grammar kept in `deps-core` with ecosystem-specific bound parsing and comparison
- `fuzz/fuzz_targets/pypi_requirement.rs`, `fuzz/fuzz_targets/requirement_matcher.rs` — existing fuzz targets for PyPI parsing
- Upstream: `konstin/pep440-rs` README (maintenance statement, 2026-10-20); `astral-sh/uv` (`uv-pep440`); `pep508_rs` issue #703 (malformed-name panic)
- Related project history: #118 (exhaustive-enum bug class), #835 (keep pre-1.0 `pep508_rs` types out of public signatures)

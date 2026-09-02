---
aliases:
  - OSV Fix-Target Scan Gap
  - Recommended Fix Never Scanned
tags:
  - sdd
  - spec
  - bug
  - osv
  - deps-lsp
  - deps-core
created: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]]"
---

# Feature: OSV Fix-Target Scan Gap — Recommended Fix Version Is Never Independently Scanned

> [!info] Metadata
> **Author**: continuous-improvement cycle (research/architecture stream)
> **Branch**: fix/osv-fix-target-scan-gap (no issue number assigned yet — file a GitHub issue before branching)
> **Priority**: P2
> **Type**: bug

## 1. Overview

### Problem Statement

The OSV vulnerability-scan pipeline runs in two phases:

- **Phase A** (full scan) determines which dependencies have known advisories at all,
  producing `deps_core::osv::ScanOutcome::Vulnerable(DependencyVulnerabilities)` per key.
- **Phase B** (`run_osv_phase_b_and_commit` in
  `crates/deps-lsp/src/document/lifecycle.rs`, around line 552) takes every
  dependency phase A flagged vulnerable and re-checks a *single candidate
  version per dependency* against OSV: the registry's **latest** version
  (`doc.cached_versions[key].latest`, built into `ScanTarget` around line
  578). The result is written into `DependencyVulnerabilities::upgrade_status`
  as either `CandidateClean` or `CandidateVulnerable { advisory_ids, .. }`.

Independently, `DependencyVulnerabilities::recommended_fix()`
(`crates/deps-core/src/osv/types.rs`, lines 255–293) computes a
`FixRecommendation` whose `version` field (F) is the **maximum
`fixed_versions` entry across advisories not excluded by
`upgrade_status`'s `CandidateVulnerable.advisory_ids` subtraction** — i.e. the
lowest version that clears every advisory this method is willing to *claim*
as fixed. F is derived purely from advisory metadata already fetched; it is
a different value from "latest" whenever the minimal version that clears
the currently-known/claimed advisories is older than the registry's newest
release.

`crates/deps-core/src/lsp_helpers/code_actions.rs` (`generate_code_actions`,
line ~66) reads this `FixRecommendation` and offers a one-click "Update to
`{F}` (fixes `{advisory_id}`)" code action. **F itself is never submitted to
`OsvClient::check_candidates`** — only "latest" was ever checked, in phase
B, before `recommended_fix()` even ran. The code action therefore presents F
as a verified-clean fix without OSV having verified F.

This gap was known to the implementers: a
`// TODO(critic): phase B checks registry-latest only; the fix target F is
never scanned — see #216 critique D1` comment was added at
`crates/deps-lsp/src/document/lifecycle.rs:560` in the *same commit*
(PR #236, commit `c28c7e42`) that introduced `recommended_fix()`. That PR
also *closed* #216 (the issue the TODO cites), so the comment now points at
a closed issue with no live tracking artifact. A search of open issues
(`gh issue list --search`, multiple term combinations) found no separate
issue ever filed for this specific residual gap — this spec is the first
formal artifact tracking it.

### Goal

Phase B (or an equivalent verification step) scans the actual recommended
fix target F — not only the registry's "latest" — before
`generate_code_actions` presents F to the user as a verified fix. Exactly
how F gets verified (extra OSV round-trip vs. a provably-sufficient
reduction over already-fetched advisory data) is an open design question,
deferred to `/sdd plan`.

### Out of Scope

- Redesigning `recommended_fix()`'s advisory-selection/exclusion logic
  itself — this spec addresses only the fact that its output version is
  unverified, not how that version is chosen.
- Changing the code action's UX/wording beyond what's needed to reflect a
  verified-vs-unverified fix state.
- Any change to phase A (the initial full OSV scan).
- Historical vulnerability data / advisory `introduced` event tracking
  (already documented as a separate accepted limitation in
  `recommended_fix()`'s doc comment).

## 2. User Stories

### US-001: Trustworthy one-click fix

AS A developer using deps-lsp's OSV code action
I WANT the "Update to X (fixes ADVISORY-ID)" suggestion to reflect a version
that has actually been checked against OSV
SO THAT applying the suggested edit doesn't silently leave me exposed to a
different, unrelated advisory that also affects the recommended version

**Acceptance criteria:**
```
GIVEN a dependency with advisory A (fixed in 1.5.0, still affects latest
  3.0.0) and advisory B (fixed in 2.0.0, does not affect latest)
WHEN phase B / fix-target verification runs
THEN the version actually offered by the code action (F) has itself been
  checked against OSV — either via a direct check_candidates call or via a
  data-derived proof that no other known advisory applies to F
```

### US-002: No regression in phase B's existing "latest" check

AS A maintainer of the OSV pipeline
I WANT the existing "is latest still vulnerable" signal (used elsewhere,
e.g. hover, to say "latest is also affected") to keep working exactly as
today
SO THAT fixing the fix-target gap does not remove or weaken an already
correct and tested code path

**Acceptance criteria:**
```
GIVEN the current phase B behavior for the registry-latest candidate
WHEN the fix-target verification is added
THEN CandidateClean / CandidateVulnerable for the "latest" candidate is
  computed exactly as before, unchanged in cardinality or trigger conditions
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `recommended_fix()` computes a `FixRecommendation` whose `version` (F) differs from the registry's `latest` THE SYSTEM SHALL verify F against OSV (or a provably-sufficient equivalent) before `generate_code_actions` presents F to the user | must |
| FR-002 | WHEN F equals the already-scanned `latest` candidate THE SYSTEM SHALL reuse the existing phase B result for `latest` rather than issuing a redundant OSV request for the same version | should |
| FR-003 | WHEN the verification of F finds F is itself still vulnerable to an advisory not already excluded by `recommended_fix()`'s claim logic THE SYSTEM SHALL NOT present F as a fix for that excluded advisory, and SHALL update the code action / recommendation accordingly (e.g. recompute against a higher fix version, or suppress the claim) | must |
| FR-004 | WHEN the verification step is unable to complete (timeout, OSV unavailable) THE SYSTEM SHALL fall back to a documented degraded behavior (see NFR-002 / Edge Cases) rather than silently presenting an unverified F as verified | must |
| FR-005 | WHEN a dependency's declared version is edited to F via the code action THE SYSTEM SHALL continue to trigger the existing full-rescan-on-`version_changed` path (already implemented, per the mitigating factor) — this spec does not change that behavior, only tightens the pre-edit guarantee | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Verifying F must not add an unbounded number of extra OSV round-trips per document scan cycle — at most one additional `check_candidates` batch call across all vulnerable dependencies in the document, batched the same way phase B already batches the `latest` candidates |
| NFR-002 | Reliability | If F cannot be verified within the existing `fetch_timeout_secs` / `OSV_SCAN_TIMEOUT_CEILING_SECS` budget, the system must degrade to a safe, clearly-distinguishable state (e.g. mark the recommendation as unverified, or omit the code action) rather than presenting an unverified F as verified |
| NFR-003 | Correctness | The fix must close the concrete repro scenario in §"Edge Cases and Error Handling" without introducing a new false-negative (a fix presented as verified when it was not actually checked or provably covered) |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencyVulnerabilities` (existing, `crates/deps-core/src/osv/types.rs`) | Per-dependency vulnerability state after phase A/B | `advisories`, `total_known`, `upgrade_status` |
| `UpgradeStatus` (existing) | Result of checking one candidate version against OSV | `NotChecked`, `CandidateClean { version }`, `CandidateVulnerable { version, advisory_ids }` — currently populated only for the "latest" candidate |
| `FixRecommendation` (existing) | Computed recommendation surfaced to the code action | `version` (F), `advisory_ids` — currently computed without F itself ever being scanned |
| `ScanTarget` (existing, `deps_core::osv`) | Input to `OsvClient::check_candidates` | `key`, `osv_name`, `version`, `display_version` — phase B currently builds these only from `latest` |
| *(new, shape TBD)* Fix-target verification result | Whatever `DependencyVulnerabilities` needs to record "F was checked / F is clean / F is still vulnerable to {ids}" so `generate_code_actions` can read it | `[NEEDS CLARIFICATION: does this reuse `UpgradeStatus` with a second variant/field, or is a separate field needed alongside `upgrade_status` since F and latest are two distinct candidates that can both need a stored verification result?]` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| F == latest (the common case) | No extra OSV call — reuse the existing phase B result for `latest` (FR-002) |
| F < latest, F itself is clean against all known advisories | Code action presents F as verified-clean, using the new verification path |
| F < latest, F is still vulnerable to an advisory C not covered by the phase-A advisory set considered in `recommended_fix()`'s exclusion (the repro scenario: advisory C fixed only in 2.1.0, F=2.0.0) | System must not claim F as a clean fix for advisories excluded solely because they don't affect *latest* — either bump the recommendation to the version that clears C too, or explicitly surface C in the code action / suppress it until resolved |
| OSV request for F times out or fails | Fall back per NFR-002 — do not silently present F as verified; degrade to omitting the extra guarantee or the whole code action, per implementation-time decision |
| F cannot be parsed / is not a valid version in the target ecosystem's version scheme | Skip verification for that dependency, log at `debug`/`warn`, do not crash the scan |
| Advisory data for F is only partially known due to `ADVISORY_DISPLAY_CAP` truncation (already-documented limitation of `recommended_fix()`) | Verification of F should be understood as best-effort within the same accepted incompleteness — no additional guarantee beyond what phase A's advisory fetch already provides |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Fix targets (F) that differ from `latest` and get verified before being offered by the code action | 100% (no F is presented as a fix without being scanned or provably covered) |
| SC-002 | Additional OSV round-trips introduced per document scan when F == latest | 0 (reuse existing `latest` result, per FR-002) |
| SC-003 | Live-tester follow-up (see Reproduction in Description) confirms the repro scenario no longer surfaces an unverified fix recommendation | Reproduced scenario passes after fix |

## 8. Agent Boundaries

### Always (without asking)
- Read `crates/deps-core/src/osv/types.rs` and
  `crates/deps-lsp/src/document/lifecycle.rs` in full before editing —
  `DependencyVulnerabilities`, `UpgradeStatus`, and `run_osv_phase_b_and_commit`
  all carry dense doc-comment context (critique references M4, S1, D1) that
  must not be silently dropped
- Preserve the existing "latest" phase B behavior (US-002) — add
  verification for F alongside it, not instead of it
- Update or remove the now-orphaned `// TODO(critic): ... see #216 critique
  D1` comment once this gap is tracked by a live issue/PR
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest, rustdoc
  gate) per project convention before any PR

### Ask First
- Whether to extend `UpgradeStatus` with a new variant/field vs. adding a
  parallel field to `DependencyVulnerabilities` for F's verification result
  (data model open question above)
- Whether verifying F should always cost one extra OSV batch call, or
  whether an interval-safe reduction over already-fetched advisory data can
  substitute for it in the common case (the core open design question this
  spec defers to `/sdd plan`)

### Never
- Silently drop the mitigating factor (post-edit full rescan on
  `version_changed`) — that path must keep working exactly as today
  regardless of how this gap is closed
- File this as fixed without a live-tester (or equivalent) empirical
  verification against a real OSV-affected package, per the project's
  Live Testing Principle (`.claude/rules/continuous-improvement.md`) — this
  finding was code-reading-only and explicitly flagged for live-test
  follow-up

## 9. Open Questions

- [NEEDS CLARIFICATION: Should F be verified via an additional direct `OsvClient::check_candidates` call, or can it be proven safe using only already-fetched advisory data (e.g. by checking whether every known advisory's `fixed_versions` is `<= F`, making a network round-trip unnecessary in the common case)? This is the central design trade-off deferred to `/sdd plan`.]
- [NEEDS CLARIFICATION: When F differs from `latest`, should the two candidates (F and `latest`) share one `ScanTarget`/`check_candidates` batch call, or does the existing phase B call site need to grow a second, separate candidate list? Affects NFR-001's batching requirement.]
- [NEEDS CLARIFICATION: What is the desired code-action UX when F cannot be verified before display (timeout/failure per NFR-002) — omit the code action entirely for that dependency, show it with a "unverified" qualifier in the title, or defer showing it until the next scan cycle?]
- [NEEDS CLARIFICATION: Should a GitHub issue be filed for this finding (with `bug` + `P2` labels, referencing this spec) before implementation starts, per the project's continuous-improvement workflow? No issue currently exists — this spec was requested to be produced first.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]] — the original feature spec this bug was found within
- `crates/deps-lsp/src/document/lifecycle.rs` — `run_osv_phase_b_and_commit`, the orphaned TODO at line ~560
- `crates/deps-core/src/osv/types.rs` — `DependencyVulnerabilities::recommended_fix`, `FixRecommendation`, `UpgradeStatus`
- `crates/deps-core/src/lsp_helpers/code_actions.rs` — `generate_code_actions`, the consumer of `recommended_fix()`
- PR #236, commit `c28c7e42` — introduced `recommended_fix()` and the now-orphaned TODO; closed issue #216

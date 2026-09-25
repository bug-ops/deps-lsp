---
aliases:
  - deps.dev GOSSIP Signals
  - Google Open Source Security Intelligence Platform Signals
tags:
  - sdd
  - spec
  - research
  - security
  - deps-dev
  - priority/p3
created: 2026-09-25
status: ready
related:
  - "[[MOC-specs]]"
  - "[[002-osv-vulnerability-diagnostics/spec]]"
  - "[[004-release-freshness-signal/spec]]"
  - "[[037-supply-chain-trust-signal/spec]]"
  - "[[049-osv-malicious-package-severity/spec]]"
  - "[[071-typosquat-similarity-diagnostic/spec]]"
  - "[[011-deprecation-replacement-diagnostics/spec]]"
---

# Feature: Adopt deps.dev GOSSIP signals (Google Open Source Security Intelligence Platform)

> [!info] Metadata
> **Author**: continuous-improvement research cycle ci-086, researcher stream (2026-09-25)
> **Branch**: none yet — research/spec-only, no implementation branch
> **Type**: research (capability-gap assessment). Prioritized out of triage order (issue #1456 was next in
> the priority queue) and progressed to `/sdd plan` readiness on 2026-09-25 after live-API research and
> maintainer decisions resolved all `[NEEDS CLARIFICATION]` items (§9) — see §7

## 1. Overview

### Problem Statement

`deps-lsp` already integrates deps.dev (Google's cross-ecosystem package-metadata API) for two distinct
purposes: license/OpenSSF-Scorecard/SLSA-provenance supply-chain trust signals
([[037-supply-chain-trust-signal/spec|#037]], issue #543) and, most recently, typosquat-similarity
detection via `GetSimilarlyNamedPackages` ([[071-typosquat-similarity-diagnostic/spec|#071]], PR #1451,
shipped 2026-09-25). deps.dev published a blog post on 2026-06-09 announcing "GOSSIP signals" (Google
Open Source Security Intelligence Platform,
[https://blog.deps.dev/gossip/](https://blog.deps.dev/gossip/)) — a new API capability layer exposing five
authoritative, per-package-version security indicators computed centrally by Google rather than by
individual consumers:

1. **Dynamic Cooldown** — an authoritative, per-ecosystem/per-vulnerability-status holding-period
   recommendation for new releases, with expedited cooldown for `PATCH_VERSION` security fixes.
2. **Malicious Packages** — flags sourced from the OSSF Malicious Packages Project.
3. **Critical Vulnerabilities** — marks a version `VULNERABLE` for critical security gaps.
4. **Low-Usage Packages** — flags suspiciously low-usage packages, explicitly citing "slopsquatting"
   (malicious registration of LLM-hallucinated package names) as the motivating risk.
5. **Archived Packages** — flags packages whose upstream repository has been archived.

No existing deps-lsp issue, spec, or code references "GOSSIP" — verified this cycle via
`gh issue list --search "gossip"` (zero results) and `grep -ri gossip crates/` (zero results). This is a
genuinely new, previously unassessed research finding, distinct from spec 071's `GetSimilarlyNamedPackages`
work: GOSSIP's "Low-Usage Packages" signal flags a package on its own low-adoption signal, independent of
name similarity to any other package, whereas spec 071 flags a package for being *similar to* a more
popular one. These are complementary but non-overlapping attack-surface detectors — slopsquatting
(LLM-hallucinated names with no real-world antecedent) is not name-similarity typosquatting.

Two of the five signals plausibly overlap with capability deps-lsp already has, from a different data
source:

- **Dynamic Cooldown** overlaps with `crates/deps-core/src/freshness.rs`'s existing release-cooldown
  heuristic ([[004-release-freshness-signal/spec|#004]], issue #145), which mirrors GitHub Dependabot's
  default fixed 3-day window rather than sourcing a per-package, per-vulnerability-status recommendation
  from any upstream authority.
- **Critical Vulnerabilities** overlaps with existing OSV.dev-sourced vulnerability diagnostics
  ([[002-osv-vulnerability-diagnostics/spec|#002]]).
- **Malicious Packages** overlaps with existing OSV.dev MAL-* advisory severity handling
  ([[049-osv-malicious-package-severity/spec|#049]], issue #646), sourced directly from OSV.dev rather
  than GOSSIP.
- **Archived Packages** likely overlaps with deps.dev's own existing `isDeprecated` /
  `deprecatedReason` fields already consumed by the deprecation/abandoned-package diagnostic
  ([[011-deprecation-replacement-diagnostics/spec|#011]], issue #205).

Only **Low-Usage Packages / slopsquatting detection** is unambiguously net-new capability with no existing
deps-lsp equivalent.

### Goal

Determine, per-signal, whether GOSSIP represents (a) net-new capability deps-lsp should acquire, (b) an
opportunity to replace an existing bespoke/local heuristic with an authoritative upstream signal, or (c)
redundant coverage of something deps-lsp already detects via a different source. Resolved (§7): adopt
Dynamic Cooldown (replacing `freshness.rs`) and Low-Usage Packages; defer Malicious/Critical-Vulnerabilities;
treat Archived Packages as already covered. The HOW of integrating the two adopted signals is `plan.md`'s
job, not this spec's.

### Out of Scope

- Any implementation code — this spec (Phase 1) remains WHAT/WHY; `crates/deps-core::deps_dev` API-client
  wiring belongs to `plan.md`/`tasks.md`.
- Any UI/UX design for how a GOSSIP-sourced diagnostic or hover note would be worded or severity-ranked —
  left to the plan phase.
- The Malicious Packages / Critical Vulnerabilities signals — explicitly deferred (§7, §9), not part of
  this spec's adopted scope.

## 2. User Stories

### US-001: Slopsquatting protection for a declared dependency

AS A developer adding a new dependency to my project
I WANT deps-lsp to warn me if the package I just typed has suspiciously low real-world usage
SO THAT I don't unknowingly pull in an LLM-hallucinated or newly-squatted package name that an AI coding
assistant suggested to me and that I never independently verified

**Acceptance criteria:**
```
GIVEN a manifest declares a dependency whose package name has very low download/usage volume
  AND deps.dev's GOSSIP Low-Usage Packages signal flags that package version
WHEN the LSP server generates diagnostics or hover content for that dependency
THEN the user sees a low-severity, non-blocking signal distinguishing this from a known-vulnerable
  or known-malicious package, inviting them to double-check the package identity
```

### US-002: Authoritative cooldown recommendation

AS A developer relying on deps-lsp's freshness/cooldown diagnostic to avoid adopting a
just-published, not-yet-vetted release
I WANT the cooldown window to reflect an authoritative, per-package-context recommendation rather than a
fixed 3-day heuristic
SO THAT I get a more accurate signal for both routine releases and expedited security-patch releases

**Acceptance criteria:**
```
GIVEN a package has a newly published version within the last N days
  AND deps.dev's GOSSIP Dynamic Cooldown signal recommends a holding period for that version
WHEN deps-lsp evaluates whether to surface a "wait before adopting" hint
THEN the hint reflects the authoritative recommendation (or, if `freshness.rs`'s heuristic is retained
  alongside it, the two do not silently disagree without explanation)
```

### US-003: Cross-referenced malicious/critical-vulnerability coverage

AS A deps-lsp maintainer
I WANT to know whether GOSSIP's Malicious Packages and Critical Vulnerabilities signals catch anything
OSV.dev's existing MAL-* records and vulnerability diagnostics miss
SO THAT I can decide whether adding GOSSIP as a second signal source for these two categories is
worthwhile engineering effort or redundant

**Acceptance criteria:**
```
GIVEN a corpus of known-malicious and known-critical-vulnerability packages already detected via OSV.dev
WHEN the same corpus is checked against GOSSIP's equivalent signals (in a future plan-phase investigation)
THEN a coverage-gap analysis exists showing overlap vs. GOSSIP-only vs. OSV-only detections
```

## 3. Functional Requirements

These are research-finding-stage requirements — they describe what a future implementation would need to
satisfy, contingent on the `[NEEDS CLARIFICATION]` items in §9 being resolved first.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a future plan phase adopts GOSSIP's Low-Usage Packages signal THE SYSTEM SHALL surface it as a distinct, low-severity signal from existing typosquat-similarity ([[071-typosquat-similarity-diagnostic/spec\|#071]]) and vulnerability diagnostics, not merged into either | must (if adopted) |
| FR-002 | WHEN a future plan phase adopts GOSSIP's Dynamic Cooldown signal THE SYSTEM SHALL document explicitly whether it replaces or augments `freshness.rs`'s existing heuristic, and SHALL NOT silently present two disagreeing cooldown windows to the user without explanation | must (if adopted) |
| FR-003 | Malicious Packages / Critical Vulnerabilities cross-reference — **not adopted** per §9's maintainer decision (2026-09-25); deferred to a separate `research`-labeled coverage-gap issue. If ever revisited, THE SYSTEM SHALL treat OSV.dev as authoritative on any disagreement, per §9's precedence rule | deferred |
| FR-004 | WHEN GOSSIP is unavailable for a given ecosystem (per §9's system-coverage question) THE SYSTEM SHALL degrade gracefully with no user-visible error, consistent with existing deps.dev integration behavior for the 7 unsupported ecosystems in [[037-supply-chain-trust-signal/spec\|#037]] | must (if adopted) |
| FR-005 | WHEN adding the GOSSIP `GetFindings` call THE SYSTEM SHALL place it on either the hover-synchronous path (bounded by its own timeout constant, mirroring `DEPS_DEV_CALL_TIMEOUT = 400ms`) or a decoupled background-prefetch path (mirroring `TYPOSQUAT_CALL_TIMEOUT = 3s`), explicitly choosing per FR-006/FR-007 below rather than assuming a shared multi-call budget that does not exist in the current architecture (corrected §9 finding) | must (if adopted) |
| FR-006 | WHEN GOSSIP's Dynamic Cooldown replaces `freshness.rs` at the completion call site (`crates/deps-core/src/completion.rs`) THE SYSTEM SHALL do so through a dedicated prefetch/cache layer (design deferred to `plan.md`) so that no completion request issues a live network call per candidate item — a per-package memoized/background-warmed cache, not a synchronous per-item fetch | must |
| FR-007 | WHEN GOSSIP's Dynamic Cooldown is adopted THE SYSTEM SHALL remove the existing `deps-lsp` user-facing `freshness.cooldown_secs` config override (maintainer decision, 2026-09-25: GOSSIP's authority supersedes a user-adjustable window) and document the removal as a breaking change in `CHANGELOG.md` with a migration note | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | A GOSSIP call on the hover-synchronous path must not increase hover p95 latency beyond a dedicated timeout budget for that call (existing `DEPS_DEV_WAIT_BUDGET`/`DEPS_DEV_CALL_TIMEOUT` bound only the pre-existing `trust_signal` chain, not GOSSIP — corrected §9 finding). Completion must incur zero added *per-request* latency — served from the FR-006 prefetch/cache layer, never a synchronous fetch inside the completion handler |
| NFR-002 | Reliability | GOSSIP unavailability (rate limit, timeout, unsupported ecosystem, API not GA) must degrade to no-signal, never to a blocking error or stale/incorrect diagnostic |
| NFR-003 | Maintainability | If GOSSIP's Dynamic Cooldown replaces `freshness.rs`'s local heuristic, the replacement should reduce — not add to — the total amount of bespoke cooldown logic maintained in-repo |
| NFR-004 | Accuracy | Any GOSSIP-sourced signal presented to the user must be attributable (e.g. in hover text) to deps.dev/GOSSIP as its source, consistent with how Scorecard/SLSA signals are already attributed per [[037-supply-chain-trust-signal/spec\|#037]] |

## 5. Data Model

Confirmed against the live `v3alpha` API (`docs.deps.dev/api/v3alpha/#getfindings`) and verified with real
requests to `api.deps.dev` during this plan-phase research (2026-09-25) — no longer provisional:

- **Endpoints**: `GET /v3alpha/systems/{system}/packages/{name}:findings` (package-scoped, all versions) and
  `GET /v3alpha/systems/{system}/packages/{name}/versions/{version}:findings` (version-scoped). A batch
  variant (`GetFindingsBatch`) exists, capped at 5000 items per batch.
- **Response shape**: `recommendedVersions[]` (low-risk version suggestions, each with its own `findings[]`
  and `cooldownEnd`), `requestedVersion` (findings for the version actually asked about — version-scoped
  calls only), `defaultVersion`, `packageFindings[]` (package-wide, not version-specific).
- **Finding.type** enum (observed + documented): `NOT_FOUND`, `MALICIOUS`, `DEPRECATED`, `COOLDOWN`,
  `LOW_USAGE`, `VULNERABLE`, `REMEDIATION`.
- **Finding.risk** enum: `RISK_CRITICAL`, `RISK_HIGH`, `RISK_MEDIUM`, `RISK_LOW`, `RISK_INFORMATIONAL`.
- **Context objects** (populated per finding type): `deprecatedContext.reason`, `cooldownContext`,
  `lowUsageContext` (exact sub-fields for the latter two not yet observed live — no active-cooldown or
  low-usage finding was hit in this session's sampling; see empirical notes below).

**Empirical notes from live testing** (`npm/lodash`, `npm/request`, `npm/left-pad`, `npm/chalk@5.3.0/5.3.1`,
`npm/debug@4.4.2`, `npm/ua-parser-js@0.7.29`, `pypi/requests@2.31.0`, `cargo/serde@1.0.195`):
- `npm/request@2.88.2` and `npm/left-pad@1.3.0` correctly return a `DEPRECATED` finding
  (`RISK_MEDIUM`) with a human-readable `deprecatedContext.reason` — confirms viability for
  [[011-deprecation-replacement-diagnostics/spec|#011]]'s overlap question.
- Every non-latest version checked (`lodash@4.17.21`, `chalk@5.3.0`) returns `REMEDIATION`/`RISK_INFORMATIONAL`
  on its recommended-version entry, not a cooldown-specific finding — consistent with `cooldownEnd` dates
  already in the past for all versions sampled (no currently-active cooldown was captured live).
- Versions known to have been part of real npm supply-chain-compromise incidents but since unpublished/pulled
  from the registry (`ua-parser-js@0.7.29`, the October 2021 compromise; `debug@4.4.2`, the September 2025
  chalk/debug phishing-worm incident) both returned **`NOT_FOUND` / `RISK_CRITICAL`** for `requestedVersion`,
  not a `MALICIOUS` finding. No live `MALICIOUS` finding was captured in this session — either GOSSIP only
  flags `MALICIOUS` for versions still resolvable in its index (an unpublished version collapses to
  `NOT_FOUND` instead), or the specific incidents sampled predate/postdate GOSSIP's malicious-package feed
  coverage window. This directly bears on FR-003 (see §9, updated).

| Entity | Description | Key Attributes (confirmed) |
|--------|-------------|----------------|
| Finding | One flagged condition for a package/version | `type` (enum above), `risk` (enum above), optional type-specific context object |
| Findings response | Per-package or per-version bundle | `recommendedVersions[]`, `requestedVersion`, `defaultVersion`, `packageFindings[]`, each carrying `findings[]` and `cooldownEnd` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GOSSIP flags a package as low-usage that is a legitimate new/niche package (false positive) | RESOLVED (§9): surface the raw `LOW_USAGE` finding as-is, worded as a non-blocking, low-severity invitation to double-check package identity — no corroborating-signal gate built |
| deps.dev API returns GOSSIP data for an ecosystem not yet confirmed to be covered | RESOLVED (§9): all 7 `deps_dev_system()` ecosystems (GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET) confirmed covered by live testing — no coverage gap |
| GOSSIP and OSV.dev disagree on whether a package is malicious | Not currently reachable: FR-003 defers Malicious/Critical-Vulnerabilities adoption entirely (§9). If a future coverage-gap study reverses that decision, OSV.dev is authoritative per §9's precedence rule |
| GOSSIP and `freshness.rs` disagree on cooldown window for the same release | Not reachable: RESOLVED (§9) as full replacement of `freshness.rs`'s heuristic — there is only one cooldown source after adoption, so no disagreement case exists |
| GOSSIP API is still in preview/alpha status (unstable schema) | RESOLVED (§9): confirmed still `v3alpha`, no GA designation found. Follow the same provisional-integration posture spec 071 adopted for `GetSimilarlyNamedPackages` |

## 7. Success Criteria

Met (2026-09-25): all `[NEEDS CLARIFICATION]` items in §9 are resolved — four via live-API research this
session (system coverage, GA status, response schema, latency), three via explicit maintainer decision
(cooldown replacement, malicious/critical-vuln deferral, low-usage false-positive handling). Net adoption
scope narrowed from "5 signals, all open" to:

- **Adopt**: Dynamic Cooldown at all 5 `freshness.rs` call sites — hover, diagnostics, code_lenses,
  code_actions, and completion via a new dedicated prefetch/cache layer (FR-006) — plus
  Low-Usage/slopsquatting (raw flag, soft wording). `freshness.cooldown_secs` config option removed as a
  breaking change (FR-007).
- **Defer to separate research issue**: Malicious Packages, Critical Vulnerabilities (coverage-gap study
  needed first).
- **No action** (redundant with existing signal, not re-litigated this session): Archived Packages —
  original overlap analysis with `isDeprecated`/`deprecatedReason` ([[011-deprecation-replacement-diagnostics/spec|#011]])
  stands; this session's live testing incidentally confirmed GOSSIP's own `DEPRECATED` finding type
  (`npm/request`, `npm/left-pad`) carries the same information deps.dev's `isDeprecated` field already
  provides, reinforcing that no new signal is needed here.

Ready for `/sdd plan` on the two adopted signals (Dynamic Cooldown, Low-Usage).

## 8. Agent Boundaries

### Always (without asking)
- Treat this as a specify-only artifact; do not begin implementation from this spec alone — `/sdd plan` is
  the next phase, not direct code changes.
- Cross-reference specs 002, 004, 037, 049, 071, and 011 during the plan phase, since GOSSIP overlaps with
  all of them to varying degrees.

### Ask First (resolved this session — recorded for audit trail)
- ~~Before running `/sdd plan` on this spec, confirm the `[NEEDS CLARIFICATION]` items in §9 have been
  investigated against deps.dev's actual API reference (not just the blog announcement).~~ Done: live
  `api.deps.dev` testing this session (§5, §9).
- ~~Before deciding to replace `freshness.rs`'s cooldown heuristic outright, confirm with a maintainer given
  it is user-facing behavior with an existing spec/issue history (#145 and its four follow-on PRs per
  [[004-release-freshness-signal/spec|#004]]).~~ Done: maintainer confirmed full replacement (§9).

### Never
- Do not implement any GOSSIP API client or wire it into `crates/deps-core` from this spec directly —
  research/parity findings at P3 require `specify` only per this project's threshold rules.
- Do not remove or modify `freshness.rs`, OSV.dev integration, or spec 071's typosquat-similarity code as
  a side effect of filing this research spec.

## 9. Open Questions

Resolved this session against the live API (2026-09-25):

- **System coverage — RESOLVED**: `GetFindings`/`GetFindingsBatch` accept `packageKey.system` /
  `versionKey.system` values `GO`, `RUBYGEMS`, `NPM`, `CARGO`, `MAVEN`, `PYPI`, `NUGET` — the same 7 systems
  spec 037/071 already integrate against. Live-verified with successful 200 responses for `npm`, `pypi`, and
  `cargo` package/version queries. No system-coverage gap relative to the existing `deps_dev_system()` set.
- **GA status — RESOLVED**: still `v3alpha` (`docs.deps.dev/api/v3alpha/#getfindings`); no GA designation
  found in the API reference. Same provisional-integration posture as spec 071's `GetSimilarlyNamedPackages`
  applies (FR-004/NFR-002's graceful-degradation requirement is unchanged).
- **Response schema — RESOLVED**: see §5's confirmed data model, live-verified with 8 real requests across
  3 ecosystems.
- **Latency — RESOLVED, but the spec's own framing was wrong**: isolated single-call latency measured at
  170–350ms per request across npm/pypi/cargo (5 samples). Plan-phase codebase research
  (`crates/deps-core/src/lsp_helpers/hover.rs`, `crates/deps-core/src/deps_dev/mod.rs`) corrected this
  spec's original assumption: `DEPS_DEV_WAIT_BUDGET` (700ms, `hover.rs:39`) bounds **only** the
  `trust_signal` (license/Scorecard/SLSA) call chain on the synchronous hover path. Spec 071's
  typosquat-similarity call is **not** on that path at all — it runs from a decoupled background
  document-lifecycle prefetch (`deps-lsp::document::osv_scan::run_typosquat_prefetch`), confirmed by
  `deps_dev/mod.rs`'s own doc comment. There is no existing "5 concurrent calls sharing one budget" to slot
  a 6th into. GOSSIP's `GetFindings` call needs its own placement decision (hover-path with its own timeout,
  mirroring `DEPS_DEV_CALL_TIMEOUT = 400ms`, vs. background-prefetch like typosquat, mirroring
  `TYPOSQUAT_CALL_TIMEOUT = 3s`) — this is now a `plan.md` design decision, not something FR-005's original
  wording (which assumed a shared 6-way budget) correctly described. FR-005 is corrected below.
- **NEW empirical finding — not one of the original 9 items, but consequential enough to record here**:
  `freshness.rs`'s `is_within_cooldown`/`PublishTime` are pure, synchronous, zero-network-cost functions
  (the cooldown timestamp already rides along on data the ecosystem registry client already fetched). They
  are called from **5 distinct call sites**: hover (`hover.rs:596`), diagnostics (`hover.rs:2262`, per
  declared dependency), code_lenses, code_actions, **and completion**
  (`crates/deps-core/src/completion.rs:1154-1802`, per candidate item — the most latency-sensitive LSP
  surface in the project). A literal full replacement with GOSSIP's `GetFindings` (a ~200-350ms network
  call) would turn every one of those free call sites into a network call — for completion specifically,
  one network call per candidate item, which is very unlikely to be viable without a dedicated
  prefetch/cache layer completion doesn't currently have. **This materially affects the "replace
  `freshness.rs` entirely" maintainer decision recorded above** — see the follow-up question posed to the
  maintainer after this table, since resolving it fully requires their input, not further research.

Resolved by maintainer decision this session (2026-09-25), per §8's Agent Boundaries "Ask First" gate:

- **Dynamic Cooldown — RESOLVED: replace `freshness.rs` entirely at all 5 call sites**, confirmed by
  maintainer after plan-phase code research surfaced the completion-call-site network-cost problem (see
  the new finding above). `freshness.rs`'s `is_within_cooldown`/`PublishTime` are zero-cost synchronous
  functions called from hover, diagnostics, code_lenses, code_actions, and completion (per candidate item).
  The first 4 absorb an async GOSSIP-backed call the way `trust_signal` already does (FR-005). Completion
  requires a **dedicated prefetch/cache layer** (FR-006) — its design (per-package memoization warmed
  ahead of the completion request, not a synchronous per-candidate-item fetch) is now explicitly in scope
  for `plan.md`, not deferred further. This is the single largest design surface in the plan phase for this
  feature. Separately, `deps-lsp`'s existing user-facing `freshness.cooldown_secs` config option
  (`server.rs`, confirmed live via `did_change_configuration` tests) is **removed** (maintainer decision,
  FR-007) — document as a breaking change in `CHANGELOG.md` with a migration note (users lose the ability
  to widen/narrow the cooldown window locally; GOSSIP's authoritative value is now the sole source). The
  existing heuristic's multi-PR history (#145, #219, #220, #221, #222, #225, #277, #293, #294, #316) is the
  removal surface for all 5 call sites.
- **Malicious Packages / Critical Vulnerabilities cross-reference — RESOLVED: defer to a separate research
  issue, not adopted in this spec's scope.** Maintainer decision: this session's empirical finding (both
  `ua-parser-js@0.7.29` and `debug@4.4.2` — real, well-documented compromised npm versions — returned
  `NOT_FOUND`/`RISK_CRITICAL` rather than `MALICIOUS`) is not conclusive enough to justify the engineering
  cost without a proper coverage-gap study on a corpus of *currently live* (not retroactively unpublished)
  malicious packages. File a follow-up `research` issue for that dedicated coverage-gap comparison; this
  spec's FR-003 is downgraded from "should (if adopted)" to **not adopted** for now.
  - **If a future coverage-gap study does justify adoption**, the maintainer-set precedence rule is:
    **OSV.dev takes priority** on any GOSSIP/OSV.dev disagreement over malicious or vulnerable status — OSV.dev
    remains the source of record for specs 002 and 049; GOSSIP would only ever add signal, never override or
    downgrade an existing OSV.dev-sourced diagnostic.
- **Low-Usage Packages / slopsquatting false-positive handling — RESOLVED: raw flag with soft wording, no
  corroborating-signal gate.** Maintainer decision: surface GOSSIP's `LOW_USAGE` finding as-is, worded as a
  non-blocking, low-severity invitation to double-check the package identity (per US-001's acceptance
  criteria) rather than building additional age/download-count heuristics to suppress it. This keeps FR-001
  simple — no new `deps-core` corroboration logic needed beyond what already exists for severity/attribution
  formatting.

## 10. See Also

- [GOSSIP signals announcement](https://blog.deps.dev/gossip/) — Google's deps.dev blog post, published
  2026-06-09, source of this finding
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec]] — existing OSV.dev vulnerability diagnostic, overlaps with
  GOSSIP's Critical Vulnerabilities signal
- [[004-release-freshness-signal/spec]] — existing local cooldown heuristic in `freshness.rs`, candidate
  for replacement/augmentation by GOSSIP's Dynamic Cooldown signal
- [[037-supply-chain-trust-signal/spec]] — existing deps.dev integration pattern (license/Scorecard/SLSA),
  including the `DEPS_DEV_WAIT_BUDGET` latency-budget pattern this feature would need to respect
- [[049-osv-malicious-package-severity/spec]] — existing OSV.dev MAL-* malicious-package handling,
  overlaps with GOSSIP's Malicious Packages signal
- [[071-typosquat-similarity-diagnostic/spec]] — most recent deps.dev integration (`GetSimilarlyNamedPackages`,
  PR #1451), the closest prior art for how to evaluate and scope a new deps.dev signal, and the spec that
  establishes the name-similarity vs. low-usage/slopsquatting distinction this spec relies on
- [[011-deprecation-replacement-diagnostics/spec]] — existing deprecation diagnostic, overlaps with
  GOSSIP's Archived Packages signal

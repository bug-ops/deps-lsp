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
status: draft
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
> **Type**: research (capability-gap assessment; specify-only per this project's SDD threshold for
> research/parity findings — no `/sdd plan` in this cycle)

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
redundant coverage of something deps-lsp already detects via a different source — and capture open design
questions for a future `/sdd plan` to resolve, without designing the integration itself in this spec.

### Out of Scope

- Any implementation code, API client design, or wiring into `crates/deps-core::deps_dev` — this is
  specify-only.
- A `/sdd plan` phase — per the project's `.claude/rules/specs.md` and `continuous-improvement.md`
  threshold rules, a research/parity finding of this priority (P3) only requires `specify`; `plan` is
  deferred until (if) this is prioritized for implementation.
- Deciding the final per-signal adopt/reject disposition — that is exactly what the
  `[NEEDS CLARIFICATION]` items in §9 defer to plan-phase investigation.
- Any UI/UX design for how a GOSSIP-sourced diagnostic or hover note would be worded or severity-ranked.

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
| FR-003 | WHEN a future plan phase adopts GOSSIP's Malicious Packages or Critical Vulnerabilities signals THE SYSTEM SHALL cross-reference them against existing OSV.dev-sourced results before deciding whether to surface both sources or deduplicate | should (if adopted) |
| FR-004 | WHEN GOSSIP is unavailable for a given ecosystem (per §9's system-coverage question) THE SYSTEM SHALL degrade gracefully with no user-visible error, consistent with existing deps.dev integration behavior for the 7 unsupported ecosystems in [[037-supply-chain-trust-signal/spec\|#037]] | must (if adopted) |
| FR-005 | WHEN adding any GOSSIP API call to the existing concurrent hover/diagnostic deps.dev fetch set THE SYSTEM SHALL respect the existing `DEPS_DEV_WAIT_BUDGET` latency-budget pattern established in [[037-supply-chain-trust-signal/spec\|#037]] §8, rather than adding an unbounded sixth call | must (if adopted) |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | A GOSSIP call must not increase hover/diagnostic p95 latency beyond what the existing `DEPS_DEV_WAIT_BUDGET` already bounds for concurrent deps.dev calls (license, Scorecard, SLSA, typosquat-similarity) |
| NFR-002 | Reliability | GOSSIP unavailability (rate limit, timeout, unsupported ecosystem, API not GA) must degrade to no-signal, never to a blocking error or stale/incorrect diagnostic |
| NFR-003 | Maintainability | If GOSSIP's Dynamic Cooldown replaces `freshness.rs`'s local heuristic, the replacement should reduce — not add to — the total amount of bespoke cooldown logic maintained in-repo |
| NFR-004 | Accuracy | Any GOSSIP-sourced signal presented to the user must be attributable (e.g. in hover text) to deps.dev/GOSSIP as its source, consistent with how Scorecard/SLSA signals are already attributed per [[037-supply-chain-trust-signal/spec\|#037]] |

## 5. Data Model

[NEEDS CLARIFICATION: exact GOSSIP response schema — the blog post references deps.dev's technical
documentation and the `google/deps.dev` GitHub repo for integration details, but this cycle's research was
limited to the blog announcement itself; the plan phase must fetch and read the actual API reference
(analogous to how spec 071 cited `docs.deps.dev/api/v3alpha/` directly) before any data-model definition
is possible.]

| Entity | Description | Key Attributes (provisional, pending API reference) |
|--------|-------------|----------------|
| GOSSIP Signal Result | Per-package-version security indicator bundle | package system, package name, version, cooldown recommendation, malicious flag, critical-vulnerability flag, low-usage flag, archived flag |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GOSSIP flags a package as low-usage that is a legitimate new/niche package (false positive) | [NEEDS CLARIFICATION: what threshold or corroborating signal avoids noisy false positives on legitimate low-adoption packages — same class of concern spec 071 raised for typosquat-similarity false positives on intentionally-similar package families] |
| deps.dev API returns GOSSIP data for an ecosystem not yet confirmed to be covered | System must not assume all 7 existing `deps_dev_system()` ecosystems are covered by GOSSIP without verifying against the API reference (see §9) |
| GOSSIP and OSV.dev disagree on whether a package is malicious | [NEEDS CLARIFICATION: precedence rule between the two sources, or dual-display with both attributions] |
| GOSSIP and `freshness.rs` disagree on cooldown window for the same release | [NEEDS CLARIFICATION: precedence rule — see FR-002] |
| GOSSIP API is still in preview/alpha status (unstable schema) | Follow the same provisional-integration posture spec 071 adopted for `GetSimilarlyNamedPackages`'s v3alpha status, pending confirmation of GOSSIP's actual API maturity level (see §9) |

## 7. Success Criteria

Not applicable at specify-only stage for a research finding — no implementation is being measured yet.
Success for this spec is: all five `[NEEDS CLARIFICATION]` items in §9 are answered with confidence
sufficient to proceed to `/sdd plan`, OR a documented decision that GOSSIP adoption is not currently
worthwhile (mirroring spec 001's and spec 053's decision-record pattern for a "researched, decided not to
proceed" outcome).

## 8. Agent Boundaries

### Always (without asking)
- Treat this as a specify-only artifact; do not begin implementation from this spec alone.
- Cross-reference specs 002, 004, 037, 049, 071, and 011 before any future plan phase, since GOSSIP
  overlaps with all of them to varying degrees.

### Ask First
- Before running `/sdd plan` on this spec, confirm the `[NEEDS CLARIFICATION]` items in §9 have been
  investigated against deps.dev's actual API reference (not just the blog announcement).
- Before deciding to replace `freshness.rs`'s cooldown heuristic outright, confirm with a maintainer given
  it is user-facing behavior with an existing spec/issue history (#145 and its four follow-on PRs per
  [[004-release-freshness-signal/spec|#004]]).

### Never
- Do not implement any GOSSIP API client or wire it into `crates/deps-core` from this spec directly —
  research/parity findings at P3 require `specify` only per this project's threshold rules.
- Do not remove or modify `freshness.rs`, OSV.dev integration, or spec 071's typosquat-similarity code as
  a side effect of filing this research spec.

## 9. Open Questions

- [NEEDS CLARIFICATION: Should GOSSIP's Dynamic Cooldown replace `freshness.rs`'s existing from-scratch
  3-day-default heuristic entirely, augment it as a second signal, or remain unadopted if the local
  heuristic is judged sufficient? This is the highest-leverage decision since it could reduce maintained
  bespoke logic (per NFR-003) but also touches a heuristic with an existing multi-PR history (#145, #219,
  #220, #221, #222, #225, #277, #293, #294, #316).]
- [NEEDS CLARIFICATION: Should GOSSIP's Malicious Packages and Critical Vulnerabilities signals be
  cross-referenced against OSV.dev results to catch coverage gaps in OSV's MAL-* record format, or is
  that redundant engineering effort given OSV.dev is already the vulnerability source of record for specs
  002 and 049? Requires an empirical coverage-gap comparison, not a documentation-only judgment call.]
- [NEEDS CLARIFICATION: Is GOSSIP available for all 7 systems deps.dev already covers in
  `deps_dev_system()` (GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET, per spec 037/071), or only a subset?
  The blog announcement does not enumerate per-system coverage; this requires reading deps.dev's technical
  documentation / `google/deps.dev` GitHub repo directly, not inferring from the existing Scorecard/SLSA
  system list.]
- [NEEDS CLARIFICATION: What is the rate-limit/latency budget impact of adding a 6th deps.dev call type
  (alongside license, Scorecard, SLSA, and spec 071's typosquat-similarity calls already fetched
  concurrently in hover per [[037-supply-chain-trust-signal/spec|#037]] §8's `DEPS_DEV_WAIT_BUDGET`
  pattern)? Needs a live latency measurement once the API reference and an actual endpoint are available,
  not a theoretical estimate.]
- [NEEDS CLARIFICATION: Is GOSSIP generally available (GA), or still in a v3alpha-style preview like
  `GetSimilarlyNamedPackages` was treated in spec 071? The blog post's publish date (2026-06-09) predates
  this research (2026-09-25) by over three months, which may or may not indicate GA status by now — the
  actual API reference/changelog needs to be checked rather than assumed from the announcement date alone.]

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

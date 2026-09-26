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
redundant coverage of something deps-lsp already detects via a different source. Resolved (§7, revised
2026-09-26 after critique): adopt Dynamic Cooldown at hover+diagnostics (existing) and completion (net-new)
— `freshness.rs` is kept as the fallback, not replaced — plus Low-Usage Packages; defer
Malicious/Critical-Vulnerabilities; treat Archived Packages as already covered. The HOW of integrating the
adopted signals is `plan.md`'s job, not this spec's.

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

**Revised 2026-09-26** after an adversarial `rust-critic` pass on the first plan.md found 4 false premises
(recorded in full in `plan.md` §0's revision history). The corrected scope below reflects verified code
facts and 4 follow-up maintainer decisions, not the original (partly wrong) assumptions.

**Revised again 2026-09-26 (round 3)** after a second critic pass on the round-2 revision found 4 further
gaps (N1-N4) — see §9's round-3 table. A fourth pass found 2 more (N5-N6) — see §9's round-4 table. A fifth
round (N7-N8, staleness/refresh and cross-document concurrency) added FR-011/FR-012 — see §9's round-5
table. FR-010 is dropped; FR-005, FR-006, and FR-009 are corrected below.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN GOSSIP's Low-Usage Packages signal is adopted THE SYSTEM SHALL surface it as a distinct, low-severity signal from existing typosquat-similarity ([[071-typosquat-similarity-diagnostic/spec\|#071]]) and vulnerability diagnostics, not merged into either. **Gated**: implementation SHALL NOT finalize `GossipFindingsWire`'s low-usage sub-schema until a real `LOW_USAGE` finding has been observed live at least once (none was, across ~20 combined probes across both critique rounds) | must, gated on live observation |
| FR-002 | WHEN GOSSIP's Dynamic Cooldown is available for a dependency (ecosystem covered, `GossipConfig.enabled`, document-level cache has data whose version exactly matches the registry's own reported latest — see FR-008) THE SYSTEM SHALL treat it as authoritative for that dependency's cooldown status at hover and diagnostics (`diagnostics.rs:2262`); WHEN unavailable THE SYSTEM SHALL fall back to the existing local `is_within_cooldown`/`FreshnessConfig.cooldown_secs` check. The two SHALL NOT be shown as disagreeing without the hover/diagnostic text making the source explicit, since live windows differ materially (verified 2026-09-26: npm 15d, PyPI 5d, Cargo 10d vs. local 3d default) | must |
| FR-003 | Malicious Packages / Critical Vulnerabilities cross-reference — **not adopted**; deferred to a separate `research`-labeled coverage-gap issue. If ever revisited, THE SYSTEM SHALL treat OSV.dev as authoritative on any disagreement | deferred |
| FR-004 | WHEN GOSSIP is unavailable for a given ecosystem, disabled (FR-009), offline, or the dependency's source is not a public registry (per `SourcePolicy::source_is_public_registry_content`) THE SYSTEM SHALL degrade gracefully with no user-visible error | must |
| FR-005 | **CORRECTED round 3 (critique N4), memo restored round 4 (critique N5): round 2's "await concurrently" framing does not fix hover's latency doubling, because cooldown and low-usage render at two different points in `hover.rs` (cooldown before the existing `trust_signal` join, low-usage at/after it).** THE SYSTEM SHALL instead source hover's cooldown callout from `VersionData.gossip_prefetch` (FR-006's storage, no live network wait at all for cooldown), and SHALL fetch low-usage live only for the pinned/resolved version, spawned alongside `spawn_trust_signal_fetch` and awaited at the same existing join point under its own `GOSSIP_WAIT_BUDGET`, backed by a version-keyed `DepsDevClient` memo entry so a response landing past the budget still warms something for the next hover instead of being lost (critique N5 — round 3 had no memo at all, so "spawn-and-warm" warmed nothing) | must |
| FR-006 | **CORRECTED round 3 (critique N2/N3), further corrected round 4 (critique N5/N6).** Cooldown status SHALL be surfaced in completion (net-new — completion has no cooldown check today) via THE SYSTEM'S existing local `is_within_cooldown` per candidate as the **default-on baseline** (zero cost, works for all 14 ecosystems and with GOSSIP disabled, honoring the existing `FreshnessSettings.enabled`/`cooldown_secs` knobs already in `CompletionRequest`). **Completion SHALL NOT read any GOSSIP-sourced data** (round 4 reverses round 3's plan to enrich the `defaultVersion`-matching candidate: `generate_completions` has no `VersionData`/prefetch channel, and adding one requires either a sealed-trait signature change or a new field interacting with the `#319` DashMap-across-await liveness constraint — not justified for one candidate's cooldown-window precision). Hover/diagnostics SHALL read GOSSIP data from a **per-document** `GetFindingsBatch` result, backed by **both** a per-package `DepsDevClient` memo (network dedupe — critique N5, a `DocumentState`-only design reintroduces an uncached POST per debounced edit) **and** `DocumentState` storage (durability across idle documents — critique N2). No completion request SHALL ever issue a live network call | must |
| FR-007 | WHEN GOSSIP's Dynamic Cooldown is available THE SYSTEM SHALL use it in preference to `FreshnessConfig.cooldown_secs` **only within `deps-lsp`'s hover/diagnostics/completion call sites** for covered ecosystems. `FreshnessConfig.cooldown_secs` is **NOT removed** — it remains unchanged for `deps-cli`'s `--cooldown` flag, the GitHub Action's `cooldown` input, and as the operative window for the 7 ecosystems GOSSIP does not cover. This is a behavior-precedence change within `deps-lsp` only, **not** a breaking change | must |
| FR-008 | WHEN reading GOSSIP data from the per-document cache (FR-006) THE SYSTEM SHALL treat `defaultVersion`'s cooldown/low-usage data as applicable only if its version exactly equals the version being displayed at that call site — named per site: hover's `latest_line`, diagnostics' `package_versions.latest`, completion's own candidate version (critique M13; live-verified canonical version strings for Go/NuGet/PyPI make plain string equality viable). On mismatch, treat as a cache-miss and fall back per FR-002/FR-006 | must |
| FR-009 | WHEN GOSSIP integration is shipped THE SYSTEM SHALL gate all GOSSIP network calls behind a new opt-in `GossipConfig.enabled` flag (default `false`, structural twin of `TyposquatConfig` — including `#[serde(default)]` on the field and `#[non_exhaustive]` on the struct, critique M12), because the per-document prefetch discloses every declared dependency's name to deps.dev | must |
| FR-010 | **DROPPED round 3 (critique N1, maintainer decision 2026-09-26).** `deps-cli` GOSSIP integration delivers near-zero practical value (cooldown only changes a diagnostic message's text, not `--fail-on`/exit-code behavior; `update` doesn't use cooldown at all) for a real implementation cost (`deps-cli`/`deps-engine` have no `DepsDevClient` today). Removed from this issue's scope; filed as a separate follow-up issue instead of implemented here | dropped |
| FR-011 | **NEW round 5 (critique N7).** `GossipCooldown`'s active status SHALL be computed by comparing its stored `end: PublishTime` against the current time at every read — never by storing a precomputed boolean. WHEN a version-equality mismatch (FR-008) is found for a package THE SYSTEM SHALL schedule a background refetch for that package, throttled to no more than once every 15 minutes, so an idle open document does not remain on stale/local-fallback data indefinitely after a new release. A soft ~1-hour staleness age on otherwise-matching data SHOULD schedule the same background refresh without blocking the current read | must |
| FR-012 | **NEW round 5 (critique N8).** THE SYSTEM SHALL bound concurrent `GetFindingsBatch` calls across all open documents with a global semaphore (mirroring the existing `max_concurrent_fetches` pattern), rather than leaving cross-document bursts (e.g. the disabled→enabled config transition firing one call per open document) unbounded. THE SYSTEM SHALL enforce the existing `DEPS_DEV_BODY_LIMIT` on every paginated page of a batch response, not only the first | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Hover's only live GOSSIP wait is the low-usage fetch, under its own `GOSSIP_WAIT_BUDGET`, at the same point `trust_signal` already awaits (FR-005 — cooldown no longer waits on anything live). Diagnostics incurs zero added latency — synchronous `VersionData.gossip_prefetch` reads. Completion incurs zero added latency AND zero GOSSIP involvement (FR-006, round 4). The per-document prefetch (FR-006) must check a per-package memo before firing `GetFindingsBatch`, so repeated triggers from the 100ms `did_change` debounce do not each cost a network round-trip (critique N5) |
| NFR-002 | Reliability | GOSSIP unavailability (disabled, offline, non-public-registry source, cache miss/version mismatch) must degrade to the FR-002/FR-007 local-heuristic fallback, never to a blocking error. A `NOT_FOUND`/`RISK_CRITICAL` package-level finding SHALL NOT be surfaced as a diagnostic on its own — ambiguous between "malicious/removed" and "too new to be indexed yet" |
| NFR-003 | Maintainability | `freshness.rs`'s pure functions are kept, unmodified, as the fallback layer for all ecosystems and all GOSSIP-unavailable cases — this feature adds new GOSSIP-integration code in front of it, never inside it |
| NFR-004 | Accuracy | Any GOSSIP-sourced signal presented to the user must be attributable to deps.dev/GOSSIP as its source, distinguishable from the local-heuristic fallback when both could apply (FR-002) |
| NFR-005 | Privacy | Per FR-009, no dependency name reaches deps.dev's GOSSIP endpoint unless (a) the opt-in flag is enabled, (b) the dependency's source passes `SourcePolicy::source_is_public_registry_content`, and (c) the request is not running offline |
| NFR-006 | Availability | Per FR-012, GOSSIP network calls are bounded by a global concurrency limit and a per-page body-size limit, so this feature cannot itself cause an outbound-request burst or an unbounded response read regardless of workspace size |

## 5. Data Model

Confirmed against the live `v3alpha` API (`docs.deps.dev/api/v3alpha/#getfindings`), verified with real
requests to `api.deps.dev` first during spec-phase research (2026-09-25) and again, with corrections, during
the plan-critique pass (2026-09-26 — this second round actually caught a live active `COOLDOWN` finding,
which the first round never did):

- **Endpoints**: `GET /v3alpha/systems/{system}/packages/{name}:findings` (package-scoped, all versions) and
  `GET /v3alpha/systems/{system}/packages/{name}/versions/{version}:findings` (version-scoped). A batch
  variant (`GetFindingsBatch`) exists, capped at 5000 items per batch, live-verified to work with mixed
  systems and `nextPageToken` pagination (round 3) — used for the per-document prefetch (FR-006), one POST
  per document rather than a per-package fan-out.
- **Response shape**: `recommendedVersions[]` (low-risk version suggestions), `requestedVersion` (findings
  for the version actually asked about — version-scoped calls only; **also includes `defaultVersion` and
  `packageFindings` in the same response**, so one version-scoped hover call serves both the pinned
  version's low-usage finding and the Latest-version cooldown status — no second call needed), `defaultVersion`,
  `packageFindings[]` (package-wide, not version-specific).
- **`recommendedVersions[]` is frequently EMPTY** when the package's default version is itself in cooldown
  (live-verified 2026-09-26: `vite`, `boto3`, `next`, `@types/node` all returned an empty
  `recommendedVersions[]` while in an active cooldown) — `defaultVersion` is the only reliable field for
  "is the latest version in cooldown", not `recommendedVersions[0]` as the original plan assumed. See FR-008
  for the version-equality check this requires.
- **Finding.type** enum (observed + documented): `NOT_FOUND`, `MALICIOUS`, `DEPRECATED`, `COOLDOWN`,
  `LOW_USAGE`, `VULNERABLE`, `REMEDIATION`.
- **Finding.risk** enum: `RISK_CRITICAL`, `RISK_HIGH`, `RISK_MEDIUM`, `RISK_LOW`, `RISK_INFORMATIONAL`.
- **CORRECTED (2026-09-26): an active cooldown is a `COOLDOWN`-type entry in `findings[]`, not a bare
  always-present field.** The version wrapper's own `cooldownEnd` field (top-level, sibling of `findings[]`)
  is present even for long-past cooldowns with no active `COOLDOWN` finding (this is what every spec-phase
  probe on 2026-09-25 observed, since none happened to hit a package still in cooldown) — it is a historical
  timestamp, not itself the "is this active" signal. The actual live example (`vite` on npm, 2026-09-26):
  a `findings[]` entry `{"type": "COOLDOWN", "risk": "RISK_HIGH", "cooldownContext": {"end": "<RFC3339>"}}`.
  Implementation must key off the `COOLDOWN` finding's presence + `cooldownContext.end`, not the version
  wrapper's bare `cooldownEnd`.
- **Context objects** (populated per finding type): `deprecatedContext.reason`, `cooldownContext.end`,
  `lowUsageContext` (exact sub-fields still not observed live even after combined spec-phase + critique-phase
  sampling of ~20 packages including deliberately obscure/low-adoption names — see FR-001's gate).

**Empirical notes from live testing**, spec-phase 2026-09-25 (`npm/lodash`, `npm/request`, `npm/left-pad`,
`npm/chalk@5.3.0/5.3.1`, `npm/debug@4.4.2`, `npm/ua-parser-js@0.7.29`, `pypi/requests@2.31.0`,
`cargo/serde@1.0.195`) plus critique-phase 2026-09-26 (`typescript`, `@types/node`, `vite`, `next`, `boto3`,
`tokio`, `vite@8.3.0`, 5 obscure npm packages, 2 non-existent names):
- `npm/request@2.88.2` and `npm/left-pad@1.3.0` correctly return a `DEPRECATED` finding
  (`RISK_MEDIUM`) with a human-readable `deprecatedContext.reason` — confirms viability for
  [[011-deprecation-replacement-diagnostics/spec|#011]]'s overlap question.
- **Active cooldown confirmed live 2026-09-26**: `npm/vite` (8.3.1), `npm/@types/node`, `npm/next`, and
  `pypi/boto3` all showed a real `COOLDOWN` finding on `defaultVersion` — with windows of npm 15 days,
  PyPI 5 days, Cargo 10 days (`tokio`), all longer than `freshness.rs`'s local 3-day default. This directly
  informs FR-002/NFR-002's source-attribution requirement — the two sources give materially different
  answers for a release 4-15 days old, not just theoretically.
- Versions known to have been part of real npm supply-chain-compromise incidents but since unpublished/pulled
  from the registry (`ua-parser-js@0.7.29`, the October 2021 compromise; `debug@4.4.2`, the September 2025
  chalk/debug phishing-worm incident) both returned **`NOT_FOUND` / `RISK_CRITICAL`** for `requestedVersion`,
  not a `MALICIOUS` finding. Separately, two non-existent/very-new package names probed 2026-09-26 also
  returned `NOT_FOUND`/`RISK_CRITICAL` at the `packageFindings` level — meaning `NOT_FOUND` is overloaded
  between "known malicious/removed" and "not yet ingested" (deps.dev indexing lag), which is why NFR-002
  forbids surfacing it directly as a diagnostic. No live `MALICIOUS` finding was captured in either round.
  This directly bears on FR-003 (see §9).

| Entity | Description | Key Attributes (confirmed) |
|--------|-------------|----------------|
| Finding | One flagged condition for a package/version | `type` (enum above), `risk` (enum above), optional type-specific context object (`cooldownContext.end` for `COOLDOWN`) |
| Findings response | Per-package or per-version bundle | `recommendedVersions[]` (often empty during active cooldown — see FR-008), `requestedVersion` (version-scoped only; also carries `defaultVersion`+`packageFindings`), `defaultVersion`, `packageFindings[]`, each carrying `findings[]` and a version-wrapper-level `cooldownEnd` (historical, not itself the active-cooldown signal) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GOSSIP flags a package as low-usage that is a legitimate new/niche package (false positive) | RESOLVED (§9): surface the raw `LOW_USAGE` finding as-is, worded as a non-blocking, low-severity invitation to double-check package identity — no corroborating-signal gate built. Gated on FR-001's live-observation requirement first |
| deps.dev API returns GOSSIP data for an ecosystem not yet confirmed to be covered | RESOLVED (§9): all 7 `deps_dev_system()` ecosystems (GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET) confirmed covered by live testing — no coverage gap |
| GOSSIP and OSV.dev disagree on whether a package is malicious | Not currently reachable: FR-003 defers Malicious/Critical-Vulnerabilities adoption entirely (§9). If a future coverage-gap study reverses that decision, OSV.dev is authoritative per §9's precedence rule |
| GOSSIP and `freshness.rs` disagree on cooldown window for the same release | **REVISED 2026-09-26** (was incorrectly marked "not reachable" under the original full-replacement plan): this is a live, reachable case — verified windows differ by 2-12x (npm 15d/PyPI 5d/Cargo 10d vs. local 3d). FR-002 requires the source to be explicit in the hover/diagnostic text whenever GOSSIP is available for that dependency, precisely because the two can and do disagree |
| GOSSIP API is still in preview/alpha status (unstable schema) | RESOLVED (§9): confirmed still `v3alpha`, no GA designation found. Follow the same provisional-integration posture spec 071 adopted for `GetSimilarlyNamedPackages` |
| A package-level `NOT_FOUND`/`RISK_CRITICAL` finding is returned for a name that is not actually malicious, just not yet indexed by deps.dev (ingestion lag) | **NEW 2026-09-26** (critique finding M4): verified live for 2 legitimate-shaped but non-existent/very-new probe names. NFR-002: never surface `NOT_FOUND` as a standalone diagnostic — it is ambiguous between "malicious/removed" and "too new to index" |
| A completion candidate needs a cooldown/low-usage signal | **CORRECTED round 3, simplified further round 4** (FR-006): the local `is_within_cooldown` baseline renders a cooldown badge for every candidate from locally-known `published_at` data — this is the *only* signal completion ever shows (round 4, N6b: no GOSSIP data reaches completion at all, so there is no separate "covered by the cache" case to distinguish) |

## 7. Success Criteria

Met (2026-09-25, revised four times on 2026-09-26): all `[NEEDS CLARIFICATION]` items in §9 are resolved.
Four successive adversarial-review rounds found, respectively, 4 false premises (round 2), 4 further design
gaps (round 3), 2 gaps introduced by round 3's own fixes (round 4), and 2 remaining staleness/concurrency
gaps (round 5) — each corrected via direct code verification and live-API testing, not guesswork. Current
adopted scope:

- **Adopt**: Dynamic Cooldown at hover and diagnostics (`diagnostics.rs:2262`) — the only 2 real existing
  call sites, not 5 as originally assumed (critique C1) — sourced from `VersionData.gossip_prefetch`
  (a new field mirroring the existing `typosquat_prefetch`, round 4 critique N6a), populated from a
  per-document `GetFindingsBatch` result backed by **both** a per-package `DepsDevClient` memo (network
  dedupe, round 4 critique N5) **and** `DocumentState` storage (durability across idle documents, round 3
  critique N2) — not a live per-request fetch. Plus **net-new** cooldown in completion (FR-006), shipped as
  the local `is_within_cooldown` per-candidate baseline **only** — no GOSSIP enrichment (round 4 critique
  N6b reverses round 3's plan to enrich the `defaultVersion`-matching candidate, once the real plumbing cost
  was found: `generate_completions` has no data channel for it without a sealed-trait signature change or a
  new field touching a real liveness constraint, `#319`). Plus Low-Usage/slopsquatting (raw flag, soft
  wording, gated on live observation per FR-001). `FreshnessConfig.cooldown_secs` is **kept**, not removed
  (FR-007) — it remains the sole, unchanged source for `deps-cli`, the GitHub Action, and the 7 non-GOSSIP
  ecosystems, and the `deps-lsp` fallback elsewhere. All GOSSIP network calls are opt-in (FR-009), mirroring
  spec 071's typosquat prefetch.
- **Dropped from this issue**: `deps-cli` GOSSIP parity (FR-010, round 3 critique N1) — near-zero practical
  value for real implementation cost; filed as a separate follow-up issue instead. A `[gossip]` config
  section now surfaces `deps-cli`'s existing "no effect" warning (round 4, M14) rather than being silently
  accepted.
- **Defer to separate research issue**: Malicious Packages, Critical Vulnerabilities (coverage-gap study
  needed first) — unchanged from the original decision.
- **No action** (redundant with existing signal, not re-litigated): Archived Packages — unchanged.

Ready for implementation on this corrected scope — see `plan.md`'s own revision history (§0) for the full
critique-to-decision mapping across both rounds.

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
  [[004-release-freshness-signal/spec|#004]]).~~ Done, then corrected: the maintainer's initial "full
  replacement" answer was itself based on the round-2 (still-incorrect) framing; the settled design (§9,
  round 3) keeps `freshness.rs` entirely unmodified as the permanent fallback, never replaced.

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
- **Empirical finding from the 2026-09-25 session — LATER FOUND FALSE, kept here only as a documented
  error, corrected below.** The original claim was that `freshness.rs`'s `is_within_cooldown`/`PublishTime`
  are called from **5 distinct call sites**: hover, diagnostics, code_lenses, code_actions, and completion
  (per candidate item). A `rust-critic` pass on 2026-09-26 found this false by direct `grep` inspection —
  only 2 real call sites exist (hover, `diagnostics.rs:2262`). See the "2026-09-26 critique round" table
  below for the corrected finding and its downstream effect on FR-005/FR-006.

Resolved by maintainer decision this session (2026-09-25), per §8's Agent Boundaries "Ask First" gate:

- **Dynamic Cooldown — RESOLVED 2026-09-25, then CORRECTED 2026-09-26 after critique.** The 2026-09-25
  resolution ("replace `freshness.rs` entirely at all 5 call sites", removing `cooldown_secs` as a breaking
  change) rested on a claim — repeated from an earlier research pass — that `is_within_cooldown` is called
  from hover, diagnostics, code_lenses, code_actions, *and* completion. A `rust-critic` adversarial pass on
  the resulting plan.md (2026-09-26) found this false on direct inspection (`grep -rn is_within_cooldown
  crates/deps-core/src/`): the **only** two call sites are `hover.rs:596` and `diagnostics.rs:2262`.
  `completion.rs` only renders relative age via a `freshness_enabled: bool` flag (never calls
  `is_within_cooldown`); `code_actions.rs:531` constructs `FreshnessSettings { enabled: false, .. }`
  (explicitly disabled); the `code_lenses.rs` reference is an unused `_freshness` test parameter. See the
  "2026-09-26 critique round" subsection below for the full C1-C4/S1-S6 finding list and how each was
  resolved.
  **Corrected resolution (round 2, then refined further in round 3 — see the "2026-09-26 critique round 3"
  table below)**: adopt GOSSIP cooldown at the 2 real call sites (hover, diagnostics), *plus* add it to
  completion as genuinely new scope, built on completion's existing local per-candidate check as the
  baseline (round 3 correction — round 2 had specified a dedicated completion-only prefetch/cache layer,
  which round 3 found unnecessary once storage moved to a per-document cache diagnostics also uses).
  `FreshnessConfig.cooldown_secs` is **kept** (FR-007) — maintainer decision after critique found the
  original removal's blast radius extended far beyond `deps-lsp` (shared with `deps-cli`'s `--cooldown` flag
  and the GitHub Action's `cooldown` input; `deps-lsp`'s `deny_unknown_fields` is top-level-only so a
  removed key would silently no-op rather than error, contradicting the original plan's assumption).
  `deps-cli` GOSSIP parity was initially added as FR-010, then **dropped** in round 3 once critique found it
  delivered almost no practical value there (§9's round-3 table, N1) — filed as a separate follow-up issue
  instead. All GOSSIP calls are gated behind a new opt-in flag (FR-009) mirroring spec 071's
  `TyposquatConfig`, because the per-document prefetch discloses every declared dependency's name to
  deps.dev — the same concern that made spec 071 opt-in, which the original (round 1) plan missed entirely.
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

### 2026-09-26 critique round 2

A `rust-critic` adversarial pass on the 2026-09-25 plan.md returned verdict **critical**: 4 false premises
(C1-C4) plus 6 significant/minor findings (S1-S6/M1-M4), verified against both the live GOSSIP API and
direct code inspection. Resolution of each, folded into the FR/NFR table and the corrected resolution above:

| # | Finding | Resolution |
|---|---------|------------|
| C1 | "5 `is_within_cooldown` call sites" was false — only 2 exist (hover, diagnostics); completion/code_actions/code_lenses don't call it at all | FR-006 re-scoped as new capability for completion, not a fix for a non-existent regression |
| C2 | Live GOSSIP cooldown windows (npm 15d/PyPI 5d/Cargo 10d) differ materially from local 3d default; `deps-cli` never prefetches so would permanently disagree with the LSP | FR-002 (explicit source attribution), FR-010 (`deps-cli` batched GOSSIP call) |
| C3 | `FreshnessConfig` removal blast radius extends to `deps-cli --cooldown`, the GitHub Action `cooldown` input, and 5 doc files — not just `deps-lsp`'s `server.rs` | FR-007 reversed: `cooldown_secs` is kept, scope narrowed to a `deps-lsp`-only precedence change |
| C4 | `deny_unknown_fields` is top-level-only (`deps-lsp/src/config.rs:33`) — a removed key would be silently ignored, not rejected, contradicting the original plan's assumption | Moot once FR-007 no longer removes the key |
| S1 | `recommendedVersions[]` is empty exactly when the default version is in cooldown; `defaultVersion` is the only reliable field | FR-008 (exact version-equality check against the registry's own latest) |
| S2 | A version-scoped hover call's response already includes `defaultVersion`+`packageFindings` alongside `requestedVersion` — one call serves both cooldown and low-usage | Folded into §5's data model correction; no separate call needed |
| S3 | `LOW_USAGE` never observed live across ~20 combined probes | FR-001 gated on a live observation before schema finalization |
| S4 | Original plan had no republish mechanism for diagnostics (typosquat precedent republishes via `spawn_typosquat_prefetch_and_republish`); diagnostics also lack existing `DepsDevClient` plumbing | Plan.md's diagnostics design now mirrors the typosquat prefetch-and-republish pattern explicitly |
| S5 | Prefetch fan-out was unbounded; no public-registry-source filter; prefetching all declared deps on document open widens name disclosure beyond "hovered only" | FR-004 (public-registry filter), FR-009 (opt-in gate), NFR-001 (concurrency cap mirroring `TYPOSQUAT_FETCH_CONCURRENCY = 8`) |
| S6 | Once `cooldown_secs` is gone, the fallback window value was unstated; 7/14 ecosystems have no deps.dev coverage and would lose configurability for nothing | Moot once FR-007 no longer removes the key — the 7 uncovered ecosystems are entirely unaffected |
| M1 | Sequential hover awaits (`trust_signal` then GOSSIP) would double worst-case latency to ~1.4s | FR-005 (concurrent await, independent budgets) |
| M2 | 1h TTL is fine, conditional on S1's fix | Addressed by FR-008 |
| M3 | Live wire shape is a `COOLDOWN` finding with `cooldownContext.end`, not a bare always-present `cooldownEnd` field | §5's data model corrected with the live `vite` example |
| M4 | `NOT_FOUND`/`RISK_CRITICAL` also fires for not-yet-indexed legitimate new packages, not just malicious/removed ones | NFR-002 (never surface `NOT_FOUND` standalone) |

Three questions the critique posed to the maintainer were resolved 2026-09-26: FR-006 keeps completion in
scope as new capability (not dropped); `deps-cli` awaits GOSSIP via a batch call (FR-010) rather than
accepting permanent CLI/LSP disagreement; `cooldown_secs` is kept everywhere except as the LSP's
GOSSIP-available precedence (FR-007). A fourth question the critique raised independently (S5's privacy
concern) was also resolved: GOSSIP is opt-in (FR-009), matching spec 071's precedent.

### 2026-09-26 critique round 3

A second `rust-critic` pass, on the round-2 revision (commit `db68e6f89`), returned verdict **significant**
(no redesign needed, but real gaps). Confirmed as actually addressed, not just claimed: C1, C2 (LSP side),
C3, C4, S1, S2, S3, S5, S6, M1-M4. New findings:

| # | Finding | Resolution |
|---|---------|------------|
| N1 | FR-010 (`deps-cli` GOSSIP parity) delivers near-zero value: cooldown only changes a diagnostic message's text (no `--fail-on`/exit-code effect), `update` doesn't use cooldown at all, and `deps-cli`/`deps-engine` have no `DepsDevClient` today (verified: zero `cooldown` hits in `report.rs`/`analyze.rs`, zero in `update/`, zero `DepsDevClient` references) | **FR-010 dropped from this issue** (maintainer decision 2026-09-26), filed as a separate follow-up issue |
| N2 | Reading GOSSIP data from the shared `DepsDevClient` memo (1h TTL, 512-entry cap) silently loses data for idle open documents — a diagnostics regeneration in between reverts to the local-fallback text with no refetch trigger | Store GOSSIP findings in `DocumentState` (mirrors `merge_typosquats`, `osv_scan.rs:441`, same content-snapshot staleness guard), not the transient client memo |
| N3 | Completion's round-2 "no badge on cache-miss" design is inconsistent with hover/diagnostics' local-heuristic fallback; GOSSIP can only ever cover one candidate (`defaultVersion`) anyway, while per-candidate `published_at` is already available locally (`completion.rs:1253`) | Local `is_within_cooldown` per candidate becomes the default-on baseline (works for all 14 ecosystems, zero cost); GOSSIP only enriches the `defaultVersion`-matching candidate. No dedicated completion prefetch layer needed — simplifies round 2's FR-006 |
| N4 | Round 2's FR-005 ("await concurrently") doesn't fix M1: hover's cooldown callout renders before the code point where `trust_signal` is joined, so a single `join!` there can't supply cooldown data in time; two sequential timeouts would still sum to ~1.4s | Source hover's cooldown from the same `DocumentState` cache N2/N3 use (no live wait for cooldown at all); low-usage remains the only live hover fetch, at the same point `trust_signal` already awaits, under its own budget — no shared-deadline mechanism needed once cooldown isn't live |
| M5 | Hover's low-usage fetch needs `resolve_in_use_version` — a range-only dependency with no lockfile has no concrete version to check | Skip the low-usage fetch entirely when `resolve_in_use_version` returns `None`; cooldown still works via the document-level cache |
| M6 | The old plan's "already warmed by a prior hover" claim was false — hover (version-scoped) and prefetch (package-scoped in round 2) use different endpoints/keys | Moot in round 3 — hover no longer does a version-scoped cooldown fetch at all |
| M7 | `GetFindingsBatch` (one POST per document) is simpler than round 2's per-package fan-out, and live-verified to work with `nextPageToken` pagination | Adopted for the network-fetch shape; **round 4 note**: round 3 also dropped the per-package memo entirely alongside the fan-out, which turned out to be a separate mistake (see round-4 table, N5) — the batch-vs-fan-out simplification and the memo-vs-no-memo dedupe question are independent decisions |
| M8 | `GossipConfig` needs a `PolicyConfigDiff` destructure entry and the same runtime-toggle mechanics as `TyposquatConfig` (`ServerState` atomic + trigger-on-enable, `server.rs:866-927`) | Added to plan.md §1/§2/§3 |
| M9 | `low_usage_context: Option<serde_json::Value>` was an untyped placeholder — a type-safety-rule violation for no benefit | Dropped from `GossipFindingWire` entirely until a live finding is observed (serde ignores unknown keys safely) |
| M10 | FR-002's exact message wording was unspecified; the local text must stay unchanged when GOSSIP is disabled (existing `diagnostics.rs` tests) | Implementation-task detail, flagged for the developer to specify against the existing test fixtures |
| M11 | Stale spec text still repeated the "5 call sites"/"full replacement" claims in §7-§9 after round 2's correction | Cleaned up throughout this document (this revision) |
| M12 | `GossipConfig`'s snippet lacked `#[serde(default)]` on `enabled` and `#[non_exhaustive]` — without the former, a partial `{"gossip":{}}` config fails to parse and the *entire* config reload is discarded | Fixed in plan.md §3's snippet, matching `TyposquatConfig`'s exact shape |
| M13 | FR-008 should name the exact comparand per call site; live Go/NuGet/PyPI default-version strings are canonical, so plain string equality is viable | Named per site in FR-008/plan.md §1 |

### 2026-09-26 critique round 4

A third `rust-critic` pass, on the round-3 revision (commit `faeaa4e8e`), returned verdict **significant**
once more — confirmed N1-N4/M5-M13 all actually addressed, but round 3's own fixes introduced 2 new gaps:

| # | Finding | Resolution |
|---|---------|------------|
| N5 | Round 3 dropped the `DepsDevClient` memo/in-flight pair entirely, removing all network-request dedupe: the document prefetch fires on every 100ms-debounced `did_change` (`lifecycle.rs:920`), so an uncached `GetFindingsBatch` POST would fire per edit per document; the content-snapshot guard then discards most in-flight results anyway (a ~300ms call routinely outlives the 100ms debounce); hover's low-usage GET, also memo-less, meant "spawn-and-warm" warmed nothing | Restore a per-package `DepsDevClient` memo (1h TTL, as round 2) *alongside* `DocumentState` (round 3) — the batch prefetch requests only memo-misses; a version-keyed memo entry covers the hover low-usage fetch |
| N6 | (a) `VersionData` already has the exact precedent field for this pattern — `typosquat_prefetch` (`lsp_helpers/mod.rs:645`) — so round 3's "passed alongside `VersionData`" would have meant changing the sealed `Ecosystem` trait's signatures instead of adding a sibling field. (b) Completion never receives `VersionData` at all (`generate_completions`'s real signature has no such parameter), and `handlers/completion.rs` cannot hold a `DashMap` shard reference across an await (`#319`, a real liveness constraint with its own regression test) — enriching one completion candidate would need a sealed-trait change or a new `CompletionRequest` field, for one candidate's cooldown-window precision | (a) Add `VersionData.gossip_prefetch` mirroring `typosquat_prefetch` exactly (FR-005/FR-006). (b) **Drop GOSSIP enrichment from completion entirely** — ship only the local per-candidate baseline (FR-006, maintainer-equivalent engineering decision 2026-09-26: an acceptable cost/benefit call on an already-approved capability, not a scope reversal, since completion still gets a genuine new cooldown signal it never had) |

Minor: `[gossip]` in `deps.toml` would be silently accepted with no effect in `deps-cli` now that FR-010 is
dropped — added to `deps-cli`'s existing `ignored_sections` "no effect" warning list (M14). Completion's
new local baseline must honor the existing `FreshnessSettings.enabled`/`cooldown_secs` knobs already
threaded into `CompletionRequest`, not bypass them (M15).

### 2026-09-26 critique round 5

Two follow-up questions the team-lead posed alongside round 4 (about `DocumentState` staleness policy and
dropping the per-package concurrency cap) surfaced 2 more real gaps, neither previously covered:

| # | Finding | Resolution |
|---|---------|------------|
| N7 | A content-snapshot guard alone doesn't handle staleness from time passing while a document sits open and unedited. FR-008's version-mismatch check already falls back correctly when a new release appears, but nothing then triggers a refetch — an idle document stays on the local 3-day fallback for that new release indefinitely. A TTL that drops the data would reintroduce N2 | `GossipCooldown.end` is compared to `now()` at every read (never a stored bool) — an ended cooldown self-clears with no refetch. An FR-008 mismatch schedules a background refetch, throttled to ≥15 minutes per package (deps.dev's own ingestion lag). A soft ~1h staleness age is a backstop for GOSSIP's own indexing lag on an already-matching version. None of this drops stored data on a timer (FR-011) |
| N8 | Dropping the within-document concurrency cap (round 3's batch-not-fan-out simplification) is fine, but cross-*document* bursts remain real: the disabled→enabled config transition fires one batch call per open document simultaneously, as does a cold-start multi-manifest load. Also: a paginated batch response's page size isn't itself bounded, so `DEPS_DEV_BODY_LIMIT` must apply per page, not just to the first | A global `Semaphore` bounds concurrent `GetFindingsBatch` calls across all documents, mirroring the existing `max_concurrent_fetches` pattern, rather than being left unbounded "to revisit later". `DEPS_DEV_BODY_LIMIT` applied to every `nextPageToken` page (FR-012). `MAX_DEPENDENCIES_PER_DOCUMENT` (5000) already composes correctly with `GetFindingsBatch`'s own 5000-item cap — no separate cap needed |

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

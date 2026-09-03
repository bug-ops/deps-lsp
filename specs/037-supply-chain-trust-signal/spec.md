---
aliases:
  - Supply-Chain Trust Signal
  - OpenSSF Scorecard in Hover
  - SLSA Provenance Signal
  - deps.dev Integration
tags:
  - sdd
  - spec
  - research
  - enhancement
  - deps-core
  - supply-chain-risk
  - cross-ecosystem
created: 2026-09-03
updated: 2026-09-03
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[004-release-freshness-signal/spec|Release-Freshness Signal for Version Recommendations]]"
  - "[[010-license-hover-policy/spec|License in Hover + License-Policy Diagnostics]]"
  - "[[011-deprecation-replacement-diagnostics/spec|Deprecation/Abandoned Diagnostics with Suggested Replacement]]"
  - "[[002-osv-vulnerability-diagnostics/spec|OSV Vulnerability Diagnostics]]"
---

# Feature: Supply-Chain Trust Signal (OpenSSF Scorecard + SLSA Provenance via deps.dev)

> [!info] Metadata
> **Author**: continuous-improvement cycle (deps-lsp)
> **Branch**: (assign at implementation time, e.g. `feat/<issue>-supply-chain-trust-signal`)
> **Priority**: P3
> **Type**: research/enhancement (competitive-parity gap — differentiator, not catch-up)

## 1. Overview

### Problem Statement

deps-lsp's hover panel already surfaces version status, license, deprecation,
and (per [[002-osv-vulnerability-diagnostics/spec|002]]) vulnerability data,
but has zero signal about the *source repository's* supply-chain health or a
specific published version's *build provenance*. Confirmed via grep this
cycle: zero references to `"scorecard"`, `"provenance"`, `"deps.dev"`, or
`"slsa"` anywhere in `crates/`.

[Google's deps.dev API v3](https://docs.deps.dev/api/v3/) is a free, keyless,
cross-ecosystem metadata API already covering 7 of deps-lsp's 10 ecosystems
(npm, Cargo, Go, Maven, PyPI, RubyGems/Bundler, NuGet — no Composer, Dart, or
Swift). It exposes two supply-chain-trust signals deps-lsp does not surface
anywhere today:

1. **OpenSSF Scorecard** — per-project checks (Code-Review,
   Dangerous-Workflow, Maintained, Packaging, Branch-Protection,
   Vulnerabilities, etc.), each scored 0-10 (or `-1` for not-applicable), via
   `GET /v3/projects/{project-key}` where `project-key` is derived from the
   package's linked source repository (e.g. `github.com/expressjs/express`,
   URL-encoded as the path segment).
2. **SLSA provenance / attestations** — per-version `slsaProvenances[]` and
   `attestations[]` arrays via
   `GET /v3/systems/{system}/packages/{name}/versions/{version}`, indicating
   whether a specific published version has verified build provenance
   (increasingly relevant post-npm/PyPI trusted-publishing rollouts).

Both endpoints were live-verified this cycle, keyless, no repo source
touched:

- `curl -s -A "deps-lsp-research/1.0" "https://api.deps.dev/v3/systems/npm/packages/express/versions/4.19.2"`
  returns `licenses`, `isDeprecated`, `advisoryKeys[]`, `slsaProvenances: []`,
  `attestations: []`, `registries[]`, and `relatedProjects[]` — the last of
  which links to the GitHub source repo and is the path to derive a project
  key (`relatedProjects[].projectKey.id` where
  `relationType == "SOURCE_REPO"`).
- `curl -s -A "deps-lsp-research/1.0" "https://api.deps.dev/v3/projects/github.com%2Fexpressjs%2Fexpress"`
  returns a full `scorecard` object: `date`, `repository.commit`,
  `scorecard.version`, and a `checks[]` array with `name`/`score`
  (0-10, or `-1` for not-applicable)/`reason`/`documentation.url` per check
  (for `express`: Code-Review 10, Dangerous-Workflow 10, Maintained 10,
  Packaging -1, etc.), plus top-level `starsCount`/`forksCount`/`openIssuesCount`.

`.local/testing/playbooks/competitive-parity.md` already lists deps.dev API
v3 in its Reference Projects table as a "data source, not competitor" (note
dated 2026-08-23) enumerating `licenses[]`/`isDeprecated`/`advisoryKeys[]`/
`slsaProvenances`/`attestations`/OpenSSF-Scorecard/stars/open-issues as
available fields across npm/Cargo/Go/Maven/PyPI/RubyGems/NuGet. This spec is
the first time acting on the Scorecard/SLSA half of that entry — the
license/deprecation half is already redundant with deps-lsp's own
registry-native data shipped via [[010-license-hover-policy/spec|010]] and
[[011-deprecation-replacement-diagnostics/spec|011]].

**Why this is a differentiator, not a catch-up item**: none of the reference
projects already tracked in `.local/testing/playbooks/competitive-parity.md`
(Dependi, Version Lens, crates.nvim, RHDA, JetBrains Package Checker) surface
OpenSSF Scorecard or SLSA provenance data inline in an editor today. Every
other row in that playbook is deps-lsp catching up to a feature a competitor
already ships; this one would be new ground.

> [!warning] Assumptions
> - deps.dev's `relatedProjects[].relationType == "SOURCE_REPO"` reliably
>   identifies the correct upstream repository for the vast majority of
>   well-maintained packages; a package with no linked source repo, or one
>   linked to a fork/mirror rather than the canonical upstream, degrades to
>   "no trust signal available" (see Edge Cases) rather than showing
>   incorrect or misleading data.
> - deps.dev has no documented public rate limit, but as an unauthenticated,
>   free, third-party dependency, deps-lsp must treat it conservatively —
>   caching, backoff, and graceful degradation on failure are mandatory, not
>   optional (see Non-Functional Requirements).
> - This spec captures WHAT and WHY only. HOW (concrete Rust types, module
>   placement, caching call sites, hover-string formatting) is deferred to a
>   future `/sdd plan` session — per this project's convention that research
>   findings are specified before planning begins.

### Goal

A dependency whose package has deps.dev coverage (npm, Cargo, Go, Maven,
PyPI, RubyGems/Bundler, or NuGet) and a resolvable linked source repository
gets an additional, compact, informational supply-chain trust summary in its
hover panel — e.g. "OpenSSF Scorecard: 7.2/10 · SLSA provenance: verified" —
with zero impact on packages/ecosystems where this data is unavailable, and
zero new diagnostic severity introduced by this signal alone.

### Out of Scope

> [!danger] Explicit Exclusions
> - **Composer, Dart, and Swift ecosystems** — deps.dev has no coverage for
>   these three; see Open Questions for whether they get a documented "not
>   available" hover line or silently omit the section entirely.
> - **A new diagnostic or code-action category driven by a low Scorecard
>   score** — see Open Questions; this spec's default assumption (pending
>   confirmation) is informational-only, matching the precedent
>   [[004-release-freshness-signal/spec|004]] established for release
>   freshness (a risk signal surfaced in hover, not escalated to a blocking
>   diagnostic).
> - **Any deps.dev field already redundant with deps-lsp's own
>   registry-native data** — `licenses[]`, `isDeprecated`, `advisoryKeys[]`
>   are explicitly excluded from this spec's scope; deps-lsp already sources
>   these natively per-ecosystem ([[010-license-hover-policy/spec|010]],
>   [[011-deprecation-replacement-diagnostics/spec|011]],
>   [[002-osv-vulnerability-diagnostics/spec|002]]) and duplicating them from
>   a third-party aggregator would be a maintenance liability with no user
>   benefit.
> - **Historical Scorecard trend data or repository-level analytics beyond
>   the single latest `scorecard` snapshot** deps.dev's `/v3/projects/{key}`
>   endpoint returns.
> - **Any write path** — this is a read-only, informational metadata
>   addition; no code actions, no quick-fixes.
> - **Authentication or API-key management for deps.dev** — the API is
>   keyless by design; no vault entry, no credential handling of any kind.

## 2. User Stories

### US-001: Scorecard summary in hover

AS A developer evaluating whether to add or keep a dependency
I WANT to see the upstream repository's OpenSSF Scorecard score in the
hover panel
SO THAT I can factor supply-chain health (CI hardening, code review
practice, branch protection) into my dependency decisions without leaving
my editor

**Acceptance criteria:**
```
GIVEN a dependency resolved from an ecosystem deps.dev covers (npm, Cargo,
      Go, Maven, PyPI, RubyGems/Bundler, NuGet) whose package has a
      resolvable SOURCE_REPO-linked project with Scorecard data
WHEN I hover over that dependency
THEN the hover includes a compact trust-signal line showing the aggregate
     Scorecard score (e.g. "OpenSSF Scorecard: 7.2/10")
```

### US-002: SLSA provenance status in hover

AS A developer relying on a package's specific pinned version
I WANT to know whether that exact version has verified SLSA build
provenance or an attestation
SO THAT I can distinguish a trusted-publishing-backed release from one with
no verifiable build chain

**Acceptance criteria:**
```
GIVEN a dependency's resolved version has a non-empty slsaProvenances[] or
      attestations[] array per deps.dev's per-version endpoint
WHEN I hover over that dependency
THEN the hover indicates provenance is verified for that version (and,
     conversely, indicates its absence when both arrays are empty, rather
     than silently omitting the line — see FR-004)
```

### US-003: Graceful absence for uncovered ecosystems/packages

AS A developer using Composer, Dart, or Swift, or any ecosystem package with
no linked source repository
I WANT the hover to behave exactly as it does today
SO THAT this feature never introduces a regression, error state, or
confusing "unknown" marker for the majority of cases where the signal
simply isn't obtainable

**Acceptance criteria:**
```
GIVEN a dependency from an ecosystem deps.dev does not cover, or one it
      covers but with no resolvable SOURCE_REPO project
WHEN I hover over that dependency
THEN the hover shows no trust-signal line (or a documented explicit
     "not available" line — see Open Questions), and no error/warning is
     surfaced to the user
```

### US-004: Resilience to deps.dev unavailability

AS A developer working offline or when deps.dev is unreachable
I WANT hover to continue working with all of deps-lsp's existing data
SO THAT a third-party dependency's outage never degrades a core feature

**Acceptance criteria:**
```
GIVEN deps.dev is unreachable, times out, or returns an error/malformed
      response
WHEN I hover over any dependency
THEN all existing hover content (version, license, deprecation,
     vulnerability data) renders unaffected, and the trust-signal line is
     simply omitted for that hover
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL query deps.dev's per-version endpoint (`GET /v3/systems/{system}/packages/{name}/versions/{version}`) for a resolved dependency belonging to one of the 7 covered ecosystems (npm, Cargo, Go, Maven, PyPI, RubyGems/Bundler, NuGet) to obtain `slsaProvenances[]`, `attestations[]`, and `relatedProjects[]` | must |
| FR-002 | WHEN a per-version response's `relatedProjects[]` contains one or more entries with `relationType == "SOURCE_REPO"` THE SYSTEM SHALL derive a project key by preferring an entry whose `relationProvenance == "SLSA_ATTESTATION"` over one whose `relationProvenance == "UNVERIFIED_METADATA"` (live-verified 2026-09-03: packages commonly carry multiple `SOURCE_REPO` entries; an unranked pick would let a hostile package's self-reported repository field — `UNVERIFIED_METADATA` — inherit an unrelated, reputable repo's Scorecard) and query deps.dev's project endpoint (`GET /v3/projects/{project-key}`, percent-encoded as one path segment) to obtain the `scorecard` object | must |
| FR-003 | WHEN the project endpoint's `scorecard` object is present THE SYSTEM SHALL surface deps.dev's own `scorecard.overallScore` field as the hover's aggregate Scorecard score (US-001) — live-verified 2026-09-03 (`GET /v3/projects/github.com%2Fexpressjs%2Fexpress` returns `scorecard.overallScore: 8.5` at the top level, sibling to `checks[]`); deps-lsp SHALL NOT compute its own mean of `checks[].score`, and SHALL NOT parse or store `checks[]` at all (unused surface — FR-003 only mandates the aggregate) | must |
| FR-004 | WHEN a resolved version's `slsaProvenances[]`/`attestations[]` entries are queried successfully THE SYSTEM SHALL surface a three-state provenance status distinguishing `Verified` (at least one entry has `verified == true` — live-verified 2026-09-03: every entry carries a boolean `verified` field, so a non-empty-but-unverified array is a real, distinct case), `Unverified` (both arrays non-empty but no entry has `verified == true`), and `None` (both arrays empty) — collapsing `Unverified` into `Verified` would render a false trust claim; never omitting the line silently when the query itself succeeded, so a user cannot mistake "we didn't check" for "we checked and found nothing" (US-002) | must |
| FR-005 | WHEN no `relatedProjects[]` entry with `relationType == "SOURCE_REPO"` exists, OR the ecosystem is not one of the 7 deps.dev covers THE SYSTEM SHALL omit the Scorecard portion of the trust signal entirely, with no error/warning surfaced (US-003) | must |
| FR-006 | WHEN any deps.dev request fails (network error, timeout, non-2xx status, malformed/unparseable JSON) THE SYSTEM SHALL omit the entire trust-signal section from that hover render and SHALL NOT block, delay, or degrade any other hover content (US-004) | must |
| FR-007 | THE SYSTEM SHALL route deps.dev requests through the existing `deps_core::HttpCache` transport (online/HTTPS/DNS-guard/body-limit/origin-pinned-redirect policy) rather than introducing a parallel HTTP client, and SHALL cache the assembled trust signal via an in-process TTL memo rather than `HttpCache`'s entry-body cache — live-verified 2026-09-03: deps.dev sends neither `ETag` nor `Last-Modified` on either endpoint, only `cache-control: max-age=3600`, so `HttpCache`'s conditional-GET/304 machinery cannot apply (see NFR-002); this mirrors the existing precedent for OSV.dev's identical missing-validators case (`crates/deps-core/src/osv/mod.rs`) | must |
| FR-013 | THE SYSTEM SHALL provide a configuration toggle (`supply_chain.enabled`, default `true`) that, when disabled, SHALL suppress every deps.dev request and the trust-signal hover section entirely | must |
| FR-008 | THE SYSTEM SHALL classify the `api.deps.dev` host through the existing `deps_core::net_policy` classifier and treat it as a fixed, non-workspace-configurable trusted-origin endpoint (deps.dev is a deps-lsp-selected third-party API, not a user-supplied registry URL) — it is not subject to the `registries.workspace_registries` gate that governs user-declared alternate registries | must |
| FR-009 | THE SYSTEM SHALL treat deps.dev as strictly additive to existing hover content — its data SHALL NOT replace, override, or be conflated with any registry-native field deps-lsp already sources itself (license, deprecation, vulnerability advisories per the Out of Scope exclusions) | must |
| FR-010 | THE SYSTEM SHALL scope this signal to hover only — no new diagnostic or inlay-hint category is introduced by this spec; a diagnostic/inlay-hint surface, if ever justified, is a separate future spec | must |
| FR-011 | WHEN the ecosystem is Composer, Dart, or Swift THE SYSTEM SHALL silently omit the trust-signal section (identical behavior to any other case of unavailable data per US-003/FR-005) — no explicit "not available" line is shown | must |
| FR-012 | THE SYSTEM SHALL treat the Scorecard score as informational-only in hover — a low score SHALL NOT escalate to a diagnostic, warning, or any blocking behavior, matching the [[004-release-freshness-signal/spec|004]] precedent; any future escalation requires a separate spec | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance / Rate Limiting | deps.dev publishes no documented public rate limit, but SHALL be treated conservatively: a repeated hover for the same package/version within the TTL memo window (NFR-002) issues zero HTTP requests rather than a fresh request every time; no fixed requests-per-second budget is assumed without further research at plan time |
| NFR-002 | Caching Strategy | Live-verified 2026-09-03: deps.dev sends no `ETag`/`Last-Modified` on either endpoint, only `cache-control: public, max-age=3600` — `HttpCache`'s conditional-GET model has no validators to revalidate against, so it cannot avoid a full-body re-fetch per hover for this API (unlike deps-lsp's registry clients). The assembled `SupplyChainTrustSignal` SHALL instead be cached in an in-process TTL memo keyed by `(base_url, system, name, version)`, success TTL 1 hour (matching the server's declared `max-age=3600`), error TTL 90 seconds (negative caching, matching `RELEASE_DATES_ERROR_TTL`) |
| NFR-003 | Reliability / Graceful Degradation | Per FR-006, a deps.dev outage or malformed response SHALL NOT be visible to the user as an error, warning, or blank/stalled hover — existing hover content renders identically to today with the trust-signal section simply absent |
| NFR-004 | Reliability / No Linked Repo | Per FR-005, a package with no resolvable `SOURCE_REPO` project (a materially common case — many packages have no linked repo, or link to a non-canonical mirror) SHALL degrade identically to an outright deps.dev failure from the user's perspective — no distinct error state |
| NFR-005 | Security | The `api.deps.dev` request SHALL be a plain, unauthenticated HTTPS GET with no credential, cookie, or workspace-derived value ever attached — consistent with deps.dev being keyless by design |
| NFR-006 | Maintainability | The Scorecard/SLSA data model SHALL be represented by new, deps.dev-specific types (not force-fit into any existing ecosystem crate's registry-response types) so a future change to deps.dev's schema does not ripple into unrelated ecosystem code |
| NFR-007 | Performance / Latency Bound | The two-call deps.dev sequence SHALL be bounded by an outer timeout (~700ms) in addition to any per-call timeout, and SHALL run concurrently with (not sequentially before or after) the dependency's own registry fetch — added 2026-09-03: the registry fetch is typically served from a warm prefetch cache (near-zero latency), making the deps.dev calls the hover's actual critical path in the common case, not a rare one; FR-006's "SHALL NOT block, delay, or degrade" is meaningless without an explicit bound |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DepsDevVersionInfo` | New type — parsed subset of deps.dev's per-version endpoint response relevant to this spec | `slsa_provenances: Vec<ProvenanceEntry>`, `attestations: Vec<ProvenanceEntry>`, `related_projects: Vec<RelatedProject>` |
| `ProvenanceEntry` | New type — one `slsaProvenances[]`/`attestations[]` entry | `verified: bool` (live-verified 2026-09-03; drives FR-004's three-state mapping) |
| `RelatedProject` | New type — one `relatedProjects[]` entry | `project_key: String` (extracted from the wire response's nested `projectKey.id`), `relation_type: String`, `relation_provenance: String` (`"SLSA_ATTESTATION"` vs `"UNVERIFIED_METADATA"`; drives FR-002's ranked pick) |
| `DepsDevScorecard` | New type — parsed subset of deps.dev's per-project endpoint `scorecard` object, plus one derived field | `overall_score: Option<f32>` (from `scorecard.overallScore`; `None`, not a defaulted `0.0`, when absent/unparseable — a defaulted zero would itself be a false trust claim), `self_reported: bool` (derived, not wire data — `true` when FR-002's pick landed on the `UNVERIFIED_METADATA` fallback rather than an `SLSA_ATTESTATION` relation; renders as the FR-002/Edge-Cases disclosure marker). `checks[]`, `scorecard.version`, and `date` are intentionally not parsed — the first two per FR-003, `date` because O3 settled that v1 renders no age qualifier, so it would be parsed and never read (same unused-surface reasoning as `checks[]`) |
| `ProvenanceStatus` | New, three-state enum (FR-004) | `Verified \| Unverified \| None` |
| `SupplyChainTrustSignal` | New, ecosystem-agnostic aggregate type assembled from the two deps.dev calls, consumed by the hover-formatting layer | `scorecard: Option<DepsDevScorecard>` (the hover-facing form; an implementation may split this into a wire-parsed type and a public summary type, as long as the fields above are preserved), `provenance: Option<ProvenanceStatus>` (`None` only when the version-level query itself failed, per FR-004/FR-006 distinction) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Ecosystem is Composer, Dart, or Swift | No deps.dev query attempted at all (FR-005); trust-signal section silently omitted from hover, no explicit "not available" line (FR-011) |
| Package has no `relatedProjects[]` entry with `relationType == "SOURCE_REPO"` | Scorecard portion omitted; SLSA/attestation portion (version-level, independent of project linkage) still shown per FR-001/FR-004 |
| deps.dev per-version query succeeds, per-project query fails/times out | Provenance status still shown (FR-004); Scorecard portion omitted (mirrors FR-006's per-call independence) |
| Both deps.dev queries fail (network error, timeout, non-2xx) | Entire trust-signal section omitted; no other hover content affected (FR-006, US-004) |
| deps.dev returns malformed/unexpected JSON shape | Treated identically to a request failure — parse error is not surfaced to the user (FR-006) |
| `slsaProvenances[]` and `attestations[]` both empty but the query succeeded | Explicit "no provenance found" shown, distinct from "not checked" (FR-004) |
| Same package/version hovered repeatedly within the TTL memo window | Served from the in-process memo, zero HTTP requests issued (FR-007, NFR-001, NFR-002) |
| deps.dev linked repo is a fork or mirror, not canonical upstream | Out of scope for this spec to detect/correct — deps-lsp trusts deps.dev's own `SOURCE_REPO` relation as given (see Assumptions) |
| Package's only `SOURCE_REPO` relation is `UNVERIFIED_METADATA` (self-reported, no `SLSA_ATTESTATION` entry) | Scorecard is still shown (FR-002 ranked pick falls back to it) but the hover line marks it as self-reported (e.g. a trailing qualifier) rather than presenting it with the same confidence as an attested relation — mitigates, does not eliminate, the spoofing risk the Assumptions section accepts |
| Dependency has no resolvable in-use/pinned version (no lockfile, no exact-version requirement) | The entire trust signal (Scorecard and provenance both) is omitted — FR-004's provenance claim is version-specific, and attaching another version's provenance/Scorecard data to an unresolved requirement would misattribute it |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover shows a correct Scorecard score for a live, well-known package with linked source repo and Scorecard data (e.g. `npm:express`) | Manual/integration test against a live or mocked deps.dev fixture matching the session's verified `express` response |
| SC-002 | Hover shows correct provenance status (`Verified` / `Unverified` / `None`) across all three FR-004 branches, including a non-empty-but-unverified array | Test asserting all three branches |
| SC-003 | Zero regression to existing hover content when deps.dev is offline/unreachable | Test running with deps.dev calls forced to fail; existing hover assertions unchanged |
| SC-004 | No deps.dev request issued for Composer/Dart/Swift dependencies | Test asserting zero HTTP calls to `api.deps.dev` for those three ecosystems |
| SC-005 | A second `trust_signal` call for the same package/version within the TTL memo window issues zero HTTP requests | Test asserting a mock endpoint hit-count of 1 across two calls (replaces the original ETag/304-based criterion — deps.dev has no cache validators, live-verified 2026-09-03; see NFR-002) |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps_core::HttpCache`'s transport (online/HTTPS/DNS-guard/body-limit/origin-pinned-redirect policy) and `deps_core::net_policy` host classification (FR-007, FR-008) rather than introducing a parallel HTTP client; cache the assembled signal via an in-process TTL memo, not a parallel entry-body cache (FR-007, NFR-002).
- Treat every deps.dev call as independently failable (FR-004, FR-006) — a Scorecard failure must never suppress an already-successful provenance result, and vice versa.
- Add the new `DepsDevVersionInfo`/`DepsDevScorecard`/etc. types to a dedicated module rather than embedding deps.dev-specific fields into any existing ecosystem crate's registry-response types (NFR-006).
- Validate `projectKey.id` before interpolating it into a request path (untrusted, third-party-controlled text) — reject anything that is not a clean `/`-separated, non-dot-segment, `[A-Za-z0-9._-]` host-like path before percent-encoding it as one path segment.

### Ask First
- Any change to `deps_core::net_policy`'s trusted-origin classification mechanism to accommodate a fixed, non-workspace-configurable third-party API endpoint, if the existing mechanism does not already support this cleanly.

### Never
- Duplicate `licenses[]`, `isDeprecated`, or `advisoryKeys[]` from deps.dev when deps-lsp already sources this data natively per-ecosystem (Out of Scope, FR-009).
- Block, delay, or degrade any existing hover content on a deps.dev failure (FR-006).
- Attach any credential, cookie, or workspace-derived value to a deps.dev request (NFR-005) — it is keyless by design.
- Escalate a Scorecard score into a diagnostic or blocking behavior (FR-012) — informational-only, permanently, for this spec's scope.
- Introduce a new diagnostic or inlay-hint category for this signal (FR-010) — hover-only.

## 9. Open Questions

All open questions were resolved 2026-09-03 during `/sdd specify` review; none remain.

- **Hover-only vs. new diagnostic/inlay-hint category** (FR-010) — resolved:
  hover-only. A diagnostic/inlay-hint surface is deferred to a future spec if
  ever justified by user demand.
- **Composer/Dart/Swift treatment** (FR-011) — resolved: silent omission,
  identical to any other ecosystem/package lacking data. No explicit "not
  available" line, keeping the UI/messaging surface minimal.
- **Low-score escalation** (FR-012) — resolved: informational-only,
  permanently, matching the [[004-release-freshness-signal/spec|004]]
  precedent. Any future escalation to a diagnostic requires a separate spec.
- **Scorecard data TTL / revalidation cadence** (NFR-002) — originally
  resolved to reuse `HttpCache`'s ETag-revalidate model as-is; **superseded**
  2026-09-03 during `/sdd plan` (D1) once live verification showed deps.dev
  sends no `ETag`/`Last-Modified` on either endpoint, so that model cannot
  apply to this API at all. Current resolution: an in-process TTL memo over
  the assembled signal (1 h success / 90 s error), see NFR-002 and FR-007.
- **Scorecard aggregate computation** (FR-003) — resolved via live
  verification 2026-09-03: deps.dev's `scorecard.overallScore` field is a
  top-level pass-through value (confirmed present in the API response, e.g.
  `8.5` for `github.com/expressjs/express`); deps-lsp does not compute its
  own aggregate from `checks[].score`.

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; cross-check against `.claude/rules/*.md` instead)
- [[MOC-specs]] — all specifications
- [[004-release-freshness-signal/spec|004-release-freshness-signal]] — precedent for "informational signal, not a diagnostic" applied to a supply-chain-risk-adjacent hover addition; directly relevant to FR-012's open question
- [[010-license-hover-policy/spec|010-license-hover-policy]] — precedent for adding a new informational hover section end-to-end (formatting, policy, `EcosystemFormatter` integration points)
- [[011-deprecation-replacement-diagnostics/spec|011-deprecation-replacement-diagnostics]] — the deprecation-signal precedent this spec's Out of Scope explicitly avoids duplicating from deps.dev
- [[002-osv-vulnerability-diagnostics/spec|002-osv-vulnerability-diagnostics]] — the vulnerability-signal precedent this spec's Out of Scope explicitly avoids duplicating from deps.dev
- `.local/testing/playbooks/competitive-parity.md` — deps.dev API v3 Reference Projects entry ("data source, not competitor", checked 2026-08-23), listing the fields this spec now acts on
- `crates/deps-core/src/cache.rs` — `HttpCache`; this feature reuses its transport/policy layer only, not its ETag/Last-Modified conditional-GET cache (deps.dev sends no validators — FR-007, NFR-002)
- `crates/deps-core/src/net_policy.rs` — `HostClass`, `classify_host`, trusted-origin classification (FR-008)
- `crates/deps-core/src/lsp_helpers/formatter.rs` — `EcosystemFormatter`, the hover-formatting integration point a future plan would extend
- [deps.dev](https://deps.dev) — the project homepage
- [deps.dev API v3 documentation](https://docs.deps.dev/api/v3/) — `GET /v3/systems/{system}/packages/{name}/versions/{version}` and `GET /v3/projects/{project-key}` endpoints this spec is built against
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) — the upstream project defining the checks deps.dev's `scorecard` object reports

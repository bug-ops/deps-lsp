---
aliases:
  - Typosquat Similarity Diagnostic
  - deps.dev GetSimilarlyNamedPackages
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
  - "[[010-license-hover-policy/spec]]"
  - "[[011-deprecation-replacement-diagnostics/spec]]"
  - "[[025-osv-fix-target-scan-gap/spec]]"
---

# Feature: Typosquat detection via deps.dev's `GetSimilarlyNamedPackages` endpoint

> [!info] Metadata
> **Author**: continuous-improvement research cycle, researcher stream (2026-09-25)
> **Branch**: none yet — research/spec-only, no implementation branch
> **Type**: research / enhancement (security-adjacent capability gap)

## 1. Overview

### Problem Statement

Typosquatting — publishing a malicious package under a name that closely resembles a popular one
(`crossenv` vs `cross-env`, `python3-dateutil` vs `python-dateutil`, lookalikes of `discord.js`) — is a
well-documented supply-chain attack vector across npm, PyPI, RubyGems, and crates.io. `deps-lsp` already
surfaces several security-posture signals for a project's declared dependencies — OSV vulnerability
diagnostics ([[002-osv-vulnerability-diagnostics/spec|#002]]), deprecation/replacement hints
([[011-deprecation-replacement-diagnostics/spec|#011]]), license-policy diagnostics
([[010-license-hover-policy/spec|#010]]), and OpenSSF Scorecard / SLSA-provenance trust signals via the
existing `deps.dev` integration (`crates/deps-core/src/deps_dev/mod.rs`, issue #543) — but has **no signal
of any kind for whether a declared dependency's name itself might be a typosquat of a more popular
package**.

deps.dev shipped a new `GetSimilarlyNamedPackages` endpoint in its v3alpha API
([announcement](https://blog.deps.dev/api-v3/), [reference](https://docs.deps.dev/api/v3alpha/), June
2026): `GET /v3alpha/systems/{system}/packages/{name}:similarlyNamedPackages`, returning the canonical
`packageKey` plus a `packages[]` array of similarly-named packages. deps.dev's own docs describe the
relation only as "computed by deps.dev," publish no algorithm or threshold, and explicitly state it "is not
necessarily a symmetric relation, as we take into account popularity when calculating similar names." That
popularity-weighting is exactly the shape a typosquat detector needs — a typosquat is a low-popularity name
similar to a high-popularity one — but the endpoint's own documentation does **not** frame it as a
security/typosquatting tool; it is presented as a generic similarity lookup. Applying it to typosquat
detection is deps-lsp's own novel use of the data, not something deps.dev already positions this way.

`GetSimilarlyNamedPackages`'s `system` parameter accepts `GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET` —
exactly the same seven-ecosystem set `deps-lsp` already has a compile-time-exhaustive mapping for in
`deps_dev_system()` (`crates/deps-core/src/deps_dev/mod.rs`), built for the existing Scorecard/SLSA feature
(issue #543). The remaining seven `deps-lsp` ecosystems — Deno, Dart, Gradle, Swift, Composer, GitHub
Actions, GitLab CI/CD — have no coverage because deps.dev does not track those package systems at all;
`deps_dev_system()` already returns `None` for all of them today, so this feature inherits that exclusion
for free rather than needing new ecosystem-gating logic.

A codebase grep for existing "typosquat" references (`crates/deps-core/src/lsp_helpers/formatter.rs:651`,
`crates/deps-core/src/registry.rs:811`, `crates/deps-core/src/lsp_helpers/code_actions.rs:295`,
`crates/deps-npm/src/types.rs:150`, `crates/deps-npm/src/formatter.rs:226`) confirms all of them concern a
**different, defensive** concern from issue #205: refusing to synthesize a package-rename quickfix target
from regex-extracted free text, because *that itself* could become a typosquatting vector. None of them
address warning the user that one of their *own declared dependencies* might itself be a typosquat. A
search of open and closed GitHub issues (`gh issue list --search "typosquat"`, `--search "similarly
named"`, `--search "deps.dev"`) returns no prior issue on this topic.

### Goal

For a project's direct dependencies declared in one of the seven deps.dev-covered ecosystems, `deps-lsp`
can optionally query `GetSimilarlyNamedPackages` and, when the declared package is a low-popularity result
that deps.dev reports as asymmetrically "similar to" a materially more popular package, surface a
low-severity signal (diagnostic and/or hover note) inviting the user to double-check the dependency —
without generating noisy false positives on legitimate, intentionally-similarly-named packages (e.g.
`serde` vs `serde_json`, monorepo/scoped-package families).

### Out of Scope

- Any ecosystem deps.dev does not track (Deno, Dart, Gradle, Swift, Composer, GitHub Actions, GitLab
  CI/CD) — no data source exists; not deferred, structurally impossible until/unless deps.dev adds
  coverage.
- Transitive/lockfile-resolved dependencies — v1 scope is manifest-declared **direct** dependencies only,
  consistent with how `deps-lsp` scopes other per-manifest diagnostics.
- Any automatic remediation action (quickfix, auto-uninstall, auto-rename) — per the existing
  `supports_package_rename` precedent (issue #205), a *similarity* signal from an undocumented black-box
  algorithm is far weaker evidence than a registry-supplied structured replacement field, so no
  code-action / rename quickfix is proposed by this spec at all, opt-in or otherwise.
- The exact similarity/popularity-gap threshold, caching/TTL strategy, and diagnostic-vs-hover channel are
  `/sdd plan`-phase design decisions — see [[plan]] for the resolved values (summarized in §9 below).
- Any change to `deps_dev_system()` or the existing Scorecard/SLSA trust-signal feature — this is an
  additive, independent use of the same client/mapping, not a modification of issue #543's delivered
  behavior.

## 2. User Stories

### US-001: Warn on a suspiciously similar low-popularity dependency

AS A developer reviewing or maintaining a project's dependency manifest
I WANT deps-lsp to flag a declared dependency whose name deps.dev reports as unusually similar to a
much more popular package
SO THAT I notice a possible typosquat (my own typo, a copy-pasted typo, or a malicious package) before it
ships to production

**Acceptance criteria:**
```
GIVEN a Cargo.toml declares a dependency named "reqwestt" (hypothetical typosquat of the popular "reqwest")
WHEN deps-lsp resolves the dependency's manifest position and queries deps.dev's GetSimilarlyNamedPackages
  for "reqwestt" on the "cargo" system
AND deps.dev returns "reqwest" in packages[] with a popularity gap exceeding the feature's threshold
THEN deps-lsp surfaces a low-severity signal referencing "reqwest" as the likely intended package,
  distinct in wording and severity from an OSV vulnerability diagnostic
```

### US-002: No noise for legitimate similarly-named packages

AS A developer with dependencies like `serde` and `serde_json`, or a monorepo package family, declared
together
I WANT deps-lsp to not flag these as typosquat suspects
SO THAT the signal stays trustworthy and I don't start ignoring it

**Acceptance criteria:**
```
GIVEN a package.json declares both "react" and "react-dom"
WHEN deps-lsp queries GetSimilarlyNamedPackages for "react-dom"
AND deps.dev's response does not show a large popularity asymmetry consistent with a typosquat pattern
  (both are independently popular, official packages)
THEN deps-lsp does not surface a typosquat signal for either package
```

### US-003: Graceful degradation when the v3alpha endpoint is unavailable or errors

AS A developer using deps-lsp
I WANT a deps.dev outage, timeout, 404, or v3alpha endpoint deprecation to never block or degrade
unrelated hover/diagnostic functionality
SO THAT this best-effort security signal never becomes a reliability liability

**Acceptance criteria:**
```
GIVEN deps.dev's GetSimilarlyNamedPackages endpoint times out, returns a non-2xx status, or is removed/
  changed incompatibly (v3alpha has no stability guarantee)
WHEN deps-lsp attempts the similarity lookup for a declared dependency
THEN the dependency's other diagnostics/hover content (vulnerabilities, license, freshness, Scorecard)
  are generated normally, and no typosquat signal is shown for that dependency
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a manifest-declared direct dependency belongs to one of the seven ecosystems `deps_dev_system()` already maps (Cargo, npm, PyPI, Go, Bundler, Maven, NuGet) THE SYSTEM SHALL be capable of querying deps.dev's `GetSimilarlyNamedPackages` endpoint for that dependency's name | must |
| FR-002 | WHEN a dependency belongs to an ecosystem `deps_dev_system()` maps to `None` (Deno, Dart, Gradle, Swift, Composer, GitHub Actions, GitLab CI/CD) THE SYSTEM SHALL skip the similarity lookup entirely for that dependency, with no attempted request | must |
| FR-003 | WHEN `GetSimilarlyNamedPackages` returns a `packages[]` entry whose `GetDependents`-derived popularity is materially higher than the declared dependency's own (exact metric and threshold: see [[plan#3. Data Model\|plan.md]]) THE SYSTEM SHALL treat that entry as a typosquat-suspect candidate | must |
| FR-004 | WHEN a typosquat-suspect candidate is identified for a declared dependency THE SYSTEM SHALL surface a signal that names the more-popular candidate package, distinguishable from OSV/license/deprecation diagnostics in severity and message framing (this is a *possible* mistake, not a confirmed vulnerability) | must |
| FR-005 | WHEN the `GetSimilarlyNamedPackages` request fails (network error, timeout, non-2xx, malformed JSON, or the endpoint no longer exists) THE SYSTEM SHALL degrade to showing no typosquat signal for that dependency, without raising an error and without blocking any other hover/diagnostic content — mirroring the existing infallible-by-construction pattern in `DepsDevClient::trust_signal` | must |
| FR-006 | WHEN a dependency's declared name is an exact match for the canonical `packageKey` deps.dev returns (i.e. the package is not itself flagged as the low-popularity side of any pair) THE SYSTEM SHALL NOT surface a typosquat signal for it | must |
| FR-007 | WHERE this feature is enabled, THE SYSTEM SHALL apply it only to direct dependencies parsed from a manifest, not to transitive/lockfile-resolved dependencies | must |
| FR-008 | THE SYSTEM SHALL reuse the existing `deps_dev` module's transport (`HttpCache`'s HTTPS enforcement, DNS guard, body cap, origin-pinned redirects) rather than introducing a second HTTP client path for deps.dev | must |
| FR-009 | WHERE a user or workspace wants to disable this signal (e.g. due to false-positive tolerance, or distrust of an alpha algorithm) THE SYSTEM SHALL provide an opt-out/opt-in configuration switch, consistent with how other optional signals (e.g. license policy) are configured | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reliability | A `GetSimilarlyNamedPackages` failure or v3alpha removal must never propagate as a user-visible error or delay other diagnostics/hover content — same infallible-by-construction bar as the existing `deps_dev::trust_signal` (FR-006 of issue #543's spec). |
| NFR-002 | Performance | Resolving one dependency's signal is a fan-out of up to `2 + 2N` deps.dev requests (`GetSimilarlyNamedPackages`, `GetPackage` + `GetDependents` for the declared package, then the same pair per candidate `N`) — see [[plan#1. Architecture\|plan.md]]. None of this may add synchronous latency to hover/diagnostic response paths; it must be spawned/cached the same way the existing Scorecard/SLSA lookups are, per `deps-lsp`'s non-blocking-handler convention (`CLAUDE.md`: "All handler methods must stay non-blocking"). |
| NFR-003 | Precision / noise control | The false-positive rate for legitimate similarly-named or family packages (e.g. `serde`/`serde_json`, scoped npm packages) must be low enough that the signal remains trustworthy; exact target is an open design question (see below) but "must not fire on `serde` vs `serde_json`"-class cases is a hard constraint on any threshold chosen in the plan phase. |
| NFR-004 | Forward compatibility | Because `GetSimilarlyNamedPackages` is v3alpha with no published stability guarantee, the client must be isolated behind the same kind of graceful-degradation boundary as the rest of `deps_dev` so an incompatible upstream change degrades to "feature silently stops firing," not a build or runtime failure. |
| NFR-005 | Caching | Given the algorithm is undocumented and the endpoint has no stated cache-control validators (`deps_dev`'s existing module doc already notes deps.dev sends no `ETag`/`Last-Modified` on its other endpoints), a TTL-memo approach consistent with `DEPS_DEV_SUCCESS_TTL`/`DEPS_DEV_ERROR_TTL` should be reused rather than re-deriving new caching semantics from scratch. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `SimilarPackageCandidate` (new) | One `packages[]` entry from a `GetSimilarlyNamedPackages` response, paired with the queried package's own key | canonical package name/system of the candidate, the queried package's name/system, whatever popularity signal is used to judge the asymmetry (metric TBD in plan phase) |
| `TyposquatSignal` (new) | The user-facing outcome for one declared dependency, if a candidate clears the threshold | declared dependency name, suspected-intended package name, confidence/severity framing |

No changes to existing `deps_dev` types (`DepsDevProject`, `DepsDevVersionInfo`, `ScorecardSummary`,
`SupplyChainTrustSignal`) are anticipated — this is an additive sibling capability on the same client, not
a modification of the existing trust-signal assembly.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Dependency's ecosystem is not one of the seven deps.dev-covered systems | Lookup skipped entirely, no request made (FR-002) |
| `GetSimilarlyNamedPackages` returns an empty `packages[]` | No signal shown; not an error |
| `GetSimilarlyNamedPackages` returns 404 (unknown package name) | No signal shown; treated the same as the existing deps.dev 404-as-authoritative-absence convention already used for the trust-signal cache (positive TTL, not error TTL) |
| v3alpha endpoint is removed or its response shape changes incompatibly upstream | Deserialization/request failure degrades to "no signal," consistent with FR-005; never a panic or propagated error |
| Two packages are mutually popular and deps.dev reports them as similar to each other (e.g. `requests` / `request`) | Symmetric-popularity case must not fire in either direction — this is exactly the popularity-asymmetry gate in FR-003/FR-006 |
| Declared dependency name exactly matches the response's own `packageKey` (i.e. deps.dev is describing what *other* packages are similar to this already-canonical, presumably-intended package) | No signal (FR-006) |
| User has disabled the feature via configuration | No request made, no signal shown (FR-009) |
| Same package name appears across multiple manifests/workspaces in one session | Should reuse the shared TTL-memo cache rather than re-querying per manifest occurrence (NFR-005) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | False-positive rate on a curated set of known legitimate similarly-named package pairs (`serde`/`serde_json`, `react`/`react-dom`, etc.) | Zero flags in the initial threshold, verified live before merge (per this project's live-testing gate) |
| SC-002 | Graceful degradation under simulated deps.dev outage/timeout/404 | No user-visible error, no delay to other diagnostics, verified live |
| SC-003 | Coverage of the seven applicable ecosystems | Feature exercised end-to-end (real manifest → real deps.dev call → signal or correctly-absent-signal) for at least Cargo, npm, and PyPI before wider ecosystem rollout |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps_dev_system()`'s existing exhaustive mapping rather than re-deriving ecosystem coverage
- Reuse `HttpCache`'s transport and the existing `deps_dev` TTL-memo pattern rather than introducing a new
  HTTP client or cache mechanism
- Keep this behind the same infallible-by-construction boundary as `DepsDevClient::trust_signal`

### Ask First
- Changing the resolved ratio threshold or `GetDependents`-based popularity comparison approach in
  [[plan]] once implementation begins (e.g. if live testing surfaces a false positive/negative the plan's
  empirical basis didn't anticipate)
- Flipping the opt-in default to on-by-default (explicitly deferred to a separate follow-up issue)

### Never
- Wire this signal into `supports_package_rename` or any automatic rename/quickfix — the similarity
  algorithm is an undocumented black box, materially weaker evidence than the structured-registry-field
  bar that gate already enforces (issue #205)
- Depend on `GetSimilarlyNamedPackages` in a way that would fail the build or a non-security code path if
  the v3alpha endpoint disappears or changes shape

## 9. Open Questions

All five items below were open at spec-authoring time and are now resolved; see [[plan#1. Architecture|plan.md]] for the full technical detail behind each decision.

- ~~What popularity metric and threshold determines "materially more popular"?~~ **Resolved**:
  `GetSimilarlyNamedPackages` itself carries no popularity field (verified live against the v3alpha API,
  2026-09-25) — popularity is derived from a second call to deps.dev's `GetDependents` endpoint, comparing
  `dependentCount` for the declared package's default version against each candidate's default version. A
  live empirical check against real deps.dev data found a >150x separation between confirmed typosquat pairs
  (`cross-env`/`crossenv` ≈300x, `express`/`expres` ≈1490x, `lodash`/`loadash` ≈1235x,
  `request`/`requests` ≈3000x) and the closest known false-positive-risk pair found
  (`coffee-script`/`coffeescript` ≈6.9x, both legitimate). See [[plan#3. Data Model|plan.md]] for the chosen
  ratio threshold and its margin.
- ~~Is a v3alpha-only endpoint acceptable for a shipped feature?~~ **Resolved**: ship behind an explicit
  opt-in flag at launch (default: disabled); revisit default-on only as a separate, deliberate follow-up
  issue once the endpoint has shown stability across multiple releases with no incompatible changes — not
  bundled into this feature's initial delivery.
- ~~Diagnostic severity/channel?~~ **Resolved**: an LSP diagnostic at `Severity::Hint`, reusing the existing
  typed `Severity` enum (`crates/deps-core/src/diagnostic.rs`) — visible in the Problems panel but clearly
  distinguished from `Warning`/`Error`-level OSV and unsatisfiable-requirement diagnostics. No hover-only
  variant in v1.
- ~~Opt-out config surface?~~ **Resolved**: a new field alongside the existing license-policy configuration
  (`crates/deps-core/src/policy_config.rs`, wired the same way as `config.policy.license_policy`), not a new
  top-level `initializationOptions` section — same parsing/validation path, already covered by existing
  config tests.
- ~~Caching key/TTL specifics?~~ **Resolved**: reuse `DEPS_DEV_SUCCESS_TTL`/`DEPS_DEV_ERROR_TTL` verbatim,
  but under a new cache key shape distinct from the existing `(system, name, version)` trust-signal memo —
  see [[plan#3. Data Model|plan.md]].

## 10. See Also

- [deps.dev API v3 announcement](https://blog.deps.dev/api-v3/) — introduces `GetSimilarlyNamedPackages`
- [deps.dev v3alpha API reference](https://docs.deps.dev/api/v3alpha/) — endpoint definition, `system`
  enum, response shape, and the "not necessarily symmetric... popularity" wording this spec builds on
- Issue #543 — existing `deps.dev` v3 integration (OpenSSF Scorecard / SLSA provenance), the precedent this
  feature extends: same client, same `deps_dev_system()` seven-ecosystem mapping, same infallible-by-
  construction degradation pattern
- Issue #205 — `supports_package_rename` / regex-extracted-replacement typosquatting rationale, the reason
  this spec explicitly excludes any auto-rename action from scope
- [[010-license-hover-policy/spec]] — precedent for an optional, policy-gated security-adjacent diagnostic
- [[025-osv-fix-target-scan-gap/spec]] — another deps.dev/OSV-adjacent research spec with open
  `[NEEDS CLARIFICATION]` items awaiting `/rust-team` pickup
- [[MOC-specs]] — all specifications

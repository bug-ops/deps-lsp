---
aliases:
  - Gradle deps.dev routing
  - Gradle supply-chain signals parity
tags:
  - sdd
  - spec
  - research
  - parity
  - deps-core
  - deps-gradle
  - supply-chain
created: 2026-10-06
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[037-supply-chain-trust-signal/spec]]"
  - "[[071-typosquat-similarity-diagnostic/spec]]"
  - "[[072-deps-dev-gossip-signals/spec]]"
---

# Feature: Route Gradle through the deps.dev Maven system for supply-chain signal parity

> [!info] Metadata
> **Author**: rust-researcher (research session, 2026-10-06)
> **Branch**: N/A (research finding, no implementation branch)
> **Priority**: P4 (cross-ecosystem consistency gap; no user-visible breakage, signals are silently absent)
> **Issue**: [NEEDS CLARIFICATION: GitHub issue number once filed]

## 1. Overview

### Problem Statement

deps-lsp resolves a deps.dev "system" per ecosystem through `deps_dev_system(EcosystemId)`
(`crates/deps-core/src/deps_dev/mod.rs`). Every deps.dev-driven feature gates on that mapping returning
`Some`: OpenSSF Scorecard and SLSA provenance (spec 037), deprecation, typosquat similarity (spec 071),
and GOSSIP cooldown/low-usage signals (spec 072), consumed from
`crates/deps-core/src/lsp_helpers/diagnostics.rs` and `lsp_helpers/hover.rs`. For
`EcosystemId::Gradle` the mapping returns `None`, so all of these are **silently skipped** for Gradle
dependencies, while the Maven ecosystem is covered, even though the two share the identical
`groupId:artifactId` coordinate format and the same Maven repositories.

The exclusion originates in spec 037's plan (section 7, decision D8: "Gradle and Deno-`npm:` excluded";
the plan described adding Gradle as "a one-line override") and was never revisited. Gradle's **license**
gap was closed separately (issues #660 and #1479) by a direct Maven POM fetch in
`crates/deps-gradle/src/license.rs`, whose module doc records the exclusion. That fetch yields license
data only; it provides no Scorecard, provenance, deprecation, typosquat, or GOSSIP signal.

Cross-ecosystem consistency is a first-class design rule of this project: a feature available for one
ecosystem and silently absent for an equivalent one is treated as a bug class. The Gradle gap is a
documented-but-stale exclusion rather than a deliberate product decision.

> [!info] Empirical evidence (live-verified 2026-10-06, keyless)
>
> | Probe | Result |
> |-------|--------|
> | `GET https://api.deps.dev/v3/systems/maven/packages/com.google.guava%3Aguava/versions/33.0.0-jre` | licenses `[Apache-2.0]`, SOURCE_REPO link, `isDeprecated`, `advisoryKeys`, `slsaProvenances` all present |
> | `GET .../systems/maven/packages/org.jetbrains.kotlin.jvm%3Aorg.jetbrains.kotlin.jvm.gradle.plugin/versions/2.0.0` | resolves a Gradle plugin marker artifact; registries `repo.maven.apache.org` and `plugins.gradle.org/m2/` |
> | `GET .../systems/maven/packages/com.gradle.enterprise%3Acom.gradle.enterprise.gradle.plugin` | lists versions back to 3.0 |
>
> deps.dev announced Gradle Plugins ecosystem support on 2025-09-11 (about 15k packages and 270k
> versions, to be treated "in the same manner as the existing Maven repositories"), so plugin marker
> artifacts are expected to be addressable through the `maven` system.

### Goal

Gradle dependencies receive the same deps.dev-derived supply-chain signals as Maven dependencies, or,
where a Gradle dependency shape cannot be mapped to a valid Maven package, an explicit documented
exclusion with reasons replaces today's silent skip.

### Out of Scope

- Changing the Gradle license path (`crates/deps-gradle/src/license.rs`, #660/#1479); its relationship to
  a deps.dev license source is an open question (OQ-6), not a change requested here.
- Plugin Portal fallback for the POM license fetch (already a documented follow-up in that module).
- Routing Deno, Composer, Dart, Swift, GitHub Actions or GitLab CI through deps.dev (separate
  ecosystem-coverage questions; Composer, Dart and Swift are not covered by deps.dev at all).
- Implementation design (variant naming, helper shape, test layout); that belongs in `plan`.
- Edits under `crates/deps-zed` (separate repository).

> [!note] Code-shape constraints to record, not prescribe
> `DepsDevSystem` is an exhaustive enum (seven variants, documented in `mod.rs`), and the test
> `deps_dev_system_covers_seven_ecosystems` pins the covered set. Any change to Gradle's mapping will
> touch the `deps_dev_system` match arm, the doc comment that names Gradle as excluded (and cites spec
> 037 plan D8), that test, and the module doc in `deps-gradle/src/license.rs`. The spec requires those
> to stay consistent; it does not prescribe how.

## 2. User Stories

### US-001: Scorecard and provenance for Gradle dependencies
AS A Gradle project developer using deps-lsp
I WANT OpenSSF Scorecard and SLSA provenance signals on my `build.gradle(.kts)` / version-catalog dependencies
SO THAT I get the same supply-chain trust information a Maven user already gets.

**Acceptance criteria:**
```
GIVEN a Gradle dependency "com.google.guava:guava" with supply-chain signals enabled
WHEN hover or diagnostics are generated
THEN Scorecard/provenance output is identical in shape to the Maven ecosystem's output for the same coordinate
```

### US-002: Deprecation, typosquat and GOSSIP parity
AS A Gradle project developer
I WANT deprecation, typosquat-similarity and GOSSIP (cooldown, low-usage) signals for Gradle dependencies
SO THAT opt-in features documented for "the supported ecosystems" do not silently skip my build tool.

**Acceptance criteria:**
```
GIVEN the opt-in typosquat or GOSSIP signal is enabled and a Gradle dependency maps to a valid Maven package
WHEN diagnostics are generated
THEN the signal is evaluated for that dependency exactly as it is for the equivalent Maven dependency
```

### US-003: Honest handling of unmappable shapes
AS A maintainer
I WANT Gradle dependency shapes that are not valid Maven `g:a` packages to be excluded explicitly
SO THAT enabling deps.dev for Gradle never produces lookups for malformed names, spurious 404 noise, or misleading "no data" states.

**Acceptance criteria:**
```
GIVEN a Gradle dependency whose coordinate cannot be expressed as a Maven groupId:artifactId pair
WHEN deps.dev-driven features run
THEN no deps.dev request is sent for it, and the behavior is documented rather than silent
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a deps.dev-driven feature (Scorecard, provenance, deprecation, typosquat, GOSSIP) is evaluated for a Gradle dependency that maps to a valid Maven package, THE SYSTEM SHALL query the deps.dev `maven` system and apply the same logic and output format as for a Maven dependency. | must |
| FR-002 | THE SYSTEM SHALL encode the Gradle-to-deps.dev mapping in `deps-core`'s shared `deps_dev_system` routing (single source of truth), not as per-crate logic in `deps-gradle`. | must |
| FR-003 | WHEN a Gradle dependency does not correspond to a valid Maven `groupId:artifactId` package (see OQ-2), THE SYSTEM SHALL NOT issue a deps.dev request for it. | must |
| FR-004 | WHEN deps.dev returns "not found" for a Gradle plugin that is not mirrored to Maven Central (see OQ-3), THE SYSTEM SHALL treat it as absent data, identical to the Maven ecosystem's not-found handling, and SHALL NOT emit a warning-level diagnostic or error. | must |
| FR-005 | THE SYSTEM SHALL apply the existing deps.dev opt-in gates, caching, timeouts, rate limiting, host policy and offline degradation to Gradle requests without a separate configuration surface. | must |
| FR-006 | WHEN Gradle is routed through the Maven system, THE SYSTEM SHALL update every comment or doc that names Gradle as deps.dev-excluded: the `deps_dev_system` doc comment (citing spec 037 plan D8), the `deps-gradle/src/license.rs` module doc, and any test or `README`/book text, and SHALL update the test pinning the covered-ecosystem set. | must |
| FR-007 | WHERE a Gradle dependency's Maven coordinate resolves against a repository deps.dev does not index (for example Google Maven for Android coordinates, see OQ-4), THE SYSTEM SHALL degrade to absent data without error. | must |
| FR-008 | THE SYSTEM SHALL keep the deps.dev signal behavior across `deps-lsp` and `deps-cli` (`check`) consistent for Gradle, per specs 037, 072 and 074. | should |
| FR-009 | WHEN user-visible behavior changes, THE SYSTEM SHALL record a one-line entry with the PR link in `CHANGELOG.md` `[Unreleased]`, and SHALL update the mdBook Ecosystem Reference (`book/src/ecosystems/`) for Gradle to list the newly available signals. | must |
| FR-010 | WHERE the decision is to keep Gradle excluded (OQ-1, option b), THE SYSTEM SHALL replace the stale "one-line override, not yet done" rationale with an explicit, reasoned exclusion in the `deps_dev_system` docs and the ecosystem reference. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Consistency | Gradle and Maven SHALL produce identical deps.dev-derived output for an identical `groupId:artifactId@version`; any divergence is a bug under the cross-ecosystem rule. |
| NFR-002 | Type safety | The mapping SHALL remain an exhaustive `match` over `EcosystemId` with no wildcard arm; Gradle SHALL stay named explicitly. Any shape-eligibility decision (FR-003) SHALL be expressed as a type or enum rather than a runtime string check or boolean flag. |
| NFR-003 | Performance | Hover and completion SHALL remain non-blocking: Gradle deps.dev lookups run in the existing background fetch path and are served from cache. |
| NFR-004 | Reliability | A deps.dev outage, 404, or rate-limit response for Gradle SHALL degrade to absent signals without affecting other diagnostics. |
| NFR-005 | Security | Gradle requests SHALL traverse the same host-policy and credential-redaction paths as other deps.dev requests; no new credential or host surface is introduced. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `EcosystemId::Gradle` | Exhaustive ecosystem identifier; currently mapped to no deps.dev system | maps to `Maven` system under option (a) |
| `DepsDevSystem` | Exhaustive enum of deps.dev systems, seven variants | `Maven` already present; no new variant expected under option (a) |
| Gradle dependency source shapes | Dependency forms parsed by `deps-gradle`: string/map notation in build scripts, version-catalog `libraries` and `plugins`, `plugins {}` block ids, settings plugin ids | only a subset is a valid Maven `g:a` (OQ-2) |
| Gradle plugin marker artifact | Maven coordinate `<plugin-id>:<plugin-id>.gradle.plugin` (live-verified resolvable via deps.dev `maven` system for at least two plugins) | plugin id to marker mapping rule is unverified for all shapes |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Plain `group:artifact:version` library | Signals as for Maven (FR-001) |
| Version-catalog `libraries` entry (`module = "g:a"` or `group`/`name` form) | Mapped to the Maven package when both parts are present and valid (OQ-2) |
| Version-catalog `plugins` entry or `plugins { id("...") }` block | Eligible only if the plugin id maps to a marker artifact (OQ-2, OQ-3) |
| Plugin-portal-only plugin not mirrored to Maven Central | deps.dev may 404; absent data, no warning (FR-004, OQ-3) |
| Android/Firebase coordinates (`androidx.*`, `com.google.firebase.*`, Google Maven) | Coverage by deps.dev unverified; absent data without error (FR-007, OQ-4) |
| Dynamic or non-pinned versions (`1.+`, `latest.release`, ranges) | Same handling as Maven's non-concrete versions; version-keyed signals skipped, package-level signals unaffected (OQ-5) |
| Project/`files()`/`gradleApi()` or other non-registry dependency | No request (FR-003) |
| Gradle dependency name with a template/`$variable` placeholder | No request; reuses existing placeholder guards (spec 069/070) |
| deps.dev unreachable | Absent signals, no error surfaced (NFR-004) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live Gradle hover/diagnostic parity with Maven for a fixed set of reference coordinates (guava, okhttp, a Kotlin plugin, a Gradle Enterprise plugin) | 100% identical signal shape |
| SC-002 | deps.dev requests sent for Gradle shapes classified as unmappable | 0 |
| SC-003 | Stale "Gradle excluded from deps.dev" statements remaining after the change | 0 |
| SC-004 | New warnings/errors in the debug log (`WARN`/`ERROR`) for Gradle plugin 404s | 0 |
| SC-005 | Gradle-specific copies of deps.dev routing logic outside `deps-core` | 0 |

## 8. Agent Boundaries

### Always (without asking)
- Verify deps.dev behavior with live keyless requests and a live LSP run on real `build.gradle(.kts)` and `libs.versions.toml` manifests before concluding.
- Keep the routing decision in `deps-core`'s `deps_dev_system` and keep the match exhaustive.
- Update stale doc/test statements about Gradle's exclusion together with any behavior change.

### Ask First
- Choosing between "route Gradle to the Maven system" and "keep excluded with documented reasons" (OQ-1).
- Adding any new `DepsDevSystem` variant (for example a Gradle-plugin-specific system) or changing its shape.
- Changing the Gradle license-fetch path in favor of deps.dev data (OQ-6).

### Never
- Edit source code as part of the continuous-improvement research session that produced this spec.
- Add a wildcard arm to `deps_dev_system` or `match` on `EcosystemId`.
- Reimplement deps.dev routing inside `crates/deps-gradle`.
- Touch files under `crates/deps-zed`.

## 9. Open Questions

> [!question] Open items (6)
> Resolve before moving to `plan`.

- [NEEDS CLARIFICATION: OQ-1 Route or exclude? Research recommendation: route Gradle to the Maven system (option a): identical coordinate format, live evidence of coverage including plugin markers, and deps.dev's 2025-09-11 announcement of Gradle Plugins coverage in the same manner as Maven repositories. Option (b) keep excluded is acceptable only with a documented reason (FR-010). Confirm.]
- [NEEDS CLARIFICATION: OQ-2 Which Gradle dependency shapes map to a valid Maven package name? Library coordinates are straightforward; catalog `plugins` entries, `plugins {}` block ids, settings-level plugin ids, and `id` + `version.ref` forms may need a plugin-id to `<id>:<id>.gradle.plugin` marker translation, or may be unmappable. This must be enumerated against the shapes `deps-gradle` actually parses, and verified live per shape, before deciding eligibility.]
- [NEEDS CLARIFICATION: OQ-3 Plugin-portal-only plugins that are not mirrored to Maven Central may 404 on deps.dev. How common are they among the plugins Gradle projects actually use, and is absent-data degradation (FR-004) sufficient, or should such plugins be excluded up front? Needs a live sample of popular plugins.]
- [NEEDS CLARIFICATION: OQ-4 Does deps.dev index Google Maven (`androidx.*`, `com.google.firebase.*`, `com.google.android.*`, `com.android.*`)? Maven is routed today, so this gap, if real, already exists for Maven; confirm whether it matters for parity and whether it warrants a note in the ecosystem reference.]
- [NEEDS CLARIFICATION: OQ-5 Version semantics: which Gradle version forms (strict, `[1.0,2.0)`, `1.+`, `latest.release`, rich versions in catalogs) are valid inputs for version-keyed deps.dev lookups (provenance, GOSSIP cooldown), and does the Maven ecosystem's existing handling transfer unchanged?]
- [NEEDS CLARIFICATION: OQ-6 Should the license path (`crates/deps-gradle/src/license.rs`, direct POM fetch from #660/#1479) stay as is once Gradle is deps.dev-routed, be superseded by deps.dev license data, or serve as fallback when deps.dev has no record (for example Google Maven coordinates)? Avoid two divergent license sources for one coordinate.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[037-supply-chain-trust-signal/spec]] — original deps.dev supply-chain signal spec; [[037-supply-chain-trust-signal/plan]] section 7 decision D8 excluded Gradle ("one-line override")
- [[071-typosquat-similarity-diagnostic/spec]] — typosquat similarity via deps.dev (issue #1437)
- [[072-deps-dev-gossip-signals/spec]] — GOSSIP cooldown/low-usage signals (issue #1456)
- [[073-gradle-package-completion-colon-solr-query/spec]] — Gradle/Maven shared coordinate handling precedent
- Issues: #660 (Gradle license via POM fetch), #1479 (Google Maven routing for the Gradle license fetch), #1456 (GOSSIP), #1437 (typosquat)
- `crates/deps-core/src/deps_dev/mod.rs` — `deps_dev_system`, `DepsDevSystem`, test `deps_dev_system_covers_seven_ecosystems`
- `crates/deps-core/src/lsp_helpers/diagnostics.rs`, `lsp_helpers/hover.rs` — deps.dev consumers gated on the mapping
- `crates/deps-gradle/src/license.rs` — Gradle license fetch whose module doc states the exclusion
- deps.dev blog: [Gradle Plugins support](https://blog.deps.dev/gradle-plugins) (2025-09-11)
- [deps.dev API v3](https://docs.deps.dev/api/v3/) — `systems/maven/packages/{name}/versions/{version}`

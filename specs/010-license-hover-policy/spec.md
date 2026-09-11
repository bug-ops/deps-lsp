---
aliases:
  - License Display and Policy Diagnostics
  - SPDX License in Hover
tags:
  - sdd
  - spec
  - research
  - parity-gap
  - priority/p4
created: 2026-08-23
status: shipped
related:
  - "[[MOC-specs]]"
  - "[[plan]]"
---

# Feature: License in hover + optional license-policy diagnostics

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: `feat/204-license-hover-policy`
> **Type**: research / competitive-parity gap — this spec documents WHAT is missing and WHY;
> the HOW (license fetching, caching, policy engine) is resolved in [[plan]].

## 1. Overview

### Problem Statement

deps-lsp surfaces no license information for dependencies. This is the single most-requested
open feature on the tracker of the closest competitor — Dependi #68 "Missing license" has
13 reactions, 2× their next-highest request — and is still unaddressed there, representing a
clear differentiation window. Red Hat Dependency Analytics ships license-compatibility
diagnostics on by default. Every major package manager and update bot (Dependabot, Renovate,
npm CLI, pip/uv, cargo) surface license information; VS Code Version Lens, crates.nvim, and
cargo-appraiser all expose it in-editor.

Most registries already expose license in their payloads (crates.io, npm, PyPI, pub.dev,
Packagist, NuGet). For ecosystems where the native registry lacks license in the hot-path
metadata endpoint (e.g., cargo's sparse index does not include license; npm's abbreviated
packument dropped it in favor of size optimization), deps.dev API v3 (free, keyless, no rate
limit per request) provides per-version SPDX `licenses[]` for npm/Cargo/Go/Maven/PyPI/RubyGems/NuGet
(but not Composer/Dart/Swift, which must fall back to registry-native license fields).

### Goal

deps-lsp displays license information (SPDX expression) in the hover content for each dependency,
for both the currently resolved version and the latest available version. A secondary, optional
phase allows configuration of an SPDX policy (allow-list or deny-list of license identifiers)
that triggers diagnostics when a dependency's license does not comply — similar to `cargo deny
licenses` but cross-ecosystem and inline in the editor.

### Out of Scope

- Full dependency-tree license aggregation (e.g., "all my transitive deps combined use X
  distinct licenses") — scope is per-dependency only.
- Legal advice or compatibility matrices (e.g., "MIT is compatible with my project's Apache
  2.0 license") — RHDA and Snyk do this; deps-lsp only surfaces the data for user judgment.
- SBOM export (CycloneDX, SPDX) — separate, complementary feature tracked elsewhere.
- Precise field names, license-field order, or hover formatting (bold/italic) — these are HOW
  decisions for `/sdd plan`.
- Ecosystem-specific license-field names or alternate SPDX sources beyond deps.dev fallback —
  this spec describes the generic approach; ecosystem-specific registry-field mapping is a plan
  detail.

## 2. User Stories

### US-001: See the license when hovering a dependency

AS A developer working with dependencies in a manifest file (e.g., `Cargo.toml`, `package.json`)
I WANT to hover over or view the package name and see the license (SPDX expression) of both
  the current pinned version and the latest available version
SO THAT I understand the license implications of a dependency without leaving the editor or
  consulting an external registry.

**Acceptance criteria:**
```
GIVEN an open manifest file with a declared dependency
WHEN the user hovers over the dependency name or version field
THEN the hover content SHALL include the license (SPDX expression or human-readable identifier)
     for both the resolved/current version and the latest available version
AND IF the license differs between current and latest, the hover SHALL flag this change
     (e.g., "License changed: MIT → Apache-2.0")
```

### US-002: Detect policy violations (optional, opt-in)

AS A developer using an organization-wide or project-level SPDX policy (e.g., "deny GPL-3.0,
  AGPL-3.0; only allow MIT, Apache-2.0, ISC")
I WANT the editor to flag dependencies that violate this policy
SO THAT I catch license-compliance issues before they reach CI or production.

**Acceptance criteria:**
```
GIVEN a user-provided policy (via initializationOptions or workspace config) listing
     allowed/denied SPDX identifiers
WHEN parsing a manifest with dependencies whose licenses are known
THEN the system SHALL produce a diagnostic (warning or error, per config) at the manifest line
     for any dependency whose license does NOT match the allow-list or DOES match the deny-list
AND the diagnostic message SHALL include the package name, its license, and a short explanation
     (e.g., "serde-json: GPL-3.0 denied by policy")
```

### US-003: Consistent behavior across every supported ecosystem

AS A developer using deps-lsp with any of the 11 supported ecosystems (Cargo, npm, PyPI, Go,
  Bundler, Dart, Maven, Composer, Gradle, Swift, NuGet)
I WANT license information to appear in the same format and location (in the hover) regardless
  of which manifest format I'm editing
SO THAT I don't have to learn ecosystem-specific patterns in how license is displayed.

**Acceptance criteria:**
```
GIVEN two open manifests from different ecosystems (e.g., Cargo.toml and package.json), each
     with dependencies whose licenses are retrievable
WHEN the user hovers over equivalent dependency declarations in each
THEN the license field format, position in the hover, and "license changed" signaling SHALL be
     identical across both ecosystems, per the project's cross-ecosystem-consistency rule
     (`.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing`)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the server receives a hover request for a dependency THE SYSTEM SHALL retrieve or already have in cache the license information (SPDX expression or identifier) for the resolved version and the latest available version | must |
| FR-002 | THE SYSTEM SHALL include license information in the hover content for each dependency (format: "License: <SPDX>" or similar) — the exact layout/formatting is a `/sdd plan` detail | must |
| FR-003 | IF the license differs between the resolved version and the latest version THE SYSTEM SHALL flag this in the hover (e.g., "License changed: <old> → <new>") so the user is alerted to the change | should |
| FR-004 | THE SYSTEM SHALL fetch license information from the package's native registry when it is already present in the response hover already fetches (verified live: PyPI, Composer); **RESOLVED (2026-09-08, see [[plan#1-architecture]])** — this is "tier 1" of the plan's three-tier fetch strategy | must |
| FR-005 | FOR ecosystems where the hot-path registry endpoint does NOT include license (crates.io sparse index, npm abbreviated packument, Go module proxy — all verified live to lack it), THE SYSTEM SHALL reuse the existing deps.dev `trust_signal()` call (tier 2, covers cargo/npm/go/maven/bundler/nuget — and is the *only* working source for Go) or, where deps.dev doesn't cover the ecosystem, pre-fetch via a background task into `DocumentState` (tier 3), without blocking the initial hover latency — **RESOLVED (2026-09-08, see [[plan#1-architecture]])** | must |
| FR-006 | FOR ecosystems without coverage in deps.dev (Composer, Dart, Swift) THE SYSTEM SHALL attempt to retrieve license from the native registry API (e.g., Packagist, pub.dev, SwiftPM index); if unavailable, the system SHALL display "License: (not found)" or similar gracefully | should |
| FR-007 | (Optional / Phase 2) IF the user provides a license policy via initializationOptions OR a project config file THE SYSTEM SHALL compute diagnostics at manifest lines for dependencies whose licenses violate the policy (deny-list or allow-list) | should |
| FR-008 | (Phase 2) THE SYSTEM SHALL allow policy configuration via `initializationOptions.license_policy: { allow?: string[], deny?: string[] }`, validated through the existing `parse_config` path; a workspace config file is explicit out-of-scope for v1 — **RESOLVED (2026-09-08, see [[plan#1-architecture]])** | should |
| FR-009 | THE SYSTEM SHALL produce equivalent license hover behavior (capability, field format, "license changed" signaling) across all 11 supported ecosystem crates, per the cross-ecosystem-consistency rule | must |
| FR-010 | WHEN a manifest is edited and dependencies change THE SYSTEM SHALL recompute license information on the next hover request (or per the existing document-change event pathway) rather than serving stale license data | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Hover latency SHALL NOT increase materially due to license fetching — if registry fetch is required for license, it SHALL be cached (per-version, TTL matching or exceeding the existing version-data cache) and SHOULD NOT block the initial hover response (lazy loading is acceptable, with a "Loading license..." placeholder) |
| NFR-002 | Performance | Hover response for a dependency with cached license information SHALL complete in the same order of magnitude as the existing hover latency (< 100ms target); [NEEDS CLARIFICATION: is this realistic if a secondary registry call is required?] |
| NFR-003 | Reliability | If license information is unavailable (registry error, not found in API response), the system SHALL NOT crash, log a panic, or fail the hover request — it SHALL degrade gracefully to "License: (unknown)" or omit the field, consistent with how diagnostics/inlay hints degrade today |
| NFR-004 | Consistency | License field format and hover content layout SHALL be identical across all 11 ecosystems — any ecosystem-specific divergence is a first-class bug per `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` |
| NFR-005 | Data Accuracy | SPDX license expressions MUST be preserved as-is from the registry (no normalization, translation, or manual curation) so that policy matching is deterministic |
| NFR-006 | Compatibility | Adding license information to hover SHALL NOT alter existing hover content (description, repository, documentation, version, outdated status, etc.) — it SHALL be additive only |

## 5. Data Model

No new persistent entities. License information is metadata attached to each version (same as
description, repository, etc.). This spec only describes adding license as a field; the storage
and caching strategy (in-memory, shared cache, per-document) is a `/sdd plan` detail.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Package License (derived) | SPDX expression or identifier for a specific package version | package name, version, license (SPDX string), source registry |
| License Policy (optional) | User-provided allow-list or deny-list of SPDX identifiers for compliance checking | allow: [SPDX identifiers], deny: [SPDX identifiers] — **RESOLVED (2026-09-08)**: both independently optional; if a license matches both, deny wins (see [[plan#1-architecture]]) |
| Policy Violation (derived) | Per-dependency diagnostic when its license does not match the policy | package name, version, license, policy-violation reason, manifest line |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| License field is missing from registry response | System SHALL degrade gracefully to "License: (unknown)" or omit the field; hover remains functional for other data (version, description, etc.) |
| Registry API is unreachable (offline, timeout, rate-limit) | System SHALL NOT block hover — if license cannot be fetched, it SHALL display "License: (unavailable)" or similar and log a debug/warn message; hover completes with other available data |
| License information exists for resolved version but not for latest version | Hover SHALL display resolved version's license and note "Latest version: (license unavailable)" for latest, consistent with graceful degradation |
| Resolved and latest versions have identical licenses | No "license changed" flag needed; hover simply shows "License: MIT" once or twice depending on display layout |
| Package has no latest stable version (all yanked, no published versions, unknown ecosystem) | Same graceful degradation as the existing "no latest version" case elsewhere in hover — **RESOLVED (2026-09-08)**: reuse the existing wording, no new sentinel string |
| User provides an invalid SPDX identifier in the policy (e.g., a typo) | **RESOLVED (2026-09-08)**: logged as one warning at config-load time, the invalid entry is dropped from the effective policy, no diagnostic is anchored to it (no document URI to anchor to for `initializationOptions`), see [[plan#1-architecture]] |
| Policy is empty (no allow-list and no deny-list) | No policy diagnostics SHALL be produced |
| Very large number of dependencies (100+, 1000+) with policy checking enabled | Policy-violation diagnostics SHALL be computed in-memory without blocking other LSP operations; caching ensures license lookups are not repeated per dependency (one lookup per version globally) |
| License changes between current and latest versions but user has not pinned to a specific version (e.g., `^1.0.0`) | The "license changed" flag SHALL apply to the latest version matching the requirement, consistent with how "outdated" is computed |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | License displayed in hover for resolved version | 100% of dependencies with available license data show it in hover |
| SC-002 | License displayed in hover for latest available version | 100% of dependencies with available license data for latest version show it in hover |
| SC-003 | "License changed" flag when current ≠ latest | Correctly identified in 100% of cases where license differs between resolved and latest versions |
| SC-004 | Cross-ecosystem consistency | License field format, position in hover, and "license changed" signaling verified equivalent across all 11 ecosystem manifest types in a live-testing session, logged in `.local/testing/coverage.md`'s LSP Feature Matrix |
| SC-005 | Graceful degradation | If license is unavailable for a dependency, hover remains functional and non-blocking (not blank, not panicked); verified in a live session with an offline registry or missing-data scenario |
| SC-006 | Policy diagnostics accuracy (if Phase 2 implemented) | Diagnostics produced for 100% of dependencies violating an allow-list or deny-list policy; false positives = 0 |
| SC-007 | No performance regression | Hover latency for a manifest with 50+ dependencies does not increase more than 20% vs. baseline (pre-license implementation) when license data is cached |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing patterns in `crates/deps-lsp/src/handlers/hover.rs` for hover content construction and
  delegate to ecosystem implementations where applicable.
- Reuse the existing `deps-core` caching infrastructure (HttpCache) for license fetches; do not
  introduce a parallel caching mechanism.
- Add license fields to the existing Metadata and/or Version traits in `crates/deps-core/src/registry.rs`
  rather than creating a separate license-only struct.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features
  --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering
  any implementation of this spec complete.

### Ask First
- Introducing a new registry API client distinct from deps.dev (e.g., a separate crate for fallback
  license fetches) vs. extending the existing ecosystem registry clients to handle license.
- Whether license should be a required field in the Metadata trait or optional (via an extension
  trait or a sub-trait).
- Any change to the hover-handler signature or VersionData struct that affects how license is
  threaded through the existing handler pipeline.
- Adding a new dependency to support SPDX parsing or policy matching, if deemed necessary.

### Never
- Modify the existing hover content for description, repository, documentation, or version fields
  as a side effect of adding license — those must remain unchanged.
- Introduce ecosystem-specific license hover behavior that diverges from the other 10 ecosystems
  without an explicit, documented rationale.
- Crash or panic if license information is unavailable — graceful degradation is mandatory.

## 9. Open Questions

All items below were resolved on 2026-09-08 during `/sdd plan`; see [[plan]] for full rationale.
Resolution was informed by live verification against the real registries (crates.io sparse index,
npm registry, PyPI JSON API, Packagist, pub.dev, Go module proxy), not by documentation alone —
this caught at least two incorrect assumptions in this spec's original drafting (Cargo's sparse
index does *not* carry license despite the original FR-004 wording implying it might; Go's module
proxy carries *no* license metadata at all, making deps.dev the only viable source for that
ecosystem).

- **RESOLVED**: Cargo sourcing — deps.dev (reuses the existing `trust_signal()` call), not a new
  crates.io secondary fetch. See [[plan#1-architecture]].
- **RESOLVED**: npm sourcing — deps.dev (same reuse), not a secondary npm fetch.
- **RESOLVED**: Non-deps.dev-covered ecosystems (Dart, Swift, Gradle, Deno) — per-ecosystem
  background pre-fetch into `DocumentState`, mirroring the existing OSV-scan pattern. Composer and
  PyPI need no secondary fetch at all — license is already in their existing hot-path response.
- **RESOLVED**: Fetch is eager where free (PyPI, Composer), reuses the existing bounded-wait
  pattern where deps.dev-covered, and is background-pre-fetched (never blocking hover) elsewhere.
- **RESOLVED**: Phase 2 config channel is `initializationOptions.license_policy`, validated via the
  existing `parse_config` path; a workspace config file is out of scope for v1.
- **RESOLVED**: Policy matching is exact top-level SPDX identifier set-membership, no expression
  operators, no new SPDX-parsing dependency.
- **RESOLVED**: No project `constitution.md` exists or is planned — this project governs via
  `.claude/CLAUDE.md` and `.claude/rules/*.md` instead (see `specs.md`); [[plan#10-constitution-compliance]]
  checks against those.

**New open item surfaced during planning** (not in the original spec):

- [NEEDS CLARIFICATION: Swift, Gradle, and Deno license sources were not live-verified during this
  planning session (only Cargo, npm, PyPI, Composer, Dart, and Go were checked). Given that 2 of
  the 6 ecosystems actually checked turned out to have surprising gaps (Cargo, Go), these three
  should not be assumed to work as documentation suggests — live-verify each against its real
  registry response before implementing its tier-3 fetch, per the project's Registry Integration
  Gate rule. Tracked as a task-level, not spec-blocking, item — see [[plan#1-architecture]] row
  "Swift / Gradle / Deno source".] — RESOLVED during PR #682's implementation (tier-3 license
  hover for Dart, Swift, Gradle, Deno shipped and live-verified).

**Shipped**: PR #663 (Phase 1, tier 1+2 ecosystems), PR #682 (tier-3 ecosystems + Phase 2 policy
diagnostics, closing issues #660 and #661), PR #665 (DRY follow-up, closing issue #662). Full
rollout complete.

## 10. See Also

- Dependi #68 "Missing license" (13 reactions; primary competitive demand signal):
  https://github.com/filllabs/dependi/issues/68
- Red Hat Dependency Analytics (ships license diagnostics on by default):
  https://raw.githubusercontent.com/fabric8-analytics/fabric8-analytics-vscode-extension/master/README.md
- deps.dev API v3 (free, keyless, per-version SPDX licenses[] for 6 ecosystems):
  https://docs.deps.dev/api/v3/
- crates.io sparse index documentation (does NOT include license):
  https://github.com/rust-lang/crates.io
- npm packument format (abbreviated form lacks license; full form includes it):
  https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md#get-a-package
- PyPI PEP 691 Simple API (lacks license; full JSON API has `license` field):
  https://peps.python.org/pep-0691/
- crates.nvim (shows license in hover):
  https://github.com/Saecki/crates.nvim
- cargo-appraiser (shows license, downloads, publish dates):
  https://github.com/simnillrig/cargo-appraiser
- `cargo deny licenses` (inspiration for Phase 2 policy engine):
  https://docs.rs/cargo-deny/latest/cargo_deny/
- `.local/testing/playbooks/competitive-parity.md` — full scan notes and ranking of all findings
  (2026-08-23)
- `.local/testing/issue-drafts-2026-08-23.md` — draft 2, raw issue template for reference
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec]] — related diagnostics work using similar per-dependency
  metadata pipeline
- [[004-release-freshness-signal/spec]] — related version-metadata (publish date) work that overlaps
  this feature's data fetching
- [[007-lightweight-registry-metadata/spec]] — registry-payload optimization that impacts what license
  data is available hot-path

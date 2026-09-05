---
aliases:
  - OSV Malicious Package Severity
  - MAL-* Advisory Distinguishing
tags:
  - sdd
  - spec
  - enhancement
  - osv
  - security
  - deps-lsp
  - deps-core
created: 2026-09-05
status: ready
related:
  - "[[constitution]]"
  - "[[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]]"
  - "[[037-supply-chain-trust-signal/spec|Supply-chain trust signal (OpenSSF Scorecard + SLSA provenance) via deps.dev]]"
---

# Feature: OSV Malicious-Package (`MAL-*`) Severity Distinguishing

> [!info] Metadata
> **Author**: continuous-improvement cycle (research/correctness stream)
> **Branch**: no issue number assigned yet — file a GitHub issue before branching
> **Priority**: P2
> **Type**: enhancement (research-originated, correctness/UX gap)

## 1. Overview

### Problem Statement

deps-lsp's OSV.dev integration (`crates/deps-core/src/osv/`, shipped via #124 /
PR #215) treats every advisory OSV returns as a graded vulnerability. OSV.dev
also serves `MAL-*` IDs — malicious-package advisories ingested from the
[OpenSSF `malicious-packages`](https://github.com/ossf/malicious-packages)
feed. GitHub's own Dependabot recently
([2026-07-28 changelog](https://github.blog/changelog/2026-07-28-dependabot-alerts-on-malicious-packages-across-more-ecosystems/))
expanded "malware alerts" to 8 ecosystems on this exact data source, treating
malware as a distinct alert category from regular vulnerability alerts.
[JetBrains Package Checker](https://www.jetbrains.com/help/idea/package-checker.html)
similarly surfaces malicious-package detection as its own headline category,
not folded into generic CVE severity.

A `MAL-*` record means "this exact published package version is confirmed
malicious code, not merely vulnerable" — categorically more urgent than any
CVSS-scored CVE. OSV's own advisory text for these records typically states
the package "should be considered fully compromised... all secrets and keys
should be rotated immediately."

Live-verified via a real `POST https://api.osv.dev/v1/query` call for
`@ctrl/tinycolor` (npm) — a package compromised in the September 2025
Shai-Hulud npm worm attack — the returned record `MAL-2025-47141` has **no
severity field at all**: no top-level CVSS `severity` array, no
`database_specific.severity`, no `ecosystem_specific.severity` on any
`affected` entry. Its only severity-adjacent signal is
`affected[].database_specific.cwes[].cweId == "CWE-506"` ("Embedded Malicious
Code").

Tracing this record through the current pipeline:

1. `crates/deps-core/src/osv/severity.rs::classify()` (lines ~41-60) has a
   3-tier fallback: `database_specific.severity` -> `ecosystem_specific.severity`
   -> `VulnSeverity::Unknown`. A `MAL-*` record with no severity field
   anywhere falls straight through to `VulnSeverity::Unknown`.
2. `to_diagnostic_severity()` (same file, lines ~84-91) maps
   `VulnSeverity::Unknown -> DiagnosticSeverity::WARNING` — the *same*
   diagnostic severity as a merely-unscored, ordinary CVE.
3. `severity_label()` (`crates/deps-core/src/lsp_helpers/hover.rs`, line
   ~644) renders `VulnSeverity::Unknown` as the literal string `"unknown
   severity"` in the hover's Security advisories section.

Net effect: a user hovering over a dependency pinned to a version that is
confirmed malware (an exact match against OpenSSF's curated malicious-package
list, not a hypothetical or low-confidence risk) sees the same "unknown
severity" label and the same capped-`WARNING` diagnostic as an obscure,
never-triaged low-confidence CVE. The diagnostic *message* text does include
the advisory summary (`push_vulnerability_diagnostics`,
`crates/deps-core/src/lsp_helpers/diagnostics.rs`, line ~1359, formats
`"{advisory.id}: {advisory.summary}"`, e.g. `"MAL-2025-47141: Malicious code
in @ctrl/tinycolor (npm)"`), so the word "Malicious" is visible in raw text —
but nothing about severity, icon, or ranking distinguishes the record, and
the hover's per-advisory line renders `"unknown severity"` right next to it:
an internally contradictory-reading signal (message says "malicious",
severity label says "unknown").

This is a known-but-deferred gap: the 2026-08-23 competitive-parity scan
(`.local/testing/playbooks/competitive-parity.md`, "Scan Notes
(2026-08-23...)" section) flagged that OSV's `MAL-*` records should be
surfaced distinctly, matching JetBrains Package Checker's headline
malicious-package detection, "worth a comment on #124 when it enters
implementation." #124 has since shipped (closed via PR #215) — this spec is
that deferred follow-through, now backed by a live-verified real-world
example instead of the original speculative note.

### Goal

A `MAL-*` / `CWE-506` malicious-package advisory is visually and textually
distinguishable from an ordinary unscored vulnerability everywhere severity
is surfaced (hover, diagnostics), so a user can never read "unknown
severity" for what is actually the single most severe class of finding OSV
can report (confirmed compromise).

### Out of Scope

- Any change to `recommended_fix()` / fix-target logic (see
  [[025-osv-fix-target-scan-gap/spec|OSV fix-target scan gap]]) — a
  malicious-package advisory typically has no "fixed" version at all (the
  package is malicious, not merely outdated); this spec does not redesign
  fix recommendation.
- Changing OSV client fetch/cache/batching behavior — the `MAL-*` record is
  already fetched and parsed today; this spec only changes how its severity
  is classified and rendered.
- Blocking installation, refusing completions, or any other enforcement
  action beyond diagnostics/hover — out of scope for this spec (would be a
  separate, larger policy discussion).
- Non-OSV malicious-package data sources (e.g. a hypothetical direct OpenSSF
  feed integration bypassing OSV) — this spec only addresses the signal
  already present in OSV's own wire format.

## 2. User Stories

### US-001: Unmistakable malicious-package warning in hover

AS A developer hovering over a dependency
I WANT a confirmed-malicious package version to be labeled distinctly from
an ordinary unscored vulnerability
SO THAT I immediately recognize "this is not a graded risk, this is known
malware" and act accordingly (remove/replace the dependency, rotate secrets)

**Acceptance criteria:**
```
GIVEN a dependency pinned to a version covered by an OSV MAL-* advisory
WHEN the hover's Security advisories section renders that advisory's line
THEN the line does not read "unknown severity" and instead carries a label
  that unambiguously signals confirmed-malicious-package status
```

### US-002: Malicious-package diagnostic distinguishable from a WARNING-capped CVE

AS A developer scanning the Problems panel
I WANT a malicious-package finding to stand out from routine
outdated/vulnerable-dependency warnings
SO THAT I don't triage it with the same priority as a low-confidence,
unscored CVE

**Acceptance criteria:**
```
GIVEN a dependency with both an ordinary unscored CVE (VulnSeverity::Unknown)
  and a MAL-* advisory
WHEN diagnostics are generated for that dependency
THEN the two diagnostics are distinguishable from each other (via message
  prefix, code, and/or severity) — a user reading the diagnostics list alone,
  without opening hover, can tell which one is the confirmed-malware finding
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN an OSV record's advisory `id` has the `MAL-` prefix THE SYSTEM SHALL classify that advisory as confirmed-malicious rather than falling through to `VulnSeverity::Unknown` (resolved: id-prefix detection only — no live-observed OSV record pairs `CWE-506` with a non-`MAL-` id, so the CWE check is dropped as unnecessary complexity per NFR-001) | must |
| FR-002 | WHEN an advisory is classified as confirmed-malicious THE SYSTEM SHALL render a hover label distinct from `"unknown severity"` and distinct from every existing graded label (`critical`/`high`/`medium`/`low`) | must |
| FR-003 | WHEN an advisory is classified as confirmed-malicious THE SYSTEM SHALL produce a diagnostic that is distinguishable from a `VulnSeverity::Unknown` diagnostic for an ordinary CVE via message content and diagnostic code, while remaining at `DiagnosticSeverity::WARNING` (resolved: keeps the existing "ERROR means broken manifest" convention from `architecture.md` §6 intact) | must |
| FR-004 | WHEN an OSV record has both a graded CVSS-style severity field AND is classified as confirmed-malicious (a record can in principle carry both) THE SYSTEM SHALL still surface the confirmed-malicious classification — a malicious-package finding must never be silently masked by an unrelated graded-severity value taking precedence | must |
| FR-005 | WHEN `classify()`'s existing 3-tier severity fallback (`database_specific.severity` -> `ecosystem_specific.severity` -> `Unknown`) runs on a record that is NOT confirmed-malicious THE SYSTEM SHALL continue to behave exactly as today — this spec adds a new classification branch, it does not change existing graded-severity precedence | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | Detection must not produce false positives — an ordinary advisory must never be misclassified as confirmed-malicious. `MAL-` prefix and `CWE-506` are both OSV-documented, low-ambiguity signals; the detection logic itself needs no external network call beyond data already fetched |
| NFR-002 | Consistency | The new classification must be applied uniformly across every ecosystem deps-lsp supports — OSV's `MAL-*` records are ecosystem-agnostic (npm, PyPI, RubyGems, etc. per the OpenSSF feed), and the classification lives in `deps-core::osv`, which is already shared across all ecosystem crates, so no ecosystem-specific code path should need to duplicate this logic |
| NFR-003 | Backward compatibility | Existing tests asserting `VulnSeverity::Unknown` behavior for non-malicious unscored records (`severity.rs`'s `cvss_vector_only_record_is_unknown`, `no_severity_at_all_is_unknown`) must continue to pass unchanged — only records actually carrying the `MAL-` prefix or `CWE-506` shift classification |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `VulnSeverity` (existing, `crates/deps-core/src/osv/types.rs`, line ~70) | Severity bucket enum | Currently `Critical`, `High`, `Medium`, `Low`, `Unknown` — resolved: add a new `Malicious` variant (forces every exhaustive `match` on `VulnSeverity` to be updated, consistent with this project's `EcosystemId` precedent) |
| `Advisory` (existing, same file, line ~104) | Per-advisory data surfaced to hover/diagnostics | `id`, `summary`, `aliases`, `severity`, `cvss_vector`, `fixed_versions`, `url` — the classification signal (id prefix and/or CWE) must be read at construction time from the raw OSV record, since `Advisory` itself does not currently carry `cwes` |
| *(new)* Malicious-package classification signal | Where the `MAL-` check reads from | Raw OSV record's `id` field (already available at `classify()`'s call site — no new field needs to be threaded through `OsvVulnRecord`/`Advisory`) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Record has `MAL-` id prefix but also a graded `database_specific.severity` (hypothetical, not observed live) | Per FR-004, confirmed-malicious classification (the new `VulnSeverity::Malicious` variant) still takes precedence and is surfaced — the id-prefix check runs before the existing 3-tier graded-severity fallback |
| Record has `MAL-` id prefix but the CWE data is entirely absent (matches the live `@ctrl/tinycolor` `MAL-2025-47141` case) | Classified as confirmed-malicious — the id prefix alone is sufficient (resolved: no CWE-506 check, see FR-001) |
| A dependency has both a confirmed-malicious advisory and one or more ordinary graded/unscored advisories | Each advisory keeps its own independent classification; the malicious one must not be diluted or hidden by unrelated advisories on the same dependency |
| `Capped` truncation (`ADVISORY_DISPLAY_CAP`) causes a confirmed-malicious advisory to fall outside the displayed slice | Out of scope for this spec (resolved: no reordering — pre-existing truncation/ordering behavior is unchanged; a dedicated "sort malicious first" enhancement is deferred to a follow-up if truncation drops turn out to matter in practice) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover rendering for `MAL-2025-47141` (`@ctrl/tinycolor`) or an equivalent live `MAL-*` record | Never renders `"unknown severity"`; renders a distinct confirmed-malicious label |
| SC-002 | Diagnostic distinguishability | A `MAL-*` diagnostic and a `VulnSeverity::Unknown` ordinary-CVE diagnostic on the same dependency are distinguishable without opening hover (message content at minimum) |
| SC-003 | Regression | All existing `severity.rs` and hover/diagnostics tests for non-malicious `Unknown` records continue to pass unchanged |
| SC-004 | Cross-ecosystem consistency | The fix lives entirely in `deps-core::osv` / `deps-core::lsp_helpers` — no ecosystem crate needs a parallel change to see the new classification (per NFR-002 and the project's cross-ecosystem-consistency rule) |

## 8. Agent Boundaries

### Always (without asking)
- Read `crates/deps-core/src/osv/severity.rs`, `crates/deps-core/src/osv/types.rs`,
  `crates/deps-core/src/lsp_helpers/hover.rs`, and
  `crates/deps-core/src/lsp_helpers/diagnostics.rs` in full before editing —
  each carries dense doc-comment context (invariant references, `architecture.md`
  citations) that must not be silently dropped
- Preserve existing graded-severity precedence and existing `Unknown`
  behavior for genuinely non-malicious unscored records (FR-005, NFR-003)
- Add/update unit tests in `severity.rs` for both detection signals
  (`MAL-` prefix, `CWE-506`) and for the FR-004 both-signals-present case
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest, rustdoc
  gate) per project convention before any PR
- Live-verify against the real `@ctrl/tinycolor` / `MAL-2025-47141` OSV
  record (or an equivalently current confirmed-malicious record, since OSV
  data can change) per the project's Live Testing Principle
  (`.claude/rules/continuous-improvement.md`) — do not conclude from code
  reading or unit tests alone

### Ask First
- All data-model and severity-handling design decisions were already made
  with the user before implementation began — see §9 Resolved Decisions.
  Any further deviation from those decisions (e.g. reconsidering the
  `VulnSeverity::Malicious` variant shape) should be raised before proceeding.

### Never
- Fold confirmed-malicious classification into the existing graded-severity
  scale (e.g. mapping it to `Critical`) in a way that makes it
  indistinguishable from an ordinary CVSS-CRITICAL CVE — the whole point of
  this spec is that "confirmed compromise" is categorically different from
  "graded but uncertain risk," per GitHub Dependabot's and JetBrains Package
  Checker's own separate-category treatment
- File this as fixed without live-testing against a real `MAL-*` OSV record,
  per the project's Live Testing Principle

## 9. Resolved Decisions

All open questions were resolved with the user before implementation:

- **Data model**: add a new `VulnSeverity::Malicious` variant (not an orthogonal flag). Forces every exhaustive `match` on `VulnSeverity` to be updated at compile time, consistent with this project's `EcosystemId` precedent.
- **Detection signal**: `MAL-` id-prefix only. No live-observed OSV record pairs `CWE-506` with a non-`MAL-` id, so the CWE check is dropped as unnecessary complexity (NFR-001).
- **Diagnostic severity**: stays `DiagnosticSeverity::WARNING`, distinguished via message content and diagnostic code — keeps the existing "ERROR means broken manifest" convention (`architecture.md` §6) intact.
- **Ordering**: no change to advisory/diagnostic ordering or `ADVISORY_DISPLAY_CAP` truncation behavior in this spec — deferred to a follow-up if it turns out to matter in practice.
- **Scope**: hover + diagnostics only, matching US-001/US-002. Inlay hints / code lens treatment is deferred to a follow-up.
- **GitHub issue**: filed as #646 (`enhancement`, `P2`, `research`), referencing this spec.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]] — the original feature this gap was found within
- [[037-supply-chain-trust-signal/spec|Supply-chain trust signal (OpenSSF Scorecard + SLSA provenance) via deps.dev]] — related deps.dev-sourced trust-signal precedent (separate data source, same "beyond CVE severity" theme)
- `crates/deps-core/src/osv/severity.rs` — `classify()`, `to_diagnostic_severity()`
- `crates/deps-core/src/osv/types.rs` — `VulnSeverity`, `Advisory`
- `crates/deps-core/src/lsp_helpers/hover.rs` — `severity_label()`, line ~644
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` — `push_vulnerability_diagnostics()`, line ~1359
- [OpenSSF `malicious-packages`](https://github.com/ossf/malicious-packages) — the upstream data source OSV ingests `MAL-*` records from
- [GitHub Changelog: Dependabot alerts on malicious packages across more ecosystems (2026-07-28)](https://github.blog/changelog/2026-07-28-dependabot-alerts-on-malicious-packages-across-more-ecosystems/) — reference-project precedent for treating malware as a distinct alert category
- [JetBrains Package Checker](https://www.jetbrains.com/help/idea/package-checker.html) — reference-project precedent for headline malicious-package detection separate from vulnerability severity
- `.local/testing/playbooks/competitive-parity.md`, "Scan Notes (2026-08-23...)" — the original deferred note that this spec follows through on
- Live OSV.dev evidence: `POST https://api.osv.dev/v1/query {"package":{"name":"@ctrl/tinycolor","ecosystem":"npm"}}` returning `MAL-2025-47141` with no severity fields anywhere in the response

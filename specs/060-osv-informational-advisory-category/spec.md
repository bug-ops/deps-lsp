---
aliases:
  - OSV Informational Advisory Category
  - RUSTSEC Unmaintained Advisory Distinguishing
tags:
  - sdd
  - spec
  - enhancement
  - osv
  - deps-core
  - deps-lsp
created: 2026-09-14
status: draft
related:
  - "[[constitution]]"
  - "[[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]]"
  - "[[011-deprecation-replacement-diagnostics/spec|Deprecation/abandoned diagnostics with suggested replacement]]"
  - "[[049-osv-malicious-package-severity/spec|OSV malicious-package (MAL-*) advisory severity distinguishing]]"
---

# Feature: OSV Informational-Advisory Category (RUSTSEC Unmaintained and Other `informational` Records)

> [!info] Metadata
> **Author**: continuous-improvement cycle (research stream)
> **Branch**: no issue number assigned yet — file a GitHub issue before branching
> **Priority**: P3
> **Type**: enhancement (research-originated, correctness/UX gap)

## 1. Overview

### Problem Statement

deps-lsp's OSV.dev vulnerability-diagnostics pipeline
(`crates/deps-core/src/osv/`, shipped via issue #124) classifies every
advisory's severity via `crates/deps-core/src/osv/severity.rs::classify()`.
That function reads `database_specific.severity` /
`ecosystem_specific.severity` and a `MAL-` id/alias prefix (for
confirmed-malicious-package records, see
[[049-osv-malicious-package-severity/spec|OSV malicious-package severity]]),
but never reads OSV's `affected[].database_specific.informational` field.

RUSTSEC "unmaintained" advisories (a distinct RustSec advisory category — the
crate isn't vulnerable, its maintainer is just unreachable) carry
`informational: "unmaintained"` in their `affected[]` entry and no
`severity` field at all, so `classify()` falls through to
`VulnSeverity::Unknown`, which `to_diagnostic_severity()` maps to
`DiagnosticSeverity::WARNING` — the exact same severity bucket, diagnostic
code shape, and Problems-panel treatment as an actual unscored real
vulnerability.

Live-verified via a direct OSV.dev query for a known-unmaintained crate:

```bash
curl -s -X POST https://api.osv.dev/v1/query -H "Content-Type: application/json" \
  -d '{"package":{"name":"yaml-rust","ecosystem":"crates.io"},"version":"0.4.5"}'
```

returns `RUSTSEC-2024-0320` ("yaml-rust is unmaintained.") with
`affected[0].database_specific.informational: "unmaintained"` and no
`severity` anywhere in the record.

Tracing this record through the current pipeline (all citations
re-confirmed against the current `main` tree, post-#124/#646):

1. `crates/deps-core/src/osv/severity.rs::classify()` — the `MAL-` id/alias
   check runs first (returns `VulnSeverity::Malicious`, not applicable
   here), then `database_specific.severity` (record-level, top of the OSV
   record — distinct from the per-`affected[]`-entry
   `database_specific.informational` field this spec is about), then
   `relevant_affected[].ecosystem_specific.severity`. Neither exists on an
   `informational`-only record, so it falls through to
   `VulnSeverity::Unknown`.
2. `crates/deps-core/src/osv/types.rs`'s `OsvAffected` struct
   (`pub(super) struct OsvAffected`, ~line 960) currently parses only
   `package` and `ecosystem_specific` from each `affected[]` entry — it has
   no `database_specific` field at all, so the `informational` value is not
   even deserialized today; `classify()` has no way to see it without a new
   field first.
3. `to_diagnostic_severity()` (same file) maps `VulnSeverity::Unknown ->
   DiagnosticSeverity::WARNING` — the same bucket as a real unscored CVE.
4. `crates/deps-core/src/lsp_helpers/diagnostics.rs::push_vulnerability_diagnostics()`
   (~line 1776) has one special case (the `Malicious` `[MALWARE]` message
   prefix, added by #646); no branch distinguishes an informational/
   unmaintained advisory from a graded or unscored one. Same diagnostic code
   shape (`advisory.id`), same `source: "deps-lsp"` tag.
5. `crates/deps-core/src/lsp_helpers/hover.rs::severity_label()` (~line 834)
   has labels for `Critical`/`High`/`Medium`/`Low`/`Unknown`/`Malicious` —
   no label exists for an informational advisory; it would render as
   `"unknown severity"`.

Net effect: both an "unmaintained crate" notice and an actual unscored CVE
render as `WARNING`-severity advisory diagnostics with identical treatment
in the Problems panel and hover, differing only in prose within the message
body (which does happen to say "yaml-rust is unmaintained." today, since
that text comes from OSV's own `summary` field — but nothing about
severity, icon, code, or category distinguishes the two mechanically).

This is a distinct, narrower gap than
[[011-deprecation-replacement-diagnostics/spec|issue #205]] (deprecation/
abandonment diagnostics via *registry-native* signals: npm `deprecated`,
Packagist `abandoned`, deps.dev `isDeprecated`/`projectStatus`, surfaced via
`apply_deprecation_rule` / `push_deprecation_diagnostic` in
`crates/deps-core/src/lsp_helpers/diagnostics.rs`, driven by
`Registry`/`VersionData::outcomes.deprecation()` — a completely separate
data path from the OSV client). #205's own issue body explicitly scoped
OSV-sourced RUSTSEC-unmaintained advisories OUT of its work ("crates.io: no
first-class signal (RUSTSEC unmaintained arrives via the separate OSV work,
#124)"), and #124 (the base OSV integration) never implemented
`informational`-field handling — it only maps `severity`. So today an
"unmaintained" advisory is neither routed through the existing
`Deprecation`/`push_deprecation_diagnostic` pathway nor given a distinct
code/category in the OSV-advisory pathway
(`push_vulnerability_diagnostics`) — it is indistinguishable in tooling
(diagnostic code, severity, filterability) from a real unscored
vulnerability.

Competitive context: crates.io's own website shipped a distinct
"unmaintained crate" warning UI in its July 2026 update (separate from
vulnerability/security-advisory badges) — see
[crates.io development update, 2026-07-13](https://blog.rust-lang.org/2026/07/13/crates-io-development-update/).
Other reference tools already tracked in this project's competitive-parity
playbook (Red Hat Dependency Analytics, JetBrains Package Checker)
distinguish vulnerability categories rather than lumping them into one
generic bucket.

This affects every OSV-covered ecosystem, not just Cargo —
`database_specific.informational` is a general OSV schema field
(documented at the
[OSV schema reference](https://ossf.github.io/osv-schema/#affecteddatabase_specific-field)),
not RUSTSEC-specific, though RUSTSEC-sourced "unmaintained" advisories
(crates.io/Cargo) are the best-documented live example.

### Goal

An OSV advisory whose relevant `affected[]` entry carries a
`database_specific.informational` value (e.g. `"unmaintained"`) is
classified and rendered distinctly from a graded or unscored vulnerability
everywhere severity is surfaced (hover, diagnostics), so a user can tell
"this dependency has no maintainer" apart from "this dependency has an
unpatched vulnerability" without reading the full advisory prose.

### Out of Scope

- Any change to `recommended_fix()` / fix-target logic — an informational
  advisory has no "fixed" version (there is nothing to patch); this spec
  does not redesign fix recommendation.
- Changing OSV client fetch/cache/batching behavior — the informational
  record is already fetched and parsed (minus the one new field) today;
  this spec only changes how it is classified and rendered.
- Reimplementing or merging with the registry-native deprecation signal
  pipeline (npm `deprecated`, Packagist `abandoned`, deps.dev
  `isDeprecated`) from [[011-deprecation-replacement-diagnostics/spec|#205]]
  — whether to route OSV-`informational` findings through that existing
  `Deprecation` machinery or keep them as a sibling `VulnSeverity`-adjacent
  category is an open design decision, not resolved here (see §9 Open
  Questions).
- Blocking installation, refusing completions, or any other enforcement
  action beyond diagnostics/hover.
- Non-OSV informational-status data sources.

## 2. User Stories

### US-001: Unmaintained-package notice distinguishable from a graded vulnerability in hover

AS A developer hovering over a dependency
I WANT an OSV-sourced "unmaintained" (or other informational-only) advisory
to be labeled distinctly from an ordinary graded or unscored vulnerability
SO THAT I understand this is a maintenance-status notice, not evidence of an
exploitable bug, and can triage it accordingly (evaluate an alternative
crate at leisure, rather than treating it as an urgent security fix)

**Acceptance criteria:**
```
GIVEN a dependency pinned to a version covered by an OSV advisory whose
  relevant affected[] entry carries database_specific.informational
WHEN the hover's Security advisories section renders that advisory's line
THEN the line does not read "unknown severity" and instead carries a label
  that identifies it as an informational/maintenance-status notice rather
  than a graded vulnerability
```

### US-002: Informational advisory distinguishable in the Problems panel from a WARNING-capped unscored CVE

AS A developer scanning the Problems panel
I WANT an informational/unmaintained finding to be visibly different from a
routine unscored-vulnerability warning
SO THAT I don't triage a maintenance-status notice with the same urgency as
an unscored-but-potentially-real vulnerability

**Acceptance criteria:**
```
GIVEN a dependency with both an ordinary unscored CVE (VulnSeverity::Unknown)
  and an OSV informational advisory
WHEN diagnostics are generated for that dependency
THEN the two diagnostics are distinguishable from each other (via severity,
  message prefix, and/or code) — a user reading the diagnostics list alone,
  without opening hover, can tell which one is the maintenance-status
  notice
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN parsing an OSV record's `affected[]` entries THE SYSTEM SHALL deserialize each entry's `database_specific.informational` field (new field on `OsvAffected`, `crates/deps-core/src/osv/types.rs`) so the value is available at `classify()`'s call site, mirroring how `ecosystem_specific` is already carried per-entry | must |
| FR-002 | WHEN an OSV record's relevant `affected[]` entry (i.e. the entry already filtered to the package actually queried, per `OsvVulnRecord::into_advisory`) carries a non-empty `database_specific.informational` value THE SYSTEM SHALL classify that advisory into a distinct informational category rather than falling through to `VulnSeverity::Unknown` — `[NEEDS CLARIFICATION: exact new-variant name and shape — see §9(a)]` | must |
| FR-003 | WHEN an advisory is classified as informational THE SYSTEM SHALL render a hover label distinct from `"unknown severity"` and distinct from every existing graded/malicious label | must |
| FR-004 | WHEN an advisory is classified as informational THE SYSTEM SHALL produce a diagnostic distinguishable from a `VulnSeverity::Unknown` diagnostic for an ordinary CVE via severity and/or message content and diagnostic code — `[NEEDS CLARIFICATION: target DiagnosticSeverity — see §9(a)]` | must |
| FR-005 | WHEN an OSV record's relevant `affected[]` entry carries BOTH a graded severity field (record-level `database_specific.severity` or per-entry `ecosystem_specific.severity`) AND an `informational` value (possible in principle, not yet live-observed) THE SYSTEM SHALL still surface the graded severity as primary — unlike the `MAL-*` precedent (#646 FR-004), an `informational` value on an otherwise-graded record does not represent a categorically more urgent finding, so it must not override an existing severity signal; open to revision if a live counterexample is found (`[NEEDS CLARIFICATION: precedence when both are present — see §9]`) | should |
| FR-006 | WHEN `classify()`'s existing precedence chain (`MAL-` prefix -> `database_specific.severity` -> `ecosystem_specific.severity` -> `Unknown`) runs on a record that has NO `informational` value on its relevant `affected[]` entries THE SYSTEM SHALL continue to behave exactly as today — this spec adds a new classification branch, it does not change existing precedence for records without the field | must |
| FR-007 | WHERE OSV's schema defines `informational` as an enum with (at minimum) `"unknown"` and `"unmaintained"` as recognized values THE SYSTEM SHALL handle an unrecognized/future `informational` string value by still classifying the advisory as generically informational (not silently reverting to `VulnSeverity::Unknown`) — `[NEEDS CLARIFICATION: whether "unknown" (the enum value, confusingly distinct from this crate's own VulnSeverity::Unknown) needs its own handling — see §9(c)]` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | Detection must not produce false positives — a record with no `informational` field must never be misclassified as informational. The field is an OSV-documented, low-ambiguity signal already present on the wire; no new network call is required |
| NFR-002 | Consistency | The new classification must be applied uniformly across every ecosystem deps-lsp supports — `database_specific.informational` is ecosystem-agnostic per the OSV schema (not RUSTSEC-specific), and classification lives in `deps-core::osv`, already shared across all ecosystem crates, so no ecosystem-specific code path should need to duplicate this logic |
| NFR-003 | Backward compatibility | Existing tests asserting `VulnSeverity::Unknown` behavior for records with no severity/informational signal (`severity.rs`'s `cvss_vector_only_record_is_unknown`, `no_severity_at_all_is_unknown`) must continue to pass unchanged — only records actually carrying `database_specific.informational` on a relevant `affected[]` entry shift classification |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `OsvAffected` (existing, `crates/deps-core/src/osv/types.rs`, `pub(super) struct OsvAffected`, ~line 960) | Wire type for one `affected[]` entry | Currently `package`, `ecosystem_specific`, `ranges` — needs a new `#[serde(default)] database_specific: Option<serde_json::Value>` field (FR-001) to carry the per-entry `informational` value through to `classify()`; note this is a *different* `database_specific` than `OsvVulnRecord`'s existing record-level `database_specific` (which is already read for `severity` today) |
| `VulnSeverity` (existing, `crates/deps-core/src/osv/types.rs`, `#[non_exhaustive] pub enum VulnSeverity`) | Severity/category bucket enum | Currently `Critical`, `High`, `Medium`, `Low`, `Unknown`, `Malicious` (the last added by #646) — `[NEEDS CLARIFICATION: add a new variant (e.g. `Informational` or `Unmaintained`) vs. a separate parallel enum/field — see §9(a)]` |
| `classify()` (existing, `crates/deps-core/src/osv/severity.rs`) | Severity-classification function | Signature takes `id`, `aliases`, `database_specific` (record-level), `relevant_affected: &[&OsvAffected]` — the new informational check would read `relevant_affected[].database_specific.informational` (the new per-entry field from FR-001), most naturally slotted after the `MAL-` check and before (or interleaved with, per FR-005) the graded-severity fallback |
| *(new)* Informational classification signal | Where the check reads from | `relevant_affected[].database_specific.informational` (new field per FR-001), an OSV enum documented as including at least `"unknown"` and `"unmaintained"` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Record's relevant `affected[]` entry has `informational: "unmaintained"` and no severity field anywhere (live-observed: `RUSTSEC-2024-0320` / `yaml-rust`) | Classified as informational per FR-002; hover/diagnostic render distinctly from `"unknown severity"` |
| Record's relevant `affected[]` entry has `informational: "unknown"` (OSV's own enum value, distinct from this crate's `VulnSeverity::Unknown`) | Still classified as generically informational per FR-007, not left to fall through to `VulnSeverity::Unknown` — naming collision between OSV's `informational: "unknown"` and this crate's `VulnSeverity::Unknown` variant must not cause the two concepts to be conflated in code or docs |
| Record has both a graded `severity` field AND an `informational` value on the same relevant entry (hypothetical, not yet live-observed) | Per FR-005 (tentative — see §9), graded severity remains primary; open question whether the informational aspect should still be surfaced as a secondary note |
| A dependency has both an informational advisory and one or more ordinary graded/unscored/malicious advisories | Each advisory keeps its own independent classification; the informational one must not be conflated with or hidden by unrelated advisories on the same dependency |
| `informational` value present at the record's top-level `database_specific` rather than per-`affected[]`-entry (not observed live for RUSTSEC-unmaintained records, which is documented as an `affected[]`-scoped field, but OSV's schema evolves) | Out of scope for this spec unless a live counterexample is found — FR-001 only adds the per-entry field |
| `Capped` truncation (`ADVISORY_DISPLAY_CAP`) causes an informational advisory to fall outside the displayed slice | Out of scope for this spec — no reordering; pre-existing truncation/ordering behavior is unchanged, matching the #646 precedent's resolution for the same question |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover rendering for `RUSTSEC-2024-0320` (`yaml-rust`) or an equivalent live informational record | Never renders `"unknown severity"`; renders a distinct informational/unmaintained-category label |
| SC-002 | Diagnostic distinguishability | An informational-advisory diagnostic and a `VulnSeverity::Unknown` ordinary-CVE diagnostic on the same dependency are distinguishable without opening hover |
| SC-003 | Regression | All existing `severity.rs` and hover/diagnostics tests for non-informational `Unknown` records continue to pass unchanged |
| SC-004 | Cross-ecosystem consistency | The fix lives entirely in `deps-core::osv` / `deps-core::lsp_helpers` — no ecosystem crate needs a parallel change to see the new classification (per NFR-002 and the project's cross-ecosystem-consistency rule) |

## 8. Agent Boundaries

### Always (without asking)
- Read `crates/deps-core/src/osv/severity.rs`, `crates/deps-core/src/osv/types.rs`,
  `crates/deps-core/src/lsp_helpers/hover.rs`, and
  `crates/deps-core/src/lsp_helpers/diagnostics.rs` in full before editing —
  each carries dense doc-comment context (invariant references,
  `architecture.md` citations, the #646 `Malicious`-variant precedent) that
  must not be silently dropped
- Preserve existing graded-severity precedence and existing `Unknown`
  behavior for records with no `informational` signal (FR-006, NFR-003)
- Add/update unit tests in `severity.rs` for the `informational` field
  check, including the `"unknown"`-value-collision edge case (FR-007) and
  the both-signals-present case (FR-005)
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest,
  rustdoc gate) per project convention before any PR
- Live-verify against a real current OSV `informational`-carrying record
  (e.g. re-query `RUSTSEC-2024-0320`/`yaml-rust`, since OSV data can
  change) per the project's Live Testing Principle
  (`.claude/rules/continuous-improvement.md`) — do not conclude from code
  reading or unit tests alone

### Ask First
- The open design decisions in §9 (target `DiagnosticSeverity`, whether to
  unify with the `Deprecation` pathway, exact `VulnSeverity` variant shape,
  precedence when both graded severity and `informational` are present)
  must be resolved with the user before implementation begins — this spec
  intentionally leaves them open per the P3/research-cycle scope

### Never
- Silently pick a `DiagnosticSeverity` or unify-vs-sibling design without
  surfacing the trade-off to the user first — unlike #646 (which resolved
  its open questions interactively before implementation), this spec is
  produced in a non-interactive research cycle and its FR-002/FR-004/FR-005
  markers are genuinely unresolved
- File this as fixed without live-testing against a real
  `informational`-carrying OSV record, per the project's Live Testing
  Principle
- Fold informational classification into the existing graded-severity scale
  in a way that makes it indistinguishable from an ordinary CVE — the whole
  point of this spec is that "no maintainer" is categorically different
  from "known/suspected vulnerability"

## 9. Open Questions

- `[NEEDS CLARIFICATION: (a) exact target classification and DiagnosticSeverity for informational advisories — options include (i) a new VulnSeverity::Informational/Unmaintained variant mapping to DiagnosticSeverity::HINT or DiagnosticSeverity::INFORMATION (distinct from the WARNING bucket every graded/Unknown/Malicious variant currently shares), or (ii) reusing DiagnosticSeverity::INFORMATION (already used today for Medium/Low and the "+N more advisories" notice) with a distinguishing message/code only. FR-002 and FR-004 are gated on this decision.]`
- `[NEEDS CLARIFICATION: (b) whether to route OSV-informational findings through the existing Deprecation/push_deprecation_diagnostic pathway (crates/deps-core/src/lsp_helpers/diagnostics.rs, from #205/[[011-deprecation-replacement-diagnostics/spec]]) for a single unified "this package has a maintenance problem" diagnostic UX across registry-native and OSV-native signals, or keep OSV-informational as a VulnSeverity-adjacent sibling category alongside Malicious (architecturally simpler — Deprecation is populated from Registry/VersionData::outcomes, a completely separate data path from DependencyVulnerabilities/OSV, so unifying would require either threading OSV data into Deprecation or threading Deprecation-shaped output out of the OSV pipeline).]`
- `[NEEDS CLARIFICATION: (c) whether other OSV informational values besides "unmaintained" need distinct handling — per the OSV schema, "unknown" is also a defined enum value (see the Edge Cases table's naming-collision note with this crate's own VulnSeverity::Unknown) and future schema revisions could add more; FR-007 proposes generic handling (any non-empty informational value maps to the same new category) as the default resolution unless the user wants per-value distinction.]`
- `[NEEDS CLARIFICATION: whether the new category (once named) should also get its own hover icon/callout treatment analogous to Malicious's rendering, or text-label-only is sufficient for a P3 item — not yet scoped.]`

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]] — the original feature this gap was found within
- [[011-deprecation-replacement-diagnostics/spec|Deprecation/abandoned diagnostics with suggested replacement]] — the registry-native sibling signal (#205), explicitly scoped OSV-unmaintained out of its own work
- [[049-osv-malicious-package-severity/spec|OSV malicious-package (MAL-*) advisory severity distinguishing]] — the direct precedent this spec extends (added `VulnSeverity::Malicious`, the `[MALWARE]` message prefix, and the distinct hover label pattern this spec's FR-002/FR-003 follow)
- `crates/deps-core/src/osv/severity.rs` — `classify()`, `to_diagnostic_severity()`
- `crates/deps-core/src/osv/types.rs` — `VulnSeverity`, `Advisory`, `OsvAffected`
- `crates/deps-core/src/lsp_helpers/hover.rs` — `severity_label()`, ~line 834
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` — `push_vulnerability_diagnostics()`, ~line 1776; `apply_deprecation_rule()` / `push_deprecation_diagnostic()`, ~lines 1214/1729 (the alternative pathway discussed in §9(b))
- [OSV schema reference — `affected[].database_specific` field](https://ossf.github.io/osv-schema/#affecteddatabase_specific-field) — documents `informational` as a general (non-RUSTSEC-specific) enum field
- [crates.io development update, 2026-07-13](https://blog.rust-lang.org/2026/07/13/crates-io-development-update/) — reference-project precedent for a distinct "unmaintained crate" warning UI, separate from vulnerability/security-advisory badges
- Live OSV.dev evidence: `POST https://api.osv.dev/v1/query {"package":{"name":"yaml-rust","ecosystem":"crates.io"},"version":"0.4.5"}` returning `RUSTSEC-2024-0320` with `affected[0].database_specific.informational: "unmaintained"` and no `severity` field anywhere in the record

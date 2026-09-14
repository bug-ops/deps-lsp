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
status: shipped
related:
  - "[[constitution]]"
  - "[[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]]"
  - "[[011-deprecation-replacement-diagnostics/spec|Deprecation/abandoned diagnostics with suggested replacement]]"
  - "[[049-osv-malicious-package-severity/spec|OSV malicious-package (MAL-*) advisory severity distinguishing]]"
---

# Feature: OSV Informational-Advisory Category (RUSTSEC Unmaintained and Other `informational` Records)

> [!info] Metadata
> **Author**: continuous-improvement cycle (research stream)
> **Branch**: issue #1007
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
| FR-002 | WHEN an OSV record's relevant `affected[]` entries (i.e. the entries already filtered to the package actually queried, per `OsvVulnRecord::into_advisory`) carry a non-empty `database_specific.informational` value on at least one entry, AND no entry among those same relevant entries carries a graded severity field (record-level `database_specific.severity` or per-entry `ecosystem_specific.severity`) THE SYSTEM SHALL classify that advisory as a new `VulnSeverity::Informational` variant, distinct from `Unknown`/`Malicious`/graded variants, mapped to `DiagnosticSeverity::INFORMATION` (resolved 2026-09-14, revised after critic review: `INFORMATION`, not `HINT` — see §9(a) for why `HINT` was rejected) | must |
| FR-002a | WHEN `classify()` evaluates a record's relevant `affected[]` entries THE SYSTEM SHALL run the graded-severity check across ALL relevant entries first (as today — first entry found with a graded severity wins) and only fall through to the informational check (FR-002) if NO relevant entry carries a graded severity — the informational check MUST NOT be interleaved entry-by-entry with the graded-severity check, and MUST run as a separate pass after the existing `MAL-` → graded-severity chain, immediately before the final `Unknown` fallback. This is the corrected slotting for FR-005: interleaving (checking each entry for informational-or-severity in one pass) lets an early entry's `informational` value win over a later entry's graded severity, which is exactly the outcome FR-005 forbids | must |
| FR-002b | WHEN `OsvVulnRecord::into_advisory` falls back to using ALL `affected[]` entries because none matched the queried package (the existing "no entry matches" fallback) THE SYSTEM SHALL NOT apply the informational classification (FR-002) from that fallback set — an `informational` value on an unrelated ("stranger") package entry must not downgrade an otherwise-`Unknown` record's diagnostic severity for a package it does not actually describe. In this fallback case, `classify()` continues past the informational check to `Unknown` exactly as before this spec. ADDITIONALLY (impl-critic finding M2): `into_advisory`'s existing relevant-entry filter treats a `package`-less `affected[]` entry (`entry.package.is_none()`) as matching ANY queried package — this is pre-existing, permissive-by-design leniency for other fields, but for the NEW informational check specifically, a `package`-less entry MUST NOT count as a "genuine match" (it is not actually about the queried package at all) — the informational check's genuine-match guard must require `entry.package` to be `Some` and actually equal to the queried package, a strictly narrower condition than the existing general relevant-entry filter used for severity | must |
| FR-003 | WHEN an advisory is classified as informational THE SYSTEM SHALL render a hover label distinct from `"unknown severity"` and distinct from every existing graded/malicious label — a plain text label, no dedicated icon/callout (resolved: §9(d)). If the advisory has no `summary` text, the label MUST still stand alone as a comprehensible notice (not just append "(no summary provided)" to a bare category word) | must |
| FR-004 | WHEN an advisory is classified as informational THE SYSTEM SHALL produce a diagnostic with `DiagnosticSeverity::INFORMATION` (revised, see FR-002) AND a `[INFORMATIONAL]` message prefix (mirroring the `[MALWARE]` precedent from #646). `INFORMATION` keeps the finding visible in every client's Problems panel — unlike `HINT`, which VS Code excludes from the Problems panel entirely and Zed de-emphasizes. `Unknown` (an ordinary unscored CVE) stays at `WARNING`, so severity alone already separates the two; the `[INFORMATIONAL]` prefix is the additional signal for a user filtering/reading by message text or diagnostic code rather than by severity icon | must |
| FR-005 | WHEN an OSV record's relevant `affected[]` entry carries BOTH a graded severity field (record-level `database_specific.severity` or per-entry `ecosystem_specific.severity`) AND an `informational` value (possible in principle, not yet live-observed) THE SYSTEM SHALL still surface the graded severity as primary — unlike the `MAL-*` precedent (#646 FR-004), an `informational` value on an otherwise-graded record does not represent a categorically more urgent finding, so it must not override an existing severity signal. Enforced via the two-pass precedence in FR-002a | should |
| FR-006 | WHEN `classify()`'s existing precedence chain (`MAL-` prefix -> `database_specific.severity` -> `ecosystem_specific.severity` -> `Unknown`) runs on a record that has NO `informational` value on its relevant `affected[]` entries THE SYSTEM SHALL continue to behave exactly as today — this spec adds a new classification branch, it does not change existing precedence for records without the field | must |
| FR-007 | WHERE a relevant `affected[]` entry's non-empty (post-`trim()`) `database_specific.informational` value is `"unmaintained"` THE SYSTEM SHALL classify the advisory as `VulnSeverity::Informational` (REVISED 2026-09-14, twice, after security review — see §9(f) — was originally "any non-empty value", then narrowed to an allowlist of `"unmaintained"`/`"notice"`, now narrowed further to `"unmaintained"` alone). Any OTHER value — including RUSTSEC's `"unsound"` (a real memory-safety/UB finding) and `"notice"` (live-verified to also carry real defects, e.g. `RUSTSEC-2026-0174`/`http-types`'s incorrect `unsafe` justification for an ASCII-invariant violation — not a reliably maintenance-only category, see §9(f)), OSV's own `"unknown"` enum value, an unrecognized future value, a missing field, `null`, or an empty/whitespace-only string — MUST NOT trigger `Informational` classification and instead falls through to the existing precedence chain (graded severity, else `Unknown`) exactly as before this spec. Defaulting unrecognized/unreliable values to the safer, more-visible `Unknown`/`WARNING` treatment (rather than the less-visible `Informational`/`INFORMATION`) is the deliberate fail-safe direction here | must |
| FR-008 | WHEN rendering the "Latest version is also affected" candidate-vulnerable hover line for a dependency THE SYSTEM SHALL suppress mentioning any advisory id whose classification is `VulnSeverity::Informational` — an informational/unmaintained notice has no "fixed version" concept, so flagging the latest version as "also affected" by it is misleading. REVISED 2026-09-14 after implementation-critique (impl-critic findings S1/S2, superseding an earlier draft that special-cased `Informational` inside `check_candidates()` itself): this filtering MUST be implemented purely as a hover-rendering-time step (`crates/deps-core/src/lsp_helpers/hover.rs`) over the advisory ids `check_candidates()` already returns — `check_candidates()` itself, its `CandidateVulnerable`/`CandidateClean`/`UpgradeStatus` classification, the `Capped` truncation semantics it already correctly respects, and every downstream consumer (`osv_scan.rs`, `code_actions.rs`'s `fix_target_is_verified`) MUST remain byte-for-byte unchanged by this spec. If the ids `check_candidates()` returns are ALL `Informational`, hover suppresses the line entirely for that dependency; if the set is mixed (informational + non-informational), hover still renders it (a real vulnerability signal must never be silently dropped) | must |
| FR-010 | WHEN the hover-render-time filter from FR-008 evaluates whether to suppress the "also affected" line THE SYSTEM SHALL treat an empty candidate-id set, OR a candidate-id set for which `!Capped::is_complete()`, as "cannot confirm all-informational" and render the line (fail OPEN) — never suppress on incomplete information (impl-critic finding N1, security finding L2) | must |

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
| `VulnSeverity` (existing, `crates/deps-core/src/osv/types.rs`, `#[non_exhaustive] pub enum VulnSeverity`) | Severity/category bucket enum | Currently `Critical`, `High`, `Medium`, `Low`, `Unknown`, `Malicious` (the last added by #646) — gains a new `Informational` variant (resolved: §9(a)), mapped to `DiagnosticSeverity::INFORMATION` |
| `severity_rank` (existing, `crates/deps-core/src/osv/types.rs:489`) | Ordering/comparison const fn over `VulnSeverity`, exhaustive match | Missing from the original spec draft (critic finding 4) — adding `VulnSeverity::Informational` to the enum breaks this exhaustive match at compile time; the new variant needs an explicit rank. Recommended: rank it below `Unknown` (least urgent) — an informational/maintenance notice is not a graded-or-unscored vulnerability and should sort after all of them |
| `classify()` (existing, `crates/deps-core/src/osv/severity.rs`) | Severity-classification function | Signature takes `id`, `aliases`, `database_specific` (record-level), `relevant_affected: &[&OsvAffected]` — implements the two-pass precedence from FR-002/FR-002a/FR-002b: `MAL-` check, then a full pass over `relevant_affected` for graded severity (existing behavior, unchanged), then — only if no graded severity was found AND `relevant_affected` reflects a genuine per-package match (not the "no entry matched, use all" fallback) — a pass over `relevant_affected` for a non-empty `database_specific.informational` value, then `Unknown` |
| `to_diagnostic_severity()` (existing, `crates/deps-core/src/osv/severity.rs:111`) | Maps `VulnSeverity` -> `DiagnosticSeverity` | Gains a `VulnSeverity::Informational -> DiagnosticSeverity::INFORMATION` arm |
| `severity_label()` (existing, `crates/deps-core/src/lsp_helpers/hover.rs:834`) | Hover severity label text | Gains a label for `Informational` (FR-003) |
| `push_vulnerability_diagnostics()` (existing, `crates/deps-core/src/lsp_helpers/diagnostics.rs:1776`, `== Malicious` compare at `:1794`) | Diagnostic message construction, incl. the `[MALWARE]` prefix special-case | Gains an `Informational -> [INFORMATIONAL]` prefix special-case alongside the existing `Malicious -> [MALWARE]` one (FR-004) |
| `check_candidates()` (existing, `crates/deps-core/src/osv/mod.rs:218-226`) | Determines whether "Latest version is also affected" is shown in hover | Gains a check: skip this line for `VulnSeverity::Informational` advisories (FR-008) |
| *(new)* Informational classification signal | Where the check reads from | `relevant_affected[].database_specific.informational` (new field per FR-001) on an entry whose `package` is `Some` and exactly matches the queried package (FR-002b/M2) — read via `.as_str()`, `.trim()`-guarded against empty/whitespace, then matched against the FR-007 allowlist (`"unmaintained"` only — see §9(f)); any other value (including OSV's own `"unknown"` enum value and RUSTSEC's `"unsound"`/`"notice"`) is treated as NOT triggering `Informational` classification |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Record's relevant `affected[]` entry has `informational: "unmaintained"` and no severity field anywhere (live-observed: `RUSTSEC-2024-0320` / `yaml-rust`) | Classified as informational per FR-002; hover/diagnostic render distinctly from `"unknown severity"` |
| Record's relevant `affected[]` entry has `informational: "unknown"` (OSV's own enum value, distinct from this crate's `VulnSeverity::Unknown`) | REVISED (§9(f)): NOT in the FR-007 allowlist (`unmaintained` only) — falls through to `VulnSeverity::Unknown` exactly like a record with no `informational` field. This also sidesteps the naming-collision risk the original draft worried about, since the two concepts now share the same code path rather than needing to stay distinguished |
| Record's relevant `affected[]` entry has `informational: "unsound"` (RUSTSEC's memory-safety/UB category, e.g. `RUSTSEC-2021-0145`/`atty`, `RUSTSEC-2019-0036`/`failure` — live-verified via `GET api.osv.dev/v1/vulns/{id}`) | NOT in the FR-007 allowlist — classifies as `Unknown`/`WARNING`, same as today. Security review (finding H1) confirmed this must NOT become `Informational`: `"unsound"` describes a real UB/memory-safety defect, not a maintenance-status notice, and the `Informational` hover label's "not a vulnerability" framing would be actively misleading here |
| Record has a graded `severity` field on one relevant entry AND an `informational` value on a *different* relevant entry of the same record (hypothetical, not yet live-observed) | Per FR-005/FR-002a, graded severity remains primary — the two-pass precedence checks ALL relevant entries for graded severity before checking any for `informational`, so entry order does not matter |
| A dependency has both an informational advisory and one or more ordinary graded/unscored/malicious advisories | Each advisory keeps its own independent classification; the informational one must not be conflated with or hidden by unrelated advisories on the same dependency |
| `informational` value present at the record's top-level `database_specific` rather than per-`affected[]`-entry (not observed live for RUSTSEC-unmaintained records, which is documented as an `affected[]`-scoped field, but OSV's schema evolves) | Out of scope for this spec unless a live counterexample is found — FR-001 only adds the per-entry field |
| `Capped` truncation (`ADVISORY_DISPLAY_CAP`) causes an informational advisory to fall outside the displayed slice | Out of scope for this spec — no reordering; pre-existing truncation/ordering behavior is unchanged, matching the #646 precedent's resolution for the same question |
| `OsvVulnRecord::into_advisory` falls back to using ALL `affected[]` entries because none matched the queried package (existing fallback, `types.rs:1039-1047`), and one of those unrelated entries carries an `informational` value (critic finding 6a) | Per FR-002b: the informational classification MUST NOT apply from this fallback set — the record classifies as it would have before this spec (graded severity if present anywhere, else `Unknown`). Prevents a stranger package's maintenance-status notice from silently downgrading a possibly-real advisory's severity for the queried package |
| `MAL-` id/alias prefix present AND an `informational` value present on a relevant entry (both signals on the same record) | `Malicious` wins — the existing `MAL-` check runs first in `classify()`'s chain and returns immediately, before either the graded-severity or the new informational pass; unchanged by this spec |
| `informational` field present but value is an empty string, whitespace-only string, or `null` | Treated as absent — does not trigger `Informational` classification (FR-007); record classifies per existing rules (graded severity or `Unknown`) |
| Advisory classified as `Informational` has no `summary` text from OSV | Hover label must still read as a self-contained notice (FR-003) — do not degrade to a bare category word plus a "(no summary provided)" placeholder that conveys nothing about *why* the advisory is informational |
| `check_candidates()`'s displayed (`Capped`) advisory slice is ALL `Informational`, but more advisories exist beyond the displayed/capped slice (of unknown severity) | RESOLVED architecturally, not via a truncation-count comparison: since FR-008 (revised) never touches `check_candidates()`, its existing `Capped`-aware `CandidateVulnerable`/`CandidateClean` classification is untouched and keeps its pre-existing correctness guarantee (`code_actions.rs`'s `!advisory_ids.is_complete()` rejection, unrelated to this spec, still applies exactly as before). This edge case was only a risk under the superseded check_candidates-level design (security finding M1 / impl-critic S1) and does not exist under the hover-rendering-only design |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover rendering for `RUSTSEC-2024-0320` (`yaml-rust`) or an equivalent live informational record | Never renders `"unknown severity"`; renders a distinct informational/unmaintained-category label |
| SC-002 | Diagnostic distinguishability | An informational-advisory diagnostic and a `VulnSeverity::Unknown` ordinary-CVE diagnostic on the same dependency are distinguishable without opening hover — verified via severity (`INFORMATION` vs `WARNING`) AND, since severity alone may not render distinctly in every client's UI chrome, the `[INFORMATIONAL]` message prefix. Verify visually in at least one real editor's Problems-panel-equivalent, not by unit assertion alone (critic finding 2) |
| SC-003 | Regression | All existing `severity.rs` and hover/diagnostics tests for non-informational `Unknown` records continue to pass unchanged |
| SC-004 | Cross-ecosystem consistency | The fix lives entirely in `deps-core::osv` / `deps-core::lsp_helpers` — no ecosystem crate needs a parallel change to see the new classification (per NFR-002 and the project's cross-ecosystem-consistency rule); confirmed true by critic review — `VulnSeverity` and `OsvAffected`/`relevant_affected` never leave `deps-core::osv` |
| SC-005 | No misleading "also affected" line | Hovering an `Informational`-only advisory never shows the "Latest version is also affected" candidate-vulnerable line (FR-008) |

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
- Add/update unit tests in `severity.rs` covering, at minimum: the plain
  `"unmaintained"` case; the `"unknown"`-value-collision edge case
  (FR-007); the both-graded-and-informational-present case across two
  different relevant entries (FR-005/FR-002a); the `MAL-` + informational
  combination (Malicious still wins); informational present only on a
  *non-relevant* / fallback-all entry (FR-002b — must NOT classify as
  Informational); and `informational: ""` / whitespace-only / `null`
  (must NOT classify as Informational, FR-007)
- Update `severity_rank` (`types.rs:489`) for the new variant — this is a
  compile-time-enforced exhaustive match, so it cannot be skipped
- Update `README.md` (`:362`, `:373`) and `docs/ECOSYSTEM_GUIDE.md` (`:74`)
  wherever they enumerate the hover severity-label list verbatim, per
  `.claude/rules/branching.md`
- Update `CHANGELOG.md`'s `[Unreleased]` section with a one-line entry for
  this change (impl-critic finding M6) — link the PR once its number is
  known, per `.claude/CLAUDE.md`
- Add a test asserting `into_advisory` itself computes the genuine-match
  signal correctly end-to-end (impl-critic finding M3) — not just a unit
  test that hands the signal in directly to `classify()`
- Add a hover-rendering test for the mixed informational+non-informational
  candidate-vulnerable case (FR-008, revised architecture: verify the line
  still renders and still lists only the non-informational id(s) when the
  set is mixed) — supersedes the originally-planned `check_candidates()`
  mixed-case test (impl-critic finding M5), which no longer applies since
  `check_candidates()` is untouched by this spec
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest,
  rustdoc gate) per project convention before any PR
- Live-verify against a real current OSV `informational`-carrying record
  (e.g. re-query `RUSTSEC-2024-0320`/`yaml-rust`, since OSV data can
  change) per the project's Live Testing Principle
  (`.claude/rules/continuous-improvement.md`) — do not conclude from code
  reading or unit tests alone. Also visually confirm the diagnostic and
  hover render distinctly in a real editor per SC-002 — a passing unit
  test alone does not confirm Problems-panel visibility

### Ask First
- (resolved, see §9) Any further deviation from the decisions recorded in
  §9 must still be surfaced to the user before implementation proceeds

### Never
- Fold informational classification into the existing graded-severity scale
  in a way that makes it indistinguishable from an ordinary CVE — the whole
  point of this spec is that "no maintainer" is categorically different
  from "known/suspected vulnerability"
- File this as fixed without live-testing against a real
  `informational`-carrying OSV record, per the project's Live Testing
  Principle

## 9. Open Questions

All open questions were resolved with the user prior to implementation
(2026-09-14), with **(a)** revised on 2026-09-14 after `rust-critic`
review of the initial resolution surfaced a concrete regression risk:

- **(a) Target classification and `DiagnosticSeverity`** — REVISED. Initial
  resolution chose a new `VulnSeverity::Informational` variant mapped to
  `DiagnosticSeverity::HINT`. Critic review found this fails the spec's own
  Goal and US-002/SC-002: VS Code's Problems panel excludes `Hint`-severity
  diagnostics entirely (Zed de-emphasizes them too), and FR-004 as
  originally written forbade a message-text fallback signal — so an
  `Informational` finding could become *less* visible than today's
  `WARNING`-bucket `Unknown` treatment, the opposite of the spec's goal.
  Final resolution: `VulnSeverity::Informational` maps to
  `DiagnosticSeverity::INFORMATION` (already used for `Medium`/`Low` and
  the "+N more advisories" notice — confirmed to render in Problems panels)
  AND the diagnostic message carries a `[INFORMATIONAL]` prefix, mirroring
  the `[MALWARE]` precedent from #646's `Malicious` variant. Applied in
  FR-002/FR-004 and the `VulnSeverity`/`to_diagnostic_severity()`
  data-model entries above.
- **(a-precedence) Classification precedence mechanics** — not originally
  posed as a question, but critic review found the spec's own §5 wording
  ("most naturally slotted after the `MAL-` check and before or
  *interleaved with* the graded-severity fallback") would violate FR-005
  if implemented as an interleaved per-entry check, because `classify()`
  returns on the first relevant entry with a graded severity — an earlier
  entry's `informational` value could win over a later entry's graded
  severity. Resolved: `classify()` implements two full passes over
  `relevant_affected` — graded severity first (unchanged from today, first
  match wins), informational second, only if no entry in the first pass
  matched (FR-002a). See FR-002a/FR-002b for the corrected precedence
  rule, including the additional "no genuine package match" fallback
  guard (FR-002b, critic finding 6a).
- **(b) Deprecation-pathway unification**: kept as a `VulnSeverity`-adjacent
  sibling category alongside `Malicious`, not unified with the
  `Deprecation`/`push_deprecation_diagnostic` pathway from #205 — that
  pathway is populated from a separate `Registry`/`VersionData::outcomes`
  data path, and unifying would require nontrivial cross-pipeline threading
  out of proportion with this P3 item's scope.
- **(c) Per-value distinction** — SUPERSEDED by (f) below. Originally:
  generic handling, any non-empty `informational` value (including OSV's
  own `"unknown"` enum value) maps to the same `VulnSeverity::Informational`
  category, per FR-007, no per-value special-casing. Security review
  (finding H1, 2026-09-14) found a concrete counterexample —
  RUSTSEC's `"unsound"` value — that this generic rule mishandled; see (f)
  for the narrowed, current rule. The FR-004 message prefix remains the
  generic `[INFORMATIONAL]` (not a value-specific tag) for the two values
  that DO still classify as `Informational` under (f) — a per-value tag
  remains unwarranted by the currently live-observed values.
- **(d) Hover icon/callout**: text-label-only, no dedicated icon/callout
  treatment — consistent with every existing severity label except
  `Malicious`'s `[MALWARE]` prefix, and proportionate to a P3 item.
- **(e) "Latest version is also affected" candidate-vulnerable line**
  (critic finding 6b, not originally scoped) — SUPERSEDED by (g) below for
  *how* it's implemented; the *what* (suppress the line for
  Informational-only findings) still holds. Originally: `check_candidates()`
  (`crates/deps-core/src/osv/mod.rs:218-226`) marks any informational-only
  finding as `CandidateVulnerable` today, so hover shows a misleading
  "Latest version X is also affected" line for an already-unmaintained
  package. Original resolution (superseded): suppress inside
  `check_candidates()` itself. See (g) for why that locus was wrong and
  what replaced it.
- **(f) `informational` value allowlist** (security review findings H1 and
  L1, 2026-09-14, supersedes (c)) — REVISED TWICE. RUSTSEC's
  `informational` field carries three live values — `"unmaintained"`,
  `"unsound"`, `"notice"`. First revision (H1): `"unsound"`
  (live-verified: `RUSTSEC-2021-0145`/`atty` "potential unaligned read",
  `RUSTSEC-2019-0036`/`failure` "type confusion") denotes a real
  memory-safety/UB defect, not a maintenance-status notice — the original
  generic rule (c) would have classified it `Informational` with a hover
  label literally reading "not a vulnerability", a false downgrade of a
  real security finding. Resolved (first pass): FR-007 became an allowlist
  of `"unmaintained"`/`"notice"`. Second revision (L1, same review cycle):
  re-audit found `"notice"` is ALSO not a reliably maintenance-only
  category — live-verified `RUSTSEC-2026-0174`/`http-types` carries
  `informational: "notice"` while describing a real defect (an `unsafe`
  justification for an ASCII-invariant guarantee found to be incorrect),
  the same failure class as H1 at smaller scale (~12 `notice` records vs.
  100+ `unsound` in the live RUSTSEC corpus at review time, some purely
  editorial and some not). Final resolution: FR-007's allowlist is
  `"unmaintained"` alone. Every other value — `"unsound"`, `"notice"`,
  OSV's own `"unknown"` enum value, any unrecognized future value, a
  missing/`null`/empty/whitespace-only value — falls through to the
  existing precedence chain (graded severity, else `Unknown`/`WARNING`).
  This is a deliberate fail-safe default, applied consistently: an
  unrecognized or unreliable `informational` value keeps today's
  more-visible `WARNING` treatment rather than being silently downgraded
  to the less-visible `Informational`/`INFORMATION` bucket. `"unmaintained"`
  alone was judged reliably single-purpose across the live corpus checked
  during this review.
- **(g) Implementation locus for the candidate-vulnerable suppression**
  (impl-critic implementation-critique findings S1/S2, 2026-09-14,
  supersedes (e)'s original locus): filtering `Informational` advisories
  out inside `check_candidates()` itself (the original (e) resolution) had
  two bugs — it compared against the *displayed* (`Capped`,
  `ADVISORY_DISPLAY_CAP`-truncated) advisory slice rather than the true
  `total()` (security finding M1, a real advisory beyond the cap could be
  silently swallowed into a false "clean" verdict), and it changed
  `UpgradeStatus`/`fix_target_is_verified` (`code_actions.rs:59`)
  behavior that the original (e) explicitly promised would stay
  unaffected — bypassing the `!advisory_ids.is_complete()` safety
  rejection `code_actions.rs` already relies on for exactly this failure
  mode (#462 critic M1 precedent). Resolved: `check_candidates()` is
  reverted to byte-for-byte its pre-feature state; the "also affected"
  line is suppressed purely as a hover-render-time filter
  (`crates/deps-core/src/lsp_helpers/hover.rs`) over the advisory ids
  `check_candidates()` already returns — `check_candidates()`,
  `UpgradeStatus`, and every downstream consumer remain untouched by this
  spec, restoring (e)'s original scope commitment. The render-time filter
  must fail OPEN (render the line) whenever it cannot confirm every
  candidate id is `Informational` — including when the candidate id set
  itself is empty (a real vulnerability signal whose detail fetch failed
  or was capped out must never be silently dropped just because no
  severity could be confirmed for it at render time; impl-critic finding
  N1). ADDITIONALLY (security re-review finding L2, same review cycle):
  the render-time filter must accept the candidate id set as its original
  `Capped<String>` type (not a bare `Vec`/slice) and fail OPEN whenever
  `!candidate_ids.is_complete()` — the same truncation-blindness risk (e)
  and M1 already identified for `check_candidates()`'s old locus recurs,
  narrower in scope, at the new hover-render locus: if more than
  `ADVISORY_DISPLAY_CAP` advisories exist for the candidate version and
  every one of the *displayed* ones happens to be `Informational`, the
  line must still render, because an undisplayed advisory beyond the cap
  could be a real vulnerability (FR-010).

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

---
aliases:
  - cli update Cooldown Fallback
tags:
  - sdd
  - spec
  - bug
  - deps-cli
  - deps-core
  - deps-engine
  - priority/p2
created: 2026-09-27
status: ready
related:
  - "[[constitution]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec]]"
  - "[[074-deps-cli-gossip-parity/spec]]"
  - "[[072-deps-dev-gossip-signals/spec]]"
  - "[[068-cli-update-subcommand/spec]]"
---

# Feature: `deps-cli update`'s freshness-cooldown fallback and check/update precedence unification

> [!info] Metadata
> **Author**: spec session 2026-09-27, following debug/architect/critic investigation of issues
> `#1528` and `#1529`
> **Branch**: `fix/1528-1529-cooldown-fallback-precedence`
> **Type**: bug, P2/P3, cross-cutting `deps-core`/`deps-engine`/`deps-cli`. Two review rounds
> (independent `rust-critic` passes, 2026-09-27) found and closed 5 significant gaps (S1-S5) in
> the first design, then 2 more (A1, A2) in the revision — both encoded as formal requirements
> below, not left as implementation notes.

## 1. Overview

### Problem Statement

Two related defects in `deps-cli`'s freshness-cooldown handling, both rooted in PR #1527:

1. **#1528 — starvation.** When a dependency's registry-`latest` is within the freshness cooldown
   window (local heuristic or GOSSIP), `deps-cli update` skips it entirely
   (`SkipReason::WithinFreshnessCooldown`) with no fallback to an older, already-cooled-down
   version. A package that publishes releases more frequently than the cooldown window (e.g. every
   2 days against a 3-day default) can therefore never be updated by `deps-cli update` — every
   `latest` it ever observes is always still within cooldown.
2. **#1529 — precedence divergence.** `deps-lsp`'s `apply_outdated_rule` treats a GOSSIP verdict
   (`Active`/`NotActive`) as authoritative over the local `freshness.cooldown_secs` heuristic
   whenever GOSSIP has data for the exact version. `deps-cli check` was assumed to have the same
   behavior, but does not: `ManifestAnalysis::version_data()` never calls
   `with_gossip_prefetch`, even though `analyze_manifest` already computes the exact
   `gossip_findings` map needed. `deps-cli check`'s cooldown wording always falls through to the
   local heuristic — a real divergence between `deps-lsp` and `deps-cli`, discovered during
   debugging while investigating what was assumed to be a `check`-vs-`update` divergence.

Both defects were investigated together because a naive fix for #1528 (walk `available`
newest-first, pick the first that clears cooldown) would reopen the exact vulnerability class PR
#1530 just closed: an older, intermediate version becomes newly reachable through `deps-cli
update` without independent OSV verification. Two adversarial review rounds also found:

- the naive fallback pick is blind to ecosystem selection rules (can select a yanked or
  prerelease version — S1);
- `Outdated` does not imply "newer than what's declared" for a non-lockfile-resolved requirement
  used as a synthetic `latest` (a stale lock can make a fallback into a silent downgrade — S2/A1);
- GOSSIP `NotActive` was fail-open for a **write** path when GOSSIP data is malformed or
  ingestion-lagged (S3);
- ignore-rule evaluation order and `PackageVersions` construction defaults could silently bypass
  the new gates (S4/S5).

### Goal

`deps-cli update` selects, for a cooldown-blocked dependency, the newest already-cooled-down,
OSV-verified, floor-protected candidate version as its write target instead of skipping the
dependency outright — and `deps-cli check`/`update` share one, single GOSSIP-vs-local-heuristic
precedence function so the two commands (and `deps-lsp`) can no longer print or act on
contradictory cooldown verdicts for the same version.

### Out of Scope

- **No-floor fallback** (a range requirement with no lockfile-resolved in-use version — the
  majority case per spec 074 §3). This spec's fallback requires either a lockfile-resolved in-use
  version (D2 floor) or an exact-pin ecosystem where the declared requirement itself is the
  in-use version. Without one, the outcome stays `NoneUsable` today's-skip, unchanged. See
  OQ1 below and §11 for the required follow-up issue — **the PR closing this spec's issues must
  say "partially addresses #1528", not "Closes #1528"**, unless the maintainer explicitly accepts
  this as full closure.
- `deps-lsp` code-action / hover convergence onto the same fallback candidate. The engine computes
  `cooldown_fallback` unconditionally when freshness is enabled, but no `deps-lsp` surface reads it
  in this spec — restated as an open question for a future spec, not implemented here.
- Iterating past a single OSV-`Flagged`/`Unverified` fallback candidate to try an older one. One
  candidate is computed and verified; if it fails verification, the outcome is a block, not a
  second attempt.
- `deps-cli update --security-only` — unaffected, fix target already comes from the advisory, not
  from freshness/GOSSIP (spec 068 FR-014, spec 074 FR-006).
- `check` wording naming the fallback version. `check` gets the same `cooldown_disposition`
  precedence as `update` (fixing #1529's divergence), but does not print anything about a fallback
  candidate — `check` never writes, so a fallback is not actionable information for it.
- Any new `deps-core` GOSSIP data type or deps.dev endpoint. The R-S3 change (§4, FR-005) is a
  reinterpretation of an existing three-state enum's `None` case, not a new type.

## 2. User Stories

### US-001: `deps-cli update` no longer starves on a frequent publisher

AS A `deps-cli update` user with a dependency that publishes new releases faster than the
configured freshness-cooldown window
I WANT `update` to fall back to the newest already-cooled-down, safe version instead of skipping
the dependency on every run
SO THAT the dependency is not permanently frozen at its current version

**Acceptance criteria:**
```
GIVEN a dependency with a lockfile-resolved in-use version 1.0.0, releases 1.1.0 (cooled, OSV
  Verified), 1.2.0 (within cooldown) published newest-first, and freshness.enabled = true
WHEN deps-cli update classifies this dependency
THEN it targets 1.1.0 (Applied), attributes the exclusion of 1.2.0 in the reason/JSON output
  (cooldown_fallback: AppliedInsteadOf(1.2.0)), and does not report SkipReason::WithinFreshnessCooldown
```
```
GIVEN the same dependency but 1.1.0 is OSV-Unverified (network timeout) or OSV-Flagged
WHEN deps-cli update classifies this dependency
THEN it does NOT write 1.1.0, exits non-zero (exit 1, OQ5'), and names 1.1.0 plus its
  advisory_ids/verdict reason in the attribution — never a silent WithinFreshnessCooldown skip
```
```
GIVEN a dependency with no lockfile-resolved in-use version and a range requirement (e.g. `^2.0`
  or `>=3.0`)
WHEN deps-cli update classifies this dependency and latest is within cooldown
THEN it reports SkipReason::WithinFreshnessCooldown exactly as today (no fallback attempted) — this
  is the documented, out-of-scope limitation (OQ1)
```

### US-002: `check` and `update` never disagree on whether a version is "in cooldown"

AS A `deps-cli` user running both `check` (CI gate) and `update` (automation) against the same
manifest and GOSSIP configuration
I WANT both commands to reach the same cooldown verdict for the same version
SO THAT CI and automation do not contradict each other about whether a release is safe to adopt

**Acceptance criteria:**
```
GIVEN [gossip].enabled = true and a dependency whose exact latest version has a GOSSIP verdict
  (Active or a parsed-and-past `end`, i.e. NotActive per FR-005)
WHEN deps-cli check renders its outdated-diagnostic wording, and deps-cli update classifies the
  same dependency
THEN both consult the same cooldown_disposition() precedence (deps-core), and check's wording
  matches what update's decision implies (GOSSIP-attributed text when GOSSIP is definitive, local
  heuristic wording only when GOSSIP has no verdict for that exact version)
```

## 3. Functional Requirements

Resolved by direct code inspection at HEAD `120e31a42` during debugger/architect/critic
investigation (2026-09-27) — see `plan.md` for exact call-site line numbers. Requirement IDs below
map 1:1 onto the architect's revised plan (`architect` handoff `2026-09-27T11-12-09`) sections
R-S1..R-S5, R-M1..R-M4, amended per critic's final re-critique (`critic` handoff
`2026-09-27T11-15-08`, amendments A1/A2, verdict: minor, conditionally approved on A1/A2 being
encoded here).

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `deps-engine::classify::fetch::fetch_and_classify_package` computes a fallback candidate for a cooldown-blocked `latest` (freshness enabled) THE SYSTEM SHALL additionally require the candidate to satisfy `!removal_status().blocks_resolution()` and `!is_prerelease()` (unless `latest` itself is a prerelease) — closing the yanked/prerelease selection-rule leak in `select_latest_for_existence`'s rung 2/3 (S1). WHEN the top-ranked cooldown-cleared candidate fails either check THE SYSTEM SHALL NOT retry further down the list — the outcome is "no fallback" (`cooldown_fallback: None`), not a second attempt | must |
| FR-002 | WHEN computing the fallback candidate THE SYSTEM SHALL enforce the D2 in-use floor: the candidate must sit strictly newer (lower `available` index) than the newest lockfile-resolved in-use version for that dependency. WHEN no in-use version is resolved (no lockfile, or a range requirement without one) THE SYSTEM SHALL NOT compute a fallback for that dependency (`cooldown_fallback: None`) — this is the documented OQ1 limitation, not a defect | must |
| FR-003 | **(A1, must-encode; corrected by fix-cycle item 1/S1, impl-critic 2026-09-27)** WHEN a manifest occurrence's declared requirement is used to determine whether the fallback candidate would be a downgrade THE SYSTEM SHALL use `compile_requirement` (the ecosystem's precise version matcher, implemented across all 14 ecosystems), NOT `version_satisfies_requirement` (the default heuristic, which only understands `^`/`~`/bare/partial forms and returns `false` for `>=3.0`, `>=3,<4`, `3.x`, or `||` ranges on ecosystems that do not override it, e.g. Cargo/npm). THE SYSTEM SHALL reject the fallback candidate (`NoneUsable`) iff the compiled matcher is unavailable (`None`), OR it accepts some `available` entry strictly newer than the fallback candidate (`available` is newest-first, so "newer" is every entry ahead of the fallback's own position) — meaning the declared requirement, left unedited, already resolves forward past the fallback on its own, so writing the fallback would move the manifest backward relative to what re-resolution already gives it. **The original wording here ("no available entry satisfies it") was proven inverted**: since the fallback view (FR-008/FR-009) only ever marks a candidate `Planned` when it does NOT satisfy the requirement under the loose default heuristic, requiring the compiled matcher to *accept* the fallback made this guard self-contradictory and rejected every legitimate fallback outside the Go exception (proven with a real `NpmFormatter` against US-001's own fixture). **Exception**: WHEN `formatter.manifest_requirement_is_resolved_version(dep)` is `true` (currently only Go's `require` directive, whose `go.mod` entry is already the MVS-selected version, not a range) THE SYSTEM SHALL treat the D2 engine floor (FR-002) as already serving this requirement floor, since the declared requirement IS the in-use version there | must |
| FR-004 | THE SYSTEM SHALL expose one `pub fn cooldown_disposition(versions: &PackageVersions, name: &PackageName, freshness: FreshnessSettings, gossip_prefetch: Option<&HashMap<PackageName, GossipFindings>>, now: PublishTime) -> CooldownDisposition<'_>` in `deps_core::lsp_helpers`, evaluated at READ time (never stored), per the precedence order in NFR-001. `apply_outdated_rule` (check/hover/LSP diagnostics wording) and the `deps-cli update` planner SHALL both call this function as their sole source of cooldown-vs-GOSSIP truth; `within_freshness_cooldown` SHALL be deleted | must |
| FR-005 | **(R-S3)** `gossip_cooldown_for`/`GossipCooldownLookup` (`deps_core::lsp_helpers`) SHALL map `findings.cooldown == None` to `Unavailable` (was `NotActive`). `NotActive` SHALL mean only "GOSSIP reported a cooldown finding with a parsed `end` that has passed" — a missing or unparseable `end`, or the total absence of a COOLDOWN finding, is no longer treated as an authoritative "not in cooldown" answer. This changes the shared gate consulted by `check`, `update`, LSP hover, and LSP diagnostics identically | must |
| FR-006 | WHEN `deps-cli::analyze::analyze_manifest` builds a `ManifestAnalysis` THE SYSTEM SHALL store the already-computed `gossip_findings: HashMap<PackageName, GossipFindings>` map on it and wire it into `version_data()` via `.with_gossip_prefetch(&self.gossip_findings)` — fixing `check`'s dead GOSSIP branch (debug finding 1) independently of the fallback feature, so `check` and `update` use one precedence (FR-004) end to end | must |
| FR-007 | **(R-S4/A2, unified per-occurrence planner)** `deps-cli update`'s planner SHALL build, per manifest occurrence (keyed by `name_range`), one `OccurrenceCandidate` (`Planned(PlannedUpdate)` \| `Unplannable(UnplannableReason)`) for the latest view AND, when `cooldown_disposition` reports `Blocked { fallback: Some(_) }` for that occurrence, a second `OccurrenceCandidate` for the fallback view. `cooldown_disposition` SHALL then select which view supplies the write target for that occurrence. `is_requested` (`--package` filtering), `ignore_rules.skip_reason(classify_update(current, target))`, and every outcome mapping SHALL run exactly once, against the SELECTED write target — never against `latest` when the fallback was chosen. The two existing loops (`planned` closure and `unplannable` loop) collapse into this one pipeline | must |
| FR-008 | **(A2a, defense in depth)** THE SYSTEM SHALL consult the fallback view for an occurrence ONLY WHEN that occurrence is `Outdated` in the latest view (i.e., latest genuinely does not satisfy the declared requirement) — on top of FR-003's requirement-floor guard, not instead of it | must |
| FR-009 | **(A2b)** WHEN an occurrence is `Blocked { fallback: Some(_) }` but the fallback candidate itself already satisfies the occurrence's declared requirement (so it is not `Outdated` in the fallback view, i.e. absent from it) THE SYSTEM SHALL resolve that occurrence to `NoneUsable` (today's `WithinFreshnessCooldown` skip) — never silently treat "no fallback view entry" as "use latest anyway" | must |
| FR-010 | **(R-M2)** THE SYSTEM SHALL OSV-verify every occurrence's fallback candidate via `build_latest_check_targets` run over the fallback view, as a 4th future in `analyze_manifest`'s existing `tokio::join!`, gated on a new `AnalysisScope` boolean field (e.g. `cooldown_fallback`) rather than an equality check against `update_default()`. Results SHALL be stored in a separate `ManifestAnalysis::fallback_status: LatestStatusMap`, NEVER merged into `latest_status` (a merge would overwrite `latest`'s own verdict via the version-equality check in `upgrade_status_to_verdict`). `vuln_keys` SHALL be computed once and shared between the latest-status and fallback-status futures. There is no rank cap (unlike `CandidateStatusMap`'s `MAX_CANDIDATE_CHECK_VERSIONS`), closing the starvation return-path a rank-capped check would reopen for a frequent publisher | must |
| FR-011 | **(OQ5', resolved by the user)** WHEN the fallback candidate selected for an occurrence is OSV `Flagged` or `Unverified` THE SYSTEM SHALL map that occurrence to the existing `NotSafelyEditable`-equivalent outcome (exit code 1), naming the fallback version and its `advisory_ids`/verdict reason in the attribution — NOT a silent or exit-0 `WithinFreshnessCooldown` skip. This applies uniformly to Flagged and Unverified (parity with today's existing behavior for a Flagged/Unverified `latest` itself, which already maps to `NotSafelyEditable`/exit 1 despite also being neither installed nor written) | must |
| FR-012 | **(OQ3)** WHEN `latest` itself is `Unplannable` due to an OSV `Flagged`/`Unverified` verdict, but its `cooldown_fallback` candidate is independently OSV `Verified` or `NotApplicable` (and passes FR-001/002/003/008/009) THE SYSTEM SHALL target the fallback (`Applied`), while KEEPING the flagged/unverified-latest attribution (`advisory_ids`, verdict reason) in the same output row — the existing `*_flagged_latest_is_never_masked_by_cooldown` / `*_unverified_latest_is_never_masked_by_cooldown` fixtures use a `latest_only` manifest (no fallback candidate) and their expectations are UNCHANGED; a new fixture with a fallback candidate present covers this new branch | must |
| FR-013 | THE SYSTEM SHALL add `PlannedUpdateItem.cooldown_fallback: Option<CooldownFallbackNote>` where `CooldownFallbackNote` is `AppliedInsteadOf(ConcreteVersion)` (fallback was written, this names the excluded fresh `latest`) or `Blocked { version: ConcreteVersion }` (a fallback existed but was OSV-blocked, FR-011) — one field so the two cases cannot both be set simultaneously. `reason()` text and `--format json` output SHALL surface it; the JSON field is additive (omitted when `None`) | must |
| FR-014 | THE SYSTEM SHALL update `SkipReason::WithinFreshnessCooldown`'s doc comment (`crates/deps-cli/src/update/mod.rs:129-139`) to reflect the new meaning: "nothing available clears cooldown (no fallback candidate, or the fallback itself does not clear the declared-requirement/in-use floor)" — its current "not guaranteed to self-resolve... starves a package" framing becomes stale once the fallback path exists | must |
| FR-015 | `dedup_overlapping_edits` (or equivalent overlap-collapsing step) SHALL run AFTER the per-occurrence view selection (FR-007), over the chosen `PlannedUpdate`s only — never over both views' candidates | must |

> [!info] Amended by [[076-cli-update-cooldown-fallback-no-lockfile/spec]]
> **FR-002**: "no in-use version resolved... SHALL NOT compute a fallback" is no longer
> categorical. Spec 076 extends the fallback to this case too (issue #1544), gated on the same
> per-occurrence requirement-floor guard FR-003 originally introduced — now generalized as spec
> 076 FR-023's `fallback_edit_excludes_newer`.
>
> **FR-003**: the `formatter.manifest_requirement_is_resolved_version(dep)` exception (the Go
> `require`-directive bypass) is REMOVED by spec 076 FR-022 — Go's `ExactMatcher` alone (no bypass)
> is sufficient once spec 076's guard ships; the exception guarded an unreachable branch. The
> compiled-matcher check this FR introduced is itself superseded by spec 076 FR-023/FR-024's
> re-parse-based `fallback_edit_excludes_newer`, which validates the manifest's EFFECTIVE post-edit
> requirement (after applying the candidate edit and re-parsing) rather than compiling the
> declared requirement's text directly — spec 076's own round-2 review found that compiling text
> directly is wrong for some grammars (Swift's `from:`/`.exact`/`.upToNextMinor` labels, Bundler's
> multi-constraint literals).

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Consistency (amends spec 074 NFR-004, `[[074-deps-cli-gossip-parity/spec]]`) | Within `deps-cli`, `check` and `update` SHALL apply one precedence model (`cooldown_disposition`, FR-004) for the freshness cooldown, in this exact order: **(0)** `freshness.enabled == false`: no cooldown effect (`NotEvaluated`), no fallback computed. **(1)** OSV `Flagged`/`Unverified` on the exact candidate: never written — on `latest` via `latest_status` (existing), on a fallback candidate via `fallback_status` (FR-010); if the candidate is the chosen fallback rather than `latest`, this is a hard failure (`NotSafelyEditable`-equivalent, exit 1, FR-011), not a silent cooldown skip. **(2)** GOSSIP reported a parsed cooldown `end` for the exact version (FR-005): an active one blocks, a past one clears; a missing or unparseable `end` (or no COOLDOWN finding at all) means no GOSSIP verdict, fall through. **(3)** Otherwise, the local `is_within_cooldown(published_at)` applies; a missing `published_at` clears `latest` (unchanged today) but does NOT clear a non-latest candidate (fail closed, OQ2). **(4)** The fallback (when one exists) is the newest candidate passing steps 0-3 plus FR-001 (ecosystem safety), FR-002 (in-use floor), and FR-003/FR-008/FR-009 (per-occurrence requirement floor) — otherwise the occurrence is `NoneUsable`. `PackageVersions::latest` and every `deps-lsp` surface other than the shared FR-005 gate are unchanged by this spec |
| NFR-002 | Reliability | `cooldown_disposition` is evaluated at READ time from `latest.published_at`, `gossip_cooldown_for`, and the stored `cooldown_fallback` candidate — never a fetch-time snapshot. A changed `freshness.cooldown_secs` between fetch and read can only make the outcome stricter (a previously-cleared fallback re-evaluated as still-cooling), never unsafe (satisfies spec 072 FR-011's read-time evaluation requirement, which a stored disposition enum would violate) |
| NFR-003 | Reliability | Any `PackageVersions` construction path that does not explicitly set `cooldown_fallback` (builder default, `get_latest_matching_from`'s fallback-pick branch, test fixtures) SHALL default to `None` — a missing fallback candidate must never be silently treated as "fresh latest may proceed" |
| NFR-004 | Performance | The FR-010 OSV round costs zero extra network calls on a typical run: it is gated on `AnalysisScope::cooldown_fallback` (only set for `update`'s default mode) and only fires for occurrences where `cooldown_disposition` already found `Blocked { fallback: Some(_) }` in a first pass |
| NFR-005 | Compatibility | FR-013's `cooldown_fallback` JSON field is additive (omitted when `None`) — NOT a breaking change (OQ6). It is documented in `CHANGELOG.md` under `### Changed`, not `### Breaking`, alongside: (a) the FR-005 GOSSIP-wording change (a version with no parsed cooldown `end` no longer reads as an authoritative "not in cooldown" in `check`/hover/diagnostics text), and (b) spec 074 FR-003b's behavior for a no-lockfile dependency whose `latest` is GOSSIP-`Active`: `update` now skips it (`WithinFreshnessCooldown`) instead of applying it, per NFR-001 step 2 combined with FR-002's "no floor, no fallback" rule |
| NFR-006 | Testability | Every row of §6's decision table SHALL be reachable by an existing or new test named in §7's traceability table — no row may be asserted only by code inspection |

> [!info] Amended by [[076-cli-update-cooldown-fallback-no-lockfile/spec]]
> **NFR-001 step 4**: the fallback selection criteria "FR-002 (in-use floor)... FR-003 (per-occurrence
> requirement floor)" is superseded — the in-use floor now has a third state (no in-use version
> resolved is no longer an unconditional exclusion, spec 076 FR-016/FR-017), and the requirement
> floor is spec 076 FR-023/FR-024's re-parse-based `fallback_edit_excludes_newer`, applied
> identically to this spec's lockfile-resolved path and spec 076's no-lockfile path.
>
> **NFR-005(b)**: the no-lockfile GOSSIP-`Active`-dependency behavior described here ("`update` now
> skips it... instead of applying it, per NFR-001 step 2 combined with FR-002's 'no floor, no
> fallback' rule") is superseded a second time. Spec 076 potentially restores "applied" for this
> case — but ONLY when spec 076 FR-023's guard passes for that dependency's ecosystem/requirement
> shape (the common case for npm/Composer/Bundler/Go/Maven/Gradle/NuGet; conditional for
> Cargo/Dart/PyPI/Swift depending on whether a known newer version falls inside or outside the
> written range, spec 076 FR-025). It remains "skipped" whenever that guard fails. This is a further
> `### Fixed`/`### Changed` `CHANGELOG.md` entry once spec 076 ships, not a reversion of this
> line's original `### Changed` entry.

## 5. Data Model

New, additive types in `deps_core::lsp_helpers` (unless noted):

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CooldownFallback` | The single cooldown-cleared, ecosystem-safe, floor-protected candidate the engine found for a dependency (or none). `#[non_exhaustive]` struct, stored as `Option<CooldownFallback>` on `PackageVersions` | `version: ConcreteVersion`, `published_at: PublishTime` (never `None` — a candidate without a publish time is never stored, OQ2) |
| `CooldownDisposition<'a>` | Exhaustive enum returned by `cooldown_disposition()`, read-time only, never persisted | `NotEvaluated` \| `Cleared` \| `Blocked { by: CooldownBlocker, fallback: Option<&'a CooldownFallback> }` |
| `CooldownBlocker` | What blocked `latest`, drives check/hover wording | `Gossip` \| `Local { published_at: PublishTime }` |
| `OccurrenceCandidate` (`deps-cli`-private) | Per-occurrence, per-view planning result feeding the unified pipeline (FR-007) | `Planned(PlannedUpdate)` \| `Unplannable(UnplannableReason)` |
| `PlannedUpdateItem.cooldown_fallback` | Attribution field on the existing planned-update item type (mirrors `gossip_excluded_version`'s shape) | `CooldownFallbackNote::AppliedInsteadOf(ConcreteVersion)` \| `CooldownFallbackNote::Blocked { version: ConcreteVersion }` |
| `ManifestAnalysis.fallback_status` | Separate OSV verdict map for fallback candidates only (FR-010) | `LatestStatusMap`, keyed identically to `latest_status` but populated from the fallback view |
| `ManifestAnalysis.gossip_findings` | Already-computed GOSSIP findings, now retained instead of discarded (FR-006) | `HashMap<PackageName, GossipFindings>` |

No wire-format or registry-protocol changes. `PackageVersions::latest` is unchanged.

## 6. Edge Cases and Error Handling

Includes the decision table required by critic amendment A2(c). Column "Outcome" is the result
BEFORE `NotRequested`/`IgnoreRule` are layered on top (§3 FR-007) — those two always evaluate
against whichever target this table selects.

| Disposition (FR-004) | Latest view | Fallback view | Selected target | Outcome |
|---|---|---|---|---|
| `NotEvaluated` / `Cleared` | `Planned` | n/a (not consulted, FR-008) | latest | Applied |
| `NotEvaluated` / `Cleared` | `Unplannable(osv)` | n/a | latest (unwritten) | `NotSafelyEditable`, exit 1 |
| `NotEvaluated` / `Cleared` | `Unplannable(other)` | n/a | latest (unwritten) | today's specific `Unplannable` reason, unchanged |
| `Blocked`, `fallback: None` | `Planned` / `Unplannable(other)` | absent | none | `WithinFreshnessCooldown` |
| `Blocked`, `fallback: None` | `Unplannable(osv)` | absent | latest (unwritten) | `NotSafelyEditable`, exit 1 — never demoted by cooldown |
| `Blocked`, `fallback: Some` | `Planned` / `Unplannable(other)` | absent (FR-009: fallback satisfies requirement, not `Outdated`) | none | `NoneUsable` → `WithinFreshnessCooldown` |
| `Blocked`, `fallback: Some` | `Unplannable(osv)` | absent (FR-009) | latest (unwritten) | `NotSafelyEditable` naming latest, exit 1 — never demoted (fix-cycle item 2/S2 correction: the original "any" wording here contradicted row 5/NFR-001(1) and let a flagged/unverified latest fall through to a silent exit-0 cooldown skip whenever no fallback view entry existed) |
| `Blocked`, `fallback: Some` | `Unplannable(osv)` | `Planned` | fallback | Applied(fallback), flagged-latest attribution kept (FR-012/OQ3) |
| `Blocked`, `fallback: Some` | `Unplannable(osv)` | `Unplannable(osv/other)` | none | `NotSafelyEditable` naming latest, exit 1 — never demoted |
| `Blocked`, `fallback: Some` | `Planned` / `Unplannable(other)` | `Planned` | fallback | Applied(fallback), `cooldown_fallback: AppliedInsteadOf(latest)` |
| `Blocked`, `fallback: Some` | `Planned` / `Unplannable(other)` | `Unplannable(osv)` | none | `NotSafelyEditable` naming FALLBACK version, exit 1 (FR-011/OQ5') |
| `Blocked`, `fallback: Some` | `Planned` / `Unplannable(other)` | `Unplannable(other)` | none | `WithinFreshnessCooldown` (fallback blocked by a non-OSV reason, e.g. placeholder/unsatisfiable span) |

> [!warning] Implementer note
> This table encodes the intent, not a proof of exhaustiveness. Before merging, run the 5 named
> regression tests in §7 plus every new test this spec requires; if any row's outcome disagrees
> with a passing existing test, the test's expectation wins and this table must be corrected in the
> same PR, not silently overridden in code.
>
> **This callout's own warning fired**: a post-implementation fix cycle (security/testing/
> impl-critic review, 2026-09-27) found row 6's original "any" latest-view wording contradicted
> row 5/NFR-001(1) (corrected above, splitting it into two rows) and that FR-003's original
> wording was inverted (corrected in FR-003's own row) — both closed in the same PR per this
> note's own instruction, with real-formatter (`NpmFormatter`, real `semver::VersionReq`) tests
> added alongside the existing Go-exception-only coverage.

Additional scenarios:

| Scenario | Expected Behavior |
|----------|-------------------|
| **S1 repro**: in-use 1.0.0 (yanked, floor idx 2), 1.1.0 (yanked, cooled, idx 1), 1.2.0 (fresh, idx 0) | FR-001's ecosystem-safety guard rejects 1.1.0 (yanked) with no retry — `cooldown_fallback: None`, `NoneUsable` |
| **A1 repro**: declared requirement `>=3.0`, lockfile 2.5.0, all 3.x fresh, 2.9.0 cooled | FR-003's `compile_requirement` check finds no `available` entry satisfying `>=3.0` below the floor is irrelevant here — the matcher-based check for whether 2.9.0 would be a downgrade below what the requirement already resolves to fails closed → `NoneUsable`, not a fallback to 2.9.0 |
| Go `require` directive (exact-pin case) | FR-003's exception applies: the D2 in-use floor (FR-002) alone gates the fallback, since the declared requirement already equals the in-use version |
| No lockfile, range requirement, GOSSIP-`Active` latest (spec 074 FR-003b case) | FR-002: no in-use version resolved → no fallback computed → `WithinFreshnessCooldown` (a behavior CHANGE from spec 074, where this was previously applied — see NFR-005b, requires CHANGELOG `### Changed`) |
| GOSSIP cooldown data present but `end` missing/unparseable | FR-005: `Unavailable`, not `NotActive` — falls through to the local heuristic (step 3) instead of being treated as an authoritative clear |
| `freshness.enabled == false` | `NotEvaluated` — no cooldown effect at all, independent of GOSSIP; `latest` may still be GOSSIP-substituted by spec 074 FR-003, which is unrelated to this gate (R-M3) |
| `deps-cli update --security-only` | Unaffected — fix target still comes from the advisory (spec 068 FR-014), never from `cooldown_disposition` |

## 7. Success Criteria

| ID | Metric | Target | Traceability (tests to keep / invert / add) |
|----|--------|--------|----------------------------------------------|
| SC-001 | Existing regression tests keep passing unchanged (except the 2 named inversions) | `crates/deps-cli/src/update/mod.rs`: `test_plan_updates_within_freshness_cooldown_is_skipped` (~834), `test_plan_updates_freshness_cooldown_takes_precedence_but_keeps_gossip_attribution` (~963), `test_plan_updates_flagged_latest_is_never_masked_by_cooldown` (~1134), `test_plan_updates_unverified_latest_is_never_masked_by_cooldown` (~1200), `test_plan_updates_unplannable_candidate_within_cooldown_is_cooldown_skip_not_unsafe` (~1257) — all `latest_only` fixtures, no fallback candidate present, so FR-007's unified pipeline must reduce to today's exact outcome for each | pass unchanged |
| SC-002 | 2 tests inverted by FR-005 (R-S3), named explicitly per critic requirement, not treated as regressions | `crates/deps-core/src/lsp_helpers/mod.rs::gossip_cooldown_for_present_but_no_cooldown_data_is_not_active` (~3478) + its fixture `gossip_findings_fixture_not_in_cooldown`; `crates/deps-core/src/lsp_helpers/diagnostics.rs::test_generate_diagnostics_from_cache_outdated_gossip_not_active_suppresses_local_fallback` (~6475) | updated to assert `Unavailable`/local-heuristic-fallback instead of `NotActive`/suppression |
| SC-003 | FR-001 (S1) ecosystem-safety guard | New test: the yanked/prerelease repro (§6 S1 repro) resolves to `cooldown_fallback: None`, never picks 1.1.0 | new, must pass |
| SC-004 | FR-003 (A1) requirement-floor guard | New test: the `>=3.0` repro (§6 A1 repro) resolves to `NoneUsable`, manifest untouched | new, must pass |
| SC-005 | FR-012 (OQ3) fallback overriding a flagged latest | New test: flagged latest + independently Verified fallback candidate → `Applied(fallback)` with flagged-latest attribution retained | new, must pass |
| SC-006 | FR-011 (OQ5') fallback OSV-blocked | New test: fallback candidate itself Flagged or Unverified → exit 1, `NotSafelyEditable`-equivalent, names the fallback version | new, must pass (2 cases: Flagged, Unverified) |
| SC-007 | FR-006 check/update parity | New `report.rs` test pinning the combined GOSSIP-wording + spec 074 FR-005 suffix message for `check`, now that `check` receives live `gossip_prefetch` data | new, must pass |
| SC-008 | Full CI check suite | `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate — all green | must pass before PR |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `gossip_cooldown_for`/`GossipCooldownLookup` (promoted `pub`) as the sole GOSSIP-precedence gate for the engine, `check`, `update`, and LSP hover/diagnostics — do not add a second copy.
- Reuse `build_latest_check_targets` for FR-010's fallback OSV round instead of introducing a new OSV-request builder.
- Keep `cooldown_fallback` computation and `cooldown_disposition` evaluation strictly separated (compute-time vs. read-time) per NFR-002 — never memoize a disposition.
- Run the full pre-commit check suite (`.claude/rules/branching.md`) before opening the PR — this touches `deps-engine`'s classification hot path and `deps-cli`'s planner, both covered by extensive existing tests.

### Ask First
- Any change to `PackageVersions`'s public shape beyond the additive `cooldown_fallback: Option<CooldownFallback>` field.
- Splitting `SkipReason::WithinFreshnessCooldown` into multiple variants instead of reusing the one variant with richer attribution (FR-013) — the closed OQ5 answer from the first critique round was to keep one variant; do not reopen without a maintainer decision.
- Deviating from OQ5''s exit-1-for-both-Flagged-and-Unverified resolution (FR-011) — this was a user decision, not an architect/critic recommendation to revisit lightly.

### Never
- Do not retry past a rejected fallback candidate to an older one (FR-001) — one candidate, one verification pass.
- Do not merge `fallback_status` into `latest_status` (FR-010) — `LatestStatusMap` has no version key; a merge silently corrupts `latest`'s own verdict.
- Do not compute or apply a fallback when no in-use version is resolved (FR-002/OQ1) — this is the explicit, documented scope boundary, not an oversight to "helpfully" fix inline.
- Do not change `deps-lsp`'s hover/code-action rendering to consume `cooldown_fallback` — out of scope (§1), tracked as an open question for a future spec.

## 9. Open Questions

None blocking. All were closed by the second critique round (`critic` handoff
`2026-09-27T11-15-08`) or by explicit user decision:

- OQ1 (no-floor fallback): accepted limitation, follow-up issue required (§11).
- OQ2 (fail closed on missing `published_at` for a non-latest candidate): closed, encoded in
  NFR-001 step 3.
- OQ3 (flagged latest + clean fallback): closed, encoded in FR-012.
- OQ4 (OSV disabled/offline passes fallback like latest): closed, parity, implicit in FR-010/011
  reusing the same `LatestVerdict::NotApplicable` pass condition as `latest`.
- OQ5 (keep one `SkipReason::WithinFreshnessCooldown` variant): closed, kept single variant with
  richer attribution (FR-013).
- OQ5' (exit code for a Flagged/Unverified fallback): **resolved by the user** — exit 1 for both
  Flagged and Unverified (FR-011), for parity with the existing Flagged/Unverified-`latest`
  behavior; not the architect's original exit-0 proposal, not the Flagged/exit-1 +
  Unverified/exit-0 split the critic floated as a compromise.
- OQ6 (JSON field breaking change): closed, additive, `### Changed` not `### Breaking` (NFR-005).

## 10. Amendments to Other Specs

This spec amends two previously shipped specs by cross-reference (their own text is not rewritten,
per this project's `specs.md` convention for shipped specs):

- **[[074-deps-cli-gossip-parity/spec]] NFR-004** — replaced by this spec's NFR-001 (§4). An
  "Amended by [[075-cli-update-cooldown-fallback/spec]]" note is added directly under 074's
  NFR-004 table row.
- **[[074-deps-cli-gossip-parity/spec]] FR-003b** (no-lockfile GOSSIP-`Active` dependency was
  previously applied unfiltered) — behavior changes per this spec's FR-002 (no floor → no
  fallback → now skipped). An amendment note is added under 074's §3 FR-003 discussion.
- **[[072-deps-dev-gossip-signals/spec]] FR-002** and the `GossipCooldownLookup::NotActive`
  definition (issue #1456, review finding S2, recorded only in the `deps-core` code comment at
  `crates/deps-core/src/lsp_helpers/mod.rs:1090-1103`, not as a separate spec section) — FR-005
  above redefines `NotActive` to require a parsed, past `end`. An amendment note is added under
  072's FR-002 table row referencing this spec and issue #1456's S2 finding by number, since #1456
  itself has no dedicated spec subsection beyond FR-002 to anchor to.

## 11. Required Follow-Up

Per OQ1/§1 Out of Scope: file a new GitHub issue for the no-floor fallback case (a range
requirement with no lockfile-resolved in-use version — the majority case per spec 074 §3) before
or alongside this spec's implementation PR. The issue should reference this spec, note that
issues `#1528`/`#1529`'s fix is partial, and record the two design options architect/critic already
rejected as premature (deriving a synthetic floor from the compiled requirement; scanning the
fallback list without any floor) so a future spec does not re-litigate them from scratch.

## 12. See Also

- [[074-deps-cli-gossip-parity/spec]] — amended by NFR-001/FR-002 above.
- [[072-deps-dev-gossip-signals/spec]] — amended by FR-005 above; source of `GossipCooldownLookup`.
- [[068-cli-update-subcommand/spec]] — `deps-cli update`'s existing planner/`SkipReason` this spec
  extends.
- [[constitution]] — project principles.
- [[MOC-specs]] — all specifications.
- `plan.md` (this feature) — exact call-site line numbers and integration order.
- `tasks.md` (this feature) — ordered implementation tasks.

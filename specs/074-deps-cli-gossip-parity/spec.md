---
aliases:
  - deps-cli GOSSIP Parity
tags:
  - sdd
  - spec
  - enhancement
  - deps-cli
  - deps-dev
  - priority/p4
created: 2026-09-26
status: ready
related:
  - "[[MOC-specs]]"
  - "[[072-deps-dev-gossip-signals/spec]]"
  - "[[068-cli-update-subcommand/spec]]"
  - "[[062-cli-check-mode/spec]]"
---

# Feature: deps-cli GOSSIP parity with deps-lsp's cooldown/low-usage signals

> [!info] Metadata
> **Author**: spec session 2026-09-26, following triage of issue #1474
> **Branch**: none yet — spec-only
> **Type**: enhancement, P4 (issue #1474). This is the follow-up spec 072 (§7, §9 round 3
> finding N1) explicitly deferred: "`deps-cli` GOSSIP parity ... filed as a separate follow-up
> issue instead of implemented here."

## 1. Overview

### Problem Statement

Spec 072 (PR #1473) wired deps.dev's GOSSIP signals (Dynamic Cooldown, Low-Usage Packages) into
`deps-lsp`'s hover/diagnostics/completion, but explicitly dropped `deps-cli` from that scope
(FR-010, dropped). `deps-cli`/`deps-engine` today have **zero** `DepsDevClient` wiring
(confirmed by direct inspection: no `deps_dev`/`DepsDevClient`/`trust_signal` references anywhere
in `crates/deps-engine/src` or `crates/deps-cli/src`). This leaves two closely related gaps:

1. `deps-cli check`/`update` cannot benefit from GOSSIP's authoritative, per-ecosystem cooldown
   recommendation at all — they rely solely on `freshness.rs`'s local 3-day-default heuristic.
2. `deps-cli`'s `[gossip]` config section is accepted with no effect for an explicit `--config`
   (verified: `crates/deps-cli/src/config.rs:233`'s `if !required` gate means the
   already-shipped `ignored_sections` warning, spec 072 M14, only fires for an
   *auto-discovered* `deps.toml`), and `[typosquat]` has no `ignored_sections` entry at all —
   both are silently accepted with zero effect when passed via an explicit `--config`.

### Goal

Give `deps-cli check`/`update` a working (not merely cosmetic) GOSSIP-cooldown integration that
reuses `deps-core`'s already-shipped GOSSIP plumbing (`DepsDevClient::gossip_findings_batch`,
`deps_core::lsp_helpers::fetch_gossip_findings_batch`, `GossipFindings`/`GossipCooldown` — all
public, protocol-agnostic types with zero `tower-lsp-server` dependency, confirmed by direct
inspection of `crates/deps-core/src/lsp_helpers/diagnostics.rs:1938-1975`), and close the
`ignored_sections` `--config`-vs-auto-discovery gap for `[gossip]` and `[typosquat]` together.

### Out of Scope

- Any new `deps-core` GOSSIP data types, endpoints, or client methods — everything needed already
  shipped in spec 072/PR #1473. This spec is wiring-only.
- Malicious Packages / Critical Vulnerabilities GOSSIP signals — unrelated, tracked separately
  (issue #1475).
- Adding a new `deps-cli` `Category` variant or changing `--fail-on`/exit-code semantics beyond
  what already flows through the existing `Category::Outdated` classification (§3, FR-004).
- Changing `--security-only`'s fix-target selection (`recommended_fix()`-driven, unaffected by
  freshness or GOSSIP today, per `main.rs:364-376`) — unchanged.
- Low-Usage Packages parity for `deps-cli` — deferred (§9); `deps-cli` has no per-dependency
  "invite to double-check" surface analogous to hover, and no existing issue asked for it.

## 2. User Stories

### US-001: GOSSIP-aware `--fail-on Outdated` and `update` target selection

AS A `deps-cli` user running `check`/`update` in CI with GOSSIP opted in (`[gossip].enabled =
true`)
I WANT the same authoritative, per-ecosystem cooldown recommendation `deps-lsp` already uses to
also govern which version counts as "latest" for `deps-cli`
SO THAT my CI gate and my editor don't quietly disagree about whether a release is safe to adopt

**Acceptance criteria:**
```
GIVEN [gossip].enabled = true, a covered ecosystem (GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET),
  and a dependency whose registry-latest version is flagged by GOSSIP with an active COOLDOWN
  finding
WHEN deps-cli check or update classifies that dependency's outdated/target status
THEN the version GOSSIP flags is excluded from being picked as "latest", in addition to (not
  instead of) whatever the existing local freshness.cooldown_secs heuristic already excludes
```

### US-002: Explicit `--config` no longer silently accepts a no-op `[gossip]`/`[typosquat]` section

AS A `deps-cli` operator passing `--config deps.toml` explicitly
I WANT the same "this section has no effect" warning that already fires for an auto-discovered
`deps.toml` to also fire for my explicitly-given file
SO THAT I don't spend time debugging why `[gossip]`/`[typosquat]` settings I added to a
tracked, explicitly-referenced config file appear to do nothing

**Acceptance criteria:**
```
GIVEN an explicit `--config path/to/deps.toml` whose `[gossip]` or `[typosquat]` section differs
  from PolicyConfig::default()
WHEN deps-cli loads that config
THEN it prints the same per-section "auto-discovered ... is ignored" style warning currently
  gated to the non-explicit path, without resetting any other field `safe_auto_discovered_config`
  would reset for an untrusted auto-discovered file (the explicit path remains fully trusted)
```

## 3. Functional Requirements

Resolved by direct code inspection of `crates/deps-engine/src/classify/fetch.rs`,
`crates/deps-cli/src/{main,analyze,config}.rs`, and `crates/deps-core/src/{deps_dev,lsp_helpers}`
during this spec session (2026-09-26) — see `plan.md` for exact call-site line numbers.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `deps-engine`'s composition root builds its runtime handles THE SYSTEM SHALL construct an `Arc<DepsDevClient>` alongside the existing `Arc<OsvClient>` (`crates/deps-cli/src/main.rs:115-120`'s `RuntimeHandles`), unconditionally — construction itself is free; all network calls remain gated by `GossipConfig.enabled` inside the reused `fetch_gossip_findings_batch` helper | must |
| FR-002 | WHEN `[gossip].enabled = true`, the run is not offline, and a manifest's ecosystem is one of the 7 `deps_dev_system`-covered systems THE SYSTEM SHALL batch-prefetch GOSSIP findings for every declared dependency in that manifest **once per manifest** (not once per package) via the existing, unmodified `deps_core::lsp_helpers::fetch_gossip_findings_batch(ecosystem_id, parse_result, formatter, offline, client)`, called from `deps-cli::analyze::analyze_manifest` before `fetch_latest_versions_parallel` — mirroring the existing `prefetch_tier3_licenses` call shape at `analyze.rs` (same file, same "prefetch once, thread the result through" pattern) | must |
| FR-003 | WHEN `fetch_and_classify_package` (`crates/deps-engine/src/classify/fetch.rs:763`) has fetched a package's `versions` list from the registry (already filtered by the ecosystem's own local-freshness logic inside `get_versions_from`) THE SYSTEM SHALL additionally exclude, before calling `select_latest_matching`, any version whose string exactly equals a prefetched `GossipFindings.version` for that package AND whose `GossipFindings.cooldown` is `Some(c)` with `c.is_active(now)` — a **union** with the existing local exclusion, never a replacement. `now` SHALL be read once per fetch call, not memoized across the batch | must |
| FR-004 | THE SYSTEM SHALL NOT add a new `Category` variant or change `FailOnPolicy::matches` (`crates/deps-cli/src/report.rs:299`). The GOSSIP-vs-`--fail-on` question is resolved: GOSSIP's effect on `--fail-on Outdated`/exit code is entirely indirect, through the same `Category::Outdated` classification path the existing local-cooldown filter already participates in — no new gating mechanism is needed | must |
| FR-005 | WHEN a version is excluded by FR-003's GOSSIP check but would **not** have been excluded by the local `cooldown_secs` heuristic alone (i.e., GOSSIP is the sole reason a different, older version was picked as "latest") THE SYSTEM SHALL attribute this in `PackageStatus::Resolved`'s data (a new field on `PackageVersions` or an equivalent outcome field) so `table`/`json`/`sarif` rendering can name GOSSIP as the source, mirroring deps-lsp's NFR-004 attribution rule. WHEN local and GOSSIP agree, or only local excludes, existing message text is unchanged | must |
| FR-006 | `deps-cli update`'s non-`--security-only` fix-target pick SHALL inherit FR-003's behavior with no update-specific code, because `run_update`/`run_check` already share one classification pipeline (`analyze_manifest` → `fetch_latest_versions_parallel` → `fetch_and_classify_package`, confirmed at `crates/deps-cli/src/main.rs:513-515` and `crates/deps-cli/src/analyze.rs:226`). The existing `--security-only` no-effect warning (`main.rs:364-376`, FR-014 of spec 068) SHALL be extended to also name GOSSIP as a second cooldown source with no effect in that mode, for the same underlying reason (fix target comes from the advisory, never the freshness/GOSSIP-filtered pick) | must |
| FR-007 | WHEN `crates/deps-cli/src/config.rs`'s `ignored_sections(&policy)` (config.rs:298) is evaluated THE SYSTEM SHALL add a `typosquat` check (`policy.typosquat.enabled != default.typosquat.enabled`) mirroring the existing `gossip` check (config.rs:340-342) — closing the gap where `[typosquat]` has no `ignored_sections` entry at all today | must |
| FR-008 | WHEN `load()` (config.rs:217) parses a config file THE SYSTEM SHALL emit `ignored_sections`' per-section warning for **both** an auto-discovered file and an explicitly-given `--config` file — the warning-emission loop currently gated behind `if !required` (config.rs:233) SHALL run unconditionally. `safe_auto_discovered_config`'s field-reset (the untrusted-input hardening from spec 062's F1/F1-follow-up) SHALL remain gated to the auto-discovered (`!required`) path only — an explicit `--config` stays fully trusted as written (config.rs:210-211's existing doc comment), only the "this section has no effect in deps-cli" warning becomes unconditional | must |
| FR-009 | WHEN GOSSIP is disabled, the run is offline, the ecosystem is not `deps_dev_system`-covered, or a dependency's source fails `EcosystemFormatter::source_is_public_registry_content` THE SYSTEM SHALL degrade to the existing local-freshness-only behavior with no user-visible error — `fetch_gossip_findings_batch` already implements every one of these gates (`diagnostics.rs:1938-1975`), reused as-is | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | One `GetFindingsBatch` POST per manifest per covered ecosystem (FR-002), not per package — reuses `DepsDevClient`'s existing per-package memo (1h TTL) and `gossip_semaphore`/`DEPS_DEV_BODY_LIMIT` bounds (spec 072 FR-012), unmodified. No new concurrency primitives needed in `deps-core` |
| NFR-002 | Reliability | A `DepsDevClient` error, timeout, or empty batch result degrades silently to local-freshness-only exclusion (FR-009) — `deps-cli check`/`update` never fail or change exit code solely because a GOSSIP call errored |
| NFR-003 | Privacy | Per FR-009, no dependency name reaches deps.dev unless `[gossip].enabled = true`, the run is not offline, and the dependency's source passes the same public-registry-content gate spec 072 already established — identical policy, no new opt-in surface |
| NFR-004 | Consistency | `deps-cli` and `deps-lsp` are explicitly allowed to diverge in *how* GOSSIP data is surfaced (per spec 072 FR-007: `cooldown_secs` remains deps-cli's own, unchanged, non-GOSSIP-overridden source outside this feature's additive filter) — this spec does not attempt to unify the two surfaces' precedence models, only to give `deps-cli` a working GOSSIP signal of its own |
| NFR-005 | Maintainability | Zero new `deps-core` code — every type (`GossipFindings`, `GossipCooldown`, `fetch_gossip_findings_batch`) and every concurrency/privacy control already ships from spec 072/PR #1473. This spec only adds wiring in `deps-engine` and `deps-cli` | 

## 5. Data Model

No new types. Reused as-is from `crates/deps-core/src/deps_dev/types.rs` and
`crates/deps-core/src/lsp_helpers/diagnostics.rs`:

| Entity | Description | Key Attributes (existing) |
|--------|-------------|----------------|
| `GossipFindings` | Per-package GOSSIP result, keyed by package name in the batch map | `version: String`, `cooldown: Option<GossipCooldown>`, `low_usage: Option<GossipLowUsage>` (unused by this spec) |
| `GossipCooldown` | An active-or-expired cooldown window | `end: PublishTime`, `risk: GossipRiskLevel`, `is_active(now: PublishTime) -> bool` |

New, additive-only field proposed in `plan.md` §3: an attribution marker on `PackageVersions`
(FR-005) — no schema/wire-format change, purely an in-process outcome-reporting field.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GOSSIP flags the registry-latest version, but the local `cooldown_secs` heuristic already excluded an even-older set of versions too | Union semantics (FR-003): both exclusions apply; the first non-excluded version (by either source) wins, same as today's local-only logic just with a wider exclusion set |
| GOSSIP's `GossipFindings.version` does not match any version in the ecosystem's `versions` list (deps.dev's view of "latest" lags the registry, or vice versa) | Treated as no signal for this run (FR-003's exact-match requirement) — never a fallback fuzzy match, mirroring spec 072 FR-008 |
| `[gossip]` and `[typosquat]` are both non-default in an explicitly-given `--config` file | Both warnings print (FR-007/FR-008), independently, one line per differing section — matches the existing per-section warning shape, just no longer gated on auto-discovery |
| `deps-cli update --security-only` with `[gossip].enabled = true` | GOSSIP has no effect here either (FR-006) — the existing FR-014 warning text is extended to name both sources, not just `--cooldown` |
| A dependency's source is a git/path/custom-registry reference, not a public registry | Excluded from the GOSSIP batch prefetch by the existing `source_is_public_registry_content` gate (FR-009) — same as spec 072's hover/diagnostics behavior |
| Offline mode (`--offline` / `network.offline = true`) | `fetch_gossip_findings_batch` returns an empty map immediately (existing `offline` check, `diagnostics.rs:1950-1952`) — zero network calls, unchanged from today's GOSSIP-absent behavior |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `deps-cli check`/`update` classification of a GOSSIP-covered package in active cooldown | Excludes that version from being "latest", matching `deps-lsp`'s hover/diagnostics behavior for the same package/version |
| SC-002 | `--fail-on`/`Category` enum | Zero new variants added; `cargo clippy`'s exhaustiveness checks pass unchanged |
| SC-003 | `[gossip]`/`[typosquat]` warning parity | Warning fires identically for auto-discovered and explicit `--config` paths; `safe_auto_discovered_config`'s reset behavior is unchanged for the auto-discovered path |
| SC-004 | New `deps-core` code | Zero — verified via `git diff --stat crates/deps-core` on the implementing PR |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps_core::lsp_helpers::fetch_gossip_findings_batch` and `DepsDevClient::gossip_findings_batch` as-is — do not add a parallel/duplicate fetch path in `deps-engine`.
- Keep `safe_auto_discovered_config`'s trust-narrowing behavior scoped to the auto-discovered (`!required`) path only when implementing FR-008.
- Run the full pre-commit check suite (`.claude/rules/branching.md`) before opening the PR, since this touches `deps-engine`'s classification hot path and `deps-cli`'s config loader, both covered by extensive existing tests.

### Ask First
- Any change to `PackageVersions`'s public shape beyond an additive attribution field (FR-005) — if the implementer finds the minimal-diff approach insufficient, confirm the alternative with the maintainer before widening scope.

### Never
- Do not add a new `Category` variant or change `--fail-on` matching semantics (FR-004) — explicitly decided out of scope.
- Do not modify `crates/deps-core/src/deps_dev/` or `policy_config.rs`'s `GossipConfig`/`TyposquatConfig` shapes — everything needed already exists.
- Do not weaken `safe_auto_discovered_config`'s existing F1/F1-follow-up protections for auto-discovered configs while fixing FR-008's warning gap.

## 9. Open Questions

None outstanding. All three decisions the issue asked for are resolved above by direct code
inspection rather than left as `[NEEDS CLARIFICATION]`:

- **Precedence rule** (`--cooldown`/`freshness.cooldown_secs` vs. GOSSIP): resolved as **union**
  (FR-003) — simpler than `deps-lsp`'s override-with-attribution model (appropriate here since
  `deps-cli`'s output is consumed by both humans and CI parsers, where an unexplained "override"
  is a bigger surprise than an explained "wider exclusion set").
- **`--fail-on`/exit-code effect**: resolved — indirect only, through the existing
  `Category::Outdated` path, no new `Category` (FR-004).
- **`update`'s cooldown-awareness**: resolved — inherited for free via the shared classification
  pipeline (FR-006), not a separate implementation.
- **`ignored_sections` M17 gap**: resolved — fixed for `[gossip]` and `[typosquat]` together
  (FR-007/FR-008), scoped to the warning only, not `safe_auto_discovered_config`'s trust model.

Deferred, not blocking this spec:

- Low-Usage Packages parity for `deps-cli` (§1 Out of Scope) — no existing user demand signal;
  revisit if requested.

## 10. See Also

- [[072-deps-dev-gossip-signals/spec]] — the spec this one follows up on; source of FR-010's drop
  decision and all reused `deps-core` GOSSIP plumbing.
- [[068-cli-update-subcommand/spec]] — `deps-cli update`'s existing `--cooldown`/FR-014
  `--security-only` interaction this spec extends.
- [[062-cli-check-mode/spec]] — `deps-cli check`'s classification pipeline and `Category`/
  `FailOnPolicy` this spec deliberately leaves unchanged.
- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `plan.md` (this feature) — exact call-site line numbers and integration order.

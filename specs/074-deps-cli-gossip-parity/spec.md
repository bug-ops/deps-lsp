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

**Revised 2026-09-26 after critique round 1** (independent `rust-critic`, `rust-security-maintenance`,
and `rust-testing-engineer` passes on the first implementation, verdict: critical). All three found
the same false premise: `crates/deps-core/src/lsp_helpers/diagnostics.rs`'s existing local
`freshness.cooldown_secs` heuristic **never excludes a version from being picked as `latest`** — it
only annotates a downstream diagnostic *message*, verified directly against
`get_versions_with`/`get_versions_from`'s contract and every ecosystem's `select_latest_matching_impl`.
So the original FR-003 ("union with the existing local exclusion") was building on an exclusion
mechanism that does not exist: GOSSIP's version-filter was the *first* thing ever to change what
counts as `latest`, and a naive implementation (excluding a cooldown-flagged version outright) could:

- **C1 (critical)**: regress `latest` *below* a dependency's already-declared/in-use version when
  that exact version is the one GOSSIP flags — `check` then reports a false "newer version available"
  pointing at an *older* release, `--fail-on Outdated` fails CI on an already-current dependency, and
  `deps-cli update` (`crates/deps-core/src/edit.rs`'s `collect_update_candidates`, which reads
  `PackageVersions.latest` with no downgrade guard) rewrites the manifest to that older version — a
  real, silent downgrade.
- **S1**: the `get_latest_matching_from` fallback (fetch.rs, invoked when the list-based pick finds
  nothing) is not filtered at all, and can simply return the same GOSSIP-flagged version — bypassing
  the exclusion entirely once it's the sole list-based candidate.

FR-003 is corrected below to a **floor-protected filter**: GOSSIP may only exclude a version that is
*strictly newer* than the newest version already in use for that dependency. A version at or older
than that floor is never excluded, so `latest` can never regress past what is already declared —
closing C1 by construction. This also closes S1 whenever an in-use version is known: the floor
version always satisfies the (wildcard) selection requirement, so the list-based pick can never come
up empty for GOSSIP reasons, and the `get_latest_matching_from` fallback is never reached on that
account. S1 remains a **narrow, documented residual gap** only for a dependency with *no* in-use
version at all (a fresh add, no lockfile) — accepted as out of proportion to fix for a P4 issue (would
need per-ecosystem `Registry` trait changes to filter the fallback itself); see §6/§9.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `deps-engine`'s composition root builds its runtime handles THE SYSTEM SHALL construct an `Arc<DepsDevClient>` alongside the existing `Arc<OsvClient>` (`crates/deps-cli/src/main.rs:115-120`'s `RuntimeHandles`), unconditionally — construction itself is free; all network calls remain gated by `GossipConfig.enabled` inside the reused `fetch_gossip_findings_batch` helper | must |
| FR-002 | WHEN `[gossip].enabled = true`, the run is not offline, and a manifest's ecosystem is one of the 7 `deps_dev_system`-covered systems THE SYSTEM SHALL batch-prefetch GOSSIP findings for every declared dependency in that manifest **once per manifest** (not once per package) via the existing, unmodified `deps_core::lsp_helpers::fetch_gossip_findings_batch(ecosystem_id, parse_result, formatter, offline, client)`, called from `deps-cli::analyze::analyze_manifest` before `fetch_latest_versions_parallel` — mirroring the existing `prefetch_tier3_licenses` call shape at `analyze.rs` (same file, same "prefetch once, thread the result through" pattern) | must |
| FR-003 | **CORRECTED round 2 (independent re-verification found round 1's floor incomplete).** Round 1's protect floor is *necessary* but not *sufficient*: `in_use_versions` is empty whenever nothing is lockfile-resolved for a range requirement (e.g. Cargo's `AlwaysRange` policy treats a bare `"2.0.0"` as `^2.0.0`, not an exact pin; npm/PyPI ranges behave the same without a lockfile) — a real-world majority case, not a rare edge case, and round 1's floor provides no protection at all when it's `None`. Round 2 simplifies rather than deepens the heuristic (rejected: deriving a synthetic floor from the compiled version requirement — adds real complexity, and further analysis showed the requirement-satisfying "natural" pick *is* the unfiltered pick, so no non-circular floor exists there anyway). WHEN `fetch_and_classify_package` (`crates/deps-engine/src/classify/fetch.rs:763`) finds the unfiltered list-based pick is GOSSIP-cooldown-flagged: (a) compute the round-1 protect floor from `in_use_versions`; (b) **WHEN no floor exists (`None`) THE SYSTEM SHALL NOT exclude anything this run** — GOSSIP no-ops for this package this fetch, the unfiltered pick is used unchanged, no attribution. This is a deliberate, documented scope narrowing: real GOSSIP-driven behavior change requires a concretely resolved in-use version (lockfile-backed, or an ecosystem where the manifest text is an unambiguous exact pin) — never a bare, unresolved range requirement; (c) WHEN a floor exists, filter as round 1 described (exclude a flagged version only strictly above the floor), then re-run `select_latest_matching` on the filtered list; (d) **WHEN that filtered pick is `None`** (not just "no floor" — also reachable *with* a floor, e.g. every remaining candidate above the floor is itself rejected by the ecosystem's own selection rules, such as Go refusing an all-prerelease remainder) **THE SYSTEM SHALL use the unfiltered pick, set no attribution, and SHALL NOT invoke `get_latest_matching_from`** — inventing a fallback network call here would just risk re-discovering the same flagged version (closing S1 universally, in every branch, without any `Registry` trait change: the existing fallback is now reached only when the *unfiltered* list-based pick itself found nothing, which is unrelated to GOSSIP). THE SYSTEM SHALL set the FR-005 attribution field only in case (c)'s genuine-exclusion outcome, never in (b) or (d). `now` SHALL be read once per fetch call, not memoized across the batch | must |
| FR-004 | THE SYSTEM SHALL NOT add a new `Category` variant or change `FailOnPolicy::matches` (`crates/deps-cli/src/report.rs:299`). The GOSSIP-vs-`--fail-on` question is resolved: GOSSIP's effect on `--fail-on Outdated`/exit code is entirely indirect, through the same `Category::Outdated` classification path FR-003's filtered `latest` feeds — no new gating mechanism is needed | must |
| FR-005 | **CORRECTED round 1, unchanged by round 2**: WHEN FR-003's second (filtered) pick differs from its first (unfiltered) pick THE SYSTEM SHALL attribute this in `PackageStatus::Resolved`'s data (`PackageVersions.gossip_excluded_version`) so `table`/`json`/`sarif` rendering can name GOSSIP as the source, mirroring deps-lsp's NFR-004 attribution rule. WHEN the two picks are identical, or FR-003(b)/(d)'s no-op cases apply, THE SYSTEM SHALL NOT set this field, and existing message text is unchanged | must |
| FR-006 | `deps-cli update`'s non-`--security-only` fix-target pick SHALL inherit FR-003's behavior with no update-specific code, because `run_update`/`run_check` already share one classification pipeline (`analyze_manifest` → `fetch_latest_versions_parallel` → `fetch_and_classify_package`, confirmed at `crates/deps-cli/src/main.rs:513-515` and `crates/deps-cli/src/analyze.rs:226`) and FR-003's floor protection is keyed off the same `in_use_versions` `collect_update_candidates` (`crates/deps-core/src/edit.rs:701`) ultimately reads `PackageVersions.latest` from — a version at or below what's already declared can never become the computed `latest`, so `update` can never be pointed at a downgrade by this feature. The existing `--security-only` no-effect warning (`main.rs:364-376`, FR-014 of spec 068) SHALL be extended to also name GOSSIP as a second cooldown source with no effect in that mode, for the same underlying reason (fix target comes from the advisory, never the freshness/GOSSIP-filtered pick) | must |
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
| **C1a (round 1)**: the dependency's already-declared/in-use version is itself the one GOSSIP flags with an active cooldown, and it is also the true registry-latest | FR-003's protect floor covers this version's own position — the exclusion is fully neutralized, the pick is unchanged, and no attribution is set (nothing was actually held back; this is genuinely the best available version) |
| **T2 (round 1)**: the in-use version is older and safe, but GOSSIP flags only the newest release while a safe intermediate release exists above the floor | The flagged release alone is excluded; the safe intermediate release is picked as `latest`, with attribution naming the excluded (flagged) version |
| **C1b (round 2, previously unfixed by round 1)**: no `in_use_versions` entry resolves at all — a range requirement with no lockfile (the common case: Cargo's `AlwaysRange` policy, unlocked npm/PyPI ranges) — and GOSSIP flags the unfiltered pick | **Deliberate no-op** (FR-003b): GOSSIP excludes nothing this run; the unfiltered pick is used exactly as it would be without this feature. A concretely resolved in-use version is required for GOSSIP to change anything — documented scope narrowing, not a bug |
| **S1 (round 1 residual, closed in round 2)**: the floor-filtered candidate list yields no pick at all — either because there is no floor (C1b, folded into the no-op above) or because every remaining candidate above a real floor is itself rejected by the ecosystem's own selection rules (e.g. Go refusing an all-prerelease remainder) | The unfiltered pick is used, no attribution is set, and `get_latest_matching_from` is **never** invoked as a consequence of GOSSIP's own filtering — the pre-existing fallback path remains reachable only when the *unfiltered* pick itself found nothing, entirely unrelated to GOSSIP. Fully closed, no residual gap, no `Registry` trait change needed |
| GOSSIP's `GossipFindings.version` does not match any version in the ecosystem's `versions` list (deps.dev's view of "latest" lags the registry, or vice versa) | Treated as no signal for this run (FR-003's exact-match requirement) — never a fallback fuzzy match, mirroring spec 072 FR-008 |
| `[gossip]` and `[typosquat]` are both non-default in an explicitly-given `--config` file | Both warnings print (FR-007/FR-008), independently, one line per differing section — matches the existing per-section warning shape, just no longer gated on auto-discovery |
| `deps-cli update --security-only` with `[gossip].enabled = true` | GOSSIP has no effect here either (FR-006) — the existing FR-014 warning text is extended to name both sources, not just `--cooldown` |
| A dependency's source is a git/path/custom-registry reference, not a public registry | Excluded from the GOSSIP batch prefetch by the existing `source_is_public_registry_content` gate (FR-009) — same as spec 072's hover/diagnostics behavior |
| Offline mode (`--offline` / `network.offline = true`) | `fetch_gossip_findings_batch` returns an empty map immediately (existing `offline` check, `diagnostics.rs:1950-1952`) — zero network calls, unchanged from today's GOSSIP-absent behavior |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `deps-cli check`/`update` classification of a GOSSIP-covered package in active cooldown | Excludes that version from being "latest" **only when a strictly newer, safe version would result** — never regresses below the dependency's already-declared/in-use version (FR-003's protect floor) |
| SC-005 | Regression coverage for C1a/C1b/S1 (rounds 1-2 critique) | Dedicated tests: in-use version itself flagged (C1a: floor neutralizes exclusion, no attribution), in-use version safe with a newer flagged release above it (T2: exclusion applies, attribution set), no in-use version at all with the sole candidate flagged (C1b: asserted as a no-op — GOSSIP changes nothing, not merely "documented as still-broken"), and a floor-protected candidate list whose ecosystem-level selection still yields no pick (S1: unfiltered pick used, `get_latest_matching_from` never invoked) |
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

- **Precedence rule** (`--cooldown`/`freshness.cooldown_secs` vs. GOSSIP): **revised round 1** — the
  original "union with local exclusion" framing was retired once critique proved no local exclusion
  exists to union with (`freshness.cooldown_secs` only ever changes message text). GOSSIP is the sole
  exclusion mechanism, hardened by FR-003's protect floor so it can only ever hold back forward
  progress (a newer, not-yet-safe release), never regress an already-declared dependency.
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

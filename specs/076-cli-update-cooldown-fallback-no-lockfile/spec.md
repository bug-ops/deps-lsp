---
aliases:
  - cli update Cooldown Fallback No-Lockfile Extension
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
  - "[[075-cli-update-cooldown-fallback/spec]]"
  - "[[074-deps-cli-gossip-parity/spec]]"
  - "[[072-deps-dev-gossip-signals/spec]]"
---

# Feature: `deps-cli update`'s cooldown fallback for dependencies with no lockfile-resolved in-use version

> [!info] Metadata
> **Author**: spec session 2026-09-27, following architect/critic investigation of issue `#1544`,
> a direct follow-up to `[[075-cli-update-cooldown-fallback/spec]]`'s documented OQ1 limitation.
> **Branch**: `feat/1544-cooldown-fallback-no-lockfile`
> **Type**: bug/enhancement, P2, cross-cutting `deps-core`/`deps-engine`/`deps-cli`. Four
> architect design rounds and four `rust-critic` review rounds (2026-09-27) progressively closed
> S1 (a written fallback edit that does not actually exclude the version it exists to exclude),
> S2 (a NuGet floor-shape guard gap), and M1-M7 minor gaps, converging on a single uniform rule
> applied identically across all 14 ecosystems (final critic verdict: minor, approved to proceed).

## 1. Overview

### Problem Statement

`[[075-cli-update-cooldown-fallback/spec]]` fixed issue #1528 (`deps-cli update` starving a
dependency whose registry-`latest` is always within the freshness cooldown window) only for
dependencies with a **lockfile-resolved in-use version** (the D2 floor) or an **exact-pin
ecosystem** where the declared requirement itself is the in-use version (Go's `require`
directive). That spec's own §1 Out of Scope explicitly named the remaining case — a range
requirement with no lockfile-resolved in-use version, spec 074 §3's **majority case** for
range-requirement ecosystems — as unaddressed, and its §11 required a follow-up issue rather
than re-litigating the two design options already rejected as premature: deriving a synthetic
floor from the compiled requirement, or scanning the fallback list with no floor at all. Issue
`#1544` is that follow-up.

A naive fix — drop the D2 floor requirement whenever no in-use version is resolved, and rely on
spec 075's existing per-occurrence requirement-floor guard (`fallback_satisfies_requirement`,
`crates/deps-cli/src/update/mod.rs:729`) as the sole floor for this path — very nearly works,
because that guard is already a correct requirement-derived floor for 11 of 12
`compile_requirement` ecosystems (the newest version a re-resolve of the unedited requirement
would pick). Four review rounds found it is not sufficient on its own:

1. **S1 (second_order_effects, round 2).** The written fallback edit auto-follows: for every
   ecosystem whose default rendering widens the requirement into a range (Cargo bare `X` means
   `^X`, Dart bare `X` means `^X`, PyPI's default `>=X,<next`), the very edit `deps-cli update`
   writes to exclude an in-cooldown version admits that version again on the next resolve. For
   the #1528 population — a package whose `latest` is *always* inside the cooldown window — this
   is not a one-time nuisance: the pin moves forward on every run and never returns to a range,
   which for a Cargo/Dart/PyPI *library* manifest means permanent downstream resolution
   conflicts, not a transient inconvenience. Three design rounds (bounded ranges, an ordered
   per-ecosystem exact-pin override, a PyPI `>=X,<=X` self-healing form) were tried and rejected
   before the user made the deciding call recorded in §9 OQ-C: never write an exact pin as a
   fallback rendering, for any ecosystem — the guard instead evaluates only each ecosystem's own
   default-rendered edit, which fails closed for the common in-range-churn case but still writes
   when a fresh version falls outside that edit's admitted range (round-4 critic M5, §1).
2. **S2 (round 1, closed).** Under an early version of the guard, NuGet's bare-floor requirement
   shape (`[2.0.0,)`) let a fallback **below** the existing floor through, because
   `requirement_already_resolves_to` returns `false` for every target of a floor shape. Closed by
   folding `is_requirement_up_to_date` into the same self-contained guard.
3. **S2 (round 2, closed differently).** The guard as first revised compiled the *replacement
   span's own text* in isolation, which is wrong for any grammar where the effective requirement
   is built from context outside that span — Swift's `from:`/`.exact`/`.upToNextMinor` labels and
   Bundler's multi-constraint literals both parse this way. Closed by re-parsing the edited
   manifest through the ecosystem's own parser instead of compiling the span text directly.
4. **M1-M5 (various rounds).** DRY duplication between the fallback-floor lookup and spec 074's
   own floor-protected GOSSIP filter (`crates/deps-engine/src/classify/fetch.rs:894` and `:1241`
   independently compute the same `in_use_versions` → position lookup); an unnecessary full
   version-history scan on every no-lockfile fetch even when `latest` is not cooldown-blocked; an
   unmodellable requirement (e.g. an unsatisfiable `^5`) silently passing the guard; a lookup
   assumption ("name precedes version in every grammar") that is false for NuGet's
   `Version`-before-`Include` attribute order, Maven's element ordering, and Gradle's map
   notation; and the re-parse mechanism bypassing the #796 dependency-count cap chokepoint.

### Goal

`deps-cli update` extends spec 075's fallback mechanism to a dependency with **no**
lockfile-resolved in-use version: it computes the same cooldown-cleared, ecosystem-safe candidate
with no positional floor, but writes it **only when the ecosystem's own default-rendered edit,
once applied and the manifest re-parsed, still excludes every currently known `available` version
newer than the fallback** — otherwise the occurrence is `NoneUsable` (today's skip), identically
to how an ecosystem with no compiled requirement model (GitHub Actions, GitLab CI) already
behaves under spec 075. This closes #1544 for every ecosystem whose default write already
produces an exact or floor-shaped requirement (npm, Composer, Bundler, Go, Maven, Gradle, NuGet, a
user's own PyPI `==`/`===` pin, Swift `.exact(...)`, and Swift `.upToNextMinor` when no newer
same-minor version exists), and it documents, as an explicit scope boundary, the same universal
rule now also applying to spec 075's existing lockfile path.

### Out of Scope

- **The common-case fail-closed outcome for auto-following ecosystems.** THIS IS A CONDITIONAL
  outcome, not an absolute exclusion (round-4 critic M5 addendum) — do not read the ecosystems
  named below as "never receive a fallback". Cargo (`^X`), Dart (`^X`), PyPI's default `>=X,<next`
  and `~=` form, and Swift `from:` fail closed under this spec's guard (FR-023/FR-025) ONLY WHEN a
  known newer version falls INSIDE the range their own default-rendered edit would admit — the
  common case for ordinary patch/minor release churn, but not universal. When a known newer
  version falls OUTSIDE that range (e.g. Cargo's `^2.5.0` excludes a fresh `3.0.0`; PyPI's
  `~=2.2` excludes a fresh `3.0`), the fallback IS written, on both this spec's no-lockfile path
  and spec 075's lockfile path (a behavior tightening from spec 075, see §10). What IS out of
  scope, unconditionally, is any mechanism to also cover the in-range case for these four
  ecosystems (a per-ecosystem pin override, a bounded range, etc. — see §8's design-history note).
  GitHub Actions and GitLab CI are a SEPARATE, unrelated case: they have no compiled requirement
  model at all, so spec 075's existing guard check (a) rejects them before this spec's rule is
  ever reached — this is unchanged, existing behavior from spec 075, not a new fail-closed case
  and not part of this conditional boundary. **Rationale for leaving the in-range case
  unaddressed (user decision, §9 OQ-C)**: the only requirement shape that would ALSO exclude an
  in-range fresh version is an exact pin, and for the #1528 population — a package that publishes
  faster than the cooldown window — that pin would be written again, moved forward, on every
  subsequent run and never return to a range. A transient inconvenience for a rare publisher is
  not the design target; a *permanent* exact pin in a published library, causing downstream
  resolution conflicts in Cargo/pub/pip indefinitely, is unacceptable regardless of publish
  frequency. §11 requires a follow-up issue researching an installer-level alternative (e.g.
  `uv`'s `exclude-newer`, npm's `min-release-age`) instead of a manifest-level pin for these
  ecosystems' remaining in-range-churn case.
- **PyPI/Composer `!=X` exclusion specifiers.** The guard (FR-023) can approve a fallback the user
  explicitly excluded via a `!=` term — a pre-existing gap on spec 075's lockfile path (round-1
  critic M6), not introduced or worsened here. Filed as a separate follow-up issue (§11), not
  fixed in this spec.
- **`#1551` items 3 and 5.** FR-028 closes items 1, 2, and 4 (the `InUseFloor`/`cooldown_verdict_for`
  DRY refactor and the M4 gate); items 3 and 5 are unrelated to this spec's design and are filed as
  their own follow-up issue (§11 item 2), not addressed here.
- **Graph-level dependency resolution.** Gradle's highest-wins strategy, Maven's nearest-wins
  strategy, and NuGet's lowest-applicable-across-the-graph resolution can all still select a
  fresh, still-in-cooldown version via a *transitive* requirement regardless of what this feature
  does to the *direct* manifest requirement. This is the same limitation spec 075's lockfile-path
  fallback already has (its own §1/§6 do not address transitive resolution either) — documented
  here as an explicit, accepted, pre-existing limitation, not a new gap (round-4 critic M4).
- **`deps-lsp` code-action/hover convergence** onto the fallback candidate — unchanged from spec
  075 §1, still an open question for a future spec.
- **Iterating past a single rejected fallback candidate** to try an older one — unchanged from
  spec 075 FR-001.
- **A new `PackageRendering`/formatter trait method, or any per-ecosystem override/retry
  mechanism for the written edit shape.** Three prior design rounds explored a
  `format_version_pinned_for` override (Cargo `=X`, Dart `X`, PyPI `>=X,<=X`) and rejected it once
  the decision to apply one uniform rule to every ecosystem with no override (OQ-C) removed its
  reason to exist — see §8's design-history note. No ecosystem-crate source file changes; only new
  tests.
- **The `formatter_conformance!` assertion macro** considered in round 3 — dropped once no
  overridable trait method remained to force a declaration against (§8).

## 2. User Stories

### US-003: `deps-cli update` no longer starves a no-lockfile frequent publisher

AS A `deps-cli update` user with a range-requirement dependency that has no lockfile-resolved
in-use version (spec 074 §3's majority case) and publishes releases faster than the configured
freshness-cooldown window
I WANT `update` to fall back to the newest already-cooled-down, safe version whenever the
ecosystem can express that exclusion without a permanent exact pin
SO THAT the majority of `deps-cli update`'s dependency population is not permanently frozen at its
current declared requirement merely because it has no lockfile entry

**Acceptance criteria:**
```
GIVEN an npm dependency `"pkg": "1.0.0"` (bare, exact by npm convention) with no lockfile, releases
  1.1.0 (cooled, OSV Verified) and 1.2.0 (within cooldown) published newest-first
WHEN deps-cli update classifies this dependency
THEN it targets 1.1.0 (Applied), attributes AppliedInsteadOf(1.2.0), and the re-parsed written
  edit ("1.1.0") admits no available entry newer than 1.1.0
```
```
GIVEN a Cargo dependency `pkg = "1.0"` (caret by Cargo convention) with no lockfile, releases 1.1.0
  (cooled) and 1.2.0 (within cooldown)
WHEN deps-cli update classifies this dependency
THEN the default-rendered edit ("1.1.0", meaning ^1.1.0) re-parses to a requirement that still
  admits fresh 1.2.0, so FR-023's guard rejects it; the occurrence resolves to NoneUsable
  (SkipReason::WithinFreshnessCooldown) — the documented, out-of-scope common-case fail-closed
  outcome for an in-range fresh version (§1), not a defect
```
```
GIVEN a Cargo dependency `pkg = "1.0"` with no lockfile, releases 1.1.0 (cooled) and 3.0.0 (within
  cooldown, outside the ^1.1.0 range the default edit would produce)
WHEN deps-cli update classifies this dependency
THEN the default-rendered edit ("1.1.0", meaning ^1.1.0) does NOT admit fresh 3.0.0, so FR-023's
  guard accepts it; the occurrence resolves to Applied(1.1.0) — the rule is conditional on the
  fresh version's position, not a fixed per-ecosystem verdict (§3 FR-025)
```

### US-004: A written fallback edit never needs a permanent exact pin to stay safe

AS A `deps-cli update` user maintaining a manifest that other projects depend on (a library, not
only an application)
I WANT the tool to never write a fallback edit whose safety depends on an exact pin that would
have to move forward on every subsequent run
SO THAT `deps-cli update` never introduces a permanent downstream resolution conflict as the price
of clearing one cooldown-blocked run

**Acceptance criteria:**
```
GIVEN any ecosystem and any occurrence where the only requirement text that would exclude every
  known newer available version is an exact pin the ecosystem's own default rendering does not
  already produce
WHEN deps-cli update evaluates that occurrence's fallback edit
THEN FR-023/FR-024 reject it (NoneUsable) rather than writing a value whose only safe rendering is
  outside the ecosystem's default-rendering vocabulary
```

## 3. Functional Requirements

Requirement IDs continue spec 075's FR-001..FR-015 numbering. Resolved by architect/critic
investigation (2026-09-27, four design rounds, final critic handoff
`2026-09-27T16-52-51-critic`, verdict: minor, approved to proceed) against shipped HEAD
`73c9d52b9` (spec 075's own PR #1550, already merged).

| ID | Requirement | Priority |
|----|------------|----------|
| FR-016 | **(#1551 item 2, DRY)** THE SYSTEM SHALL expose one engine-private classifier `fn in_use_floor(versions: &[Box<dyn Version>], in_use_versions: &[String]) -> InUseFloor` in `deps-engine::classify::fetch`, replacing BOTH the ad-hoc `protect_floor` lookup (spec 074's GOSSIP filter, `fetch.rs:894`) AND the fallback-candidate `floor` lookup (spec 075's D2 floor, `fetch.rs:1241`) — no third independent copy of the `in_use_versions.iter().filter_map(..).min()` pattern | must |
| FR-017 | `InUseFloor` SHALL be an exhaustive enum `{ Absent, Located(usize), Unlocatable { newest_located: Option<usize> } }`. `Absent` means `in_use_versions` is empty. `Located(idx)` means every resolvable `in_use_versions` entry maps to a position in `versions`, `idx` being the newest (smallest index). `Unlocatable { newest_located }` means AT LEAST ONE `in_use_versions` entry does NOT map to any position in `versions` (a Go pseudo-version, a private registry pin, or a stale lockfile entry) — `newest_located` carries the newest position among the entries that DID resolve, or `None` if none did | must |
| FR-018 | **(round-3 critic M1, preserves spec 074 unchanged)** At spec 074's GOSSIP-filter call site (`fetch.rs:894`), `Located(idx)` and `Unlocatable { newest_located: Some(idx) }` SHALL both filter at `idx`, and `Absent` and `Unlocatable { newest_located: None }` SHALL both no-op the filter — byte-for-byte the same behavior spec 074 already has today (this requirement exists only to state that FR-016's refactor must not change it). At spec 075/076's fallback-candidate call site (`fetch.rs:1241`), `Located(idx)` SHALL set the D2 floor at `idx` (spec 075 FR-002, unchanged); `Absent` SHALL compute the fallback with NO positional floor (this spec's core feature, FR-001's ecosystem-safety guard still applies); `Unlocatable` (either variant) SHALL yield `cooldown_fallback: None` — a stricter behavior than today's shipped code, which silently uses only the resolvable entries' minimum as the floor and ignores that another in-use version could not be placed at all. This tightens spec 075's own lockfile path (§10 amendment) | must |
| FR-019 | **(#1551 items 1/4)** THE SYSTEM SHALL expose one shared precedence primitive `pub fn cooldown_verdict_for(gossip: Option<&HashMap<PackageName, GossipFindings>>, name: &PackageName, version: &str, published_at: Option<PublishTime>, freshness: FreshnessSettings, now: PublishTime) -> CooldownVerdict` in `deps_core::lsp_helpers`, covering ONLY the GOSSIP-vs-local-heuristic precedence (spec 075 NFR-001 steps 2-3) — the freshness-enabled gate (step 0) and OSV verdicts (step 1) remain each caller's own concern. `cooldown_disposition` (spec 075 FR-004), the fallback-candidate's cooled-subset filter (spec 075 FR-001/FR-002, `fetch.rs`), and `fetch_and_classify_package`'s FR-020 gate SHALL all call this one function — no second independent GOSSIP-precedence branch anywhere in this call graph. Spec 074's `is_gossip_cooldown` closure (`fetch.rs:856-859`) SHALL remain its own separate GOSSIP-only-Active check by design, not routed through this function | must |
| FR-020 | **(#1551 item 4, performance)** `CooldownVerdict SHALL be an exhaustive enum { Blocked(CooldownBlocker), Cleared, NoPublishTime }`. `fetch_and_classify_package` SHALL run the fallback-candidate computation (the full version-history/GOSSIP-lookup scan) ONLY WHEN `cooldown_verdict_for` on the UNFILTERED pick (`unfiltered_pick_version`, `fetch.rs:848`) returns `Blocked(_)`. WHEN it returns `Cleared` or `NoPublishTime` THE SYSTEM SHALL NOT scan `available` for a fallback candidate at all (`cooldown_fallback: None`, zero extra GOSSIP lookups), including in `deps-lsp`, which reads `PackageVersions` but never consults `cooldown_fallback` (spec 075 §1) | must |
| FR-021 | **(gate-superset invariant)** For identical `(freshness, gossip)` inputs and `now_read >= now_fetch`, THE SYSTEM'S read-time `cooldown_disposition` reporting `Blocked` for `latest` SHALL imply FR-020's fetch-time gate was `Blocked` for the unfiltered pick at fetch time — never the reverse gap (a read-time block with no stored fallback candidate to consult). The one permitted exception is a `freshness.cooldown_secs` narrowed between fetch and read, which can only make the read-time outcome MORE blocked (stricter), consistent with spec 075 NFR-002 — never less safe | must |
| FR-022 | **(round-1 critic M1, amends spec 075 FR-003)** THE SYSTEM SHALL remove spec 075 FR-003's `formatter.manifest_requirement_is_resolved_version(dep)` exception (the Go `require`-directive bypass) entirely. After spec 075 shipped, Go's `ExactMatcher` already passes the compiled-matcher guard for a located, in-use pin on its own — the bypass guards an unreachable branch (Go's `require` directive is always concrete, so it never reaches `InUseFloor::Absent`, and a pseudo-version reaches `Unlocatable`, which FR-018 already fails closed). FR-023 below applies uniformly to Go with no special case | must |
| FR-023 | **(S1+S2, the uniform edit-shape rule)** THE SYSTEM SHALL expose one function `pub fn fallback_edit_excludes_newer(formatter: &dyn EcosystemFormatter, reparse: &dyn ManifestReparse, content: &str, dep: &dyn Dependency, candidate: &ManifestEdit, fallback: &ConcreteVersion, available: &[ConcreteVersion]) -> bool` in `deps_core::lsp_helpers`, replacing spec 075's span-text `fallback_satisfies_requirement` (`crates/deps-cli/src/update/mod.rs:729`) for BOTH the `Located` (spec 075's existing lockfile path) and `Absent` (this spec's new no-lockfile path) cases. It re-parses the manifest with `candidate` applied (FR-024) and, on the resulting occurrence's effective `version_requirement()`, returns `true` (the candidate edit may be written) iff ALL of: (a) `formatter.compile_requirement` on it is `Some`; (b) the compiled matcher admits AT LEAST ONE entry in `available` (an unmodellable or unsatisfiable requirement fails closed, round-1 critic M5); (c) `formatter.is_requirement_up_to_date(requirement, fallback)` is `false` (closes the NuGet floor-shape gap, round-1 critic S2); (d) NO entry in `available` AT OR NEWER than `fallback`'s position satisfies `formatter.requirement_already_resolves_to(requirement, entry)` (the core downgrade/S1 exclusion check — includes the fallback's own position, unlike spec 075's original strictly-newer-only check). `false` from any of (a)-(d), or FR-024's re-parse failing to locate exactly one occurrence, SHALL resolve the occurrence to `NoneUsable` (spec 075's existing `WithinFreshnessCooldown` skip) | must |
| FR-024 | **(S2 round 2, round-3 critic M2/M3)** `fallback_edit_excludes_newer` SHALL validate the EFFECTIVE post-edit requirement, not the replacement span's own text in isolation (some grammars, e.g. Swift's `from:`/`.exact`/`.upToNextMinor` labels and Bundler's multi-constraint literals, build the effective requirement from context outside the span). THE SYSTEM SHALL: (1) apply `candidate` to a scratch copy of `content` via the existing `deps_core::edit::apply_edits`; (2) re-parse the scratch copy via a new `pub trait ManifestReparse { fn reparse(&self, content: &str) -> Option<Box<dyn ParseResult>>; }` (`deps_core::edit`), whose production implementation `EcosystemReparse` calls a new SYNCHRONOUS sibling of `parse_manifest_blocking` — `parse_manifest_now(ecosystem: &dyn Ecosystem, content: &str, uri: &Url) -> Option<Box<dyn ParseResult>>` — that drives `Ecosystem::parse_manifest`'s documented no-real-`.await` future via `futures::FutureExt::now_or_never()` AND applies the SAME `dependency_cap::cap_dependencies` chokepoint `parse_manifest_blocking` applies (closing round-3 critic M2: `now_or_never()` alone would bypass the #796 cap, adding a second, uncapped parse entry point); `Pending` or a parse error SHALL map to `None` (fail closed); (3) locate the edited occurrence by `(formatter.normalize_package_name(dep.name()), version_range.start)` — NOT by `name_range` (round-4 critic M3: the name does not precede the version in every grammar — NuGet's `Version`-before-`Include` attribute order, Maven's XML element order, and Gradle's map notation would otherwise silently fail closed after the edit shifts `name_range`); `version_range.start` is invariant under an edit that only changes text at or after it. EXACTLY ONE match SHALL be required — zero or more than one fails closed | must |
| FR-025 | **(OQ-C, universal rule, no per-ecosystem table)** THE SYSTEM SHALL apply FR-023/FR-024 as ONE uniform rule with no per-ecosystem override, retry, or alternative rendering — only the ecosystem's own DEFAULT-rendered edit (spec 075's existing `replacement_text`/fallback-view output, unmodified) is ever tried. The resulting scope is DESCRIPTIVE and CONDITIONAL on whether a known newer version happens to fall inside or outside the written requirement's admitted range — not a fixed per-ecosystem verdict (round-4 critic M5: e.g. Cargo's `^2.5.0` excludes a fresh `3.0.0` but admits a fresh `2.6.0`; PyPI's `~=2.2` excludes a fresh `3.0` but admits a fresh `2.3`). Ecosystems with no compiled requirement model at all (GitHub Actions, GitLab CI) are excluded by check (a) exactly as they already are under spec 075 — this is unchanged, existing behavior, not a new fail-closed case introduced by this spec | must |
| FR-026 | **(round-4 critic, replaces the dropped `formatter_conformance!` macro)** For each of the 14 ecosystem crates, THE SYSTEM SHALL add one test driving `fallback_edit_excludes_newer` with that ecosystem's REAL formatter and a real `EcosystemReparse`, pinning its canonical declared-requirement shape's current outcome. WHERE the requirement shape from FR-025's note is conditional (a fresh version inside vs. outside the written range), THE SYSTEM SHALL pin BOTH sub-cases in that ecosystem's test, not only one — a single true/false assertion per ecosystem is insufficient (round-4 critic M5 requirement) | must |
| FR-027 | **(round-4 critic M1, amends spec 075's lockfile path — see §10)** FR-023/FR-024's guard SHALL apply on spec 075's EXISTING lockfile-resolved (`Located`) path exactly as it applies on this spec's `Absent` path — there is no separate, looser check for a dependency that happens to have a lockfile entry. THE SYSTEM SHALL verify, for each spec 075 test asserting a WRITTEN caret/range-shaped fallback for Cargo, Dart, or PyPI's default form, or a Swift `from:` fallback, whether that assertion still holds under FR-023/FR-024 and correct the test's expectation if it does not (§10 lists the specific test named by critic review as a verification candidate) | must |
| FR-028 | **(#1551 closure)** `Closes #1551` REQUIRES both FR-019's shared `cooldown_verdict_for` call sites (the candidate filter and `cooldown_disposition`) to be verified, by test, to route through the same function — #1551 items 1, 2 (FR-016's `InUseFloor`), and 4 (FR-020's gate) are closed by this spec; items 3 and 5 are OUT OF SCOPE here and SHALL be filed as a separate follow-up issue alongside this spec's implementation PR (§11), per this project's no-partial-issue-proxy rule | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-007 | Reliability (pure refactor safety net, round-2 critic M2) | Every existing `cooldown_disposition`, `apply_outdated_rule`, `gossip_cooldown_for`, LSP hover, and LSP diagnostics test in `deps-core`/`deps-lsp`, plus every `deps-cli check`/`update` report test, SHALL pass with its EXISTING expectations unchanged after `cooldown_verdict_for` is extracted from `cooldown_disposition`'s inline branching (FR-019). Only the tests §7's traceability table explicitly names as inversions may change |
| NFR-008 | Documentation (scope boundary) | THE SYSTEM'S documentation (this spec, `CHANGELOG.md`) SHALL record: (a) the permanence rationale for leaving the in-range-churn case unaddressed for Cargo/Dart/PyPI-default/Swift `from:` (FR-025) — a moving exact pin never returns to a range for a frequently-publishing package, so the ONLY shape that would additionally cover that case is rejected as a design option for EVERY such ecosystem uniformly (not adopted for some and not others), rather than accepted as a per-ecosystem partial mitigation (§1 Out of Scope, user decision OQ-C); this is a rule about which MECHANISM is rejected, not a claim that these ecosystems never receive a fallback (§1's conditional framing, round-4 critic M5); (b) the pre-existing, unchanged graph-level-resolution limitation (§1 Out of Scope) as identical to spec 075's own limitation, not a new one; (c) the same pre-existing normalization behavior spec 075 already has, where a user's own manual `=X`-style pin is rewritten to the ecosystem's default caret/range form on a later, unrelated `latest`-path write — unrelated to this spec, stated for completeness only |
| NFR-009 | Performance | FR-024's re-parse mechanism SHALL cost at most one extra synchronous, dependency-count-capped parse per occurrence that reaches the fallback-view pipeline (i.e., only occurrences FR-020's gate found `Blocked` with a fallback candidate) — never a parse per fetch, never uncapped, and never for an occurrence FR-020's gate already excluded |

## 5. Data Model

New, additive types (unless noted):

| Entity | Crate | Description | Key Attributes |
|--------|-------|-------------|-----------------|
| `InUseFloor` | `deps-engine` (private) | FR-016/FR-017's shared floor classifier, replacing two independent duplicate lookups | `Absent` \| `Located(usize)` \| `Unlocatable { newest_located: Option<usize> }` |
| `CooldownVerdict` | `deps_core::lsp_helpers` (`pub`) | FR-019's shared GOSSIP-vs-local precedence result, used by 3 call sites | `Blocked(CooldownBlocker)` \| `Cleared` \| `NoPublishTime` |
| `ManifestReparse` | `deps_core::edit` (`pub` trait) | FR-024's re-parse abstraction; production impl `EcosystemReparse`, test impls stub a fixed re-parsed occurrence | `fn reparse(&self, content: &str) -> Option<Box<dyn ParseResult>>` |
| `EcosystemReparse` | `deps_core::edit` (`pub` struct) | Production `ManifestReparse`, holds `&dyn Ecosystem` + `&Url`, drives `parse_manifest_now` | — |
| `parse_manifest_now` | `deps_core::ecosystem` (`pub` fn) | FR-024's synchronous, `cap_dependencies`-enforcing sibling of `parse_manifest_blocking`, via `now_or_never()` | `fn(ecosystem: &dyn Ecosystem, content: &str, uri: &Url) -> Option<Box<dyn ParseResult>>` |
| `fallback_edit_excludes_newer` | `deps_core::lsp_helpers` (`pub` fn) | FR-023's uniform guard, replaces `deps-cli`'s private `fallback_satisfies_requirement` | see FR-023 signature |

No changes to `PackageVersions`, `CooldownFallback`, `CooldownDisposition`, or `CooldownBlocker` —
all shipped as spec 075 defined them (round-1's `FallbackFloor` addition was proposed, then
dropped in round 1 per critic M1 before shipping; #1544 does not reopen it).

## 6. Edge Cases and Error Handling

### `InUseFloor` classification × call site (FR-016/FR-017/FR-018)

| `InUseFloor` | Spec 074 GOSSIP filter (`fetch.rs:894`) | Spec 075/076 fallback candidate (`fetch.rs:1241`) |
|---|---|---|
| `Absent` (no in-use versions) | No-op (unchanged from today) | No positional floor — FR-001-guarded, `select_latest_matching`-ranked pick over the cooled subset (this spec's core feature) |
| `Located(idx)` | Filter at `idx` (unchanged) | D2 floor at `idx` (spec 075, unchanged) |
| `Unlocatable { newest_located: Some(idx) }` | Filter at `idx` (unchanged) | `cooldown_fallback: None` — stricter than today's shipped behavior, which silently floors at `idx` and ignores the unplaceable entry (§10 amendment) |
| `Unlocatable { newest_located: None }` | No-op (unchanged) | `cooldown_fallback: None` |

### `fallback_edit_excludes_newer` outcome (FR-023/FR-024/FR-025)

| Check | Failure meaning | Example |
|---|---|---|
| (a) `compile_requirement` on the re-parsed occurrence | No precise matcher for this ecosystem/requirement shape | GitHub Actions/GitLab CI tag pins — always `None`, unchanged from spec 075 |
| (b) matcher admits nothing in `available` | An unsatisfiable or malformed requirement | `^5` with only 1.x/2.x published (round-1 critic M5) |
| (c) `is_requirement_up_to_date(requirement, fallback)` | The written requirement already reads `fallback` as current, e.g. it IS the floor | NuGet `[2.0.0,)` bare-floor requirement (round-1 critic S2) |
| (d) some `available` entry at/above `fallback` resolves via `requirement_already_resolves_to` | The written requirement re-admits a known newer version | Cargo `pkg = "1.0"` no-lock, fresh 1.2.0 inside `^1.1.0` (US-003's fail-closed example) |
| all pass | The default-rendered edit is safe to write | npm bare `"1.1.0"` (exact); NuGet floor `[2.1.0,)`; a fresh version outside the written range for any ecosystem |

### Additional scenarios

| Scenario | Expected Behavior |
|----------|-------------------|
| No lockfile, range requirement, latest within cooldown, no known newer version falls inside the ecosystem's default-rendered fallback edit | FR-017 `Absent` + FR-023 all pass → `Applied(fallback)`, `cooldown_fallback: AppliedInsteadOf(latest)` — the #1544 fix |
| No lockfile, range requirement, latest within cooldown, a known newer version falls inside the ecosystem's default-rendered fallback edit (Cargo/Dart/PyPI-default/Swift `from:` typical, in-range churn case) | FR-023 check (d) fails → `NoneUsable` → `WithinFreshnessCooldown` — the documented, out-of-scope common-case fail-closed outcome (§1); the SAME dependency instead gets `Applied(fallback)` when the fresh version falls outside the written range (round-4 critic M5) |
| GitHub Actions/GitLab CI tag pin, latest within cooldown | FR-023 check (a) fails (`compile_requirement` is `None`) — excluded before this spec's rule is ever reached, unaffected by this spec, unchanged from spec 075 (NOT part of the conditional fail-closed boundary above) |
| Partial in-use-version match: one in-use version resolves to a position, a second does not (e.g. a mixed Go pseudo-version alongside a resolvable one — hypothetical, Go itself never reaches `Absent`) | `Unlocatable { newest_located: Some(idx) }` → spec 074's own filter unaffected; the fallback candidate is `None` (§10 amendment tightens spec 075) |
| `freshness.cooldown_secs` widened between fetch and read | FR-021's gate-superset invariant: a fetch-time `Cleared`/`NoPublishTime` (no candidate scanned) cannot become read-time `Blocked` with a missing fallback in a way that regresses safety — worst case is a stricter, not less-safe, skip |
| A 15th, future ecosystem adds `EcosystemFormatter` with no `compile_requirement` override | FR-023 check (a) fails closed automatically — no macro or trait-method declaration required (round-4 critic: the runtime post-condition is the safety mechanism, not a compile-time declaration) |

## 7. Success Criteria

| ID | Metric | Target | Traceability (tests to keep / invert / add) |
|----|--------|--------|----------------------------------------------|
| SC-009 | FR-017 `Absent` produces a fallback | New test: no-lockfile range dependency, frequent-publisher scenario (US-003, criterion 1) resolves `Applied(fallback)` | new, must pass |
| SC-010 | FR-018 `Unlocatable` fails closed at the fallback site | New test: a partial in-use-version match (one placed, one not) resolves `cooldown_fallback: None` | new, must pass |
| SC-011 | FR-018 preserves spec 074's own filter unchanged | Existing spec 074 partial-match tests (`fetch.rs` `floor_exists_but_ecosystem_selection_rejects_the_remainder_is_a_no_op`, `filtered_pick_below_the_floor_is_rejected_in_favor_of_the_unfiltered_pick`, and related fixtures) pass unchanged after FR-016's `InUseFloor` refactor | pass unchanged |
| SC-012 | FR-020 M4 gate — no scan unless `latest` is `Blocked` | New test: `latest` `Cleared`/`NoPublishTime` triggers zero fallback-candidate computation (no `select_latest_matching`/GOSSIP calls beyond the initial unfiltered-pick check) | new, must pass |
| SC-013 | FR-021 gate-superset invariant | New tests: the 3 cases in the invariant's proof (unfiltered-pick-is-latest, spec-074-substituted-latest, `get_latest_matching_from` branch), plus the cooldown-window-narrowed-between-fetch-and-read case asserting a skip, not an unsafe write | new, must pass |
| SC-014 | FR-023 guard (a)-(d) on the re-parsed occurrence | New tests: NuGet S2 repro (`[2.0.0,)` floor, a below-floor fallback rejected via check (c)); M5 unsatisfiable-requirement repro (`^5`); the `>=2.0,<2.3` widen-admits-fresh repro (check (d), includes the fallback's own position) | new, must pass |
| SC-015 | FR-024 re-parse validates the effective requirement, not span text | New tests: Swift `.exact(...)` and `.upToNextMinor` pass/fail on their real parsed semantics (not accidentally correct span text); Bundler multi-constraint literal | new, must pass |
| SC-016 | FR-024 M2 sync cap | New test: `parse_manifest_now` applied to a manifest at/over `MAX_DEPENDENCIES_PER_DOCUMENT` is capped identically to `parse_manifest_blocking`'s async path | new, must pass |
| SC-017 | FR-024 M3 lookup fix | New test: a NuGet `<PackageReference Version="1.0" Include="X"/>` (`Version` before `Include`) fixture resolves via `(name, version_range.start)` lookup — does NOT silently fail closed the way a `name_range`-based lookup would | new, must pass |
| SC-018 | FR-026 per-ecosystem outcome tests | 14 new tests (one per ecosystem crate), each pinning FR-025's conditional rule with both sub-cases where applicable (round-4 critic M5) | new, must pass |
| SC-019 | FR-027 spec 075 lockfile-path regression, verified | `crates/deps-cli/src/update/mod.rs::test_plan_updates_real_semver_formatter_applies_fallback` (~2386) is checked against FR-023/FR-024 and its expectation corrected if the written shape no longer passes; any other spec 075 test asserting a written caret/range/`from:` fallback shape for Cargo/Dart/PyPI-default/Swift is likewise checked | verify, correct if needed |
| SC-020 | FR-022 Go bypass removal | Existing Go fallback tests (spec 075's `test_fallback_satisfies_requirement_go_exception_bypasses_compile_requirement` and its `plan_updates`-level equivalents) are inverted to prove Go's `ExactMatcher` alone (no bypass) still resolves the same outcome | invert, must pass |
| SC-021 | NFR-007 pure-refactor safety net | Every existing `cooldown_disposition`/`apply_outdated_rule`/`gossip_cooldown_for`/hover/diagnostics/`check`-report test passes with UNCHANGED expectations, except SC-011/SC-019/SC-020's named inversions | pass unchanged except named inversions |
| SC-022 | Full CI check suite | `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, the branching.md rustdoc gate — all green | must pass before PR |

## 8. Agent Boundaries

### Always (without asking)
- Route every GOSSIP-vs-local-heuristic decision through `cooldown_verdict_for` (FR-019) — do not
  add a second copy anywhere in this call graph.
- Use `InUseFloor` (FR-016) at both call sites — do not leave or reintroduce a third independent
  `in_use_versions` position-lookup.
- Re-parse via `ManifestReparse`/`parse_manifest_now` for FR-023/FR-024 — never compile the
  replacement span's text directly (this was tried and rejected, round 2 S2).
- Run the full pre-commit check suite (`.claude/rules/branching.md`) before opening the PR — this
  touches the same hot paths spec 075 already covers extensively.

### Ask First
- Any reintroduction of a per-ecosystem override or retry mechanism for the fallback edit's
  shape (`format_version_pinned_for` or equivalent) — three design rounds tried and rejected this
  path (§1, design-history note below); the user's OQ-C decision (one uniform rule with no
  per-ecosystem override, applied identically to every ecosystem) is not to be revisited without a
  new explicit decision.
- Splitting `SkipReason::WithinFreshnessCooldown` further, or adding a new outcome variant for the
  fail-closed boundary — spec 075's existing single-variant-with-attribution shape (its own OQ5
  decision) is unchanged and extends naturally to this spec's `NoneUsable` cases.

### Never
- Do not add a `format_version_pinned_for` (or equivalently named) trait method, or any
  ecosystem-crate source change — this spec's guard is enforced entirely by the re-parse
  post-condition (FR-023/FR-024), not by a compile-time per-ecosystem declaration (§1, §3 FR-026's
  note).
- Do not compile the replacement span's text in isolation for FR-023's guard — always re-parse the
  edited manifest (FR-024; round-2 S2's exact mistake).
- Do not derive a synthetic requirement floor independent of what the ecosystem's OWN default
  rendering already produces — the rule is "does the default edit already exclude the newer
  version", never "construct a new requirement shape that would".
- Do not restore spec 075's `manifest_requirement_is_resolved_version` Go bypass (FR-022) —
  it guards an unreachable branch after this spec's changes.

### Design history (rejected alternatives, preserved for context)

Three prior design rounds are NOT the current design and must not be reintroduced without a new
explicit decision:
1. **Bounded range `>=F,<N`** — core cannot pick `N` safely without per-ecosystem comparison
   logic, and a bound still admits an in-cooldown patch below `N` published later.
2. **Per-ecosystem `format_version_pinned_for` override** (Cargo `=X`, Dart `X`, PyPI `>=X,<=X`,
   with a `formatter_conformance!` macro forcing an explicit per-ecosystem declaration) — round 3's
   design. Rejected in round 4 (OQ-C) once the user extended the "permanent pin is unacceptable"
   rationale from Cargo alone to every ecosystem, which removed the override's only remaining
   justification (Dart/PyPI would still need one). With no overridable method left, the
   conformance macro had nothing to force a declaration against, so it was dropped too — the
   runtime post-condition (FR-023) already fails closed for a 15th ecosystem with no override.
3. **PyPI `>=X,<=X` self-healing pinned form** — semantically correct (verified against
   `deps-pypi`'s `format_version_replacing`, which does not special-case a `>=`/`<=` pair) but
   superseded by (2)'s removal.

## 9. Open Questions

None blocking. All were closed across four review rounds:

- **OQ-A** (is an exact Cargo pin acceptable in a library manifest, round-2 architect):
  superseded — round-2 critic's S1 finding showed the pin is not transient for the #1528
  population, which reopened the question rather than closing it as originally asked.
- **OQ-B** (`reason()` wording for a pinned-rendering write): moot — no pinned-rendering write
  path remains after OQ-C.
- **OQ-C** (extend the Cargo fail-closed decision to Dart and PyPI too, round-3 architect):
  **resolved by the user** — extended universally to every ecosystem, not only Cargo/Dart/PyPI.
  This is the load-bearing decision behind §1's Out of Scope and FR-025.

## 10. Amendments to Other Specs

This spec amends `[[075-cli-update-cooldown-fallback/spec]]` by cross-reference — its own text is
not rewritten, per this project's `specs.md` convention for a shipped spec (mirroring how spec 075
itself amended `[[074-deps-cli-gossip-parity/spec]]` and `[[072-deps-dev-gossip-signals/spec]]` at
spec-writing time, not deferred to its own implementation). The amendment notes below have ALREADY
BEEN APPLIED to `specs/075-cli-update-cooldown-fallback/spec.md` as `> [!info] Amended by
[[076-cli-update-cooldown-fallback-no-lockfile/spec]]` callouts (one after its §3 FR table, one
after its §4 NFR table), and spec 075's frontmatter `related` list now includes this spec:

- **FR-002** (D2 in-use floor): amended to note that "no in-use version resolved" (spec 075's
  `Absent` case, in this spec's `InUseFloor` terms) is no longer an unconditional "no fallback" —
  see this spec's FR-017/FR-023.
- **FR-003** (requirement-floor guard, Go exception): the `manifest_requirement_is_resolved_version`
  exception clause is REMOVED by this spec's FR-022 — the note under 075's FR-003 row states the
  exception is dropped and points to FR-022's rationale (the exception guarded an unreachable
  branch once `ExactMatcher` alone was proven sufficient).
- **NFR-001 step 4** (fallback selection criteria): amended to reference FR-023's guard
  (superseding FR-003's original span-text check) and to note the guard now also requires the
  re-parse mechanism (FR-024) rather than compiling requirement text directly.
- **NFR-005(b)** (the no-lockfile GOSSIP-`Active` behavior change, spec 074 FR-003b): amended
  again — spec 075 changed this case from "applied" (spec 074) to "skipped" (spec 075, no floor).
  This spec's FR-017 potentially changes it a THIRD time, to "applied" again, but ONLY when
  FR-023's guard passes for that ecosystem's default rendering; otherwise it remains "skipped".

The `CHANGELOG.md` `[Unreleased]` entry for spec 075 (currently: `deps-cli, deps-core,
deps-engine: deps-cli update now falls back to the newest cooled-down, OSV-verified candidate
instead of skipping outright when latest is within the freshness cooldown window (partially
addresses #1528, resolves #1529) (#1550)`) SHOULD be corrected or superseded by a new entry once
this spec ships, since "falls back... instead of skipping outright" is no longer universally true
even on the lockfile path for Cargo/Dart/PyPI-default/Swift `from:` (§1, FR-027) — unlike the spec
amendments above, this genuinely IS an implementation-time task (`tasks.md` T008), consistent with
spec 075's own convention of deferring its `CHANGELOG.md` entry to its implementation PR rather
than writing it during spec-writing.
- **§6 decision table**: FR-023/FR-024 supersede the table's implicit "FR-003's guard" reference
  wherever the guard is mentioned — the decision table's row STRUCTURE (which view is selected,
  what outcome results) is unchanged; only the guard's internal mechanics changed.
- **§11 Required Follow-Up**: spec 075's own OQ1 follow-up issue (the no-floor case) is
  substantially addressed by this spec for the ecosystems FR-025 covers. This spec's OWN §11
  below records the NARROWER follow-up that remains: the common-case, in-range-churn fail-closed
  outcome for Cargo/Dart/PyPI-default/Swift `from:`, on both this spec's no-lockfile path and spec
  075's lockfile path.

## 11. Required Follow-Up

Three follow-up issues are required alongside this spec's implementation PR, per this project's
no-partial-issue-proxy rule (each is filed as its own issue at PR time, not held open as a
tracking proxy):

1. **In-range-churn fail-closed outcome restoration** (§1 Out of Scope, FR-025). Research an
   installer-level cooldown mechanism (e.g. `uv`'s `exclude-newer`, npm's `min-release-age`) or
   another manifest-independent approach for Cargo, Dart, PyPI's default range form, and Swift
   `from:` — the sub-population where a known newer version falls INSIDE the default-rendered
   edit's admitted range, where #1528's starvation persists after this spec, on both the
   no-lockfile and lockfile paths (the out-of-range sub-population is already fixed by this spec,
   §1). Reference this spec and issue #1544/#1528, and record that a manifest-level pin was
   deliberately rejected (§8 design history) so a future spec does not re-litigate it.
2. **`#1551` items 3 and 5** (FR-028). Filed as their own issue, referencing #1551 and this spec's
   partial closure.
3. **PyPI/Composer `!=X` exclusion specifiers** (§1 Out of Scope, spec 075 round-1 critic M6). A
   pre-existing gap on spec 075's lockfile path, unchanged by this spec — filed as its own issue.

## 12. See Also

- [[075-cli-update-cooldown-fallback/spec]] — amended by §10 above; the spec this one extends.
- [[074-deps-cli-gossip-parity/spec]] — FR-016/FR-018 preserve its floor-protected filter
  unchanged.
- [[072-deps-dev-gossip-signals/spec]] — source of `GossipCooldownLookup`, consumed by FR-019.
- [[constitution]] — project principles.
- [[MOC-specs]] — all specifications.
- `plan.md` (this feature) — exact call-site line numbers and integration order.
- `tasks.md` (this feature) — ordered implementation tasks.

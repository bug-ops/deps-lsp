---
aliases:
  - Release Freshness Signal
  - Cooldown-Aware Version Recommendations
  - Publish Recency Risk Signal
tags:
  - sdd
  - spec
  - research
  - deps-core
  - supply-chain-risk
  - cross-ecosystem
created: 2026-08-20
updated: 2026-08-23
status: approved
related:
  - "[[constitution]]"
---

> [!note] Revision 2026-08-23
> Current State, FR-007/FR-008, NFR-001 and SC-001 were revised after every
> registry was verified live; FR-011 and FR-012 were added. All Open Questions
> (§9) are resolved in `plan.md`. v1 scope is **six ecosystems**.

# Feature: Release-Freshness Signal for Version Recommendations

> [!info] Metadata
> **Author**: continuous-improvement cycle (deps-lsp)
> **Branch**: feat/{issue-number}-release-freshness-signal
> **Priority**: P2
> **Type**: research / parity gap

## 1. Overview

### Problem Statement

deps-lsp's hover, diagnostics, and completion features recommend the "latest"
version of a dependency as soon as a registry reports it, with no awareness of
how recently that version was published. Two reference projects in the
dependency-tooling space have converged on treating "very recently published"
as a risk signal rather than a pure positive:

- GitHub Dependabot (as of 2026-07-14) now defaults to a 3-day "cooldown"
  period before opening a version-update PR for a newly published release —
  security updates are exempted and still surface immediately.
  ([source](https://github.blog/changelog/2026-07-14-dependabot-version-updates-introduce-default-package-cooldown/))
- Socket.dev's supply-chain risk scoring flags packages/releases with
  characteristics like "very new", "new maintainer/author", or otherwise low
  publication history as elevated-risk signals, independent of known-CVE
  status.

Rationale: a version published minutes or hours ago carries meaningfully
higher risk of being yanked, containing a build mistake, or — rarer but
higher-impact — being a compromised/malicious publish that has not yet been
caught, compared to a version that has been live for days. Today deps-lsp has
no concept of "time since publish" surfaced anywhere in hover, diagnostics, or
completion, so it cannot distinguish "safe, well-established latest" from
"just published 10 minutes ago" when it tells a user "you're outdated, upgrade
to X".

### Current State (verified against the codebase, 2026-08-20)

The shared `Version` trait
(`crates/deps-core/src/registry.rs:135`, implemented by every ecosystem crate)
has no publish-timestamp accessor. `find_latest_stable`
(`crates/deps-core/src/registry.rs:202`) — the single shared function that
selects "latest" for hover, diagnostics (`crates/deps-core/src/lsp_helpers.rs`,
`generate_diagnostics` / `generate_diagnostics_from_cache`), and completion
(`crates/deps-core/src/completion.rs`) — only considers `is_yanked()` and
`is_prerelease()`. Publish recency plays no role in ranking or in the
`DiagnosticSeverity` chosen (`WARNING` for unknown package, `HINT` for
outdated, per `lsp_helpers.rs:474/494/524/550/563`).

At the per-ecosystem level, the picture is mixed rather than uniformly
absent — some ecosystem `Version` structs already parse a raw publish
timestamp from the registry response, but the value is dead data: parsed,
stored, and never read by any hover/diagnostic/completion code path.

> [!warning] Revised 2026-08-23 after live verification
> The table below was originally derived from code reading alone and was wrong
> for 6 of 11 ecosystems, in **both** directions. It has been replaced with
> results verified by live `curl` against every registry. Raw evidence in
> `plan.md` §0.

The decisive question is not "does the registry expose a timestamp somewhere"
(all of them do) but "is it in the payload the crate **already fetches**".

| Ecosystem crate | `*Version` struct | In the already-fetched payload? | Format / notes |
|---|---|---|---|
| `deps-cargo` | `CargoVersion` (`types.rs:99`) | **YES** | Sparse index NDJSON now carries `pubtime`, 100% coverage (195/195 for `tokio`, back to 2016). `2026-07-18T23:05:13Z`. **No separate crates.io API call needed** — contrary to the original finding |
| `deps-pypi` | `PypiVersion` (`types.rs:111`) | **YES** | PEP 700 `files[].upload-time` inside the already-requested PEP 691 JSON (api-version 1.4). `2026-05-14T19:25:27.735762Z`. Per **file**, so a version's time is the minimum across its files |
| `deps-composer` | `ComposerVersion` (`types.rs:78`) | **YES** | Packagist p2 `time` on every entry (87/87 for `monolog/monolog`). `2026-01-02T08:56:05+00:00` (numeric offset) |
| `deps-bundler` | `BundlerVersion` (`types.rs:39`) | **YES** | `created_at` already parsed and discarded |
| `deps-dart` | `DartVersion` (`types.rs:30`) | **YES** | `published` already parsed and discarded |
| `deps-go` | `GoVersion` (`types.rs:39`) | **PARTIAL** | `/@latest` returns `Time` (feeds diagnostics); `/@v/list`, used by `get_versions` for hover/completion, is plain text with no dates. The `time` field exists but `parse_version_list` hardcodes `None` |
| `deps-npm` | `NpmVersion` (`types.rs:89`) | **NO** | The abbreviated packument deliberately used by the crate omits the top-level `time` object entirely. The full packument is **2.37×** larger (804 975 vs 339 376 B for `express`) |
| `deps-maven` / `deps-gradle` | `MavenVersion` (`types.rs:45`) | **NO** | `maven-metadata.xml` has **no per-version dates** at all (only `<lastUpdated>` per artifact). `timestamp: Option<u64>` is **dead code** — both construction sites pass `None`. Per-version dates need the solrsearch `core=gav` API or a `HEAD` per version |
| `deps-nuget` | `NuGetVersion` (`types.rs:54`) | **NO** | Flat container `index.json` is a bare `{"versions": [...]}`. `published` lives in the registration hive, which the crate deliberately does not resolve and which is paged |
| `deps-swift` | `SwiftVersion` (`types.rs:76`) | **NO** | Version data comes from the GitHub **tags** API, which has no date field for any host. Needs N commit lookups or the releases API (which misses tag-only packages), against an already rate-limited endpoint |

This supersedes the original finding's "zero hits" characterization in both
directions. Three ecosystems (Cargo, PyPI, Composer) are **cheaper** than
assumed — their timestamps are already on the wire, merely not deserialized.
Four (npm, Maven/Gradle, NuGet, Swift) are **more expensive** than assumed — the
timestamp is not in the fetched payload at all, so the spec's premise that every
registry "already fetches" it does not hold. What is genuinely true across the
board is that no timestamp ever reaches the shared `Version` trait or any
hover/diagnostic/completion decision: the freshness *signal* does not exist
anywhere in `deps-core`.

**v1 scope (confirmed by the user 2026-08-23):** the six ecosystems with a
zero-cost timestamp — Cargo, PyPI, Composer, Bundler, Dart, and Go (diagnostics
path only). npm, Maven/Gradle, NuGet and Swift are deferred to one follow-up
issue each, because each carries a distinct, non-trivial network cost that
deserves its own decision rather than a blanket one.

### Goal

deps-lsp can express, per version, "how long has this been published" as a
first-class signal available to hover, diagnostics, and completion, so that a
just-published "latest" version can be visually and semantically
distinguished from an established one — without ever hiding, blocking, or
demoting the version below other choices if the user wants to pick it anyway.

### Out of Scope

- Choosing the final UX treatment (color, icon, severity level, exact
  wording) for the freshness signal in hover/diagnostics/completion — this
  spec defines the capability and the signal; `/sdd plan` decides rendering
  details in collaboration with the user
- Blocking, auto-rejecting, or filtering out recently-published versions from
  any list — Dependabot's cooldown delays the *update PR*; deps-lsp has no PR
  concept, so at most this delays/softens a *recommendation*, never removes a
  version from what the user can see or select
- Fetching additional network calls per version where the timestamp is not
  already part of an already-fetched payload (see Data Model/NFR for the
  per-ecosystem cost analysis) — if an ecosystem requires a materially more
  expensive API call it may be deferred, flagged as a partial implementation
  in `/sdd plan`
- Any determination about maintainer reputation, publish-history depth, or
  other Socket.dev-style supply-chain signals beyond publish-recency of the
  specific version — those are a distinct, larger research topic
- Security-update exemption logic equivalent to Dependabot's — deps-lsp does
  not currently have a vulnerability-aware diagnostics pathway merged (see
  [[002-osv-vulnerability-diagnostics/spec|002]], still in `plan` phase with
  open clarifications); wiring freshness-exemption-for-security-updates
  together with 002 is a follow-up, not this spec

## 2. User Stories

### US-001: See publish recency in hover

AS A developer hovering over a dependency version in my manifest
I WANT the hover card to tell me how recently the "latest" version was
published (e.g. "published 2 hours ago" vs. "published 4 months ago")
SO THAT I can judge whether it is safe to jump straight to it or whether I
should wait

**Acceptance criteria:**
```
GIVEN a dependency whose registry-reported latest version has a known publish
  timestamp
WHEN the user hovers over that dependency's version field
THEN the hover card shows a human-readable "published <relative time> ago"
  line for the latest version, in addition to the existing version number
```

### US-002: Softer signal for very recent releases

AS A developer relying on deps-lsp's outdated-version diagnostics
I WANT a version published within a short, configurable window (default
mirrors Dependabot's 3-day default) to be flagged distinctly from an
established outdated recommendation
SO THAT I am not nudged to adopt a release that might still be yanked or
buggy within its first hours/days

**Acceptance criteria:**
```
GIVEN the registry-reported latest version was published less than the
  configured cooldown window ago
WHEN deps-lsp generates a diagnostic or hover recommendation for that
  dependency
THEN the recommendation is visually/semantically distinguished from a
  standard "outdated, upgrade now" recommendation (exact treatment decided in
  /sdd plan), and the previous stable version outside the cooldown window
  remains visible as an alternative
```

### US-003: Graceful degradation when publish data is unavailable

AS A developer using an ecosystem where publish-timestamp data cannot be
retrieved (e.g. a non-GitHub-hosted Swift package registry, or a transient
registry error)
I WANT deps-lsp to behave exactly as it does today — no freshness signal
shown, no error, no blocked recommendation
SO THAT the new capability never regresses existing behavior for ecosystems
or edge cases where the data genuinely is not available

**Acceptance criteria:**
```
GIVEN a version's publish timestamp cannot be determined (parse failure,
  missing field, or ecosystem where the API does not expose it)
WHEN deps-lsp renders hover, diagnostics, or completion for that version
THEN it falls back to current (pre-feature) behavior with no freshness line,
  no error surfaced to the user, and no change in severity/ranking
```

### US-004: Consistent behavior across ecosystems

AS A developer who works across multiple ecosystems in the same or different
projects (e.g. Cargo and npm)
I WANT the freshness signal to look and behave the same way regardless of
which of the 10+ supported ecosystems I am using
SO THAT the feature is predictable and not something I have to re-learn per
manifest type

**Acceptance criteria:**
```
GIVEN two dependencies in different ecosystems whose latest versions were
  both published 1 hour ago
WHEN the user hovers over either dependency
THEN both hover cards present the freshness signal in the same format and
  with the same cooldown-window semantics, per the cross-ecosystem
  consistency principle in .claude/rules/continuous-improvement.md
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN an ecosystem registry response for a version already includes a publish timestamp THE SYSTEM SHALL parse it into a structured, ecosystem-independent time value accessible via the shared `Version` trait (`crates/deps-core/src/registry.rs`) | must |
| FR-002 | WHEN the shared `Version` trait exposes a publish timestamp for a version THE SYSTEM SHALL make it available to hover rendering, diagnostic generation (`generate_diagnostics`, `generate_diagnostics_from_cache`), and completion (`build_version_completion`) without ecosystem-specific branching in `deps-core` | must |
| FR-003 | WHEN a version's publish timestamp is known and hover is requested for that dependency THE SYSTEM SHALL include a human-readable relative-time indicator (e.g. "published 2 hours ago") in the hover content for that version | must |
| FR-004 | WHEN the latest version's publish timestamp is within a configurable cooldown window (default 3 days, mirroring Dependabot's default) THE SYSTEM SHALL distinguish the resulting recommendation from a recommendation for a version outside the cooldown window, via: a hover age suffix plus a cooldown callout, and a distinct diagnostic **message** with severity unchanged at `HINT` (mechanism decided in `plan.md` §4; completion carries relative age only, no cooldown verdict) | must |
| FR-005 | WHEN a version's publish timestamp cannot be parsed or is absent from the registry response THE SYSTEM SHALL fall back to current pre-feature behavior for that version with no error surfaced to the user | must |
| FR-006 | WHEN the cooldown window influences a recommendation THE SYSTEM SHALL NOT remove, hide, or block the recently-published version from being visible or selectable in hover or completion — only the recommendation framing changes | must |
| FR-007 | WHEN an ecosystem's publish timestamp is present in the payload the crate already fetches but is not yet deserialized (Cargo `pubtime`, PyPI `files[].upload-time`, Composer `time`, per Current State table) THE SYSTEM SHALL add that deserialization without introducing an additional network round trip | must |
| FR-008 | WHEN an ecosystem crate already parses a publish timestamp but discards it (Dart `published`, Bundler `created_at`, Go `time`, per Current State table) THE SYSTEM SHALL wire the existing field into the shared `Version` trait rather than re-parsing or re-fetching it | must |
| FR-009 | WHEN the cooldown window is not explicitly configured by the user THE SYSTEM SHALL apply a default of 3 days | should |
| FR-010 | WHEN a user configures a custom cooldown window THE SYSTEM SHALL apply it uniformly across all ecosystems (no per-ecosystem override), consistent with the cross-ecosystem consistency principle | should |
| FR-011 | WHEN an ecosystem's publish timestamp is NOT in the already-fetched payload (npm, Maven/Gradle, NuGet, Swift) THE SYSTEM SHALL leave that ecosystem unmodified in v1, falling back to FR-005 graceful degradation, and defer the cost decision to a per-ecosystem follow-up issue | must |
| FR-012 | WHEN the user changes the cooldown configuration at runtime THE SYSTEM SHALL apply the new value without requiring an editor or server restart, via `workspace/didChangeConfiguration` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Parsing and exposing the publish timestamp MUST NOT add any network round trip, nor enlarge any existing request/response, for the six ecosystems whose timestamp is already on the wire (Cargo, PyPI, Composer, Bundler, Dart, Go-partial). This constraint **defined** v1 scope, deferring the four ecosystems whose timestamp is not already on the wire (npm, Maven/Gradle, NuGet, Swift) rather than making them more expensive. **Amended for Maven/Gradle (issues #221, #225):** after live probing found no zero-cost data source (see `plan-maven-gradle.md` §1), the team accepted a scoped, documented, opt-out-able exception for Maven/Gradle specifically — `freshness.enabled` (default `true`) issues one extra conditional GET per hover/completion to the CDN host already serving `maven-metadata.xml` (~130–170ms cold, a 304 on repeat; document-open/diagnostics untouched), with `freshness.enabled: false` restoring the original zero-extra-request behavior. npm, NuGet, and Swift remain deferred under the original, unamended constraint. No observable hover/completion latency regression for the six ecosystems this constraint still applies to unmodified |
| NFR-002 | Cross-ecosystem consistency | Per `.claude/rules/continuous-improvement.md` ("Cross-Ecosystem Consistency Testing"), the freshness signal MUST be implemented once in `deps-core` (shared `Version` trait, hover/diagnostic/completion helpers) rather than duplicated per ecosystem crate |
| NFR-003 | Backward compatibility (pre-1.0) | Adding a timestamp accessor to the `Version` trait MUST be done via a default trait method (returning `None`) so existing ecosystem implementations compile unchanged until each is migrated, avoiding a big-bang breaking change across all 11+ ecosystem crates in one PR |
| NFR-004 | Test coverage | Each ecosystem crate that gains timestamp parsing MUST have unit tests covering: present timestamp, missing/null timestamp, and malformed/unparseable timestamp, per the existing test patterns already used for `created_at`/`time` fields (e.g. `crates/deps-bundler/src/registry.rs::test_parse_versions_response_with_created_at`) |
| NFR-005 | Correctness | Timestamp parsing and relative-time formatting MUST use an existing, maintained date/time crate already in the workspace dependency tree or added per the project's dependency-addition policy (context7 mcp check) — no hand-rolled date arithmetic |
| NFR-006 | Live verification | Per the project's live-testing principle, the freshness signal MUST be verified against at least one real, currently-recent release per ecosystem (a package that published a version within the last few days) before the feature is considered complete — not just unit-tested with fixture data |

## 5. Data Model

No new persistent entities; this extends the existing per-ecosystem `*Version`
structs and the shared `Version` trait with an optional timestamp.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `Version` (trait, `deps-core`) | Shared abstraction every ecosystem's version type implements | existing: `version_string()`, `is_yanked()`, `is_prerelease()`; new: `published_at() -> Option<DateTime<Utc>>` (default `None`) `[NEEDS CLARIFICATION: exact method name/signature — decided in /sdd plan]` |
| `MavenVersion` / `DartVersion` / `BundlerVersion` / `GoVersion` | Already carry a raw timestamp field (`timestamp: Option<u64>`, `published: Option<String>`, `created_at: Option<String>`, `time: Option<String>`) | Wire existing field into `Version::published_at()` |
| `CargoVersion` / `NpmVersion` / `PypiVersion` / `ComposerVersion` / `SwiftVersion` / `NuGetVersion` | Do not currently carry a timestamp | Add a field sourced from the registry response field identified in the Current State table |
| Cooldown configuration | New, currently undefined | Default 3-day window; storage location (LSP client settings? `deps-lsp` config file? hardcoded constant for v1?) `[NEEDS CLARIFICATION: see Open Questions]` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Registry response omits the timestamp field entirely | `published_at()` returns `None`; hover/diagnostics/completion behave exactly as pre-feature (US-003) |
| Timestamp field present but malformed (unparseable date string) | Treated identically to absent — parse failure logged at `debug`/`trace`, never surfaced as a user-facing error or panic |
| Version was published in the future relative to the local clock (clock skew, or registry timestamp bug) | Freshness signal MUST NOT show a negative/nonsensical duration; clamp to "just now" or suppress the signal — `[NEEDS CLARIFICATION: exact clamping behavior]` |
| Latest version is exactly at the cooldown boundary (e.g. published 3 days minus 1 second ago) | Boundary is inclusive/exclusive per a single documented rule applied uniformly across all ecosystems |
| All available versions for a package are within the cooldown window (package is brand new) | The freshest version is still shown as the best available choice — cooldown softens the recommendation, never leaves the user with nothing to install (consistent with FR-006) |
| Multiple ecosystems return timestamps in different formats (Unix epoch `u64` for Maven, ISO 8601 string for most others) | Parsing normalizes all formats to one internal `DateTime<Utc>` (or equivalent) representation in `deps-core` before any comparison logic runs |
| User's editor/LSP client does not support whatever configuration mechanism is chosen for the cooldown window | Falls back to the 3-day default; feature still functions, just not customizable in that client |
| A lockfile pins a version that is itself within the cooldown window (already installed, not a recommendation) | `[NEEDS CLARIFICATION: does the freshness signal apply to the currently-installed/locked version too, or only to the "latest" recommendation target?]` |

## 7. Success Criteria

Measurable metrics that prove the feature works:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover shows a "published X ago" line for a package with a known-recent release, verified live for at least one package per ecosystem | 100% of the **six v1 ecosystems** — Cargo, PyPI, Composer, Bundler, Dart on both hover and diagnostics; Go on the diagnostics path only (its `**Latest**` hover line, not its "Recent versions" list). Verified via `.local/testing/lsp_test.py`. The four deferred ecosystems are explicitly expected to show **no** freshness line — that is SC-003, not a failure |
| SC-002 | Diagnostics/hover for a version published within the cooldown window are distinguishable (per whatever mechanism `/sdd plan` selects) from one published outside it | Verified live with at least one real package published within the last 3 days |
| SC-003 | No regression: ecosystems/edge cases without timestamp data behave identically to pre-feature baseline | 100% of existing hover/diagnostics/completion tests continue to pass unchanged |
| SC-004 | `Version` trait extension is additive only | Zero call sites outside `deps-core` and the ecosystem crates being actively migrated require changes; existing ecosystem crates not yet migrated (per NFR-003) compile without modification |
| SC-005 | Full CI gate passes | `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate — 0 failures |

## 8. Agent Boundaries

### Always (without asking)
- Reproduce the freshness signal live via the LSP harness against a debug
  build for at least one real, recently-published package before considering
  any implementation task complete, per `continuous-improvement.md`
- Add unit tests for present/missing/malformed timestamp per ecosystem
  touched
- Preserve existing hover/diagnostic/completion behavior for ecosystems not
  yet migrated (default trait method returns `None`)

### Ask First
- Adding a new date/time crate dependency if the workspace's current
  dependency tree (`chrono`/`time`, whichever if either is already present)
  is insufficient — must be checked via context7 mcp per user's dependency
  policy
- Choosing where cooldown-window configuration lives (LSP `initializationOptions`,
  a config file, or a hardcoded constant for v1) — this is a UX/architecture
  decision for `/sdd plan`, not an implementation default to silently pick
- Changing the public signature of the `Version` trait in a way that is not
  purely additive (i.e. anything beyond a new default method)

### Never
- Filter, hide, or block a recently-published version from any hover,
  completion, or diagnostic output as a side effect of this feature
  (violates FR-006 / US-002 intent — Dependabot delays PRs, it does not
  delete releases from view)
- Silently change `find_latest_stable`'s selection criteria (yanked/prerelease
  exclusion) as a side effect of adding freshness data — freshness is an
  additional signal, not a replacement for existing latest-selection logic,
  unless explicitly scoped in `/sdd plan`
- Mark the fix complete based on unit tests alone — live LSP verification
  against a real, recently-published package per ecosystem is required per
  the project's continuous-improvement testing gate

## 9. Open Questions

> [!success] All resolved 2026-08-23 — see `plan.md` §7 for the decision record
> Summary: hover gets an age suffix plus a cooldown callout and per-entry ages;
> diagnostics change message only, severity stays `HINT`; completion uses
> `label_details` for age with no cooldown verdict. Cooldown lives in
> `DepsConfig.freshness` (3-day default, clamped 0–30 d) and is **live-reloadable**
> via `did_change_configuration` (FR-012). The trait method is
> `published_at() -> Option<PublishTime>`, a `deps-core` newtype over `i64` Unix
> seconds backed by the `time` crate, which stays confined to `deps-core`. Future
> timestamps clamp to "just now" and count as within cooldown; the boundary rule
> is `age < cooldown` (exclusive). Freshness applies only to the recommendation
> target, never to the locked/installed version. Swift is deferred entirely, so
> the non-GitHub-host question is moot. The FR-007/FR-008 PR split was rejected as
> an axis in favour of splitting by network cost. OSV/002 coordination stays out
> of scope.
>
> The original questions are retained below for provenance.

- [NEEDS CLARIFICATION: Exact UX treatment for the cooldown-window signal —
  softer diagnostic severity (e.g. `HINT` instead of `WARNING`), a distinct
  hover badge/icon, a completion item detail suffix, or some combination?
  Decided in `/sdd plan`.]
- [NEEDS CLARIFICATION: Where does the cooldown-window duration get
  configured — LSP `initializationOptions`, a `deps-lsp` config file, an
  environment variable, or hardcoded to 3 days for v1 with configurability
  deferred?]
- [NEEDS CLARIFICATION: Exact `Version` trait method signature and return
  type for the timestamp — `Option<DateTime<Utc>>` via `chrono`, or
  `Option<OffsetDateTime>` via `time`, depending on which (if either) is
  already a workspace dependency. Needs a dependency audit in `/sdd plan`.]
- [NEEDS CLARIFICATION: Does the freshness signal apply only to the
  registry-reported "latest" version, or also to the version currently
  pinned/locked in the user's manifest or lockfile (relevant to
  `crates/deps-core/src/lockfile.rs` consumers)?]
- [NEEDS CLARIFICATION: Clamping/edge-case behavior for a publish timestamp
  in the future relative to local clock — suppress the signal entirely, or
  clamp to "just now"?]
- [NEEDS CLARIFICATION: For Swift packages hosted on non-GitHub Swift Package
  Registries (per the finding, "varies by host"), is a best-effort partial
  implementation (GitHub-hosted only) acceptable for v1, with other hosts
  falling back to US-003 graceful degradation?]
- [NEEDS CLARIFICATION: Should FR-007 (adding timestamp parsing to Cargo,
  npm, PyPI, Composer, Swift, NuGet) ship in the same PR as FR-008 (wiring
  already-parsed timestamps for Maven, Dart, Bundler, Go), or should this be
  split into two PRs — "wire what we already have" first, "add parsing where
  missing" second — to keep each PR reviewable? Recommend the split in
  `/sdd plan`.]
- [NEEDS CLARIFICATION: Interaction with the still-in-progress
  [[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]]
  spec — should a security-relevant version be exempted from cooldown
  softening, mirroring Dependabot's security-update exemption? Deferred as
  explicitly out of scope above, but flagged here in case `/sdd plan` for
  either feature wants to coordinate.]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec|OSV vulnerability diagnostics]] — related risk-signal spec, currently in `plan` phase
- [[003-maven-legacy-version-sort/spec|Maven/Gradle legacy version sort fix]] — already flags Maven's unused `timestamp` field as a candidate sort tiebreaker
- `crates/deps-core/src/registry.rs` — `Version` trait (`:135`), `find_latest_stable` (`:202`)
- `crates/deps-core/src/lsp_helpers.rs` — `generate_diagnostics`, `generate_diagnostics_from_cache`, `DiagnosticSeverity` assignment
- `crates/deps-core/src/completion.rs` — `build_version_completion`, `VersionDisplayItem`
- `crates/deps-maven/src/types.rs`, `crates/deps-dart/src/types.rs`, `crates/deps-bundler/src/types.rs`, `crates/deps-go/src/types.rs` — ecosystems that already parse a publish timestamp but discard it
- `.claude/rules/continuous-improvement.md` — live-testing principle and cross-ecosystem consistency gate
- [GitHub Changelog: Dependabot version updates introduce default package cooldown](https://github.blog/changelog/2026-07-14-dependabot-version-updates-introduce-default-package-cooldown/) — source of the 3-day default cooldown reference

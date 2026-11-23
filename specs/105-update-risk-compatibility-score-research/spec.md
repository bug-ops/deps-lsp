---
aliases:
  - Update risk and compatibility score research
  - Compatibility-score data source decision record
  - Issue 1121 research
tags:
  - sdd
  - spec
  - research
  - decision-record
  - deps-cli
  - deps-core
  - security
  - priority/p4
created: 2026-11-23
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[037-supply-chain-trust-signal/spec|037 Supply-chain trust signal]]"
  - "[[049-osv-malicious-package-severity/spec|049 OSV malicious-package severity]]"
  - "[[060-osv-informational-advisory-category/spec|060 OSV informational-advisory category]]"
  - "[[068-cli-update-subcommand/spec|068 deps-cli update subcommand]]"
  - "[[071-typosquat-similarity-diagnostic/spec|071 Typosquat similarity diagnostic]]"
  - "[[072-deps-dev-gossip-signals/spec|072 deps.dev GOSSIP signals]]"
  - "[[074-deps-cli-gossip-parity/spec|074 deps-cli GOSSIP parity]]"
  - "[[075-cli-update-cooldown-fallback/spec|075 Cooldown fallback]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec|076 Cooldown fallback (no lockfile)]]"
  - "[[099-honor-native-package-manager-cooldown/spec|099 Native package-manager cooldown]]"
  - "[[101-operator-advisory-exemptions/spec|101 Operator advisory exemptions]]"
  - "[[102-installer-level-cooldown-dart-swift/spec|102 Installer-level cooldown (Dart/Swift)]]"
  - "[[104-cli-update-open-pr/spec|104 deps-cli update --open-pr]]"
---

# Feature: Compatibility-score and advisory-based risk data source research (decision record)

> [!info] Metadata
> **Author**: researcher + sdd-orchestrator (research session, 2026-11-23)
> **Branch**: `feat/2135-gradle-drift-research`
> **Resolves**: #1121 ("Research: compatibility-score / advisory-based risk data source for automated updates")
> **Epic**: #1114 (`deps-cli` as a full Dependabot replacement — final open sub-issue; all 8 sibling sub-issues `#1115`–`#1120`, `#2072`, `#2073` are shipped)
> **Phase**: `specify` — research/decision-record, P4, spec is the artifact (no `/sdd plan`, no `/sdd tasks`, 0 open `[NEEDS CLARIFICATION]` items)
> **Provenance**: 2026-11-23 codebase audit at HEAD and external data-source survey (captured in full in §§5–6, §13)

> [!abstract]
> Issue #1121 investigates whether a keyless, public data source can supply Dependabot-style compatibility scores or advisory-based update risk assessments for `deps-cli update`. No drop-in keyless public replacement for crowdsourced CI pass/fail compatibility scores exists, and even GitHub's own Dependabot score returns `"unknown"` on 83% of updates. This decision record defers standalone compatibility-score implementation, closes #1121 and parent epic #1114, and captures a tiered categorical risk-profile blueprint (`Low` / `Medium` / `High` / `Unknown` + explicit factors) for any future risk-assessment work.

## 1. Overview

### Problem Statement

Parent epic #1114 tracks `deps-cli` parity with Dependabot for automated dependency updates. Eight of its nine sub-issues (`#1115`–`#1120`, `#2072`, `#2073`) have shipped across [[068-cli-update-subcommand/spec|spec 068]] and [[104-cli-update-open-pr/spec|spec 104]], covering `deps-cli update`, `--security-only`, `[update].ignore`, lockfile regeneration, `[update.groups]`, `--open-pr`, and `--close-superseded`. The sole remaining sub-issue, #1121, asks whether a public, keyless data source exists to provide Dependabot-like compatibility scores or advisory-based risk scoring before automated updates are applied or opened as pull requests.

Dependabot's compatibility score measures crowdsourced CI pass rates across public GitHub repositories:

$$\text{Score}(\text{pkg}, v_{\text{from}}, v_{\text{to}}) = \frac{\text{successful\_updates}}{\text{candidate\_updates}}$$

where a *candidate update* is a Dependabot PR on a public GitHub repository whose default branch had passing CI prior to the PR, and a *successful update* is one whose PR CI also passes. A minimum sample floor (historically $\ge 5$ candidate repositories) is required; otherwise Dependabot renders `"unknown"`.

Four structural facts govern this problem:

1. **No public GitHub API**: GitHub does not expose raw compatibility scores or sample counts via REST or GraphQL APIs (only rendered SVG badges historically served via `dependabot-badges.githubapp.com/badges/compatibility_score` inside Dependabot PR bodies).
2. **Empirical sparsity**: Rombaut, Cogo, & Hassan (*"Leveraging the Crowd for Dependency Management: An Empirical Study on the Dependabot Compatibility Score"*, IEEE TSE / arXiv) found **83%** of Dependabot updates result in `"unknown"` under the 5-candidate threshold across specific `(from, to)` pairs. Even with GitHub's global repository corpus, crowdsourced CI outcomes are unavailable for more than four in five updates.
3. **Structural impossibility for a local-first CLI**: Reproducing CI pass-rate telemetry requires harvesting CI outcomes across tens of thousands of downstream repositories. As a keyless, local-first, zero-telemetry tool, `deps-lsp` / `deps-cli` has neither a central telemetry backend nor permission to collect user CI results.
4. **Empirical SemVer breaking-change baseline**: Empirical studies across Maven, npm, and Cargo (Raemaekers et al., Van Deursen et al., Maracas/Ochoa et al.) show roughly 10%–33% of non-major (`minor` / `patch`) releases still introduce breaking changes (API removals, signature shifts, MSRV or runtime engine bumps, transitive cascades), while maintainers self-correct via yanks, deprecations, and rapid consecutive patch hotfix bursts.

### Goal

Provide a verified, evidence-backed decision on compatibility-score and update-risk data sources for `deps-cli update` — auditing existing `deps-core` / `deps-cli` signals, comparing public and commercial alternatives against project constraints, and recording a concrete tiered design blueprint — so #1121 and epic #1114 close cleanly without speculative implementation or future re-litigation.

### Decision

> [!important] Decision: Defer standalone compatibility-score implementation
> **Do not implement** a standalone compatibility-score integration or synthetic percentage score at this time. Close #1121 (and parent epic #1114) referencing this spec as the authoritative decision record.
>
> - **No keyless public source** replaces Dependabot's crowdsourced CI pass/fail compatibility score.
> - **Never synthesize a `0–100%` score** from SemVer bumps, Scorecard grades, or advisory counts — doing so conflates orthogonal risk axes (API breakage vs. supply-chain hygiene) and implies empirical CI validation that does not exist.
> - **`deps-cli update` already ships the highest-value keyless safety rails**: 3-day freshness cooldown, native package-manager cooldowns, opt-in GOSSIP dynamic cooldown, floor-protected cooldown fallback, OSV fail-closed target verification, `--security-only`, `[update].ignore`, `[update.groups]`, and `--open-pr`.
> - **When user demand or a Revisit Trigger fires**, implement a **categorical risk profile** (`Low` / `Medium` / `High` / `Unknown` + explicit `Vec<RiskFactor>`) starting with Tier 0 zero-network local heuristics across all 15 ecosystems, followed optionally by Tier 1 already-wired keyless `deps.dev` / `OSV.dev` signals under existing opt-in privacy gates.

### Out of Scope

- Any code changes under `crates/**`, `book/`, `README.md`, or `CHANGELOG.md` — this spec is a `specify`-only research and decision record (no `/sdd plan` or `/sdd tasks`).
- Implementing Tier 0 or Tier 1 risk-assessment features before a Revisit Trigger (§11) fires.
- Building a telemetry backend or harvesting user CI pass/fail results.
- Integrating API-key-gated or ToS-restricted commercial backends (Mend Renovate Merge Confidence, Socket.dev, Libraries.io) into `deps-lsp` / `deps-cli`'s keyless default.

## 2. User Stories

### US-001: Maintainer closes #1121 and epic #1114 without speculative code

AS A project maintainer reviewing the final open sub-issue of epic #1114
I WANT an evidence-backed decision record explaining why no keyless compatibility-score backend is adopted
SO THAT #1121 and #1114 can be closed cleanly and future sessions do not re-run the same market survey from scratch.

**Acceptance criteria:**
```
GIVEN issue #1121 and parent epic #1114
WHEN a maintainer reads this spec's Decision, Source Matrix, and Revisit Triggers
THEN they can confirm why implementation is deferred, verify all 8 sibling sub-issues are shipped,
     and identify the exact conditions that would re-open implementation.
```

### US-002: Future spec author designs `deps-cli update` risk assessment cleanly

AS A contributor or coding agent drafting a future risk-assessment feature if a Revisit Trigger fires
I WANT a verified baseline audit of existing `deps-core` / `deps-cli` capabilities and a tiered design blueprint
SO THAT future work reuses wired infrastructure, preserves 15-ecosystem uniformity, respects opt-in privacy boundaries, and never emits a misleading `0–100%` score.

**Acceptance criteria:**
```
GIVEN a Revisit Trigger in §11 has fired
WHEN a contributor starts a new feature spec for update risk assessment
THEN they can adopt the Tier 0 / Tier 1 / Tier 2 split, categorical UpdateRiskLevel model,
     and verified code entry points in §5 and §7 without re-auditing every crate.
```

### US-003: Reviewer audits findings against the live codebase

AS A reviewer verifying this decision record
I WANT every codebase claim tied to verified `file:line` references and every external data source judged against explicit project constraints
SO THAT conclusions can be audited independently without trusting assertions blindly.

**Acceptance criteria:**
```
GIVEN this spec
WHEN a reviewer checks the Verified Baseline Audit (§5) and Source Matrix (§6)
THEN every cited Rust type, endpoint, ecosystem count, and constraint matches HEAD,
     and no external source is cited with unverified capabilities or fabricated URLs.
```

## 3. Functional Requirements

These requirements govern both the research decision process today and any future specification triggered under §11.

### FR-001

WHEN a future session proposes adding a Dependabot-style compatibility score to `deps-cli` or `deps-lsp` THE SYSTEM (specification process) SHALL first evaluate the Revisit Triggers in §11 and, if none have fired, reference this decision record instead of re-deriving the data-source survey.

**Priority**: must

### FR-002

WHEN a future `deps-cli update` feature surfaces update risk THE SYSTEM SHALL represent risk as a categorical `UpdateRiskLevel` (`Low`, `Medium`, `High`, `Unknown`) paired with an explicit list of structured `RiskFactor` entries that separate `Compatibility` factors from `SupplyChain` factors, and SHALL NOT synthesize a single `0–100%` compatibility percentage.

**Priority**: must

### FR-003

WHEN evaluating update risk across the 15 supported `EcosystemId` variants THE SYSTEM SHALL place shared risk logic in `deps-core`, match `EcosystemId` exhaustively per [[constitution]] Principle 2, and report missing ecosystem signals as `Unknown` or explicit partial coverage rather than collapsing unavailable data into `Low` risk.

**Priority**: must

### FR-004

WHEN implementing update risk assessment for the first time THE SYSTEM SHALL deliver Tier 0 zero-network local heuristics (pre-1.0-aware bump severity, hotfix-burst and yank-cluster detection, cooldown status, and local lockfile-diff churn) before introducing any new third-party network dependencies.

**Priority**: must

### FR-005

WHEN a future Tier 1 risk feature queries third-party APIs beyond the package's own registry (`deps.dev` or any future external provider) across a manifest THE SYSTEM SHALL gate the feature behind opt-in configuration (`enabled = false` by default), enforce `DepsDevScope` / `source_is_public_registry_content` so private, git, and path dependencies are never disclosed, and use batch endpoints (`POST /v3alpha/findingsbatch`, `POST /v3alpha/projectbatch`) rather than N+1 per-dependency requests.

**Priority**: must

### FR-006

WHEN a future `--max-risk` / `[update].max_risk` filter is introduced on `deps-cli update` THE SYSTEM SHALL exempt `--security-only` mode from risk gating so vulnerability remediations retain precedence over non-security risk filters (matching existing `[update].ignore` and cooldown precedence in [[068-cli-update-subcommand/spec|spec 068]]).

**Priority**: should

## 4. Non-Functional Requirements

### NFR-SEC-001

**Keyless default and zero telemetry**: Core `deps-cli update` risk assessment SHALL require zero API keys, zero paid accounts, and zero outbound user CI telemetry. Any optional bulk metadata query to a third-party service MUST remain opt-in (`enabled = false` by default) and MUST NOT leak private, internal, path, or git dependency names (`DepsDevScope::target`, `crates/deps-core/src/deps_dev/mod.rs:329-338`).

### NFR-REL-001

**Offline safety and explicit degradation**: Tier 0 local risk heuristics SHALL operate identically under `--offline` using already-cached `PackageVersions` and local lockfiles. Tier 1 network failures or uncovered ecosystems MUST degrade explicitly to `Unknown` / partial-coverage attribution (mirroring `FetchCompleteness` and `LatestVerdict::Unverified`), never silently to `Low`.

### NFR-PERF-001

**Bounded network fan-out**: Any future Tier 1 CLI enrichment SHALL reuse `HttpCache` transport with batch endpoints and bounded memo/timeout controls matching `DepsDevClient` (`DEPS_DEV_SUCCESS_TTL = 1h`, `DEPS_DEV_ERROR_TTL = 90s`, `MAX_MEMO_ENTRIES = 512`, `crates/deps-core/src/deps_dev/mod.rs:92-102`) and `OsvClient` (`BATCH_CHUNK_SIZE = 1000`, `RECORD_FETCH_CONCURRENCY = 10`, `crates/deps-core/src/osv/mod.rs:123-138`).

### NFR-POR-001

**15-ecosystem uniformity**: Shared risk classification and heuristic engines SHALL live in `deps-core` per [[constitution]] Principle 1 ("One fix, one place"), with zero `tower-lsp-server` leakage into `deps-cli` ([[064-deps-cli-lsp-isolation/spec|spec 064]]).

## 5. Verified Baseline Audit (HEAD)

All references below were verified against the repository at HEAD during the 2026-11-23 research pass.

### Supported Ecosystems

`EcosystemId` (`crates/deps-core/src/ecosystem.rs:248-279`) defines **15 variants**: `Cargo`, `Npm`, `Pypi`, `Go`, `Bundler`, `Dart`, `Maven`, `Composer`, `Gradle`, `Swift`, `NuGet`, `Deno`, `GithubActions`, `GitlabCi`, `PreCommit`.

### A. `deps.dev` Client (`crates/deps-core/src/deps_dev/mod.rs`, `types.rs`)

- **Ecosystem coverage** (`deps_dev_system`, `crates/deps-core/src/deps_dev/mod.rs:288-305`): **8 of 15** `EcosystemId`s mapped to 7 `DepsDevSystem`s (`Npm`, `Cargo`, `Go`, `Maven | Gradle -> Maven` per [[080-gradle-deps-dev-maven-system-routing/spec|spec 080]], `Pypi`, `Bundler -> Rubygems`, `NuGet`). Excluded (**7 of 15**): `Composer`, `Dart`, `Swift`, `Deno` (even for `npm:` specifiers), `GithubActions`, `GitlabCi`, `PreCommit`.
- **Transport, caching, and privacy gate** (`DepsDevScope`, `crates/deps-core/src/deps_dev/mod.rs:314-384`): Keyless over `HttpCache` transport-only (deps.dev does not emit `ETag`/`Last-Modified`); `1h` success TTL (`DEPS_DEV_SUCCESS_TTL`, `mod.rs:92`), `90s` degraded TTL (`DEPS_DEV_ERROR_TTL`, `mod.rs:97`), 512-entry memos (`MAX_MEMO_ENTRIES`, `mod.rs:102`). `DepsDevScope` enforces online mode, `formatter.source_is_public_registry_content` (private/git/path names are never sent), and unexpanded template rejection.
- **6 endpoints already wired**:
  1. `GET /v3/systems/{sys}/packages/{pkg}/versions/{ver}` (`mod.rs:905-911`, `types.rs:15-27`, [[037-supply-chain-trust-signal/spec|spec 037]]): parses `slsaProvenances[]`, `attestations[]`, `relatedProjects[]` (preferring `SLSA_ATTESTATION` over `UNVERIFIED_METADATA`), and `licenses[]`. Unparsed fields already returned in the JSON payload: `publishedAt`, `isDeprecated`, `advisoryKeys[]`, `links[]`, `registries[]`.
  2. `GET /v3/projects/{key}` (`mod.rs:969-973`, `types.rs:56-72`, spec 037): parses `scorecard.overallScore` (`Option<f32>`) only. Unparsed fields already returned: `scorecard.checks[]` (individual OpenSSF Scorecard checks such as `CI-Tests`, `Maintained`, `Vulnerabilities`, `Code-Review`, `Branch-Protection`), `scorecard.date`, `starsCount`, `forksCount`, `openIssuesCount`, `description`, `licenses` (array), `archived` (boolean).
  3. `GET /v3alpha/systems/{sys}/packages/{pkg}:similarlyNamedPackages` (`mod.rs:1107-1112`, [[071-typosquat-similarity-diagnostic/spec|spec 071]]): typosquat candidates, capped at 5. Opt-in (`TyposquatConfig`, `enabled: false`, `crates/deps-core/src/policy_config.rs:2230-2250`).
  4. `GET /v3alpha/systems/{sys}/packages/{pkg}` (`mod.rs:1176-1181`, `types.rs:102-115`, spec 071): parses `versions[].versionKey.version` and `isDefault` only. Unparsed: per-version `publishedAt` and full version timeline.
  5. `GET /v3alpha/systems/{sys}/packages/{pkg}/versions/{ver}:dependents` (`mod.rs:1208-1214`, `types.rs:129-132`, spec 071): parses `dependentCount` only (ignoring `directDependentCount`, `indirectDependentCount`), used solely for typosquat 50x ratio gating on `defaultVersion`.
  6. `POST /v3alpha/findingsbatch` and `GET /v3alpha/.../versions/{ver}:findings` (`mod.rs:1474`, `mod.rs:1571-1599`, `types.rs:153-325`, [[072-deps-dev-gossip-signals/spec|spec 072]] & [[074-deps-cli-gossip-parity/spec|spec 074]]): GOSSIP batch and version-scoped signals. Opt-in (`GossipConfig`, `enabled: false`, `crates/deps-core/src/policy_config.rs:2282-2302`). Parses `COOLDOWN` (`cooldownContext.end` plus fallback `cooldownEnd`) and `LOW_USAGE` (`lowUsageContext.alternativePackages`). The remaining 5 of GOSSIP's 7 documented `FindingType` values (`NOT_FOUND`, `MALICIOUS`, `DEPRECATED`, `VULNERABLE`, `REMEDIATION` — abandoned/archived packages surface under `DEPRECATED`, while `archived` itself is a boolean on `GetProject`) collapse into `GossipFindingType::Other` (`types.rs:294-306`, spec 072 §5).
- **CLI wiring gap**: `DepsDevClient::trust_signal()` (Scorecard + SLSA) is wired only in `deps-lsp` hover (`SupplyChainConfig`, `enabled: true` by default, `crates/deps-core/src/policy_config.rs:1496-1528`), **not** in `deps-cli` (`AnalysisScope`, `crates/deps-cli/src/analyze.rs:77-149`). Default `deps-cli update` runs registry fetch, OSV latest-check, opt-in GOSSIP, and cooldown-fallback OSV verification.

### B. `OSV.dev` Client (`crates/deps-core/src/osv/`)

- **Ecosystem coverage** (`EcosystemId::osv_ecosystem`, `crates/deps-core/src/ecosystem.rs:307-327`): **13 of 15** `EcosystemId`s via 11 `OsvEcosystem`s (`crates.io`, `npm` shared by `Npm | Deno`, `PyPI`, `Go`, `RubyGems`, `Pub`, `Maven` shared by `Maven | Gradle`, `Packagist`, `SwiftURL`, `NuGet`, `GitHub Actions`). Excluded (**2 of 15**): `GitlabCi`, `PreCommit`.
- **Endpoints and caching** (`crates/deps-core/src/osv/mod.rs:109-143`): `POST /v1/querybatch` (`BATCH_CHUNK_SIZE = 1000`), `POST /v1/query` truncation fallback (`MAX_TRUNCATED_REQUERY_BUDGET = 20`), `GET /v1/vulns/{id}` (`QUERY_CACHE_TTL = 6h`, `MAX_ADVISORY_RECORDS = 50`, `RECORD_FETCH_CONCURRENCY = 10`, `MAX_CACHE_ENTRIES = 10_000`).
- **Severity classification** (`crates/deps-core/src/osv/severity.rs:104-146`):
  - `VulnSeverity::Malicious` for `MAL-*` ID or alias ([[049-osv-malicious-package-severity/spec|spec 049]], taking precedence over graded severity).
  - Graded `Critical` / `High` / `Medium` / `Low` from `database_specific.severity` and `ecosystem_specific.severity`.
  - `VulnSeverity::Informational` strictly for `affected[].database_specific.informational == "unmaintained"` on the matching package ([[060-osv-informational-advisory-category/spec|spec 060]]; `"unsound"` and `"notice"` remain `Unknown`).
- **Target verification**: `recommended_fix()` and `check_candidates()` verify update targets before edits are written (`LatestStatusMap`, `fallback_status`, `--security-only` phase-B re-verification).

### C. `deps-cli update` Existing Risk and Safety Controls

- **Freshness cooldown**: `DEFAULT_COOLDOWN_SECS = 3 days` (`crates/deps-core/src/freshness.rs:15`, enabled by default, `--cooldown` override up to 30d); GOSSIP dynamic cooldown authoritative when opted in (specs 072, 074); native package-manager cooldowns honored for Cargo, npm, pnpm, Yarn, Bun, and uv, with Dart and Swift verified to have no native gate as of 2026-11-17 ([[099-honor-native-package-manager-cooldown/spec|spec 099]], [[102-installer-level-cooldown-dart-swift/spec|spec 102]]).
- **Cooldown fallback**: selects the newest cooled-down, OSV-verified, floor-protected version ([[075-cli-update-cooldown-fallback/spec|spec 075]], [[076-cli-update-cooldown-fallback-no-lockfile/spec|spec 076]]).
- **OSV target-safety gate**: default `update` refuses to write `Flagged` or `Unverified` targets (`crates/deps-cli/src/analyze.rs:132-149`); `--security-only` (`plan_security_updates`, `crates/deps-cli/src/update/security.rs:103`) targets `recommended_fix()`, re-verifies against OSV, filters yanked fixes, overrides `[update].ignore`, and guards lockfile regeneration against cooldown-held versions (`crates/deps-cli/src/update/mod.rs:219-261`, spec 068).
- **SemVer bump classification** (`deps_core::edit::classify_update`, `crates/deps-core/src/edit.rs:479-534`): classifies `Major` / `Minor` / `Patch` / `Unknown` via leading dotted-numeric segments while rejecting Go pseudo-versions. Used by `[update].ignore`, `[update.groups.<name>]`, and `--open-pr` PR body tables (`| Package | From | To | Kind |`, `crates/deps-cli/src/update/pr/mod.rs:1223-1241`, spec 104).
  - **Verified gap for future risk assessment**: `classify_update("0.4.0", "0.5.0")` returns `UpdateKind::Minor` (`f.0 == t.0 == 0`, `f.1 != t.1` at `crates/deps-core/src/edit.rs:524-530`), not breaking/major — even though SemVer 2.0.0 §4 and Cargo/npm caret semantics treat `0.x -> 0.y` (and `0.0.x -> 0.0.y`) as potentially breaking.
- **Registry version metadata already in `PackageVersions`** (`crates/deps-core/src/lsp_helpers/mod.rs:919-970`): carries `latest`, `available` (all published versions newest-first), `yanked: Arc<[(ConcreteVersion, RemovalStatus)]>`, `published_at`, and `publish_times` (per-version timestamps aligned with `available`).
  - `Registry::reports_yanked()` (`crates/deps-core/src/registry.rs:512`): `true` on **6 of 15** ecosystems (`Cargo`, `Npm` [advisory deprecated], `Pypi`, `Dart`, `Deno`, `Swift` [SE-0292 registry releases with `problem` at `crates/deps-swift/src/registry.rs:630-634`; GitHub tags path yields only `Available`]); `false` on **9 of 15** (`Bundler`, `Composer` [package-level abandoned only], `Go`, `Maven`, `Gradle`, `NuGet`, `GithubActions`, `GitlabCi`, `PreCommit`).
  - `Version::published_at()`: wired in **15 of 15** ecosystems across 13 registry implementations (`Gradle` shares `Maven`, and `PreCommit` shares `GithubActions` GitHub Releases); some registries require an extra fetch gated on freshness/demand (Cargo crates.io API, npm full packument, Maven/Gradle Central Search, NuGet registration, Swift/GitHub Actions Releases).

## 6. Comparative Data Source Matrix

### Candidate Signals and External Providers

| Source / Signal | Endpoint / Mechanism | Auth / ToS | Ecosystem Coverage (of 15) | Signal Type | Wired Today? | Key Limitations |
|---|---|---|---|---|---|---|
| **Local: SemVer + Pre-1.0 magnitude** | `deps_core::edit::classify_update` + pre-1.0 rule (`0.x`/`0.0.x`) + prerelease delta | None (offline) | **15/15** (partial on non-semver pins/SHAs) | Breaking-change prior | Partial (`0.x` gap) | Misses 10%–33% non-major breaking changes; `Unknown` on SHA/pseudo-versions |
| **Local: Release age / Cooldown** | `PackageVersions::{published_at, publish_times}` + native cooldowns | None (offline from cache) | **15/15** (13 registry implementations; extra fetch on some) | Release maturity / supply-chain soak time | **Yes** (specs 004, 075, 076, 099, 102) | Measures age, not API compatibility; some registries need extra fetch |
| **Local: Hotfix-burst & yank-cluster velocity** | Pure analysis over already-fetched `PackageVersions::{available, publish_times, yanked}` | None (offline) | **15/15** for burst; **6/15** for yank status | Regression / unstable release-line proxy | **No** (0 extra HTTP) | Cannot detect a brand-new broken release before its first hotfix/yank; uneven `reports_yanked()` coverage |
| **Local: Lockfile-diff transitive churn** | Compare pre- vs. post-`--lockfile regenerate` resolved graph (`LockFileProvider`) | None (offline / local tool) | **11/15** (ecosystems with lockfiles + regen) | Transitive blast radius / dependency graph delta | **No** (lockfile parsers exist) | Only available when `--lockfile regenerate` runs (not `--dry-run` or lockfile-less manifests) |
| **deps.dev `GetProject` / `GetProjectBatch`** | `GET /v3/projects/{key}` / `POST /v3alpha/projectbatch` (OpenSSF Scorecard checks) | Keyless (free) | **8/15** (`npm`, `cargo`, `go`, `maven`, `gradle`, `pypi`, `bundler`, `nuget`) | Upstream quality/hygiene (`CI-Tests`, `Maintained`, `Vulnerabilities`, `archived`) | Partial (LSP hover `overallScore` only; not CLI; not individual checks) | Repo-level security hygiene, not per-version compatibility; no historical trends; requires opt-in privacy gate for bulk CLI calls |
| **deps.dev `GetFindingsBatch` (GOSSIP)** | `POST /v3alpha/findingsbatch` (up to 5,000/batch) | Keyless (free) | **8/15** (same 7 systems) | Dynamic `COOLDOWN`, `LOW_USAGE`, `DEPRECATED`, `VULNERABLE`, `MALICIOUS`, `REMEDIATION`, `NOT_FOUND` | Partial (`COOLDOWN`/`LOW_USAGE` wired; `DEPRECATED` and other 4 dropped into `Other`) | Opt-in (`[gossip].enabled = false`); `v3alpha` stability; security/supply-chain focus, not API breakage |
| **deps.dev `GetDependents`** | `GET /v3alpha/.../versions/{ver}:dependents` (`dependentCount`, direct/indirect) | Keyless (free) | **5/15** (`npm`, `cargo`, `maven`+`gradle`, `pypi` — 4 systems only) | Version adoption proxy (cf. Renovate "Adoption") | Partial (wired for typosquat on `defaultVersion` only) | Tracks published packages only (not private/app repos); indexing lag makes fresh releases look unadopted; 10/15 ecosystems uncovered |
| **deps.dev `GetDependencies`** | `GET /v3/.../versions/{ver}:dependencies` | Keyless (free) | **5/15** (`npm`, `cargo`, `maven`+`gradle`, `pypi` — 4 systems only) | Remote transitive dep graph delta (`from` vs. `to`) | **No** | 2 GETs per dependency; Linux `x86_64` generic resolution; redundant when `--lockfile regenerate` runs locally |
| **OSV.dev API v1** | `POST /v1/querybatch`, `GET /v1/vulns/{id}` | Keyless (free) | **13/15** (all except `gitlab-ci`, `pre-commit`) | Active CVEs, `MAL-*`, `unmaintained`, verified fix targets | **Yes** (specs 002, 049, 060, 068) | Security advisories, not API compatibility; raw historical advisory count suffers from streetlight bias on popular packages |
| **OpenSSF Scorecard REST API** | `GET /projects/{platform}/{org}/{repo}` on `api.scorecard.dev` | Keyless (free) | GitHub/GitLab/Bitbucket repos (useful for `github-actions`, `pre-commit`, `swift`) | 18 security checks (`CI-Tests`, `Maintained`, etc.) | **No** (consumed via deps.dev) | Latest snapshot only — no historical trends via REST (BigQuery `openssf:scorecardcron` requires GCP auth and faces deprecation/shifts); redundant with deps.dev for 8/15 ecosystems |
| **Ecosyste.ms (`packages` + `repos`)** | `packages.ecosyste.ms/api/v1/...`, `repos.ecosyste.ms/api/v1/...` | Keyless (Polite pool `mailto:` ~15k req/hr; Common ~5k/hr) | **12+/15** (adds `packagist`, `pub.dev`, `swift`, `jsr` beyond deps.dev) | Dependents, downloads, archived status, mirrored GitHub/GitLab releases & changelogs | **No** | Community-run infrastructure (no enterprise SLA); bulk package-name disclosure requires opt-in privacy gate; unstructured release-note text |
| **GitHub Releases / Raw `CHANGELOG.md`** | `api.github.com/repos/{owner}/{repo}/releases` | Keyless **60 req/hr** (5,000/hr w/ `GITHUB_TOKEN`) | GitHub-hosted packages | `BREAKING CHANGE` / migration-note text cues | Partial (`GithubTagsClient` for tags/dates only) | Unusable keyless at manifest scale (60 req/hr exhausted by one medium manifest); regex keyword matching has high false-positive/negative noise |
| **Renovate Merge Confidence (Mend)** | `developer.mend.io/api/mc/` | **Proprietary / ToS-restricted** | ~7 major ecosystems | Crowdsourced Age, Adoption, Passing, Confidence | **No (Ruled Out)** | Closed commercial backend; ToS prohibits unauthorized programmatic scraping or third-party CLI consumption |
| **Socket.dev API** | REST API (`Authorization: Bearer <key>`, `/purl`, `/quota`) | **API key + quota/billing** (`402`/`429`) | ~6 ecosystems (`npm`, `pypi`, `go`, `maven`, `rubygems`, `cargo`) | 70+ supply-chain malice/hygiene alerts | **No (Ruled Out)** | Violates keyless-default constraint; measures supply-chain risk rather than API compatibility |
| **Libraries.io** | `libraries.io/api/...?api_key=...` | **API key required** (60 req/min) | Broad | Dependents, SourceRank | **No (Ruled Out)** | Requires API key, tight rate limit, stale metadata; strictly dominated by `deps.dev` + Ecosyste.ms |

### Evaluation Against `deps-lsp` / `deps-cli` Architectural Constraints

1. **Keyless default**: Eliminates Mend Merge Confidence, Socket.dev, Libraries.io, GCP BigQuery Scorecard history, and unauthenticated per-dependency GitHub Releases scanning.
2. **15-ecosystem uniformity ([[constitution]] Principles 1–2)**: Shared logic belongs in `deps-core` with exhaustive `EcosystemId` matching and explicit `Unknown` / partial-coverage reporting. Missing coverage on an ecosystem must never silently render as `Low` risk.
3. **Privacy / zero telemetry**: Matching `TyposquatConfig` (`policy_config.rs:2230`) and `GossipConfig` (`policy_config.rs:2282`), any bulk per-manifest query to a third party beyond the package's own registry must be opt-in (`enabled = false` by default) and gated by `source_is_public_registry_content`.
4. **Offline safety (`--offline`)**: Tier 0 local heuristics rely solely on cached `PackageVersions` and local lockfiles with zero network I/O.
5. **Rate-limit and latency budget**: Any Tier 1 CLI enrichment must use batch endpoints over `HttpCache`, never N+1 per-dependency GETs.
6. **Orthogonal risk axes**: Conflating *API compatibility risk* ("will my build or tests break?") with *supply-chain/security posture* ("is this repo maintained, tested, and CVE-free?") into a single opaque number misleads operators (e.g., a security-patch bump on a low-Scorecard repo vs. a breaking major bump on a 9.5-Scorecard repo).

## 7. Tiered Risk-Profile Blueprint (Deferred Future Design)

If a Revisit Trigger (§11) fires, future implementation should follow this tiered blueprint rather than attempting to emulate a Dependabot percentage badge.

### Domain Representation (Target Shape)

- Categorical `UpdateRiskLevel::{Low, Medium, High, Unknown}` paired with `Vec<RiskFactor>`.
- Each `RiskFactor` tags its axis (`Compatibility` vs. `SupplyChain`), machine-readable kind, and human-readable explanation.
- Never collapse heterogeneous factors into a synthetic `0–100%` score.

### Tier 0 — Zero-Network Local Heuristics (Ship First; 15/15 Ecosystems)

Operates offline with zero privacy cost and zero extra HTTP requests:

1. **Pre-1.0-aware bump severity**: extend bump risk classification beyond `classify_update` (`crates/deps-core/src/edit.rs:518-534`) so `0.x -> 0.y`, `0.0.x -> 0.0.y`, and prerelease transitions are flagged as breaking/elevated rather than routine post-1.0 `Minor`/`Patch`.
2. **Hotfix-burst and yank-cluster detector**: pure function over already-fetched `PackageVersions::{available, publish_times, yanked}` (`crates/deps-core/src/lsp_helpers/mod.rs:919-970`) flagging rapid consecutive patches (e.g., $\ge 2$ patches within 72 hours on the target minor line), recently yanked sibling versions (where `Registry::reports_yanked()` is `true`), or wide multi-minor/multi-major jumps.
3. **Cooldown / freshness status**: surface already-computed local freshness, GOSSIP dynamic cooldown, and native package-manager cooldown state.
4. **Local lockfile-diff transitive churn**: when `--lockfile regenerate` executes, diff pre- vs. post-regeneration lockfile snapshots (`LockFileProvider`) to report transitive package additions, removals, and major jumps (11/15 ecosystems with lockfile regeneration).

### Tier 1 — Opt-In Network Enrichment (Reuse Wired Keyless Clients)

Strictly opt-in under existing `DepsDevScope` / `source_is_public_registry_content` privacy gates:

1. **OSV status**: already wired (fail-closed target verification plus `MAL-*` and `unmaintained` severity classification).
2. **GOSSIP `DEPRECATED`** (covers deprecated, abandoned, and archived packages in GOSSIP): deserialize alongside already-fetched `COOLDOWN` and `LOW_USAGE` from `POST /v3alpha/findingsbatch` (`crates/deps-core/src/deps_dev/types.rs:294-306`) at zero extra HTTP cost.
3. **Project `archived` flag and Scorecard `CI-Tests` / `Maintained` checks**: widen `DepsDevProject` and `DepsDevScorecardWire` (`crates/deps-core/src/deps_dev/types.rs:56-72`) to read `GetProject.archived` and individual Scorecard checks, and add `POST /v3alpha/projectbatch` (opt-in) as explicitly labeled repo-level maintenance and security/CI hygiene context, never as per-version API compatibility.
4. **Version adoption ratio via `GetDependents` (optional, 5/15 ecosystems only)**: compare `dependentCount(target)` vs. `dependentCount(current)` only for versions aged $\ge 14$ days (mitigating indexing lag); report `N/A` on the remaining 10/15 ecosystems.

### Tier 2 — Parked / Rejected

- **Ecosyste.ms (`packages` / `repos`)**: parked; revisit only if users specifically request Composer/Dart/Swift/JSR adoption signals or mirrored release-note links in `--open-pr` pull request bodies (and behind an opt-in privacy gate).
- **GitHub Releases / `CHANGELOG.md` text scanning**: parked; if ever added, restrict strictly to optional human-readable PR-body excerpts when `GITHUB_TOKEN` (or Ecosyste.ms) is configured — never as an automated risk gate.
- **Commercial / API-key backends** (Mend Merge Confidence, Socket.dev, Libraries.io): permanently rejected for `deps-lsp` / `deps-cli`'s keyless default.

### Future CLI and PR Integration Surface

When triggered, risk output would extend existing `deps-cli update` surfaces additively:

- `--format json` (`UpdateItemDocument`, `crates/deps-cli/src/format/json.rs:288`) and `--format table`: additive `risk` (`low` / `medium` / `high` / `unknown`) and `risk_factors[]` fields derived from `PlannedUpdateItem` (`crates/deps-cli/src/update/mod.rs:159`).
- `--open-pr` PR body (`body_for`, `crates/deps-cli/src/update/pr/mod.rs:1223-1241`): optional `Risk` column or collapsible factor summary per updated package.
- Optional `--max-risk low|medium|high` CLI flag / `[update].max_risk` config key, with `--security-only` exempt per FR-006.

## 8. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|---|---|
| Ecosystem is not covered by `deps.dev` (7/15) or `GetDependents` (10/15) | Tier 1 signals report explicit `N/A` / partial coverage; overall `UpdateRiskLevel` uses Tier 0 factors or `Unknown`, never silently downgraded to `Low` |
| Dependency comes from a private registry, git URL, or local path | `DepsDevScope::target` excludes it from all third-party queries; only Tier 0 local heuristics apply |
| `deps-cli update --offline` is active | Tier 1 queries are skipped without error; Tier 0 local heuristics run from cached metadata |
| Non-semver version pin (Git SHA, Go pseudo-version, wildcard, custom tag) | `classify_update` yields `Unknown`; risk level stays `Unknown` unless a concrete factor (e.g., cooldown or yank) applies |
| Brand-new broken patch release with no hotfix or yank yet | Hotfix-burst detector cannot see future patches; existing 3-day freshness cooldown and opt-in GOSSIP cooldown remain the primary defense |
| `--security-only` update carries a `High` compatibility risk (e.g., major bump required to fix CVE) | Security remediation is never blocked by `--max-risk` (FR-006); risk factors are still surfaced transparently for reviewer awareness |

## 9. Success Criteria

| ID | Metric | Target |
|---|---|---|
| SC-001 | Closure of #1121 and parent epic #1114 | Both issues close cleanly referencing this spec, with zero speculative code PRs opened |
| SC-002 | Prevention of misleading compatibility scores | 0 implementations synthesizing a `0–100%` compatibility score from non-CI signals |
| SC-003 | Re-evaluation efficiency | A future session decides whether to re-open risk-assessment implementation directly from §11 without re-auditing external providers or `deps-core` wiring |

## 10. Agent Boundaries

### Always (without asking)

- Reference this spec when #1121, Dependabot compatibility scores, or external risk-score APIs resurface and no Revisit Trigger (§11) has fired.
- Re-verify `file:line` citations and `EcosystemId` coverage counts against HEAD before starting any future implementation spec.

### Ask First

- Opening a new implementation spec for Tier 0 / Tier 1 risk profiles before a Revisit Trigger (§11) occurs.
- Adding any new third-party API host (such as Ecosyste.ms) to `deps-core` or widening opt-in privacy disclosures.

### Never

- Synthesize a `0–100%` Dependabot-style compatibility percentage without real CI pass/fail sample data.
- Scrape or call ToS-restricted commercial endpoints (Mend Merge Confidence) or add API-key-required backends (Socket.dev, Libraries.io) to the keyless default path.
- Send private, internal, git, or path dependency names to third-party services (`deps.dev`, Ecosyste.ms, Scorecard).
- Modify `crates/**`, `book/`, `README.md`, or `CHANGELOG.md` as part of this decision record.

## 11. Revisit Triggers

Re-open implementation under a new numbered feature spec only if **any** of the following triggers occur:

1. **deps.dev GOSSIP expansion**: `deps.dev` introduces a verified compatibility or API-breakage finding type in GOSSIP (`GetFindingsBatch`).
2. **Open crowdsourced CI feed**: OpenSSF, OSV, or an equivalent open initiative launches a keyless, public crowdsourced build/test-pass feed with non-restrictive ToS.
3. **Concrete user or maintainer demand**: Maintainers or users specifically request `--max-risk` gating or PR risk-factor annotations on `deps-cli update --open-pr`, triggering a Tier 0 (and optionally Tier 1) implementation spec using the §7 blueprint.

## 12. Open Questions

None — all research questions from #1121 are resolved with verified codebase evidence and zero open `[NEEDS CLARIFICATION]` markers. This decision record is ready to close #1121 and parent epic #1114 directly.

## 13. References and External URL Note

> [!note] External URL convention
> Per repository and Obsidian formatting conventions, all external links below use `[text](url)` Markdown syntax (no bare URLs), cite only sources verified during the 2026-11-23 research pass, and keep non-browseable API path templates as inline code spans.

- Empirical Dependabot compatibility-score study: Rombaut, Cogo, & Hassan, *"Leveraging the Crowd for Dependency Management: An Empirical Study on the Dependabot Compatibility Score"* (IEEE TSE / arXiv; documents the 83% `"unknown"` rate under the 5-candidate threshold).
- [deps.dev API v3 documentation](https://docs.deps.dev/api/v3/) and [deps.dev API v3alpha documentation](https://docs.deps.dev/api/v3alpha/).
- [deps.dev GOSSIP announcement](https://blog.deps.dev/gossip/) (2026-06-09).
- [OSV.dev API v1 documentation](https://google.github.io/osv.dev/api/).
- OpenSSF Scorecard REST API: `https://api.scorecard.dev/projects/{platform}/{org}/{repo}` (transitioned from `api.securityscorecards.dev`).
- [Ecosyste.ms Packages API](https://packages.ecosyste.ms/api/v1) and [Ecosyste.ms Repos API](https://repos.ecosyste.ms/api/v1).
- [Mend Renovate Merge Confidence documentation](https://docs.renovatebot.com/merge-confidence/) (proprietary backend `developer.mend.io/api/mc/`).
- [Socket.dev API reference](https://docs.socket.dev/reference) (Bearer auth and quota billing).

## 14. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[037-supply-chain-trust-signal/spec|037]] — OpenSSF Scorecard + SLSA provenance via `deps.dev`
- [[049-osv-malicious-package-severity/spec|049]] — OSV `MAL-*` malicious-package severity
- [[060-osv-informational-advisory-category/spec|060]] — OSV `unmaintained` informational-advisory category
- [[068-cli-update-subcommand/spec|068]] — `deps-cli update` subcommand (`#1115`, `#1119`, `#1120`)
- [[071-typosquat-similarity-diagnostic/spec|071]] — typosquat detection via `deps.dev`
- [[072-deps-dev-gossip-signals/spec|072]] — `deps.dev` GOSSIP cooldown and low-usage signals
- [[074-deps-cli-gossip-parity/spec|074]] — `deps-cli` GOSSIP parity
- [[075-cli-update-cooldown-fallback/spec|075]] & [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] — freshness-cooldown fallback
- [[099-honor-native-package-manager-cooldown/spec|099]] & [[102-installer-level-cooldown-dart-swift/spec|102]] — native package-manager cooldowns
- [[101-operator-advisory-exemptions/spec|101]] — operator-controlled advisory exemptions
- [[104-cli-update-open-pr/spec|104]] — `deps-cli update --open-pr` and `[update.groups]` (`#1117`, `#1118`, `#2072`, `#2073`)

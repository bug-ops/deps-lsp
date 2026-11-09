---
aliases:
  - Honor native package-manager cooldown
  - Native release-age gate
tags:
  - sdd
  - spec
  - research
  - parity
  - cross-ecosystem
  - ecosystem/cargo
  - ecosystem/npm
  - ecosystem/pypi
  - deps-core
  - priority/p3
created: 2026-11-09
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[004-release-freshness-signal/spec|004 Release freshness signal]]"
  - "[[020-freshness-cooldown-diagnostics-blind/spec|020 Freshness cooldown diagnostics]]"
  - "[[075-cli-update-cooldown-fallback/spec|075 CLI update cooldown fallback]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec|076 CLI update cooldown fallback, no lockfile]]"
  - "[[072-deps-dev-gossip-signals/spec|072 deps.dev GOSSIP signals]]"
  - "[[094-lsp-per-package-diagnostic-suppression/spec|094 Per-package diagnostic suppression]]"
---

# Feature: Honor the project's native package-manager release-age configuration

> [!info] Metadata
> **Author**: sdd (research/parity finding, live evidence 2026-11-09, HEAD 971ae08ae)
> **Type / priority**: research / parity (enhancement), P3, cross-ecosystem (`deps-core`, `deps-cargo`, `deps-npm`, `deps-pypi`, `deps-cli`)
> **Issue**: to be filed (labels `enhancement`, `research`, `P3`, `cross-ecosystem`)
> **Related issues**: #1569 (open, P4: installer-level cooldown for auto-following ecosystems), #1964 (untrusted-repository config must not hide advisories)
> **Phase**: specify. Open `[NEEDS CLARIFICATION]`: 8.

> [!abstract]
> deps-lsp's freshness signal (hover "recently published" callout, diagnostics, update code actions, `deps-cli update` fallback) is driven only by `freshness.cooldown_secs` (default 3 days). Since 2025-2026 every major package manager ships its own release-age gate (Cargo `min-publish-age`, npm `min-release-age`, pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`, Bun `minimumReleaseAge`, uv `exclude-newer`), but deps-lsp never reads them. The editor can therefore recommend a version the project's own resolver will refuse. This spec makes the native window an input to the effective freshness window, explains the reason in the UI, and keeps the untrusted-repository threat model intact: a native window may delay a recommended upgrade, but never hides a vulnerability diagnostic.

## 1. Overview

### Problem Statement

Live evidence (2026-11-09, `./target/debug/deps-lsp` driven through `.local/testing/lsp_test.py`):

- Scratch project with `Cargo.toml` `rmcp = "=3.8.0"` and `.cargo/config.toml` containing `[registry] global-min-publish-age = "7 days"`.
- rmcp 3.9.0 was published 2026-11-05, about 3.9 days earlier, inside the 7-day window. Cargo 1.100 or newer with `incompatible-publish-age = "deny"` (the default) ignores it.
- deps-lsp output: hover `Latest: 3.9.0 (published 3 days ago)` with no cooldown caveat; diagnostic `Newer version available: 3.9.0`; code action `Update to 3.9.0 (fixes RUSTSEC-2026-0462)` with edit `=3.9.0`.
- This particular case is a security-fix update, which deps-lsp deliberately exempts from its own cooldown ([[075-cli-update-cooldown-fallback/spec|075]]). The finding is that the project's configured window is not consulted at all: a search of `crates/` and `book/` finds no reader of publish-age, release-age, `exclude-newer`, `minimumReleaseAge` or `npmMinimalAgeGate` (only an unrelated `hover.rs` doc comment mentions publish-age).
- Cargo's `deny` does not exempt security fixes (the user must set an env override), so a silent mismatch between the editor recommendation and what `cargo update` accepts is possible.

Native gates in scope, as reported by the research finding (units and versions marked below are not yet verified against primary docs, see section 9):

| Tool | Setting | Location | Unit / format | Per-package exemption |
|------|---------|----------|---------------|-----------------------|
| Cargo (Rust 1.100, stable 2026-11-12; cargo#17335 merged 2026-08-28; RFC 3923) | `[registry] global-min-publish-age`, `[registries.<name>] min-publish-age`, `[resolver] incompatible-publish-age = "deny"\|"allow"` | `.cargo/config.toml` (hierarchical) and env `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE`, `CARGO_REGISTRIES_<NAME>_MIN_PUBLISH_AGE`, `CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE` | seconds, minutes, hours, days, weeks, months; default `"0"` (opt-in) | none reported |
| npm >= 11.10.0 | `min-release-age` (`before` wins if both are set) | `.npmrc` | number of days | `min-release-age-exclude` (names/globs, newer npm) |
| pnpm | `minimumReleaseAge`, `minimumReleaseAgeStrict` | `pnpm-workspace.yaml` (not `.npmrc`) | minutes (believed), pnpm 11 default 1440 (believed) | `minimumReleaseAgeExclude` |
| Yarn >= 4.10 | `npmMinimalAgeGate` | `.yarnrc.yml` | unverified | `npmPreapprovedPackages` |
| Bun >= 1.3 | `[install] minimumReleaseAge` | `bunfig.toml` | seconds (believed) | unverified |
| uv | `exclude-newer` | `pyproject.toml` `[tool.uv]` or `uv.toml` | RFC 3339 timestamp, friendly duration (`"1 week"`), or ISO 8601 duration (`"P7D"`); compares artifact upload time | `exclude-newer-package` per-package map; `false` exempts a package |

Cargo's gate does not apply to `cargo install`, git or path dependencies, or registries without publish-time data. Versions already in `Cargo.lock` stay eligible under `deny`; resolution fails if no eligible version remains.

### Goal

When a project declares a native release-age window, deps-lsp and deps-cli use it as the effective freshness window for that ecosystem and manifest scope, so no recommendation, diagnostic, or edit proposes a version the project's own tool will reject, and the UI says why.

### Out of Scope

- Writing or editing native cooldown configuration (no code action that sets `min-publish-age` and the like).
- Rewriting manifests to pin around the window (rejected for the same reasons as [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] sections 1 and 8).
- Ecosystems without a verified native gate: Dart, Swift, Maven, Gradle, NuGet, Composer, Bundler, Go, GitHub Actions, GitLab CI/CD. If a later check finds a native gate for one of them, it is a new spec row, not an extension of this one. `[NEEDS CLARIFICATION]` item 8 covers re-verifying this list.
- Installer-level cooldown for auto-following ecosystems (#1569); this spec supplies its answer for Cargo, npm and PyPI/uv only.
- Network calls: no new registry or deps.dev requests; the feature reuses publish times already fetched for the existing freshness signal.
- Editing anything under `crates/deps-zed`.

## 2. User Stories

### US-001: Cargo project with a publish-age gate
AS A Rust developer using Cargo 1.100 or newer with `global-min-publish-age = "7 days"`
I WANT deps-lsp to treat versions younger than 7 days as not yet eligible
SO THAT the editor never offers an update that `cargo update` would refuse.

**Acceptance criteria:**
```
GIVEN .cargo/config.toml with [registry] global-min-publish-age = "7 days"
  AND the newest registry version was published 3 days ago
WHEN the user hovers the dependency or requests code actions
THEN the hover callout says the version is excluded by "cargo registry.global-min-publish-age = 7 days"
  AND no plain "Update to <that version>" action is offered
  AND the newest eligible version is the one proposed
```

### US-002: npm and pnpm project with a release-age gate
AS A JavaScript developer using `min-release-age` (npm) or `minimumReleaseAge` (pnpm)
I WANT the same behavior as US-001
SO THAT updates proposed from `package.json` match what my package manager installs.

**Acceptance criteria:**
```
GIVEN .npmrc with min-release-age=7 (or pnpm-workspace.yaml with the equivalent minimumReleaseAge)
  AND the newest version is younger than the window
WHEN diagnostics and code actions are computed
THEN the younger version is treated as inside the cooldown with the native source named
```

### US-003: uv project with exclude-newer
AS A Python developer using uv with `exclude-newer = "1 week"`
I WANT versions uploaded inside the window treated as not yet eligible
SO THAT edits to `pyproject.toml` match what `uv lock` resolves.

**Acceptance criteria:**
```
GIVEN [tool.uv] exclude-newer = "7 days" and a newest release uploaded 2 days ago
WHEN the update action is computed for a dependency
THEN the 2-day-old release is not proposed and the reason names uv exclude-newer
```

### US-004: Per-package exemptions
AS A developer who exempts a package from the gate (npm `min-release-age-exclude`, pnpm `minimumReleaseAgeExclude`, uv `exclude-newer-package`)
I WANT deps-lsp to apply the exemption
SO THAT the editor does not delay a package my tool would install immediately.

### US-005: Advisories stay visible
AS A user (and as a maintainer defending against hostile repositories)
I WANT a native window to never hide a vulnerability diagnostic
SO THAT a repository-controlled config cannot be used to suppress advisories.

**Acceptance criteria:**
```
GIVEN a dependency with a known advisory fixed only in a version inside the native window
WHEN diagnostics are computed
THEN the vulnerability diagnostic is still emitted
  AND the fix action is shown annotated with the native window it falls inside (not removed, not silently offered as plain)
```

### US-006: Opt-out
AS A user who wants the old behavior
I WANT a configuration switch to ignore native windows
SO THAT I can fall back to `freshness.cooldown_secs` only.

## 3. Functional Requirements

Terminology: **native window** is the duration derived from the project's own package-manager config; **effective window** is the duration deps-lsp applies to a given dependency; **source** is the human-readable name of the setting that produced it.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN an ecosystem's manifest scope declares a native release-age window THE SYSTEM SHALL compute the effective window for each dependency in that scope from the native window and `freshness.cooldown_secs`, using the rule fixed by `[NEEDS CLARIFICATION]` item 3. | must |
| FR-002 | WHEN a version's publish time is younger than the effective window and the window comes from a native source THE SYSTEM SHALL treat that version as ineligible for "latest" in hover, update code actions, the "Update N outdated" lens and `deps-cli update`, and SHALL propose the newest eligible version instead. | must |
| FR-003 | WHEN a version is excluded by a native window THE SYSTEM SHALL state the source in the hover callout and the diagnostic message, in the form `excluded by <tool> <setting> = <value>`. | must |
| FR-004 | WHEN the native window comes from Cargo THE SYSTEM SHALL read `[registry] global-min-publish-age`, the matching `[registries.<name>] min-publish-age`, and `[resolver] incompatible-publish-age` from the `.cargo/config.toml` hierarchy already used for registry configuration, and SHALL apply the window only when `incompatible-publish-age` resolves to `deny`. | must |
| FR-005 | WHEN a Cargo dependency resolves to a registry without publish-time data, or is a git or path dependency THE SYSTEM SHALL NOT apply a native window to it. | must |
| FR-006 | WHEN a Cargo dependency's version is already recorded in `Cargo.lock` THE SYSTEM SHALL keep that in-use version eligible, matching `deny` semantics. | must |
| FR-007 | WHEN the native window comes from npm THE SYSTEM SHALL read `min-release-age` (days) and `min-release-age-exclude` from the ancestor `.npmrc` chain through the existing bounded reader, and SHALL give `before` precedence over `min-release-age` when both are set. | must |
| FR-008 | WHEN the native window comes from pnpm THE SYSTEM SHALL read `minimumReleaseAge`, `minimumReleaseAgeExclude` and `minimumReleaseAgeStrict` from `pnpm-workspace.yaml`, converting the unit fixed by `[NEEDS CLARIFICATION]` item 1. | should |
| FR-009 | WHEN the native window comes from uv THE SYSTEM SHALL read `exclude-newer` and `exclude-newer-package` from `[tool.uv]` in `pyproject.toml` and from `uv.toml`, accepting RFC 3339 timestamps, friendly durations and ISO 8601 durations, and SHALL honor `exclude-newer-package = false` as an exemption. | should |
| FR-010 | WHEN a duration-normalization or per-package-exemption concern applies to more than one ecosystem THE SYSTEM SHALL implement it once in `deps-core` (a typed native-window value and a typed source label) and SHALL NOT duplicate it per ecosystem crate. | must |
| FR-011 | WHEN a dependency has a known advisory THE SYSTEM SHALL emit the vulnerability diagnostic regardless of any native window, and SHALL NOT let a native window suppress, downgrade or hide it. | must |
| FR-012 | WHEN the only fix for an advisory lies inside a native window THE SYSTEM SHALL still list that fix, annotated with the window it falls inside, and SHALL follow the per-tool semantics fixed by `[NEEDS CLARIFICATION]` item 4 for whether it is offered as an ordinary edit. | must |
| FR-013 | WHERE the user sets the opt-out configuration THE SYSTEM SHALL ignore all native windows and apply only `freshness.cooldown_secs`. | must |
| FR-014 | WHEN a native setting is present but malformed, out of range, or in an unsupported unit THE SYSTEM SHALL ignore that setting, fall back to `freshness.cooldown_secs`, and log one `tracing` warning naming the file and key, without failing the document load. | must |
| FR-015 | WHEN a native config file changes on disk (`.cargo/config.toml`, `.npmrc`, `pnpm-workspace.yaml`, `pyproject.toml`, `uv.toml`) THE SYSTEM SHALL recompute affected documents through the existing watched-file reparse path. | should |
| FR-016 | WHEN `deps-cli update` computes its cooldown fallback THE SYSTEM SHALL apply the same effective window as the LSP for the same manifest, so both interfaces produce identical edits. | must |
| FR-017 | WHEN the native tool's per-package exemption matches a dependency THE SYSTEM SHALL use only `freshness.cooldown_secs` for that dependency. | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security (untrusted repository) | Native config is repository-controlled input. A hostile config may only lengthen or shorten the delay of a non-security recommendation; it SHALL NOT suppress any diagnostic, alter any edit target to an unlisted version, or cause network access. See #1964 and the `vulnerability` suppression rule of [[094-lsp-per-package-diagnostic-suppression/spec|094]]. |
| NFR-002 | Security (bounded reads) | Every native config read SHALL go through `deps-core::fs_probe::read_to_string_capped` and the existing ancestor search bound `MAX_CONFIG_ANCESTOR_DEPTH`; unbounded or TOCTOU-prone reads are not permitted. Ancestor files SHALL be cached through `mtime_cache`. |
| NFR-003 | Security (resource) | A window value SHALL be clamped to a documented maximum so an absurd value (for example a 10^12 day count) cannot overflow duration arithmetic; overflow SHALL fall back per FR-014. |
| NFR-004 | Network | The feature SHALL add no registry, deps.dev or OSV request. It consumes publish times already fetched for the existing freshness signal. Where a registry response lacks a publish time, the window does not apply (FR-005). |
| NFR-005 | Performance | Hover and completion SHALL remain non-blocking; native windows are resolved at document load or reparse and cached, not on the request path. |
| NFR-006 | Type safety | The native window, its source and the opt-out SHALL be dedicated types (a duration newtype, an enum of sources that is exhaustive and without a catch-all `_` arm), not raw `u64` seconds or `String` labels. |
| NFR-007 | Consistency | The same scenario SHALL give the same hover, diagnostic and action behavior across Cargo, npm/pnpm and uv, differing only in the source label. |
| NFR-008 | Compatibility | With no native config present, output SHALL be byte-identical to current behavior; existing snapshots SHALL not change. |
| NFR-009 | Documentation | The mdBook ecosystem pages for the covered ecosystems and the configuration reference SHALL document the behavior and the opt-out. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| NativeCooldown | A window read from the project's package-manager config | tool, setting name, window duration, enforcement mode (deny/allow or strict/non-strict), config file path |
| NativeCooldownSource | Exhaustive label of where the window came from | Cargo registry-wide, Cargo per-registry, npm, pnpm, Yarn, Bun, uv (variant set follows the phased rollout) |
| PackageExemption | Per-package opt-out of a native window | package name or glob, exemption kind |
| EffectiveWindow | The window applied to one dependency | duration, optional NativeCooldownSource (absent means only `freshness.cooldown_secs`) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Cargo `incompatible-publish-age = "allow"` | Window is not applied (FR-004); cooldown is `freshness.cooldown_secs` only |
| Cargo window set but the installed Cargo predates 1.100 | Cargo ignores the key; deps-lsp cannot know the installed version `[NEEDS CLARIFICATION]` item 5 |
| Per-registry `min-publish-age` overrides `global-min-publish-age` | The per-registry value applies to dependencies of that registry (FR-004) |
| Dependency version already in `Cargo.lock` | Stays eligible (FR-006) |
| Newest version is inside the window and a lower eligible version exists | Propose the newest eligible version, never lower than the in-use version |
| No eligible version exists | Show no update, hover states all newer versions are inside the native window; no edit offered |
| npm `before` and `min-release-age` both set | `before` wins (FR-007) |
| `.npmrc` found in an ancestor above the workspace root | Followed only within `MAX_CONFIG_ANCESTOR_DEPTH` |
| pnpm config lives in `.npmrc` instead of `pnpm-workspace.yaml` | Ignored for pnpm settings (pnpm does not read it there) |
| uv `exclude-newer` is an absolute RFC 3339 timestamp | Versions uploaded after the timestamp are ineligible; semantics fixed by `[NEEDS CLARIFICATION]` item 6 |
| uv `exclude-newer-package.<name> = false` | Exempt (FR-017) |
| Malformed or unsupported value (for example `"7 fortnights"`) | Ignored with one warning (FR-014) |
| Native window shorter than `freshness.cooldown_secs` | Resolved by the rule in `[NEEDS CLARIFICATION]` item 3 |
| Advisory fix lies inside the window | Diagnostic stays; fix annotated (FR-011, FR-012) |
| Config file unreadable, oversized, or a symlink loop | Treated as absent, debug-level log, no user-visible error |
| Monorepo with different windows per workspace member | Resolved per manifest scope; nearest config wins following each tool's own precedence |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | The 2026-11-09 repro (`rmcp = "=3.8.0"`, `global-min-publish-age = "7 days"`) no longer yields a plain `Update to 3.9.0` for a non-security case, and names the native source | 100% |
| SC-002 | Per-ecosystem live checks (Cargo, npm, pnpm, uv) where the proposed version matches what the real tool resolves | 100% of verified fixtures |
| SC-003 | Projects with no native config produce unchanged output | 0 snapshot diffs |
| SC-004 | Vulnerability diagnostics emitted with a hostile native window set | identical to the no-config run |
| SC-005 | Added network requests per document load | 0 |
| SC-006 | Duplicate window-parsing or duration-normalization code across ecosystem crates | 0 (single `deps-core` implementation) |

## 8. Agent Boundaries

### Always (without asking)
- Verify each behavior live with the LSP harness against real manifests before concluding (continuous-improvement live-testing principle).
- Route all file reads through `fs_probe` and cache through `mtime_cache`.
- Put shared parsing and duration normalization in `deps-core`.
- Run the full CI-matching check suite before commit.

### Ask First
- Adding a new dependency (for example a duration-string parser); prefer the existing workspace crates.
- Adding a new public configuration key or changing the `deny_unknown_fields` config schema.
- Changing which release-age semantics apply to security-fix updates.
- Extending coverage to an ecosystem not listed in the rollout.

### Never
- Let a native window suppress, downgrade or hide a vulnerability diagnostic.
- Execute or shell out to a package manager to read its effective config.
- Make a network request to resolve a native window.
- Write or modify the user's native package-manager config.
- Edit files under `crates/deps-zed`.
- Add `#[non_exhaustive]` or a catch-all arm to the source enum.

## 9. Open Questions

> [!question] Unresolved items
> 1. [NEEDS CLARIFICATION: pnpm `minimumReleaseAge` unit (minutes believed) and pnpm 11 default (1440 believed); confirm from https://pnpm.io/settings/dependency-resolution. If the default is non-zero without any config, does deps-lsp apply it when no pnpm config exists, or only an explicitly declared value?]
> 2. [NEEDS CLARIFICATION: Yarn `npmMinimalAgeGate` (>= 4.10) and Bun `[install] minimumReleaseAge` (>= 1.3, seconds believed): confirm units, minimum versions, exemption keys and config locations from primary docs, and decide whether either joins the rollout phase with npm/pnpm.]
> 3. [NEEDS CLARIFICATION: effective-window rule. The finding says "the larger/authoritative of {native window, freshness.cooldown_secs}". When the native window is shorter than `freshness.cooldown_secs`, is the native window authoritative for eligibility (the tool would accept the version) while `freshness.cooldown_secs` still drives the existing "recently published" advisory, or does the larger value win for both? Recommendation: native window decides eligibility and the explanation; `freshness.cooldown_secs` keeps its advisory role unchanged.]
> 4. [NEEDS CLARIFICATION: security-fix semantics per tool. Cargo `deny` does not exempt security fixes; npm `audit fix` keeps the vulnerable version when blocked. Should a fix inside the native window be offered as an annotated, ordinary edit (the user's tool will then refuse it) or as an annotated non-applicable hint pointing at the tool's override (for Cargo, the env override)? FR-011 holds either way.]
> 5. [NEEDS CLARIFICATION: Cargo version detection. Cargo ignores the keys before 1.100 (stable 2026-11-12), and the Cargo version may not be knowable (toolchain files, CI). Apply the window whenever configured (recommended: the config express intent), or gate on a detected `rust-version`/toolchain?]
> 6. [NEEDS CLARIFICATION: uv `exclude-newer` as an absolute timestamp is a fixed cutoff, not a rolling window. Treat any version uploaded after the cutoff as ineligible (matches uv), and is the duration form evaluated against "now" at each request or at document load? Also confirm how uv's per-file upload time maps onto the per-version publish time deps-pypi already fetches.]
> 7. [NEEDS CLARIFICATION: configuration surface and environment. Name and shape of the opt-out (a boolean `freshness.honor_native_cooldown`, a per-ecosystem enum, or both); and whether deps-lsp reads the Cargo `CARGO_*` and npm env overrides from the language-server process environment (editor-launched servers often do not share the terminal environment, and the threat model treats repository files and process env differently). Also whether user-level configs (`~/.cargo/config.toml`, `~/.npmrc`, user `uv.toml`) are honored alongside repository-level ones.]
> 8. [NEEDS CLARIFICATION: confirm from primary docs that Dart, Swift, Maven, Gradle, NuGet, Composer, Bundler and Go have no native release-age gate as of 2026-11, so the out-of-scope list is correct.]

## 10. Phased Rollout (suggestion)

| Phase | Scope | Rationale |
|-------|-------|-----------|
| 1 | `deps-core` typed native-window value, source enum, and shared duration parser; Cargo reader (`.cargo/config.toml` hierarchy, `deny` semantics, lockfile-eligible rule); LSP and `deps-cli update` wiring; opt-out; mdBook + tests + live test | Rust 1.100 lands 2026-11-12 with deny-by-default semantics when configured, and `deps-cargo` already parses `.cargo/config.toml` (#431) |
| 2 | npm (`.npmrc` via the existing ancestor reader) and pnpm (`pnpm-workspace.yaml` via the existing workspace readers), exclusions; Yarn/Bun if item 2 is resolved | Reuses `mtime_cache`/`fs_probe`; per-package exclusion lists exist |
| 3 | uv (`pyproject.toml` `[tool.uv]`, `uv.toml`), `exclude-newer-package`, absolute-timestamp semantics | Most semantic ambiguity (item 6), so last |

Each phase ships behind the same opt-out and updates `.local/testing/coverage.md` and the relevant playbook per the branching rules.

## 11. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[004-release-freshness-signal/spec|004]], [[020-freshness-cooldown-diagnostics-blind/spec|020]] — freshness cooldown signal and diagnostics
- [[075-cli-update-cooldown-fallback/spec|075]], [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] — deps-cli update cooldown fallback and why a manifest-level exact pin was rejected
- [[072-deps-dev-gossip-signals/spec|072]] — deps.dev GOSSIP cooldown signal
- [[094-lsp-per-package-diagnostic-suppression/spec|094]] — `vulnerability` suppression rule and untrusted-repository threat model
- Issue #1569 (installer-level cooldown), #1964 (untrusted config must not hide advisories), #431 (Cargo registry config)
- Cargo config reference: https://doc.rust-lang.org/beta/cargo/reference/config.html
- Cargo cooldowns write-up (2026-10-20): https://socket.dev/blog/rust-cargo-cooldowns
- Cargo stabilization PR: https://github.com/rust-lang/cargo/pull/17335 (RFC 3923)
- npm config (`min-release-age`): https://docs.npmjs.com/cli/v11/using-npm/config
- pnpm settings (`minimumReleaseAge`): https://pnpm.io/settings/dependency-resolution
- uv settings (`exclude-newer`): https://docs.astral.sh/uv/reference/settings/#exclude-newer

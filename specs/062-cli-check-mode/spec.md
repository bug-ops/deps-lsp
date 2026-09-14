---
aliases:
  - CLI Check Mode
  - deps-cli
tags:
  - sdd
  - spec
  - cli
  - ci
created: 2026-09-14
status: draft
related:
  - "[[constitution]]"
---

# Feature: CLI Check Mode (`deps-cli check`)

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: feat/issue-711/cli-check-mode
> **Source issue**: `#711` (research, P3)
> **Related issues**: `#547` (workspace/diagnostic pull model), `#700` (disk-persisted registry cache), `#710` (MCP server mode — shares the multi-file walk, kept as a decoupled sibling feature)

## 1. Overview

### Problem Statement

`deps-lsp` computes outdated / yanked / unsatisfiable / vulnerable / deprecated /
license-policy / mutable-ref-pin verdicts for 14 manifest ecosystems, but today
that analysis is reachable only from inside an editor (`crates/deps-lsp/src/main.rs`
exposes only `--stdio` / `--version` / `--help`). Teams that want the same policy
enforced in CI, in a pre-commit hook, or from a plain shell have no way to invoke
this engine outside an LSP client — they either re-implement per-ecosystem checks
with single-purpose tools (`cargo outdated`, `npm outdated`, `pip list --outdated`,
`osv-scanner`) or skip the check entirely for ecosystems those tools don't cover
(GitHub Actions, GitLab CI/CD).

### Goal

A new `deps-cli` binary crate exposes a `check [PATH…]` subcommand that walks a
workspace, runs the exact same parse → resolve → diagnostics pipeline the LSP
uses (reusing `EcosystemRegistry`, `Ecosystem::generate_diagnostics`, and the
registry/cache/OSV/deps.dev clients unchanged), and reports findings as
`table` (human), `json` (machine), or `sarif` (GitHub code scanning) output, with
a configurable `--fail-on` policy and process exit code suitable for CI gating.
A `.pre-commit-hooks.yaml` and a thin GitHub Action wrapper ship on top of the
same binary so adoption needs no separate packaging step.

### Out of Scope

- **MCP server mode** (`#710`) — a separate, decoupled feature; this spec does
  not share a crate or binary with it, only (optionally, see §9) the directory-walk
  helper.
- **Disk-persisted registry cache** (`#700`) — `--offline` in this spec only
  serves whatever is already warm in the in-memory `HttpCache` for the process's
  own lifetime; it is not a persistent cache across CLI invocations. Cross-run
  caching is `#700`'s concern and can be adopted by `deps-cli` later without
  changing this spec's CLI surface.
- **CycloneDX output** (`--format cyclonedx`) — explicitly deferred by the source
  issue to a later increment; only declared-dependency (not resolved-dependency)
  CycloneDX would be possible without a `LockFileProvider` for every ecosystem,
  and that distinction needs its own design pass.
- **`workspace/diagnostic` LSP pull-model support** (`#547`) — a protocol-level
  feature for editors, not this CLI. The two may end up sharing the underlying
  multi-file walk in the plan phase, but `#547`'s own scope is unaffected by
  this spec.
- **Auto-fix / write-back mode** — `check` only reports; it never edits a
  manifest in place (no `--fix` flag in this spec). Applying the same edit the
  LSP's code actions would apply is a plausible future increment, not part of
  this one.

## 2. User Stories

### US-001: Enforce dependency policy in CI

AS A team lead running CI on a monorepo with multiple ecosystems
I WANT a single command that fails the build when a dependency is vulnerable,
yanked, unsatisfiable, or violates a license policy
SO THAT dependency health regressions are caught before merge, without needing
a separate CLI per ecosystem

**Acceptance criteria:**
```
GIVEN a repository containing a Cargo.toml with a vulnerable dependency and a
      package.json with an outdated (but not vulnerable) dependency
WHEN  `deps-cli check --fail-on vulnerable` runs against the repository root
THEN  the process exits with code 1, and the report lists the vulnerable Cargo
      dependency as a failing finding while the outdated npm dependency is
      reported but does not affect the exit code
```

### US-002: Upload findings to GitHub code scanning

AS A developer using GitHub Advanced Security
I WANT `deps-cli check --format sarif` output I can feed to
`github/codeql-action/upload-sarif`
SO THAT dependency findings appear in the repository's Security tab alongside
other code-scanning alerts

**Acceptance criteria:**
```
GIVEN a repository with at least one outdated dependency
WHEN  `deps-cli check --format sarif > results.sarif` runs
THEN  `results.sarif` is a well-formed SARIF 2.1.0 document whose `results`
      entries carry the diagnostic's existing rule id, message, and LSP range
      translated to a SARIF physical location
```

### US-003: Block a bad commit locally via pre-commit

AS A contributor
I WANT a pre-commit hook that runs the same check before a commit is created
SO THAT I catch a newly-introduced vulnerable or unsatisfiable dependency
before it ever reaches CI

**Acceptance criteria:**
```
GIVEN the project's `.pre-commit-config.yaml` references deps-lsp's
      `.pre-commit-hooks.yaml` entry
WHEN  a contributor commits a manifest change that introduces a yanked version
THEN  the commit is rejected locally with a human-readable table pointing at
      the offending manifest line, before the commit reaches any remote
```

### US-004: Run fully offline against warm cache

AS A developer on a network-restricted CI runner
I WANT `--offline` to use only already-cached registry data instead of failing
the whole run
SO THAT the check still produces a partial, clearly-labeled result instead of
an opaque network error

**Acceptance criteria:**
```
GIVEN a process where `HttpCache` already holds a warm entry for package X but
      not for package Y
WHEN  `deps-cli check --offline` runs
THEN  X's verdict is reported normally, Y is reported as `unknown (offline,
      no cached data)`, and the process does not attempt any new outbound
      request
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `deps-cli check [PATH…]` runs with no `PATH` given THE SYSTEM SHALL walk the current working directory | must |
| FR-002 | WHEN walking a directory THE SYSTEM SHALL route each discovered file through `EcosystemRegistry`'s existing `manifest_filenames()` / `manifest_patterns()` / `manifest_extensions()` / `manifest_directory_patterns()` resolution, unchanged from the LSP's own routing | must |
| FR-003 | WHEN walking a directory THE SYSTEM SHALL respect `.gitignore` and skip any path already excluded by it | must |
| FR-004 | WHEN walking a directory THE SYSTEM SHALL cap total file count and per-file size using the existing `fs_probe` bounds, never reading an uncapped file into memory | must |
| FR-005 | WHEN a manifest is discovered THE SYSTEM SHALL run the identical `Ecosystem::generate_diagnostics` path the LSP uses to produce that manifest's findings, so CLI and LSP verdicts cannot structurally drift | must |
| FR-006 | WHEN `--format table` is selected (the default) THE SYSTEM SHALL print a human-readable table grouping findings by file and severity | must |
| FR-007 | WHEN `--format json` is selected THE SYSTEM SHALL print a versioned JSON document listing every finding with its ecosystem, manifest path, dependency name, requirement, resolved verdict, and range | must |
| FR-008 | WHEN `--format sarif` is selected THE SYSTEM SHALL print a SARIF 2.1.0 document where each existing diagnostic code becomes a SARIF rule id and each LSP range becomes a SARIF physical location region | must |
| FR-009 | WHEN `--fail-on <category>[,<category>…]` is given THE SYSTEM SHALL exit with code 1 if and only if at least one reported finding matches one of the given categories (`outdated`, `yanked`, `vulnerable`, `unsatisfiable`, `mutable-ref`, `license`, `deprecated`) | must |
| FR-010 | WHEN `--fail-on` is not given THE SYSTEM SHALL default to failing on `vulnerable,yanked,unsatisfiable` (the categories that represent a broken or unsafe build, as opposed to `outdated`, which is advisory) | must |
| FR-011 | WHEN every registry a run needed was reachable (or `--offline` was given) and the run completed THE SYSTEM SHALL exit 0 if no finding matched `--fail-on`, or 1 if at least one did | must |
| FR-012 | WHEN a registry required by a non-offline run is unreachable THE SYSTEM SHALL exit with code 2, distinct from a policy-violation exit of 1 | must |
| FR-013 | WHEN `--offline` is given THE SYSTEM SHALL serve only data already warm in the process's `HttpCache`, mark any dependency with no cached data as `unknown (offline, no cached data)`, and never attempt a new outbound request | must |
| FR-014 | WHEN a `deps.toml` file exists at the walked root (or a path given via `--config`) THE SYSTEM SHALL parse it through the same validating, `deny_unknown_fields`-enforcing configuration path the LSP's `initialization_options` go through, applying the CLI's own policy-relevant subset of settings (severities, network/offline, cache, freshness, supply-chain, registries, license-policy) | must |
| FR-015 | WHEN a CLI flag (e.g. `--fail-on`, `--offline`, `--cooldown`) overlaps with a `deps.toml` setting THE SYSTEM SHALL let the flag override the file's value for that run only | must |
| FR-016 | WHEN `deps.toml` fails to parse THE SYSTEM SHALL print the parse error to stderr and exit 2, rather than silently falling back to defaults (unlike the LSP's own live-reload behavior, a CLI run has no prior known-good configuration to keep) | must |
| FR-017 | WHEN the repository ships `.pre-commit-hooks.yaml` at its root THE SYSTEM SHALL define a hook entry that installs from the Rust source (`language: rust`) and runs `deps-cli check` against the files pre-commit passes it | must |
| FR-018 | WHEN a GitHub Actions consumer uses the shipped composite action THE SYSTEM SHALL run `deps-cli check --format sarif`, write the result to a file, and leave the `upload-sarif` step to the consumer's own workflow (not bundled as a second, separate action) | should |
| FR-019 | WHEN `GITHUB_TOKEN` is set in the environment THE SYSTEM SHALL use it for GitHub-registry-backed ecosystems (GitHub Actions, and any ecosystem resolving via the GitHub API) exactly as the LSP already does, raising the unauthenticated 60 req/h ceiling | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Consistency | `deps-cli` and `deps-lsp` must never implement their own, second copy of parse/resolve/diagnostic logic — both call the same `deps-core`/`Ecosystem` entry points (constitution principle 1) |
| NFR-002 | Security | Directory walk and file reads use the existing capped, TOCTOU-safe `fs_probe::read_to_string_capped` path — no new unbounded read introduced for the CLI |
| NFR-003 | Security | `deps.toml`/CLI-flag values that are secret-shaped (tokens, credentials) are never echoed into `table`/`json`/`sarif` output or process stdout/stderr, mirroring `Redacted<T>`'s existing contract |
| NFR-004 | Performance | A `check` run against N manifests must not exceed the LSP's own per-registry concurrency/rate-limit ceilings (`CacheConfig::max_concurrent_fetches`) — the CLI is a new caller of the same budget, not a separate, uncapped one |
| NFR-005 | Portability | `deps-cli` builds and runs on the same platforms `deps-lsp` already targets (Linux/macOS/Windows, per the existing CI test matrix) |
| NFR-006 | API stability | `deps-cli` is a new crate; it does not change any existing published crate's public API, so it introduces no breaking-change obligation under constitution principle 8 |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `CheckReport` | The full result of one `check` invocation | `findings: Vec<CheckFinding>`, `summary` (counts per category), `exit_code` |
| `CheckFinding` | One reported issue, derived 1:1 from an existing LSP `Diagnostic` | `ecosystem`, `manifest_path`, `dependency_name`, `requirement`, `category` (outdated/yanked/vulnerable/unsatisfiable/mutable-ref/license/deprecated), `severity`, `range` (line/column), `message` |
| `FailOnPolicy` | The set of categories that turn a finding into a non-zero exit | `categories: Vec<Category>` |
| `CliConfig` | The CLI's own policy-relevant configuration, loaded from `deps.toml` and overridden by flags | subset of `DepsConfig`'s non-editor-only sections (diagnostics severities, cache, network, freshness, supply_chain, registries, license_policy) — see Open Questions §9 for how this subset relates structurally to `deps-lsp::config::DepsConfig` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Empty workspace (no recognized manifest found) | Exit 0, report "no manifests found", not an error |
| Very large monorepo (hundreds of manifests) | Discovery and diagnostics generation run concurrently under the existing rate-limit ceiling; no unbounded memory growth (FR-004, NFR-004) |
| Registry unreachable, `--offline` not given | Exit 2 (FR-012); message names which registry/ecosystem failed |
| Registry unreachable, `--offline` given | Never attempted; affected dependencies marked unknown (FR-013), exit reflects only `--fail-on` policy over what *was* resolved |
| Malformed `deps.toml` | Exit 2 with the parse error on stderr (FR-016) — never silently falls back to defaults, since there is no live prior configuration to keep |
| Unknown key in `deps.toml` | Rejected by the same `deny_unknown_fields` top-level struct the LSP config uses (FR-014) — same fail-closed behavior as a bad LSP `initializationOptions` payload |
| A manifest path given explicitly on the command line that no ecosystem recognizes | Reported as a warning line, not a fatal error; the rest of the run proceeds |
| `GITHUB_TOKEN` absent and the run needs >60 GitHub API requests/hour | Reported the same actionable rate-limit diagnostic the LSP already emits (issue `#478`/spec `039`), not a bare HTTP error |
| Concurrent manifests belonging to the same ecosystem but different lock files | Each resolved independently through the same per-ecosystem `LockFileProvider` the LSP uses — no CLI-specific lockfile logic |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | CLI verdict matches LSP verdict for the same manifest+lockfile pair | 100% agreement in the cross-ecosystem regression suite (`.local/testing/regressions.md` manifests re-run through both paths) |
| SC-002 | SARIF output validates against the SARIF 2.1.0 schema | 100% of emitted documents |
| SC-003 | A `check` run over the project's own workspace (14 ecosystems' worth of test fixtures) | completes and exits deterministically (repeatable exit code across 3 consecutive runs with a warm cache) |
| SC-004 | `--offline` run issues zero outbound requests | verified via network-disabled integration test |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `EcosystemRegistry`, `Ecosystem::generate_diagnostics`, and existing `fs_probe`/`net_policy` helpers rather than reimplementing routing, parsing, or SSRF guards
- Run the full pre-commit check suite (`.claude/rules/branching.md`) before any PR
- Add `CHANGELOG.md` entries under `[Unreleased]`

### Ask First
- Adding a new external dependency (candidates: a directory-walk crate such as `ignore`, `serde-sarif`, an argument-parsing crate such as `clap`) — check current versions via context7 first per global `CLAUDE.md`
- Deciding the exact shape of the `deps.toml` ↔ `DepsConfig` code-sharing refactor (see Open Questions §9) if it touches `deps-lsp`'s existing public `config` module
- Naming the new crate's Cargo.toml `authors`/publish metadata

### Never
- Duplicate parse/diagnostic logic instead of calling into `deps-core`/`Ecosystem` (constitution principle 1)
- Add a `--fix` / write-back capability under this spec's scope
- Send any outbound request `--offline` mode is active
- Log or print a secret-shaped configuration value in any output format

## 9. Open Questions

All three architectural questions raised during `/sdd specify` were resolved with
the project owner before moving to `/sdd plan`; none are blocking any longer.

- **Config code-sharing — RESOLVED**: the policy-relevant sections of
  `deps-lsp::config::DepsConfig` (`diagnostics` severities, `cache`, `network`,
  `freshness`, `supply_chain`, `registries`, `license_policy`) move into a new
  `deps-core` type. Both `deps-lsp::config::DepsConfig` (keeping its editor-only
  sections — `inlay_hints`, `loading_indicator`, `code_lens`) and `deps-cli`'s
  own top-level config compose that shared `deps-core` type rather than each
  parsing it independently. This is consistent with constitution principle 1
  ("one fix, one place") at the cost of a refactor to already-shipped,
  `1.0.0`-tagged `deps-lsp::config` code — the plan phase must scope that
  refactor as its own step, sequenced before or alongside `deps-cli`'s own
  config loading, and treat it as **not** a breaking change to `deps-lsp`'s
  public API surface (the section types keep their existing field-level shape;
  only where they physically live changes) — verify this with
  `cargo-semver-checks` per constitution principle 8 before considering the
  refactor step done.
- **Directory-walk implementation — RESOLVED**: take a new workspace dependency
  on `ignore` (the crate `ripgrep` uses) for `.gitignore`-aware directory
  walking, rather than hand-rolling one on top of `fs_probe`. Per this spec's
  "Ask First" boundary (§8), check `ignore`'s current version via context7
  before pinning it in root `Cargo.toml`'s `[workspace.dependencies]`
  (alphabetically sorted, no features specified there, per this project's
  workspace conventions).
- **Crate publishing — RESOLVED**: `deps-cli` publishes from its first release
  as the workspace's 17th published crate, under the same
  `version = "1.0.0"`/compatibility contract as the other 16 (constitution
  principle 8). Its CLI flag surface, `deps.toml` schema, `json`/`sarif` output
  schemas, and any public library API it exposes are therefore all subject to
  the standard major-bump-on-breaking-change and `CHANGELOG.md` "Breaking"
  labeling rules from day one — there is no pre-1.0 grace period for this new
  crate to accumulate breaking changes informally.

## 10. See Also

- `[[constitution]]` — project principles (principle 1: one fix, one place; principle 8: post-1.0 breaking-change policy)
- `[[MOC-specs]]` — all specifications
- GitHub issue `#711` — source research issue
- Related issues: `#547` (workspace/diagnostic pull model), `#700` (disk-persisted registry cache), `#710` (MCP server mode)
- `crates/deps-lsp/src/config.rs` — existing `DepsConfig` this spec's CLI config must not fork
- `crates/deps-core/src/ecosystem_registry.rs` — existing `EcosystemRegistry` routing this spec reuses unchanged

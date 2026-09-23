---
aliases:
  - deps-cli update subcommand Plan
tags:
  - sdd
  - plan
  - deps-cli
  - deps-core
  - security
created: 2026-09-23
status: draft
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: deps-cli update subcommand

> [!info] References
> **Spec**: [[spec]]

## 1. Architecture

### Approach

Two shared planners, one extraction pattern. `collect_update_all_edits`'
body (default outdated→latest planning) and `build_vulnerability_fix_action`'s
body (vulnerable→`recommended_fix()` planning) both move into a new,
ungated `deps_core::edit` module, following the same LSP-extraction shape
spec 064 already applied to `Diagnostic` (protocol-agnostic domain type +
thin `lsp-responses`-gated adapter). `deps-lsp`'s two existing consumers
become one-line adapters over the moved logic; `deps-cli` gains a second,
independent consumer (`deps-cli update`) that never links
`tower-lsp-server` (CI guard, spec 064/#1083).

`deps-cli update` itself reuses `check`'s parse → lockfile → fetch → OSV
pipeline by extracting it out of `check_manifest` into a shared
`analyze_manifest`, then feeds the result into exactly one of two planners
depending on `--security-only`, applies the selected plan's edits, and
writes them back atomically.

### Component Diagram

```mermaid
graph TD
    subgraph deps-core edit module (ungated)
        CU[collect_update_edits] --> PU[PlannedUpdate]
        PVF[plan_vulnerability_fix] --> PU
        DED[dedup_overlapping_edits generic over EditSpan]
        AE[apply_edits]
    end
    subgraph deps-lsp lsp-responses gated
        CLA[code_lenses adapter] --> CU
        CAA[code_actions adapter] --> PVF
    end
    subgraph deps-cli
        AM[analyze_manifest] --> DEFP{--security-only?}
        DEFP -- no --> CU
        DEFP -- yes --> OSVB[OSV phase-B re-verification]
        OSVB --> PVF
        CU --> PKGF[--package filter]
        PVF --> YANK[yank filter]
        PKGF --> IGN[ignore-rule filter]
        YANK --> PKGF2[--package filter]
        IGN --> DED
        PKGF2 --> DED
        DED --> AE
        AE --> TOCTOU[re-read + byte compare]
        TOCTOU -- unchanged --> WA[write_atomic]
        TOCTOU -- changed --> ABORT[abort, exit 2]
        WA --> REND[render_update]
        REND --> EXIT[update_exit_code]
    end
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| Two planners, not one filter chain | `collect_update_edits` (default) and `plan_vulnerability_fix` (security), both in `deps_core::edit` | `--security-only` targets `recommended_fix()`, an OSV-derived value the default planner's `latest` never touches; filtering the default planner's output cannot produce this target. This is what issue #1120's text points at directly | A single collector with a post-hoc filter (revision 1) — rejected: cannot retarget an edit's version, only drop it, so it silently downgrades #1120 to selection-only |
| `EditSpan` trait + generic `dedup_overlapping_edits<E>` | New local trait (`start()`/`end()` as `(u32, u32)` tuples), implemented for `ManifestEdit` (ungated) and `ls_types::TextEdit` (gated) | Orphan-rule-clean (local trait, foreign type for the LSP impl); keeps one dedup implementation instead of two | Two separate `dedup_overlapping_edits` functions, one per edit type — rejected: exact duplication of overlap-comparison logic, the DRY violation this project treats as a bug class |
| Atomic write via `OpenOptions::create_new(true)`, not `tempfile` | `deps_core::fs_probe::write_atomic` hand-rolls the temp-file/rename sequence | `tempfile` is `optional = true` behind `deps-core`'s `test-util` feature; promoting it to unconditional would link it into `deps-lsp`'s release binary for a path neither crate uses today. `create_new` maps to `O_CREAT\|O_EXCL`/`CREATE_NEW` on every CI-targeted platform and fails on a pre-existing symlink by open-mode, a stronger property than name-entropy guessing | Promoting `tempfile` on `deps-core` — rejected during design review (Q2, verified against `deps-core/Cargo.toml:51,62,80`) |
| Config allowlist lifted one level, not a new `PolicyConfig` field | `safe_auto_discovered_policy(PolicyConfig) -> PolicyConfig` becomes `safe_auto_discovered_config(CliConfig) -> CliConfig`, same allowlist mechanism widened by one level; `UpdateConfig` lives on `CliConfig` (already `#[non_exhaustive]`), never on `PolicyConfig` | `PolicyConfig` is deliberately exhaustive with a CI grep guard on `PolicyConfig::diff` (`policy_config.rs:17-20,78-88`) — adding a field there is a breaking change on a `publish = true` crate and forces a `PolicyConfigDiff`/`reparse_scope` decision for semantics `deps-lsp` can never read | Putting `UpdateConfig` inside `PolicyConfig` (revision 1) — rejected (Q1 ruling); a second, parallel allowlist on `deps-cli` alone — rejected as the exact duplication the allowlist mechanism exists to avoid |
| `update` never auto-discovers `deps.toml` | No default `./deps.toml` lookup for this subcommand; `--config` is the only way to load `[update].ignore` | Provably a no-op after the allowlist lift: an auto-discovered file would contribute only the six cosmetic `*_severity` values, none of which `update` renders. Disabling auto-discovery outright is one sentence instead of "discover, warn, strip nothing meaningful", with nothing to keep in sync | Auto-discovering and warning that `[update]` was stripped (revision 2) — rejected (Q3 ruling) as an unnecessary half-state given the allowlist already makes it a no-op |

## 2. Project Structure

```
crates/deps-core/src/
├── edit.rs                     (new, ungated: ManifestEdit, PlannedUpdate, EditSpan,
│                                 dedup_overlapping_edits<E>, apply_edits, UpdateKind,
│                                 classify_update, collect_update_edits, plan_vulnerability_fix)
├── fs_probe.rs                 (+ write_atomic)
└── lsp_helpers/
    ├── code_lenses.rs          (collect_update_all_edits -> thin adapter over edit::collect_update_edits)
    └── code_actions.rs         (build_vulnerability_fix_action -> thin adapter over edit::plan_vulnerability_fix)

crates/deps-engine/src/classify/
└── osv.rs                      (+ osv_name_by_key(&[ScanTarget]) -> HashMap<String, String>)

crates/deps-cli/src/
├── cli.rs                      (+ Command::Update(UpdateArgs); UpdateArgs duplicates
│                                 --config/--offline/--cooldown clap attrs, no CommonArgs flatten)
├── analyze.rs                  (new: ManifestAnalysis + analyze_manifest, extracted from
│                                 report.rs:408-580; check_manifest = analyze_manifest +
│                                 generate_diagnostics + to_finding)
├── report.rs                   (check_manifest reduced to the composition above)
├── config.rs                   (safe_auto_discovered_policy -> safe_auto_discovered_config(CliConfig);
│                                 + UpdateConfig/IgnoreRule/UpdateTypeToken on CliConfig)
├── update/
│   ├── mod.rs                  (new: UpdatePlan, PlannedUpdateItem, Outcome, SkipReason,
│                                 plan_updates, apply_plan)
│   ├── ignore.rs                (new: IgnoreRules::skip_reason(normalized_name, kind))
│   └── security.rs              (new: phase-B OSV re-verification + plan_vulnerability_fix wiring)
├── format/
│   ├── table.rs                 (+ render_update)
│   └── json.rs                  (+ render_update)
├── exit.rs                      (+ update_exit_code)
└── main.rs                      (match cli.command; run_update alongside run_check)
```

No new Cargo dependencies.

## 3. Data Model

```rust
// deps-core/src/edit.rs (ungated)

/// Protocol-agnostic replacement for `ls_types::TextEdit`.
pub struct ManifestEdit {
    pub range: crate::position::Range,
    pub new_text: String,
}

/// An edit with attribution — what makes #1119/#1120's filtering possible;
/// the LSP `TextEdit` this replaces discards everything but the edit itself.
pub struct PlannedUpdate {
    pub name: String,
    pub normalized_name: String,
    pub name_range: crate::position::Range,
    pub current: String,
    pub target: crate::package::ConcreteVersion,
    pub edit: ManifestEdit,
}

pub trait EditSpan {
    fn start(&self) -> (u32, u32);
    fn end(&self) -> (u32, u32);
}

impl EditSpan for ManifestEdit { /* .. */ }
// impl EditSpan for ls_types::TextEdit lives in the lsp-responses-gated module

pub fn dedup_overlapping_edits<E: EditSpan>(edits: Vec<E>, caller: &str) -> Vec<E>;

pub fn apply_edits(content: &str, edits: &[ManifestEdit]) -> String;

pub enum UpdateKind { Major, Minor, Patch, Unknown }

pub fn classify_update(from: &str, to: &str) -> UpdateKind;

pub fn collect_update_edits(
    parse_result: &dyn ParseResult,
    content: &str,
    versions: &VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Vec<PlannedUpdate>;

pub fn plan_vulnerability_fix(
    dep: &dyn Dependency,
    fix: &FixTarget,
    formatter: &dyn EcosystemFormatter,
) -> Option<PlannedUpdate>;
```

```rust
// deps-core/src/fs_probe.rs

/// Atomically writes `content` to `path`. Creates a temp file in the same
/// directory (`O_CREAT|O_EXCL`), copies the original file's permissions to
/// the temp handle on Unix before writing content, fsyncs the file, then
/// renames it over `path`. Refuses (no temp file created) when `path`'s
/// final component is a symlink. Does not close the write-time TOCTOU
/// window against a concurrent writer — see plan §6.
///
/// # Errors
/// Returns an error if `path`'s final component is a symlink, if the temp
/// file cannot be created or written, or if the rename fails.
pub fn write_atomic(path: &Path, content: &str) -> io::Result<()>;
```

```rust
// deps-cli/src/config.rs

pub struct CliConfig {
    #[serde(flatten)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub update: UpdateConfig,   // new field; CliConfig is already #[non_exhaustive]
}

pub struct UpdateConfig {
    #[serde(default)]
    pub ignore: Vec<IgnoreRule>,
}

pub struct IgnoreRule {
    pub name: String,
    #[serde(default)]
    pub update_types: Option<Vec<UpdateTypeToken>>, // None = matches every kind
}

pub enum UpdateTypeToken { Major, Minor, Patch }

/// `safe_auto_discovered_policy` widened one level: reverts every `CliConfig`
/// field not on the explicit allowlist to its default, so a field added to
/// `CliConfig` (like `update`) is safe-by-default rather than
/// attacker-controlled by default. Used only by `check`'s auto-discovery
/// path; `update` never calls it (FR-007 — no auto-discovery at all).
pub fn safe_auto_discovered_config(parsed: CliConfig) -> CliConfig {
    CliConfig {
        policy: PolicyConfig { diagnostics: /* six existing *_severity values */, ..PolicyConfig::default() },
        ..CliConfig::default()   // update: UpdateConfig::default(), by omission
    }
}
```

```rust
// deps-cli/src/update/mod.rs

pub struct UpdatePlan {
    pub items: Vec<PlannedUpdateItem>,
}

pub struct PlannedUpdateItem {
    pub name: String,
    pub current: String,
    pub target: String,
    pub outcome: Outcome,
    pub edit: Option<deps_core::edit::ManifestEdit>,
}

pub enum Outcome {
    Applied,
    Skipped(SkipReason),
    RequiresLockfileUpdate,
    Unfixable(UnfixableReason),
}

pub enum SkipReason { IgnoreRule, NotRequested, UnclassifiableUpdateKind }
pub enum UnfixableReason { FetchFailedOrAbsent, Yanked, TargetStillVulnerable }
```

## 4. API Design

Not applicable — no HTTP/RPC surface. User-facing surface:

```
deps-cli update <MANIFEST>
    [--package <NAME>]...
    [--security-only]
    [--dry-run]
    [--format table|json]
    [--config <path>]
    [--offline]
    [--cooldown <duration>]
```

No `--respect-gitignore`, no `--follow-symlinks` (Out of Scope). `UpdateArgs`
duplicates `CheckArgs`' `--config`/`--offline`/`--cooldown` clap attributes
rather than flattening a shared `CommonArgs` struct, so `CheckArgs`' public
field layout (a post-1.0-adjacent, tested surface) is untouched (NFR-005).

## 5. Data Flow (single manifest)

```
walk::walk(&[path], registry, ..) -> exactly one manifest
  -> read_to_string_capped
  -> analyze_manifest -> ManifestAnalysis

default mode:
  collect_update_edits(analysis.version_data())
    -> --package allowlist filter
    -> [update].ignore filter (classify_update against the resolved in-use version;
       Unknown fails closed per FR-006)
    -> plan

--security-only mode:
  osv_name_by_key(build_scan_targets(..))
    -> collect_fix_target_resolutions (empty latest_native_by_key)
    -> OsvClient::check_candidates
    -> apply_live_fix_target_statuses
    -> plan_vulnerability_fix per Vulnerable dependency
    -> yank filter (native-form comparison against cached PackageVersions.yanked,
       gated on blocks_resolution(); two-signal Unfixable per FR-011)
    -> --package filter
    -> ignore rules NOT applied (FR-008 override)
    -> plan, retaining RequiresLockfileUpdate / Unfixable items for reporting

then, both modes:
  dedup_overlapping_edits(plan's edits)
    -> apply_edits(original_content, edits) -> new_content
    -> re-read manifest, byte-compare against original_content snapshot
       -> mismatch: abort, exit 2 (FR-019)
    -> write_atomic(path, new_content)   (skipped entirely under --dry-run)
    -> render_update(&plan)              (table or json, per --format)
    -> update_exit_code(&plan)
```

## 6. Security

- **Symlink refusal (FR-017)**: `write_atomic` checks the manifest path's
  final component before creating any temp file. `OpenOptions::create_new`
  additionally fails (`EEXIST`) if anything — including a dangling symlink
  — already exists at the temp path, closing the classic
  symlink-pre-creation race by open-mode rather than by guessing an
  unpredictable temp name.
- **Permission handling (FR-016, corrected per critic finding N3)**: platform
  split, not a "read-or-fallback-and-restore" sequence (which is
  self-contradictory — there is nothing to restore to if the mode was never
  readable). On Unix: read the original file's mode via `metadata()`,
  `set_permissions` on the *open temp handle* before any content is
  written (not after, which would leave a `0600` manifest's content briefly
  world-readable under its temp name). On Windows: skip the permission-copy
  step entirely; the destination directory's inherited ACL governs the
  renamed file. `sync_all` covers the file's own durability; it does not by
  itself guarantee the rename's directory entry survives a crash — that
  would additionally need the parent directory fsynced, which this feature
  does not implement (documented gap, not a claimed guarantee).
- **TOCTOU (FR-019)**: re-read-and-byte-compare before writing narrows, but
  does not close, the race — `rename(2)` has no compare-and-swap primitive.
  Accepted: `update` is an operator-invoked, foreground command, not a
  background daemon racing arbitrary writers.
- **Positive property to preserve (FR-018)**: `fs::rename`'s target-side
  symlink is replaced, not followed, on every platform this project
  targets. A symlink swapped in for the manifest after the TOCTOU check
  passes has the symlink itself replaced, not its target's content. A
  future "simplification" to `fs::write` would silently lose this and must
  not be made without re-deriving the guarantee.
- **`--security-only` Unfixable rule (FR-011, critic finding N1)**: the
  two-signal check (`fetch_failed` OR absent `PackageVersions` entry) is
  **load-bearing**, not redundant defense-in-depth. The disjointness
  between `FetchResult::fetch_failed` and `FetchResult::versions` is
  established inside `fetch_and_classify_package`
  (`crates/deps-engine/src/classify/fetch.rs:605-825` — every arm setting
  `failed_name` returns `None` for `version`, and vice versa), by
  convention across a ~220-line `match`, not by the type system. The
  aggregation loop that actually populates both maps
  (`fetch.rs:492-515`) enforces nothing on its own — it would happily
  accept a future producer that returns both. Checking both signals means
  a future change that broke the disjointness degrades to fail-closed
  (dependency lands in one map or the other, either way still caught)
  rather than silently admitting a stale-but-present entry through the
  yank filter.
- **Yank-check comparison form (FR-012)**: comparing OSV's wire-form
  version string directly against `PackageVersions::yanked` would silently
  never match for any ecosystem whose OSV and native spellings diverge
  (PyPI, Maven, NuGet), turning the filter into a no-op that writes a
  yanked target while exiting 0. The comparison must go through
  `formatter.osv_version_to_native` first, matching the LSP path's own
  comparison (`code_actions.rs:595-601`).
- **`reports_yanked() == false` fail-open (FR-013, critic finding N4)**:
  documented, accepted limitation, not silence. `yanked_list` is built as
  `Arc::from([])` whenever the registry cannot report removal status
  (`fetch.rs:617-629`), so the yank filter is structurally inert for those
  ecosystems. The alternative — classifying every such dependency
  `Unfixable` — would disable `--security-only` entirely for them, which is
  a worse outcome than the documented fail-open `deps-lsp` already accepts
  for the same case.
- **`--security-only` availability gate (FR-015)**: hard-errors under
  `network.offline`/`vulnerabilities_enabled = false` rather than silently
  scanning zero dependencies and exiting 0 — the same fail-closed pattern
  `config.rs`'s F1-follow-up hardening already established for `check`.

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|---------------|-------------------|
| Unit/regression | `cargo nextest`, existing `#[cfg(test)]` modules in `code_lenses.rs`/`code_actions.rs` | FR-001: every existing test/insta snapshot for `collect_update_all_edits`/`build_vulnerability_fix_action` passes unchanged after the extraction | 0 changed assertions (SC-001) |
| Unit | `cargo nextest`, new `edit.rs` test module | `classify_update` cross-ecosystem matrix (FR-004, NFR-006): Cargo/npm/PyPI semver bumps, GitHub Actions SHA pins, Go pseudo-versions, Maven/NuGet ranges, Gradle `{strictly}!!{preferred}`, `*`/`latest`/`workspace:*` | Every FR-004 counterexample has a dedicated case |
| Unit | `cargo nextest`, `edit.rs` | `dedup_overlapping_edits<E>` generic behavior preserved for both `ManifestEdit` and `ls_types::TextEdit` instantiations | Existing LSP dedup tests pass unchanged; one new test for `ManifestEdit` |
| Unit | `cargo nextest`, `fs_probe.rs`, `tempfile::TempDir` fixtures | `write_atomic`: symlink refusal (FR-017), Unix permission-copy-before-write ordering (FR-016), rename-replaces-symlink property (FR-018, `#[cfg(unix)]`) | One test per property |
| Integration | `cargo nextest`, `deps-cli/tests/` or inline | US-001/US-002 default-mode flows; US-003 three-outcome `--security-only` flow (mixed fixture); US-004 ignore-rule override under `--security-only`; US-005 `--dry-run`/`--format json`; US-006 symlink refusal end-to-end | Each acceptance-criteria block in spec §2 has a corresponding test |
| Integration | Divergent OSV/native version-spelling fixture (PyPI, Maven, or NuGet) | FR-012's yank-check comparison form is not a silent no-op (SC-005) | At least one ecosystem with a confirmed OSV/native spelling divergence |
| Live | Manual, per `.claude/rules/continuous-improvement.md` | Real `deps-cli update`/`--security-only` run against a real manifest and live OSV/registry data before considering the feature done | Constitution principle 5 |

## 8. Performance Considerations

- FR-012's yank filter and vulnerability-key lookup use the prebuilt map
  from `build_scan_targets`/`osv_name_by_key`, never rebuilding it per
  dependency — O(n) over the manifest's dependency count, matching the
  sibling `collect_update_edits`'s existing documented avoidance of the
  same O(n²) pattern.
- `write_atomic`'s extra `metadata`/`set_permissions`/`sync_all` calls are
  bounded to one invocation per `update` run (single manifest, MVP scope) —
  not a hot path.
- The TOCTOU re-read (FR-019) is one extra `read_to_string_capped` call per
  run, negligible relative to the network round-trips the OSV
  re-verification (FR-009) already requires.

## 9. Rollout Plan

Single PR sequence (see tasks.md for ordering), pre-1.0, no feature flag
beyond the CLI subcommand itself (inherently opt-in — nothing existing
calls `deps-cli update`). No migration needed.

## 10. Constitution Compliance

| Principle | Status | Notes |
|-----------|--------|-------|
| 1. One fix, one place | Compliant | `deps_core::edit` is the single home for both planners and the generic dedup; `deps-lsp` and `deps-cli` both consume it rather than each having their own copy |
| 5. Verify live, not just in CI | Compliant (planned) | A manual `deps-cli update`/`--security-only` run against real registry/OSV data is required before this is considered done (§7 Testing Strategy, Live row) |
| 7. Pre-1.0 clean breaks | Compliant | `dedup_overlapping_edits`'s generic signature change is a direct breaking change, documented via a `### Breaking` CHANGELOG entry (FR-023), no deprecation shim |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|--------------|------------|
| The `deps_core::edit` extraction subtly changes LSP-observable behavior (e.g. a difference in how `tracing::warn!` logs a generic `E`'s range, or an ordering change in `dedup_overlapping_edits`) | Medium | Low | FR-001/SC-001: the full existing `code_lenses.rs`/`code_actions.rs` test and insta-snapshot suite must show zero changes; log the `EditSpan::start`/`end` tuple explicitly rather than a field a generic `E` doesn't have |
| `fetch_and_classify_package`'s disjointness invariant (FR-011's load-bearing assumption) is broken by an unrelated future refactor | Medium | Low | The two-signal check itself is the mitigation — a broken invariant degrades to fail-closed, not to a silent yank-filter bypass; this plan documents the invariant's exact location so a future reviewer touching `fetch.rs:605-825` is warned |
| A wrapper script assumes `update --security-only`'s exit code alone tells it whether the working tree changed | High (silently skips committing a real fix) | Medium | FR-022 states the contract explicitly in the spec and this plan; `--format json`'s per-item `outcome` field is the documented alternative for #1117 |
| Yank-check comparison form regresses to comparing OSV wire-form directly (an easy mistake to reintroduce during a later refactor) | High (silent no-op, writes a yanked target) | Low | FR-012 and this plan's Security section spell out the exact comparison; SC-005's divergent-spelling test fails loudly if regressed |

## See Also

- [[spec]] — feature specification
- [[tasks]] — implementation tasks (after this phase)
- [[MOC-specs]] — all specifications
- `crates/deps-core/src/lsp_helpers/code_lenses.rs`, `code_actions.rs`, `in_use_version.rs` — extraction sources
- `crates/deps-engine/src/classify/fetch.rs` (`fetch_and_classify_package`, `fetch_latest_versions_parallel`), `classify/osv.rs` (`collect_fix_target_resolutions`, `apply_live_fix_target_statuses`, `build_scan_targets`)
- `crates/deps-cli/src/config.rs` (`safe_auto_discovered_policy`, `ignored_sections`, `load`), `report.rs` (`check_manifest`)

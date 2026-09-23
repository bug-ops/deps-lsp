---
aliases:
  - deps-cli update subcommand
  - CLI Dependency Update Automation
tags:
  - sdd
  - spec
  - deps-cli
  - deps-core
  - security
created: 2026-09-23
status: draft
related:
  - "[[constitution]]"
---

# Feature: deps-cli update subcommand

> [!info] Metadata
> **Author**: Andrei G.
> **Branch**: feat/1115-cli-update-subcommand
> **Resolves**: #1115 (subcommand + `--package` selection), #1119 (`[update].ignore` config), #1120 (`--security-only` vulnerability-driven selection)
> **Epic**: #1114 (deps-cli as a full Dependabot replacement)
> **Design provenance**: three rounds of architect/critic adversarial review
> (`.local/handoff/2026-09-23T00-47-49-architect.md` through
> `2026-09-23T01-27-46-critic.md`); final verdict `minor`, cleared for spec-writing.

## 1. Overview

### Problem Statement

`deps-cli check` (spec [[062-cli-check-mode/spec|062]]) can *report* that a
dependency is outdated, unknown, yanked, vulnerable, or unsatisfiable, but it
cannot *act* on that report — every remediation deps-lsp already offers
interactively (the "update all outdated" code lens, the per-dependency
vulnerability-fix code action) exists only behind an LSP client. A CI
pipeline or a scripted workflow has no non-interactive way to apply those
same edits.

The edit-planning logic that would need to be reused
(`collect_update_all_edits`, `build_vulnerability_fix_action`) lives behind
`deps-core`'s `lsp-responses` feature and returns
`tower_lsp_server::ls_types` values, while CI (`.github/workflows/ci.yml`,
spec [[064-deps-cli-lsp-isolation/spec|064]], #1083) forbids
`tower-lsp-server` from reaching `deps-cli`'s non-dev dependency tree. Reuse
therefore cannot be a direct call — it must be an extraction into a new,
ungated `deps_core::edit` module that both the LSP handlers and the new CLI
subcommand consume, following the same shape spec 064 already applied to
`Diagnostic` and spec 063 applied to `Dependency`/`LockFileCache` (protocol-
agnostic domain types, thin LSP adapters on top).

### Goal

`deps-cli update <MANIFEST>` reads exactly one manifest, plans a set of
version-requirement edits, and writes them back atomically:

- **Default mode**: every dependency `check` would report `Outdated` is a
  candidate, narrowed by `--package <NAME>` (repeatable) and by
  `[update].ignore` rules read from an explicit `--config <path>` (#1119).
- **`--security-only` mode** (#1120): only dependencies OSV reports
  `Vulnerable` are candidates, targeting `recommended_fix()` (never
  `latest`), independently re-verified against OSV before being written, and
  never suppressed by an ignore rule.

`deps-lsp`'s existing code-lens/code-action behavior stays byte-identical
after the `deps_core::edit` extraction — this is a testable constraint, not
an aspiration (see FR-001).

### Out of Scope

Explicitly deferred — do not design or task any of the following here:

- **Lockfile regeneration** (#1116) — `update` rewrites declared version
  requirements only; a requirement that already admits a vulnerable resolved
  version is reported as `RequiresLockfileUpdate`, not remediated.
- **Git branch/commit/PR automation** (#1117) — `update` only writes to the
  working tree; it never touches git. #1117 consumes this feature's
  `--format json` output.
- **Update grouping config** (#1118).
- **Bulk multi-manifest mode and its transactional write semantics** —
  `update` takes exactly one explicit manifest path; a directory, a glob,
  or a path no ecosystem claims is an execution error (exit 2). This
  removes the partial-write hazard entirely (one file, no transaction
  needed) rather than deferring it. Revisiting this needs its own spec.
- **Ignore-rule name wildcards** (e.g. `@types/*`) — `[update].ignore` names
  are matched exactly (after `formatter.normalize_package_name` on both
  sides).
- **New vulnerability data sources** (#1121) — `--security-only` uses the
  same OSV.dev integration `check`/deps-lsp already have.
- **`--respect-gitignore` / `--follow-symlinks` on `update`** — an
  explicitly named manifest path is already an explicit choice; these flags
  from `check` (spec [[065-cli-check-symlink-manifest-walk/spec|065]]) would
  only turn a user-named file into a confusing "not a single recognized
  manifest" error.
- **Full Dependabot `update_types` semantics** (retargeting an
  ignored-major dependency to the highest non-major version) — an ignored
  update is skipped entirely, not retargeted; this must be documented in
  the book, not silently assumed away.
- **Fixing `deps-lsp`'s `build_vulnerability_fix_action`'s own S1 gap**
  (implementation code review, round 3) — the CLI's `--security-only`
  planner (`deps-cli::update::security`) checks whether the declared
  requirement already admits the fix target before rewriting it
  (`RequiresLockfileUpdate` instead); `deps-lsp`'s shared
  `plan_vulnerability_fix`-backed code action does not have this check,
  and can still offer a rewrite that would collapse to a no-op. Fixing it
  there is explicitly out of scope for this PR — FR-001 requires
  `deps-lsp`'s code-lens/code-action behavior to stay byte-identical
  (zero snapshot changes) after the `deps_core::edit` extraction, and
  this divergence exists precisely because the S1 fix was scoped to the
  CLI-only wrapper to satisfy that constraint, not shared `plan_vulnerability_fix`
  logic touching frozen LSP behavior. A follow-up GitHub issue tracks the
  `deps-lsp` side separately.

## 2. User Stories

### US-001: Apply all eligible outdated-dependency updates to one manifest

AS A maintainer running dependency maintenance outside an editor
I WANT `deps-cli update Cargo.toml` to rewrite every outdated dependency's
version requirement to its latest matching version in one pass
SO THAT I don't have to open every manifest in an editor to accept each
code-lens update individually

**Acceptance criteria:**
```
GIVEN a Cargo.toml with three dependencies, two Outdated and one already
  at the latest matching version
WHEN `deps-cli update Cargo.toml` runs with no other flags
THEN the two Outdated dependencies' version requirements are rewritten to
  their latest matching version, the third is left untouched, and the
  process exits 0
```

### US-002: Scope an update to one named dependency

AS A maintainer who wants to bump a single dependency without touching the
rest of the manifest
I WANT `--package <NAME>` (repeatable) to narrow the update set
SO THAT I retain manual control over the blast radius of a single run

**Acceptance criteria:**
```
GIVEN the same three-dependency Cargo.toml as US-001
WHEN `deps-cli update --package serde Cargo.toml` runs and `serde` is
  Outdated
THEN only `serde`'s version requirement is rewritten; the other Outdated
  dependency is left untouched and reported as `skipped (not-requested)`
```

### US-003: Remediate a known vulnerability without silently reporting success

AS A security engineer running `deps-cli update --security-only` in a
scheduled job
I WANT every `Vulnerable` dependency classified into exactly one of
`Applied` / `RequiresLockfileUpdate` / `Unfixable`, with a non-zero exit
whenever at least one dependency was not actually remediated
SO THAT the job cannot report exit 0 while a known-vulnerable dependency's
declared requirement is left untouched

**Acceptance criteria:**
```
GIVEN a manifest declaring `serde = "1"` where the resolved/locked version
  1.0.1 is Vulnerable and the advisory's recommended_fix is 1.0.2, already
  admitted by the declared requirement "1"
WHEN `deps-cli update --security-only Cargo.toml` runs
THEN no requirement-level edit is written for `serde` (its declared
  requirement already admits the fix), the item is reported as
  `RequiresLockfileUpdate` referencing #1116, and the process exits 1

GIVEN a manifest declaring `foo = "0.9"` where 0.9.x is Vulnerable and
  recommended_fix is 0.10.3, not admitted by "0.9"
WHEN `deps-cli update --security-only Cargo.toml` runs and the live OSV
  re-verification (§FR-009) confirms 0.10.3 is not itself vulnerable, and
  0.10.3 is not present in the registry's yanked list
THEN `foo`'s requirement is rewritten to admit 0.10.3, the item is reported
  `Applied`, and (if this is the only vulnerable dependency) the process
  exits 0
```

### US-004: Configure ignore rules that do not silently reduce security coverage

AS A maintainer who wants to defer major-version bumps for specific
dependencies but never wants that preference to block a security fix
I WANT `[update].ignore` rules (loaded only from an explicit `--config`)
that scope by dependency name and, optionally, by update kind
SO THAT routine maintenance respects my stated preferences while
`--security-only` runs are never silently held back by them

**Acceptance criteria:**
```
GIVEN --config deps.toml with
  `[update] ignore = [{ name = "tokio", update_types = ["major"] }]`
  and `tokio`'s latest matching version is a major bump
WHEN `deps-cli update --config deps.toml Cargo.toml` runs (default mode)
THEN `tokio` is skipped, reported `skipped (ignore-rule)`, and the run
  still exits 0 if every other selected dependency was applied

GIVEN the same ignore rule and `tokio` is additionally `Vulnerable`, with
  its recommended_fix being a major bump
WHEN `deps-cli update --config deps.toml --security-only Cargo.toml` runs
THEN the ignore rule is overridden — `tokio` is still evaluated for the
  security fix — and the run reports that the matching ignore rule was
  overridden rather than silently applying the rule
```

### US-005: Preview a run and consume its result programmatically

AS A future automation consumer (#1117) deciding whether to commit a
resulting diff
I WANT `--dry-run` to plan without writing, and `--format json` to emit a
per-item `outcome` field
SO THAT a wrapper script can decide what to do with the working tree
without depending on the process exit code alone

**Acceptance criteria:**
```
GIVEN the US-003 mixed scenario (one Applied, one RequiresLockfileUpdate)
WHEN `deps-cli update --security-only --format json Cargo.toml` runs
THEN the process exits 1 (US-003), but the JSON output's `serde` item has
  `"outcome": "requires-lockfile-update"` and the `foo` item (if present)
  has `"outcome": "applied"` with its edit already written to disk —
  proving that exit 1 does not mean the working tree is unchanged
```

### US-006: A crash or a symlinked manifest cannot corrupt or escape the target

AS A maintainer running `update` unattended
I WANT the write path to be crash-safe and to refuse writing through a
symlink
SO THAT a killed process leaves the original manifest intact, and a
manifest path that is itself a symlink cannot be used to write outside the
intended file

**Acceptance criteria:**
```
GIVEN a manifest path whose final path component is a symlink
WHEN `deps-cli update` targets that path
THEN the run refuses to write (exit 2) before opening any temp file, and
  the symlink and its target are both left unmodified

GIVEN a normal (non-symlink) manifest and a simulated write failure between
  temp-file creation and rename
WHEN the failure occurs
THEN the original manifest's content is unchanged (the temp file, not the
  original, absorbed the partial write) and the temp file is removed
```

## 3. Functional Requirements

EARS notation. Type: **U** = ubiquitous, **E** = event-driven, **S** =
state-driven, **UB** = unwanted-behavior, **O** = optional-feature.

| ID | Type | Requirement | Priority |
|----|------|-------------|----------|
| FR-001 | U | THE SYSTEM SHALL produce byte-identical `deps-lsp` hover/code-lens/code-action output before and after the `deps_core::edit` extraction — `collect_update_all_edits` and `build_vulnerability_fix_action` become thin adapters over `deps_core::edit::collect_update_edits`/`plan_vulnerability_fix`, never reimplementations, verified by the existing `code_lenses.rs`/`code_actions.rs` test and insta-snapshot suite staying unchanged | must |
| FR-002 | E | WHEN `deps-cli update` is invoked THE SYSTEM SHALL accept exactly one explicit manifest path (via the existing `walk::walk` single-path routing) and SHALL treat a directory, a glob expanding to more than one path, or a path no ecosystem's `manifest_filenames`/`manifest_patterns`/`manifest_extensions`/`manifest_directory_patterns` claims as an execution error (exit 2) | must |
| FR-003 | E | WHEN planning the default (non-`--security-only`) edit set THE SYSTEM SHALL derive each candidate's `from` version via `resolve_in_use_version` per occurrence (never the collapsed per-name map, so a renamed/aliased dependency classifies against its own pin, per the fix in spec [[050-cargo-renamed-dependency-lockfile-resolution/spec\|050]]) and SHALL classify it `UpdateKind::Unknown` when `resolve_in_use_version` returns `None` | must |
| FR-004 | U | `classify_update(from, to)` SHALL return `UpdateKind::Unknown` unless both `from` and `to` have an unambiguous leading dotted-numeric segment; it SHALL NOT reuse `is_same_major_minor` (whose `_ => true` fallback arm is wrong for this purpose) and SHALL classify GitHub Actions SHA pins, Go pseudo-versions, Maven/NuGet range syntax, `*`/`latest`/`workspace:*`, and Gradle `{strictly}!!{preferred}` syntax as `Unknown` | must |
| FR-005 | E | WHEN `--package <NAME>` is passed (repeatable) THE SYSTEM SHALL select only dependencies whose name matches one of the given values after `formatter.normalize_package_name` is applied to both sides | must |
| FR-006 | E | WHEN a dependency's normalized name matches an `[update].ignore` rule THE SYSTEM SHALL skip it (`SkipReason::IgnoreRule`) if the rule has no `update_types` (matches every kind including `Unknown`), or if the rule's `update_types` contains the dependency's classified kind, or if the dependency's classified kind is `Unknown` (fail-closed: an `update_types`-scoped rule that cannot confirm an update is below its stated threshold treats it as if it met the threshold, per FR-004) | must |
| FR-007 | UB | `deps-cli update` SHALL NOT auto-discover a `./deps.toml` (or any ancestor config file) under any circumstance; `[update].ignore` rules SHALL be read only when `--config <path>` is passed explicitly, and the config `load` call's `required` parameter SHALL always be `true` on this path | must |
| FR-008 | E | WHEN `--security-only` is passed THE SYSTEM SHALL override every `[update].ignore` rule entirely — a rule that would have matched a `Vulnerable` dependency SHALL still be evaluated as a candidate, and the run SHALL report that the matching rule was overridden rather than applying it silently | must |
| FR-009 | E | WHEN `--security-only` is passed THE SYSTEM SHALL target `DependencyVulnerabilities::recommended_fix()` (never the freshness-filtered `latest`) for every dependency OSV classifies `Vulnerable`, and SHALL independently re-verify each fix target by running `deps_engine::classify::osv::{collect_fix_target_resolutions, apply_live_fix_target_statuses}` plus `OsvClient::check_candidates` in the CLI itself, passing an **empty** `latest_native_by_key` map (the CLI runs no phase B.1 shortcut, so a populated map would falsely resolve every target to `NotChecked` and suppress every fix — see plan.md §Security) | must |
| FR-010 | U | THE SYSTEM SHALL classify every `--security-only` candidate into exactly one of three outcomes: `Applied` (a fix plan existed and its edit was written; contributes to exit 0), `RequiresLockfileUpdate` (the dependency is `Vulnerable` but the declared requirement already admits the fix target, so no requirement-level edit exists; exit 1, references #1116), or `Unfixable` (no verified fix target, timed-out or failed fetch, or an unreportable-yank-status ecosystem's residual risk per FR-013; exit 1) — no outcome SHALL allow the run to exit 0 while a `Vulnerable` dependency was left unremediated | must |
| FR-011 | UB | WHEN a dependency appears in `FetchResult::fetch_failed` **or** has no corresponding `PackageVersions` entry THE SYSTEM SHALL classify it `Unfixable` under `--security-only`. This two-signal check is **load-bearing, not redundant defense-in-depth**: the two conditions are equivalent today only because `fetch_and_classify_package` (`crates/deps-engine/src/classify/fetch.rs:605-825`) upholds the disjointness by convention across a large `match`, not by the type system — a future refactor of that function could silently break the equivalence, and checking both signals degrades to fail-closed rather than silently dropping the yank filter if it ever does | must |
| FR-012 | E | WHEN filtering a `--security-only` fix target for yank status THE SYSTEM SHALL compare `formatter.osv_version_to_native(&fix.version)` against each entry's native form (`ConcreteVersion::as_str()`) in the cached `PackageVersions::yanked` list, gated on `RemovalStatus::blocks_resolution()`, using the ecosystem's normalized-then-raw name fallback for the `PackageVersions` lookup, and SHALL use the prebuilt vulnerability-keys map (never rebuild it per dependency — an O(n²) pattern the sibling collector already documents avoiding) | must |
| FR-013 | UB | WHERE the target ecosystem's registry reports `reports_yanked() == false` THE SYSTEM SHALL accept that the yank filter is inert for that dependency (fail-open, matching `deps-lsp`'s existing behavior) rather than classifying it `Unfixable` solely for that reason; this limitation SHALL be stated explicitly in this spec, in `--security-only`'s CLI help/doc text, and in the mdBook CLI reference — it is a documented limitation, not a discovered one | must |
| FR-014 | E | WHEN `--cooldown` is passed together with `--security-only` THE SYSTEM SHALL print a warning that it has no effect (the security fix target comes from the advisory via `recommended_fix()`, never from the freshness-filtered registry pick) and SHALL proceed rather than reject at parse time; a `[freshness]` cooldown value sourced from `--config` SHALL receive the same treatment (no special-cased rejection) | must |
| FR-015 | UB | WHEN `--security-only` is passed together with `network.offline = true` or `diagnostics.vulnerabilities_enabled = false` THE SYSTEM SHALL hard-error (exit 2) rather than silently scanning zero dependencies and exiting 0 | must |
| FR-016 | U | THE SYSTEM SHALL write manifest edits via `deps_core::fs_probe::write_atomic(path, content)`: create the temp file in the manifest's own directory with `OpenOptions::create_new(true)` (`O_CREAT|O_EXCL`, closing the symlink-pre-creation race by open-mode, not by name unpredictability); on Unix, read the original file's mode and set it on the temp file's open handle **before** writing any content; on Windows (no Unix mode bits), skip the permission-copy step and rely on the destination directory's inherited ACL; then `sync_all` the file and `fs::rename` it over the original | must |
| FR-017 | UB | `write_atomic` SHALL refuse to write (return an error, no temp file created) when the target manifest path's final path component is itself a symlink | must |
| FR-018 | U | THE SYSTEM SHALL preserve, and future refactors SHALL NOT remove, the positive property that `fs::rename`'s target-side symlink is replaced rather than followed — a switch to `fs::write` would silently lose this guarantee and must not be made without re-deriving it | must |
| FR-019 | E | WHEN the plan is ready to be written THE SYSTEM SHALL re-read the manifest via `fs_probe::read_to_string_capped` and compare it byte-for-byte against the content snapshot the plan's ranges were computed against, and SHALL abort with an execution error (exit 2, no write) if they differ; this narrows, but does not close, the TOCTOU window — a concurrent editor save between the compare and the `rename` can still be clobbered, and this is an accepted, documented limitation (`rename(2)` has no compare-and-swap) | must |
| FR-020 | O | WHERE `--dry-run` is passed THE SYSTEM SHALL perform planning and reporting exactly as a normal run would, but SHALL NOT call `write_atomic` | must |
| FR-021 | O | WHERE `--format json` is passed THE SYSTEM SHALL emit a versioned JSON document with, per item: name, current version, target version, `outcome` (`applied` / `skipped` / `requires-lockfile-update` / `unfixable`), a reason, and (in `--security-only` mode) the advisory ids | must |
| FR-022 | U | THE SYSTEM SHALL treat a non-zero exit code as never implying an unmodified working tree: a mixed run (some items `Applied`, others not) exits 1 with real edits already on disk; a consumer (e.g. the future #1117 automation) deciding whether to act on the result SHALL branch on each item's `outcome` field in `--format json` output, never on the process exit code alone | must |
| FR-023 | U | `dedup_overlapping_edits`'s generic `EditSpan`-parameterized signature (`deps_core::edit`) IS a breaking `pub` API change on `deps-core` — THE SYSTEM'S changelog SHALL carry a `### Breaking` entry under `[Unreleased]` for it, with no crate version bump required in the feature PR itself | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | `deps-lsp`'s code-lens count and code-action edit content must be provably unaffected by the `deps_core::edit` extraction — see FR-001; any test or snapshot change in `code_lenses.rs`/`code_actions.rs` during this feature's implementation is a signal the extraction is not a pure move |
| NFR-002 | Security | `--security-only` can never exit 0 while leaving a `Vulnerable` dependency's declared requirement unremediated and unreported (FR-010); it can never silently scan zero dependencies under `network.offline`/`vulnerabilities_enabled = false` (FR-015); the yank filter never trusts a stale or absent registry entry (FR-011) |
| NFR-003 | Security | The write path never follows a symlink on the manifest's final path component, in either direction (refusal on read per FR-017, non-following `rename` on write per FR-018) |
| NFR-004 | Performance | The `--security-only` yank filter and vulnerability-key lookup are O(n) over the manifest's dependencies, not O(n²) (FR-012) |
| NFR-005 | Compatibility | `CheckArgs`' existing public field layout and clap surface are untouched — `UpdateArgs` duplicates the relevant ~15 lines of clap attributes rather than introducing a shared `CommonArgs` flatten that would change `CheckArgs`' shape |
| NFR-006 | Test coverage | Every FR above has at least one dedicated test; `UpdateKind::classify_update` has a cross-ecosystem test matrix covering at minimum Cargo/npm/PyPI (semver), GitHub Actions (SHA pins), Go (pseudo-versions), Maven/NuGet (range syntax), and Gradle (`{strictly}!!{preferred}`) |
| NFR-007 | Durability | `write_atomic`'s `sync_all` durability guarantee is documented as covering only the file's own content, not the rename's directory-entry durability (which would additionally need the parent directory fsynced) — stated as an accepted limitation, not implemented in this feature |

## 5. Data Model

New/changed entities (see plan.md §3 for full type signatures):

| Entity | Location | Description |
|--------|----------|-------------|
| `ManifestEdit` | `deps_core::edit` (new, ungated) | `{ range, new_text }` — protocol-agnostic replacement for `ls_types::TextEdit` |
| `PlannedUpdate` | `deps_core::edit` | An edit with attribution: `{ name, normalized_name, name_range, current, target, edit }` |
| `EditSpan` (trait) | `deps_core::edit` | `{ start() -> (u32,u32), end() -> (u32,u32) }`; implemented by `ManifestEdit` (ungated) and, in the `lsp-responses`-gated module, by `ls_types::TextEdit` |
| `dedup_overlapping_edits<E: EditSpan>` | `deps_core::edit` | Generic over `EditSpan` — the breaking-change function (FR-023) |
| `UpdateKind` | `deps_core::edit` | `Major \| Minor \| Patch \| Unknown` |
| `classify_update(from, to) -> UpdateKind` | `deps_core::edit` | See FR-004 |
| `collect_update_edits` | `deps_core::edit` | Default-mode planner, body moved from `code_lenses.rs:143-222` |
| `plan_vulnerability_fix` | `deps_core::edit` | Security planner, body moved from `code_actions.rs:98-220`; yank/timeout filtering stays with callers |
| `write_atomic(path, content) -> io::Result<()>` | `deps_core::fs_probe` | See FR-016/FR-017 |
| `UpdateConfig` / `IgnoreRule` / `UpdateTypeToken` | `deps_cli::config`, on `CliConfig` (already `#[non_exhaustive]`) | `[update]` config section (#1119) |
| `UpdatePlan` / `PlannedUpdateItem` / `Outcome` / `SkipReason` | `deps_cli::update` | Per-manifest plan and per-item disposition |
| `osv_name_by_key(&[ScanTarget]) -> HashMap<String, String>` | `deps_engine::classify::osv` | Two-line projection reused from `deps-lsp`'s identical inline logic (`document/osv_scan.rs:116`) |

### Config schema (#1119)

```toml
[update]
ignore = [
  { name = "tokio",            update_types = ["major"] },
  { name = "tower-lsp-server",  update_types = ["major"] },
  { name = "legacy-thing" },   # no update_types = every kind, including Unknown
]
```

Tokens: `major` / `minor` / `patch`; any other token is a hard config error
(`deny_unknown_fields` spirit). Names are matched exactly after
`formatter.normalize_package_name` on both sides (wildcards deferred, see
Out of Scope). Honored only from an explicit `--config <path>` (FR-007);
never honored in `--security-only` mode (FR-008, override not suppression).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every selected update was applied, or nothing was eligible, or every non-applied item was a deliberate operator exclusion — a `--package` narrowing (`NotRequested`) or an `[update].ignore` match (`IgnoreRule`) — per US-004's acceptance criterion |
| `1` | At least one item the run *wanted* to fix but could not — an unsafe/unrecognized span (`NotSafelyEditable`), `RequiresLockfileUpdate`, or `Unfixable` |
| `2` | Execution error — not a single recognized manifest (FR-002), oversized/unreadable manifest, parse error, registry unreachable, stale content detected before write (FR-019), write failure, symlinked manifest path (FR-017), or `--security-only` combined with `network.offline`/`vulnerabilities_enabled = false` (FR-015) |

FR-022 applies across this table: exit `1` or `2` never implies the working
tree is byte-identical to before the run.

**Amendment (implementation review S3)**: this table originally listed
*any* `Skipped` item — including an operator-requested `--package`
exclusion or an `[update].ignore` match — under exit `1`, which directly
contradicted US-004's own acceptance criterion ("still exits 0"). The `0`/`1`
rows above are the corrected, implemented behavior: an operator explicitly
asking to skip something is not a failure; only an item the run *wanted* to
apply but could not (`NotSafelyEditable`/`RequiresLockfileUpdate`/`Unfixable`)
drives a non-zero exit. See `exit.rs::update_exit_code`'s doc comment for
the authoritative implementation.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| Manifest path is a directory, a glob, or unclaimed by every ecosystem | Execution error, exit 2 (FR-002) |
| A dependency's declared requirement is a non-literal span (Maven `${property}`, Gradle catalog alias, SHA-pinned GH Action) | Skipped by the inherited literal-span guard already in `collect_update_edits`'s source — not corrupted, not silently rewritten |
| `resolve_in_use_version` returns `None` (no lockfile, requirement not itself a resolved literal) | `UpdateKind::Unknown` (FR-003); still eligible for a default-mode update unless an `[update].ignore` rule with `update_types` matches it (FR-006's fail-closed clause) |
| `[update].ignore` rule's `update_types` includes `major` and the dependency classifies `Unknown` | Skipped anyway (fail-closed, FR-006) — the rule cannot confirm the update is *not* major, so it is treated as if it met the threshold |
| `--security-only` and a dependency is `Vulnerable` but its declared requirement already admits `recommended_fix()` | `RequiresLockfileUpdate`, exit 1, no edit written (US-003, needs #1116) |
| `--security-only` and a dependency's fetch times out or fails, or has no `PackageVersions` entry | `Unfixable`, exit 1 (FR-011, the load-bearing two-signal rule). Deliberately stricter than `deps-lsp`, which fails closed only on a *timed-out* fetch and leaves a plain fetch failure unfiltered (`code_actions.rs:590-604`) — the CLI's broader fail-closed behavior is intentional (the safe direction) and must not be narrowed to match `deps-lsp` |
| `--security-only` and the fix target is present in `PackageVersions::yanked` with `blocks_resolution() == true` | `Unfixable`, exit 1, target not written |
| `--security-only` against an ecosystem whose registry has `reports_yanked() == false` | Yank filter is inert for that dependency; fail-open is accepted and documented (FR-013), not converted to `Unfixable` |
| `--cooldown` passed with `--security-only` | Warning printed, no effect on the fix target, run proceeds (FR-014) |
| `--security-only` with `network.offline = true` or `vulnerabilities_enabled = false` | Hard error, exit 2 (FR-015) |
| Manifest content changes on disk between planning and write (another process/editor) | Abort, exit 2, no write (FR-019) — narrows but does not close the TOCTOU window (a concurrent write landing *after* the compare can still be clobbered; accepted, see NFR docs) |
| Manifest path's final component is a symlink | Refused before any temp file is created, exit 2 (FR-017) |
| Process is killed between temp-file creation and `rename` | Original manifest is untouched; a stray temp file may remain on disk (no automatic sweep in this feature — out of scope) |
| `[update].ignore` entry has an unrecognized `update_types` token | Hard config error at load time |
| `--config` not passed | No `[update].ignore` rules are ever loaded — every dependency is eligible for the default-mode plan, `Unknown`-kind included (FR-007) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Existing `code_lenses.rs`/`code_actions.rs` unit tests and insta snapshots after the `deps_core::edit` extraction | 0 changed (FR-001) |
| SC-002 | `deps-cli update Cargo.toml` (US-001 fixture) | Two Outdated dependencies rewritten, third untouched, exit 0 |
| SC-003 | `deps-cli update --security-only` mixed-outcome fixture (US-003) | `Applied` item's edit on disk, `RequiresLockfileUpdate` item unedited, exit 1 |
| SC-004 | `UpdateKind::classify_update` cross-ecosystem test matrix (NFR-006) | All added and passing, including every `Unknown`-classification counterexample in FR-004 |
| SC-005 | Yank-check native-form comparison test with divergent OSV/native spellings (PyPI, Maven, or NuGet) | Fix target correctly identified as yanked and excluded — proves FR-012 is not a silent no-op |
| SC-006 | `write_atomic` symlink-refusal and TOCTOU-abort tests (US-006, FR-017, FR-019) | Both pass; original manifest content verified byte-identical after a simulated failure |
| SC-007 | `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast` | All pass |
| SC-008 | `CHANGELOG.md` `[Unreleased]` | Contains a `### Breaking` entry for `dedup_overlapping_edits`'s generic signature (FR-023) |

## 8. Agent Boundaries

### Always (without asking)
- Run the full check suite (`cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`) per `.claude/rules/branching.md` before considering any resulting task done
- Move `collect_update_all_edits`'/`build_vulnerability_fix_action`'s bodies into `deps_core::edit` rather than reimplementing equivalent logic in `deps-cli` (constitution principle 1; DRY per global `CLAUDE.md`)
- Keep every existing `deps-core`/`deps-lsp` test and fixture passing unchanged (FR-001, SC-001)
- Add the `### Breaking` CHANGELOG entry for `dedup_overlapping_edits` (FR-023)

### Ask First
- Any change to `CheckArgs`' existing public field layout (NFR-005 — `UpdateArgs` must duplicate clap attributes instead)
- Promoting `tempfile` to a non-optional dependency of `deps-core` instead of using `OpenOptions::create_new(true)` (deliberately rejected during design review — `tempfile` is `optional = true` behind `test-util`, and promoting it would link it into `deps-lsp`'s release binary for a path neither crate uses today)
- Extending `--security-only`'s yank check to treat `reports_yanked() == false` ecosystems as `Unfixable` instead of accepting the documented fail-open (FR-013) — this was a deliberate project decision, not an oversight to "fix"

### Never
- Read or write manifest content before FR-017's symlink refusal and FR-019's TOCTOU re-check both pass
- Auto-discover a `deps.toml` for the `update` subcommand under any flag combination (FR-007)
- Let a `--security-only` run exit 0 while any `Vulnerable` dependency remains in `RequiresLockfileUpdate` or `Unfixable` state (FR-010)
- Rebuild the vulnerability-keys map per dependency inside the security planner (FR-012's O(n²) prohibition)
- Change `dedup_overlapping_edits`'s LSP-facing behavior while generalizing its signature (FR-001/FR-023 — the generalization must be behavior-preserving for the existing `ls_types::TextEdit` caller)

## 9. Open Questions

None. Every design decision reaching this spec passed three rounds of
architect/critic adversarial review
(`2026-09-23T00-47-49-architect.md` → `2026-09-23T01-27-46-critic.md`,
final verdict `minor`); the three critic corrections not yet folded into the
architect's revision 3 text (load-bearing citation for FR-011, the platform
split for FR-016, and the documented fail-open for FR-013) are incorporated
directly into this spec's requirements above, not left as clarification
markers.

## 10. See Also

- [[constitution]] — project principles, especially principle 1 (one fix, one place)
- [[MOC-specs]] — all specifications
- [[062-cli-check-mode/spec]] — the `check` pipeline `update` reuses (`analyze_manifest` extraction)
- [[063-deps-core-domain-boundary-hardening/spec]] — precedent for protocol-agnostic domain-type extraction
- [[064-deps-cli-lsp-isolation/spec]] — the `tower-lsp-server` isolation constraint that forces the `deps_core::edit` extraction
- [[065-cli-check-symlink-manifest-walk/spec]] — `walk::walk`'s single-path routing, reused unchanged by `update`
- [[050-cargo-renamed-dependency-lockfile-resolution/spec]] — precedent for per-occurrence (not per-name) version resolution, reused by FR-003
- Issues #1115, #1119, #1120 (this spec's source), #1114 (epic), #1116/#1117/#1118/#1121 (explicitly deferred, see §1 Out of Scope)
- `crates/deps-core/src/lsp_helpers/code_lenses.rs` (`collect_update_all_edits`, `dedup_overlapping_edits`), `code_actions.rs` (`build_vulnerability_fix_action`, `fix_target_is_verified`), `in_use_version.rs` (`resolve_in_use_version`)
- `crates/deps-engine/src/classify/fetch.rs` (`fetch_and_classify_package`, the FR-011 disjointness invariant), `crates/deps-engine/src/classify/osv.rs` (`collect_fix_target_resolutions`, `apply_live_fix_target_statuses`, `build_scan_targets`)
- `crates/deps-cli/src/config.rs` (`safe_auto_discovered_policy`, `ignored_sections`, `load`)

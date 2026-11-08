---
aliases:
  - Operator-keeping update edits for Bundler and Composer
  - Bundler Composer bare-pin rewrite bug
tags:
  - sdd
  - spec
  - bug
  - cross-ecosystem
  - ecosystem/bundler
  - ecosystem/composer
  - deps-core
  - priority/p2
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec|076 CLI update cooldown fallback]]"
---

# Feature: Update edits keep the Bundler and Composer constraint operator

> [!info] Metadata
> **Author**: sdd (live-testing cycle ci-107 finding, 2026-11-08)
> **Type / priority**: bug, P2, cross-ecosystem (`deps-core`, `deps-bundler`, `deps-composer`)
> **Issue**: to be filed (labels `bug`, `P2`, `cross-ecosystem`)
> **Branch**: suggested `fix/<issue>-keep-bundler-composer-operator`
> **Related shipped work**: #1885 (npm/Deno keep `^`, `~`, `=`; PR #1896), #1892/#1895 (fallback exact pin, partial precision; PR #1898)
> **Phase**: specify. Open `[NEEDS CLARIFICATION]`: 9.

> [!abstract]
> The "update to X" code action, the vulnerability and unsatisfiable-requirement quickfixes, the "Update N outdated" code lens and `deps-cli update` rewrite a Bundler `~> 2.0` and a Composer `^2.0`, `~6.0` or `^5.0@beta` constraint to a bare version. In both package managers a bare version is an exact pin, so the edit silently turns a range into a pin (and Composer also loses its `@beta`/`@dev` stability flag). npm and Deno were fixed in #1885; Cargo, Dart and PyPI already keep their operator. This spec makes the operator-keeping rule a single `deps-core` behavior that Bundler and Composer adopt, with a per-ecosystem table of expected rewrites.

## 1. Overview

### Problem Statement

Observed on `main` (713d6368e) against real registries, fixtures under `.local/testing/fixtures/ci107/ops/`:

| Manifest line | Current edit | Effect |
|---------------|--------------|--------|
| Gemfile `gem "rack", "~> 2.0"` | `3.2.8` | `~> 2.0` allowed any 2.x; the new text allows only 3.2.8, and a later `bundle update` can no longer move it |
| composer.json `"monolog/monolog": "^2.0"` | `3.12.1` | exact pin in Composer |
| composer.json `"guzzlehttp/guzzle": "~6.0"` | `8.3.1` | exact pin |
| composer.json `"symfony/console": "^5.0@beta"` | `8.1.11` | exact pin, `@beta` flag dropped |
| composer.json `"laravel/framework": "^8.0@dev"` | `13.40.0` | exact pin, `@dev` flag dropped |
| Gemfile `gem "json", "2.3.0"` | `3.1.0` | correct (input was already exact) |

Both `deps-cli update` and the LSP code action produce the same text because they share one edit plan.

Root cause by code reading (to be re-verified live before implementation, per the live-testing principle): `BundlerFormatter` does not override `format_version_replacing` and its `format_version_replacing_for` returns `format_version_for_text_edit` (a bare version). `ComposerFormatter::format_version_replacing` only restyles the `v` prefix (`match_v_prefix_style`). Neither calls `deps_core::lsp_helpers::format_version_replacing_by_shape`, which npm and Deno use, and which already keeps `~`, `~>`, `^` and `=` for bare-is-exact ecosystems (`bare_meaning(EcosystemId::Bundler | Composer)` is already `BareMeaning::ExactPin`).

Calling the shared helper alone is not sufficient, for two reasons:

1. Pessimistic operators are precision-sensitive. Bundler `~> 2.0` means `>= 2.0, < 3`, while `~> 3.2.8` means `>= 3.2.8, < 3.3`. Composer `~6.0` and `~6.0.1` differ the same way. The helper writes the full target version (`~> 3.2.8`), which would narrow `~> 2.0` from "any 2.x" to "3.2.x only". The rewrite must preserve the operand's precision.
2. Composer's `@stability` suffix is part of the constraint text and must survive the rewrite.

> [!note] Correction to the finding's control group
> Dart's bare version is an exact pin under pub's grammar (`bare_meaning(EcosystemId::Dart)` is `ExactPin`), not a caret. Dart is still a correct control because its inputs in the repro carry an explicit `^`, which is kept. Only Cargo's bare version is an implicit caret.

### Goal

An update edit for a Bundler or Composer dependency preserves the constraint's operator, operand precision and stability flag, so the rewritten requirement admits the same kind of range as before, now anchored on the chosen version; `deps-cli update` and the LSP code action keep producing identical text.

### Out of Scope

- The `deps-cli update` table's empty "current" column for these dependencies (`[applied] rack  -> 3.2.8`). It is cosmetic and tracked separately; this spec does not change table rendering.
- NuGet, Maven and Gradle. A bare version there is a minimum bound (`BareMeaning::Floor`); the shared helper already refuses to collapse a bounded requirement and keeps `[1.0.0]` brackets. No divergence was found by code reading; not verified live (see Open Questions).
- Completion (`format_version_for_completion`): it inserts a version the user is typing and has no existing operator to preserve.
- Composer branch constraints (`dev-main`, `dev-main as 1.0.x-dev`, `1.0.x-dev`) and VCS/path repositories: they are not version updates.
- Changing which version is picked (latest, cooldown, minimum-stability, vulnerability fix target). Only the rendering of the chosen version changes.
- Cargo, npm, Deno, PyPI and Dart behavior, except the audit item in section 9.

## 2. User Stories

### US-001: Range survives an update (Bundler)
AS A Ruby developer
I WANT "update to latest" on `gem "rack", "~> 2.0"` to produce `~> 3.2`
SO THAT my Gemfile keeps allowing compatible upgrades instead of freezing at one release

**Acceptance criteria:**
```
GIVEN a Gemfile line gem "rack", "~> 2.0" and a registry whose latest is 3.2.8
WHEN I apply the "update to 3.2.8" code action
THEN the quoted literal becomes "~> 3.2"
AND deps-cli update writes the same literal
```

### US-002: Range survives an update (Composer)
AS A PHP developer
I WANT "update" on `"monolog/monolog": "^2.0"` to produce `^3.12`
SO THAT composer.json keeps a caret range instead of an exact pin

**Acceptance criteria:**
```
GIVEN "monolog/monolog": "^2.0" and a registry whose latest is 3.12.1
WHEN I apply the update action or run deps-cli update
THEN the constraint becomes "^3.12"
```

### US-003: Stability flag is kept (Composer)
AS A PHP developer who opted into beta releases for one package
I WANT the `@beta` or `@dev` suffix to survive an update
SO THAT the update does not silently change which stabilities Composer may install

**Acceptance criteria:**
```
GIVEN "symfony/console": "^5.0@beta" and a picked version 8.1.11
WHEN the update edit is planned
THEN the constraint becomes "^8.1@beta"
```

### US-004: Security and fallback targets never lower the floor
AS A maintainer applying a vulnerability fix
I WANT a fix target to be rendered with its full version
SO THAT the rewritten range cannot admit an affected release below the fix

**Acceptance criteria:**
```
GIVEN Gemfile "~> 2.0" and a vulnerability fixed in 2.9.1
WHEN the vulnerability quickfix is planned
THEN the literal becomes "~> 2.9.1"
```

## 3. Functional Requirements

"Operand" is the version part of a constraint after its operator. "Picked version" is the version the edit plan chose. "Floor target" is a vulnerability-fix or cooldown-fallback version (the `format_version_replacing_floor_for` path).

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the declared Bundler or Composer requirement is a single comparator with a `~>`, `~` or `^` operator THE SYSTEM SHALL render the update edit with the same operator spelling (`~>` stays `~>`, `~` stays `~`, `^` stays `^`) and the same whitespace between operator and operand. | must |
| FR-002 | WHEN the operator is `~>` or `~` and the picked version is a final (non-prerelease) release THE SYSTEM SHALL truncate the picked version to the operand's segment count (`~> 2.0` -> `~> 3.2`, `~6.0` -> `~8.3`, `~> 2` -> `~> 3`, `~> 2.0.1` -> `~> 3.2.8`). | must |
| FR-003 | WHEN the operator is `^` and the picked version is a final release THE SYSTEM SHALL truncate the picked version to the operand's segment count, except where truncation would change the caret's meaning (picked version `0.0.x`, whose caret is exact): then it SHALL write the full version. | must |
| FR-004 | WHEN the picked version is a prerelease THE SYSTEM SHALL write the full version after the kept operator (`^3.0.0-beta1`, `~> 3.0.0.rc1`), because a truncated form would not select it. | must |
| FR-005 | WHEN the rewrite is for a floor target THE SYSTEM SHALL write the full picked version after the kept operator and SHALL NOT truncate. | must |
| FR-006 | WHEN a Composer constraint ends with a stability flag (`@dev`, `@alpha`, `@beta`, `@RC`, `@stable`, case-insensitive) THE SYSTEM SHALL keep the flag verbatim after the rewritten constraint. | must |
| FR-007 | WHEN the Composer operand carries a `v` or `V` prefix THE SYSTEM SHALL keep that prefix style on the new operand (existing behavior of `match_v_prefix_style`, #1435), after the operator. | must |
| FR-008 | WHEN the requirement is a bare version in Bundler or Composer (an exact pin) THE SYSTEM SHALL write a bare picked version (current behavior; `gem "json", "2.3.0"` -> `3.1.0`) and SHALL keep a Composer stability flag on it. | must |
| FR-009 | WHEN the requirement is `>=` or `>` with one operand THE SYSTEM SHALL render `>= <picked version>` (a `>` input becomes `>=` so the picked version satisfies it). | should |
| FR-010 | WHEN the requirement is a compound whose members are exactly one `~>`/`~`/`^` comparator plus lower bounds the picked version satisfies (`~> 1.0, >= 1.0.1`) THE SYSTEM SHALL render the single operator comparator per FR-001 to FR-006 and drop the subsumed lower bounds. | should |
| FR-011 | WHEN the requirement is any other multi-comparator shape (`>=1.0 <2.0`, `^2.0 \|\| ^3.0`, a comparator with an upper bound, Bundler `!=`) THE SYSTEM SHALL keep today's behavior, a bare picked version, and SHALL NOT claim to preserve the range. | should |
| FR-012 | WHEN the requirement is already satisfied by the latest version (`^2.0 \|\| ^3.0` with latest 3.12.1) THE SYSTEM SHALL NOT offer an update edit for it, unchanged from today. | must |
| FR-013 | WHEN the operator-preserving rewrite of a fallback or fix target would still admit a newer withheld version (`^2.0` with a cooldown fallback of 2.9.1 where 2.9.2 is withheld) THE SYSTEM SHALL retry with an exact pin, so Bundler and Composer SHALL provide the exact-pin rendering (`format_version_exact_pin`, a bare version; Composer keeps its stability flag). | must |
| FR-014 | WHEN any edit path builds update text (the REFACTOR "update to" actions, the vulnerability and unsatisfiable quickfixes, the "Update N outdated" code lens, `deps-cli update`) THE SYSTEM SHALL obtain it from the one shared rendering, so the LSP and CLI texts are identical for the same input and picked version. | must |
| FR-015 | WHEN the Bundler literal span has mixed quote styles THE SYSTEM SHALL keep echoing the original literal (existing #1366 guard, unchanged). | must |
| FR-016 | WHEN an unresolved placeholder or an oversized requirement is declared THE SYSTEM SHALL skip the rewrite exactly as today (`replacement_text` guards, #1391); this spec adds no path around them. | must |
| FR-017 | WHEN the rewritten text equals the declared text THE SYSTEM SHALL treat the edit as a no-op and omit the action (existing textual no-op check). | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Architecture | The operator, precision and stability rules live once in `deps-core::lsp_helpers` (next to `format_version_replacing_by_shape`); `deps-bundler` and `deps-composer` only supply their grammar-specific inputs. No rule is reimplemented per crate (cross-ecosystem consistency rule). |
| NFR-002 | Type safety | The rewrite is keyed by exhaustive `EcosystemId` matches with no catch-all `_` arm; operator, precision and stability flag are modeled as typed values (enums/newtypes), not re-parsed from strings at each call site. |
| NFR-003 | Behavior compatibility | Cargo, npm, Deno, PyPI, Dart, NuGet, Maven and Gradle output is byte-identical before and after (existing snapshot and unit tests pass unchanged). |
| NFR-004 | Latency | Rendering is pure string work with no I/O and adds no registry call; handlers stay non-blocking. |
| NFR-005 | Robustness | A malformed or unrecognized constraint never panics and falls back to today's rendering; fuzz-style inputs (empty operand, lone operator, unicode, 4-segment Composer versions) are covered. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Declared requirement | Manifest constraint text of one dependency | operator spelling, operand text, segment count, optional stability flag, optional `v` prefix |
| Picked version | Version the edit plan chose | final or prerelease, segment values, floor-target or plain update |
| Rendered edit | Replacement text for the version literal | operator, truncated or full operand, stability flag |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `~> 2` (one segment), picked 3.2.8 | `~> 3` |
| `^0.3`, picked 0.5.2 | `^0.5` |
| `^0.0.3`, picked 0.0.9 | `^0.0.9` (full, caret is exact) |
| `^0.0`, picked 0.0.9 | `^0.0.9` (full; truncation would change meaning) |
| `^2.0`, picked 3.0.0-beta1 | `^3.0.0-beta1` (full) |
| Composer `^v2.0`, picked `v3.12.1` (Packagist raw tag) | `^v3.12` |
| Composer 4-segment operand `~1.2.3.4`, picked 1.3.0.1 | `~1.3.0.1` |
| `~> 2.0` and picked version has fewer segments than the operand (picked `3.2`) | `~> 3.2` (pad nothing; never invent segments) |
| `"^5.0@beta"` with picked stable 8.1.11 | `^8.1@beta` (flag kept verbatim, see Open Questions) |
| `"^5.0 @beta"` (space before flag) | spacing kept as written |
| Compound with `<` bound (`>=1.0 <2.0`) | bare picked version, as today |
| `*` or empty Composer constraint | bare picked version, as today (any-version collapse is a narrowing but unchanged here) |
| Placeholder or oversized requirement | no edit, as today |

## 7. Success Criteria

Each row is a unit test on the shared rendering plus an LSP code-action and a `deps-cli update` check asserting identical text. Picked version column is the plain update (non-floor) unless marked "floor".

| ID | Ecosystem | Input constraint | Picked | Expected output | Today |
|----|-----------|------------------|--------|-----------------|-------|
| SC-001 | Bundler | `~> 2.0` | 3.2.8 | `~> 3.2` | `3.2.8` |
| SC-002 | Bundler | `~> 2.0.1` | 3.2.8 | `~> 3.2.8` | `3.2.8` |
| SC-003 | Bundler | `~> 2` | 3.2.8 | `~> 3` | `3.2.8` |
| SC-004 | Bundler | `~> 2.0` | 2.9.1 (floor) | `~> 2.9.1` | `2.9.1` |
| SC-005 | Bundler | `2.3.0` (bare) | 3.1.0 | `3.1.0` | `3.1.0` |
| SC-006 | Bundler | `>= 12.0` | 13.3.0 | `>= 13.3.0` | `13.3.0` |
| SC-007 | Bundler | `~> 1.0, >= 1.0.1` | 1.9.0 | `~> 1.9` | `1.9.0` |
| SC-008 | Bundler | `>= 5.0, < 6.0` | 6.1.0 | `6.1.0` | `6.1.0` |
| SC-009 | Composer | `^2.0` | 3.12.1 | `^3.12` | `3.12.1` |
| SC-010 | Composer | `~6.0` | 8.3.1 | `~8.3` | `8.3.1` |
| SC-011 | Composer | `~6.0.1` | 8.3.1 | `~8.3.1` | `8.3.1` |
| SC-012 | Composer | `^5.0@beta` | 8.1.11 | `^8.1@beta` | `8.1.11` |
| SC-013 | Composer | `^8.0@dev` | 13.40.0 | `^13.40@dev` | `13.40.0` |
| SC-014 | Composer | `^2.0` | 2.9.1 (floor) | `^2.9.1` | `2.9.1` |
| SC-015 | Composer | `^2.0` | 3.0.0-beta1 | `^3.0.0-beta1` | `3.0.0-beta1` |
| SC-016 | Composer | `^2.0 \|\| ^3.0` | 3.12.1 | no action (already satisfied) | no action |
| SC-017 | Composer | `^2.0 \|\| ^3.0` | 4.1.0 | `4.1.0` | `4.1.0` |
| SC-018 | Composer | `3.28.0` (bare) | 4.0.0 | `4.0.0` | `4.0.0` |
| SC-019 | Composer | `v3.28.0` (bare, `v` style) | 4.0.0 | `v4.0.0` | `v4.0.0` |
| SC-020 | Cargo | `=0.4.10` / `~1.5.0` | 0.4.35 / 1.13.1 | `=0.4.35` / `~1.13.1` | unchanged |
| SC-021 | Dart | `^0.13.0` | 1.6.0 | `^1.6.0` | unchanged |
| SC-022 | PyPI | `~=2.20.0` / `==1.0` | 2.34.2 / 3.1.3 | `~=2.34.2` / `==3.1.3` | unchanged |
| SC-023 | npm, Deno | `^`, `~`, `=` forms | any | unchanged from #1896 | unchanged |
| SC-024 | all | CLI vs LSP | same | `deps-cli update` text equals the code action's `newText` for every row above | n/a |

Aggregate targets: 100% of rows above pass; 0 byte differences in the existing test and snapshot corpus for non-Bundler, non-Composer ecosystems; a live re-run of the ci107 fixtures shows no bare pin for any row marked as range-preserving.

## 8. Agent Boundaries

### Always (without asking)
- Verify the repro live against a debug build with real registries before and after the change (`RUST_LOG=debug cargo run -p deps-lsp`, the `lsp_probe_ci107_actions.py` harness, and `deps-cli update` on a scratch copy of each fixture).
- Reuse `deps-core::lsp_helpers` (`format_version_replacing_by_shape`, `bare_meaning`, `match_v_prefix_style`, `classify_requirement_rewrite_shape`) before writing new logic; extend them rather than adding crate-local copies.
- Add a regression entry to `.local/testing/regressions.md` and update the Bundler and Composer playbooks and `coverage.md`.
- Add a `CHANGELOG.md` `[Unreleased]` entry (one line plus the PR link) and update the mdBook ecosystem pages for Bundler and Composer.

### Ask First
- Changing the shared `format_version_replacing_by_shape` result for any ecosystem other than Bundler and Composer (it is used by npm, Deno and others).
- Adding a dependency (a Composer or RubyGems constraint parser crate); the existing hand-rolled classification is expected to suffice.
- Rewriting wildcard (`2.*`) or upper-bound constraints (open questions below).

### Never
- Edit `crates/deps-zed` (separate repository).
- Change which version is picked, or weaken the placeholder, size and mixed-quote guards.
- Use a catch-all `_` arm on `EcosystemId` or an untyped string flag for the stability suffix.
- Change the CLI table's "current" column in this work.

## 9. Open Questions

- [NEEDS CLARIFICATION: Q1. Compound with one pessimistic operator plus lower bounds (`~> 1.0, >= 1.0.1`, the Gemfile `thor` line in the fixture). Default in FR-010: render only the operator comparator (`~> 1.9`), dropping the lower bounds because the picked version satisfies them. Alternative: keep the lower bounds verbatim, or leave today's bare pin.]
- [NEEDS CLARIFICATION: Q2. Other compound shapes (`>=1.0 <2.0`, `^2.0 || ^3.0` beyond latest, upper bounds). Default in FR-011: keep today's bare exact pin, the same choice npm made in #1576. Alternative: refuse the edit (echo unchanged, as Cargo does under `BareMeaning::Caret`), or rewrite the last comparator.]
- [NEEDS CLARIFICATION: Q3. Single lower bound (`>= 12.0`, Composer `>=2.0`). Default in FR-009: `>= <picked version>`. Today it collapses to an exact pin, which is a large narrowing for an open-ended bound. Alternative: leave as FR-011. Upper-bound singles (`< 3.0`) are assumed to stay on today's bare pin.]
- [NEEDS CLARIFICATION: Q4. Composer wildcards (`2.*`, `2.0.*`) share the defect (collapse to a bare pin). Default: out of scope here, tracked as a follow-up; alternative: in scope as `3.*` and `3.2.*` using the same precision rule.]
- [NEEDS CLARIFICATION: Q5. Stability flag when the picked version is a stable release (`^5.0@beta` -> `^8.1@beta`). Default: always keep the flag verbatim (it is user intent and costs nothing). The finding suggested keeping it only "when the picked version is a prerelease or the flag is meaningful". Also: does Composer need `@beta` on a constraint that names a prerelease version (`^3.0.0-beta1` with no flag, under `minimum-stability: stable`)? `composer` is not installed in the test environment; verify against Composer itself before fixing FR-004's no-flag behavior.]
- [NEEDS CLARIFICATION: Q6. Truncation versus full version for plain (non-floor) updates. Default: truncate to the operand's precision (FR-002, FR-003), matching the finding's `^2.0` -> `^3.12`. Alternative: always write the full version for caret and truncate only for `~`/`~>`, where precision changes meaning. The first choice leaves the floor slightly below the picked version (`^3.12` admits 3.12.0).]
- [NEEDS CLARIFICATION: Q7. Likely same defect class in other ecosystems: Cargo, npm and Dart tilde with fewer segments than the full picked version (`~1` or `~1.2` rewritten to `~1.13.1`) narrows a major or minor range to a patch range. Not verified live. Default: out of scope for this fix; verify with the harness and file a separate `cross-ecosystem` issue if confirmed, reusing the FR-002 helper.]
- [NEEDS CLARIFICATION: Q8. Other `BareMeaning::ExactPin` ecosystems with operator grammar not covered by this table: Swift (`.upToNextMajor(from:)`, ranges) and Go, GitHub Actions and GitLab CI (tags, no operators). Default: audit by code reading in the plan phase and record the result; no change expected.]
- [NEEDS CLARIFICATION: Q9. Composer inline aliases (`dev-main as 1.0.x-dev`) and `-dev` suffixes on version-like constraints (`1.0.x-dev`). Default: treated as non-version constraints and left unchanged; confirm the parser already excludes them from update edits.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] — the cooldown-fallback and exact-pin retry flow FR-013 depends on
- `crates/deps-core/src/lsp_helpers/formatter.rs` — `format_version_replacing_by_shape`, `bare_meaning`, `PackageRendering`
- `crates/deps-npm/src/formatter.rs` — the #1885/#1895 operator-keeping and partial-precision implementation to mirror
- `crates/deps-bundler/src/formatter.rs`, `crates/deps-composer/src/formatter.rs` — the two formatters this spec changes

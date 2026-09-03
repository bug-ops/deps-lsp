---
aliases:
  - Composer Uppercase V Prefix Bug
tags:
  - sdd
  - spec
  - bug
  - deps-composer
created: 2026-09-03
status: draft
related:
  - "[[constitution]]"
---

# Feature: Composer requirement matching fails for uppercase-`V`-prefixed versions

> [!info] Metadata
> **Author**: continuous-improvement research cycle
> **Branch**: fix/composer-uppercase-v-prefix (suggested — no issue number yet)

## 1. Overview

### Problem Statement

`ComposerFormatter::version_satisfies_requirement` (`crates/deps-composer/src/formatter.rs`,
`impl RequirementResolution for ComposerFormatter`, starting at line 130) strips a leading
lowercase `v` from both the candidate version and the requirement string before comparing —
at line 142 for `version` (`version.strip_prefix('v').unwrap_or(version)`), and repeated at
every operator branch for `requirement` (lines 152, 198, 204, 213, 218, 223, 228, 233, 238:
caret `^`, tilde `~`, `>=`, `<=`, `>`, `<`, `=`, `!=`). None of these calls strip an uppercase
`V`.

Real Composer/Packagist packages publish uppercase-`V`-prefixed tags — e.g.
`jeremykenedy/laravel2step` on Packagist has tags `V3.1.0`, `V4.0.0` mixed with plain
`3.0.0`, `2.2.0`. This is the same root cause — case-sensitive `v`-prefix handling of
registry version data — that competitor filllabs/dependi hit in
`` filllabs/dependi#308 `` ("Uppercase V prefix breaks semantic version sorting").

Composer's own `VersionParser::normalize()` strips the `v`/`V` prefix case-insensitively
(PHP: `preg_replace('#^v#i', '', $version)`), so deps-lsp's requirement matcher diverges
from the tool it is emulating.

**Root cause detail**: when `version_satisfies_requirement` falls through to
`compare_versions(a, b)` (formatter.rs, line ~521), it calls
`split_composer_core_and_suffix` on the *raw, unstripped* `V`-prefixed string. That
function finds the first non-digit-non-dot character to split "numeric core" from
"qualifier suffix" — for `"V3.1.0"` the very first character `V` is non-digit, so it
splits at index 0: `core = ""` (parses to numeric `0` via `.parse().unwrap_or(0)`) and
`suffix = "V3.1.0"` (the entire original string, since the trim-leading-`[-_.]` step
doesn't match `V`). The version then compares as if its numeric core were `0.0.0` with an
unrecognized qualifier suffix — nowhere close to its real value.

Notably, a *different* function in the same crate,
`composer_version_stability_rank`/its prerelease classifier
(`crates/deps-composer/src/types.rs`, line 434:
`version.strip_prefix(['v', 'V']).unwrap_or(version)`), already correctly strips both
cases. The codebase already has the correct pattern established elsewhere (added for
issue #424 critique C1, covered by `test_composer_version_stability_rank_strips_v_prefix`)
— it just was not applied consistently to `version_satisfies_requirement` in
`formatter.rs`.

**Downstream impact**: `version_satisfies_requirement` is consumed by
`crates/deps-core/src/lsp_helpers/in_use_version.rs` and
`crates/deps-core/src/lsp_helpers/inlay_hints.rs` (confirmed via
`grep -rln version_satisfies_requirement crates/`). It drives whether deps-lsp reports the
currently-locked/in-use version as satisfying the manifest's declared requirement for
Composer dependencies — i.e. it feeds inlay hints and outdated/up-to-date diagnostic
classification.

### Goal

`version_satisfies_requirement` treats an uppercase-`V`-prefixed version or requirement
identically to its lowercase-`v`-prefixed or unprefixed equivalent, for every operator
branch (caret, tilde, comparison operators, exact/partial match, wildcard).

### Out of Scope

- Any other Composer version-comparison entry point already handling `v`/`V` correctly
  (e.g. `composer_version_stability_rank` in `types.rs`) — no change needed there.
- Non-Composer ecosystems — this is a Composer/Packagist-specific normalization quirk
  (mirrors `VersionParser::normalize()`'s `#^v#i` regex); other ecosystems have their own
  version-parser crates (`semver`, `node-semver`, `pep440_rs`) with their own prefix rules,
  not covered by this spec.
- Mixed-case prefixes other than a single leading `v`/`V` (Composer/Packagist do not
  publish e.g. `Vv1.2.3`; not a real-world case).

## 2. User Stories

### US-001: Correct in-use-version status for uppercase-`V`-tagged Composer packages

AS A developer with a `composer.json` dependency on a package that publishes
uppercase-`V`-prefixed Packagist tags (e.g. `V3.1.0`)
I WANT deps-lsp's hover/inlay-hint/diagnostic to correctly report whether my locked
version satisfies the declared requirement
SO THAT I don't get a false "outdated"/"requirement not satisfied" signal purely because
of tag casing.

**Acceptance criteria:**
```
GIVEN a Composer dependency requirement "^3.0"
AND the in-use/locked version is "V3.1.0"
WHEN deps-lsp evaluates version_satisfies_requirement("V3.1.0", "^3.0")
THEN it returns true (matches the result for "v3.1.0" and "3.1.0" against the same requirement)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `version_satisfies_requirement` receives a candidate version with a leading uppercase `V` THE SYSTEM SHALL strip it identically to a leading lowercase `v`, for every operator branch (caret, tilde, `>=`, `<=`, `>`, `<`, `=`, `!=`, wildcard, exact/partial match) | must |
| FR-002 | WHEN `version_satisfies_requirement` receives a requirement string with a leading uppercase `V` (bare, or immediately after an operator prefix such as `^V1.0`, `>=V1.0.0`) THE SYSTEM SHALL strip it identically to a leading lowercase `v` | must |
| FR-003 | WHEN both the candidate version and the requirement carry a leading `V`/`v` in any combination (`V`+`V`, `V`+`v`, `v`+`V`, unprefixed+`V`, etc.) THE SYSTEM SHALL produce the same satisfaction result as the fully-unprefixed comparison | must |
| FR-004 | WHEN the fallthrough exact/partial-match and wildcard branches (lines ~242-261) compare a `V`-prefixed candidate version against a requirement THE SYSTEM SHALL compare on the stripped value, not the raw `V`-prefixed string | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Consistency | The fix must not change comparison behavior for versions/requirements that carry no `v`/`V` prefix at all (regression safety for the existing test suite in `formatter.rs`) |
| NFR-002 | Maintainability | The chosen strip mechanism should read as a single, obviously-correct operation per call site, consistent with the existing `strip_prefix(['v', 'V'])` idiom already used in `types.rs` — not a bespoke case-folding routine |

## 5. Data Model

No data model changes — this is a pure string-normalization fix inside an existing
comparison function. No new entities.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `V3.1.0` satisfies `^3.0` | true (currently false — see Evidence) |
| `V3.1.0` satisfies exact requirement `3.1.0` | true (currently false — see Evidence) |
| `V4.0.0` satisfies `>=3.0` | true (currently false — see Evidence) |
| `v3.1.0` satisfies `^3.0` / `3.1.0` | true (already correct — must remain true after fix) |
| `3.1.0` (no prefix) satisfies `^3.0` / `3.1.0` | true (already correct — must remain true after fix) |
| Requirement itself carries uppercase prefix, e.g. `^V3.0` | requirement's `V` must be stripped the same way `^v3.0` already is (mirrors existing `req.strip_prefix('v')` calls per operator branch) |
| Bare requirement `"V"` (degenerate, mirrors the existing bare-`"v"` guard at line 152-155) | must fall through to exact/partial match unchanged (not collapse to empty string), matching the existing lowercase-`v` guard's documented rationale |
| Wildcard requirement `V3.*` against version `V3.1.0` | both sides normalized before the `.starts_with(prefix)` comparison |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | All five reproduction cases from the Evidence section (`V3.1.0` vs `^3.0`, `v3.1.0` vs `^3.0`, `V3.1.0` vs `3.1.0`, `v3.1.0` vs `3.1.0`, `V4.0.0` vs `>=3.0`) return identical, correct (`true`) results | 5/5 pass |
| SC-002 | Existing `formatter.rs` test suite for `version_satisfies_requirement` (lowercase-`v` and unprefixed cases) continues to pass unmodified | 100% pass, zero regressions |
| SC-003 | New unit test(s) covering uppercase-`V` on both the version side and the requirement side, across at least caret, tilde, one comparison operator, and exact-match branches | added and passing |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo nextest run -p deps-composer` after the fix
- Add regression tests mirroring the existing `test_composer_version_stability_rank_strips_v_prefix` naming/style convention
- Follow existing code patterns and doc-comment style already present in `formatter.rs`

### Ask First
- Whether to centralize `v`/`V` stripping into one shared helper reused by both
  `formatter.rs` and `types.rs` (see Open Questions) — this is a design choice with DRY
  implications beyond the minimal bug fix

### Never
- Change `composer_version_stability_rank`'s existing correct `strip_prefix(['v', 'V'])`
  behavior in `types.rs`
- Touch other ecosystems' version-comparison logic

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the fix centralize `v`/`V`-prefix stripping into one shared
  helper function (e.g. `strip_v_prefix(s: &str) -> &str`) used by both
  `version_satisfies_requirement` in `formatter.rs` and `composer_version_stability_rank`
  in `types.rs` — consistent with the project's DRY convention (user CLAUDE.md: "Follow
  DRY: before creating any functionality, check for existing implementations... and reuse
  them") — or should each of the ~10 existing `strip_prefix('v')` call sites in
  `formatter.rs` simply be changed in place to `strip_prefix(['v', 'V'])`, matching the
  established local idiom with minimal diff? A shared helper reduces duplication across
  two files but is a slightly larger refactor for what is otherwise a single-character
  case-sensitivity bug.]
- [NEEDS CLARIFICATION: Does the bare degenerate-prefix guard at formatter.rs line 152-155
  (`Some(rest) if !rest.is_empty() => rest`, documented rationale for why a lone `"v"`
  requirement must not collapse to `""`) need an equivalent guard for a lone `"V"`
  requirement, or can both cases share one guard once the strip call accepts `['v', 'V']`?]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-composer/src/formatter.rs` — `ComposerFormatter::version_satisfies_requirement` (bug site)
- `crates/deps-composer/src/types.rs`, line 434 — `composer_version_stability_rank`'s existing correct `strip_prefix(['v', 'V'])` pattern (reference for the fix)
- `crates/deps-core/src/lsp_helpers/in_use_version.rs`, `crates/deps-core/src/lsp_helpers/inlay_hints.rs` — downstream consumers affected by this bug

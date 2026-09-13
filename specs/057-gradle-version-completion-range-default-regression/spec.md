---
aliases:
  - Gradle version completion range regression
  - "#922 literal-span guard breaks Gradle completion"
tags:
  - sdd
  - spec
  - bug
  - deps-gradle
  - completion
created: 2026-09-13
status: draft
related:
  - "[[constitution]]"
---

# Feature: Fix Gradle Version-Completion Total Regression from PR #922's Literal-Span Guard

> [!info] Metadata
> **Author**: continuous-improvement cycle ci-064, live-tester + architect finding
> **Branch**: not yet created (spec precedes implementation)
> **Regressed by**: PR #922 / commit `23f440811` ("fix(deps-core): reject non-literal version
> spans in completion guard", closing #919)
> **Live-tested against**: commit `23f440811` (main), 2026-09-13

## 1. Overview

### Problem Statement

PR #922 added `deps_core::lsp_helpers::dependency_version_range_is_literal(dep, content, range)`
as a guard in front of `CompletionContext::Version` completions, so that a non-literal version
span (Maven `${property}`, Gradle `$var`/`${var}` interpolation, YAML alias) is never offered
version completion — accepting one would splice replacement text into a reference instead of a
literal value. The guard works by slicing `content` at the `range` argument and comparing that
slice against the dependency's declared literal text.

`crates/deps-gradle/src/ecosystem.rs`'s `generate_completions` is a full override of the shared
`deps-core` dispatch (Gradle drives its own `GradleCompletionContext` via
`Self::detect_completion_context`, because it works from raw manifest text rather than parsed-AST
dependency ranges — see that method's own doc comment for why). It was wired into the new guard at
line ~426 as `dependency_version_range_is_literal(dep, content, range)`, where `range` is the third
element of the tuple returned by `detect_completion_context` → `detect_dsl_context` (for
`.gradle`/`.gradle.kts`) or `detect_catalog_context` (for `libs.versions.toml`) — **not**
`dep.version_range()` (the dependency's own parsed version span).

Two of the three `Version`-context return arms in these functions have returned a hardcoded
`Range::default()` — `(0,0)-(0,0)` — since Gradle support was introduced, because until #922
nothing consumed that range for a content comparison:

- `detect_dsl_context`'s `colon_count >= 2` match arm (`crates/deps-gradle/src/ecosystem.rs:339`),
  which handles the compact GAV-coordinate form `'group:artifact:version'` /
  `"group:artifact:version"` (e.g. `implementation 'com.google.guava:guava:32.0.1-jre'`) —
  introduced 2026-02-22, commit `7a18ee6`.
- `detect_catalog_context`'s `version = "..."` / `version.ref = "..."` branch
  (`crates/deps-gradle/src/ecosystem.rs:234`), used for `libs.versions.toml` — introduced by PR
  #239, commit `18b17bb`.

Since #922, `dependency_version_range_is_literal` slices `content` at this placeholder `(0,0)-(0,0)`
span instead of the value's real location. That slice essentially never matches the dependency's
actual declared literal version text (empty or wrong content), so the guard now rejects **every**
version-completion request through these two paths — including plain literal versions with no
interpolation at all. This is a total feature regression for the two most common real-world Gradle
dependency-declaration styles, not a missed edge case.

The third `Version`-context path — `detect_catalog_context`'s `module = "..."` branch (a `Package`
context, computed via `byte_range` and not gated by this guard at all) — is unaffected, as is
Maven's equivalent wiring (`MavenEcosystem::detect_xml_context` already computes a real range, and
Maven literal-version completion was live-verified working correctly in this session; Maven
`${property}` interpolation is correctly rejected).

### Goal

Gradle version completion for a plain literal version — in either the compact DSL coordinate form
or a version-catalog `version = "..."` / `version.ref = "..."` entry — returns the real completion
list from the registry (Maven Central), exactly as it did before PR #922, while #919's protection
against non-literal spans (`$var`, `${var}`, YAML alias) continues to hold for both contexts.

### Out of Scope

- Maven's guard wiring (`crates/deps-maven/src/ecosystem.rs`) — confirmed unaffected, no change
  needed.
- `detect_catalog_context`'s `module = "..."` (`Package`-context) branch — already computes a real
  range, not gated by this guard, unaffected.
- Any change to `dependency_version_range_is_literal` itself or to the #919 literal-span-rejection
  logic — the guard's own behavior is correct; only its Gradle-side inputs are wrong.
- Any other ecosystem crate.
- Redesigning `GradleCompletionContext` or `detect_completion_context`'s overall dispatch approach.

## 2. User Stories

### US-001: Compact GAV-coordinate version completion

AS A Gradle developer writing a dependency as a compact coordinate string
I WANT version completion when my cursor is inside the version segment
SO THAT I can pick an available version without leaving the editor to check the registry

**Acceptance criteria:**
```
GIVEN a `.gradle` or `.gradle.kts` file containing
  `implementation 'com.google.guava:guava:32.0.1-jre'`
WHEN the cursor is positioned inside the literal version segment (`32.0.1-jre`)
THEN completion returns the real list of published versions for
  `com.google.guava:guava` from Maven Central, with the top item marked `(latest)`
```

### US-002: Version-catalog version completion

AS A Gradle developer using a version catalog (`libs.versions.toml`)
I WANT version completion when my cursor is inside a `version = "..."` or `version.ref = "..."`
value
SO THAT I can pick an available version for the module declared in the same catalog entry

**Acceptance criteria:**
```
GIVEN a `libs.versions.toml` entry
  `commons-lang = { module = "org.apache.commons:commons-lang3", version = "3.12.0" }`
WHEN the cursor is positioned inside the literal version value (`3.12.0`)
THEN completion returns the real list of published versions for
  `org.apache.commons:commons-lang3` from Maven Central
```

### US-003: Non-literal spans stay rejected (no regression of #919)

AS A maintainer of the completion guard added in #922
I WANT the fix for this regression to preserve #919's rejection of non-literal version spans
SO THAT completion never splices replacement text into a `$var`/`${var}` interpolation or a YAML
alias

**Acceptance criteria:**
```
GIVEN a `.gradle.kts` file containing
  `implementation("com.example:lib:$libVersion")`
WHEN the cursor is positioned inside `$libVersion`
THEN completion returns zero items (unchanged from current behavior)

GIVEN a `libs.versions.toml` entry using `version.ref = "guavaVersion"` where the referenced
  alias name itself is the literal value under the cursor
WHEN the cursor is positioned inside the literal `version.ref` string value
THEN completion returns real completion items scoped to whatever that context is intended to
  complete (see FR-002 and the Edge Cases table — `version.ref` completes a catalog-alias name,
  not a registry version, and must not be confused with the `version = "..."` case)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `detect_dsl_context` matches the `colon_count >= 2` arm (compact GAV-coordinate `Version` context) THE SYSTEM SHALL compute the returned `Range` from the actual byte span of the version segment in `line`, not `Range::default()` | must |
| FR-002 | WHEN `detect_catalog_context` matches the `version = "..."` / `version.ref = "..."` branch (`Version` context) THE SYSTEM SHALL compute the returned `Range` from the actual byte span of the value in `line`, not `Range::default()` | must |
| FR-003 | WHEN the cursor sits inside a literal (non-interpolated) version segment in either context THE SYSTEM SHALL return the real registry-backed completion list, matching the pre-#922 baseline (5 items, top item marked `(latest)`, per `.local/testing/regressions.md`'s `#125` entry for `build.gradle (7, 44)`) | must |
| FR-004 | WHEN the cursor sits inside a `$var`/`${var}`-interpolated version segment in either context THE SYSTEM SHALL continue to return zero completion items, unchanged from current (post-#922) behavior | must |
| FR-005 | WHEN the computed range for the `colon_count >= 2` DSL arm or the catalog `version`/`version.ref` arm is passed to `dependency_version_range_is_literal` THE SYSTEM SHALL slice `content` at a span whose text is byte-for-byte the version segment under the cursor, so the literal-text comparison inside that guard is meaningful rather than incidentally empty or wrong | must |
| FR-006 | WHEN multiple dependency declarations exist in the same file/line context THE SYSTEM SHALL compute a range scoped to the correct occurrence under the cursor, not a range that could match an unrelated declaration elsewhere in the file | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The range computation must stay allocation-light and O(line length), consistent with the existing `byte_range`/`find_closing_quote` helpers already used by the `Package`-context arms in the same functions — no new per-keystroke registry calls or full-document rescans |
| NFR-002 | Consistency | The fix should reuse the existing `byte_range` helper (already used by `detect_catalog_context`'s `module` arm and `detect_dsl_context`'s `colon_count 0 \| 1` arm) rather than introducing a second, divergent span-computation approach for the same file |
| NFR-003 | Regression safety | The fix must not change behavior for the `Package`-context arms (`module = "..."`, and `colon_count 0 \| 1`), which already compute correct ranges and are unaffected by this bug |

## 5. Data Model

No new entities. This bug concerns the `Range` value threaded through the existing
`GradleCompletionContext`-detection return tuple `(GradleCompletionContext, &str, Range)`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `GradleCompletionContext` | Enum discriminating what kind of value is under the cursor (`None`, `Package`, `Version`) | existing, unchanged |
| Completion-context `Range` | The `tower_lsp_server::ls_types::Range` returned alongside the context and value-prefix, used both to compute the completion's edit range and — since #922 — as the slice bounds for the literal-span guard | must become a real computed span for the two `Version`-context arms currently returning `Range::default()` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Compact coordinate with cursor inside a literal version (`'group:artifact:1.2.3'`) | Real completion list returned (regression fixed) |
| Compact coordinate with cursor inside a `$var`/`${var}` version segment | Zero items (unchanged #919 protection) |
| Catalog `version = "1.2.3"` with cursor inside the literal value | Real completion list returned (regression fixed) |
| Catalog `version.ref = "someAlias"` with cursor inside the alias name | Completion behavior for this sub-case must be defined explicitly by the fix: `version.ref` refers to a `[versions]` table alias, not a registry version string directly — the fix must not treat the alias name itself as a version literal to send to the registry. If today's `detect_catalog_context` does not distinguish `version.ref` from `version` beyond the `rfind("version")` match, this ambiguity already exists pre-fix and must not be made worse; scoping the range correctly (FR-002) is the requirement here, not adding new alias-resolution behavior |
| Unterminated string (no closing quote on the line) before the cursor, in either context | Bounded by the cursor position rather than end-of-line, mirroring the existing no-closing-tag fallback already used by the `Package`-context arms in the same functions and by `MavenEcosystem::detect_xml_context` |
| Multiple dependency declarations on the same line or file | Computed range must scope to the occurrence under the cursor only, per FR-006 |
| Multi-byte (non-ASCII) characters preceding the version segment on the line | Byte offsets used for the range must remain correct — reuse `byte_range` (NFR-002), which is already exercised against the `Package`-context arms in the existing test suite |
| Maven equivalent contexts (`<version>...</version>`, `${property}`) | Unaffected by this fix; already compute real ranges and already pass/reject correctly (control case, live-verified) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `.local/testing/manifests/build.gradle` line 7, char 44 completion request | Returns 5 items, top item `33.7.1-jre (latest)` — matches the documented pre-regression baseline (`.local/testing/regressions.md` `#125`) |
| SC-002 | `.local/testing/manifests/gradle-catalog/libs.versions.toml` line 7, char 75 completion request | Returns real, non-empty version completion items for `org.apache.commons:commons-lang3` |
| SC-003 | `cargo nextest run -p deps-gradle --all-features` | All existing tests pass, including the three call sites in `crates/deps-gradle/src/ecosystem.rs` that currently assert `range == Range::default()` (lines ~653, ~756, ~834) — these assertions must be updated to assert the new real-range behavior for the `Version`-context cases they cover, not left asserting the placeholder |
| SC-004 | New regression test(s) for both fixed arms (compact-coordinate `Version` context, catalog `version`/`version.ref` `Version` context) | Added and passing, each asserting the returned `Range`'s slice of `content` equals the literal version text, per the pattern in `crates/deps-core/src/lsp_helpers/mod.rs`'s `dependency_version_range_is_literal` doctest and unit tests |
| SC-005 | `$var`/`${var}` interpolation regression check (existing test `test_generate_completions_version_context_withheld_for_unresolved_variable`, `crates/deps-gradle/src/ecosystem.rs:~1071`) | Continues to pass unchanged — zero completion items for non-literal spans |
| SC-006 | Full pre-commit check suite (`cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`) | Passes |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo nextest run -p deps-gradle --all-features` after the change, then the full workspace
  check suite before opening a PR, per [[branching.md]]
- Reuse the existing `byte_range` helper already used by the unaffected `Package`-context arms in
  the same two functions, rather than writing a second span-computation routine
- Update the three existing tests in `crates/deps-gradle/src/ecosystem.rs` that currently assert
  `range == Range::default()` for the arms this fix changes, so they assert the new real-range
  behavior instead of silently continuing to assert the placeholder
- Add regression tests for both fixed contexts (compact-coordinate DSL, catalog
  `version`/`version.ref`) mirroring `deps-core`'s existing `dependency_version_range_is_literal`
  test patterns

### Ask First
- Any change to `deps_core::lsp_helpers::dependency_version_range_is_literal` itself or to #919's
  literal-span-rejection semantics — this spec's fix is scoped to Gradle's inputs into that
  function, not the function itself
- Any change to Maven's or another ecosystem's completion-guard wiring — confirmed unaffected,
  out of scope
- Introducing a new shared `deps-core` helper for this specific range computation if `byte_range`
  turns out not to be directly reusable as-is — check with the maintainer before adding new public
  API surface for what should likely be a local fix

### Never
- Weaken or bypass the #919 literal-span guard for Gradle specifically (e.g. special-casing Gradle
  to skip `dependency_version_range_is_literal`) as a shortcut to restoring completion
- Edit `crates/deps-zed` (git submodule) as part of this fix
- Change `crates/deps-maven` as part of this fix (control case, confirmed unaffected)

## 9. Open Questions

None outstanding — root cause is confirmed by source read (`crates/deps-gradle/src/ecosystem.rs:339`
and `:234`) and by live reproduction against commit `23f440811` (see Evidence below). The only
soft ambiguity — how `version.ref` completion should ultimately behave once its range is real
(Edge Cases table) — is pre-existing scope, not something this fix needs to resolve; FR-002/FR-006
bound what this spec requires.

## 10. Evidence (Live Reproduction)

Live-tested against a debug build of commit `23f440811` (2026-09-13), per the continuous-improvement
live-testing protocol ([[continuous-improvement.md]]):

1. `RUST_LOG=debug cargo run -p deps-lsp` (or the built `./target/debug/deps-lsp`), then:
   ```
   python3 .local/testing/lsp_test.py ./target/debug/deps-lsp \
     .local/testing/manifests/build.gradle 7 44 completion
   ```
   Expected (documented baseline, `.local/testing/regressions.md` `#125`, live-verified
   2026-08-20): 5 version items, top item `33.7.1-jre (latest)`.
   Actual: `[completion] count=0 isIncomplete=False`. Debug log shows
   `deps_lsp::handlers::completion: completion: ecosystem returned empty, trying fallback` then
   `fallback_completion: no completable prefix at this position` — zero items from any path.

2. ```
   python3 .local/testing/lsp_test.py ./target/debug/deps-lsp \
     .local/testing/manifests/gradle-catalog/libs.versions.toml 7 75 completion
   ```
   Expected: real version completions against Maven Central for
   `org.apache.commons:commons-lang3`.
   Actual: `[completion] count=0 isIncomplete=False`.

3. Control case confirming Maven is unaffected: `.local/testing/manifests/pom.xml`,
   `<version>3.2.0</version>` still returns 5 real completion items correctly. A new fixture
   (`.local/testing/manifests/maven-922/pom.xml`) with `<version>${guava.version}</version>`
   is correctly rejected (0 items) — confirms #922 itself works as intended for Maven.

4. `.local/testing/debug/session.log` from this session showed zero WARN/ERROR/panics — this is a
   silent logic bug, not a crash.

## 11. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-gradle/src/ecosystem.rs` — `detect_dsl_context` (line ~339),
  `detect_catalog_context` (line ~234), `generate_completions` (line ~426)
- `crates/deps-core/src/lsp_helpers/mod.rs` — `dependency_version_range_is_literal` (introduced by
  PR #922 / issue #919)
- `.local/testing/regressions.md` — `#125` baseline entry this spec's SC-001 restores
- `.local/testing/manifests/build.gradle`, `.local/testing/manifests/gradle-catalog/libs.versions.toml`
  — fixtures used for reproduction

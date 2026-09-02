---
aliases:
  - Maven Legacy Version Sort Bug
  - r09 sorts above 33.7.1
tags:
  - sdd
  - spec
  - bug
  - deps-maven
  - deps-gradle
  - version-sorting
created: 2026-08-19
status: draft
related:
  - "[[constitution]]"
---

# Feature: Fix Maven/Gradle Version Sort Corrupted by Legacy Non-Semver Versions

> [!info] Metadata
> **Author**: continuous-improvement cycle (deps-lsp)
> **Branch**: fix/{issue-number}-maven-legacy-version-sort
> **Priority**: P1
> **Type**: bug

## 1. Overview

### Problem Statement

`compare_versions()` in `crates/deps-maven/src/version.rs` (lines 36-66) is a
hand-rolled version comparator: it splits a version string on `.` and `-` into
segments, parses each segment as `u64`, and falls back to raw string (`Ord::cmp`)
comparison whenever a segment fails to parse as a number.

Legacy Maven artifacts occasionally shipped bare, qualifier-only version
identifiers with no `.` or `-` separators at all — e.g. Guava's `r03`..`r09`
releases from ~2012. For such a version, `split_version("r09")` yields a single
segment `"r09"`, which fails `u64::parse`. `compare_segment` then falls back to
`a.cmp(b)`, i.e. lexicographic string comparison, against numeric segments such
as `"33"`. Because ASCII `'r'` (114) sorts above `'3'` (51), `"r09" > "33"`
lexicographically — so `r09` permanently outranks every real, newer release
regardless of how many stable versions have shipped since 2012.

This broken comparator is used at `crates/deps-maven/src/registry.rs:221`
(`versions.sort_by(|a, b| compare_versions(&b.version, &a.version))`) to sort
the version list returned by the Maven Central registry client. Both
`deps-maven` and `deps-gradle` (Gradle reuses the Maven Central registry client
for library coordinates) consume this sorted list for hover rendering and
completion rendering.

The top-line "Latest" badge in the hover card was already fixed correctly by
PR #93 / #91, which reads Maven metadata's authoritative `<release>` XML tag
instead of relying on the sorted list. However, that fix is narrow: it did not
touch `compare_versions` or the sort call itself, so every OTHER
version-ordered surface remains broken:

- The "Recent versions" list in the hover card (below the "Latest" badge)
- The completion dropdown's item ordering
- The completion dropdown's `(latest)` label, which is assigned purely by
  index `0` into the same broken sort in
  `crates/deps-core/src/completion.rs` (`build_version_completion` /
  `VersionDisplayItem::new`), with no independent correctness check against
  the authoritative release value

The result is a hover card that contradicts itself in the same response
(`**Latest**: 33.7.1-jre` on one line, `- r09 *(latest)*` two lines below), and
a completion dropdown that offers a 14-year-old version as the default/first
suggestion when the user invokes completion with an empty prefix — the common
real-world case of opening the version field for the first time.

This is worsened by the fact that the crate's own test suite documents the
brokenness as accepted rather than asserting correctness:
`crates/deps-maven/src/registry.rs::test_parse_metadata_xml_legacy_versions_release_wins`
(~lines 442-469) only asserts `assert_ne!(versions[0].version, "33.5.0-jre", "sort
puts r09 first")` — i.e. it confirms the sort produces something other than the
correct top result, without asserting what the correct top result actually is.

This also violates the project's own coding convention
(`.claude/rules/rust-code.md`, "Registry Crates" section): "Version parsing:
use ecosystem-specific crates (`semver`, `node-semver`, `pep440_rs`) — do not
hand-roll version comparison logic." `compare_versions` is exactly such a
hand-rolled comparator, and Maven's own de facto versioning scheme
(Maven `ComparableVersion`, used by Maven Central itself) is not equivalent to
strict semver, so a purely mechanical swap to the `semver` crate is not
guaranteed to be sufficient on its own — see Open Questions.

### Goal

The version ordering used to render the "Recent versions" list in hover and
the completion dropdown for Maven and Gradle packages agrees with the
authoritative "Latest" determination (the `<release>` tag when present), and no
legacy or malformed version identifier lacking numeric structure can ever
outrank a well-formed, numerically-versioned release — regardless of how the
underlying comparator is implemented.

### Out of Scope

- Changing how the "Latest" badge itself is computed (already correct via
  `<release>` tag, PR #93/#91) — this spec covers the list/dropdown ordering
  and the completion `(latest)` label logic that consumes that ordering
- Non-Maven/Gradle ecosystems (Cargo, npm, PyPI, Go, Bundler, Dart, Composer,
  Swift) — each already uses an ecosystem-specific version-parsing crate per
  `.claude/rules/rust-code.md` and is not affected by this comparator
- Redesigning the completion API surface (`build_version_completion`,
  `VersionDisplayItem`) beyond what is required to source a correct
  latest-version determination and a correct sort order
- Retroactively fixing already-cached/persisted version lists (cache
  invalidation strategy, if any, is an implementation detail for `/sdd plan`)

## 2. User Stories

### US-001: Correct hover "Recent versions" ordering

AS A developer editing a `pom.xml` or `build.gradle` file
I WANT the hover card's "Recent versions" list to show genuinely recent
releases first, consistent with the "Latest" badge in the same card
SO THAT I can trust the hover information without cross-checking it against
Maven Central manually

**Acceptance criteria:**
```
GIVEN a Maven artifact whose version history includes both legacy bare
  qualifier identifiers (e.g. "r03".."r09") and well-formed numeric releases
  (e.g. "14.0", "33.4.0-jre", "33.7.1-jre")
WHEN the user hovers over the version field of a dependency using that
  artifact
THEN the "Latest" badge and the first entry of the "Recent versions" list
  refer to the same version, and no legacy bare-qualifier identifier appears
  above any well-formed numeric release in that list
```

### US-002: Correct completion default suggestion

AS A developer typing or triggering completion on a dependency version field
I WANT the first/default completion item (and the item labeled `(latest)`) to
be the actual latest stable release
SO THAT accepting the top suggestion never regresses my dependency to a
14-year-old version

**Acceptance criteria:**
```
GIVEN the same artifact as US-001
WHEN the user triggers textDocument/completion with the cursor positioned at
  the start of the version value (empty typed prefix)
THEN the first completion item returned is the actual latest stable release
  and is the only item labeled "(latest)"
```

### US-003: Consistency across Maven and Gradle

AS A developer using either a Maven `pom.xml` or a Gradle `build.gradle` /
`build.gradle.kts` file
I WANT identical, correct version ordering behavior in both ecosystems for the
same underlying Maven Central coordinate
SO THAT the fix is not ecosystem-specific and does not need to be reapplied
separately for Gradle

**Acceptance criteria:**
```
GIVEN the same Maven Central artifact (e.g. com.google.guava:guava) is
  referenced from a Gradle build.gradle file instead of a Maven pom.xml
WHEN the user hovers or triggers completion on the version field
THEN the observed ordering and "(latest)" labeling match the Maven case
  exactly, since both consume the shared Maven Central registry client
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the Maven Central registry client sorts a version list for display THE SYSTEM SHALL order it such that the item identified as "latest" is never outranked by a version segment that failed to parse numerically | must |
| FR-002 | WHEN a version identifier contains one or more segments that cannot be parsed as a number (e.g. bare qualifiers like `r09`, or letter-prefixed identifiers) THE SYSTEM SHALL NOT allow raw lexicographic (`Ord::cmp` on `&str`) comparison of that segment to silently outrank a purely-numeric segment from another version | must |
| FR-003 | WHEN Maven metadata provides an authoritative `<release>` tag THE SYSTEM SHALL ensure the sorted version list's first element and the completion dropdown's `(latest)`-labeled item are consistent with that `<release>` value | must |
| FR-004 | WHEN Maven metadata does NOT provide a `<release>` tag (fallback path) THE SYSTEM SHALL determine "latest" using a version-ordering algorithm that also satisfies FR-001 and FR-002, so hover and completion remain internally consistent even without the authoritative tag | must |
| FR-005 | WHEN the completion dropdown assigns the `(latest)` label and `sort_text` in `crates/deps-core/src/completion.rs` (`build_version_completion` / `VersionDisplayItem::new`) THE SYSTEM SHALL derive "latest" status independently verified against the authoritative determination (FR-003/FR-004), not purely from array index `0` of a potentially-incorrect sort | must |
| FR-006 | WHEN a Gradle manifest (`build.gradle`, `build.gradle.kts`) references a Maven Central coordinate THE SYSTEM SHALL exhibit identical corrected ordering and labeling behavior as the Maven `pom.xml` case, since both share the same registry client | must |
| FR-007 | WHEN the version list contains a mix of pre-release-qualified versions (SNAPSHOT/alpha/beta/rc/milestone, per existing `is_prerelease()`) and legacy non-numeric identifiers THE SYSTEM SHALL continue to apply existing pre-release exclusion/ranking rules without regression, in addition to fixing the legacy-identifier defect | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | The fixed comparator/sort MUST NOT be a hand-rolled ad hoc comparison per `.claude/rules/rust-code.md` ("do not hand-roll version comparison logic") — an ecosystem-appropriate approach (e.g. a maintained Maven-version-aware crate, or an explicit documented algorithm modeled on Maven's own `ComparableVersion` semantics) MUST be used or clearly justified if none exists |
| NFR-002 | Regression safety | The existing test `test_parse_metadata_xml_legacy_versions_release_wins` MUST be strengthened from `assert_ne!` (asserts brokenness) to a positive assertion of the correct top-ranked version, and MUST NOT regress once the fix lands |
| NFR-003 | Performance | Sorting MUST remain O(n log n) over the version list returned by the registry (typically tens to low hundreds of versions per artifact) with no observable hover/completion latency regression |
| NFR-004 | Test coverage | New unit tests MUST cover: bare non-numeric identifiers (`r03`..`r09`), mixed numeric/non-numeric segment versions, and at least one other legacy Maven artifact pattern beyond Guava if one is identified during implementation |
| NFR-005 | Cross-ecosystem consistency | Per `.claude/rules/continuous-improvement.md` ("Cross-Ecosystem Consistency Testing"), the fix MUST be implemented once in the shared Maven Central registry client / `deps-core` completion helper rather than duplicated separately for `deps-maven` and `deps-gradle` |

## 5. Data Model

No new persistent entities. The defect is confined to ordering logic over the
existing `MavenVersion` list (`version: String`, `timestamp: Option<...>`)
already produced by `parse_metadata_xml` in
`crates/deps-maven/src/registry.rs`, and to the derived `VersionDisplayItem`
in `crates/deps-core/src/completion.rs`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `MavenVersion` | One version entry parsed from Maven Central `maven-metadata.xml` | `version: String`, `timestamp: Option<...>` |
| `VersionDisplayItem` | Derived completion-item view over a `Version`, including latest/index-based labeling | `version`, `package_name`, `index`, `is_latest` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Version is a bare non-numeric qualifier with no `.`/`-` separators (e.g. `r09`) | Never sorts above a well-formed numeric release; does not receive the `(latest)` label unless it genuinely is the only/authoritative latest |
| Version list contains ONLY legacy bare-qualifier identifiers (no numeric releases at all) | System falls back to a deterministic, documented ordering (e.g. registry publish order / lexicographic among like-typed segments) without crashing; `[NEEDS CLARIFICATION: exact fallback ordering rule when no numeric-leading version exists in the entire list]` |
| Maven metadata has no `<release>` tag at all | "Latest" determination falls back to the corrected comparator (FR-004) and must still agree between hover and completion |
| Mixed-type version list includes both classic semver-like Maven versions (`33.7.1-jre`) and dotted-numeric-only versions (`14.0`) | Fixed comparator ranks purely by numeric/qualifier semantics per Maven versioning rules, not accidentally by string length or lexicographic segment count |
| Version list contains pre-release-qualified versions alongside the legacy identifiers (e.g. `34.0.0-jre-rc1` and `r09` in the same list) | Existing `is_prerelease()` exclusion/ranking behavior is preserved; legacy fix does not accidentally start treating pre-releases as latest |
| Gradle manifest references the same coordinate as a Maven manifest in the same workspace | Both surfaces show identical ordering (shared registry client, FR-006) |
| Registry returns an empty version list | No change from current behavior — out of scope for this fix, must not regress existing empty-list handling |

## 7. Success Criteria

Measurable metrics that prove the fix works:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover "Recent versions" first entry matches "Latest" badge value for `com.google.guava:guava` (both `pom.xml` and `build.gradle`) | 100% match, verified via live LSP harness (`.local/testing/lsp_test.py`) per `continuous-improvement.md` live-testing principle |
| SC-002 | `textDocument/completion` with empty version prefix returns the authoritative latest stable release as item 0, labeled `(latest)` | 100% match for `com.google.guava:guava` and at least one additional legacy-affected artifact if identified |
| SC-003 | `test_parse_metadata_xml_legacy_versions_release_wins` (renamed/updated) asserts the correct top version positively, not just `assert_ne!` | Passing with positive assertion |
| SC-004 | No regression in existing pre-release exclusion tests (`test_prerelease_detection` and related) | All existing tests continue to pass |
| SC-005 | Full CI gate passes: `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate | 0 failures |

## 8. Agent Boundaries

### Always (without asking)
- Reproduce the bug live via the LSP harness (`.local/testing/lsp_test.py`) against a debug build before considering the fix verified, per `continuous-improvement.md`
- Run the full local check suite before proposing a PR: `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features --no-fail-fast`, rustdoc gate
- Update `CHANGELOG.md` under `[Unreleased]`
- Update the existing test `test_parse_metadata_xml_legacy_versions_release_wins` to assert the correct behavior positively
- Test both Maven (`pom.xml`) and Gradle (`build.gradle`) surfaces, since they share the registry client (cross-ecosystem consistency gate)

### Ask First
- Adding a new external crate dependency for Maven-aware version comparison (per NFR-001, if a mechanical hand-rolled fix is judged insufficient) — must be checked via context7 mcp for current versions per user's dependency policy
- Changing the public signature of `compare_versions`, `MavenVersion`, or `VersionDisplayItem` if it affects other crates' call sites beyond `deps-maven`/`deps-gradle`/`deps-core`

### Never
- Modify the `<release>`-tag-based "Latest" badge logic that PR #93/#91 already fixed correctly, unless a regression in that logic is independently discovered and documented
- Silently change ordering behavior for other ecosystems (Cargo/npm/PyPI/Go/etc.) as a side effect of this fix
- Mark the fix complete based on unit tests alone — live LSP verification against real Maven Central data is required per the project's continuous-improvement testing gate

## 9. Open Questions

- [NEEDS CLARIFICATION: Should the fix adopt a maintained Maven-version-comparison crate (if one with acceptable maturity/license exists), or is a corrected, well-documented hand-rolled algorithm acceptable given Maven's `ComparableVersion` scheme has no widely-adopted `semver`-compatible crate on crates.io? This determines whether `/sdd plan` needs a dependency-addition step.]
- [NEEDS CLARIFICATION: Exact fallback ordering rule when a version list contains ONLY non-numeric/legacy identifiers and no `<release>` tag is present — is publish `timestamp` (already present as `Option<...>` on `MavenVersion` but currently unused for sorting) an acceptable tiebreaker/primary key in that degenerate case?]
- [NEEDS CLARIFICATION: Beyond Guava's `r03`-`r09`, are there other known legacy Maven Central artifacts with similar bare-qualifier version identifiers that should be added to the regression test/regressions.md catalog? A search across popular artifacts may be warranted during `/sdd plan` or implementation.]
- [NEEDS CLARIFICATION: Should `timestamp` (currently parsed but unused, per `MavenVersion.timestamp: Option<...>`) be wired into the corrected sort as a secondary/fallback signal, or left unused as before?]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- `crates/deps-maven/src/version.rs` — `compare_versions`, `is_prerelease` (defect location)
- `crates/deps-maven/src/registry.rs` — `parse_metadata_xml`, version sort call site, `test_parse_metadata_xml_legacy_versions_release_wins`
- `crates/deps-core/src/completion.rs` — `build_version_completion`, `VersionDisplayItem::new` (consumer of the broken order)
- `.claude/rules/rust-code.md` — "do not hand-roll version comparison logic" convention this defect violates
- `.claude/rules/continuous-improvement.md` — live-testing principle and cross-ecosystem consistency gate applied to verification

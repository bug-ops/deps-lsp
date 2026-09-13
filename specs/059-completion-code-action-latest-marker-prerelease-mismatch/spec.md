---
aliases:
  - Completion/Code-Action Latest Marker Prerelease Mismatch
tags:
  - sdd
  - spec
  - bug
  - lsp-completion
  - lsp-code-actions
created: 2026-09-13
status: draft
related:
  - "[[constitution]]"
  - "[[017-hover-latest-marker-prerelease-mismatch/spec]]"
---

# Feature: Version-completion and code-action quick-fix lists mislabel a pre-release as `(latest)` when it is the raw top-fetched entry

> [!info] Metadata
> **Author**: continuous-improvement live-testing cycle
> **Branch**: no branch/issue filed yet

## 1. Overview

### Problem Statement

`crates/deps-core/src/completion.rs`'s `prepare_version_display_items` (currently
lines 807-819) builds the shared `VersionDisplayItem` list consumed by **both**:

1. The version-completion dropdown, via `complete_versions_generic_from`
   (`crates/deps-core/src/completion.rs`, ~line 1023 onward), for every
   ecosystem crate in the workspace, and
2. The code-action "update version" quick-fix list, via
   `crates/deps-core/src/lsp_helpers/code_actions.rs` (~line 675), which calls
   the same function directly.

It decides which entry earns the `"(latest)"` label suffix and gets
preselected purely by raw fetch-order position:

```rust
pub fn prepare_version_display_items<V: AsRef<dyn Version>>(
    versions: &[V],
    package_name: &PackageName,
) -> Vec<VersionDisplayItem> {
    versions
        .iter()
        .map(|v| v.as_ref())
        .filter(|v| !v.removal_status().blocks_resolution())
        .take(MAX_COMPLETION_VERSIONS)
        .enumerate()
        .map(|(index, version)| VersionDisplayItem::new(version, package_name, index, index == 0))
        .collect()
}
```

The only filter applied before the `index == 0` check is
`removal_status().blocks_resolution()` (yanked/removed versions). There is no
check for `Version::is_prerelease()` — a trait method that already exists and
is already used elsewhere in this same crate (e.g.
`crates/deps-core/src/registry.rs:641`, and the mock implementations in
`crates/deps-core/src/completion.rs:1259` and `crates/deps-core/src/macros.rs`).

When the numerically-highest fetched version is a pre-release/milestone
build, that pre-release is placed at index 0, gets tagged `"(latest)"` (per
`VersionDisplayItem::new`'s label-formatting branch), and is preselected (per
`build_version_completion`'s `preselect: Some(display_item.is_latest)`) —
even though the correctly-computed *stable* latest (the same value
`generate_hover`'s `**Latest**:` header shows, derived from an independent
Ch1/Ch2/fallback resolution chain per issues #227, #313, #373) is a
different, older, stable version.

This is the exact bug class previously filed and fixed as
[[017-hover-latest-marker-prerelease-mismatch/spec|#313]] ("Hover
Recent-versions `(latest)` marker can tag a pre-release while the Latest
header shows stable") — but #313's fix only touched
`crates/deps-core/src/lsp_helpers/hover.rs`'s "Recent versions" list
rendering. The *separate*, shared `prepare_version_display_items` helper —
which #313's own issue body explicitly claimed was unaffected ("does not
affect diagnostics, code actions, or actual latest-version resolution, which
are computed correctly and separately") — has the identical positional-index
flaw and was never fixed. Because this helper is shared `deps-core`
infrastructure (this project's cross-ecosystem-consistency design rule, see
`.claude/CLAUDE.md` "Cross-ecosystem consistency is a first-class design
rule"), the bug reproduces across every ecosystem whose registry can return a
pre-release/milestone as the numerically newest version — confirmed live for
Maven and NuGet, and by design (single shared call site, no ecosystem-level
override) not specific to those two.

This differs from the hover-only #313 case in a way that makes it more
actionable and harmful: a code-action quick-fix list is what a user actually
clicks to apply an edit (`Cmd+.` → pick the entry labeled `"(latest)"`), so
mislabeling a pre-release as `(latest)` and preselecting it can cause the LSP
to *write* a pre-release/milestone version into the user's manifest when they
intended to accept "the latest stable version" — not merely a cosmetic
display mismatch as in the hover-only case #313 fixed.

**Reproduction / Evidence** (live-tested against the real registries, commit
`92150f827`, 2026-09-13, via `.local/testing/lsp_test.py` and the real
`./target/debug/deps-lsp` debug binary):

1. **Maven** (`.local/testing/manifests/pom.xml`,
   `org.springframework.boot:spring-boot-starter-web` pinned to `3.2.0`):
   - `hover` at `(13, 24)` correctly shows `**Latest**: \`4.1.1\`` in the
     header, and its own "Recent versions" list correctly tags
     `4.1.1 *(latest)*` (NOT the newer `4.2.0-M1` milestone at the top of the
     list) — confirming #313's hover fix still holds.
   - `diagnostics` correctly reports `Newer version available: 4.1.1` (also
     correctly stable-aware).
   - `code_action` on that same diagnostic returns, as its first
     (preselected) entry: `title='4.2.0-M1 (latest)'` — the milestone build,
     contradicting both hover and diagnostics for the identical dependency in
     the identical session.

2. **NuGet** (`/tmp/lsp_test_nuget_csproj/App.csproj`, `Newtonsoft.Json`
   pinned to `13.0.3` — the exact original #313 repro package):
   - `hover` at `(5, 34)` correctly shows `**Latest**: \`13.0.4\`` and tags
     `13.0.4 *(latest)*` in its own "Recent versions" list
     (`13.0.5-beta1` listed above it, untagged) — confirms #313's fix.
   - `code_action` on the `Newtonsoft.Json` "Newer version available: 13.0.4"
     diagnostic returns, as its first (preselected) entry:
     `title='13.0.5-beta1 (latest)'` — the pre-release, again contradicting
     hover/diagnostics for the identical dependency.

> [!danger] Blast radius is write-capable, not cosmetic
> Unlike #313 (hover display only), this defect affects the code-action
> quick-fix list and completion preselection — both of which drive an actual
> text edit the LSP applies to the user's manifest on selection. A user who
> trusts the `(latest)` label can end up with a pre-release pinned in their
> dependency file.

### Goal

`prepare_version_display_items` marks `is_latest = true` (and thus the
`"(latest)"` label + preselection) only on a stable, non-pre-release entry —
never on a pre-release — so the version-completion dropdown and the
code-action quick-fix list built from the same shared function agree with
hover's already-correct stable-latest computation.

### Out of Scope

- Changing hover's own "Recent versions" list logic (`crates/deps-core/src/lsp_helpers/hover.rs`) —
  already fixed by #313 and not regressed by this finding.
- Changing how hover's `**Latest**:` header value itself (`latest_line` /
  `latest_ver`, the Ch1/Ch2/fallback resolution chain) is computed — that
  selection logic is out of scope and already correct.
- Changing `removal_status().blocks_resolution()` filtering or yanked-version
  handling — unaffected by this fix.
- Changing the sort order of the raw registry-fetched `available_versions` /
  `versions` list passed into `prepare_version_display_items` (ecosystem
  crates' own `parse_versions_response` sorting stays as-is).
- Changing `MAX_COMPLETION_VERSIONS` (currently `5`) or which versions are
  *included* in the returned list — pre-release entries remain visible and
  selectable in completion/code-action lists; only which single entry (if
  any) is labeled/preselected as `(latest)` changes.
- Unifying this function's "first non-pre-release in fetch order" heuristic
  with hover's independent Ch1/Ch2/fallback stable-latest resolution chain
  into one shared code path — see Open Questions.

## 2. User Stories

### US-001: Trustworthy completion preselection
AS A developer typing a version string in a manifest and invoking
version-completion
I WANT the entry labeled `(latest)` and preselected in the dropdown to be a
stable release, not a pre-release
SO THAT accepting the preselected suggestion never silently pins a
pre-release/milestone build.

**Acceptance criteria:**
```
GIVEN a package whose raw fetched version list's first (highest-numbered,
      non-yanked) entry is a pre-release, and whose correctly-computed
      stable latest is a different, older version present further down the
      same list
WHEN the version-completion dropdown is requested for that dependency
THEN no pre-release entry is labeled "(latest)" or preselected; the entry
     matching the stable latest is labeled "(latest)" and preselected
     instead
```

### US-002: Trustworthy code-action quick-fix
AS A developer applying the "update version" code action (quick-fix) on an
outdated-dependency diagnostic
I WANT the quick-fix entry labeled `(latest)` to be the same stable version
hover and diagnostics already report
SO THAT clicking the top/preselected quick-fix entry never writes a
pre-release/milestone version into my manifest when I intended to accept the
latest stable release.

**Acceptance criteria:**
```
GIVEN the Maven live-test fixture (spring-boot-starter-web pinned to 3.2.0,
      hover/diagnostics correctly reporting 4.1.1 as latest, with 4.2.0-M1
      present as a newer milestone in the raw fetched list)
WHEN the "update version" code action is requested for the corresponding
     diagnostic
THEN the first/preselected quick-fix entry's title is "4.1.1 (latest)", not
     "4.2.0-M1 (latest)"
```

### US-003: Cross-ecosystem consistency
AS A maintainer relying on `deps-core` shared infrastructure for consistent
behavior across all 14 ecosystems
I WANT the `(latest)` marker fix applied once, in the shared
`prepare_version_display_items` function
SO THAT every ecosystem (not just the two confirmed live-tested here)
benefits without ecosystem-specific patches.

**Acceptance criteria:**
```
GIVEN any ecosystem crate whose registry can return a pre-release as the
      numerically newest fetched version
WHEN completion or code-action display items are built via
     prepare_version_display_items
THEN the same non-pre-release-aware `(latest)` selection logic applies,
     with no per-ecosystem override
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `prepare_version_display_items` builds its filtered, capped version slice (post `removal_status().blocks_resolution()` filter, post `take(MAX_COMPLETION_VERSIONS)`) THE SYSTEM SHALL mark `is_latest = true` only on the first entry, in existing fetch order, whose `Version::is_prerelease()` returns `false`, instead of unconditionally marking index `0` | must |
| FR-002 | WHEN every entry within the filtered/capped slice is a pre-release (no stable entry present within the top `MAX_COMPLETION_VERSIONS` non-removed entries) THE SYSTEM SHALL mark no entry as `is_latest` (all `false`) — see Open Questions for the alternative considered | must |
| FR-003 | WHEN determining `is_latest` per FR-001 THE SYSTEM SHALL leave every other field of every `VersionDisplayItem` (label text for non-latest entries, `description`, `index`, `published_at`) unchanged from current behavior — only the boolean passed as `is_latest` into `VersionDisplayItem::new` changes | must |
| FR-004 | WHEN the fix lands in `prepare_version_display_items` THE SYSTEM SHALL apply identically to both call sites — `complete_versions_generic_from` (`crates/deps-core/src/completion.rs`) and the code-action quick-fix builder (`crates/deps-core/src/lsp_helpers/code_actions.rs`) — with no per-call-site branching, since both already delegate to the same shared function | must |
| FR-005 | WHEN the entry marked `is_latest` per FR-001 is not at index `0` (i.e. one or more pre-releases sort above it in fetch order) THE SYSTEM SHALL still render those higher-indexed pre-release entries in the returned list with their normal (non-latest) label and `is_latest = false`, not omit them | must |
| FR-006 | WHEN the fix is implemented THE SYSTEM SHALL apply uniformly across all ecosystem crates that feed `versions` into `prepare_version_display_items` (deps-cargo, deps-npm, deps-pypi, deps-go, deps-bundler, deps-dart, deps-maven, deps-composer, deps-gradle, deps-swift, deps-nuget, deps-github-actions, deps-gitlab-ci, deps-deno-jsr where applicable) without per-ecosystem special-casing, since the bug and its fix are both in shared `deps-core` code | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The pre-release check must not change the overall complexity class of `prepare_version_display_items`; scanning the already-capped (`MAX_COMPLETION_VERSIONS = 5`) slice for the first non-pre-release entry is O(N) over a small fixed N — no additional network or registry calls |
| NFR-002 | Compatibility | The fix must not alter which versions are *included* in the returned `Vec<VersionDisplayItem>` (count, order, filtering by `removal_status`) — only which single entry (if any) carries `is_latest = true` |
| NFR-003 | Testability | The fix must be verifiable with a unit test fixture, colocated with the existing `test_prepare_version_display_items_*` tests (`crates/deps-core/src/completion.rs`, ~line 2724 onward), where the filtered slice's index-0 entry is a pre-release and a later index in the same slice is a stable version |
| NFR-004 | Consistency | The fix should reduce (not necessarily fully eliminate — see Open Questions) disagreement between the `(latest)`-marked entry here and hover's `**Latest**:` header value for the same dependency in the same session |

## 5. Data Model

No new entities. This is a selection-logic fix over data already available
inside `prepare_version_display_items`'s existing scope:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `VersionDisplayItem` (existing, `crates/deps-core/src/completion.rs`) | Display metadata for one version in a completion item or code-action title | `version`, `label`, `description`, `index`, `is_latest`, `published_at` |
| `versions` parameter (existing) | Raw, ecosystem-fetched version list passed into `prepare_version_display_items`, already filtered by `removal_status().blocks_resolution()` and capped at `MAX_COMPLETION_VERSIONS` before the `is_latest` decision is made | ordered list; each entry exposes `version_string()`, `removal_status()`, `is_prerelease()`, `published_at()` via the `Version` trait |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Filtered/capped slice's index 0 is a pre-release; a stable entry exists at a later index within the same slice (Maven/NuGet live-repro shape) | `is_latest` moves to that later stable entry (FR-001); the pre-release at index 0 renders as a normal, non-latest, non-preselected entry (FR-005) |
| Filtered/capped slice's index 0 is a pre-release; a stable entry exists in the full registry response but falls outside the `MAX_COMPLETION_VERSIONS`-capped slice actually considered | No entry in the returned list is marked `is_latest` per FR-002 — `[NEEDS CLARIFICATION: should the implementation instead scan the full, uncapped `versions` list for the first non-pre-release entry before applying `take(MAX_COMPLETION_VERSIONS)`, so a stable version further down the raw list is still found and surfaced (potentially widening which 5 entries are returned, or at least deciding `is_latest` against the wider list even though only 5 are displayed)? Mirrors the equivalent open question left unresolved in #313's own spec, section 9, for hover's truncated slice.]` |
| Filtered/capped slice contains only pre-releases (e.g. a package still in pre-1.0 development with no stable release yet) | No entry marked `is_latest` per FR-002 — `[NEEDS CLARIFICATION: is "no (latest) label at all" acceptable UX for genuinely pre-1.0/pre-release-only packages, or should the first pre-release still be marked latest in that specific case (distinguishing "a stable release exists but sorts lower" from "no stable release exists at all")? #313's hover fix did not need to resolve this because hover's `latest_ver` is `None` in that case too, which already suppresses the marker consistently — the same precedent (FR-002) is used here.]` |
| Filtered/capped slice's index 0 IS already a stable release (the common, non-buggy case) | Behavior is unchanged from today — index-0 entry still gets `is_latest = true`, now via a pre-release check that happens to agree with position rather than via an unconditional positional assumption |
| `Version::is_prerelease()` returns `true` for a version an ecosystem's registry does not actually mark as a pre-release (implementation bug in an ecosystem crate, not this fix) | Out of scope for this fix — `prepare_version_display_items` trusts the `Version` trait's own `is_prerelease()` implementation, same trust boundary hover's #313 fix and diagnostics/hover's stable-latest resolution already rely on |
| Multiple entries in the filtered slice happen to be non-pre-release with the same version string (duplicate entries, e.g. unresolved Bundler platform-variant duplicates from spec 016) | Mark only the first (lowest-index) matching stable entry — same first-match-wins precedent as #313's spec, section 6 |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Code-action quick-fix / completion `(latest)` label attached to a pre-release entry when a stable entry exists within the considered slice | 0 (verified by new unit test per NFR-003, and live re-test against both the Maven `spring-boot-starter-web` and NuGet `Newtonsoft.Json` reproduction cases from this finding) |
| SC-002 | Existing `prepare_version_display_items` / completion / code-action tests (`crates/deps-core/src/completion.rs` ~line 2724+, `crates/deps-core/src/lsp_helpers/code_actions.rs` existing tests) | All continue to pass unmodified (common case: index 0 already is the stable latest) |
| SC-003 | Cross-ecosystem consistency check (Maven, NuGet confirmed live; Cargo, npm, PyPI, Bundler spot-checked at minimum per NFR-003/FR-006) with a pre-release-at-top fixture | `(latest)` marker in completion and code-action output matches hover's `**Latest**:` header value in all tested ecosystems where a stable entry exists within the capped slice |

## 8. Agent Boundaries

### Always (without asking)
- Add a unit test in `crates/deps-core/src/completion.rs` (alongside existing
  `test_prepare_version_display_items_*` tests) that constructs a fixture
  where the filtered slice's index-0 entry is a pre-release distinct from a
  later stable entry, and asserts `is_latest` lands on the correct entry
- Add or extend a test in `crates/deps-core/src/lsp_helpers/code_actions.rs`
  confirming the code-action quick-fix title/preselection reflects the same
  corrected `is_latest` selection
- Run `cargo nextest run -p deps-core` after the change
- Follow existing code style and helper patterns already used in
  `prepare_version_display_items` and `VersionDisplayItem::new`

### Ask First
- Widening the `is_latest` search beyond the `MAX_COMPLETION_VERSIONS`-capped
  slice into the full, untruncated `versions` list (resolves the truncation
  edge case in section 6, but changes which data is scanned and could affect
  which versions are ultimately displayed — confirm with maintainer before
  implementing)
- Any change to `MAX_COMPLETION_VERSIONS` itself
- Any attempt to unify this function's stable-latest heuristic with hover's
  separate Ch1/Ch2/fallback resolution chain into one shared code path
  (larger refactor than this narrowly-scoped fix warrants)

### Never
- Change `removal_status().blocks_resolution()` filtering or yanked-version
  handling
- Change ecosystem crates' raw version-list fetch/sort order
  (`parse_versions_response` and equivalents)
- Modify hover's "Recent versions" rendering (`crates/deps-core/src/lsp_helpers/hover.rs`) —
  already correctly fixed by #313; out of scope here
- Remove pre-release entries from the returned completion/code-action list —
  they must remain visible and selectable, only unlabeled/non-preselected

## 9. Open Questions

- [NEEDS CLARIFICATION: When no stable entry exists within the
  `MAX_COMPLETION_VERSIONS`-capped slice but one does exist further down the
  full raw `versions` list, should the fix (a) omit the `(latest)` marker
  entirely (FR-002, simplest, matches this spec's default), or (b) search the
  full untruncated list for `is_latest` purposes while still only *returning*
  the capped slice for display? This mirrors the identical unresolved
  question left open in #313's spec (section 9) for hover's truncated slice
  — that question also appears to remain unresolved as of this finding.]
- [NEEDS CLARIFICATION: Should `prepare_version_display_items`'s "first
  non-pre-release in raw fetch order" heuristic be reconciled with hover's
  independent, more sophisticated Ch1/Ch2/fallback stable-latest resolution
  chain (issues #227, #313, #373), so that completion/code-action and hover
  are guaranteed to agree even in edge cases beyond simple fetch-order
  pre-release exclusion (e.g. version-requirement-constrained resolution)?
  Full unification is a larger architectural change explicitly out of scope
  for this bug fix; flagging so a follow-up spec can be filed if divergence
  is later observed in practice.]
- Resolved: filed as [#952](https://github.com/bug-ops/deps-lsp/issues/952) (bug, P1), referencing this
  spec.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[017-hover-latest-marker-prerelease-mismatch/spec|Hover "Recent versions" `(latest)` marker can disagree with the header's `Latest` field]] — the sibling defect in the same bug class, already fixed for hover only (issue #313, PR #321)
- [[021-maven-wildcard-latest-ignores-prerelease/spec|Maven/Gradle "Newer version available" diagnostic and quick-fix must not recommend a prerelease when a stable release is newer]] — related prior fix confirming diagnostics' own stable-latest computation is correct and separate from this defect

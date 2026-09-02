---
aliases:
  - Hover Latest Marker Prerelease Mismatch
tags:
  - sdd
  - spec
  - bug
  - lsp-hover
created: 2026-08-24
status: draft
related:
  - "[[constitution]]"
---

# Feature: Hover "Recent versions" `(latest)` marker can disagree with the header's `Latest` field

> [!info] Metadata
> **Author**: continuous-improvement live-testing cycle
> **Branch**: fix/hover-latest-marker-prerelease-mismatch (no issue filed yet)

## 1. Overview

### Problem Statement

`generate_hover` in `crates/deps-core/src/lsp_helpers.rs` builds two independent
representations of "the latest version" from two different data sources within
the same hover popup:

1. The `**Latest**:` header line (around line 1260-1276) is computed from
   `versions.cached.<pkg>.latest`, which is the properly-selected latest
   *stable* version — pre-releases are excluded by default SemVer matching
   rules. This is the same selection logic already exercised correctly by the
   `#305` unsatisfiable-requirement prerelease-hint work.
2. The **"Recent versions"** list (around line 1284-1300) iterates
   `available_versions` — the raw, registry-returned version list sorted
   purely by version-number descending (see e.g. `deps-bundler`'s
   `parse_versions_response`, which sorts with
   `versions.sort_by(|a, b| compare_versions(&b.number, &a.number))`, a pattern
   representative of most ecosystem crates) — and unconditionally marks index
   `0` (`if i == 0`) with `*(latest)*`, without checking whether that raw
   top-of-list entry is itself a pre-release.

Because a raw numeric-descending sort does not distinguish "highest version
number, possibly pre-release" from "highest stable release", whenever a
package's most-recently-numbered version is a pre-release, the "Recent
versions" list's `*(latest)*` tag ends up attached to that pre-release —
directly contradicting the header's own `**Latest**:` value shown two lines
above it in the same hover popup.

This was discovered via live testing against real `nuget.org` data
(`Newtonsoft.Json`, deps-lsp debug binary at commit `2f99f63c`, 2026-08-24)
while regression-spot-checking `#300`'s HttpCache redirect-policy change —
unrelated to that PR. Reproduction:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
```

Hover over `Newtonsoft.Json` produces:

```
# Newtonsoft.Json
Requirement: 13.0.3
Latest: 13.0.4
Recent versions:
- 13.0.5-beta1 (latest) — 7 months ago
- 13.0.4 — 11 months ago
- 13.0.4-beta1
- 13.0.3 — 3 years ago
...
```

The header says `Latest: 13.0.4` (correctly excludes the pre-release), but the
very next section's top entry marks `13.0.5-beta1` — a pre-release — as
`(latest)`, directly contradicting the header two lines above.

> [!note] Blast radius
> This is cosmetic/informational only. It does not affect diagnostics, code
> actions, or actual latest-version resolution logic (`versions.cached.latest`),
> which are computed correctly and separately from the display bug described
> here.

### Goal

The `*(latest)*` marker in the "Recent versions" list agrees with the header's
`**Latest**:` value in every hover popup — i.e. it marks whichever list entry's
version string matches the header's stable-latest version, never a
pre-release entry that the header itself excluded.

### Out of Scope

- Changing how `versions.cached.<pkg>.latest` itself is computed (that
  selection logic is already correct per `#305`).
- Changing the sort order of `available_versions` / the raw registry-fetch
  list (ecosystem crates' `parse_versions_response` sorting stays as-is).
- Adding a distinct "pre-release" badge/label to individual entries in the
  "Recent versions" list beyond what is needed to fix the marker mismatch
  (existing yanked-label and age-suffix rendering stay unchanged).
- Any change to `deps-core`'s existing pre-release exclusion / SemVer matching
  rules used for `**Latest**:` computation.

## 2. User Stories

### US-001: Consistent hover popup
AS A developer viewing a dependency's hover tooltip
I WANT the "latest" marker in the recent-versions list to match the version
the header calls "Latest"
SO THAT I am not misled into thinking a pre-release is the recommended
upgrade target when the header says otherwise.

**Acceptance criteria:**
```
GIVEN a package whose raw registry version list's first (highest-numbered)
      entry is a pre-release, and whose header `**Latest**:` value is a
      different, stable version present further down the truncated list
WHEN the hover popup is rendered
THEN the `*(latest)*` marker is attached to the list entry whose version
     string equals the header's `**Latest**:` value, not to the pre-release
     entry at index 0
```

### US-002: No marker duplication or omission surprise
AS A developer viewing a dependency's hover tooltip
I WANT at most one entry in "Recent versions" tagged `(latest)`
SO THAT the popup is unambiguous.

**Acceptance criteria:**
```
GIVEN the header's `**Latest**:` value
WHEN the "Recent versions" list is rendered
THEN exactly zero or one entries carry the `*(latest)*` marker (never more
     than one), and if the header has no `**Latest**:` value at all (e.g.
     dependency not resolvable), no entry in the list is marked `(latest)`
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN rendering the "Recent versions" list AND a `**Latest**:` header value was computed (i.e. `latest_ver` is `Some`) THE SYSTEM SHALL mark with `*(latest)*` the list entry whose `version.version_string()` equals `latest_ver`, instead of unconditionally marking index `0` | must |
| FR-002 | WHEN the header's `latest_ver` is `None` (dependency not resolvable / no cached latest) THE SYSTEM SHALL NOT mark any entry in the "Recent versions" list with `*(latest)*` | must |
| FR-003 | WHEN the header's `latest_ver` string does not match any entry within the truncated top-`HOVER_RECENT_VERSIONS` slice actually rendered THE SYSTEM SHALL omit the `*(latest)*` marker entirely for that hover response rather than falling back to marking index 0 | must |
| FR-004 | WHEN the header's `latest_ver` matches a list entry THE SYSTEM SHALL preserve all other per-entry rendering for that same index unchanged (age suffix, yanked label suppression, code-span formatting) — only the marker-selection condition changes, not the rendering of the matched line itself | must |
| FR-005 | WHEN the header's `latest_ver` matches an entry at an index other than 0 (i.e. a pre-release sorts above it in the raw list) THE SYSTEM SHALL still render that non-zero-index entry using the same non-`(latest)` branch logic currently used for entries below index 0 (yanked check, age suffix), except it now additionally carries the `*(latest)*` marker instead of that entry's original unmarked/yanked rendering | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The marker lookup must not change the overall hover-generation complexity class; a linear scan over the already-truncated top-`HOVER_RECENT_VERSIONS` slice (small, fixed-size N) to find the matching entry is acceptable — no additional network or registry calls |
| NFR-002 | Compatibility | The fix must apply uniformly across all ecosystem crates that feed `available_versions` into `generate_hover` (deps-cargo, deps-npm, deps-pypi, deps-go, deps-bundler, deps-dart, deps-maven, deps-composer, deps-gradle, deps-swift, deps-nuget) without per-ecosystem special-casing, since the bug is in shared `deps-core` code, not ecosystem-specific code |
| NFR-003 | Testability | The fix must be verifiable with a unit test fixture where the raw `available_versions` list's index-0 entry is a pre-release distinct from the separately-supplied `versions.cached.latest` stable value |

## 5. Data Model

No new entities. This is a display-logic fix over two existing data sources
already present in `generate_hover`'s scope:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `latest_ver` (existing, local `Option<&str>`) | The header's stable-latest version string, derived from `versions.cached.<pkg>.latest` | version string |
| `available_versions` (existing) | Raw registry-returned version list, sorted numerically descending, may include pre-releases at the top | ordered list of version entries; each has `version_string()`, `is_yanked()`, publish-time metadata |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Raw list index 0 is a pre-release; header's stable latest is present further down within the rendered top-N slice | `(latest)` marker moves to that entry (per FR-001); entry at index 0 renders as a normal (non-latest) pre-release line |
| Raw list index 0 is a pre-release; header's stable latest exists in the registry but falls outside the truncated top-`HOVER_RECENT_VERSIONS` slice actually shown | No entry in the rendered list is marked `(latest)` (per FR-003) — `[NEEDS CLARIFICATION: should the implementation instead widen the search to the full untruncated `available_versions` list before giving up, only truncating for display? Left as an implementation decision; either resolves the header/list contradiction, but full-list search is more expensive and only matters when the stable latest is unusually far down the raw list]` |
| Header has no `**Latest**:` value at all (`latest_ver` is `None`, e.g. dependency unresolved) | No entry marked `(latest)` (per FR-002); this already matches today's absence of contradiction since the header line itself is also omitted in this case |
| Raw list index 0 IS the stable latest (the common, non-buggy case) | Behavior is unchanged from today — index-0 entry still gets `(latest)`, now via string-match rather than positional assumption |
| Multiple entries in the raw list happen to share the same version string as `latest_ver` (should not occur in practice, but registries can return duplicates) | Mark only the first (highest-priority / lowest-index) matching entry — `[NEEDS CLARIFICATION: confirm no ecosystem crate can legitimately return duplicate version strings in `available_versions`; if bundler platform-variant duplicates from spec 016 are still unresolved when this ships, first-match is the safe default]` |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover popups where header `**Latest**:` and list `*(latest)*` marker disagree on version string | 0 (verified by new unit test fixture per NFR-003 and live re-test against the `Newtonsoft.Json` NuGet reproduction case) |
| SC-002 | Existing hover tests (`test_generate_hover_recent_versions_shows_age_when_known` and siblings, `crates/deps-core/src/lsp_helpers.rs` ~line 3738+) | All continue to pass unmodified (common case: index 0 already is the stable latest) |
| SC-003 | Cross-ecosystem consistency check (deps-cargo, deps-npm, deps-pypi, deps-nuget, deps-bundler at minimum) with a pre-release-at-top fixture | Marker matches header in all tested ecosystems |

## 8. Agent Boundaries

### Always (without asking)
- Add a unit test in `crates/deps-core/src/lsp_helpers.rs` that constructs a
  fixture where the raw version list's index-0 entry is a pre-release
  distinct from the mocked `versions.cached.latest` value, and asserts the
  `(latest)` marker lands on the correct entry
- Run `cargo nextest run -p deps-core` after the change
- Follow existing code style and helper patterns already used in
  `generate_hover` (e.g. `markdown_code_span`, `writeln!` usage)

### Ask First
- Widening the match to search beyond the truncated `HOVER_RECENT_VERSIONS`
  slice into the full `available_versions` list (resolves the truncation edge
  case in section 6, but changes lookup cost characteristics — confirm with
  maintainer before implementing)
- Any change to `HOVER_RECENT_VERSIONS` truncation count itself

### Never
- Change the pre-release exclusion / SemVer matching logic that computes
  `versions.cached.<pkg>.latest` (out of scope, already correct)
- Change ecosystem crates' raw version-list sort order
  (`parse_versions_response` and equivalents)
- Modify diagnostics or code-action logic — this is a hover-rendering-only fix

## 9. Open Questions

- [NEEDS CLARIFICATION: When the header's stable latest is not found within the
  truncated top-N "Recent versions" slice, should the fix (a) omit the
  `(latest)` marker entirely, or (b) search the full untruncated
  `available_versions` list before truncating for display? Left as an
  implementation decision per the finding; (a) is simpler and matches FR-003,
  (b) fully eliminates the contradiction at a small extra cost.]
- [NEEDS CLARIFICATION: Should a `(pre-release)` or similar marker be added to
  entries above the matched `(latest)` line to make it visually obvious *why*
  a higher-numbered version isn't tagged latest? Not required by this fix but
  would improve UX; left out of scope per section "Out of Scope" unless the
  maintainer wants it bundled.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[016-bundler-platform-duplicate-versions/spec|Deduplicate RubyGems platform-variant versions in Bundler hover]] — related recent hover-rendering fix in the same cycle
- PR #305 — prerelease-hint enrichment for unsatisfiable-requirement diagnostics (source of the correct `versions.cached.latest` selection logic referenced here)

---
aliases:
  - NuGet Unlisted Version Marker
  - NuGet Multi-Project Lock File Matching
tags:
  - sdd
  - spec
  - bug
  - deps-nuget
  - lockfile
  - hover
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: NuGet Unlisted-Version Hover Marker and Multi-Project Lock File Matching

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Status**: Shipped — PR #458 (issue #451)
> **Priority**: P2
> **Type**: bug

## 1. Overview

### Problem Statement

`deps-nuget` carried two `TODO(critic)` markers documenting known, accepted-tradeoff gaps
that were never turned into tracked issues — issue #451 formalized both, and PR #458 shipped
both fixes:

1. **Unlisted versions reported as listed (D1).** The flat-container `get_versions` response
   (`PackageBaseAddress`) carries no `listed` flag at all, so an unlisted (delisted/pulled)
   NuGet version was indistinguishable from a listed one everywhere — hover, completion, and
   inlay hints. The registration hive (`RegistrationsBaseUrl/3.6.0`) does carry a `listed`
   field, but fetching it for every dependency on every code path (including inlay hints,
   which render for every dependency in an open document) was rejected as the wrong latency
   tradeoff. The gap sat undocumented and unfiled.
2. **Multi-project lock file names not matched (D3).** NuGet's per-project lock file
   convention, `packages.<project_name>.lock.json`, cannot be expressed in
   `lockfile_filenames()`'s exact-name list (`&["packages.lock.json"]`, no glob support), so
   a project sharing a directory with sibling projects — each with its own per-project lock
   file — never had its lock file located at all.

### Goal (as shipped)

- Hover renders a `*(unlisted)*` marker on each unlisted version in the "Recent versions"
  list, sourced from the registration hive, without changing completion, inlay hints, or
  diagnostics (which all share the un-enriched cached version list).
- `NuGetLockParser::locate_lockfile` finds a manifest's own
  `packages.<project_name>.lock.json` when the exact `packages.lock.json` name is absent,
  matched by the *requesting manifest's own* file stem — never the first
  `packages.*.lock.json` file a directory scan happens to find.

### Out of Scope

- Threading `listed`/unlisted status into `deps_core::Version::removal_status` — that shared
  type backs `get_versions_with`, which completion (`complete_versions_generic`) and the
  per-document cached version list (read by inlay hints and diagnostics) all consume.
  `prepare_version_display_items` filters unconditionally on
  `removal_status().blocks_resolution()`, so wiring unlisted status through there would make
  an unlisted version silently vanish from completion suggestions too — the exact tradeoff
  issue #451 rejected. The marker stays hover-only, by design.
- A general-purpose glob/wildcard capability for `Ecosystem::manifest_patterns` beyond the
  single-`*` prefix/suffix scheme already in use — the new
  `lockfile_pattern_matches`/`manifest_pattern_matches` helpers in
  `crates/deps-core/src/ecosystem_registry.rs` reuse that existing scheme rather than
  introducing a new one.

## 2. User Stories

### US-001: See that a version is unlisted, on hover

AS A developer hovering over a NuGet `PackageReference`
I WANT the "Recent versions" list to mark any unlisted (delisted/pulled) version
SO THAT I know not to newly depend on it, the same way a `*(yanked)*` marker warns me off a
yanked version in other ecosystems

**Acceptance criteria (as shipped):**
```
GIVEN a package whose registration hive marks version 1.0.0 as listed: false (or, for a
  registration predating that field, published <= the unlisted sentinel epoch)
WHEN I hover over a dependency on that package
THEN the "Recent versions" bullet for 1.0.0 reads "- `1.0.0` *(unlisted)*", in the same
  position/spacing formatter.yanked_label() uses for *(yanked)*, and completion/inlay-hints/
  diagnostics for the same package are unaffected
```

### US-002: Resolve a per-project lock file in a multi-project directory

AS A developer with two or more `.csproj` files sharing one directory, each with its own
`packages.<ProjectName>.lock.json`
I WANT the LSP to find *my* project's lock file, not a sibling's
SO THAT in-use-version data (hover, diagnostics) reflects what my project actually has
resolved, not an unrelated project's resolution

**Acceptance criteria (as shipped):**
```
GIVEN App1.csproj and App2.csproj in the same directory, with packages.App1.lock.json and
  packages.App2.lock.json both present
WHEN the LSP locates App1.csproj's lock file
THEN it resolves to packages.App1.lock.json, never packages.App2.lock.json, and if only
  packages.App2.lock.json exists (App1's own lock file absent), locate_lockfile returns None
  rather than misattaching App2's resolved versions
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a registration-hive catalog entry carries `"listed": false`, OR carries no `listed` field and its `published` timestamp is the unlisted sentinel (`<= 1970-01-01T00:00:00Z`, the pre-`listed`-field signal) THE SYSTEM SHALL classify that version as unlisted | must |
| FR-002 | WHEN `NuGetEcosystem::generate_hover` renders a hover for a dependency THE SYSTEM SHALL concurrently (`tokio::join!`, not sequentially) fetch the base hover render and `NuGetRegistry::unlisted_versions_for_hover`'s unlisted-version set, so the unlisted lookup does not double hover's worst-case latency | must |
| FR-003 | WHEN the unlisted-version fetch does not complete within `HOVER_UNLISTED_TIMEOUT` (5 seconds) THE SYSTEM SHALL return the base hover unmodified rather than delaying or failing the hover response | must |
| FR-004 | WHEN the unlisted-version fetch fails (parse error, unreachable feed, no `RegistrationsBaseUrl` resource) THE SYSTEM SHALL degrade to an empty unlisted set and return the base hover unmodified, never surfacing a distinct error to the caller | must |
| FR-005 | WHEN at least one version in the rendered "Recent versions" list is unlisted THE SYSTEM SHALL insert a `*(unlisted)*` marker immediately after the version literal and before any existing tag (`*(latest)*`, age suffix), leaving non-bullet lines (headers, footer) unchanged | must |
| FR-006 | THE SYSTEM SHALL NOT thread unlisted status into `deps_core::Version::removal_status`, completion, inlay hints, or diagnostics — the marker is hover-only by design (see Out of Scope) | must |
| FR-007 | WHEN `NuGetLockParser::locate_lockfile`'s exact-name search (`packages.lock.json`, same directory then up to 5 ancestor directories) finds nothing THE SYSTEM SHALL fall back to `packages.<project_name>.lock.json`, where `<project_name>` is the requesting manifest's own file stem, searched in the same directory then the same ancestor-walk order | must |
| FR-008 | WHEN the multi-project fallback searches for `packages.<project_name>.lock.json` THE SYSTEM SHALL match only that exact computed filename — never the first `packages.*.lock.json` file found by a directory scan — so a directory holding multiple projects' per-project lock files never attaches an unrelated project's resolved versions to a manifest | must — regression, tester-found |
| FR-009 | THE SYSTEM SHALL register `"packages.*.lock.json"` in `NuGetEcosystem::lockfile_filenames()` alongside the existing exact `"packages.lock.json"`, solely so `EcosystemRegistry`'s file-watch glob registration picks up per-project lock file changes — actual lock file *location* is unaffected by this list and is performed independently by `NuGetLockParser::locate_lockfile`'s own directory scan | must |
| FR-010 | WHEN `EcosystemRegistry::get_for_lockfile` matches a filename against a single-`*`-wildcard `lockfile_filenames()` entry THE SYSTEM SHALL apply the same prefix/suffix matching scheme `manifest_patterns` already uses (`lockfile_pattern_matches`/`prefix_suffix_matches`), not a new matching mechanism | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | The unlisted-version enrichment adds zero additional latency to hover's happy path beyond the pre-existing registration-hive walk already performed for publish-time freshness — both signals are extracted from the same `registration_enrichment_from_index` walk in one pass |
| NFR-002 | Reliability | Hover must never fail or hang because of the unlisted-version enrichment — bounded by `HOVER_UNLISTED_TIMEOUT` and fully error-tolerant (FR-003/FR-004) |
| NFR-003 | Reliability | The multi-project lock file fallback must never silently attach a sibling project's resolved versions — verified by dedicated regression tests (FR-008) |
| NFR-004 | Maintainability | The lockfile-pattern and manifest-pattern wildcard matching share one `prefix_suffix_matches` helper in `crates/deps-core/src/ecosystem_registry.rs` rather than duplicating the match logic per call site |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `RegistrationEnrichment` (new, `deps-nuget::registry`) | Per-package result of one registration-hive walk | `published: HashMap<String, PublishTime>` (existing), `unlisted: HashSet<String>` (new) |
| `CatalogEntry::listed` (new field) | Explicit unlist flag on a registration-hive entry, absent on entries predating the field | `Option<bool>` |
| `NuGetRegistry::unlisted_versions_for_hover` (new method) | Hover-only accessor returning the unlisted subset of a package's recent versions | Degrades to an empty `HashSet` on any failure |
| `NuGetLockParser::locate_multi_project_lockfile` (new function) | Computes and searches for `packages.<project_stem>.lock.json` | Mirrors `locate_lockfile_for_manifest`'s own directory-walk depth (`MAX_WORKSPACE_DEPTH = 5`) |
| `EcosystemRegistry::get_for_directory_pattern` / `lockfile_pattern_matches` / `prefix_suffix_matches` (new, `deps-core::ecosystem_registry`) | Shared wildcard-matching primitives | `prefix_suffix_matches` is the single-`*` glob core reused by both the lockfile matcher here and the directory-pattern matcher used by the sibling pypi fix (see [[028-pypi-requirements-documentlinks-and-directory-layout/spec\|requirements.txt documentLinks and directory-layout support]]) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Registration entry has no `listed` field (predates it) but `published` is the unlisted sentinel | Classified unlisted (FR-001's fallback signal) |
| Registration hive unreachable / malformed / no `RegistrationsBaseUrl` resource at all | Empty unlisted set; base hover renders unmodified (FR-004) |
| Unlisted-version fetch exceeds `HOVER_UNLISTED_TIMEOUT` | Base hover returned unmodified; a `tracing::warn!` is logged (FR-003) |
| No unlisted versions among the rendered "Recent versions" | Hover markdown passes through `annotate_unlisted_versions` unchanged |
| Two `.csproj` files in one directory, each with its own per-project lock file | Each resolves to its own lock file by exact file-stem match (FR-008) |
| Only a sibling project's `packages.<OtherProject>.lock.json` exists, this manifest's own is absent | `locate_lockfile` returns `None` — no misattachment (FR-008) |
| Both `packages.lock.json` (exact) and `packages.<project>.lock.json` present in the same directory | Exact name wins; multi-project fallback is never consulted |
| Multi-project lock file located in an ancestor (workspace) directory, not the manifest's own directory | Found via the same ancestor-walk order `locate_lockfile_for_manifest` already uses, up to `MAX_WORKSPACE_DEPTH` |
| Unrelated files in the directory (`packages.json`, `packages..lock.json` with an empty project-name segment) | Not matched — `project_name.is_empty()` is rejected, and `packages.json` doesn't fit the computed pattern |

## 7. Success Criteria

| ID | Metric | Target | Verification |
|----|--------|--------|--------------|
| SC-001 | Unlisted versions marked in hover | `*(unlisted)*` rendered for every version classified unlisted per FR-001 | `test_annotate_unlisted_versions_tags_matching_bullet`, `test_annotate_unlisted_versions_preserves_existing_tags_and_age_suffix` (deps-nuget/src/ecosystem.rs) |
| SC-002 | No regression to completion/inlay-hints/diagnostics | Unaffected by this change — verified by the pre-existing `deps-nuget` test suite passing unmodified | Existing suite, unmodified |
| SC-003 | Multi-project lock file resolves to the correct sibling | Each of two co-located per-project lock files resolves to its own manifest, never the other's | `test_locate_lockfile_multi_project_matches_own_project_not_first_found`, `test_locate_lockfile_multi_project_does_not_match_other_projects_lock_file` (deps-nuget/src/lockfile.rs) |
| SC-004 | Exact lock file name still takes priority | `packages.lock.json` wins over the multi-project fallback when both exist | `test_locate_lockfile_prefers_exact_name_over_multi_project` |
| SC-005 | File-watch glob registered for per-project lock files | `lockfile_filenames()` includes `"packages.*.lock.json"` | `test_lockfile_filenames` |

## 8. Agent Boundaries

### Always (without asking)
- Keep the unlisted-version enrichment hover-only; never thread it into
  `Version::removal_status` or the shared cached-version-list path (FR-006).
- Keep `HOVER_UNLISTED_TIMEOUT`-bounded, fail-open behavior for the unlisted fetch — hover
  must never hang or error because of this optional decoration.
- Reuse `prefix_suffix_matches` for any future single-`*`-wildcard matching need in
  `ecosystem_registry.rs` rather than re-implementing prefix/suffix comparison.

### Ask First
- Widening `Ecosystem::lockfile_filenames()`'s pattern syntax beyond a single `*` wildcard.
- Enriching completion, inlay hints, or diagnostics with unlisted status — a deliberate,
  documented scope exclusion (Out of Scope), not an oversight.

### Never
- Pick "the first `packages.*.lock.json` found in a directory scan" as a shortcut for the
  multi-project fallback — this was the exact tester-found regression FR-008 closes.
- Add a dedicated map/index for directory-pattern or lockfile-pattern matching where the
  existing linear scan (pattern count per ecosystem is tiny) already suffices.

## 9. Open Questions

None — this spec documents already-shipped, merged work with no outstanding scope decisions.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[028-pypi-requirements-documentlinks-and-directory-layout/spec|requirements.txt documentLinks and directory-layout support]] — the pypi half of the same PR #458, sharing the new `ecosystem_registry.rs` wildcard-matching primitives
- `crates/deps-nuget/src/registry.rs` — `RegistrationEnrichment`, `unlisted_versions_for_hover`, `accumulate_catalog_entries`
- `crates/deps-nuget/src/ecosystem.rs` — `generate_hover` override, `annotate_unlisted_versions`
- `crates/deps-nuget/src/lockfile.rs` — `locate_multi_project_lockfile`
- `crates/deps-core/src/ecosystem_registry.rs` — `prefix_suffix_matches`, `lockfile_pattern_matches`
- Issue #451
- PR #458

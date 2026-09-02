---
aliases:
  - Lightweight Registry Metadata for npm/PyPI
  - Abbreviated Packument and Simple JSON API Adoption
tags:
  - sdd
  - spec
  - enhancement
  - performance
  - npm
  - pypi
created: 2026-08-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Adopt Lightweight Registry Metadata Formats for npm and PyPI Version Lookups

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: feat/lightweight-registry-metadata
> **Priority**: P2
> **Type**: enhancement

## 1. Overview

### Problem Statement

`deps-npm` and `deps-pypi`'s version-lookup hot path is called on every hover,
completion, and diagnostic refresh (per `.claude/rules/rust-code.md`'s
requirement that hover/completion responses return quickly). Both clients
currently fetch the **heaviest** payload their registry offers, even though
each registry provides an official lightweight alternative that carries every
field the hot path actually parses.

**npm** — `NpmRegistry::get_versions` (`crates/deps-npm/src/registry.rs:69-74`)
fetches `https://registry.npmjs.org/{package}` with no `Accept` header,
returning the full packument (complete README, full per-version dependency
graphs, `maintainers`, `time`, etc.). The parser (`VersionMetadata`,
`crates/deps-npm/src/registry.rs:162-167`) only reads `deprecated` per
version. npm's registry has supported an abbreviated packument since 2018 via
`Accept: application/vnd.npm.install-v1+json`
([registry metadata docs](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)).
Verified live:

```
curl -s -o /dev/null -w "%{size_download}\n" https://registry.npmjs.org/express
# 804975
curl -s -H "Accept: application/vnd.npm.install-v1+json" \
     -o /dev/null -w "%{size_download}\n" https://registry.npmjs.org/express
# 339376  (58% smaller)
```

The abbreviated packument was fetched live and confirmed to contain, per
version, exactly `{name, version, directories, dist, engines, deprecated}` —
a strict superset of the one field (`deprecated`) `parse_package_metadata`
consumes, plus `dist-tags`, `modified`, and standard ETag/Last-Modified
response headers unchanged.

**PyPI** — `PypiRegistry::get_versions` (`crates/deps-pypi/src/registry.rs:113-127`)
fetches `https://pypi.org/pypi/{package}/json` (the full JSON API), returning
the complete `info` block (description, classifiers, project URLs) plus the
full `releases` map with every historical file's metadata. The parser
(`PypiRelease`, `crates/deps-pypi/src/registry.rs:317-320`) only reads
`yanked` per release file. PyPI's PEP 691 Simple JSON API
(`https://pypi.org/simple/{package}/`, `Accept:
application/vnd.pypi.simple.v1+json`) is purpose-built for version and
file-availability lookups. Verified live:

```
curl -s -o /dev/null -w "%{size_download}\n" https://pypi.org/pypi/django/json
# 619755
curl -s -H "Accept: application/vnd.pypi.simple.v1+json" \
     -o /dev/null -w "%{size_download}\n" https://pypi.org/simple/django/
# 411376  (34% smaller)
```

The Simple JSON API response was fetched live and confirmed to expose a
top-level `versions: [String]` array (the full, deduplicated version list —
exactly what `get_versions` needs to build its result) plus a `files` array
where each file carries a `yanked: bool` field, matching the semantics
`get_versions` already consumes. It does **not** carry a per-file `version`
field, which is a real difference from the current `releases: { version:
[files] }` grouping and is addressed as a design decision in the plan (see
[[007-lightweight-registry-metadata/plan|plan]]).

A **separate** function, `PypiRegistry::get_package_metadata`
(`crates/deps-pypi/src/registry.rs:220-234`, using the `PypiInfo` struct at
line 310-315: `summary`, `project_urls`), genuinely needs the full JSON API's
`info` block for hover display and must **not** be changed by this feature.

Other ecosystem clients were surveyed and found to already use lean registry
endpoints: cargo (sparse index), composer (`p2` metadata endpoint), nuget
(v3 flat-container), go (module proxy protocol, inherently lean), maven/gradle
(repository XML metadata), dart (`pub.dev/api`), bundler (rubygems `api/v1`,
no lighter alternative exists). This feature is scoped to npm and PyPI only.

### Goal

`deps-npm::registry::NpmRegistry::get_versions` and
`deps-pypi::registry::PypiRegistry::get_versions` fetch the lightest payload
their registry offers that still satisfies every field currently consumed,
with no change to `PypiRegistry::get_package_metadata` or any other
ecosystem's registry client, and no loss of currently-produced `NpmVersion` /
`PypiVersion` data.

### Out of Scope

- Any registry client other than `deps-npm::registry::get_versions` and
  `deps-pypi::registry::get_versions` (cargo, go, bundler, dart, maven,
  composer, gradle, swift, nuget are already lean; `deps-pypi`'s
  `get_package_metadata` and `deps-npm`'s `search` are unaffected).
- Adding npm registry search-result trimming — `search()`
  (`crates/deps-npm/src/registry.rs:143-153`) already uses the lean
  `-/v1/search` endpoint and is not part of this finding.
- Byte-based `HttpCache` capacity accounting (tracked separately in issue
  #142) — this feature reduces per-entry byte size, which improves #142's
  effective headroom, but does not implement byte-based eviction itself.
- Adding configurable/self-hosted registry URLs for npm or PyPI — both
  `REGISTRY_BASE` and `PYPI_BASE` remain hardcoded to the public registries;
  content-negotiation compatibility with third-party mirrors is not addressed.
- Changing the `NpmVersion` / `PypiVersion` public struct shape, or the
  `deps_core::Registry` / `deps_core::Version` trait implementations for
  either ecosystem.

## 2. User Stories

### US-001: Faster hover/completion for packages with large version history

AS A developer with `express`, `lodash`, `django`, or `numpy` (or any
package with a long release history) in their manifest
I WANT hover, completion, and diagnostic checks to fetch only the version
data actually needed
SO THAT I see results sooner and my editor's LSP session spends less
bandwidth and memory on data it never displays

**Acceptance criteria:**
```
GIVEN an open package.json with "express" as a dependency
WHEN deps-lsp resolves hover/completion/diagnostics for "express"
THEN the HTTP request sent to registry.npmjs.org carries
     `Accept: application/vnd.npm.install-v1+json`
AND the response body is the abbreviated packument (smaller than the full
    packument), not the full packument
AND the resulting version list (versions, deprecated flags) is identical to
    what the full-packument code path would have produced
```

```
GIVEN an open requirements.txt or pyproject.toml with "django" as a dependency
WHEN deps-lsp resolves hover/completion/diagnostics for "django"
THEN the HTTP request sent is to https://pypi.org/simple/django/ with
     `Accept: application/vnd.pypi.simple.v1+json`, not to
     https://pypi.org/pypi/django/json
AND the resulting version list (versions, yanked flags) is identical to what
    the full-JSON-API code path would have produced
```

### US-002: Hover metadata (summary, project URLs) is unaffected

AS A developer viewing hover text for a PyPI package
I WANT the hover panel to keep showing the package summary and project URLs
SO THAT switching `get_versions` to a lighter endpoint does not degrade any
user-visible feature

**Acceptance criteria:**
```
GIVEN an open pyproject.toml with "flask" as a dependency
WHEN hover is requested and deps-lsp calls get_package_metadata("flask")
THEN the request still goes to https://pypi.org/pypi/flask/json (full JSON API)
AND the hover panel still shows summary and project URLs, unchanged from
    current behavior
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `NpmRegistry::get_versions` fetches package metadata THE SYSTEM SHALL send an `Accept: application/vnd.npm.install-v1+json` header on the request to `https://registry.npmjs.org/{package}` | must |
| FR-002 | WHEN `NpmRegistry::get_versions` parses the abbreviated packument response THE SYSTEM SHALL continue to extract `version` and `deprecated` per entry and produce the same `Vec<NpmVersion>` shape and sort order (newest-first) as before | must |
| FR-003 | WHEN `PypiRegistry::get_versions` fetches version data THE SYSTEM SHALL request `https://pypi.org/simple/{normalized_name}/` with `Accept: application/vnd.pypi.simple.v1+json` instead of `https://pypi.org/pypi/{normalized_name}/json` | must |
| FR-004 | WHEN `PypiRegistry::get_versions` parses the Simple JSON API response THE SYSTEM SHALL derive the full version list from the top-level `versions` array and the per-version `yanked` flag from the `files` array (any file belonging to a version being yanked marks that version yanked), matching current any-file-yanked semantics | must |
| FR-005 | WHEN `PypiRegistry::get_package_metadata` fetches package info for hover display THE SYSTEM SHALL continue to use the full JSON API endpoint (`https://pypi.org/pypi/{name}/json`) unchanged | must |
| FR-006 | WHEN either new endpoint returns a non-2xx status, malformed JSON, or a network error THE SYSTEM SHALL surface the same error types as before (`DepsError::RegistryError`, `PypiError::PackageNotFound`, `PypiError::registry_error`) with no new failure modes | must |
| FR-007 | WHEN `NpmRegistry::get_latest_matching` and `PypiRegistry::get_latest_matching` call the now-changed `get_versions` THE SYSTEM SHALL continue to produce identical matching results, since neither function's own logic changes | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | npm `get_versions` response payload for a representative large package (e.g. `express`) is measurably smaller than the current full-packument payload (58% smaller observed live); PyPI `get_versions` response payload for a representative large package (e.g. `django`) is measurably smaller than the current full-JSON-API payload (34% smaller observed live) |
| NFR-002 | Correctness | Zero loss of currently-consumed fields: `deprecated` (npm) and `yanked` (PyPI) must be derivable from the new payloads with identical resulting values for the same package, across representative fixture and live packages |
| NFR-003 | Caching | `HttpCache`'s ETag (`If-None-Match`) and Last-Modified (`If-Modified-Since`) conditional-request flow (`crates/deps-core/src/cache.rs`) must continue to function against both new endpoints — repeated requests for an unchanged package must still receive `304 Not Modified` and reuse the cached body |
| NFR-004 | Compatibility | `NpmVersion` and `PypiVersion` public struct shapes, and the `deps_core::Registry` / `deps_core::Version` trait implementations for both ecosystems, are unchanged — this is an internal fetch-format change only, invisible to callers |
| NFR-005 | Testability | Both changed parsers must be covered by unit tests using fixture payloads that match the *actual* shape of the new endpoints (abbreviated packument / PEP 691 Simple JSON), not the old shape, to catch any latent assumption mismatch |

## 5. Data Model

No changes to `NpmVersion` or `PypiVersion` (both remain `{version: String,
deprecated/yanked: bool}`). This feature changes only the *source* JSON shape
parsed inside each registry client's private response types.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `NpmVersion` | Existing, unchanged | `version`, `deprecated` |
| `PypiVersion` | Existing, unchanged | `version`, `yanked` |
| npm abbreviated packument (new internal parse target) | npm's lightweight package-metadata response, replaces the full packument as `get_versions`'s input | `versions: { [version]: { version, dist, engines, deprecated } }`, `dist-tags`, `modified` |
| PyPI PEP 691 Simple JSON response (new internal parse target) | PyPI's lightweight per-project index response, replaces the full JSON API as `get_versions`'s input | `name`, `versions: [String]`, `files: [{ filename, yanked, hashes, ... }]`, `meta` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| PyPI Simple JSON API's `files` entries have no explicit per-file `version` field (unlike the current `releases` map, which is already grouped by version) | `get_versions` must derive each file's version by parsing the filename (sdist/wheel naming conventions) to match it against an entry in the top-level `versions` array — see plan for the exact parsing approach |
| Package has zero published versions | Both endpoints return an empty version collection; `get_versions` returns an empty `Vec`, same as current behavior |
| npm package has no `deprecated` field on a version | Same as today — `#[serde(default)]` treats it as `None`/not deprecated |
| PyPI Simple JSON response's `files` array is empty for a version present in `versions` (edge case: version exists in the index but has no distributable files) | Version is treated as not yanked (no yanked file found) — the same result the current "any release file yanked" logic would produce for a release with zero files |
| A version string in PyPI's `versions` array fails PEP 440 parsing | Filtered out silently, matching current behavior in `parse_package_metadata`'s `filter_map` |
| Either endpoint is unreachable or returns a transient 5xx | Existing `HttpCache` stale-while-revalidate fallback applies unchanged — cached data (if any) is served, otherwise the existing error path (FR-006) triggers |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | npm `get_versions` response payload size for `express` (live) | ≤ 50% of current full-packument size (58% reduction observed) |
| SC-002 | PyPI `get_versions` response payload size for `django` (live) | ≤ 70% of current full-JSON-API size (34% reduction observed) |
| SC-003 | Unit tests for `parse_package_metadata` (both crates) using fixtures matching the real new payload shapes | 100% passing, including the existing deprecated/yanked assertions |
| SC-004 | Live end-to-end: version list (set of versions + deprecated/yanked flags) for `express` and `django` before vs. after the change | Identical output |
| SC-005 | Live end-to-end: repeated `get_versions` call for an unchanged package against both new endpoints | Second call observes `304 Not Modified` via `HttpCache` |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `HttpCache::get_cached_with_headers` (`crates/deps-core/src/cache.rs:204`), which already supports injecting an `Accept` header — no new HTTP client code needed
- Add/update unit test fixtures to match the real abbreviated-packument and PEP 691 Simple JSON shapes (captured live in this spec's Overview)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features --lib --bins` before considering the change complete
- Update `CHANGELOG.md` under `[Unreleased]`
- Follow the Registry Integration Gate (`.claude/rules/continuous-improvement.md`) — verify against the live npm and PyPI endpoints before filing the implementation PR

### Ask First
- Any change to `PypiVersion` / `NpmVersion` public struct shape
- Introducing a new dependency for filename parsing (wheel/sdist filename conventions) if hand-rolled parsing proves insufficient
- Any change to `PypiRegistry::get_package_metadata` or `NpmRegistry::search`

### Never
- Change `get_package_metadata`'s endpoint away from the full JSON API
- Touch registry clients for cargo, go, bundler, dart, maven, composer, gradle, swift, or nuget — already confirmed lean by this finding's survey
- Add configurable/self-hosted registry base URLs as part of this change

## 9. Open Questions

- [NEEDS CLARIFICATION: PEP 691's `files` array has no explicit per-file `version` field, so deriving per-version `yanked` status requires parsing sdist/wheel filenames to extract the version segment and match it against the `versions` list. Should this be a minimal hand-rolled parser scoped only to extracting the version segment (default assumption — a full wheel-filename-parsing crate would be over-engineering for one field), or is there an existing workspace dependency that already does this?]
- [NEEDS CLARIFICATION: PyPI's Simple JSON API response was observed live to return only an `ETag` header, no `Last-Modified` header (unlike the full JSON API). `HttpCache`'s conditional-request logic already treats `last_modified` as `Option<String>`, so this should work unchanged — confirm via live 304 test (SC-005) rather than assuming.]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- [[007-lightweight-registry-metadata/plan|plan]] — technical plan
- `crates/deps-npm/src/registry.rs` — `NpmRegistry::get_versions`, `parse_package_metadata`
- `crates/deps-pypi/src/registry.rs` — `PypiRegistry::get_versions`, `get_package_metadata`, `parse_package_metadata`, `parse_package_info`
- `crates/deps-core/src/cache.rs` — `HttpCache::get_cached_with_headers`
- [npm registry package metadata responses](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [PEP 691 – JSON-based Simple API for Python Package Indexes](https://peps.python.org/pep-0691/)
- Issue #142 — `HttpCache` retained memory bounded by entry count, not bytes

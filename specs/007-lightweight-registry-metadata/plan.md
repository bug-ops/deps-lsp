---
aliases:
  - Lightweight Registry Metadata plan
tags:
  - sdd
  - plan
  - enhancement
  - performance
  - npm
  - pypi
created: 2026-08-20
status: draft
related:
  - "[[spec]]"
  - "[[constitution]]"
---

# Technical Plan: Adopt Lightweight Registry Metadata Formats for npm and PyPI Version Lookups

> [!info] References
> **Spec**: [[spec]]
> **Priority**: P2 — plan produced per this project's SDD-integration threshold
> (P2–P3 enhancement = specify + plan; `/sdd tasks`/implementation deferred to
> a dedicated `/rust-team` session, not this research cycle)

> [!warning] Planning under open clarifications
> The spec carries two `[NEEDS CLARIFICATION]` markers (filename-based version
> derivation for PyPI, ETag-only caching on the Simple API). Neither blocks
> planning — both are given a concrete working design below — but both must
> be verified live (per the Testing Strategy) before this plan is considered
> ready for `/sdd tasks`.

## 1. Architecture

### Approach

This is a narrow, surgical change confined to two functions:
`NpmRegistry::get_versions` (`crates/deps-npm/src/registry.rs`) and
`PypiRegistry::get_versions` (`crates/deps-pypi/src/registry.rs`). No new
crate, module, or `deps-core` abstraction is introduced — both changes reuse
the existing `HttpCache::get_cached_with_headers` method
(`crates/deps-core/src/cache.rs:204`), which already supports injecting
arbitrary request headers (originally added for Authorization use cases) and
already keys its cache purely by URL, so switching to a header-negotiated
lighter response for the *same* npm URL does not collide with any other
cached entry.

**npm**: the request changes (add `Accept:
application/vnd.npm.install-v1+json`); the response *parsing* does not. The
abbreviated packument is a strict field-subset of the full packument for
every field the existing `PackageMetadata`/`VersionMetadata` structs already
deserialize (`version` key implicit in the map, `deprecated` per entry) —
`serde`'s default "ignore unknown fields" behavior means the existing structs
work unchanged against the new response shape. This was confirmed live (see
[[spec#Overview|spec Overview]]).

**PyPI**: both the request *and* the response shape change, because the
Simple JSON API's top-level structure (`versions: [String]`, `files:
[{filename, yanked, ...}]`) is fundamentally different from the full JSON
API's `releases: {version: [files]}` grouping. A new set of internal
deserialization types replaces `PypiResponse`/`PypiRelease` *only* inside
`get_versions`'s call path; `get_package_metadata` keeps using the old
`PypiResponse`/`PypiInfo` types against the unchanged full-JSON-API endpoint.

The one genuine technical gap: PEP 691's `files` array carries no explicit
per-file `version` field (the full JSON API's `releases` map, by contrast,
groups files by version key already). `get_versions`'s current semantics —
"a version is yanked if any of its release files is yanked" — require
mapping each file back to a version. This plan resolves it with a
filename-based matching pass against the already-known `versions` list (see
[[#3. Data Model]]), not a new dependency.

### Component Diagram

```mermaid
graph TD
    subgraph deps-npm
        A[NpmRegistry::get_versions] --> B[HttpCache::get_cached_with_headers<br/>Accept: vnd.npm.install-v1+json]
        B --> C[registry.npmjs.org/{package}<br/>SAME URL as before]
        C --> D[parse_package_metadata<br/>UNCHANGED structs]
    end
    subgraph deps-pypi
        E[PypiRegistry::get_versions] --> F[HttpCache::get_cached_with_headers<br/>Accept: vnd.pypi.simple.v1+json]
        F --> G[pypi.org/simple/{name}/<br/>NEW URL]
        G --> H[NEW: parse_simple_api_response<br/>SimpleApiResponse / SimpleApiFile]
        H --> I[NEW: match_files_to_versions<br/>filename -&gt; version derivation]
        J[PypiRegistry::get_package_metadata] --> K[HttpCache::get_cached_with_headers<br/>unchanged, no Accept override]
        K --> L[pypi.org/pypi/{name}/json<br/>UNCHANGED URL]
        L --> M[parse_package_info<br/>UNCHANGED, uses existing PypiResponse/PypiInfo]
    end
```

### Key Design Decisions

| Decision | Choice | Rationale | Alternatives Considered |
|----------|--------|-----------|--------------------------|
| HTTP mechanism for content negotiation | Reuse `HttpCache::get_cached_with_headers` with an `Accept` header | Already exists, already supports arbitrary headers, no new HTTP client code | Add a new `HttpCache` method dedicated to Accept headers — rejected, `get_cached_with_headers` is already generic enough |
| npm response parsing | No change to `PackageMetadata`/`VersionMetadata` structs | Abbreviated packument is a superset of the fields already deserialized; serde ignores unknown fields by default | Define new `AbbreviatedPackageMetadata` structs mirroring the new schema exactly — rejected, unnecessary duplication for identical field names |
| PyPI cache key / URL | Switch `get_versions` to `https://pypi.org/simple/{name}/`, distinct from `get_package_metadata`'s `https://pypi.org/pypi/{name}/json` | `HttpCache` keys strictly by URL (`crates/deps-core/src/cache.rs:133`), so the two functions naturally get independent cache entries with no collision risk | Reuse the same URL for both with different Accept headers — rejected, `HttpCache`'s cache key is URL-only, so two different Accept-negotiated bodies for one URL would collide and one would silently serve stale/wrong-shaped data to the other caller |
| PyPI per-version yanked derivation | Match each Simple API file to a version by filename, using the already-known `versions` list as the candidate set (longest-match-first prefix matching after underscore/hyphen normalization) | No per-file `version` field exists in PEP 691; the `versions` list gives a small, authoritative candidate set to match against, avoiding a full wheel/sdist filename-parsing library | Add a wheel-filename-parsing crate (e.g. a PEP 427/625 parser) — rejected as over-engineering for extracting one field; hand-rolled matching against a known-versions set is simpler and sufficient |
| Yanked field decoding on Simple API | Custom deserializer accepting both `false`/`true` (bool) and a string (yank reason) — PEP 691 allows either | The full JSON API uses a plain `bool`, but PEP 691's `yanked` field is `false \| string`; a plain `bool` deserializer would fail to parse a yank-reason string | Deserialize as `serde_json::Value` inline without a helper — rejected, less testable and repeats logic if reused |
| `get_package_metadata` endpoint | Left unchanged, still full JSON API | It needs `summary`/`project_urls`, which the Simple API does not provide (FR-005, NFR-004) | Migrate everything to Simple API and drop hover summary — rejected, explicitly out of scope and would degrade an existing feature |

## 2. Project Structure

```
crates/deps-npm/src/
└── registry.rs        (modified: get_versions adds Accept header via
                         get_cached_with_headers; no struct changes)

crates/deps-pypi/src/
└── registry.rs         (modified:
                          - get_versions: new URL (pypi.org/simple/{name}/),
                            new Accept header, new response types
                            (SimpleApiResponse, SimpleApiFile), new
                            filename-to-version matching helper
                          - get_package_metadata: UNCHANGED
                          - parse_package_info: UNCHANGED, still parses
                            PypiResponse from the full JSON API
                          - NEW private fn: parse_simple_api_response
                          - NEW private fn: match_files_to_versions
                            (or equivalent filename-matching helper)
```

No changes anywhere in `deps-core`, `deps-lsp`, or any other ecosystem crate.

## 3. Data Model

```rust
// crates/deps-npm/src/registry.rs — NO CHANGES to existing types.
// Only the request changes:
pub async fn get_versions(&self, name: &str) -> Result<Vec<NpmVersion>> {
    let url = format!("{REGISTRY_BASE}/{name}");
    let data = self
        .cache
        .get_cached_with_headers(
            &url,
            &[(header::ACCEPT, "application/vnd.npm.install-v1+json")],
        )
        .await?;
    parse_package_metadata(&data) // unchanged function, unchanged structs
}
```

```rust
// crates/deps-pypi/src/registry.rs — NEW types, scoped to get_versions only.

/// PEP 691 Simple JSON API response for a single project.
#[derive(Debug, Deserialize)]
struct SimpleApiResponse {
    versions: Vec<String>,
    files: Vec<SimpleApiFile>,
}

#[derive(Debug, Deserialize)]
struct SimpleApiFile {
    filename: String,
    #[serde(default, deserialize_with = "deserialize_yanked")]
    yanked: bool,
}

/// PEP 691 allows `yanked` to be `false` or a string (the yank reason).
/// Any string value means "yanked"; `false`/absent means "not yanked".
fn deserialize_yanked<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Bool(b) => b,
        serde_json::Value::String(_) => true,
        _ => false,
    })
}

pub async fn get_versions(&self, name: &str) -> Result<Vec<PypiVersion>> {
    let normalized = normalize_package_name(name);
    let url = format!("https://pypi.org/simple/{normalized}/");
    let data = self
        .cache
        .get_cached_with_headers(
            &url,
            &[(header::ACCEPT, "application/vnd.pypi.simple.v1+json")],
        )
        .await
        .map_err(/* unchanged 404 -> PackageNotFound mapping */)?;

    parse_simple_api_response(name, &normalized, &data)
}

/// Derives per-version yanked status from the flat `files` list by matching
/// each filename against the known `versions` set (longest-match-first,
/// underscore/hyphen normalized), since PEP 691 files carry no explicit
/// `version` field.
fn parse_simple_api_response(
    package_name: &str,
    normalized_name: &str,
    data: &[u8],
) -> Result<Vec<PypiVersion>> {
    let response: SimpleApiResponse = serde_json::from_slice(data)
        .map_err(|e| PypiError::api_response_error(package_name, e))?;

    // Longest version strings first, so "1.0.10" is preferred over a
    // false-positive prefix match against "1.0.1".
    let mut candidates: Vec<&str> = response.versions.iter().map(String::as_str).collect();
    candidates.sort_unstable_by_key(|v| std::cmp::Reverse(v.len()));

    let mut yanked_by_version: std::collections::HashMap<&str, bool> =
        response.versions.iter().map(|v| (v.as_str(), false)).collect();

    for file in &response.files {
        if let Some(version) = match_filename_to_version(&file.filename, normalized_name, &candidates) {
            let entry = yanked_by_version.entry(version).or_insert(false);
            *entry = *entry || file.yanked;
        }
    }

    // Parse + sort exactly as before, now sourced from `versions` + the map above.
    let mut versions_with_parsed: Vec<(PypiVersion, Version)> = response
        .versions
        .into_iter()
        .filter_map(|version_str| {
            let yanked = yanked_by_version.get(version_str.as_str()).copied().unwrap_or(false);
            Version::from_str(&version_str).ok().map(|parsed| {
                (PypiVersion { version: version_str, yanked }, parsed)
            })
        })
        .collect();

    versions_with_parsed.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}
```

### Migrations

Not applicable — no persisted storage; all data lives in `HttpCache`'s
in-memory, process-lifetime entries, unchanged in structure (`CachedResponse
{ body, etag, last_modified, fetched_at }`).

## 4. API Design

### Outbound (deps-npm/deps-pypi → registries)

| Method | Path | Description | Request Headers | Response (relevant fields) |
|--------|------|-------------|------------------|------------------------------|
| GET | `https://registry.npmjs.org/{package}` | npm version lookup (changed: header only, URL unchanged) | `Accept: application/vnd.npm.install-v1+json` (new) | `{ versions: { [v]: { version, dist, engines, deprecated } }, dist-tags, modified }` |
| GET | `https://pypi.org/simple/{name}/` | PyPI version lookup (changed: new URL + header) | `Accept: application/vnd.pypi.simple.v1+json` (new) | `{ name, versions: [String], files: [{ filename, yanked, hashes, ... }], meta }` |
| GET | `https://pypi.org/pypi/{name}/json` | PyPI hover metadata (`get_package_metadata`) — **unchanged** | none (unchanged) | `{ info: { summary, project_urls, version }, releases }` |

No inbound (LSP-facing) API changes — `Hover`, `CompletionItem`, and
`Diagnostic` payloads produced downstream are unaffected; this feature only
changes what each registry client fetches internally.

## 5. Integration Points

| System | Direction | Protocol | Notes |
|--------|-----------|----------|-------|
| `registry.npmjs.org` | outbound | HTTPS | Same host/path as today, different `Accept` header |
| `pypi.org/simple/{name}/` | outbound, NEW endpoint for this crate | HTTPS | Public, keyless, PEP 691 |
| `pypi.org/pypi/{name}/json` | outbound, unchanged | HTTPS | Still used by `get_package_metadata` |
| `HttpCache` (`deps-core`) | internal, reused unchanged | in-process | `get_cached_with_headers` already supports the header-injection this feature needs; cache keying by URL already isolates the two PyPI endpoints from each other |

## 6. Security

- Authentication: none — both endpoints are public and keyless, same as
  today.
- Authorization: not applicable.
- Input validation: `name`/`normalized_name` are already validated/normalized
  by existing `normalize_package_name` (PEP 503) before being interpolated
  into the URL; no new untrusted-input surface.
- Response handling: both new response shapes are deserialized via `serde`
  into strongly typed structs; a malformed or oversized response is treated
  as a fetch/parse failure (FR-006), not a panic. `HttpCache`'s existing
  `MAX_RESPONSE_BYTES` cap (`crates/deps-core/src/cache.rs`) applies
  unchanged to both new endpoints.
- Sensitive data: none — no change to what's transmitted (package name only).

## 7. Testing Strategy

| Level | Framework | What to Test | Coverage Target |
|-------|-----------|-------------|-----------------|
| Unit | `cargo nextest` | npm: existing `test_parse_package_metadata` continues to pass unchanged (structs unchanged); add a fixture using the *actual* abbreviated-packument shape (captured live) to prove forward-compatibility | Existing + 1 new fixture-based test |
| Unit | `cargo nextest` | PyPI: `parse_simple_api_response` against a fixture matching the real PEP 691 shape — cases: version with all files yanked, version with no files yanked, version with a `yanked` string reason (not just bool), version absent from `files` entirely, malformed/unmatchable filename | 5+ new test cases replacing/extending `test_parse_package_metadata` |
| Unit | `cargo nextest` | `match_filename_to_version` (or equivalent helper) — sdist filenames (`.tar.gz`, `.zip`), wheel filenames (with/without build tag), a version that is a strict prefix of another version's filename (e.g. `1.0.1` inside `1.0.10`) to prove longest-match-first correctness | Dedicated unit tests for the matching algorithm |
| Unit | `mockito` (already in workspace) | `HttpCache::get_cached_with_headers` is called with the correct `Accept` header for both `NpmRegistry::get_versions` and `PypiRegistry::get_versions`; `get_package_metadata` is verified to NOT send the new Accept header / NOT hit the Simple API URL | Regression guard for NFR-004/FR-005 |
| Live/manual | per `.claude/rules/continuous-improvement.md` Registry Integration Gate | Real requests to `registry.npmjs.org` (e.g. `express`) and `pypi.org/simple/` (e.g. `django`) — confirm payload size reduction (SC-001/SC-002), identical version-list output vs. current production code (SC-004), and that a second call returns `304 Not Modified` (SC-005, resolves the ETag-only ` [NEEDS CLARIFICATION]`) | Required before merge, not before spec/plan |
| Regression | existing suite | `get_latest_matching` tests for both crates continue passing unchanged (FR-007) | 100% pass |

## 8. Performance Considerations

- Expected load: identical request *count* — one request per `get_versions`
  call, unchanged from today; only the response *size* decreases.
- Bottleneck risk: none introduced — no new round trips, no new
  serialization complexity beyond the filename-matching pass, which is O(number
  of files) per package (bounded, typically well under a few hundred for
  even large PyPI/npm packages) and runs once per fetch (not per hover
  keystroke), same as today's existing parse step.
- Benefit: smaller payloads reduce both network transfer time (directly
  improving hover/completion latency for large-history packages, per
  `.claude/rules/rust-code.md`'s "must return quickly" requirement) and
  `HttpCache`'s per-entry memory footprint, which increases effective cache
  capacity for the same byte budget — relevant to the still-open issue #142
  (`HttpCache` retained memory bounded by entry count, not bytes), though this
  feature does not implement byte-based eviction itself.

## 9. Rollout Plan

Given P2 priority and this project's SDD-integration threshold rule (P2–P3 =
specify + plan; implementation deferred to a dedicated `/rust-team` session):

1. This plan is reviewed and the two open `[NEEDS CLARIFICATION]` items are
   confirmed via the Live/manual testing row above before `/sdd tasks` is run.
2. `/sdd tasks` breaks this plan into discrete tasks in a dedicated
   implementation session (not this research cycle).
3. No feature flag needed — this is an internal fetch-format change with no
   externally observable behavior change beyond payload size and latency, so
   there is no user-facing toggle to gate. If a regression is discovered
   post-merge, revert is a single-commit rollback per crate (npm change and
   PyPI change are independent and can be reverted separately).
4. No phased/canary rollout infrastructure exists in this project — ship
   directly once live verification (Testing Strategy) passes.

## 10. Constitution Compliance

`[NEEDS CLARIFICATION: .local/specs/constitution.md does not exist yet for
this project (confirmed via file check) — this plan cross-checks against the
project's existing enforced rules under .claude/rules/, which function as the
project's de facto constitution today.]`

| Principle (from `.claude/rules/`) | Status | Notes |
|---|---|---|
| Registry Integration Gate (`continuous-improvement.md`) | Addressed in [[#7. Testing Strategy]] | Live verification against real npm/PyPI required before merge |
| Hover/completion must return quickly (`rust-code.md`) | Directly served by this feature | Smaller payloads reduce the dominant latency cost (network transfer) on the hot path |
| Registry crates use ecosystem-specific version-parsing crates, not hand-rolled | Compliant | No change — `node_semver`/`pep440_rs` usage is untouched, this feature only changes the JSON source, not version comparison logic |
| `thiserror` typed errors (`rust-code.md`) | Compliant | No new error variants — FR-006 keeps existing `DepsError`/`PypiError` types |
| Testing conventions (`testing.md`) — `nextest`, `mockito` | Planned | See [[#7. Testing Strategy]] |
| Dependencies rule — check current versions via context7 mcp before adding | Not applicable | No new dependency — `reqwest`, `serde`, `serde_json` already in workspace; filename matching is hand-rolled, no crate added |

## 11. Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Filename-to-version matching produces a false match or misses a match for an unusual sdist/wheel naming pattern (e.g. legacy pre-PEP 625 sdist, `.egg`, `.tar.bz2`) | Medium (a yanked version could be reported as not-yanked, or vice versa) | Low–Medium | Longest-match-first against the known `versions` set (not free-form parsing) minimizes false positives; unmatched files simply don't contribute a yanked signal (fail-safe toward "not yanked", same as today's behavior for a release with zero files) — covered by dedicated unit tests (Testing Strategy) |
| PyPI's Simple JSON API omits `Last-Modified` (confirmed live) — if any part of `HttpCache` implicitly assumed both headers are present together | Low | Low | `HttpCache`'s `last_modified` field is already `Option<String>` and only sent as `If-Modified-Since` when `Some` (`crates/deps-core/src/cache.rs:258-260`) — no code change needed; confirmed via live 304 test (SC-005) |
| npm abbreviated packument silently drops a field the current struct relies on that wasn't caught by this analysis | Low (grep-confirmed only `deprecated` is read; risk is a missed private/internal usage) | Low | Existing unit test suite plus a new live-fixture test (Testing Strategy) catch any parse failure immediately since `serde` would error on a genuinely required-but-missing field |
| PEP 691 `yanked` field's two-shape (`bool \| string`) is mis-decoded if the custom deserializer has a bug | Medium (yanked status silently wrong) | Low | Dedicated unit test cases for both shapes (bool `false`/`true` and string reason) in the Testing Strategy |
| No project constitution exists to check formal compliance against | Low (process risk, not implementation risk) | Certain (confirmed) | Cross-checked against `.claude/rules/*.md` instead (see [[#10. Constitution Compliance]]) |

## See Also

- [[spec]] — feature specification
- [[MOC-specs]] — all specifications
- `crates/deps-npm/src/registry.rs` — `NpmRegistry::get_versions`, `parse_package_metadata`
- `crates/deps-pypi/src/registry.rs` — `PypiRegistry::get_versions`, `get_package_metadata`, `parse_package_metadata`, `parse_package_info`
- `crates/deps-core/src/cache.rs` — `HttpCache::get_cached_with_headers`
- [npm registry package metadata responses](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [PEP 691 – JSON-based Simple API for Python Package Indexes](https://peps.python.org/pep-0691/)
- `.claude/rules/continuous-improvement.md`, `.claude/rules/testing.md`, `.claude/rules/rust-code.md`
- Issue #142 — `HttpCache` retained memory bounded by entry count, not bytes

---
aliases:
  - npm all-deprecated Unknown package
tags:
  - sdd
  - spec
  - bug
  - deps-npm
  - deps-deno
  - npm
created: 2026-08-24
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: npm/JSR packages whose every published version is deprecated must not be reported "Unknown package"

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: (none yet)
> **Priority**: P1
> **Discovered during**: ci-007 live testing of #309/#324 (Deno/JSR ecosystem, npm-registry sharing) via a `deno.json` `npm:left-pad@1.0.0` import

## 1. Overview

### Problem Statement

`left-pad` is a real, installable, currently-published npm package (versions
`0.0.0`..`1.3.0` all present in the registry) whose *every* published version
carries an npm-level `deprecated` message
(`"use String.prototype.padStart()"`). This is a common, legitimate
real-world pattern — many long-lived, still-functional npm packages
(`left-pad`, `request`, `har-validator`, several `node-uuid`-family packages)
carry a package-wide deprecation notice on all their versions while remaining
perfectly installable and widely depended-upon.

Live-tested against real `registry.npmjs.org` data (2026-08-24): opening a
`deno.json` with `"left-pad": "npm:left-pad@1.0.0"` produces:
- `textDocument/publishDiagnostics`: `Unknown package 'npm:left-pad'`
  (severity Warning) — as if the package does not exist.
- Hover: renders "Recent versions" correctly (each entry tagged
  `*(deprecated)*`), but the `**Latest**:` line is missing entirely — normally
  always present for a resolvable package.

Root cause, traced live via `RUST_LOG=debug`:
1. `crates/deps-npm/src/registry.rs`'s `Registry::select_latest_matching`
   (~line 614) and `NpmRegistry::get_latest_matching` (~line 338) both filter
   out any version where `v.is_yanked()` is true — and npm's `deprecated`
   flag is mapped to `is_yanked()` (`crates/deps-npm/src/registry.rs:418`,
   `deprecated: meta.deprecated.is_some()`).
2. `crates/deps-lsp/src/document/lifecycle.rs` (~line 704) resolves each
   dependency's cache entry using a **wildcard** requirement (`"*"`) for the
   "does this package exist / what is its most-recent version" check, calling
   `select_latest_matching(&versions, "*")` and, on `None`, falling back to
   `get_latest_matching(name, "*")`.
3. When every returned version is deprecated, both the wildcard
   `select_latest_matching` and the `get_latest_matching` fallback return
   `None` — even under a wildcard requirement that should match anything —
   because both apply the `!v.is_yanked()` filter unconditionally, with no
   "wildcard bypasses the yanked filter" exception.
4. `None` here is logged as `"no version found"`
   (`crates/deps-lsp/src/document/lifecycle.rs:783`) and no cache entry is
   ever inserted for the package.
5. `crates/deps-core/src/lsp_helpers/diagnostics.rs` (~line 449) then finds no
   `package_versions` entry in cache and — since the name-syntax is valid and
   the source is version-resolvable and no lockfile entry masks it — emits
   `Unknown package '<name>'` (line 476). This is indistinguishable from a
   genuinely nonexistent package.

This conflates two different questions that the wildcard fast-path was meant
to answer for two different purposes:
- "What's the newest version I should offer to install/recommend?" — legitimately excludes deprecated versions.
- "Does this package exist at all?" — must NOT exclude deprecated versions; a deprecated package still exists.

Both currently share the same `!v.is_yanked()`-filtered wildcard call, so the
existence check inherits the recommendation-only filter.

Same root cause path applies through `deps-deno`'s shared `NpmRegistry`
instance (#324), so this affects both `package.json` (deps-npm) and
`deno.json` `npm:` specifiers (deps-deno) identically.

### Goal

A dependency on a real, currently-published npm package must never be
reported as `Unknown package`, and its hover `**Latest**:` line must always
be populated, regardless of whether every published version happens to carry
a package-wide deprecation notice. Deprecated-version filtering must remain
in effect for actual "recommend an upgrade target" decisions (diagnostics'
"Newer version available", quick-fix code actions, completion) — this spec
narrows the fix to the existence/latest-for-display resolution only.

### Out of Scope

- Changing whether `deprecated` versions are offered as upgrade targets in
  "Newer version available" diagnostics, completion, or quick-fix code
  actions — deprecated versions should continue to be excluded there.
- Adding a distinct "this package is deprecated" diagnostic/hover callout —
  a possible follow-on enhancement, not required to fix the false "Unknown
  package" report. See Open Questions.
- Ecosystems other than npm/Deno's `npm:` routing — no other supported
  registry's `select_latest_matching`/`get_latest_matching` wildcard path was
  found to have this specific gap during this cycle's spot checks (see
  sibling findings for Maven's *different* wildcard gap, spec 021).

## 2. User Stories

### US-001: All-deprecated package resolves as a known, existing package

AS A developer with `left-pad` (or any all-deprecated-but-published package)
in `package.json` or `deno.json`
I WANT hover and diagnostics to recognize the package exists
SO THAT I am not misled into thinking I have a typo'd/nonexistent dependency
when the package is actually installed and working fine.

**Acceptance criteria:**
```
GIVEN a package.json/deno.json dependency on a real npm package where every
      published version has a `deprecated` field set
WHEN textDocument/publishDiagnostics is computed
THEN no "Unknown package" diagnostic is emitted for that dependency
AND hover's "**Latest**:" line is populated with the actual newest published
    version (deprecated or not)
```

### US-002: Deprecated versions still excluded from upgrade recommendations

AS A developer relying on "Newer version available" / quick-fix suggestions
I WANT the LSP to still avoid steering me toward installing extra deprecated
versions where a non-deprecated alternative exists
SO THAT the fix for US-001 does not regress existing deprecated-version
avoidance behavior for packages that DO have non-deprecated versions.

**Acceptance criteria:**
```
GIVEN a package with a mix of deprecated and non-deprecated versions
WHEN "Newer version available" / quick-fix candidates are computed
THEN only non-deprecated versions are offered, unchanged from current
     behavior (regression-checked)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN resolving whether a package exists / its most-recent version for cache-population purposes under a wildcard (`"*"`) requirement, THE SYSTEM SHALL NOT exclude deprecated/yanked versions from that resolution | must |
| FR-002 | WHEN resolving the recommended upgrade target for diagnostics ("Newer version available"), completion, or quick-fix code actions, THE SYSTEM SHALL continue to exclude deprecated/yanked versions when at least one non-deprecated version exists | must |
| FR-003 | WHEN every published version of a package is deprecated/yanked, THE SYSTEM SHALL still surface the newest deprecated version as `PackageVersions.latest` / hover `**Latest**` rather than reporting no version at all | must |
| FR-004 | THE SYSTEM SHALL apply the fix uniformly to both `deps-npm`'s direct `Registry` implementation and `deps-deno`'s shared `NpmRegistry` usage (no separate deno-specific patch) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | New unit test(s) in `deps-npm` covering `select_latest_matching`/`get_latest_matching` under `"*"` against an all-deprecated abbreviated-packument fixture, asserting a `Some`/non-`None` result |
| NFR-002 | Backward compatibility | Existing tests asserting deprecated versions are excluded from *matched* (non-wildcard) requirement resolution must continue to pass unchanged |
| NFR-003 | Consistency | Fix SHALL NOT introduce a divergence between hover's `**Latest**` and diagnostics' "Unknown package"/"Newer version available" logic — both read from the same corrected cache entry |

## 5. Data Model

No new types. Affects `crates/deps-npm/src/registry.rs`: `Registry::select_latest_matching`
(~line 614-623) and `NpmRegistry::get_latest_matching` (~line 338-350), and
their interaction with `crates/deps-lsp/src/document/lifecycle.rs`'s
wildcard-based cache-population loop (~line 704-800) and
`crates/deps-core/src/lsp_helpers/diagnostics.rs`'s `Unknown package` branch
(~line 449-490).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Package has a mix of deprecated and non-deprecated versions | Existing/unchanged: `**Latest**` and upgrade recommendations pick the newest non-deprecated version |
| Package has zero published versions at all (genuinely nonexistent) | Unchanged: `Unknown package` still correctly emitted — this fix must not weaken genuine not-found detection |
| Package's requirement is an exact pin matching a specific deprecated version | Unchanged: exact-pin matching already works today (confirmed live — `left-pad@1.0.0` hover lists it), only the wildcard existence/latest-for-display path is affected |
| `deps-deno`'s shared `NpmRegistry` for an `npm:` specifier in `deno.json` | Same fix applies automatically since deno.json shares the `NpmRegistry` instance (#324) — no deno-specific code path to patch separately |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live hover for `npm:left-pad@1.0.0` (deno.json) against real `registry.npmjs.org` | `**Latest**: `1.3.0`` line present |
| SC-002 | Live diagnostics for the same manifest | No `Unknown package 'npm:left-pad'` diagnostic |
| SC-003 | Live diagnostics for `react@^18.2.0` (non-deprecated, real data) unchanged | Still reports `Newer version available: <stable latest>`, no deprecated version offered |
| SC-004 | `cargo nextest run -p deps-npm -p deps-deno` | All pass, including new fixture-based test(s) |

## 8. Agent Boundaries

### Always (without asking)
- Add unit test(s) in `crates/deps-npm/src/registry.rs` with an
  all-deprecated abbreviated-packument fixture (see existing
  `test_parse_abbreviated_packument_all_deprecated` for the fixture shape —
  that test only covers parsing, not `select_latest_matching`/
  `get_latest_matching` resolution, which is the actual gap)
- Run `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run -p deps-npm -p deps-deno --all-features`
- Live-verify against real `registry.npmjs.org` (`left-pad`) per the Registry Integration Gate

### Ask First
- Whether to add a distinct "package is fully deprecated" hover/diagnostic callout (Open Questions) — separate enhancement, confirm scope before implementing

### Never
- Remove deprecated-version filtering from the upgrade-recommendation paths (FR-002) — only the existence/latest-for-display wildcard path changes
- Weaken genuine not-found detection for packages with zero versions

## 9. Open Questions

> [!question] Fix shape
> [NEEDS CLARIFICATION: Should the wildcard fast-path (`select_latest_matching`/`get_latest_matching` under `"*"`) simply drop the `!v.is_yanked()` filter entirely (since `versions` is already newest-first, index 0 under `"*"` is trivially correct without any filter), or should it fall back to "newest deprecated version" only when no non-deprecated version exists (two-tier: prefer non-deprecated, else take newest regardless)? The two-tier approach is closer to current behavior for the mixed case and safer against silently changing which version diagnostics recommends; recommend two-tier.]

> [!question] Deprecation-aware UX
> [NEEDS CLARIFICATION: Once existence is fixed, should hover/diagnostics add an explicit "this package is deprecated" note distinct from "Unknown package"? Deferred — not required to close this bug, but likely valuable follow-on given how common package-wide deprecation is in the npm ecosystem.]

## 10. See Also

- [[MOC-specs]] — all specifications
- [[021-maven-wildcard-latest-ignores-prerelease/spec|Maven wildcard "latest" ignores prerelease qualifier]] — same class of bug (wildcard fast-path disagreeing with the real recommendation-path filter), different ecosystem and different filter (prerelease vs deprecated)
- `crates/deps-npm/src/registry.rs` — `select_latest_matching` (~line 614), `get_latest_matching` (~line 338)
- `crates/deps-lsp/src/document/lifecycle.rs` — wildcard cache-population loop (~line 704)
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` — `Unknown package` branch (~line 449)
- `.local/testing/journal/ci-007.md` — live-testing cycle that discovered this finding (2026-08-24)

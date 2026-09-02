---
aliases:
  - Maven wildcard latest ignores prerelease
tags:
  - sdd
  - spec
  - bug
  - deps-maven
  - deps-gradle
  - prerelease
created: 2026-08-24
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Maven/Gradle "Newer version available" diagnostic and quick-fix must not recommend a prerelease when a stable release is newer

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: (none yet)
> **Priority**: P1
> **Discovered during**: ci-007 live spot-check of #326/#330 (prerelease detection and version-comparison correctness) — Maven was not in scope of those two PRs, but this cycle's cross-ecosystem consistency check surfaced a live, independent prerelease-handling gap in the same problem space

## 1. Overview

### Problem Statement

Live-tested against real Maven Central data (2026-08-24): `org.hibernate:hibernate-core`
pinned to `6.0.0.Final`, where Maven Central's `maven-metadata.xml`
currently has `<latest>8.0.0.Beta1</latest>` / `<release>8.0.0.Beta1</release>`
(the most recently *deployed* artifact is a Beta), while the newest *stable*
release is `7.4.6.Final`.

- Hover correctly shows `**Latest**: 7.4.6.Final` — `NpmRegistry`... (n/a,
  Maven) `get_latest_matching_typed`'s prerelease-skipping scan
  (`crates/deps-maven/src/registry.rs` ~line 174, `.position(|v|
  !crate::version::is_prerelease(&v.version))`) is used here and works
  correctly.
- `textDocument/publishDiagnostics` for the same dependency, same instant,
  reports `"Newer version available: 8.0.0.Beta1"` — a **prerelease**, and
  the driving diagnostic for the quick-fix code action.
- The quick-fix code action's top suggestion is `8.0.0.Beta1 (latest)`, with
  `8.0.0.Alpha1` as the *second* alternative — i.e. the two prerelease
  qualifiers are offered ahead of the actual newest stable release
  (`7.4.6.Final`, offered third).

Root cause: `crates/deps-maven/src/registry.rs`'s
`Registry::select_latest_matching` (~line 828-844), used by
`crates/deps-lsp/src/document/lifecycle.rs`'s wildcard (`"*"`) bulk
cache-population pass (the same code path diagnostics reads from), has a
fast path for the wildcard case:

```rust
if req_str.is_empty() || req_str == "*" {
    return if versions.is_empty() { None } else { Some(0) };
}
```

This trusts that index 0 — which `get_versions`'s
`move_release_to_front` placed there from `maven-metadata.xml`'s `<release>`
tag — is "the" authoritative latest, with a code comment asserting this
keeps it "in agreement with `get_latest_matching_typed`'s `<release>`-preferring
pick". That assertion is **false** whenever the most recently deployed
artifact happens to be a prerelease: Maven Central's `<release>`/`<latest>`
tags carry no prerelease semantics at all (unlike npm's maintainer-curated
`dist-tags.latest`) — they simply track the most recently *deployed*
version, prerelease or not. `get_latest_matching_typed` (hover's path)
explicitly re-scans past prereleases with `is_prerelease`; the wildcard fast
path does not, and disagrees with it whenever the front-of-list entry is a
prerelease.

`is_prerelease` itself (`crates/deps-maven/src/version.rs`) correctly
classifies both `8.0.0.Beta1` and `8.0.0.Alpha1` as prereleases (dot- and
dash-separated qualifiers both handled per its `split_version` docs) — the
gap is entirely in `select_latest_matching`'s wildcard shortcut skipping that
classification.

Per the code's own comment, `crates/deps-gradle`'s registry is the same
`MavenCentralRegistry` type (#233), so Gradle inherits this bug identically
— not independently re-verified live this cycle due to budget, flagged for
next cycle.

### Goal

Maven/Gradle's "Newer version available" diagnostic and its quick-fix code
action must agree with hover: never recommend a prerelease version as "the"
latest when a newer-or-equal stable release exists, using the same
`is_prerelease`-aware selection hover already uses correctly.

### Out of Scope

- Changing `is_prerelease`'s classification rules themselves — verified
  correct for the qualifiers exercised this cycle (`Beta1`, `Alpha1`).
- The `#326`/`#330` prerelease-detection fixes' actual ecosystems (pypi,
  cargo, dart, swift, npm, deno, bundler, composer) — Maven/Gradle were never
  in scope of those PRs; this is a pre-existing, independently-discovered gap
  in a neighboring code path.
- Non-wildcard (exact requirement / range) matching — unaffected; only the
  `"*"` fast path skips the prerelease filter.
- Offering prereleases as an *explicit, opt-in* alternative in the quick-fix
  list — reasonable UX, but the *default*/top-ranked suggestion and the
  diagnostic's headline version must be the stable pick per FR-002; ordering
  of prerelease alternatives further down the list is a secondary concern
  (see Open Questions).

## 2. User Stories

### US-001: Diagnostic recommends the stable latest, not a prerelease

AS A Java/Kotlin developer with an outdated Maven/Gradle dependency
I WANT the "Newer version available" diagnostic to name the newest *stable*
release
SO THAT I'm not nudged toward installing an Alpha/Beta/RC/Milestone/SNAPSHOT
build I never asked for, inconsistent with what hover already tells me.

**Acceptance criteria:**
```
GIVEN a Maven/Gradle dependency where the registry's most recently deployed
      artifact is a prerelease (Alpha/Beta/RC/M/SNAPSHOT) but a newer-than-
      the-pinned-version stable release also exists
WHEN textDocument/publishDiagnostics computes "Newer version available"
THEN the named version is the newest STABLE release, matching hover's
     **Latest** field for the same dependency
```

### US-002: Quick-fix default suggestion is the stable latest

AS A developer invoking the quick-fix code action on an outdated Maven/Gradle dependency
I WANT the top/"(latest)"-labeled suggestion to be the stable release
SO THAT accepting the default quick-fix never silently pins me to a prerelease.

**Acceptance criteria:**
```
GIVEN the same scenario as US-001
WHEN the quick-fix code action is requested
THEN the entry labeled "(latest)" is the newest stable release
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `Registry::select_latest_matching` is called with a wildcard (`"*"`) requirement, THE SYSTEM SHALL return the newest version for which `is_prerelease` is false, if one exists in the list | must |
| FR-002 | WHEN every version in the list is a prerelease (no stable release exists at all), THE SYSTEM SHALL fall back to the newest version regardless of prerelease status, matching `get_latest_matching_typed`'s existing fallback behavior | must |
| FR-003 | THE SYSTEM SHALL keep this resolution free of extra I/O (no second registry round trip) — the fix operates on the already-fetched, already-front-loaded `versions` slice, same as today | must |
| FR-004 | THE SYSTEM SHALL produce results identical to `get_latest_matching_typed`'s existing prerelease-skipping scan for the same input list, so hover and diagnostics/quick-fix never disagree again | must |
| FR-005 | THE SYSTEM SHALL apply the same fix to Gradle, since `deps-gradle` shares the identical `MavenCentralRegistry` implementation (#233) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | New unit test in `crates/deps-maven/src/registry.rs` for `select_latest_matching` under `"*"` with a fixture where index 0 (front-loaded `<release>`) is a prerelease and a stable release exists later in the list |
| NFR-002 | Consistency | Add a test asserting `select_latest_matching("*")` and `get_latest_matching_typed`'s scan agree on the same fixture |
| NFR-003 | Backward compatibility | Existing behavior (front-of-list stable release picked directly, no scan needed) unchanged when index 0 is already stable — the common case, verified via existing tests |

## 5. Data Model

No new types. Affects `crates/deps-maven/src/registry.rs`'s
`Registry::select_latest_matching` (~line 828-844) only; reuses the existing
`crate::version::is_prerelease` predicate already relied on by
`get_latest_matching_typed` (~line 174, ~line 210).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Front-of-list version is already stable (common case) | Unchanged — `Some(0)` still returned directly, no scan overhead |
| All versions are prereleases (brand-new artifact with no stable release yet) | Falls back to newest prerelease (FR-002), matching current `get_latest_matching_typed` fallback |
| Empty version list | Unchanged: `None` |
| Gradle (`build.gradle`/`build.gradle.kts`, `libs.versions.toml`) dependency on the same artifact | Same fix applies automatically via the shared `MavenCentralRegistry` type — no Gradle-specific code path |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live diagnostics for `org.hibernate:hibernate-core` pinned to `6.0.0.Final` (real Maven Central data) | "Newer version available" names the newest stable release (`7.4.6.Final` at time of writing), not `8.0.0.Beta1` |
| SC-002 | Live quick-fix code action for the same dependency | Entry labeled "(latest)" is the newest stable release |
| SC-003 | Live hover for the same dependency, same instant | Unchanged (already correct) — used as the cross-check oracle |
| SC-004 | `cargo nextest run -p deps-maven -p deps-gradle` | All pass, including new fixture-based tests |

## 8. Agent Boundaries

### Always (without asking)
- Fix `select_latest_matching`'s wildcard branch to scan for the newest non-prerelease entry, falling back to index 0 only if none exists
- Add unit tests per NFR-001/NFR-002
- Run `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run -p deps-maven -p deps-gradle --all-features`
- Live-verify against real Maven Central using a package whose `<release>` currently points at a prerelease (re-check `hibernate-core`'s current metadata, since the concrete versions will have moved on by fix time — pick whatever real artifact currently exhibits the pattern)

### Ask First
- Whether to also reorder the quick-fix alternatives list so prereleases sort after all stable releases (currently `8.0.0.Alpha1` ranks second, ahead of `7.4.6.Final`) — US-002/FR-001 only requires the *default* "(latest)" pick to be stable; full list reordering is a related but separable UX call (see Open Questions)

### Never
- Change `is_prerelease`'s qualifier-classification rules as part of this fix — already correct, out of scope
- Add a second registry round trip to resolve this — must stay a pure in-memory scan (FR-003)

## 9. Open Questions

> [!question] Alternatives list ordering
> [NEEDS CLARIFICATION: Should the quick-fix code action's full alternatives list (beyond the top "(latest)" pick) also demote prereleases below all stable releases, or is raw-version-descending order (current behavior) acceptable for the non-default alternatives? Live-observed order today: `8.0.0.Beta1 (latest)`, `8.0.0.Alpha1`, `7.4.6.Final`, `7.4.5.Final`, `7.4.4.Final`. Recommend demoting for consistency with FR-004's "never disagree with hover" principle, but confirm scope/cost before implementing — this may require the same fix applied to the alternatives-list builder, not just `select_latest_matching`.]

## 10. See Also

- [[MOC-specs]] — all specifications
- [[019-npm-all-deprecated-unknown-package/spec|npm/JSR packages whose every published version is deprecated must not be reported "Unknown package"]] — same class of bug: a wildcard fast-path disagreeing with the real recommendation-path filter, different ecosystem and different filter (deprecated vs prerelease)
- `crates/deps-maven/src/registry.rs` — `select_latest_matching` (~line 828), `get_latest_matching_typed` (~line 174)
- `crates/deps-maven/src/version.rs` — `is_prerelease` (~line 13)
- `crates/deps-gradle` — shares `MavenCentralRegistry` (#233), same fix applies
- `.local/testing/journal/ci-007.md` — live-testing cycle that discovered this finding (2026-08-24)

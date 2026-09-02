---
aliases:
  - Bundler platform duplicate versions
tags:
  - sdd
  - spec
  - bug
  - deps-bundler
  - rubygems
created: 2026-08-24
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Deduplicate RubyGems platform-variant versions in Bundler hover

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: fix/bundler-platform-duplicate-versions (no tracked issue number yet)
> **Priority**: P1
> **Discovered during**: live verification of PR #301 (fix: stop trusting RubyGems' always-empty `yanked` signal, closes #298) — not caused by that PR, pre-existing gap

## 1. Overview

### Problem Statement

RubyGems' `versions.json` API
(`https://rubygems.org/api/v1/versions/<gem>.json`) returns **one entry per
(version, platform) pair**, not one entry per distinct version number. Any
gem that ships platform-specific prebuilt binaries — a very common pattern
for native-extension gems (`nokogiri`, `ffi`, `sassc`, `grpc`,
`google-protobuf`, and others) — has multiple API entries that share the same
`number` field but differ in `platform` (e.g. `ruby`, `x86-mingw32`,
`x64-mingw32`, `x86-mswin32`, `java`, `x86_64-linux`, `arm64-darwin`, ...).

`parse_versions_response` in `crates/deps-bundler/src/registry.rs` (around
line 98) deserializes every raw entry into a `BundlerVersion` with no
deduplication by `number`, then sorts the full list by version descending.
The hover "Recent versions" section
(`crates/deps-core/src/lsp_helpers.rs`, capped by the
`HOVER_RECENT_VERSIONS` constant defined around line 21, rendering logic
further in the file) takes the top N entries from this undeduplicated list.

Because the list is not deduplicated, the top N slots are filled with N
copies of the same version number (one per platform variant) instead of the
N most recent *distinct* versions. This makes the "Recent versions" hover
section provide zero useful information for the most common
native-extension gems in the Ruby ecosystem — a large share of real-world
Gemfiles.

Latest-version selection (`get_latest_matching`) and yanked-status logic are
NOT affected — both already operate correctly (confirmed during #301's live
verification, e.g. pinning to known-yanked `rest-client` 1.6.2 produces the
correct signal). This spec is scoped exclusively to the version *list*
construction feeding the "Recent versions" hover display.

### Goal

The Bundler hover "Recent versions" section shows N distinct version
numbers, deduplicated across platform variants, for every gem — including
native-extension gems that publish multiple platform-specific builds per
release.

### Out of Scope

- Changes to latest-version resolution (`get_latest_matching`) — already
  correct, not affected by this bug.
- Changes to yanked-status detection/display — already correct (see #301),
  out of scope.
- Displaying per-platform availability information anywhere in the hover
  (e.g. "available for: ruby, java, x86-mingw32") — a possible enhancement,
  but not required to fix this bug. See Open Questions.
- Changes to other ecosystems' registry clients — this is a RubyGems/Bundler
  specific data-shape issue; no other supported registry (npm, PyPI, Cargo,
  Go, Maven, etc.) returns one entry per platform for the versions-list
  endpoint used by deps-lsp.
- Changes to completion or diagnostics features — only the hover "Recent
  versions" rendering path is affected by this bug in observable behavior
  (the underlying `BundlerVersion` list is shared internally, but this spec
  targets the fix at the source: list construction).

## 2. User Stories

### US-001: Distinct recent versions in hover for native-extension gems

AS A Ruby developer using a Gemfile with native-extension gems (e.g.
`nokogiri`, `ffi`, `sassc`)
I WANT the hover "Recent versions" section to show distinct, genuinely
different version numbers
SO THAT I can see the real recent release history of the gem and decide
whether to upgrade, instead of seeing the same version number repeated
7-8 times with no useful information.

**Acceptance criteria:**
```
GIVEN a Gemfile with `gem 'nokogiri'` (any version, unpinned)
WHEN the user hovers over the package name
THEN the "Recent versions" section shows up to HOVER_RECENT_VERSIONS (8)
     entries, each with a distinct version `number`
AND no version `number` appears more than once in the list
```

### US-002: Correct age/date shown per distinct version

AS A Ruby developer inspecting a gem's release history via hover
I WANT the displayed "N months/days ago" age for each listed version to
correspond to a real publish event for that version
SO THAT the freshness signal is meaningful (not accidentally picking a
platform-specific `created_at` that happens to differ from the canonical
release date for that version number).

**Acceptance criteria:**
```
GIVEN a version number with multiple platform entries with different
      `created_at` timestamps (they are typically published within
      seconds/minutes of each other, but may differ)
WHEN deduplicating entries that share the same `number`
THEN the retained entry's `published_at` is a deterministic, documented
     choice (e.g. earliest `created_at` among the group, or the entry
     matching the preferred platform — see FR-002)
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `parse_versions_response` builds the `Vec<BundlerVersion>` from the RubyGems `versions.json` payload, THE SYSTEM SHALL deduplicate entries so that each distinct version `number` appears at most once in the returned list | must |
| FR-002 | WHEN multiple raw entries share the same version `number` with different `platform` values, THE SYSTEM SHALL select exactly one entry to represent that version number, using a documented, deterministic preference order (see [NEEDS CLARIFICATION] below) | must |
| FR-003 | WHEN multiple raw entries share the same version `number` and differ in `yanked` status, THE SYSTEM SHALL treat the version as yanked only if the retained (or all, per implementation choice) entries indicate yanked — MUST NOT silently pick a non-yanked platform entry to mask a yanked release, or vice versa | must |
| FR-004 | THE SYSTEM SHALL preserve existing sort order (version descending, via `compare_versions`) after deduplication | must |
| FR-005 | WHEN `get_latest_matching` filters the deduplicated list for the highest version satisfying a requirement, THE SYSTEM SHALL continue to return the correct result — deduplication MUST NOT change which version number is selected as latest-matching, only remove redundant platform copies | must |
| FR-006 | THE SYSTEM SHALL apply deduplication once, in `parse_versions_response` (or equivalent single choke point), so all consumers of `RubyGemsRegistry::get_versions` (hover "Recent versions", latest-matching, any future consumer) receive an already-deduplicated list — no per-call-site deduplication logic | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Deduplication SHALL add no more than O(n log n) overhead to `parse_versions_response` (n = raw entry count, typically well under a few hundred for platform-heavy gems); no additional network round-trip |
| NFR-002 | Correctness | Deduplication logic SHALL be covered by unit tests using a `mockito`-mocked RubyGems response fixture containing multiple platform entries per version number (per `.claude/rules/testing.md` mock conventions) |
| NFR-003 | Backward compatibility | Gems with no platform variants (single entry per version — the common case for pure-Ruby gems) SHALL produce byte-identical hover output before and after the fix |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `VersionEntry` (raw, private to `registry.rs`) | One raw entry from RubyGems' `versions.json`, one per (version, platform) pair | `number`, `prerelease`, `yanked`, `created_at`, `platform` |
| `BundlerVersion` (public, `types.rs`) | Deduplicated, display-ready version record consumed by hover/completion/latest-matching | `number`, `prerelease`, `yanked`, `published_at`, `platform` |

No schema changes required — `BundlerVersion` already carries a `platform`
field; the fix changes *how many* `BundlerVersion` records are produced per
distinct `number`, not the struct shape.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Gem with no platform-specific builds (single entry per version, e.g. most pure-Ruby gems) | No behavior change — list already has one entry per version |
| Gem where the `ruby` (pure-Ruby) platform entry is missing for a given version (rare, but possible if a release is platform-only, e.g. `java`-only build) | Deduplication SHALL still retain exactly one entry for that version number, falling back to any available platform per FR-002's preference order |
| All platform entries for a version share identical `created_at` | Any entry may be retained; resulting `published_at` is unambiguous |
| Platform entries for the same version have differing `created_at` (staggered publish) | Deterministic choice per FR-002 (e.g. earliest, or preferred-platform's timestamp) — documented in code comment so behavior is not accidental |
| Version has zero platform entries after malformed/partial API response | Not applicable — version numbers only exist because at least one entry produced them; no empty-group case |
| Gem with `HOVER_RECENT_VERSIONS` (8) or fewer *distinct* versions but many raw entries (e.g. 3 distinct versions × 6 platforms = 18 raw entries) | Hover shows all 3 distinct versions, not padded/truncated incorrectly |
| Gem with more than `HOVER_RECENT_VERSIONS` distinct versions | Existing truncation-to-N behavior applies to the deduplicated list, unchanged |

## 7. Success Criteria

Measurable metrics that prove the fix works:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover "Recent versions" for `nokogiri` (live rubygems.org data) shows distinct version numbers | 100% of listed entries have unique `number` |
| SC-002 | Hover "Recent versions" for `rest-client` (live rubygems.org data) no longer repeats `2.1.0` / `2.1.0.rc1` per platform | Each version number appears exactly once |
| SC-003 | Existing `deps-bundler` unit tests plus new deduplication test(s) | All pass (`cargo nextest run -p deps-bundler`) |
| SC-004 | `get_latest_matching` result for platform-heavy gems unchanged before/after fix | Same version number selected in a live/regression comparison |

## 8. Agent Boundaries

### Always (without asking)
- Add/extend unit tests in `crates/deps-bundler/src/registry.rs` (or its
  `#[cfg(test)]` module) covering multi-platform dedup, per
  `.claude/rules/testing.md`
- Run `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`, and
  `cargo nextest run -p deps-bundler --all-features` before considering the
  fix complete
- Follow existing code patterns in `registry.rs` (e.g. keep `VersionEntry`
  private, keep dedup logic inside `parse_versions_response` or a small
  private helper in the same module)
- Live-verify against real `rubygems.org` API for at least `nokogiri` and
  `rest-client` per this project's Registry Integration Gate
  (`.claude/rules/continuous-improvement.md`)

### Ask First
- Adding a new dependency (e.g. a crate for grouping/dedup helpers) — should
  not be necessary given `std` `HashMap`/`itertools` (if already a workspace
  dep) suffice
- Changing the public `BundlerVersion` struct shape (adding fields such as
  "available platforms") — out of scope per section 1, ask before expanding

### Never
- Change latest-version selection semantics (FR-005) without an explicit
  regression test proving the selected version is unchanged
- Silently drop yanked-status information during deduplication (FR-003)
- Modify other ecosystem crates (`deps-npm`, `deps-cargo`, etc.) as part of
  this fix — this is RubyGems-specific

## 9. Open Questions

> [!question] Deduplication preference order
> [NEEDS CLARIFICATION: When multiple platform entries share a version
> number, which one should be retained? Candidate orders: (a) prefer
> `platform == "ruby"` if present, else first-seen; (b) prefer the entry
> with the earliest `created_at`; (c) prefer the entry with the latest
> `created_at`; (d) always take the first entry as returned by the API
> (API order is not documented/guaranteed). Left as an implementation
> decision for whoever picks up the fix — recommend (a) with fallback to
> first-seen, since `ruby` is the canonical/source-of-truth platform for
> most gems and matches how `default_platform()` already treats missing
> platform data.]

> [!question] Yanked-status conflict resolution
> [NEEDS CLARIFICATION: Given the `yanked` field is currently always `false`
> in practice (per the code comment on `VersionEntry::yanked`, RubyGems
> omits yanked versions from this endpoint entirely — see #298/#301), is
> FR-003's conflict-handling requirement realistically reachable today, or
> is it purely defensive for a future API change / different registry
> behavior? If unreachable today, implementer may simplify to "pick any
> entry, yanked is defensively OR'd across the group" without extensive
> test coverage for the conflict case.]

> [!question] Surfacing platform availability
> [NEEDS CLARIFICATION: Should the hover eventually indicate that a version
> has multiple platform builds (e.g. a small "(6 platforms)" suffix or
> tooltip), or is silent deduplication sufficient? Explicitly deferred to a
> future enhancement per section 1 Out of Scope — confirm no user-facing
> demand exists before considering it.]

## 10. See Also

- [[MOC-specs]] — all specifications
- PR #301 — fix: stop trusting RubyGems' always-empty yanked signal
  (closes #298) — the fix that was being live-verified when this bug was
  discovered; confirmed unaffected by this issue
- `crates/deps-bundler/src/registry.rs` — `parse_versions_response`
  (~line 98), fix location
- `crates/deps-bundler/src/types.rs` — `BundlerVersion` struct (~line 39)
- `crates/deps-core/src/lsp_helpers.rs` — `HOVER_RECENT_VERSIONS` constant
  (~line 21), hover rendering
- `.local/testing/journal/` — live-testing cycle that discovered this
  finding (2026-08-24)

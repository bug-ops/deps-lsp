---
aliases:
  - Completion Prefix Quote Stripping
  - JSON Completion Quote Bug
tags:
  - sdd
  - spec
  - bug
  - completion
  - npm
  - composer
created: 2026-08-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Strip JSON String-Delimiter Quote from Fallback Completion Prefix

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: fix/completion-prefix-quote-stripping
> **Priority**: P2
> **Type**: bug

## 1. Overview

### Problem Statement

`fallback_completion` in `crates/deps-lsp/src/handlers/completion.rs` (lines 149-152)
extracts the user's in-progress package-name prefix as:

```rust
let prefix_end = std::cmp::min(position.character as usize, line.len());
let prefix = &line[..prefix_end];
let prefix = prefix.trim();
```

`prefix.trim()` only strips whitespace. For JSON-based manifests (`package.json`
for npm, `composer.json` for Composer), `is_in_json_dependencies` (line 264)
confirms the cursor line is inside a `dependencies` / `require` / `require-dev`
block, but the raw line text still contains the opening `"` of the JSON string
literal the user is mid-typing (e.g. `"expr` while typing `"expr-eval"` inside
`"dependencies": { "expr`). That leading `"` is not stripped, so it is passed
straight through as the search query.

This query flows unmodified into `search_packages(registry, ecosystem_id, prefix)`
(line 430) and then into the registry's `search()` implementation, which URL-encodes
it verbatim and sends it to the live registry search API:

- npm: `format!("{}/-/v1/search?text={}&size={}", REGISTRY_BASE, urlencoding::encode(query), limit)`
  (`crates/deps-npm/src/registry.rs:143-149`) — sends `text=%22expr` (`"expr`) instead
  of `text=expr`.
- Composer/Packagist: `format!("{}?q={}&per_page={}", PACKAGIST_SEARCH, urlencoding::encode(query), limit)`
  (`crates/deps-composer/src/registry.rs:84-90`) — same defect pattern, same root cause
  (`is_in_json_dependencies` is also used for Composer's `require`/`require-dev`
  sections per `is_in_dependencies_section`, lines ~200-210).

Live verification against npm's real `/-/v1/search` endpoint confirms this is not
a caching or ranking-noise artifact but a genuine relevance regression: querying
with the stray leading quote (`%22expr`) omits the exact-name match package `expr`
from the top-5 results entirely, while querying without it (`expr`) returns `expr`
as the top-ranked result. See Reproduction below for the full comparison.

This is a longstanding, pre-existing defect (present since the original completion
feature, commit `ac0646e`, #36) — not introduced by the recent `EcosystemId` enum
refactor (#135) — but it directly degrades package-name completion quality for
npm and Composer, the two most commonly used JSON-manifest ecosystems, and had
gone undetected until this cycle's live end-to-end completion test because it was
not covered by any existing `journal.md`/`regressions.md` playbook entry.

### Goal

For JSON-based ecosystems (npm, Composer), the prefix passed to
`search_packages`/`registry.search` contains only the bare package-name text the
user has typed so far — with any leading and/or trailing JSON string-delimiter
quote (`"`) stripped in addition to whitespace — so registry search relevance
matches what a normal, well-formed query would return.

### Out of Scope

- Changes to non-JSON ecosystems (Cargo, PyPI, Maven, Go, Dart, Bundler, Swift,
  Gradle) — their raw-text prefix extraction does not involve a JSON string
  delimiter and is unaffected by this defect.
- Changes to `is_in_dependencies_section` / `is_in_json_dependencies` section-boundary
  detection logic itself — this spec only concerns prefix *content* extraction,
  not section detection.
- Changes to registry `search()` implementations (`deps-npm`, `deps-composer`) —
  the fix is upstream of them, in the prefix extraction shared by all ecosystems.
- Ranking/relevance tuning on the registry side — out of deps-lsp's control.
- Any parsed-completion path (`ecosystem.generate_completions`) — this only affects
  the raw-text `fallback_completion` fallback path used while the manifest is
  mid-typing and fails to parse.

## 2. User Stories

### US-001: Accurate package suggestions while typing a new npm/Composer dependency

AS A developer editing `package.json` or `composer.json`
I WANT completion suggestions to reflect what I actually typed, not a mangled query
SO THAT the package I'm typing (e.g. `expr`) appears near the top of the suggestion
list instead of being pushed out by irrelevant results

**Acceptance criteria:**
```
GIVEN a package.json with an unterminated dependency entry `"dependencies": { "expr`
WHEN completion is requested with the cursor immediately after "expr"
THEN the search query sent to the npm registry is `expr` (no leading quote)
AND the completion list includes the exact-name match `expr` package among the
    top results (subject to registry-side ranking, not degraded by a stray query
    character)
```

```
GIVEN a composer.json with an unterminated require entry `"require": { "monolog/lo`
WHEN completion is requested with the cursor immediately after "monolog/lo"
THEN the search query sent to Packagist is `monolog/lo` (no leading quote)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `fallback_completion` extracts the raw-text prefix for a JSON-based ecosystem (npm, Composer) THE SYSTEM SHALL strip a leading `"` character from the prefix, if present, before using it as the search query | must |
| FR-002 | WHEN `fallback_completion` extracts the raw-text prefix for a JSON-based ecosystem THE SYSTEM SHALL strip a trailing `"` character from the prefix, if present (e.g. cursor positioned just after a fully-closed string literal), before using it as the search query | must |
| FR-003 | WHEN the prefix, after quote-stripping, is empty or shorter than the existing minimum-length threshold (2 chars) THE SYSTEM SHALL reject it and return no completions, per existing behavior at line 157 | must |
| FR-004 | WHEN the ecosystem is not JSON-based (Cargo, PyPI, Maven, Go, Dart) THE SYSTEM SHALL NOT alter its existing prefix-extraction behavior | must |
| FR-005 | WHEN the stripped prefix still contains an internal `=` character (existing reject condition at line 157) THE SYSTEM SHALL continue to reject it as before | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | The fix must not change behavior for any ecosystem other than npm and Composer (or more generally, any ecosystem routed through `is_in_json_dependencies`) |
| NFR-002 | Performance | The added quote-stripping is a constant-time string operation on an already-bounded-length line prefix; no measurable latency impact on the completion hot path |
| NFR-003 | Testability | The fix must be covered by a unit test that reproduces the exact scenario in the finding (unterminated `"expr` inside `package.json` dependencies) and asserts the extracted prefix is `expr`, not `"expr` |

## 5. Data Model

No data model changes. This is a pure string-processing fix within
`fallback_completion`; no new entities, persisted state, or schema changes.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| N/A | No entities introduced or modified | — |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Prefix is exactly `"` (only the opening quote typed, nothing after) | After stripping, prefix is empty string; rejected by existing empty-check (FR-003), no completions returned |
| Prefix has quote on both ends, e.g. cursor lands right after a closed string `"expr"` | Both leading and trailing `"` stripped per FR-001/FR-002, leaving `expr` |
| Prefix has no quote at all (e.g. cursor is mid-value after `=`, non-JSON ecosystem, or user is inside a bare key) | No-op — quote-stripping only removes `"` if present at the boundary; unaffected inputs pass through unchanged |
| Prefix contains an escaped quote inside the value, e.g. `"expr\"` (unlikely for package names but theoretically typable) | `[NEEDS CLARIFICATION: should escaped-quote sequences inside the prefix be unescaped/handled specially, or is a simple leading/trailing `"` strip sufficient given package names practically never contain quote characters?]` — default assumption: simple boundary strip is sufficient since npm/Composer package names cannot contain `"` per registry naming rules |
| Non-JSON ecosystem line that happens to contain a literal `"` character in the prefix (e.g. TOML value context) | Not affected — quote-stripping is gated on `ecosystem_kind` being JSON-based (npm/Composer), per FR-004 |
| Multiple consecutive leading quotes (malformed input, e.g. `""expr`) | `[NEEDS CLARIFICATION: strip only one leading quote or all consecutive leading quotes?]` — default assumption: strip only one leading and one trailing quote (matches the realistic single-string-literal case); pathological multi-quote input is not expected from normal typing |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Query sent to npm/Composer registry search for a mid-typed JSON dependency name | Contains no leading/trailing `"` character |
| SC-002 | Regression test reproducing the finding's exact scenario (`"expr` in `package.json`) | Passes: extracted prefix equals `expr` |
| SC-003 | Existing completion test suite (lines ~1040-1090 and surrounding fallback-completion tests in `completion.rs`) | Continues to pass unchanged |
| SC-004 | Live end-to-end verification via `.local/testing/lsp_test.py` against real npm registry, matching the finding's reproduction steps | Top completion results now include the exact-name match package (e.g. `expr` for query `expr`) |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, and `cargo nextest run --workspace --all-features --lib --bins` before considering the fix complete
- Add a unit test reproducing the exact finding scenario
- Follow existing code patterns in `completion.rs` (the file already has helper functions like `is_in_json_dependencies`, `is_in_toml_dependencies`, etc. — keep the fix consistent with that style)
- Update `CHANGELOG.md` under `[Unreleased]`

### Ask First
- Any change to `is_in_dependencies_section` dispatch logic beyond what's needed to gate quote-stripping to JSON ecosystems
- Any change to registry `search()` signatures in `deps-npm`/`deps-composer`

### Never
- Modify non-JSON ecosystem prefix-extraction paths (Cargo, PyPI, Maven, Go, Dart, Bundler, Swift, Gradle)
- Perform live registry end-to-end verification during a code-writing/fix session — per `.claude/rules/continuous-improvement.md`, live testing against real registries is scoped to dedicated testing sessions, not fix implementation sessions (unit test coverage per SC-002/SC-003 is sufficient to close this spec; SC-004 live verification is a follow-up testing-session activity)
- Commit secrets or credentials

## 9. Open Questions

- [NEEDS CLARIFICATION: should escaped-quote sequences inside the prefix (e.g. `"expr\"`) be unescaped/handled specially, or is a simple leading/trailing `"` boundary strip sufficient? Default assumption: simple strip is sufficient since npm/Composer package names cannot contain `"`.]
- [NEEDS CLARIFICATION: for malformed input with multiple consecutive leading quotes (e.g. `""expr`), strip only one or all? Default assumption: strip only one leading and one trailing quote.]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- `crates/deps-lsp/src/handlers/completion.rs` — `fallback_completion`, `is_in_json_dependencies`, `search_packages`
- `crates/deps-npm/src/registry.rs` — npm `search()` implementation
- `crates/deps-composer/src/registry.rs` — Composer/Packagist `search()` implementation
- Issue #36 (`ac0646e`) — original completion feature introducing this defect
- PR #135 — `EcosystemId` enum refactor (unrelated to this defect, but touches the same dispatch logic)

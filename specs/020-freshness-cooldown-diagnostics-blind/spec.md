---
aliases:
  - Freshness cooldown blind in diagnostics
tags:
  - sdd
  - spec
  - bug
  - deps-lsp
  - deps-core
  - freshness
created: 2026-08-24
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Release-cooldown callout never reaches diagnostics for registries that gate freshness behind `get_versions_with`

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Branch**: (none yet)
> **Priority**: P1
> **Discovered during**: ci-007 live testing of #316 (release-freshness diagnostics, cooldown callout, live config reload)

## 1. Overview

### Problem Statement

#316 shipped a diagnostic-message differentiation
(`crates/deps-core/src/lsp_helpers/diagnostics.rs` ~line 584-606): when an
"outdated" dependency's replacement was published within the configured
`freshness.cooldown_secs` window (default 3 days, mirroring Dependabot),
the diagnostic message gets extra context —
`"Newer version available: X (published Y — still within the release
cooldown window)"` — instead of the plain message. The equivalent hover
callout (`crates/deps-core/src/lsp_helpers/hover.rs` ~line 179) — "⏳
**Recently published** — this release is still within the cooldown window."
— was live-verified working correctly.

Live-tested against real `registry.npmjs.org` data (2026-08-24): a
`package.json` pinning `@aws-sdk/client-s3` to an outdated version, with the
real latest (`3.1116.0`, published 2 days prior — inside the default 3-day
cooldown) produces:
- Hover: correctly shows the full cooldown callout.
- `textDocument/publishDiagnostics` at the exact same moment, same document:
  plain `"Newer version available: 3.1116.0"` — **no cooldown context at
  all**, despite being well inside the cooldown window.

Root cause, traced live via `RUST_LOG=debug` (only one HTTP request was
logged — the abbreviated packument fetch — confirming no separate
freshness-carrying fetch happened for this diagnostics run):

1. `Registry` trait (`crates/deps-core/src/registry.rs` ~line 84-114) defines
   two methods: `get_versions` (no freshness) and `get_versions_with`
   (freshness-aware, defaults to forwarding to `get_versions` and ignoring
   freshness — i.e. opt-in per registry). Five registries currently override
   `get_versions_with` to provide real `Version::published_at` data via an
   *extra* request: `deps-npm`, `deps-deno` (shared npm client + JSR),
   `deps-maven`, `deps-nuget`, `deps-swift`.
2. The trait doc comment is explicit about the footgun: *"Callers that render
   publish ages MUST call this method rather than `get_versions`: the default
   implementation ... simply forwards to `get_versions` and ignores
   `freshness`, so a caller that keeps calling `get_versions` silently gets
   no freshness signal even from a registry that implements this override."*
3. `crates/deps-lsp/src/handlers/hover.rs` correctly calls the
   freshness-aware path (comment there references `Registry::get_versions_with`
   explicitly).
4. `crates/deps-lsp/src/document/lifecycle.rs` (~line 721), which populates
   the shared diagnostics cache (`PackageVersions`, including
   `published_at`) for **all** dependencies in a document in one bulk pass,
   calls the **plain** `registry.get_versions(&name)` — never
   `get_versions_with`. This is the single code path diagnostics reads from
   (`crates/deps-core/src/lsp_helpers/diagnostics.rs` ~line 589,
   `package_versions.published_at`).
5. Consequently, for every one of the five registries that implement
   `get_versions_with`, `published_at` is always `None` in the diagnostics
   cache, so the `is_within_cooldown(...)` branch (diagnostics.rs line 595)
   can never be reached — the cooldown-differentiated diagnostic message is
   effectively dead code in production for those five ecosystems, even
   though its own unit tests (which construct `PackageVersions` directly,
   bypassing the real fetch path) pass.

This is not npm-specific: any of the five `get_versions_with`-implementing
registries (npm, Deno's npm:/jsr: routing, Maven, NuGet, Swift) has the
diagnostics half of #316 silently inert, while the hover half works.

### Goal

The diagnostics "Newer version available" cooldown-context message fires
consistently for every registry that can supply `published_at`, matching
hover's existing correct behavior — using the same underlying data, computed
once per document open/change rather than diverging by handler.

### Out of Scope

- Changing the cooldown threshold, its config surface, or the live-reload
  mechanism — all independently verified working this cycle (see journal).
- Changing severity of the "outdated" diagnostic — #316 already establishes
  message-only differentiation, severity is out of scope per its own design
  (diagnostics.rs comment ~line 585-588).
- The 10 registries with no `get_versions_with` override (e.g. Cargo, PyPI,
  Go, Bundler, Composer, Gradle) are unaffected by this specific bug — they
  either have no freshness source at all, or their `get_versions` already
  carries publish dates in the same response with no extra opt-in call.

## 2. User Stories

### US-001: Cooldown-aware diagnostic message

AS A developer with an outdated dependency whose replacement is a very
recent release
I WANT the inline diagnostic (not just hover-on-demand) to warn me it may
still be within the cooldown/soak window
SO THAT I don't act on a squiggle-driven quick-fix to jump to a
just-published version without the same context hover already gives me.

**Acceptance criteria:**
```
GIVEN an outdated npm/Maven/NuGet/Swift/Deno dependency whose latest version
      was published within freshness.cooldown_secs of "now"
WHEN textDocument/publishDiagnostics is computed
THEN the "Newer version available" diagnostic message includes the
     "— still within the release cooldown window" context, matching what
     hover already shows for the same dependency at the same instant
```

### US-002: No behavior change for registries without extra freshness cost

AS A maintainer of the 10 registries that don't override `get_versions_with`
I WANT this fix to not add an unconditional extra network round trip to
their diagnostics path
SO THAT diagnostics latency for Cargo/PyPI/Go/etc. is unaffected.

**Acceptance criteria:**
```
GIVEN a registry with no get_versions_with override (uses the trait default)
WHEN diagnostics are computed
THEN behavior and request count are unchanged from before this fix
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `crates/deps-lsp/src/document/lifecycle.rs` populates the diagnostics cache and `freshness.enabled` is true, THE SYSTEM SHALL call `Registry::get_versions_with` (not the plain `get_versions`) so `published_at` is populated for registries that support it | must |
| FR-002 | WHEN `freshness.enabled` is false, THE SYSTEM SHALL continue calling the plain `get_versions` (or pass a disabled `FreshnessSettings`), avoiding the extra request for registries that only pay the freshness cost on demand | must |
| FR-003 | THE SYSTEM SHALL NOT change the request count or behavior for the 10 registries using the trait-default `get_versions_with` (which simply forwards to `get_versions`) | must |
| FR-004 | THE SYSTEM SHALL keep hover and diagnostics reading `published_at` from the same underlying fetch per document lifecycle, avoiding a second divergent freshness fetch already performed once for the bulk pass | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness | New integration-level test (mockito-mocked npm registry with a `time` fixture) asserting `generate_diagnostics_from_cache` produces the cooldown-context message when fed a cache populated via the real `lifecycle.rs` bulk-fetch path, not a hand-built `PackageVersions` | 
| NFR-002 | Performance | For the 5 affected registries, the extra freshness request already happens today for hover on-demand — this fix moves it earlier (bulk pass) but SHALL NOT double it (i.e. hover must not re-fetch once the bulk pass already has fresh `published_at` for the same TTL window, respecting each registry's existing `publish_times` cache) |
| NFR-003 | Consistency | Hover and diagnostics MUST agree on cooldown status for the same dependency at the same instant — add a live regression scenario per registry in `regressions.md` |

## 5. Data Model

No new types. Affects `crates/deps-lsp/src/document/lifecycle.rs`'s bulk
fetch loop (~line 700-800, specifically line 721's `registry.get_versions(&name)`
call) and its interaction with `crates/deps-core/src/registry.rs`'s
`Registry::get_versions_with` trait method (~line 107) and the five
overriding implementations (`deps-npm`, `deps-deno`, `deps-maven`,
`deps-nuget`, `deps-swift`).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `freshness.enabled = false` | No behavior/request-count change — cooldown differentiation already suppressed per existing tests |
| Registry with no `get_versions_with` override (10 of 15) | No behavior/request-count change |
| Registry's extra freshness fetch fails/times out | Degrades to `published_at = None` per each registry's existing "never fails the caller" contract (e.g. `deps-npm`'s `fetch_publish_times` doc comment) — diagnostics falls back to the plain message, not an error |
| Live config reload shrinks `cooldown_secs` mid-session (already verified working for hover) | Diagnostics refresh (`workspace/diagnostic/refresh`, already implemented in `server.rs`) must reflect the new threshold on next pull/push, consistent with hover |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live diagnostics for `@aws-sdk/client-s3` outdated pin (real npm data, latest published 2 days ago, default 3-day cooldown) | Message includes "still within the release cooldown window" |
| SC-002 | Live hover for the same dependency, same instant | Unchanged (already correct) — used as the cross-check oracle |
| SC-003 | `cargo nextest run --workspace --all-features` | All pass, including new fixture-driven diagnostics test |
| SC-004 | Live regression check for a Cargo (no-`get_versions_with`) dependency's diagnostics before/after | Byte-identical output |

## 8. Agent Boundaries

### Always (without asking)
- Add the missing `get_versions_with` call in `lifecycle.rs`'s bulk fetch loop, gated on `freshness.enabled` per FR-002
- Add unit/integration test(s) exercising the real bulk-fetch-to-diagnostics path (not just diagnostics.rs's existing hand-built-cache unit tests, which already pass and mask this gap)
- Run `cargo +nightly fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo nextest run --workspace --all-features`
- Live-verify against real `registry.npmjs.org` (`@aws-sdk/client-s3` or similarly fast-moving package) per the Registry Integration Gate — re-run the exact scenario from `.local/testing/regressions.md`

### Ask First
- Whether to also route Maven/NuGet/Swift/Deno through the same fix in one PR or split per-ecosystem — recommend one PR since the fix is entirely in the shared `deps-lsp`/`deps-core` layer, not per-registry

### Never
- Add an unconditional extra network round trip for registries without a `get_versions_with` override (FR-003)
- Change diagnostic severity as part of this fix — message-only per #316's existing design

## 9. Open Questions

> [!question] Caching interaction
> [NEEDS CLARIFICATION: `deps-npm`'s `publish_times` cache is keyed by package name with its own TTL and "top-8" invalidation predicate (`crates/deps-npm/src/registry.rs` ~line 217-256). Calling `get_versions_with` from the bulk diagnostics pass (all dependencies, not just the top-8 "recent versions" window) may retain a different `current_top8` set than hover's call did moments earlier for the same package, potentially causing one extra invalidation/refetch cycle. Confirm whether this is negligible (bounded, TTL'd, already handled by `publish_times_stale`) or needs adjustment as part of this fix.]

## 10. See Also

- [[MOC-specs]] — all specifications
- [[019-npm-all-deprecated-unknown-package/spec|npm/JSR packages whose every published version is deprecated must not be reported "Unknown package"]] — same live-testing session, different root cause, same `deps-npm`/`lifecycle.rs` neighborhood
- `crates/deps-core/src/registry.rs` — `Registry::get_versions_with` (~line 107)
- `crates/deps-lsp/src/document/lifecycle.rs` — bulk fetch loop (~line 700-800)
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` — cooldown-context branch (~line 584-606)
- `crates/deps-core/src/lsp_helpers/hover.rs` — working cooldown callout (~line 179), used as the correctness oracle
- `.local/testing/journal/ci-007.md` — live-testing cycle that discovered this finding (2026-08-24)

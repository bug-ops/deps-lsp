---
aliases:
  - Completion Search Blocking Timeout
  - Fallback Completion Latency Fix
tags:
  - sdd
  - spec
  - bug
  - lsp
  - completion
  - performance
created: 2026-08-20
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Bound Latency of Package-Name Completion Fallback Search

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: fix/{issue-number}-completion-search-timeout
> **Priority**: P1 (bug)
> **Source finding**: continuous-improvement session, 2026-08-20, deps-lsp v0.9.5 (commit `03c5a1b03`)

## 1. Overview

### Problem Statement

`textDocument/completion` for a new package-name prefix (the "fallback completion" path)
blocks the LSP request handler for as long as the live registry search takes — up to the
generic 30-second `HTTP_TIMEOUT_SECS` (`crates/deps-core/src/cache.rs:11`) — instead of
returning within an interactive latency budget.

Root cause, traced through `crates/deps-lsp/src/handlers/completion.rs`:

- `handle_completion` (line ~94/100) calls `fallback_completion(&state, ecosystem_id, position, &content).await`
  **inline**, on the request-handling task, not delegated to `tokio::spawn`.
- `fallback_completion` (line ~171) calls `search_packages(registry.as_ref(), ecosystem_kind, prefix).await`.
- `search_packages` (line ~442) directly awaits `registry.search(query, 50).await` — a live
  HTTP call to the ecosystem registry — with no dedicated shorter timeout for this
  interactive path. It shares the same `HTTP_TIMEOUT_SECS` constant applied to the
  underlying `reqwest::Client` (`crates/deps-core/src/registry.rs:145`,
  `crates/deps-core/src/cache.rs:11`) that background hover/inlay-hint prefetches use —
  paths that are not latency-sensitive because their results are cached ahead of the
  request that needs them.
- On any error (including timeout), `search_packages` catches it and silently returns
  `vec![]` (line ~448) with only a `tracing::warn!` log line — no partial results, no
  indication to the editor/user that the search timed out rather than genuinely finding
  nothing.

This directly violates the project's own documented convention in
`.claude/rules/rust-code.md` under "LSP Layer (`crates/deps-lsp`)":
*"Hover and completion responses must return quickly; delegate registry fetches to
background tasks with caching."* The hover and inlay-hint paths already honor this
(pre-fetched, cached, background-populated data); the package-name completion fallback
path does not — it performs a synchronous, uncached, live registry search inline in the
request handler.

Confirmed live against Maven Central: a 2-character query (`gu`, the shortest prefix
`fallback_completion` accepts — see `prefix.len() < 2` rejection at
`crates/deps-lsp/src/handlers/completion.rs:157`) sent to
`https://search.maven.org/solrsearch/select` can hang for the full 30s (h2 handshake
completes, then no data frame arrives), versus ~0.2s for a longer, more specific query
(`guava`). A raw `curl` control test against the same Solr endpoint reproduced the same
first-attempt slowness independently of deps-lsp, confirming this is upstream registry
behavior (Maven Central's Solr backend being flaky/slow for short, unqualified queries) —
exactly the kind of registry latency variance the "delegate to background task"
convention exists to protect the interactive completion request from. Gradle shares the
same Maven registry client (`crates/deps-maven`) and is very likely to exhibit the same
freeze, though this was not separately re-verified live for `build.gradle`.

### Goal

`textDocument/completion` on a package-name prefix returns within a short, bounded,
interactive-latency window (target: within the existing `handle_completion` cold-start
budget class, i.e. single-digit seconds, not 30s) regardless of how slow the underlying
registry is for that particular query — by applying a short, dedicated timeout to the
fallback-completion live-search path, returning promptly (empty or best-effort partial
results) when that timeout is exceeded, distinct from the 30s `HTTP_TIMEOUT_SECS` used for
background prefetches.

### Out of Scope

- Changing `HTTP_TIMEOUT_SECS` itself or any other background-fetch timeout (hover,
  inlay hints, diagnostics) — those are correctly unbounded-ish because their results are
  pre-fetched/cached ahead of the request that consumes them.
- Fixing Maven Central's own Solr backend latency/flakiness — that is upstream, out of
  deps-lsp's control.
- Adding a warm-cache-on-timeout / "search continues in background, next keystroke sees
  the result" mechanism, unless selected as the chosen approach in section 3 (see open
  question OQ-1) — a minimal fix (bounded timeout + prompt empty return) satisfies the
  Goal above on its own.
- Re-verifying the Gradle-specific repro live — Gradle shares `deps-maven`'s registry
  client, so the fix in `deps-maven`/`search_packages` covers it, but a dedicated
  `build.gradle` short-query repro is not required to close this spec (may be covered by
  the fix's test suite instead, see NFR-002 / edge cases table).

## 2. User Stories

### US-001: Fast completion regardless of registry slowness
AS A developer editing a manifest file (e.g. `pom.xml`, `build.gradle`) in an editor with
LSP support
I WANT `textDocument/completion` for a new package name to respond quickly
SO THAT I am not blocked mid-typing while the editor's UI freezes or the completion
popup silently fails to appear for up to 30 seconds

**Acceptance criteria:**
```
GIVEN a manifest file open in the editor with the cursor inside a dependencies section
WHEN I type a short package-name prefix (e.g. 2 characters) that happens to trigger a
     slow response from the ecosystem registry's search endpoint
THEN the completion response returns within the bounded interactive timeout
     (see NFR-001), even if that means returning an empty completion list because the
     registry did not respond in time
```

### US-002: No silent multi-second UI freeze
AS A developer
I WANT the editor to remain responsive while I type
SO THAT a slow registry does not make the entire editor session feel hung

**Acceptance criteria:**
```
GIVEN the LSP server is processing a completion request whose fallback search is slow
WHEN the bounded timeout for that search elapses
THEN the LSP server returns a completion response (possibly empty) to the client instead
     of leaving the `textDocument/completion` request outstanding
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `fallback_completion` invokes `search_packages` for an interactive completion request THE SYSTEM SHALL apply a timeout to the registry search call that is strictly shorter than `HTTP_TIMEOUT_SECS` (30s) [NEEDS CLARIFICATION: exact bound — see OQ-2] | must |
| FR-002 | WHEN the fallback-completion search timeout elapses before the registry responds THE SYSTEM SHALL return an empty completion list for that request rather than continuing to await the in-flight HTTP call | must |
| FR-003 | WHEN the fallback-completion search times out THE SYSTEM SHALL log the timeout at a distinguishable level/message (e.g. `tracing::warn!` with an explicit "timed out" reason) separate from the existing generic search-failure log, so timeouts are distinguishable from genuine zero-result searches in `.local/testing/debug/session.log` | must |
| FR-004 | WHEN applying the new bounded timeout THE SYSTEM SHALL apply it uniformly across all ecosystems that use `fallback_completion` (Cargo, Pypi, Npm, Composer, Maven, Go, Dart, and any ecosystem for which `is_in_dependencies_section` returns true), not only Maven | must |
| FR-005 | THE SYSTEM SHALL NOT change the timeout used by background hover, inlay-hint, or diagnostic registry fetches (`HTTP_TIMEOUT_SECS` stays 30s for those paths) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `textDocument/completion` for a package-name prefix SHALL return within [NEEDS CLARIFICATION: target bound — candidates discussed in OQ-2, e.g. 3s, 5s] of request receipt, independent of registry response time, measured end-to-end via the existing `.local/testing/lsp_test.py` harness |
| NFR-002 | Reliability | The fix SHALL NOT regress the existing control case (a longer/more specific query, e.g. `guava` against Maven Central, currently ~0.2s) — no added latency floor beyond negligible timer/task overhead |
| NFR-003 | Observability | Timeout events on the fallback-completion path SHALL be visible in `RUST_LOG=debug` output with enough detail (ecosystem, query, elapsed time) to distinguish "registry timed out" from "registry returned zero matches" without re-running the request |
| NFR-004 | Consistency | The bounded-timeout behavior SHALL be identical across all ecosystems sharing `fallback_completion`/`search_packages` — this is a `deps-core`/`deps-lsp` layer fix, not an ecosystem-specific one, per the project's cross-ecosystem-consistency convention |

## 5. Data Model

No new persistent entities. This is a control-flow/timeout change on an existing
request path.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Fallback completion request | In-flight interactive search triggered by `fallback_completion` → `search_packages` → `registry.search()` | ecosystem id, query prefix, elapsed time, outcome (results / empty-timeout / empty-error) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Registry responds within the new bounded timeout | Completion items returned as today (no behavior change) |
| Registry never responds (network hang, upstream flakiness) within the bounded timeout | `search_packages` returns `vec![]`; `handle_completion` returns `Some(CompletionResponse::Array(vec![]))` or `None` per existing `items.is_empty()` branching (unchanged from current empty-result behavior, just reached faster) |
| Registry returns a genuine HTTP error (4xx/5xx) before the bounded timeout | Unchanged: existing `Err(e) => { warn!; vec![] }` branch in `search_packages`, distinguishable in logs from a timeout per FR-003 |
| Query prefix is 2 characters (minimum accepted length) against a registry backend known to be slow for short queries (e.g. Maven Central Solr) | Bounded timeout applies exactly as for any other query length; no separate short-prefix carve-out (see OQ-1) |
| Multiple rapid keystrokes each triggering a new fallback-completion search before the previous one's timeout elapses | [NEEDS CLARIFICATION: does this spec require cancelling/superseding a still-in-flight prior search, or is it acceptable for prior in-flight bounded-timeout searches to simply run to completion/timeout in the background and be discarded? Current code has no such cancellation; out of scope unless explicitly requested — see OQ-3] |
| Ecosystem's own `generate_completions` already returns non-empty results | Fallback path (and this fix) is never reached — unchanged |
| Ecosystem with no raw-text dependencies-section boundary (Bundler, Swift, Gradle's TOML/Groovy/Kotlin manifests per `is_in_dependencies_section`) | Fallback completion already returns `vec![]` before reaching `search_packages` — unaffected by this fix, though FR-004 still requires the timeout to apply uniformly for ecosystems where the fallback path IS reached (e.g. Maven's `pom.xml`, which does have a raw-text `<dependencies>` boundary) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `textDocument/completion` wall-clock latency for a 2-char Maven prefix against a slow/hanging Solr response | Reduced from the reproduced ~36s to within the bounded timeout target (NFR-001), verified live via `.local/testing/lsp_test.py` per the repro steps in this finding |
| SC-002 | Control-case latency (longer/specific query, e.g. `guava`) | Remains ~0.2s–low seconds, no regression |
| SC-003 | Cross-ecosystem consistency | Same bounded-timeout behavior verified for at least Maven and one other ecosystem using `fallback_completion` (e.g. Cargo or Npm) with an artificially slow/mocked registry response in a unit/integration test |
| SC-004 | Log distinguishability | A timed-out fallback search produces a log line distinguishable from a zero-result search when grepped in `.local/testing/debug/session.log` |

## 8. Agent Boundaries

### Always (without asking)
- Run `cargo nextest run -p deps-lsp` (and `-p deps-core` / affected registry crates) after changes
- Follow existing code patterns in `crates/deps-lsp/src/handlers/completion.rs` and
  `crates/deps-core/src/cache.rs` / `registry.rs` for timeout/error handling style
- Preserve existing public behavior for non-timeout cases (successful search, genuine
  HTTP errors) exactly as documented in section 6

### Ask First
- Introducing a new constant name/location for the bounded completion-search timeout if
  it isn't obviously implied by existing naming conventions (e.g. alongside
  `HTTP_TIMEOUT_SECS` in `deps-core/src/cache.rs`, or local to `deps-lsp`)
- Any change that also touches the 30s `HTTP_TIMEOUT_SECS` background-fetch timeout
  (explicitly out of scope per FR-005 unless the user says otherwise)
- Adding cancellation/supersession logic for rapid successive keystroke-triggered
  searches (see OQ-3) — this is a larger behavioral change than the minimal bounded-
  timeout fix

### Never
- Change registry API client logic unrelated to timeout handling (e.g. Maven Solr query
  construction, result parsing)
- Silently increase `HTTP_TIMEOUT_SECS` as a workaround instead of adding a dedicated
  shorter timeout for the interactive path
- Remove or weaken the existing `tracing::warn!` on search failure — only extend/clarify it

## 9. Open Questions

- [NEEDS CLARIFICATION: OQ-1 — Should there be a background "warm the cache" behavior
  where, after the bounded timeout returns empty results to the editor, the live search
  keeps running in the background so a follow-up keystroke on a similar/extended prefix
  can hit a cache and return real results faster? The finding's "Expected behavior"
  section mentions this as one of two acceptable approaches (the other being a bare
  bounded timeout). Decide before `/sdd plan`.]
- [NEEDS CLARIFICATION: OQ-2 — What is the exact timeout bound for the interactive
  completion-search path? Candidates to consider: a fixed value (e.g. 2s, 3s, 5s)
  independent of `HTTP_TIMEOUT_SECS`, or a fraction/derived value. The existing
  cold-start document-load timeout in `handle_completion` uses 200ms for a much
  cheaper local operation (disk load), which is not directly comparable to a live
  cross-network registry search.]
- [NEEDS CLARIFICATION: OQ-3 — Should rapid successive completion requests (each
  triggering a new fallback search before the prior one's timeout elapses) cancel the
  prior in-flight search, or is running multiple bounded-timeout searches concurrently
  acceptable? No existing cancellation mechanism exists in `fallback_completion` today.]
- [NEEDS CLARIFICATION: whether the bounded timeout should be implemented via
  `tokio::time::timeout` wrapping the `registry.search()` call in `search_packages`
  (simplest, most local to the fix), or via a `reqwest::Client`-level per-request
  timeout override passed down through the `Registry` trait (more invasive, touches
  `crates/deps-core/src/registry.rs` trait signature and every ecosystem's
  implementation). Recommend the former unless plan-phase investigation shows the
  `Registry` trait already supports per-call timeout overrides.]

## 10. See Also

- [[constitution]] — project principles (not yet created for this project)
- [[MOC-specs]] — all specifications
- `.claude/rules/rust-code.md` — "LSP Layer" convention this bug violates
- `.claude/rules/continuous-improvement.md` — testing/anomaly-reporting process this
  finding originated from
- `crates/deps-lsp/src/handlers/completion.rs` — `handle_completion`,
  `fallback_completion`, `search_packages` (lines ~19, ~115, ~429)
- `crates/deps-core/src/cache.rs:11` — `HTTP_TIMEOUT_SECS` constant (background-fetch
  timeout, unaffected by this fix per FR-005)
- `crates/deps-core/src/registry.rs:117,145` — `Registry::search` trait method and
  `HTTP_TIMEOUT_SECS` application to the underlying `reqwest::Client`
- `crates/deps-maven/src/registry.rs:18,133` — `MAVEN_SEARCH_BASE`
  (`https://search.maven.org/solrsearch/select`), `search_typed` — concrete repro path
  for the Maven Central Solr slowness

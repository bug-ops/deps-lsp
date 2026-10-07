---
aliases:
  - Interactive registry await failure memo
  - Hover 10s stall
  - REGISTRY_FETCH_BUDGET stall
tags:
  - sdd
  - spec
  - lsp
  - hover
  - code-actions
  - latency
  - cross-ecosystem
  - deps-core
created: 2026-10-07
status: draft
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[081-wall-clock-test-assertions/spec|spec 081 (wall-clock test assertions)]]"
---

# Feature: Fail-fast interactive registry awaits (failure memo) for hover and code actions

> [!info] Metadata
> **Author**: continuous-improvement cycle (spec session, 2026-10-07)
> **Branch**: N/A (no implementation branch yet; suggested `fix/interactive-registry-await-failure-memo`)
> **Priority**: P2
> **Category**: bug, cross-ecosystem
> **Issue**: not yet filed at spec time (finding reported by the live-tester stream against HEAD `8cb71b132`)
> **Follows**: #1204 (introduced `REGISTRY_FETCH_BUDGET`)

## 1. Overview

### Problem Statement

Issue #1204 bounded the interactive registry await in hover and code actions with
`REGISTRY_FETCH_BUDGET = 10s` (`crates/deps-core/src/lsp_helpers/mod.rs`, `await_versions_fetch`, called from
`lsp_helpers/hover.rs` and `lsp_helpers/code_actions.rs`). The bound turned an unbounded stall into a 10 s
stall, but it is a **per-request** bound with **no memory**: against a registry that never answers (connect
black-hole, dead proxy, unroutable custom `registry-index`), every hover re-awaits a live fetch for the full
10 s, even long after the background fetch has already failed and surfaced a
"Registry lookup failed for '<pkg>'" diagnostic for that very package.

The failure is already known to the server. `VersionData::outcomes` (`DependencyOutcomes`) carries a per-package
`FetchFailure` (`Actionable` / `Transient` / `NotAttempted`), and hover and code actions already receive it
(`VersionData` is passed to both). Neither consults it before calling `await_versions_fetch`.

The second symptom is system-wide. `tower-lsp-server` dispatches requests via `buffer_unordered(4)` (see the
comments at `crates/deps-lsp/src/server.rs` ~line 961). Four hovers stalled on a black-holed registry (a user
sweeping the mouse across four dependencies) occupy every dispatch slot, so an unrelated request (codeLens,
completion, codeAction, inlay hint) is answered only after the 10 s elapse. This violates the project rule
"All handler methods must stay non-blocking ... hover/completion must return quickly from already-cached state"
(`.claude/CLAUDE.md`, `deps-lsp` section).

> [!bug] Live reproduction (HEAD `8cb71b132`, debug build, harness `.local/testing/lsp_ci103.py`)
> 1. `Cargo.toml`: `serde = { version = "1.0.100", registry-index = "sparse+https://203.0.113.7/" }`
>    (TEST-NET-3 black hole; public host class, so the SSRF policy allows the attempt). Open it, wait 12 s.
>    Background fetch finishes and the diagnostic "Registry lookup failed for 'serde'; package status could
>    not be determined" is published.
> 2. Three sequential `textDocument/hover` requests on the dependency: **each takes 10.01 s** and returns the
>    basic card without `Latest`.
> 3. Four concurrent hovers, then `textDocument/codeLens`: all four hovers **and** the codeLens answer at
>    t = 10.01 s. With one hover in flight the codeLens answers at 0.01 s.
> 4. Same with npm (`.npmrc` `registry=https://203.0.113.7/`, `package.json` `lodash`): 10.01 s per hover.
>    Same with `HTTPS_PROXY=http://10.255.255.1:3128` (dead proxy) and default crates.io: 10.00 s per hover.
>
> Control: reachable registry, hover answers in 0.05 to 0.2 s.

### Why it is cross-ecosystem

The await lives in `deps-core::lsp_helpers` and is reached through the default `Ecosystem::generate_hover` /
`generate_code_actions` implementations, so every ecosystem that does not override those methods inherits the
stall (confirmed live for Cargo and npm). Per the project's cross-ecosystem consistency rule, the fix belongs in
`deps-core` once, not per ecosystem crate.

### Goal

After a registry lookup for a package has failed or timed out and that fact is known to the server, hover and
code actions answer for that package immediately from the degraded path (basic card without `Latest`, no
speculative fix actions where applicable), and a slow registry can never occupy all LSP dispatch slots.

### Out of Scope

- Changing the **background** fetch pipeline, its timeouts, retry counts, or `max_concurrent_fetches`
  (`crates/deps-lsp/src/handlers/diagnostics.rs`). That path is already bounded and off the request path.
- Raising or lowering the HTTP-level timeouts inside `HttpCache` / per-ecosystem registry clients.
- Disk-persistent negative cache across server restarts (see [[051-disk-persistent-registry-cache/spec|spec 051]]).
- Completion, code lens, and inlay hints: these already return from cached state or carry their own tighter
  budget (`COMPLETION_SEARCH_TIMEOUT = 2 s`) and were not observed to stall in the reproduction (codeLens
  stalled only because dispatch slots were taken, not because of its own await).
- Changing `tower-lsp-server`'s `buffer_unordered(4)` dispatch width (third-party; not configurable here).
- Any change to diagnostics text or the `FetchFailure` privacy contract (no raw, IP-bearing error text).

## 2. User Stories

### US-001: Hovering a dependency whose registry is down is instant

AS A developer working off-VPN (or against a dead private registry)
I WANT hover on a dependency whose lookup already failed to answer immediately with the basic card
SO THAT my editor does not freeze each time the pointer rests on a dependency.

**Acceptance criteria:**
```
GIVEN a manifest with a dependency whose registry never answers
  AND the background fetch has finished and recorded a fetch failure for that package
WHEN the user sends textDocument/hover on that dependency three times in a row
THEN each hover returns the basic card (no Latest, no Recent versions) in under 100 ms
  AND no live registry request is issued by any of the three hovers
```

### US-002: Other LSP features stay responsive while hovers are slow

AS A developer sweeping the mouse over several dependencies
I WANT codeLens, completion, code actions, and inlay hints to keep answering promptly
SO THAT one unreachable registry does not make the whole language server look hung.

**Acceptance criteria:**
```
GIVEN four concurrent hover requests on four distinct dependencies whose registry never answers
  AND the background fetch has NOT yet recorded failures for them (cold document)
WHEN a textDocument/codeLens request is sent while the hovers are in flight
THEN the codeLens response is returned in under 250 ms
```

### US-003: Recovery after the registry comes back

AS A developer whose VPN just reconnected
I WANT hover to show live version data again without restarting the server
SO THAT a transient outage is not remembered longer than necessary.

**Acceptance criteria:**
```
GIVEN a package with a recorded fetch failure and an expired (or cleared) memo
  AND the registry is reachable again
WHEN the user hovers the dependency
THEN the hover performs one live fetch and renders Latest and Recent versions
  AND the failure record for that package is cleared
```

### US-004: Code actions do not lag on a dead registry

AS A developer opening the lightbulb menu on a dependency with a failed lookup
I WANT the menu to appear immediately
SO THAT quick fixes are usable even when the registry is unreachable.

**Acceptance criteria:**
```
GIVEN a dependency with a recorded fetch failure for its source
WHEN the user sends textDocument/codeAction on its range
THEN the response returns in under 100 ms without awaiting a live registry fetch
```

## 3. Functional Requirements

Requirements use EARS notation. "Known failure" means a failed or timed-out lookup for the package **and
source** recorded either in `VersionData::outcomes` as `FetchFailure::Transient` or `FetchFailure::Actionable`,
or in the interactive failure memo defined by FR-003 (design open, see OQ-1).

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN hover is requested for a dependency AND a known failure exists for that package and source THE SYSTEM SHALL skip the live `get_versions_from` await and render the same degraded basic card a genuine fetch error renders today | must |
| FR-002 | WHEN code actions are requested for a dependency AND a known failure exists for that package and source THE SYSTEM SHALL skip the live `get_versions_from` await and apply the code-action degrade policy chosen in OQ-5 | must |
| FR-003 | WHEN an interactive await (hover or code action) fails or exceeds `REGISTRY_FETCH_BUDGET` THE SYSTEM SHALL record the failure so that subsequent interactive requests for the same package and source within the memo lifetime do not re-await a live fetch | must |
| FR-004 | THE SYSTEM SHALL key any failure record by package name **and** dependency source (not name alone), so a failure against one registry or source does not degrade hover for the same name resolved from a different source | must |
| FR-005 | WHEN the failure memo's lifetime has elapsed (TTL, OQ-2) THE SYSTEM SHALL permit the next interactive request to perform one live fetch bounded by the interactive budget | must |
| FR-006 | WHEN a failure record is cleared by the background pipeline (a later successful fetch, a manifest reparse, a configuration reload, or a network-mode change) THE SYSTEM SHALL treat the package as having no known failure on the next interactive request | must |
| FR-007 | WHILE an interactive live fetch for a package and source is already in flight THE SYSTEM SHALL let concurrent interactive requests for the same package and source share that single fetch instead of starting additional ones | should |
| FR-008 | WHILE interactive registry awaits are in flight THE SYSTEM SHALL bound their concurrency so that at least one `buffer_unordered(4)` dispatch slot remains free for non-registry requests, and requests over the bound SHALL take the degraded path immediately | must |
| FR-009 | WHEN `FetchFailure::NotAttempted` is the only record for a package THE SYSTEM SHALL NOT treat it as a known failure (the absence of an attempt is not evidence the registry is unreachable) | must |
| FR-010 | THE SYSTEM SHALL store only the typed failure classification (`FetchFailure` or an equivalent closed enum) in the memo, never raw error text, URLs, or IP addresses | must |
| FR-011 | THE SYSTEM SHALL emit a `tracing::debug!` (not `warn!`) when a request takes the fast-fail path, naming the redacted package, and SHALL keep the existing `warn!` only for a genuine budget elapse | should |
| FR-012 | THE SYSTEM SHALL implement the behavior once in `deps-core::lsp_helpers` so every ecosystem using the default `generate_hover` / `generate_code_actions` inherits it, and SHALL NOT add per-ecosystem copies | must |
| FR-013 | WHILE `NetworkMode::Offline` is active THE SYSTEM SHALL keep its existing offline behavior unchanged (the new path must not alter offline hover rendering) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance (latency) | With a known failure, hover and codeAction p99 latency SHALL be under 100 ms and p50 under 20 ms, independent of registry reachability (compare the 10.01 s observed today) |
| NFR-002 | Performance (latency) | On a cold document (no failure known yet), a single interactive await SHALL still not exceed the interactive budget (`REGISTRY_FETCH_BUDGET` or the shorter value chosen in OQ-3) |
| NFR-003 | Responsiveness | With any number of hovers stalled on an unreachable registry, an unrelated request (codeLens, completion, codeAction, inlay hint) SHALL be answered in under 250 ms (compare 10.01 s observed today with four hovers) |
| NFR-004 | Reliability | The memo SHALL be bounded in size (entries evicted by TTL and a hard cap) so a manifest with thousands of dependencies cannot grow it without bound |
| NFR-005 | Security | The memo MUST NOT widen the SSRF or secret-exposure surface: no new outbound requests, no raw error text (FR-010), custom-registry URLs remain subject to `net_policy` |
| NFR-006 | Type safety | The memo key and failure state SHALL be typed (`PackageName` plus a typed source key; closed enums), with no `String`-keyed ad-hoc maps and no new `#[non_exhaustive]` exhaustive-enum escape hatches or catch-all arms |
| NFR-007 | Consistency | Hover and code actions SHALL consult the same record through one shared helper; the two call sites SHALL NOT diverge in what counts as a known failure |
| NFR-008 | Testability | Tests SHALL use `tokio::time::pause` / `start_paused` (as the existing #1204 tests do) rather than wall-clock bounds, in line with [[081-wall-clock-test-assertions/spec|spec 081]] |
| NFR-009 | Observability | Debug logs SHALL make a fast-fail distinguishable from a live budget elapse, so a future live test can tell them apart without code reading |

## 5. Data Model

Conceptual only; representation is a plan-phase decision.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Known failure (existing) | Per-package outcome recorded by the lifecycle fetch in `DependencyOutcomes` | normalized name, `FetchFailure` (`Actionable`, `Transient`, `NotAttempted`) |
| Interactive failure memo (new, shape open, OQ-1) | Short-lived record that an interactive await for a package and source failed or timed out | package name, source key, failure class (typed), recorded-at instant, expiry |
| In-flight interactive fetch (new, optional, FR-007) | Shared handle that lets concurrent requests for one package and source await a single fetch | package name, source key, shared future |
| Interactive concurrency bound (new, OQ-4) | Cap on simultaneously awaiting hover/code-action registry fetches | max in flight, overflow policy (degrade immediately) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| First hover on a cold document, background fetch still running against a black-holed host | Live await bounded by the interactive budget (NFR-002); on elapse, record the failure (FR-003) so the next hover is instant |
| Background fetch recorded a failure, registry recovers, no reparse happens | Failure persists until memo TTL expires or something clears it; next hover after TTL does one live fetch (FR-005, US-003) |
| Same package name from two sources (default registry and a custom `registry-index`) | Records are source-qualified (FR-004); a failure on the custom source does not degrade hover for the default-source dependency |
| `FetchFailure::NotAttempted` (name/source collision dedup) | Not a known failure (FR-009); hover does a normal bounded live fetch |
| `FetchFailure::Actionable` (rate limited, policy blocked, halted chain) | Treated as known failure; hover stays on the degraded card, and the hint remains available through the diagnostic |
| Code action on a dependency whose failure was a **timeout** | Semantics per OQ-5: today a timeout drops speculative fix/unsatisfiable actions (an unverified yank check must not fail open), whereas a genuine error lets them through |
| Package count in the thousands, all failing | Memo capped (NFR-004); eviction never causes more than one extra bounded live fetch per package per TTL |
| Four concurrent hovers on distinct, not-yet-known-failing packages | At most the bounded number hit the registry; the rest degrade immediately (FR-008); dispatch slots stay free (NFR-003) |
| Dead proxy (`HTTPS_PROXY` unreachable) with default crates.io | Same as black-holed registry: every package fails; per-package memo plus background outcomes cover all of them after the first failure per package (host-level aggregation is OQ-7) |
| Document closed and reopened, or manifest reparsed | Records tied to the document's outcomes clear with it; a memo scoped beyond one document expires by TTL or reload (FR-006) |
| Config reload changes registry URL, token, or proxy | Records are invalidated (FR-006) so a fixed configuration takes effect without waiting out the TTL |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover latency on a package with known failure (black-holed registry, live harness) | < 100 ms p99 (was 10.01 s every time) |
| SC-002 | codeLens latency with four concurrent stalled hovers in flight | < 250 ms (was 10.01 s) |
| SC-003 | Live registry requests issued by 3 sequential hovers after a recorded failure | 0 |
| SC-004 | Recovery: hover after memo expiry against a reachable registry | 1 live fetch, `Latest` rendered, failure cleared |
| SC-005 | Reachable-registry control hover latency | no regression (still 0.05 to 0.2 s) |
| SC-006 | Behavior parity across ecosystems | the same scenario passes for at least Cargo, npm, and one more default-path ecosystem (e.g. PyPI or Go) in the live matrix |
| SC-007 | Existing #1204 tests (`REGISTRY_FETCH_BUDGET` elapse degrades to basic card / drops speculative actions) | still pass unchanged or are updated only where OQ-5 deliberately changes the policy |

## 8. Agent Boundaries

### Always (without asking)
- Reproduce with a live LSP harness against a black-holed registry before and after the change, per the
  Live Testing Principle in `.claude/rules/continuous-improvement.md`.
- Put the shared logic in `deps-core::lsp_helpers`; check `lsp_helpers/`, `fs_probe`, and existing memo
  patterns (e.g. `deps-maven`'s `RECENT_FAILURE_TTL`, `deps_dev/memo.rs`) for an existing helper first.
- Use paused-time tokio tests, not wall-clock assertions (NFR-008).
- Run the full check suite (fmt, clippy `--all-features -D warnings`, nextest, strict rustdoc gate).
- Update `CHANGELOG.md` `[Unreleased]` with a one-line entry and PR link; update the testing knowledge base
  (`coverage.md`, relevant playbooks, `regressions.md`) per `branching.md`.

### Ask First
- Adding a dependency (e.g. a TTL/LRU cache crate) instead of reusing in-tree helpers.
- Changing the public signature of `generate_hover` / `generate_code_actions` or `VersionData` (both are
  public deps-core API used by every ecosystem crate).
- Lowering `REGISTRY_FETCH_BUDGET` below its current 10 s default for users with legitimately slow registries.
- Changing the code-action timeout-versus-error semantics (OQ-5).

### Never
- Fail open on a timed-out yank check without an explicit decision (see the `fetch_timed_out` rationale in
  `code_actions.rs`).
- Store raw error text, URLs, or IP addresses in the memo (FR-010).
- Add per-ecosystem copies of the fast-fail logic, or a catch-all `_ =>` arm on an exhaustive enum.
- Edit `crates/deps-zed` or `crates/deps-cli`-only code paths for this fix.
- Block a handler on registry I/O beyond the interactive budget, or add `unsafe`.

## 9. Open Questions

> [!question] Genuinely open design choices
> Everything not listed here is fixed by the reproduction and by existing project rules.

- [NEEDS CLARIFICATION: OQ-1 Memo location and shape. (a) Read-only: consult `VersionData::outcomes`
  (already the per-document record) and add nothing new, which fixes the "background already failed" case but
  not the cold-document case. (b) Add a per-package, source-qualified interactive failure memo with TTL inside
  `deps-core` (shared across documents, survives reparse). (c) Both: outcomes first, memo for cold documents.
  Recommended: (c), because the reproduction needs both the post-background case (step 2) and the cold
  four-hover case (step 3).]
- [NEEDS CLARIFICATION: OQ-2 Memo TTL, if a memo is added. Candidates: 30 s, 60 s, or a short backoff that
  grows on repeated failure. Trade-off: recovery latency after a VPN reconnect versus retry traffic. Note
  `deps-maven`'s `RECENT_FAILURE_TTL` is 2 s (search-scoped); the version-fetch case likely wants a longer
  value. Recommended default: 30 s.]
- [NEEDS CLARIFICATION: OQ-3 Shorter interactive budget. Should `REGISTRY_FETCH_BUDGET` (10 s) shrink for the
  cold-document case (e.g. 2 to 3 s while the background fetch for that package is still pending), keeping 10 s
  only as the ceiling? Cost: slow-but-working registries (large Gradle fallback chains, the case #1204 was
  written for) would degrade more often. Memo (OQ-1) plus bounded concurrency (OQ-4) may make this
  unnecessary.]
- [NEEDS CLARIFICATION: OQ-4 Concurrency-bound mechanism and value. A `tokio::sync::Semaphore` (with
  `try_acquire`, overflow degrades immediately) sized at 2 or 3 of the 4 dispatch slots, versus per-kind bounds
  (hover and code action separate), versus relying on the memo alone. Needs a decision on the numeric bound and
  on whether it is global or per-document. Interacts with the `server.rs` comments about the 4-slot dispatch.]
- [NEEDS CLARIFICATION: OQ-5 Code-action policy on a memoized failure. Today a genuine fetch error fails open
  (fix and unsatisfiable actions pass through unfiltered) while a timeout drops them. A memoized failure may
  have originated as either. Options: (a) memoize the timed-out/errored distinction and replay the same
  policy per request; (b) always drop speculative actions on any known failure; (c) always fail open on a
  known failure. (a) preserves current semantics exactly; (b) is simplest and safest for the yank check.]
- [NEEDS CLARIFICATION: OQ-6 Should an interactive budget elapse by itself populate the memo when the
  background fetch for that package has not finished? If yes, a slow-but-eventually-successful registry could
  be marked failed for one TTL; the background success must then clear it (FR-006) and the plan must say who
  owns that clear.]
- [NEEDS CLARIFICATION: OQ-7 Host-level circuit breaker. A per-package memo does not help the first hover on
  each distinct package when the whole host (or proxy) is dead. Is a host-scoped breaker (open after N
  consecutive failures to one registry host, using `net_policy::HostClass` / host identity) in scope here, or a
  follow-up? Without it, N distinct first hovers still cost up to N bounded awaits, limited only by OQ-4.]

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[081-wall-clock-test-assertions/spec|Spec 081]] — paused-time tests instead of wall-clock bounds (testing convention this fix must follow)
- [[051-disk-persistent-registry-cache/spec|Spec 051]] — persistent registry cache (a negative cache across restarts is out of scope here)
- Code: `crates/deps-core/src/lsp_helpers/mod.rs` (`REGISTRY_FETCH_BUDGET`, `await_versions_fetch`,
  `DependencyOutcomes`), `lsp_helpers/hover.rs` (~line 158), `lsp_helpers/code_actions.rs` (~line 540),
  `crates/deps-core/src/error.rs` (`FetchFailure`), `crates/deps-lsp/src/server.rs` (~line 961, dispatch width)
- Prior art: #1204 (the budget), `deps-maven` `RECENT_FAILURE_TTL` (search-failure memo), `deps_dev/memo.rs`
  (single-flight/memo shape in `deps-core`)

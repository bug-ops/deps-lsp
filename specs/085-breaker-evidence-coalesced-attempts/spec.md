---
aliases:
  - Breaker evidence for coalesced attempts
  - Breaker never opens for NuGet and GitHub Actions
  - Wire-contact evidence regression
tags:
  - sdd
  - spec
  - lsp
  - hover
  - latency
  - regression
  - cross-ecosystem
  - deps-core
created: 2026-10-19
status: plan
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[082-interactive-registry-await-failure-memo/spec|082 Interactive registry await failure memo]]"
  - "[[084-unified-registry-trust-rule/spec|084 Unified registry trust rule]]"
---

# Feature: Endpoint circuit breaker evidence for attempts that coalesce onto another task's request

> [!info] Metadata
> **Author**: continuous-improvement cycle (spec session, 2026-10-19)
> **Branch**: N/A (suggested `fix/interactive-gate-breaker-coalesced-evidence`)
> **Priority**: P2
> **Category**: bug (regression), cross-ecosystem
> **Issue**: #1863 (finding reported by the live-tester stream against HEAD `3204da4b3`)
> **Regressed by**: #1858 (commit `3204da4b3`, "wire-contact breaker evidence"); last good commit `394cb8797` (#1852)
> **Follows**: [[082-interactive-registry-await-failure-memo/spec|spec 082]] (OQ-7, the endpoint circuit breaker)

## 1. Overview

### Problem Statement

Spec 082 (OQ-7) defines an endpoint circuit breaker: two slow attempts for distinct packages on one
registry endpoint, with no answer in between, open the breaker, and hover on a third package of that endpoint
is refused for 30 s without polling. Commit `3204da4b3` (#1858) changed what counts as "slow". Evidence is
now read from a per-attempt `ContactLedger` (`crates/deps-core/src/endpoint_contact.rs`), installed as a
task-local around the polled fetch (`attempt.rs`, `AttemptGuard`). `note_request()` is called by the HTTP
cache's send sites (`crates/deps-core/src/cache/fetch.rs`) in the task that sends. `evidence()` reports
`Slow` only when `Contact.stall >= budget / 2`, and reports `Inconclusive` for an attempt that never sent a
request of its own.

That rule is correct for an attempt that issues its own request (Cargo, npm, PyPI, Go, Bundler, Dart, Maven,
Composer, Gradle, Swift, GitLab CI, Deno). It is wrong for an attempt that, by the structure of its
ecosystem crate, **waits on a request another task already put on the wire**:

| Ecosystem | Shared wait (source) | What the interactive attempt awaits |
|-----------|----------------------|-------------------------------------|
| NuGet | `ServiceIndex` `OnceCell::get_or_try_init` (`crates/deps-nuget/src/registry.rs`, `service_index`) | The single `https://<feed>/v3/index.json` request, polled by whichever task initializes the cell first (the background fetch) |
| GitHub Actions | per-repository `in_flight` mutex in `get_versions` (`crates/deps-github-actions/src/registry.rs`) | The tags request the background fetch for the same `owner/repo` holds the lock for |

While the background fetch holds the request, the hover's attempt sends nothing, its ledger stays
`UNTOUCHED`, and every ending (elapse, cancel, error) is `Inconclusive`. The breaker therefore never
accumulates the two pieces of slow evidence it needs, and every hover on a not-yet-memoized package pays the
full 10 s budget again. Four such hovers occupy all `tower-lsp-server` dispatch slots, which is the original
spec 082 symptom.

> [!bug] Live reproduction (debug build of HEAD `3204da4b3`)
> Harness: `.local/testing/ci105/s7_breaker_sweep.py <eco>` (uses `.local/testing/fetch_gate/h.py`; env
> `LT_SCRATCH` points to a scratch dir with `fx/` and `logs/`, `BIN` to `target/debug/deps-lsp`).
> 1. `HTTPS_PROXY=http://10.255.255.1:3128` (dead proxy, connect black hole); init options
>    `{"registries":{"workspace_registries":"all"},"cache":{"fetch_timeout_secs":60}}`.
> 2. Open a manifest with three dependencies (GHA: `.github/workflows/ci.yml` with `actions/checkout@v3`,
>    `actions/setup-node@v3`, `actions/cache@v3`; NuGet: `App.csproj` with Newtonsoft.Json, Serilog, Polly).
> 3. t = 0.5 s: hover dependencies A and B. t = 6.0 s: `$/cancelRequest` for both (outstanding 5.6 s, more
>    than half of the 10 s budget). t = 6.1 s: hover dependency C.
>
> | Ecosystems | Hover C | Log |
> |------------|---------|-----|
> | cargo, npm, pypi, go, bundler, dart, maven, composer, gradle, swift, gitlab, deno | 0.0 s (0.4 s where the deps.dev decoration times out) | `interactive registry await skipped ... reason="registry endpoint circuit open"` |
> | gha | **10.0 s** | `interactive registry lookup timed out package=actions/cache context="hover" lookup="version list" timeout_secs=10`; no circuit-open line |
> | nuget | **10.0 s** | timeouts logged for the decoration (5 s) and the version list (10 s) |
>
> Bisect: the same harness on `394cb8797` (#1852) gives C = 0.0 s with `registry endpoint circuit open` for
> gha (0.0 s) and nuget (0.4 s). Only #1858 changed this.
>
> Also reproduced with a dead NuGet feed (`NuGet.Config` with `<clear/><add key="dead"
> value="https://203.0.113.7/v3/index.json"/>`, script `.local/testing/fetch_gate/s2a.py`): hovers on
> Newtonsoft.Json and Serilog take 10 s each, then a hover on a newly added Polly also takes 10.01 s (0.01 s
> with the circuit open on the pre-#1851 baseline).
>
> Control: Cargo against a black-hole `registry-index` (`.local/testing/fetch_gate/s1.py 6 open`) still opens
> correctly, because there the interactive attempt sends its own request.

> [!warning] Root cause is a hypothesis
> The shared-wait sites above explain the matrix and the bisect, but this spec has not instrumented the
> ledger to confirm that the hover task records no `note_request()` in these two ecosystems (the request may
> also run in a spawned task or shared future outside the task-local `CONTACT` scope). The first plan task
> must confirm it (see AC-6). The requirements below hold under either explanation.

### Why it is cross-ecosystem

The breaker lives in `deps-core::lsp_helpers::interactive_fetch` and every ecosystem inherits it. Whether an
ecosystem's interactive attempt is a *sender* or a *waiter* is an accident of how its crate coalesces
requests (`OnceCell`, per-key mutex, a shared future). The set of waiters is therefore not stable: any
ecosystem could add a coalescing layer, and any of the 12 working ecosystems may already coalesce in a
path the live matrix did not hit (for example Cargo or npm when a background fetch for the same package is
in flight at hover time). Per the project rule (`.claude/CLAUDE.md`, "Cross-ecosystem consistency is a
first-class design rule") the fix belongs in `deps-core` and must not rely on each ecosystem crate
remembering to report.

### Goal

For every ecosystem, two distinct packages of one registry endpoint whose hover attempts stalled for at
least half the budget (by elapse or by `$/cancelRequest`) open the endpoint breaker, whether each attempt
sent its own request or waited on a request issued by another task, and a hover on a third package is then
refused immediately for 30 s.

### Out of Scope

- Changing the breaker's thresholds, open duration, probe lease, cap, or `BreakerAdmission` (hover enforces,
  code actions only observe), as defined in spec 082 OQ-7.
- Reverting #1858's intent: an attempt that is served locally (memo, fresh cache entry, local error) must
  still not vouch for or accuse an endpoint (see section 3).
- The Cargo path, which is correct.
- Body-stall tracking after headers (`TODO(#1857)` in `send_noted`).
- The `Decoration` lookup kind, which stays `BreakerEvidence::Ignored`.
- Background fetch timeouts, retry counts and `max_concurrent_fetches`.

## 2. User Stories

### US-001: A hover sweep over a dead NuGet feed or GitHub API stops costing 10 s per package

AS A developer whose NuGet feed or `api.github.com` is unreachable (VPN down, dead proxy)
I WANT the third and later hovers on dependencies of that registry to answer immediately
SO THAT my editor does not freeze while I move the pointer across dependencies.

**Acceptance criteria:**
```
GIVEN a manifest with three dependencies A, B, C on one NuGet feed (or three GitHub Actions)
  AND the endpoint never answers
  AND the background fetches for A, B and C are in flight
WHEN hover on A and B has been outstanding for 5.6 s and both are cancelled
  AND hover on C is sent 0.1 s later
THEN hover on C is answered in under 100 ms with the degraded basic card
  AND the log contains reason="registry endpoint circuit open" for C
```

### US-002: Every ecosystem behaves the same under the same scenario

AS A maintainer
I WANT one test that runs the breaker scenario for every ecosystem
SO THAT a future coalescing layer in any crate cannot silently disable the breaker again.

**Acceptance criteria:**
```
GIVEN the scenario "two distinct stalled hovers, then a third" for each EcosystemId
WHEN the test enumerates EcosystemId with an exhaustive match
THEN adding a 15th ecosystem is a compile error until it is added to the scenario
  AND each ecosystem opens the breaker for both the own-request and the coalesced-onto-background case
```

### US-003: A paginating or healthy-but-slow endpoint does not trip the breaker

AS A developer on a slow but alive registry (large package, paginated tags)
I WANT hover not to be refused because other attempts happened to wait on it
SO THAT a false open does not hide Latest and Recent versions for 30 s.

**Acceptance criteria:**
```
GIVEN a hover attempt coalesced onto a background fetch that paginates
  AND each page arrives well inside half the budget
WHEN the attempt waits longer than half the budget in total
THEN the attempt is Inconclusive or Answered, never Slow
  AND the breaker stays closed
```

## 3. Design Constraint (binding)

#1858 made breaker evidence depend on what happened **on the wire**, not on the caller's error value, for two
reasons that this fix must preserve:

1. **A purely local or memo-served attempt must not vouch for an endpoint.** A lookup answered from a memo,
   a fresh cache entry, or a locally raised error (policy block, rate-limit short-circuit, configuration,
   parse) never touched the endpoint, so it is not an `Answered`.
2. **A paginating fetch that keeps receiving pages must not open the breaker.** The stall clock restarts at
   each response, so a fetch whose requests keep being answered is unstalled however long it runs in total.

The corollary for this spec: a **coalesced** attempt may be evidence about an endpoint only through a wire
request that is actually outstanding on that endpoint during the attempt's own wait. Waiting on a lock, a
`OnceCell` or a shared future that is held for any other reason (local parsing, a held-but-idle guard, a
holder blocked on something that is not a request) is not evidence in either direction.

## 4. Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001 | WHEN an interactive attempt ends by elapse, cancel or error AND received no response of its own AND, during its own wait, a wire request issued by another task on the same `(ecosystem, endpoint)` was outstanding with no response for at least half of the lookup kind's budget, measured as busy time (the time at least one request was outstanding) clipped to the attempt's own wait THE SYSTEM SHALL report the attempt as `Slow`, exactly as for an attempt that issued the request itself. Evidence is scoped to the endpoint, not to the request the attempt waits on | must |
| FR-002 | WHEN an interactive attempt waits on another task's request AND a response to that request arrives during the wait THE SYSTEM SHALL clear the shared pending state for that attempt as a response clears it for a sender, so a paginating fetch is not `Slow` | must |
| FR-003 | WHEN an interactive attempt waits on a lock, cell or shared future that is not backed by an outstanding wire request AND no request on the same `(ecosystem, endpoint)` is outstanding with no response for at least half of the lookup kind's budget during the attempt's wait THE SYSTEM SHALL report it as `Inconclusive` (it neither accuses nor vouches); while such a request is outstanding, FR-001 applies instead | must |
| FR-004 | WHEN an interactive attempt is served from a memo, a fresh cache entry or a local error THE SYSTEM SHALL keep reporting it as `Inconclusive` (not `Answered`) | must |
| FR-005 | THE SYSTEM SHALL implement the coalesced-attempt evidence once in `deps-core` so that no ecosystem crate must call the contact hooks itself for its coalescing layer to count, and SHALL NOT add per-ecosystem copies | must |
| FR-006 | WHEN two distinct packages of one endpoint each produce `Slow` evidence from coalescing onto the same shared request (the NuGet service index) THE SYSTEM SHALL count them as two distinct slow packages and open the breaker | must |
| FR-007 | WHEN the breaker is open for an endpoint THE SYSTEM SHALL refuse a hover version-list await on a not-yet-memoized package of that endpoint without polling, for every ecosystem, whether or not a background fetch for that URL is in flight | must |
| FR-008 | WHEN a half-open probe attempt is coalesced onto another task's request THE SYSTEM SHALL apply the same evidence rules as for any attempt (a stalled wait re-arms the breaker; an inconclusive one releases the probe as today) | should |
| FR-009 | THE SYSTEM SHALL leave `Decoration` lookups ignored for breaker evidence | must |
| FR-010 | THE SYSTEM SHALL keep every existing `evidence()` outcome for an attempt that issues its own request unchanged (Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Composer, Gradle, Swift, GitLab CI, Deno), with one amendment: `Contact.stall` is busy time (a `Duration`, zero for none) instead of the age of the oldest request since the last response, so a request that failed fast no longer leaves a stall that keeps growing while the attempt idles. A slow failed request still reads as `Slow`; a fast transport error followed by an idle holder accumulates nothing (the section 7 row now holds literally) | must |

## 5. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Latency | With the breaker open, hover on a third package of a dead NuGet or GitHub endpoint SHALL answer in under 100 ms (observed 10.0 s) |
| NFR-002 | Responsiveness | Four concurrent hovers on stalled NuGet/GHA packages beyond the first two SHALL NOT occupy all dispatch slots for 10 s |
| NFR-003 | Type safety | Any new state (shared pending request, wait kind) SHALL be a closed enum or newtype, not a `bool`/`Option<Duration>` pair with an implicit meaning, with no `#[non_exhaustive]` and no catch-all `_ =>` arms |
| NFR-004 | Testability | Tests SHALL use `tokio::time::pause` / `start_paused`, not wall-clock bounds ([[081-wall-clock-test-assertions/spec|spec 081]]) |
| NFR-005 | Security | No new outbound requests, no URL or error text stored in breaker state; evidence remains URL-free (spec 082 FR-010) |
| NFR-006 | Hot path | No lock held across an await on the evidence path; no additional allocation per attempt beyond the ledger |
| NFR-007 | Consistency | The consistency test (AC-2) SHALL enumerate `EcosystemId` exhaustively so a new ecosystem forces a decision |

## 6. Acceptance Scenarios

All use paused time. "Stalled" means no response for at least `budget / 2` (5 s for a version list).

| ID | Scenario | Expected |
|----|----------|----------|
| AC-1 | **Own request** (control). For each ecosystem: hover A and B each issue their own request that never answers; cancel both after 5.6 s; hover C | Breaker opens; C is refused without polling (log reason `registry endpoint circuit open`) |
| AC-2 | **Coalesced onto a background fetch**. For each ecosystem: a background fetch for A, B and C is in flight with a request on the wire that never answers; hover A and B join at 0.5 s and are cancelled at 6.0 s; hover C at 6.1 s | Breaker opens after A and B; C is refused without polling. Failing today for NuGet and GitHub Actions |
| AC-3 | **Shared single request** (NuGet shape). One service-index request is shared by A, B and C; hovers on A and B wait on it | A and B count as two distinct slow packages (FR-006); C refused |
| AC-4 | **Paginating background fetch** (GitHub Actions shape). The background fetch receives a page every 1 s for 12 s; hover A is coalesced onto it for 11 s and then served | Not `Slow`; breaker stays closed; a later hover on B is not refused |
| AC-5 | **Local contention**. A holder keeps the per-package lock for 8 s with no wire request outstanding; hover A waits and elapses | `Inconclusive`; breaker stays closed |
| AC-6 | **Ledger instrumentation**. In a NuGet and a GHA hover attempt coalesced onto a background fetch, the attempt's own ledger snapshot | Documents (and the fix corrects) that the attempt recorded no request of its own; confirms the root-cause hypothesis |
| AC-7 | **Memo-served attempt**. A hover served from the interactive failure memo | `Inconclusive`; does not reset or open the breaker |
| AC-8 | **Fast coalesced answer**. A hover coalesced onto a background request that answers in 200 ms | Not `Slow`; see OQ-2 for whether it is `Answered` |
| AC-9 | **Probe**. After 30 s, the first hover is coalesced onto a still-stalled background request and elapses | Probe re-arms the breaker (FR-008) |
| AC-10 | **Live matrix**. `.local/testing/ci105/s7_breaker_sweep.py` for all 14 ecosystems against the dead proxy | C answers in under 0.5 s with `registry endpoint circuit open` for every ecosystem, including gha and nuget |
| AC-11 | **Dead NuGet feed regression**. `.local/testing/fetch_gate/s2a.py` | Hover on newly added Polly after two stalled hovers answers in under 100 ms |

## 7. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Background fetch finishes with a fast transport error while a hover waits | The waiter receives the shared result; no stalled request remains, so `Inconclusive` (a fast transport error is not an answer, per breaker policy). Holds because stall is busy time: the closed request stops accumulating |
| The background holder is dropped at its own timeout and the waiter then sends its own request | Busy time stays continuous across the hand-over, so a waiter that joined at 0.5 s and is cancelled at 6.0 s reads 5.5 s and is `Slow` (the holder's 5 s plus the waiter's own 1 s) |
| `Decoration` lookup under a resolved endpoint | Never writes or reads the shared ledger (FR-009); its requests feed only its own attempt ledger |
| Name-completion search whose host differs from the version host (NuGet search, crates.io API, Maven solrsearch) | Not tagged with the endpoint, so it cannot feed the version host's ledger; a search holder dropped at its own timeout is still covered by the takeover rule. Untagged holders (code lens, the untagged fallback search, and a `Decoration` attempt that is the first to initialize a shared cell such as NuGet's service index: it writes only its own ledger, so waiters see nothing until its 5 s budget drops it) give false negatives only |
| Background request answers, then the next page hangs | The stall clock restarts at the next request (FR-002); a hang of at least half the budget after the response is `Slow` |
| Waiter joins a request that has already been outstanding for 59 s and is cancelled 0.1 s later | Not `Slow` by default (the waiter's own wait is below half the budget); see OQ-3 |
| Two ecosystems in one workspace share a registry host | Unchanged: the breaker key is `(ecosystem, endpoint)`; evidence never crosses ecosystems |
| GitHub rate-limit gate tripped | A local short-circuit; `Inconclusive` (FR-004) |
| `invalidate_all` runs during a coalesced wait | The existing generation check discards the evidence |
| Deno hover composing a JSR and an npm request | The wait is evidence for whichever endpoint the request belongs to; the existing endpoint routing is unchanged |
| Background fetch and a hover both time out at 60 s vs 10 s budgets | The hover's 10 s elapse decides evidence; the background's longer timeout does not delay it |
| A stalled request on a different host than the endpoint's (NuGet registration hive) | Not counted: only the endpoint's own pending request is evidence; `Decoration` stays ignored (FR-009) |

## 8. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover C latency in the s7 sweep, gha and nuget | under 0.5 s (was 10.0 s) |
| SC-002 | Ecosystems for which the s7 sweep opens the breaker | 14 of 14 (was 12 of 14) |
| SC-003 | Consistency test (AC-1, AC-2) | passes for every `EcosystemId`; a missing variant is a compile error |
| SC-004 | Existing `interactive_fetch` tests for #1858 (paginating fetch does not open, local errors do not vouch) | pass unchanged |
| SC-005 | False opens in the paginating scenario (AC-4) | 0 |

## 9. Agent Boundaries

### Always (without asking)
- Run `cargo nextest run -p deps-core -E 'test(interactive_fetch)'` and the new consistency test after changes.
- Use paused-time tokio tests.
- Check `deps-core` helpers (`single_flight`, `endpoint_contact`, `cache/fetch.rs`) before writing ecosystem-local code.
- Verify the final behavior with the live harness (`s7_breaker_sweep.py`) for gha and nuget plus at least Cargo and npm, per `.claude/rules/continuous-improvement.md`.

### Ask First
- Changing the `Contact` or `AttemptEvidence` shape in a way that alters `evidence()` for senders. (Approved once for FR-010: `Contact.stall` is busy time. Awaiting the user's sign-off in the PR.)
- Adding any ecosystem-crate dependency on `deps-core::endpoint_contact` internals.
- Altering breaker thresholds, durations or the `Enforce` / `ObserveOnly` split.

### Never
- Let a memo-served, cache-served or locally failed attempt count as `Answered`.
- Make a waiter `Slow` without an outstanding wire request (FR-003).
- Add a per-ecosystem copy of the evidence logic, or a catch-all arm over `EcosystemId`.
- Edit `crates/deps-zed`.

## 10. Resolved Questions

> [!success] Resolved
> - **OQ-1 mechanism**: a ledger shared by every task of one `(ecosystem, endpoint)`, held weakly in a process-wide map. Orchestration code tags the task that sends (`observe_ecosystem`, `observe_endpoint`), the HTTP send sites feed every ledger of the task's scope, and an interactive attempt on a resolved endpoint reads the shared ledger over its own wait. Ecosystem crates need no hook (FR-005).
> - **OQ-2 coalesced vouching**: no. An attempt that received no response of its own is never `Answered`; only its own responses vouch.
> - **OQ-3 stall clock**: the stall is measured over the attempt's own wait, as the shared ledger's busy time between the attempt's start and end marks (restarting from zero at a response), so a late joiner is not `Slow` for a request that was already old.

## 11. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[082-interactive-registry-await-failure-memo/spec|spec 082]] — the breaker (OQ-7), lookup kinds, single-flight
- [[084-unified-registry-trust-rule/spec|spec 084]] — shipped together with #1853/#1854 in the same PR family
- Code: `crates/deps-core/src/endpoint_contact.rs`, `crates/deps-core/src/lsp_helpers/interactive_fetch/{attempt,breaker,key}.rs`, `crates/deps-core/src/cache/fetch.rs`, `crates/deps-nuget/src/registry.rs` (`service_index`), `crates/deps-github-actions/src/registry.rs` (`get_versions`)

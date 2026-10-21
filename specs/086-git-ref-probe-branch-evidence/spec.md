---
aliases:
  - Git-ref probe hook
  - Branch probe for partial tag refs
  - Shared probe infrastructure
tags:
  - sdd
  - spec
  - enhancement
  - cross-ecosystem
  - ecosystem/github-actions
  - ecosystem/gitlab-ci
  - deps-core
  - security
  - priority/p4
created: 2026-10-21
status: specify
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[plan]]"
  - "[[tasks]]"
  - "[[087-commit-lineage-membership-probe/spec|087 Commit lineage and membership probe]]"
  - "[[084-unified-registry-trust-rule/spec|084 Unified registry trust rule]]"
  - "[[085-breaker-evidence-coalesced-attempts/spec|085 Breaker evidence]]"
---

# Feature: Background git-ref probes, branch evidence and `unknown-ref` for partial refs

> [!info] Metadata
> **Author**: sdd (architect design 2026-10-21, critic-reviewed twice)
> **Type / priority**: enhancement, cross-ecosystem, P4
> **Issue**: #1778 (follow-up to #1766). Shared infrastructure here is also consumed by [[087-commit-lineage-membership-probe/spec|spec 087]] (#1725) and by a future spec 088 (#1757, still being redesigned).
> **Branch**: suggested `feat/1778-git-ref-branch-probe`
> **Depends on**: #1873 (`NormalizedName` keys); sequenced after its deps-core work.
> **Phase**: specify, plan, tasks. Open `[NEEDS CLARIFICATION]`: 0.

> [!abstract]
> `unknown-ref` today fires only for full-release refs absent from a complete tag list. Partial or suffixed
> refs (`@v40`, `@v1`, `@v5.x`, `@v3-node20`) are silent because a branch may legitimately carry that name
> (`ruby/setup-ruby@v1`). This spec adds a bounded, rate-budgeted background probe that asks the forge whether
> the ref is a branch. Neither a published tag nor a branch means the ref names nothing, and `unknown-ref`
> fires. It also introduces the reusable probe infrastructure (hook, typed ref, per-host allowance, evidence
> store, trigger function) that specs 087 and 088 build on.

## 1. Overview

### Problem Statement

`UnpublishedRef` (`deps-core/src/lsp_helpers/git_ref.rs`) distinguishes `Release` (reported as unknown) from
`Partial` (never reported). A typo such as `uses: actions/checkout@v40` is therefore invisible, and
`deps-cli check --fail-on unknown-ref` cannot gate it in CI. Diagnostics are synchronous and must stay
network-free, so the answer must come from evidence gathered in the background and read from a store.

Live-checked 2026-10-21: `GET /repos/ruby/setup-ruby/git/ref/heads/v1` returns 200 (a documented branch pin);
`.../heads/v40` returns 404.

### Goals

1. A Partial unpublished tag-shaped ref that is provably neither a published tag nor a branch is reported as
   `unknown-ref`, in the LSP and in the CLI.
2. One shared, secure, rate-budgeted probe infrastructure usable by any ecosystem.
3. No regression of tag-index fetches or core diagnostics through quota exhaustion.

### Out of Scope

> [!danger] Excluded
> - Commit lineage and default-branch membership of SHA pins (spec 087).
> - Swift SCM-to-registry identity lookups (future spec 088 / #1757); this spec only defines the interface it will reuse (section 6).
> - Probing Release-shaped refs (rule already correct) or refs of repositories whose tag index is not `Complete`.
> - A quickfix for `NotABranch` beyond the existing rule (offered only when `release_tag` yields exactly one tag).
> - Persisting evidence across process restarts.

## 2. User Stories

### US-001: Catch a mistyped partial ref
AS A developer writing `uses: actions/checkout@v40`
I WANT an `unknown-ref` diagnostic once the forge confirms no such tag or branch exists
SO THAT a broken workflow is caught before CI runs.

```
GIVEN a workflow with `uses: o/r@v40`, a Complete tag index for o/r without v40, and a branch probe returning 404
WHEN the document is open and the background probe has completed
THEN an unknown-ref diagnostic reads "`v40` is neither a published tag nor a branch of o/r"
```

### US-002: Documented branch pins stay silent
AS A developer using `ruby/setup-ruby@v1`
I WANT no false `unknown-ref`
SO THAT documented moving-branch pins keep working.

```
GIVEN `uses: ruby/setup-ruby@v1`, no tag `v1` listed, and the branch probe returns 200
THEN no unknown-ref diagnostic is published
```

### US-003: CI gate
AS A CI maintainer
I WANT `deps-cli check --fail-on unknown-ref` to fail on `@v40`
SO THAT the pipeline blocks it, and to be told when probes were skipped.

```
GIVEN the fixture above and a token in the environment
WHEN deps-cli check --fail-on unknown-ref runs
THEN exit code 1 and the finding is listed

GIVEN no token and a spent allowance
THEN exit code is unaffected and stderr prints one note: "N ref probes skipped (rate budget/inconclusive); set GITHUB_TOKEN/GITLAB_TOKEN in CI"
```

## 3. Functional Requirements (EARS)

### 3.1 Probe hook and triggers

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE `Ecosystem` trait SHALL provide `background_probes<'a>(&'a self, &'a dyn ParseResult, phase: ProbePhase) -> BoxFuture<'a, ProbeReport>` with a no-op default returning `ProbeEffect::Unchanged`. `enum ProbePhase { PreFetch, PostFetch }` is exhaustive: probes that decide what to fetch (Swift identity memo, spec 088) run in `PreFetch`; probes that need the fetched tag index (GitHub Actions, GitLab CI, this spec and 087) run in `PostFetch` | must |
| FR-002 | THE SYSTEM SHALL define `ProbeReport { effect: ProbeEffect, issued, skipped_over_budget, inconclusive }` and `enum ProbeEffect { Unchanged, Republish, Reparse }`, exhaustive | must |
| FR-003 | WHEN a document is opened, THE SYSTEM SHALL call `spawn_background_probes(state, uri, ecosystem)` after the open path's inline merge | must |
| FR-004 | WHEN a document changes, THE SYSTEM SHALL call `spawn_background_probes` after `merge_registry_fetch_result` | must |
| FR-005 | WHEN a `TagIndexRefreshes` event arrives, THE SYSTEM SHALL call `spawn_background_probes` for every open document referencing that repository (a probe gate needs a `Complete` index that may warm later) | must |
| FR-006 | `spawn_background_probes` SHALL be single-flight per document with coalesce-latest semantics (`ProbeSlot { running, rerun_requested }`): an overlapping trigger sets `rerun_requested` and the running task re-runs once on completion; a running probe is never aborted, so permits already drawn and quota already spent are not wasted | must |
| FR-007 | THE SYSTEM SHALL carry refresh broadcasts as the typed, exhaustive `RefreshEvent { TagIndex(NormalizedName), ProbeEvidence(NormalizedName), ReparseOpenDocuments { generation: u64 } }` (`Ecosystem::tag_index_refreshes` becomes `refresh_events`, `TagIndexRefreshSender` becomes `RefreshSender`; payloads are `NormalizedName`-keyed per #1873). `TagIndex` keeps today's handling (probes, OSV rescan, republish for documents referencing the repository). WHEN a probe returns `Republish`, THE SYSTEM SHALL emit `ProbeEvidence`, whose listener SHALL only republish diagnostics and SHALL NOT re-run probes or OSV re-evaluation (`rescan_osv_if_tag_index_now_warm`). `ReparseOpenDocuments { generation }` is reserved for spec 088 (coalesced re-parse of an ecosystem's open documents, applied at most once per content version and generation) | must |
| FR-008 | WHEN the CLI runs, THE SYSTEM SHALL execute: parse, `PreFetch` probes, at most one re-parse (when a probe returned `Reparse`), registry fetch, `PostFetch` probes, classify. It SHALL skip probes when offline. In the LSP, `PreFetch` runs alongside the open/change fetch and `PostFetch` after `merge_registry_fetch_result` | must |

### 3.2 Branch probe semantics

| ID | Requirement | Priority |
|----|------------|----------|
| FR-009 | THE SYSTEM SHALL probe only a ref classified `UnpublishedRef::Partial` in a repository whose `TagIndex` is populated with `ListCoverage::Complete` (a readable tag list proves the repository is accessible, so a ref 404 is authoritative) | must |
| FR-010 | WHEN the GitHub probe `GET /repos/{o}/{r}/git/ref/heads/{ref}` returns 200, THE SYSTEM SHALL record `BranchEvidence::Exists`; WHEN 404, `BranchEvidence::Absent` | must |
| FR-011 | WHEN the GitLab probe `GET /projects/:id/repository/branches/:enc_ref` returns 200 / 404, THE SYSTEM SHALL record `Exists` / `Absent`. It SHALL run only for `EndpointKind::Tags` indexes (project includes); component pins backed by a Releases index SHALL never be probed (an existing non-release tag could otherwise yield a false `NotABranch`) | must |
| FR-012 | WHEN a response is 403/429, 5xx, a timeout, breaker-open, a `BodyLimit` overflow, or 409 (empty repository), THE SYSTEM SHALL treat the probe as inconclusive and store nothing; the pin stays silent | must |
| FR-013 | THE SYSTEM SHALL add `UnpublishedRef::NotABranch`, `TagIndex::unpublished_tag_ref(written)` followed by `.refine(Option<BranchEvidence>)` mapping `Partial` + `Absent` to `NotABranch`, and `UnknownRefTarget::with_branch_evidence(Option<BranchEvidence>)`. `cap_status` SHALL return `Unresolved` for `NotABranch`; `unknown_ref_diagnostic_for` SHALL report it | must |
| FR-014 | WHEN `NotABranch` applies, THE SYSTEM SHALL publish `unknown-ref` with the message `` `v40` is neither a published tag nor a branch of <repo> ``; the quickfix is offered only when `release_tag` yields exactly one tag | must |
| FR-015 | Release-shaped refs SHALL NOT be probed | must |
| FR-016 | Diagnostics generation SHALL stay synchronous and network-free; it reads `Option<BranchEvidence>` from the evidence store | must |

### 3.3 Typed ref and security

| ID | Requirement | Priority |
|----|------------|----------|
| FR-017 | THE SYSTEM SHALL construct probe refs only through `ProbeRef::parse(&str) -> Option<ProbeRef>` (private field). It SHALL require `is_tag_shaped`, accept only `[A-Za-z0-9._+-]`, at most 255 bytes, no leading `.` or `-`, no trailing `.` or `.lock`, and SHALL reject `/`, `..` (reusing `lsp_helpers::is_dot_segment`), `?`, `#`, `%`, `@{`, whitespace and control characters | must |
| FR-018 | THE SYSTEM SHALL percent-encode the ref as a path segment (path-segment set) in every request URL regardless of FR-017 | must |
| FR-019 | WHEN a written ref fails `ProbeRef::parse` (for example `uses: o/r@1/../../../../user` or `@1?x#y`), THE SYSTEM SHALL issue no request | must |
| FR-020 | Probe requests SHALL use the same trusted-origin fetch path (host policy, token binding, redirect policy) as the tag-index fetch; tokens are never sent to a host other than the repository's forge host | must |

### 3.4 Rate budget and evidence store

| ID | Requirement | Priority |
|----|------------|----------|
| FR-021 | THE SYSTEM SHALL provide one process-wide `ProbeAllowance` per forge host (one per registry for GitHub, next to its `RateLimitGate`; one per host for GitLab), holding `{ bucket: TokenBucket, meter: Arc<QuotaMeter>, gate: Arc<RateLimitGate>, reserve: u32 }` with `try_acquire() -> Option<ProbePermit>` | must |
| FR-022 | `try_acquire` SHALL deny a permit when the gate is tripped, OR `meter.remaining <= reserve`, OR the bucket is empty | must |
| FR-023 | Parameters without a token: reserve 20, capacity 4, refill 6/h. With a token: reserve 500, capacity 32, refill 600/h. For GitLab the choice is made per host from that host's token binding | must |
| FR-Q1 | WHEN a request to a probe-governed host is sent over the network THE SYSTEM SHALL record that response's rate-limit headers into the host's `QuotaMeter` inside the HTTP fetch layer, at the moment the response is received: `X-RateLimit-Remaining`/`X-RateLimit-Reset` (GitHub), `RateLimit-Remaining`/`RateLimit-Reset` (GitLab). This applies to any 2xx, 304 or 4xx response, whether a probe or a tag-index fetch sent the request. The meter is attached through `RequestAuth::with_quota_meter(&Arc<QuotaMeter>)`, next to `with_rate_limit` | must |
| FR-Q2 | THE SYSTEM SHALL NOT update a `QuotaMeter` from a stored cache entry, a fresh-cache hit, or a header value replayed from a previously stored response. `CachedResponse` carries no quota field | must |
| FR-Q3 | WHEN a new reading `(remaining, reset_epoch, observed_at)` arrives THE SYSTEM SHALL keep it only if it is newer than the held reading: a larger `reset_epoch` replaces the held reading; an equal `reset_epoch` keeps `min(remaining)` and the later `observed_at`; a smaller `reset_epoch` is discarded. Once `now >= reset_epoch`, the held reading is treated as absent. A reading whose `reset_epoch` is more than `now + 2 h` is ignored (including `u64::MAX`). `reset_epoch` is a server-clock value compared with the local clock, so local clock skew can expire a reading early (probes fall back to FR-Q4 governance until the next live response) or late (probes are denied slightly longer); both are bounded and self-correct on the next live response, and no `Date`-header correction is attempted | must |
| FR-Q4 | WHILE a host's meter holds no reading (none observed yet, expired, or a self-hosted GitLab without `RateLimit-*` headers) THE SYSTEM SHALL govern probes by the token bucket and the `RateLimitGate` alone | must |
| FR-026 | `GithubTagsClient` SHALL use `get_cached_trusted_origin_response` so tag-index fetches feed the meter with unchanged egress | must |
| FR-027 | Evidence-store hits SHALL draw no permit. WHEN permits are scarce within one cycle the priority SHALL be: 087 lineage, then 087 membership, then 086 branch probes | must |
| FR-028 | THE SYSTEM SHALL provide an evidence store keyed by normalized repository (`NormalizedName`; GitHub Actions and GitLab lowercase) so `Actions/Checkout` and `actions/checkout` probe once. Branch evidence is a bounded LRU of 4096 with a freshness window of 1 hour (the tag index has no TTL); after the window the stored answer is still served and re-verified on the next trigger (open, change, `TagIndex` event); an inconclusive answer never overwrites it; idle documents have no timer; re-confirming a stale answer is not a change (no republish). Branches change, so there is no permanent memo | must |
| FR-029 | Concurrency of probe requests SHALL be at most 4 (`buffer_unordered`). Probes SHALL be single-flight per probe key (`ProbeKey`) across passes and documents: the key is claimed before the permit is drawn and the store is re-checked after the claim, so concurrent passes for one question send one request and spend one permit | must |
| FR-032 | The GitHub branch probe (`fetch_branch_ref`) SHALL fetch with `RevalidationFailure::Fail` and a 256 KiB body cap: a stored 200 followed by 403/404/5xx on revalidation is an error (inconclusive), never a silent reuse | must |

### 3.5 CLI and docs

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | WHEN `--fail-on unknown-ref` is set and `skipped_over_budget + inconclusive > 0`, THE CLI SHALL print exactly one stderr note per run; the exit code is unaffected | must |
| FR-031 | THE SYSTEM SHALL update the `unknown-ref` help text in `deps-cli/src/cli.rs` (currently "a full release") to cover refs that are neither a published tag nor a branch, and the book's GitHub Actions, GitLab CI and CLI pages, including "set `GITHUB_TOKEN`/`GITLAB_TOKEN` in CI" | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Rate budget | In a session with N open workflow files and no token, total probe requests SHALL NOT exceed the bucket capacity (4) plus refill (6/h), and the meter SHALL never be driven at or below the reserve (20) by probes; tag-index fetches remain possible |
| NFR-002 | Isolation | A probe SHALL NOT trip, or be starved by, the tag-index `RateLimitGate`; a tripped gate denies probes, not the reverse |
| NFR-003 | Responsiveness | Handlers and diagnostics SHALL remain non-blocking; probes run only in spawned tasks |
| NFR-004 | Type safety | `ProbeRef`, `BranchEvidence`, `ProbeEffect`, `UnpublishedRef` are exhaustive enums or private-constructor newtypes; no `_ =>` arms; no stringly-typed refs at the probe boundary |
| NFR-005 | Security | No request is built from a ref that failed `ProbeRef::parse`; credentials never leave the forge host; inconclusive answers never produce a diagnostic |
| NFR-006 | Bounded memory | Evidence store LRU bounded at 4096 entries |
| NFR-007 | Observability | `tracing` events for issued, skipped-over-budget and inconclusive probes, with repository and ref redacted per existing rules |

## 5. Typed API sketch (deps-core)

```rust
pub struct ProbeRef(/* private */ String);
impl ProbeRef { pub fn parse(written: &str) -> Option<Self>; pub fn as_path_segment(&self) -> PercentEncoded<'_>; }

pub enum BranchEvidence { Exists, Absent }
pub enum ProbeEffect { Unchanged, Republish, Reparse }
pub enum ProbePhase { PreFetch, PostFetch }
pub enum RefreshEvent { TagIndex(NormalizedName), ProbeEvidence(NormalizedName), ReparseOpenDocuments { generation: u64 } }
pub struct ProbeReport { pub effect: ProbeEffect, pub issued: usize, pub skipped_over_budget: usize, pub inconclusive: usize }

pub struct QuotaReading { pub remaining: u32, pub reset_epoch: u64, pub observed: Instant }
pub struct QuotaMeter { /* newest-reading-per-host */ }
impl QuotaMeter { pub fn observe_live(&self, host: &HostKey, r: QuotaReading); pub fn current(&self, host: &HostKey) -> Option<QuotaReading>; }
pub struct ProbeAllowance { /* bucket, meter, gate, reserve */ }
impl ProbeAllowance { pub fn try_acquire(&self) -> Option<ProbePermit>; }

pub enum UnpublishedRef { Release, Partial, NotABranch }
```

`observe_live` is `pub(crate)` to the fetch layer and is reached only through `RequestAuth::with_quota_meter`; `CachedResponse` has no quota field and no public API feeds the meter from a cache entry.

## 6. Interface reused by spec 088 (#1757) and spec 087

> [!note] Contract
> Spec 086 owns, and 087 and 088 consume without modification: the `background_probes` hook and `ProbeReport`/`ProbeEffect`;
> `spawn_background_probes` single-flight and its three triggers; `ProbeAllowance`/`QuotaMeter` per host (a registry host
> for Swift identity lookups is a host like any other, with the token-or-not parameters chosen from its binding); the
> evidence-store pattern (bounded LRU, `NormalizedName` keys, only authoritative answers stored); the typed
> `RefreshEvent` (`TagIndex` vs `ProbeEvidence` vs `ReparseOpenDocuments`) and the `ProbePhase` split (Swift warms its memo in
> `PreFetch`; CLI flow in FR-008). Spec 088 adds `ProbeEffect::Reparse` consumers (Swift re-parse) and its own
> evidence type; `ProbeRef` is not used by 088 (it has `ScmLookupUrl`).

## 7. Edge Cases

| Scenario | Expected |
|----------|----------|
| `@v1` is a branch | Exists, silent |
| `@v40` neither | `NotABranch`, `unknown-ref` |
| `@1/../../../../user`, `@1?x#y`, `@a%2Fb` | No request, silent (probe skipped, not inconclusive-counted as budget) |
| Repository 404 on the tag list | Index not Complete, no probe |
| Rate limit reached mid-cycle | Remaining pins silent, `skipped_over_budget` counted |
| Same repo in many documents | One probe per (normalized repo, ref) per freshness window |
| Offline | No probes; CLI skips |
| Self-hosted GitLab without RateLimit headers | Bucket alone governs |
| Evidence lands after diagnostics published | `Republish` event with kind `ProbeEvidence`; no probe re-run |

## 8. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live `ruby/setup-ruby@v1` / `@v40` | Exists silent / Absent reported |
| SC-002 | Traversal fixtures | Mock asserts zero hits |
| SC-003 | 50 open documents, no token | Probe requests <= 4 within the first hour window |
| SC-004 | Stale-quota replay test | A cache hit carrying old `remaining = 55` after a live `remaining = 3` leaves the meter at 3 |
| SC-005 | CLI `--fail-on unknown-ref` on `@v40` | Exit 1 with token; one stderr note, exit unchanged, without |

## 9. Test Plan

- Unit: `ProbeRef::parse` table (accept/reject, 255 boundary, dot/lock rules); `refine` matrix; `cap_status`; `QuotaMeter` ordering (reset_epoch, observation time, min remaining); `try_acquire` for gate/reserve/bucket.
- mockito: 200, 404, 403-rate, 429, 409-empty, 5xx, BodyLimit overflow; zero-hit assertions for rejected refs; GitLab Tags vs Releases index.
- Integration: open path, change path and `TagIndexRefreshes` each trigger exactly one probe; overlapping calls single-flight; `ProbeEvidence` event does not re-run probes.
- CLI: `--fail-on unknown-ref` with `@v40`, stderr note.
- Live: SC-001. Record in `.local/testing/{coverage,regressions}.md` and the GitHub Actions and GitLab CI playbooks.

## 10. Agent Boundaries

**Always**: reuse `is_dot_segment`, trusted-origin fetch, `HttpCache`; keep enums exhaustive; update CHANGELOG (one line, PR link), book, testing KB.
**Ask first**: changing budget parameters; adding any new egress host; changing `RateLimitGate` semantics.
**Never**: build a request URL from an unparsed ref; feed the meter from cache entries; block a handler on a probe; edit `crates/deps-zed`.

## 11. Decisions and Rejected Alternatives

- Probing in the diagnostics path: rejected (synchronous, network-free).
- `/branches/{b}`: rejected (about 5 KB vs 300 B).
- Per-document budgets: rejected; quota and breaker are process-wide.
- `CachedResponse.quota`: rejected; replays stale quota on cache hits and 304s.
- Changing `DiagnosticKind`: none needed; `UnknownRef` exists.

## 12. See Also

[[MOC-specs]] · [[087-commit-lineage-membership-probe/spec|087]] · issues #1778, #1766, #1873 · [[plan]] · [[tasks]]

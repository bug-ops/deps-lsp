---
tags:
  - sdd
  - plan
  - deps-core
  - cross-ecosystem
created: 2026-10-21
status: plan
related:
  - "[[spec]]"
  - "[[tasks]]"
  - "[[MOC-specs]]"
  - "[[087-commit-lineage-membership-probe/plan|087 plan]]"
---

# Plan: git-ref probe infrastructure and branch evidence (#1778)

## 1. Architecture

```
open / change / TagIndexRefreshes(TagIndex)
        |
 deps-lsp spawn_background_probes(state, uri, ecosystem)   [single-flight per document]
        |
 Ecosystem::background_probes(parse_result) -> ProbeReport   (default no-op)
        |   github-actions / gitlab-ci:
        |     for each Partial unpublished ref, Complete index, ProbeRef::parse ok:
        |        evidence store hit? -> done (no permit)
        |        ProbeAllowance::try_acquire -> fetch (trusted origin, live quota feeds QuotaMeter)
        |        200/404 -> BranchEvidence stored; else inconclusive
        v
 effect Republish -> RefreshSender event RefreshEvent::ProbeEvidence -> republish only
 diagnostics (sync) read Option<BranchEvidence> from the evidence store
CLI: parse -> PreFetch -> at most one reparse -> fetch -> PostFetch -> classify (deps-engine run_background_probes); stderr note
```

## 2. Components

| Crate | Item |
|-------|------|
| deps-core `rate_limit.rs` | `TokenBucket`, `QuotaMeter`, `ProbeAllowance`, `ProbePermit` next to `RateLimitGate` |
| deps-core `cache/fetch.rs` | live-response hook: `RequestAuth::with_quota_meter` records `X-RateLimit-*` / `RateLimit-*` from network responses only via `QuotaMeter::observe_live`; never reads `CachedResponse`; `get_cached_trusted_origin_response` path used by `GithubTagsClient` |
| deps-core `lsp_helpers/git_probe.rs` (new) | `ProbeRef`, `BranchEvidence`, evidence store (LRU 4096, TTL = tag-index TTL, `NormalizedName` keys), `ProbeReport`, `ProbeEffect` |
| deps-core `lsp_helpers/git_ref.rs` | `UnpublishedRef::NotABranch`, `unpublished_tag_ref().refine()`, `UnknownRefTarget::with_branch_evidence`, message text; `cap_status`/`unknown_ref_diagnostic_for` arms |
| deps-core `ecosystem.rs` | `background_probes` default no-op (sealed trait unchanged) |
| deps-core `tag_index_refresh.rs` | typed `RefreshEvent { TagIndex, ProbeEvidence, ReparseOpenDocuments }` (rename of `TagIndexRefreshSender` to `RefreshSender`, `NormalizedName` payloads) |
| deps-github-actions `registry.rs` | branch probe client, allowance owned beside the gate |
| deps-gitlab-ci | branch probe via `fetch_pinned`; Tags-index gate; per-host allowance |
| deps-engine `probe` module | `run_background_probes` shared by CLI and LSP |
| deps-lsp | `spawn_background_probes` (3 callers: open path `lifecycle.rs`, change path, `tag_refresh.rs`); `ProbeEvidence` listener republishes only |
| deps-cli | await probes, stderr note, help text, `--offline` skip |

## 3. Design notes

- Single-flight: a per-document `AbortHandle`/in-flight guard; overlapping triggers coalesce (skip if running, mark dirty to re-run once).
- Quota meter ordering: `(reset_epoch, observed)` newest wins; within the same `reset_epoch` keep min `remaining`. No reading means bucket-only.
- Reserve guard evaluated at acquire time against `meter.current(host)`.
- Evidence keyed `(NormalizedName(repo), ProbeRef)`; only 200/404 stored.
- Request URL: `{api}/repos/{o}/{r}/git/ref/heads/{pct_encode_segment(ref)}`; GitLab `branches/{enc_ref}` with project id encoding as in `fetch_pinned`.
- Priority order inside a cycle is enforced by the engine probe module ordering work items (lineage, membership, branch) before acquiring permits.

## 4. Security

ProbeRef charset prevents path traversal on a token-bearing request (first use of a written ref in a URL path); host and
redirect policy are inherited from the trusted-origin path; tokens stripped on cross-host redirects as today.

## 5. Constitution check

Exhaustive enums, newtypes with private constructors, typed errors, `///` docs with doctests, no `unsafe`, `tracing`.

## 6. Rollout and risks

Single PR after #1873 deps-core work merges; Phase 0 (deps-core) lands first, per-crate work in parallel (see [[tasks]]).
Risks: unauthenticated 60 req/h (mitigated by bucket 4 + 6/h, reserve 20, silence on inconclusive); a documented branch pin
probes once per TTL. Docs: book GitHub Actions, GitLab CI, CLI; CHANGELOG `### Added` plus `### Changed` (help text).

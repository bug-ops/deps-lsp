---
aliases:
  - Non-release commit pins
  - Commit lineage and membership probe
  - compare API for SHA pins
tags:
  - sdd
  - spec
  - enhancement
  - ecosystem/github-actions
  - ecosystem/gitlab-ci
  - deps-core
  - priority/p4
created: 2026-10-21
status: specify
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
  - "[[plan]]"
  - "[[tasks]]"
  - "[[086-git-ref-probe-branch-evidence/spec|086 Git-ref probe infrastructure]]"
---

# Feature: Do not report a SHA pin newer than the latest release as outdated (commit lineage and default-branch membership)

> [!info] Metadata
> **Author**: sdd (architect design 2026-10-21, critic-reviewed twice)
> **Type / priority**: enhancement, P4
> **Issue**: #1725 (follow-up to #1720 / PR #1721)
> **Branch**: suggested `feat/1725-commit-lineage-probe`
> **Depends on**: [[086-git-ref-probe-branch-evidence/spec|spec 086]] (hook, `ProbeAllowance`/`QuotaMeter`, evidence store, triggers, event kinds) and #1873 (`NormalizedName` keys).
> **Phase**: specify, plan, tasks. Open `[NEEDS CLARIFICATION]`: 0.

> [!abstract]
> A commentless SHA pin `P` that no tag names (`CommitRewrite::NoReleaseTag`) is reported outdated and
> update-all re-pins it to the latest release, effectively a downgrade when `P` is, say, a `main` HEAD newer
> than the latest release. This spec adds two forge-verified proofs, lineage ("`P` descends from the latest
> release commit") and membership ("`P` is reachable from the default branch"), via the compare/merge-base
> APIs. Only when both hold is the pin up to date. Everything else keeps today's behavior.

## 1. Overview

### Problem Statement

`uses: actions/checkout@<sha-of-main-head>` with no version comment resolves to no release tag. Today the status is
outdated and the update-all edit set rewrites it to the latest release. The current behavior is documented in the
mdBook GitHub Actions page ("effectively a downgrade").

Live-checked 2026-10-21: `compare/A...B?per_page=1&page=2` returns `status`, `ahead_by`, `behind_by` with `files`
empty (12.7 KB vs 222 KB on page 1); `compare/HEAD...{x}` works (9.5 KB); `actions/checkout` `v4.0.0` reads
`diverged` against HEAD; GitLab `repository/merge_base?refs[]=HEAD&refs[]=v1.40.0` works unauthenticated (1.2 KB) and
its id equals the tag's commit.

### Why two proofs

`ahead` alone does not prove the commit belongs to the project: a fork-network commit (an "imposter commit") compares
as `ahead` of a release commit. Reachability from the default-branch HEAD does prove membership. Both are required.

### Goals

1. No false outdated report and no downgrade for a commit proven to descend from the latest release and to be on the default branch.
2. Hover tells the user why: `commit N ahead of latest release <tag>`.
3. Conservative: any unproven, diverged, inconclusive or over-budget case keeps today's behavior.

### Out of Scope

> [!danger] Excluded
> - Pins on release branches (`diverged` from HEAD): remain at today's behavior.
> - Page-1 compare (about 1 MB), GraphQL `Ref.compare` (token-only), `commits/{sha}` (returns fork-network commits).
> - Branch-existence probing (spec 086); Swift identity lookups (spec 088).
> - Any change to commented SHA pins (those use the tag-comment path).

## 2. User Stories

### US-001: Main-branch pin is not a downgrade
AS A developer pinning to a `main` commit newer than the last release
I WANT no outdated diagnostic and no update-all rewrite
SO THAT my intentionally-newer pin is not downgraded.

```
GIVEN `uses: o/r@<P>` with P unnamed by any tag, latest release commit S_L,
  compare(S_L...P) status "ahead", compare(HEAD...P) status "behind" or "identical"
WHEN the background probes complete
THEN the pin is UpToDate, update-all excludes it, hover shows "commit N ahead of latest release <tag>"
```

### US-002: Unproven pins behave as before
```
GIVEN P with compare(HEAD...P) status "diverged" (release-branch or fork-only commit)
THEN the pin is reported exactly as today (outdated, rewrite to latest release)
```

## 3. Functional Requirements (EARS)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a SHA pin has `CommitRewrite::NoReleaseTag`, the repository's tag index is `Complete`, and a latest release commit `S_L` is known, THE SYSTEM SHALL gather lineage then membership evidence through the 086 `background_probes` hook | must |
| FR-002 | Lineage on GitHub: `GET /repos/{o}/{r}/compare/{S_L}...{P}?per_page=1&page=2`; status `ahead` yields `CommitLineage::AheadOfLatest { ahead_by }`, any other status yields `NotAhead`. Lineage on GitLab: `repository/merge_base?refs[]={S_L}&refs[]={P}` with `id == S_L` and `P != S_L` yields `AheadOfLatest` (no count: `ahead_by` is unavailable and hover omits N) | must |
| FR-003 | Membership on GitHub: `GET /repos/{o}/{r}/compare/HEAD...{P}?per_page=1&page=2`; status `behind` or `identical` yields `DefaultBranchMembership::Reachable`, `ahead`, `diverged` or anything else yields `NotProven`. On GitLab: `merge_base(HEAD, P) == P` yields `Reachable` | must |
| FR-004 | WHEN lineage is `AheadOfLatest` AND membership is `Reachable`, THE SYSTEM SHALL set the pin's status to `UpToDate`, exclude it from the update quickfix and update-all, and add the hover line `commit N ahead of latest release <tag>` | must |
| FR-005 | WHEN either proof is missing, `NotAhead`/`NotProven`, inconclusive or over budget, THE SYSTEM SHALL keep today's behavior unchanged | must |
| FR-006 | Lineage evidence (both SHAs fixed) SHALL be memoized in a bounded LRU of 4096 entries with no TTL, keyed by (normalized repository, `S_L`, `P`). Membership (HEAD moves) SHALL be a bounded LRU of 4096 with TTL equal to the tag-index TTL, never memoized forever. Keys use `NormalizedName` (GitHub Actions and GitLab lowercase) | must |
| FR-007 | A new latest release changes `S_L`, so the lineage key changes and the proof is re-evaluated; a pin proven ahead of an older release is not assumed ahead of the new one | must |
| FR-008 | Compare requests SHALL use a dedicated `BodyLimit` of 256 KiB; overflow SHALL be inconclusive and store nothing | must |
| FR-009 | Only authoritative answers are stored; 403/429, 5xx, timeout, breaker-open, 404 (unknown SHA or inaccessible repository) and overflow are inconclusive | must |
| FR-010 | Both SHAs placed in URLs SHALL be `CommitSha` values (hex, validated, existing type); `HEAD` is the fixed literal. No written text reaches the URL path | must |
| FR-011 | Probes SHALL draw permits from the 086 per-host `ProbeAllowance`; evidence-store hits draw none; priority within a cycle is lineage, then membership, then 086 branch probes. Membership is requested only after lineage is `AheadOfLatest` (a `NotAhead` pin needs no second request) | must |
| FR-012 | Triggers and event handling SHALL be those of spec 086 (open, change, `TagIndexRefreshes`; single-flight; `ProbeEvidence` event republishes only). These probes run in `ProbePhase::PostFetch` (they need the fetched tag index). New evidence SHALL return `ProbeEffect::Republish` (event `RefreshEvent::ProbeEvidence`) | must |
| FR-013 | Offline CLI runs SHALL skip these probes; CLI classification SHALL run after the probes complete so `check` and `update` agree with the LSP | must |
| FR-014 | THE SYSTEM SHALL replace the book's "effectively a downgrade" paragraph and the #1725 trade-off note on the GitHub Actions page and add GitLab CI page parity | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Rate budget | Shares the 086 budget; with no token a document set of any size SHALL NOT drive the meter to the reserve (20) |
| NFR-002 | Payload | Compare responses are at most 256 KiB; `page=2` is mandatory (removes `files`) |
| NFR-003 | Security | The compare endpoints use the trusted-origin fetch path; tokens never reach another host; imposter commits cannot satisfy membership |
| NFR-004 | Type safety | `CommitLineage` and `DefaultBranchMembership` are exhaustive enums; the combined decision is one function over both, with no `_ =>` arm |
| NFR-005 | Non-blocking | Diagnostics read the stores synchronously; all network work is spawned |
| NFR-006 | Bounded memory | Two LRUs of 4096 |

## 5. Typed API sketch

```rust
pub enum CommitLineage { AheadOfLatest { ahead_by: Option<u32> }, NotAhead }
pub enum DefaultBranchMembership { Reachable, NotProven }

pub struct CommitEvidence { pub lineage: Option<CommitLineage>, pub membership: Option<DefaultBranchMembership> }
impl CommitEvidence { pub fn proven_ahead(&self) -> Option<AheadProof> } // Some only for AheadOfLatest + Reachable
```

`AheadProof { ahead_by: Option<u32>, latest_tag: String }` feeds the status override, the update-all exclusion and the hover line.

## 6. Edge Cases

| Scenario | Expected |
|----------|----------|
| P is the latest release commit | Existing tag path; no probe |
| P equals `S_L` lineage `identical` | `NotAhead`; not applicable (a tagged commit is not `NoReleaseTag`) |
| P on `main`, ahead of latest | UpToDate with hover line |
| P fork-only (imposter) | lineage `ahead`, membership `NotProven`: today's behavior |
| P on a release branch (`v4.0.0` vs HEAD `diverged`) | `NotProven`: today's behavior |
| Compare response over 256 KiB | Inconclusive |
| Budget exhausted | Today's behavior; counted in `skipped_over_budget` |
| New release published | `S_L` changes; lineage re-probed |
| Force-pushed default branch | Membership TTL expiry re-evaluates |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live: main-branch HEAD SHA of `actions/checkout` | UpToDate, hover line present, absent from update-all edits |
| SC-002 | Live: `actions/checkout` `v4.0.0` commit SHA as a commentless pin | `NotProven`, today's behavior |
| SC-003 | LRU memo hit | Issues no request |
| SC-004 | Update-all edit set | Excludes a verified-ahead pin |

## 8. Test Plan

- mockito: compare `ahead`, `behind`, `diverged`, `identical`, overflow, 403/429, 404; GitLab merge-base cases.
- Unit: `proven_ahead` truth table; cache key changes with `S_L`; membership TTL expiry vs lineage no-TTL; case-insensitive repo key shares one entry.
- Integration: update-all excludes the proven pin; hover line; CLI `check` agrees after awaiting probes.
- Live: SC-001, SC-002; record in `.local/testing`.

## 9. Agent Boundaries

**Always**: reuse 086 infrastructure; keep enums exhaustive; CHANGELOG, book (GitHub Actions and GitLab CI pages), testing KB.
**Ask first**: relaxing the two-proof rule; raising the 256 KiB limit.
**Never**: treat `ahead` alone as proof; memoize membership forever; use `commits/{sha}` as evidence; edit `crates/deps-zed`.

## 10. See Also

[[MOC-specs]] · [[086-git-ref-probe-branch-evidence/spec|086]] · issues #1725, #1720 · [[plan]] · [[tasks]]

---
tags:
  - sdd
  - plan
  - ecosystem/github-actions
  - ecosystem/gitlab-ci
created: 2026-10-21
status: plan
related:
  - "[[spec]]"
  - "[[tasks]]"
  - "[[MOC-specs]]"
  - "[[086-git-ref-probe-branch-evidence/plan|086 plan]]"
---

# Plan: commit lineage and membership (#1725)

## 1. Architecture

Uses the 086 pipeline unchanged: `spawn_background_probes` -> `Ecosystem::background_probes` -> allowance -> fetch -> store -> `Republish` (`ProbeEvidence`).

```
SHA pin P, CommitRewrite::NoReleaseTag, Complete index, S_L = latest release commit
  lineage store hit? else permit -> compare(S_L...P)?per_page=1&page=2  (BodyLimit 256 KiB)
  if AheadOfLatest: membership store hit? else permit -> compare(HEAD...P)?per_page=1&page=2
  CommitEvidence { lineage, membership }.proven_ahead() -> AheadProof
sync diagnostics/hover/code actions read the stores:
  AheadProof -> status UpToDate, update-all exclusion, hover line
```

## 2. Components

| Crate | Item |
|-------|------|
| deps-core `lsp_helpers/git_probe.rs` | `CommitLineage`, `DefaultBranchMembership`, `CommitEvidence`, `AheadProof`; lineage LRU (no TTL) and membership LRU (1 h freshness window) |
| deps-core `lsp_helpers/git_ref.rs` | status override hook next to `commit_rewrite_to`; update-all exclusion; hover line |
| deps-github-actions | compare client (`page=2`, 256 KiB limit), status mapping |
| deps-gitlab-ci | `merge_base` client (`refs[]=`), mapping |
| deps-engine `probe` module | ordering lineage -> membership -> branch; permit priority |
| docs | book GitHub Actions page (replace downgrade paragraph and trade-off note), GitLab CI parity, CHANGELOG |

## 3. Design notes

- Compare status mapping is a pure function over a typed `CompareStatus { Ahead, Behind, Diverged, Identical }` (exhaustive; unknown string is inconclusive, not a variant).
- Lineage key `(NormalizedName, CommitSha S_L, CommitSha P)`; membership key `(NormalizedName, CommitSha P)` with a 1 h freshness window.
- Membership request is conditional on lineage so a `NotAhead` pin costs one request.
- `ahead_by` is carried only for GitHub; GitLab hover omits the count.

## 4. Security and constitution

Only validated `CommitSha` values and the literal `HEAD` enter URLs. Trusted-origin fetch inherited. Exhaustive enums; no `_ =>`.

## 5. Risks

Rate budget shared with 086 (priority favors lineage). Release-branch pins are conservative (not proven). A force-push is covered by the membership freshness window.

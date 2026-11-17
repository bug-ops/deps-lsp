---
aliases:
  - Cross-Major Sibling Scan
  - Tag Pins Scan Whole-Commit Release Tags
tags:
  - sdd
  - spec
  - osv
  - github-actions
  - security
  - cross-ecosystem
created: 2026-11-17
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Tag pins and update candidates are scanned against every release tag on their commit

> [!info] Metadata
> **Author**: team-develop session
> **Branch**: `feat/1964-vulnerability-suppress-design` (issue #1719)
> **Type**: enhancement/security, P2
> **Decision**: user decisions L2 (keep `SiblingScope::SameMajor`) and L3 (candidates and update targets are included)

> [!bug] Summary
> A SHA pin is OSV-scanned against every release tag on its commit (#1709). A tag pin was only scanned against the tags of its own major line, so `uses: owner/repo@v4.8.0` stayed clean while `v5.0.0` on the very same commit had an advisory. The code is identical, so the dependency is affected in both spellings.

## 1. Overview

### Problem Statement

A repository can publish two release names for one commit across majors (observed in the live check below: `codecov/codecov-action` `v6.0.2` and `v7.0.0`, `golangci/golangci-lint-action` `v3.7.1` and `v4.0.0`). An advisory fixed in `7.0.1` and affecting `7.0.0` affects the commit, hence also a workflow that pins `@v6.0.2` or the SHA of that commit.

### Goal

For every tag pin, floating tag pin and update candidate, the scan covers the same release names as for a SHA pin of the same commit.

### Out of Scope

- GitLab CI: it shares `resolve_git_pin` but has no OSV coordinate, so its outcome cannot change.
- Removing `SiblingScope::SameMajor`: it stays as a documented variant with no production caller (L2).
- Prerelease and non-semver tags: they are never siblings, as before.

## 2. Requirements (EARS)

- **FR-001** When a tag pin names an indexed release tag, the system shall scan that tag and every other release tag on its commit, of any major (`SiblingScope::WholeCommit`).
- **FR-002** When the pin is a full-release floating tag (`@v4` where `v4.2.2` shares the commit), the siblings shall be the releases of the primary's own specificity class on the whole commit; the primary is still chosen only among tags that extend the written one (#1684: the primary is never an unrelated release).
- **FR-003** When a floating tag has no full release of its own on its commit (`@v4` on a commit carrying only `v4` and `v5.0.0`), the pin shall be scanned through the full releases on that commit. The highest one is the scan stand-in primary, the others are siblings, and every advisory is attributed to the release tag it matched ("via v5.0.0"). The displayed version stays `v4`. This is the single exception to the specificity-class rule of `SiblingTags::from_candidates`; it is built by `SiblingTags::commit_full_releases`.
- **FR-004** When no full release exists on the commit, the pin shall keep `SkipReason::ResolvedTagNotFullVersion` (a lone `v4`).
- **FR-005** An update candidate shall be vetted against every release tag on its commit (`CandidateTagSource::tag_pin` is `WholeCommit`); a candidate sharing a commit with a vulnerable cross-major release shall never be proposed or written.
- **FR-006** When the tag list is truncated, sibling coverage shall fail closed as `SkipReason::SiblingTagsUnknown` on a clean answer, exactly as for a SHA pin.

## 3. Behavior changes

| Pin | Before | After |
|---|---|---|
| `@v4.8.0`, commit also tagged `v5.0.0` | scanned as `v4.8.0` only | scanned as `v4.8.0` plus `v5.0.0` |
| `@v4`, commit tagged `v4`, `v5.0.0` | skipped, `ResolvedTagNotFullVersion` | scanned: `Clean`, or `Vulnerable` through `v5.0.0` |
| `@v4`, complete list, commit tagged only `v4` | skipped | unchanged |
| `@v4`, truncated list | skipped | `Skipped(SiblingTagsUnknown)` |

`ResolvedTagNotFullVersion` has `coverage_gap() == None`, so `--fail-on unchecked` never counted it. The real change for the floating pin is *skipped to scanned*: `--fail-on vulnerable` can newly fail, and the truncated-list case is now a counted incomplete scan, as for a SHA pin.

### Fix targets

A pin matched only through a cross-major sibling gets that sibling's fix as the target, as a SHA pin already does: `@v4.8.0` matched through `v5.0.0` (fixed in `5.0.1`) proposes `v5.0.1` in code actions, `deps-cli update --security-only` and the update plan. A fix at or below the scanned primary is never an upgrade target (#1709 M2).

## 4. Live verification (2026-11-17)

The tag lists (up to 100 newest tags) of 25 widely used actions were grouped by commit. Two repositories carry full releases of different majors on one commit:

- `codecov/codecov-action`: `v6.0.2`, `v7.0.0`
- `golangci/golangci-lint-action`: `v3.7.1`, `v4.0.0`

The other 23 (`actions/checkout`, `setup-*`, `cache`, `upload/download-artifact`, `docker/*`, `github/codeql-action`, `ruby/setup-ruby`, and more) have none, so the change is silent for them. Both hits are genuine same-commit releases: a SHA pin on those commits is scanned against both names today, so no finding appears that a SHA pin would not also produce. No false positive was found.

## 5. Tests

- `crates/deps-core/tests/cross_major_siblings.rs`: `TagIndex` and `CandidateTagSource` level (exact, floating, candidates, truncated).
- `crates/deps-cli/tests/cross_major_siblings.rs`: `check`, `--fail-on` and `update` through mockito GitHub and OSV servers (F1-F4, U1-U2, R3).

## 6. Breaking changes (pre-1.0 policy)

Tag-pinned GitHub Actions are now OSV-scanned and candidate-vetted against cross-major release tags on the same commit; a partial floating tag with no full release of its own is scanned instead of skipped (CHANGELOG `### Breaking`).

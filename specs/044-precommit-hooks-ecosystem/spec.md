---
aliases:
  - Pre-commit Hooks Ecosystem
  - .pre-commit-config.yaml repo/rev pins
tags:
  - sdd
  - spec
  - research
  - ecosystem/pre-commit
  - new-ecosystem
  - priority/p4
created: 2026-09-04
status: draft
related:
  - "[[MOC-specs]]"
  - "[[014-github-actions-ecosystem/spec]]"
  - "[[031-github-actions-sha-pin-diagnostic/spec]]"
  - "[[030-gitlab-ci-ecosystem/spec]]"
  - "[[042-docker-base-image-ecosystem/spec]]"
---

# Feature: New ecosystem — pre-commit hooks (`.pre-commit-config.yaml` `repo:`/`rev:` pins)

> [!info] Metadata
> **Author**: continuous-improvement research cycle (2026-09-04) — a candidate first scoped
> in the 2026-08-23 competitive scan (`.local/testing/playbooks/competitive-parity.md`,
> "pre-commit (7, near-free after GitHub Actions)") and acted on now that the prerequisite
> (GitHub Actions, #208) has shipped.
> **Branch**: [NEEDS CLARIFICATION: no tracking issue filed yet — assign issue number before
> branching, e.g. `feat/<issue>-precommit-hooks`]
> **Type**: research / new ecosystem

## 1. Overview

### Problem Statement

`.pre-commit-config.yaml` is the config file for [pre-commit](https://pre-commit.com), a
Python-ecosystem-originated but language-agnostic tool widely used across polyglot
repositories to run linters/formatters/checks as git hooks. It declares hooks under a
`repos:` list, where each entry has a `repo:` field (almost always a GitHub URL, e.g.
`https://github.com/psf/black`) and a `rev:` field pinning a tag (e.g. `rev: 23.12.1` or
`rev: v4.5.0`):

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
```

This is structurally almost identical to the already-shipped
[[014-github-actions-ecosystem/spec|GitHub Actions `uses: owner/repo@ref` ecosystem]] (#208):
a GitHub-hosted repository pinned to a tag, checked against the GitHub tags API, with the
same tag-vs-SHA distinction that [[031-github-actions-sha-pin-diagnostic/spec|the GitHub
Actions mutable-ref-pin diagnostic]] (#473) already models for `uses:` pins. The only
material difference is the manifest syntax: a YAML list-of-maps (`repos: - repo: ... rev:
...`) instead of a `uses:` string.

deps-lsp currently supports 13 ecosystems (Cargo, npm, PyPI, Go, Bundler, Dart, Maven,
Gradle, Swift, Composer, NuGet, Deno, GitHub Actions) but has no visibility into
`.pre-commit-config.yaml` pins. Users maintaining polyglot repositories — the same audience
already using deps-lsp across multiple manifest types in one repo — get no in-editor signal
that a `black`/`ruff`/`prettier`/`eslint` pre-commit hook pin is outdated, even though the
underlying datasource (GitHub tags) is one deps-lsp already resolves for a different
manifest format.

### Demand Signal

Two independent, actively-maintained reference projects already support this manifest:

- **GitHub Dependabot** added native pre-commit hook support in March 2026
  ([github.blog/changelog/2026-03-10-dependabot-now-supports-pre-commit-hooks](https://github.blog/changelog/2026-03-10-dependabot-now-supports-pre-commit-hooks/)),
  parsing `.pre-commit-config.yaml` and opening PRs to bump `rev:` — first-party support
  from the same reference project this repo's competitive-parity playbook already tracks
  for GitHub Actions parity work.
- **Renovate** has mature, longstanding `pre-commit` manager support (not an
  experimental/niche manager in Renovate's manager list).

This clears the project's own "2+ reference projects" evidentiary bar used elsewhere in
`specs/` to justify P2-class demand (see e.g. [[030-gitlab-ci-ecosystem/spec]]'s and
[[042-docker-base-image-ecosystem/spec]]'s framing of prior-art coverage as a demand
signal). However, this candidate is scored **P4** rather than higher: it is a new, more
niche manifest format relative to deps-lsp's core package-manager focus, and — unlike
GitHub Actions at the time #208 was filed — this is not an unserved gap in the market;
Dependabot and Renovate both already cover it well outside the editor. This is a suggested
priority, not a mandate; a later planning session should weigh final priority against
`specs/` backlog state at that time.

`gh issue list --search "pre-commit"` (2026-09-04, all states) returns no on-topic hits —
matches are noise from unrelated issues whose titles happen to contain "pre-commit"/"commit"
substrings (CI/tooling issues, not this manifest format). No existing deps-lsp issue or spec
covers this ecosystem today.

### Goal

deps-lsp detects `.pre-commit-config.yaml` files, parses the `repos:` list, extracts each
entry's `repo:` (GitHub URL) and `rev:` (tag/SHA pin) fields, resolves available tags via
the shared `deps_core::github::GithubTagsClient` (the same client already used by
`deps-github-actions` and `deps-swift`), and surfaces hover (current pin, resolved tag/SHA,
latest available tag, outdated status), an outdated-pin diagnostic, and a mutable-ref-pin
hardening diagnostic — reusing, not re-designing, the shape already established by
[[031-github-actions-sha-pin-diagnostic/spec|GitHub Actions' mutable-ref-pin diagnostic]]
(#473) — consistent in behavior with all other supported ecosystems.

### Out of Scope

- **Non-GitHub `repo:` hosts** (self-hosted GitLab, Bitbucket, arbitrary git URLs) — phase 1
  is GitHub-only, mirroring how `deps-github-actions` itself rejects non-GitHub
  owner/repo identities via `validate_owner_repo` before any request is made.
- **`repo: local`** (hooks defined inline in the repo itself, no external pin) — not a
  version-pinnable dependency; must be recognized and skipped, not resolved.
- **`repo: meta`** (pre-commit's built-in meta-hooks, e.g. `check-hooks-apply`) — same
  treatment as `local`: recognized sentinel, skipped gracefully.
- **`hooks[].additional_dependencies` version pins** (per-hook extra package installs, e.g.
  a `mirrors-mypy` hook's `additional_dependencies: [types-requests==2.31.0]`) — these are
  ecosystem-specific package pins (PyPI, npm, etc.) layered inside a hook definition, a
  materially different parsing problem from the top-level `repo:`/`rev:` pin; left as an
  explicit open question below rather than silently included or excluded.
- **`default_language_version` / `language_version` fields** — tool-version pins, not
  dependency pins in the sense this ecosystem targets.
- **Non-GitHub URL normalization** (e.g. `git@github.com:owner/repo.git` SSH-form `repo:`
  values) beyond whatever `validate_owner_repo`/URL-parsing already handles for
  `https://github.com/...` — treated as a parsing edge case, not a new scope item.
- **Workspace-wide "update all pre-commit hooks" aggregation** — scoped to per-document
  (per-`.pre-commit-config.yaml`) behavior, consistent with every other ecosystem.

## 2. User Stories

### US-001: See outdated pre-commit hook pins in-editor

AS A developer maintaining `.pre-commit-config.yaml` across a polyglot repository
I WANT to see at a glance which hook `rev:` pins are outdated and what newer versions are
available
SO THAT I can decide whether to bump a linter/formatter hook without leaving the editor to
check each hook repository's release page.

**Acceptance criteria:**
```
GIVEN a .pre-commit-config.yaml with one or more repos entries pinned via rev: to a tag
      or commit SHA, referencing a GitHub-hosted repository
WHEN the editor requests hover over a repos entry (its repo: or rev: field)
THEN the server SHALL show:
     - The resolved tag (if rev: is a SHA, what tag does it map to, if any?)
     - The latest available tag
     - Whether the current pin is outdated
     - A code action to update the pin to the latest version
```

### US-002: Non-GitHub, local, and meta repos are not falsely flagged

AS A developer whose `.pre-commit-config.yaml` includes `repo: local` and/or `repo: meta`
entries alongside GitHub-hosted hooks
I WANT the local/meta entries left alone entirely
SO THAT I don't get nonsensical "unknown repository" diagnostics on hooks that were never
meant to be version-pinned.

**Acceptance criteria:**
```
GIVEN a .pre-commit-config.yaml with a mix of GitHub-hosted repos entries and
      repo: local / repo: meta entries
WHEN the server parses the file
THEN local/meta entries SHALL be recognized as non-pinnable sentinels and excluded from
     registry resolution and diagnostics entirely; GitHub-hosted entries SHALL be
     processed normally
```

### US-003: Consistent behavior with the GitHub Actions ecosystem

AS A developer working across both `.github/workflows/*.yml` and
`.pre-commit-config.yaml` in the same repository
I WANT hover/diagnostics/inlay-hint/code-action behavior for pre-commit hook pins to match
the conventions already established for GitHub Actions `uses:` pins
SO THAT I don't have to learn a second set of ecosystem-specific quirks for what is, under
the hood, the same GitHub-tags datasource.

**Acceptance criteria:**
```
GIVEN equivalent "outdated pin" and "mutable tag pin" scenarios in a
      .pre-commit-config.yaml rev: field and a GitHub Actions uses:@ref pin
WHEN the server processes both
THEN diagnostic severity mapping, hover section structure, and code-action wording SHALL
     follow the same conventions established by the GitHub Actions ecosystem (#208, #473),
     adapted only where the field name (rev: vs uses:@ref) genuinely differs
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `.pre-commit-config.yaml` (and `.pre-commit-config.yml`, if pre-commit accepts that extension) by filename and register it as a manifest document, routed through the existing LSP document-lifecycle handlers | must |
| FR-002 | THE SYSTEM SHALL parse the YAML `repos:` list and, for each entry, extract `repo:` (string, GitHub URL) and `rev:` (string, tag or commit SHA) | must |
| FR-003 | THE SYSTEM SHALL recognize `repo: local` and `repo: meta` as non-pinnable sentinels and exclude them from registry resolution and diagnostics entirely, with no error or false diagnostic | must |
| FR-004 | THE SYSTEM SHALL recognize `repo:` values that are not GitHub URLs (any other git host, or a malformed URL) as out of phase-1 scope, logging a debug/info-level note and skipping gracefully — no diagnostic, no crash — mirroring `deps-github-actions`'s `validate_owner_repo` rejection of non-GitHub identities | must |
| FR-005 | THE SYSTEM SHALL resolve tag information for a recognized `repo:`/`rev:` pin via `deps_core::github::GithubTagsClient` (unmodified — no new registry client), reusing its existing `HttpCache`-backed conditional-request caching, `GITHUB_TOKEN` rate-limit handling, and pagination behavior | must |
| FR-006 | WHEN a `rev:` pin is a semantic-version-shaped tag (e.g. `23.12.1`, `v4.5.0`) THE SYSTEM SHALL surface hover content showing the tag, the latest available tag, and outdated status — using `deps_core::github::normalize_tag` for tag-form comparison, consistent with GitHub Actions | must |
| FR-007 | WHEN a `rev:` pin is a commit SHA THE SYSTEM SHALL attempt to resolve the SHA to the tag it maps to (if any) and surface that tag alongside the latest available tag in hover, reusing the tag<->SHA cross-reference approach already built for `deps-github-actions` | must |
| FR-008 | THE SYSTEM SHALL produce an outdated diagnostic on any `rev:` pin behind the latest resolvable tag, consistent in severity mapping and wording conventions with the existing GitHub Actions outdated diagnostic | must |
| FR-009 | THE SYSTEM SHALL produce a mutable-ref-pin diagnostic when a `rev:` pin references a moving/branch-like ref rather than an immutable tag or full commit SHA, reusing the design established by [[031-github-actions-sha-pin-diagnostic/spec|the GitHub Actions mutable-ref-pin diagnostic]] (#473) rather than inventing a new one | should |
| FR-010 | THE SYSTEM SHALL expose a code action (via `textDocument/codeAction`) on a `repos:` entry offering to update its `rev:` to the latest tag, applied as a `WorkspaceEdit`, following the same update-action pattern already used for GitHub Actions `uses:` pins | must |
| FR-011 | THE SYSTEM SHALL NOT parse or resolve `hooks[].additional_dependencies` entries in phase 1 — see Open Questions for whether this belongs to a follow-up phase | must |
| FR-012 | THE SYSTEM SHALL produce equivalent hover/diagnostic/inlay-hint/code-action behavior across all `.pre-commit-config.yaml` instances and all `repos:` entries, per the project's cross-ecosystem-consistency rule (`.claude/rules/continuous-improvement.md`) | must |
| FR-013 | WHEN the GitHub API is rate-limited (403, no `GITHUB_TOKEN` set) THE SYSTEM SHALL degrade gracefully using the same cached-data-fallback and user-facing rate-limit messaging already implemented in `deps_core::github`/`deps-github-actions`, introducing no new rate-limit surface | must |
| FR-014 | WHEN parsing a `repos:` entry that is malformed (missing `repo:` or `rev:`, wrong YAML shape) THE SYSTEM SHALL log a warning and skip that entry gracefully — the rest of the file remains parseable | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Reuse / no new registry surface | Version resolution SHALL reuse `deps_core::github::{GithubTagsClient, GithubTag, ReleaseDatesCache, normalize_tag, validate_owner_repo}` and its pagination helper unmodified; this ecosystem introduces **no new network calls, no new rate-limit budget, and no new registry client** beyond what GitHub Actions (#208) already added — the marginal registry-client cost of this ecosystem is zero |
| NFR-002 | Rate limiting | The existing unauthenticated 60 req/hr / tokened 5000 req/hr GitHub API budget and its cooldown/coalescing behavior (`RateLimitGate`, in-flight request coalescing in `deps-github-actions`) SHALL be shared across both GitHub Actions and pre-commit lookups for the same `owner/repo`, not double-counted or separately budgeted, since they hit the identical GitHub tags endpoint |
| NFR-003 | Reliability | When the GitHub API is unreachable or rate-limited, the system SHALL degrade gracefully exactly as GitHub Actions already does: cached data served if available; otherwise an informational/loading state, never a false "outdated" positive |
| NFR-004 | Consistency | Hover format, diagnostic wording, inlay-hint presentation, and code-action wording SHALL be identical in structure to the equivalent GitHub Actions behavior, adapted only where `rev:`/`repo:` field naming genuinely differs from `uses:@ref`, per the cross-ecosystem-consistency rule |
| NFR-005 | YAML parsing | `.pre-commit-config.yaml` SHALL be parsed using `yaml-rust2` (already a workspace dependency, used by `deps-dart` and `deps-github-actions`); no new YAML parsing dependency SHALL be introduced [NEEDS CLARIFICATION: exact parsing approach — reuse `deps-github-actions`'s YAML-to-structured-list traversal pattern directly, or write a new, smaller traversal given the simpler `repos: [{repo, rev, hooks}]` shape vs. GitHub Actions' nested `jobs.<id>.steps[].uses` shape] |
| NFR-006 | Dependency-free ecosystem crate | Following the project's Simplicity principle and the precedent of `deps-github-actions`, this ecosystem SHALL be implemented as its own crate (`deps-precommit`) reusing existing workspace dependencies (`yaml-rust2`, `deps_core::github`) with no new external dependencies added to the workspace |

## 5. Data Model

No new persistent entities. A `repos:` entry is parsed as a dependency (with
`name = "owner/repo"`, `version_requirement = "rev"`) and reuses the existing `Dependency`
trait and `cached_versions`/`resolved_versions` maps already used by `deps-github-actions`
and every other ecosystem.

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| Pre-commit repo pin (derived) | A `repos:` list entry with a GitHub-hosted `repo:` | owner, repo, rev (tag/SHA), resolved_sha (if applicable), resolved_tag (if applicable), latest_tag, is_local_or_meta (bool) |
| GitHub tag list (cached, shared) | Response from `GithubTagsClient`, cached per `(owner, repo)` — the same cache entries GitHub Actions already populates for a shared repository | tag names, commit SHAs, creation timestamps |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `.pre-commit-config.yaml` with zero `repos:` entries | No diagnostics returned (empty list) |
| `repo: local` entry | Recognized and skipped — no diagnostic, no version check, no hover (FR-003) |
| `repo: meta` entry | Recognized and skipped — same treatment as `local` (FR-003) |
| `repo:` pointing to a non-GitHub host (e.g. a self-hosted GitLab URL) | Skipped gracefully, no diagnostic, phase-1 out of scope (FR-004) |
| `repo:` and `rev:` both present but repository does not exist (404 from GitHub API) | Diagnostic: "Repository not found: owner/repo", consistent with GitHub Actions' equivalent 404 handling |
| `rev:` is a commit SHA with no corresponding tag | Hover shows the raw SHA with no resolved tag, plus the latest available tag; no false "resolved" claim |
| Same `owner/repo` appears in both `.github/workflows/*.yml` (via `uses:`) and `.pre-commit-config.yaml` (via `repo:`/`rev:`) in the same workspace | Tag list for that repository is served from the same shared cache entry — no duplicate registry fetch (NFR-001/NFR-002) |
| GitHub API rate limit exhausted (403, no `GITHUB_TOKEN`) | Same user-facing message and cached-data fallback already implemented for GitHub Actions — no new messaging path |
| Malformed `repos:` entry (missing `repo:` or `rev:` key) | Logged as a warning, entry skipped, rest of file parses normally (FR-014) |
| `.pre-commit-config.yaml` is not valid YAML | Parse error logged; handlers gracefully return empty results, consistent with how other ecosystems handle malformed manifests |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Manifest detection | `.pre-commit-config.yaml` correctly routed to this ecosystem in test fixtures |
| SC-002 | `local`/`meta`/non-GitHub exclusion | 100% of `repo: local`, `repo: meta`, and non-GitHub-host entries excluded from registry resolution and diagnostics in fixture files |
| SC-003 | Hover coverage | Hover shows current pin + resolved tag/SHA + latest tag for all GitHub-hosted `repos:` entries with a resolvable `rev:` |
| SC-004 | Outdated diagnostic accuracy | 100% agreement between the outdated diagnostic count and the actual count of pins behind their latest tag, verified against fixture files |
| SC-005 | Zero marginal registry cost | No new outbound GitHub API request pattern introduced beyond what `deps-github-actions` already issues for the same `(owner, repo)` — verified via log/cache-hit inspection showing shared cache entries across the two ecosystems for an overlapping repository |
| SC-006 | Cross-ecosystem consistency | Hover/diagnostic/code-action structure verified consistent with `deps-github-actions`'s equivalent behavior, documented in `.local/testing/coverage.md` LSP Feature Matrix |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps_core::github::{GithubTagsClient, GithubTag, ReleaseDatesCache, normalize_tag, validate_owner_repo}` unmodified — do not fork or duplicate this shared module (the module's own doc comments explicitly exist to prevent `deps-swift`/`deps-github-actions` divergence per #472; a third silent fork would defeat that).
- Use `yaml-rust2` (already a workspace dependency) for YAML parsing.
- Follow the existing `Ecosystem`/`Registry`/`ParseResult`/`Dependency`/`EcosystemFormatter` trait pattern established by `deps-github-actions`.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any implementation complete.

### Ask First
- Whether to reuse the mutable-ref-pin diagnostic's exact wording/severity from #473 verbatim, or adapt terminology for `rev:`/`repo:` field names.
- Whether `hooks[].additional_dependencies` version pins are in scope for a future phase of this same crate, or belong to a separate spec entirely (see Open Questions).
- Any change to `deps_core::github` itself (new fields, new methods) needed to support pre-commit — since this module is explicitly shared with two other ecosystems, any change here has cross-ecosystem blast radius and deserves review.

### Never
- Fork or duplicate `deps_core::github`'s tag-fetching/pagination/rate-limit logic into a `deps-precommit`-local copy.
- Attempt to resolve non-GitHub `repo:` hosts, `repo: local`, or `repo: meta` entries against any registry.
- Introduce ecosystem-specific divergence in hover format, diagnostic wording, or code-action behavior from the GitHub Actions precedent without a documented, justified reason.

## 9. Open Questions

- [NEEDS CLARIFICATION: Are `hooks[].additional_dependencies` version pins (e.g.
  `additional_dependencies: [types-requests==2.31.0]` under a `mirrors-mypy` hook) in scope
  for this ecosystem at all — even as a later phase — or are they a wholly separate concern
  best left to the PyPI/npm ecosystems' own manifest detection (which do not currently look
  inside `.pre-commit-config.yaml`)?]
- [NEEDS CLARIFICATION: Exact YAML traversal approach for `repos: [{repo, rev, hooks}]` —
  reuse `deps-github-actions`'s existing YAML-to-structured-list traversal helpers directly,
  or is the flatter shape simple enough to warrant a smaller, purpose-built traversal in the
  new crate?]
- [NEEDS CLARIFICATION: Non-GitHub repo host handling — should this ecosystem merely skip
  non-GitHub `repo:` values silently (current FR-004 proposal), or surface a low-severity
  informational diagnostic/hover note ("this ecosystem currently supports GitHub-hosted
  hooks only") so users understand why a Bitbucket/self-hosted-GitLab hook shows no version
  data, rather than silence that could read as "nothing wrong here"?]
- [NEEDS CLARIFICATION: Should `.pre-commit-config.yml` (the less common `.yml` extension
  variant) be recognized alongside `.pre-commit-config.yaml`, or is `.yaml` the only form
  pre-commit itself accepts? Needs a quick check against pre-commit's own source/docs before
  `/sdd plan`.]
- [NEEDS CLARIFICATION: No project constitution exists at `specs/constitution.md` yet —
  cannot yet validate this spec against project-wide architectural principles beyond
  precedent-matching against #208/#471/#473.]
- [NEEDS CLARIFICATION: Should the filed tracking issue for this spec block on nothing
  further (unlike [[042-docker-base-image-ecosystem/spec|the Docker ecosystem candidate]],
  which explicitly recommended waiting on a second non-package-manager ecosystem to prove
  the pattern), given GitHub Actions has already shipped and this candidate reuses its
  registry client with zero new surface — or should team judgment still defer it behind
  higher-priority backlog items given the P4/no-current-issue status?]

## 10. See Also

- #208 — GitHub Actions `uses:` pins, spec [[014-github-actions-ecosystem/spec]] — direct
  architectural precedent for a GitHub-tags-API-resolved `name@ref` pin ecosystem.
- PR #471 — GitHub Actions ecosystem implementation that shipped #208 and introduced
  `deps_core::github` as the shared GitHub tags-API client this spec proposes reusing
  unmodified.
- #473 / [[031-github-actions-sha-pin-diagnostic/spec]] — GitHub Actions mutable-ref-pin
  diagnostic — direct template for this spec's proposed `rev:` mutable-pin hardening
  diagnostic (FR-009).
- `crates/deps-core/src/github.rs` — the shared `GithubTagsClient`/`GithubTag`/
  `ReleaseDatesCache`/`normalize_tag`/`validate_owner_repo`/pagination module, whose own
  module doc comment documents it as already shared between `deps-swift` and
  `deps-github-actions` (#472) specifically to prevent divergence.
- `crates/deps-github-actions/src/registry.rs` — closest existing precedent for consuming
  `deps_core::github` from an ecosystem crate, including rate-limit cooldown gating and
  in-flight request coalescing patterns this ecosystem should reuse rather than reinvent.
- `crates/deps-dart/src/parser.rs` — established `yaml-rust2` manifest-parsing pattern.
- `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` —
  consistency rule requiring identical behavior across all ecosystems.
- `.local/testing/playbooks/competitive-parity.md` — 2026-08-23 competitive scan that first
  scoped this candidate ("pre-commit (7, near-free after GitHub Actions)").
- [pre-commit configuration documentation](https://pre-commit.com/#pre-commit-configyaml---top-level)
- [Dependabot pre-commit hooks support changelog (2026-03-10)](https://github.blog/changelog/2026-03-10-dependabot-now-supports-pre-commit-hooks/)
- [Renovate `pre-commit` manager docs](https://docs.renovatebot.com/modules/manager/pre-commit/)
- [[030-gitlab-ci-ecosystem/spec]] — sibling non-package-manager ecosystem candidate (P4,
  unimplemented), same "GitHub tags reuse" cost-reduction reasoning applies less directly
  there since GitLab CI targets a different host API.
- [[042-docker-base-image-ecosystem/spec]] — sibling new-ecosystem research spec, useful
  comparison point for "near-zero marginal cost" (this spec) vs. "new parser + new registry
  protocol" (that spec).
- [[MOC-specs]] — all specifications

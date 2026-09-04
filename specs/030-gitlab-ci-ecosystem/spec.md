---
aliases:
  - GitLab CI Ecosystem
  - GitLab CI/CD include: Version Hints
tags:
  - sdd
  - spec
  - research
  - ecosystem/gitlab-ci
  - new-ecosystem
  - priority/p4
created: 2026-09-02
status: draft
related:
  - "[[MOC-specs]]"
  - "[[014-github-actions-ecosystem/spec]]"
---

# Feature: New ecosystem — GitLab CI/CD `include:` version pins

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-09-02 (research finding); clarifications resolved
> 2026-09-04 during #466 triage
> **Branch**: `feat/466-gitlab-ci-ecosystem`
> **Type**: research / new ecosystem

## 1. Overview

### Problem Statement

GitLab CI/CD pipeline files (`.gitlab-ci.yml` and files it includes) use the `include:` directive to pull
in external configuration. Two of its forms carry a version pin that can go stale, structurally similar to
the [[014-github-actions-ecosystem/spec|GitHub Actions `uses:` ecosystem candidate]] (#208, still
unimplemented, P4):

- `include: - project: org/project` + `ref: <tag|branch|sha>` — external project includes pinned to a
  tag/branch/SHA. Structurally identical to GitHub Actions' `owner/repo@ref` pattern.
- `include: - component: $CI_SERVER_FQDN/org/project/component@1.0` — CI/CD Catalog components, pinned via
  `@<sha>`, `@<tag_name>`, `@<branch_name>`, or a release name (e.g. `@1.0`) that GitLab resolves via
  release-name matching, not a literal tag lookup.

deps-lsp has zero GitLab CI awareness today (no `gitlab` references anywhere in `crates/deps-*`) — this is
a from-scratch ecosystem candidate, the same starting point as #208.

Unlike #208, demand and architecture fit are weaker, and technical scope is comparable-to-larger:
- Renovate already has two mature managers (`gitlabci-include`, `gitlabci`) covering this ground natively,
  with only a narrow live gap (partial-semver component refs skipped, Renovate discussion #43356). This is a
  materially different competitive starting point than #208, where the closest competitor (Dependi) had an
  entirely unserved, open feature request (#239).
- Dependabot has no first-party support at all (unlike #208, where Dependabot supports GHA natively); the
  closest thing is the unaffiliated, alpha-quality third-party wrapper `dependabot-gitlab`.
- A narrow, low-adoption (11 GitHub stars) but real VS Code extension,
  [GitLab Component Helper](https://github.com/eFAILution/gitlab-component-helper), already covers hover,
  version picking, and one-click updates for the `component:` include subset specifically — weakening (not
  eliminating) the "no editor solution exists" argument that made #208 compelling.
- `component:` release-name-to-semver matching is new complexity #208 never needed (GitHub Actions' moving
  major tags like `v3` are literal tags GitHub already maintains, no client-side range matching required).
- GitLab CI/CD's `$CI_SERVER_FQDN`-relative host resolution (self-hosted GitLab instances) is a wholly new
  problem class #208 never had to solve, since GitHub Actions always resolve against the single fixed host
  `api.github.com`.

### Goal

deps-lsp detects `.gitlab-ci.yml` (and included files sharing the same syntax) as manifest files, parses
`include: - project: org/project` + `ref:` pins and `include: - component: host/org/project/name@ref` pins
(skipping `template:` and `remote:` includes, and `image:`/`services:` Docker tags, gracefully), fetches
version information from the GitLab REST API repository-tags endpoint with rate-limit-aware caching
(conditional requests; optional Personal Access Token via `PRIVATE-TOKEN` header for unauthenticated budget
overflow), and surfaces hover (ref → resolved tag + latest available), outdated diagnostics, inlay hints,
and update code actions — consistent with all other 12 supported ecosystems (11 shipped + GitHub Actions
once #208 ships).

### Out of Scope

- `image:` / `services:` Docker image tag pins — this is a distinct, broader "Docker image tag" ecosystem,
  not specific to GitLab CI (Renovate itself treats it as a separate `docker` datasource even within its
  `gitlabci` manager). A future "Docker image tags" ecosystem candidate would need its own spec covering all
  manifest types that reference image tags, not just `.gitlab-ci.yml`.
- `include: - template: Name.gitlab-ci.yml` — GitLab-maintained built-in templates with no external version
  to track. Same stance as #208's `./local` skip case for GitHub Actions.
- `include: - remote: https://...` — arbitrary URL includes with no resolvable version pin.
- Recursive parsing of included files' own nested `include:` directives — mirrors #208's stance on composite
  actions (out of scope, treated as atomic/opaque for phase 1).
- CI/CD Catalog component *metadata* (descriptions, catalog listing details) — GitLab's own guidance is that
  this requires GraphQL, not REST; plain tag/version resolution does not need it, so metadata enrichment is
  deferred.
- Self-hosted GitLab instance host resolution beyond an explicit, hardcoded host in the include path (see
  Edge Cases and Open Questions) — resolving `$CI_SERVER_FQDN`-relative references without additional
  context is a wholly new problem class not present in #208's design.
- Workspace-wide aggregation or "update all includes in all GitLab CI files" — scoped to per-document scope,
  consistent with other manifests and with #208.

## 2. User Stories

### US-001: See outdated project/ref includes in-editor

AS A platform engineer maintaining `.gitlab-ci.yml` pipelines that pin external project includes to a tag,
branch, or SHA
I WANT to see at a glance which `project:`+`ref:` includes are outdated and what newer versions are
available
SO THAT I can decide whether to accept updates without leaving the editor to check the GitLab project's tag
list.

**Acceptance criteria:**
```
GIVEN a .gitlab-ci.yml file with one or more `include: - project: ... ref: ...` entries pinned to
      tags or SHAs
WHEN the editor requests hover over an include entry
THEN the server SHALL show:
     - The resolved tag (if the ref is a SHA, what tag does it map to?)
     - The latest available tag
     - Whether the current pin is outdated
     - A code action to update the pin to the latest version
```

### US-002: See outdated CI/CD Catalog component includes in-editor

AS A platform engineer using CI/CD Catalog components (`include: - component: .../name@1.0`)
I WANT to see whether the pinned release name is behind the latest published component release
SO THAT I know when a newer component version is available, without manually browsing the catalog.

**Acceptance criteria:**
```
GIVEN a .gitlab-ci.yml file with a `component:` include pinned to a release-name version (e.g. `@1.0`)
WHEN the editor requests hover over that include entry
THEN the server SHALL resolve the release name against the underlying project's published releases
     and display the latest available release version and whether the current pin is outdated
```

### US-003: Consistent diagnostics and hints across all GitLab CI files

AS A developer with multiple `.gitlab-ci.yml`-syntax files (main pipeline plus included child pipelines) in
a repository
I WANT the outdated diagnostics, hover, inlay hints, and update actions to behave identically across all of
them
SO THAT I don't have to learn file-specific quirks, per the project's cross-ecosystem-consistency rule.

**Acceptance criteria:**
```
GIVEN two or more GitLab CI YAML files with equivalent include-pin scenarios
WHEN the server processes both files
THEN the diagnostics, hover, inlay hints, and code action behavior SHALL be identical across both
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `.gitlab-ci.yml` (and, per configuration, other files matching GitLab's `.gitlab-ci.yml`-syntax convention) by path/filename pattern and register them as manifest documents, routed through the existing LSP document-lifecycle handlers | must |
| FR-002 | THE SYSTEM SHALL parse YAML GitLab CI files, extract all `include:` list entries, and identify `project:`+`ref:` pairs and `component:` references in the form `host/org/project/name@ref` | must |
| FR-003 | THE SYSTEM SHALL skip and gracefully handle (without error or false diagnostic) `include: - template: ...` (built-in templates) and `include: - remote: ...` (arbitrary URLs) — these are not version-pinnable by this feature | must |
| FR-004 | THE SYSTEM SHALL fetch version information from the GitLab REST API repository-tags endpoint (`GET /projects/:id/repository/tags`) using the existing `HttpCache` with conditional-request validation, shared by both `project:`+`ref:` and `component:` include forms | must |
| FR-005 | THE SYSTEM SHALL advertise optional configuration for a GitLab Personal/Project Access Token to increase the unauthenticated rate-limit budget — via the `GITLAB_TOKEN` environment variable, mirroring the `GITHUB_TOKEN` precedent in `crates/deps-swift/src/registry.rs` and `crates/deps-core/src/github.rs`, sent as the `PRIVATE-TOKEN` header (distinct scheme from GitHub's `Authorization: Bearer`) | must |
| FR-006 | WHEN a `project:`+`ref:` include is pinned to a semantic-version tag or SHA THE SYSTEM SHALL surface hover content showing the resolved tag, resolved commit SHA (if ref is a SHA), latest tag, and outdated status | must |
| FR-007 | WHEN a `component:` include is pinned to a version pin THE SYSTEM SHALL resolve it per GitLab's documented CI/CD Catalog priority order — commit SHA (exact match) > tag (exact match; a same-named tag and SHA resolve to the SHA) > branch (exact match; a same-named tag and branch resolve to the tag) > `~latest` (highest published semver tag) > a partial semantic version (e.g. `1.2` selects the highest published `1.2.*` tag, `1` selects the highest published `1.*.*` tag) — using `semver::VersionReq`-based range matching for the partial-version and `~latest` forms (no hand-rolled comparison, per `.claude/rules/rust-code.md`), and display the concrete resolved version | must |
| FR-008 | THE SYSTEM SHALL produce an outdated diagnostic (warning or info level, consistent with existing ecosystems) on any include pin where the resolved version is behind the latest resolvable tag/release | must |
| FR-009 | THE SYSTEM SHALL produce inlay hints showing the latest version for each include, consistent with the format and per-ecosystem `EcosystemConfig` already used elsewhere | must |
| FR-010 | THE SYSTEM SHALL expose a code action (via `textDocument/codeAction`) on any include pin, offering to update it to the latest tag/release, applied as a `WorkspaceEdit` | must |
| FR-011 | WHEN a `project:` or `component:` include's host segment is a literal, hardcoded GitLab hostname (not `$CI_SERVER_FQDN` or another CI-time variable) THE SYSTEM SHALL resolve version data against that host's API | must |
| FR-012 | WHEN a `project:` or `component:` include's host segment is `$CI_SERVER_FQDN` (or another unresolved CI-time variable) THE SYSTEM SHALL skip version resolution and surface an informational (not error/warning) diagnostic explaining that the host cannot be statically determined — no default host is guessed and no git-remote inference is performed (see Open Questions resolution: the codebase has no existing git-plumbing utility, and guessing a host risks showing version data from the wrong GitLab instance, violating NFR-003) | must |
| FR-013 | THE SYSTEM SHALL produce equivalent behavior (hover, diagnostics, inlay hints, code actions) across all GitLab CI files and all include references, not introducing ecosystem-specific divergence from the other 12+ supported ecosystems, per the cross-ecosystem-consistency rule | must |
| FR-014 | WHEN the GitLab API returns 401/403 (rate limit exceeded or auth required) without a valid access token configured THE SYSTEM SHALL display a user-facing error message recommending the user configure a Personal/Project Access Token, mirroring the pattern in `crates/deps-swift/src/registry.rs` (lines 82-86) for GitHub | must |
| FR-015 | WHEN parsing a GitLab CI file where an include entry is unparseable or the `project:`/`component:` path is malformed THE SYSTEM SHALL log a warning and skip that reference gracefully | should |
| FR-016 | THE SYSTEM SHALL NOT parse or version-check `image:` / `services:` entries under this ecosystem — those are explicitly out of scope | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Fetching tag/release lists from the GitLab API SHALL use conditional requests to avoid quota consumption on cache hits; hover/code-action latency on a cached include SHALL be dominated by in-memory YAML parsing and cached lookup, not network I/O |
| NFR-002 | Rate limiting | GitLab.com's unauthenticated API rate limit is converging toward the same order of magnitude as GitHub's 60 req/hr (down from a historical 500 req/min); the system SHALL use long TTLs and aggressive conditional-request revalidation to fit within this budget; an optional access token SHALL transparently increase the limit when configured |
| NFR-003 | Reliability | When the GitLab API is unreachable, rate-limited, or the target host cannot be resolved (`$CI_SERVER_FQDN` case), the system SHALL degrade gracefully: cached data (if available) is served; otherwise diagnostics/hovers show a minimal/loading state, never a false positive |
| NFR-004 | Consistency | Include-pin behavior (hover format, diagnostics language, inlay-hint presentation, code-action wording) SHALL be identical to all other supported ecosystems, per `.claude/rules/continuous-improvement.md`'s cross-ecosystem-consistency rule — any divergence is a first-class bug |
| NFR-005 | YAML parsing | GitLab CI YAML files are parsed using the existing `yaml-rust2` crate (already used in `deps-dart`, hardened in #174/#176); no new YAML dependency SHALL be introduced |
| NFR-006 | Authentication | Access-token transport SHALL use the `PRIVATE-TOKEN` header per GitLab's API convention — this is a distinct scheme from GitHub's `Authorization: Bearer` used by `crates/deps-swift/src/registry.rs`; the two SHALL NOT be conflated in shared HTTP-client code without an explicit auth-scheme abstraction |
| NFR-007 | Caching | Conditional-GET support already exists in `HttpCache` (RFC 7232, ETag/If-None-Match, `crates/deps-core/src/cache.rs` lines ~1072-1252); no new caching infrastructure is required, but cache keys must account for per-instance host (self-hosted GitLab installs are not all `gitlab.com`) |
| NFR-008 | Host generality | Unlike GitHub Actions (#208), which always resolves against the single fixed host `api.github.com`, GitLab CI/CD references may target self-hosted instances; the system SHALL treat the target host as a per-reference variable, not a hardcoded constant |

## 5. Data Model

No new persistent entities. Include references are parsed as dependencies (with `name` derived from
`org/project` or `org/project/component-name`, `version_requirement = "ref"`) and reuse the existing
`Dependency` trait and `cached_versions`/`resolved_versions` maps from `DocumentState`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Project include (derived) | A `project:`+`ref:` entry in `include:` | host, org/project path, ref (tag/branch/SHA), resolved_sha (if applicable), latest_tag |
| Component include (derived) | A `component:` entry in `include:` | host (literal or unresolved CI variable), org/project/component path, ref (release name / tag / SHA / branch), resolved_release, latest_release |
| GitLab tag list (cached) | Response from GitLab REST API `/projects/:id/repository/tags`, cached per (host, project) | tag names, commit SHAs, creation timestamps |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GitLab CI file with zero `include:` entries, or none matching `project:`/`component:` forms | No diagnostics returned (empty list) |
| `include: - template: ...` entry | Parsed but skipped gracefully — no diagnostic, no version check, no hover |
| `include: - remote: https://...` entry | Parsed but skipped — arbitrary URLs are not version-pinnable |
| `image:` / `services:` entries anywhere in the file | Not parsed by this ecosystem at all (explicitly out of scope, FR-016) |
| `project:`/`component:` include host is `$CI_SERVER_FQDN` (self-hosted-instance variable) | Version resolution skipped; informational diagnostic explains the host could not be statically determined (FR-012) — the parsed reference is still shown in hover, without version data |
| `component:` version pin is `~latest` or a partial semver (e.g. `1.2`, `1`) | Resolved via `semver::VersionReq` range matching against published CI/CD Catalog release tags, per FR-007's documented GitLab priority order |
| `project:`/`component:` path is malformed (missing segments, invalid characters) | Logged as a warning, skipped gracefully; file parsing continues |
| Referenced project does not exist or is private with no accessible token (404/403 from GitLab API) | Diagnostic: "Project not found or inaccessible: org/project"; no version data shown |
| `component:` release name (e.g. `@1.0`) does not match any published release via semver-range matching | Diagnostic: "No matching release found for `1.0`"; hover shows no resolvable version |
| GitLab API returns 401/403 (rate limit exhausted or private project) and no access token is configured | User-facing error message recommending the user configure a Personal/Project Access Token to increase quota / gain access |
| Self-hosted GitLab instance not reachable or its host cannot be determined | Version resolution is skipped with an informational (not error) diagnostic; hover shows the parsed reference without version data |
| GitLab CI file is not valid YAML | Parse error is logged; handlers gracefully return empty results, consistent with how other ecosystems handle malformed manifests |
| Include entry is edited while version data is being fetched | Subsequent hover/code-action requests on the new content SHALL trigger a fresh parse and fetch; stale loading state is discarded |
| Very large GitLab CI file (many include entries across many included files) | Parsing and hover latency SHALL remain acceptable (<1s per request); no new registry calls beyond one per unique (host, project) pair, cached thereafter |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Path/filename detection for `.gitlab-ci.yml`-syntax files | Detected and routed to the GitLab CI ecosystem |
| SC-002 | Hover shows current + latest version for `project:`+`ref:` includes | 100% of resolvable includes show hover content listing current ref and latest available tag |
| SC-003 | Hover shows current + latest version for `component:` includes | 100% of resolvable component includes show hover content listing current release-name pin and latest matching release, using semver-range matching rather than literal-tag equality |
| SC-004 | Outdated diagnostics match version comparison | 100% agreement between outdated diagnostics count and the actual count of include pins behind their latest resolvable version |
| SC-005 | GitLab API quota preservation | Conditional-request hit rate ≥ 80% on repeated hovers of unchanged GitLab CI files |
| SC-006 | Cross-ecosystem consistency | GitLab CI behavior (hover format, diagnostic language, inlay-hint templates) verified identical to same scenarios in other ecosystems, documented in `.local/testing/coverage.md` LSP Feature Matrix |
| SC-007 | Access-token support | Optional access-token environment variable correctly increases GitLab API quota when configured, sent via `PRIVATE-TOKEN` header, verified via mock rate-limit responses |
| SC-008 | Graceful degradation | GitLab CI files with unresolvable-host or invalid include references do not prevent other includes in the same file from being processed; malformed/unresolvable entries produce warnings or informational diagnostics, not crashes or false-positive outdated markers |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing patterns in `crates/deps-core/` for ecosystem implementation (trait-based `Ecosystem`,
  `Registry`, `ParseResult`, `Dependency`; reuse `HttpCache` for API calls).
- Use `yaml-rust2` (already hardened in #174/#176) for YAML parsing.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features
  --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any
  implementation complete.

### Ask First
- Introducing a per-reference (rather than per-ecosystem-constant) host-resolution mechanism in the HTTP
  client layer — this is new architectural surface not needed by any currently shipped ecosystem (including
  #208/GitHub Actions), since all of them target a single fixed host. Resolved direction (see Open
  Questions): a new `GitlabTagsClient`-style struct, parallel to but not derived from
  `deps_core::github::GithubTagsClient`, carrying the host as an instance field instead of a module
  constant — confirm the concrete shape with the user/reviewer before landing it, since it is the first
  per-instance-host client in the codebase.
- Adding a distinct auth-scheme abstraction to accommodate `PRIVATE-TOKEN` (GitLab) alongside
  `Authorization: Bearer` (GitHub, #208) — resolved direction: keep them separate, ecosystem-local header
  constants rather than a shared abstraction, since GitHub Actions' `Authorization: Bearer` header-building
  already lives in `deps_core::github` and is not being touched by this work.
- Implementing `semver::VersionReq`-based range matching for `component:` includes' partial-version/`~latest`
  forms (FR-007) — confirm the conversion from GitLab's partial-version syntax (`1.2`, `1`) to a
  `VersionReq` before landing it, since it is new logic with no existing precedent in the codebase to copy.

### Never
- Introduce ecosystem-specific divergence in hover format, diagnostic wording, or code-action behavior
  without a documented, justified reason — consistency across all supported ecosystems is required.
- Parse or version-check `image:`/`services:` Docker image tags under this ecosystem (explicitly out of
  scope — a separate "Docker image tags" ecosystem candidate, if pursued, must be spec'd on its own).
- Recursively parse included files' own nested `include:` directives.
- Guess or silently hardcode a default GitLab host, or infer one from a git remote, for
  `$CI_SERVER_FQDN`-relative references (FR-012) — resolved: always skip version resolution with an
  informational diagnostic instead. An incorrect guess would produce false version data against the wrong
  instance, and the codebase has no existing git-plumbing utility to add for this narrow case.

## 9. Resolved Decisions

All items previously marked `[NEEDS CLARIFICATION]` were resolved on 2026-09-04 (triage of issue #466,
now that its blocker #208 has shipped and closed):

1. **`$CI_SERVER_FQDN`-relative host resolution** (FR-012): skip version resolution, surface an
   informational diagnostic. Rejected alternatives: a configurable default host (risks silently showing
   version data from the wrong GitLab instance, violating NFR-003) and inferring the host from the
   repository's git remote origin (the codebase has no existing git-plumbing utility or dependency —
   adding one solely for this narrow self-hosted case is disproportionate new architectural surface).
2. **`component:` version-pin resolution algorithm** (FR-007): follows GitLab's own documented CI/CD
   Catalog priority order — commit SHA > tag > branch > `~latest` > partial semver (`1.2`, `1`) — verified
   against `https://docs.gitlab.com/ci/components/`. Partial-version and `~latest` forms are matched using
   `semver::VersionReq` range matching (no hand-rolled comparison logic, per `.claude/rules/rust-code.md`).
3. **Access-token environment variable**: `GITLAB_TOKEN`, mirroring the `GITHUB_TOKEN` convention already
   established in `crates/deps-swift/src/registry.rs` and `crates/deps-core/src/github.rs`.
4. **Shared Registry implementation**: `project:`+`ref:` and `component:` share one registry client (a new
   `GitlabTagsClient`, parallel to `deps_core::github::GithubTagsClient` but carrying the target host as an
   instance field rather than a fixed module constant, since GitLab references may target self-hosted
   instances per NFR-008). The `component:` release-name/semver-range resolution layers on top of that
   shared client as a separate, focused function — not a second registry implementation.
5. **Self-hosted TLS/auth beyond `PRIVATE-TOKEN`**: out of scope for v1. Relies on `reqwest` + `rustls`'s
   default system trust store, same as every other ecosystem crate; no custom CA or mTLS support.
6. **Build sequencing relative to #208**: build independently, now. #208 shipped and closed 2026-09-02.
   `deps_core::github::GithubTagsClient` is GitHub-API-specific (fixed `api_base`) and cannot be reused
   as-is for GitLab's per-instance-host requirement regardless of timing, so waiting for a further shared
   abstraction offers no benefit — this ecosystem follows the same *pattern* (trait-based
   `Ecosystem`/`Registry`/`ParseResult`/`Dependency`, `HttpCache` reuse) as parallel, not shared, code, the
   same relationship `deps-swift` and `deps-github-actions` already have to `deps_core::github`.
7. **Missing project constitution**: not a blocker. No `.local/specs/constitution.md` (or `specs/`
   equivalent) exists yet, and none of this project's other `specify`-phase specs block on one either —
   this spec proceeds against `.claude/rules/*.md` instead.
8. **Prioritization**: resolved by proceeding — issue #466's triage (2026-09-04) selected the full spec
   scope (not a reduced MVP slice) for implementation now that #208 is unblocked. Next step is `/sdd plan`.

No `[NEEDS CLARIFICATION]` markers remain in this spec.

## 10. See Also

- #208 — GitHub Actions workflow `uses:` pins ecosystem candidate, spec [[014-github-actions-ecosystem/spec]]
  (still unimplemented, P4). Same git-tags-datasource pattern, sibling new-ecosystem candidate; the
  `project:`+`ref:` include form here is structurally identical to GHA's `owner/repo@ref`.
- #466 — implementation follow-up issue for this spec. Was blocked on #208 shipping and on resolving 8
  open `[NEEDS CLARIFICATION]` items; both are now resolved (see §9) — ready for `/sdd plan`.
- `crates/deps-swift/src/registry.rs` (lines 12-95) — closest existing precedent for a hosted-git-platform
  REST API integration, including token env-var handling and rate-limit messaging (GitHub-specific auth
  scheme, not directly reusable for GitLab's `PRIVATE-TOKEN` header without an auth-scheme abstraction)
- `crates/deps-core/src/cache.rs` (lines ~1072-1252) — `HttpCache` conditional-request (`get_cached`/304
  handling) implementation; no new caching infrastructure needed, but cache keys must account for per-instance
  host
- `crates/deps-dart/src/parser.rs` — YAML parsing with `yaml-rust2`; established pattern for YAML manifest
  files
- `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` — consistency rule requiring
  identical behavior across all ecosystems; violations are first-class bugs
- [GitLab CI/CD `include:` keyword reference](https://docs.gitlab.com/ci/yaml/)
- [GitLab CI/CD Catalog components — examples and usage](https://docs.gitlab.com/ci/components/examples/)
- [GitLab REST API rate limits](https://docs.gitlab.com/rate_limits/)
- [`about.gitlab.com` blog — unauthenticated rate-limitation announcement](https://about.gitlab.com/blog/2023/04/10/rate-limitation-for-unauthorized-users-projects-list-api/)
- [GraphQL needed for CI/CD component metrics, not plain tag lists](https://levelup.gitconnected.com/the-gitlab-graphql-hack-get-instant-ci-cd-component-metrics)
- [GitLab issue: CI/CD catalog project setting not yet exposed in REST API](https://gitlab.com/gitlab-org/gitlab/-/issues/463043)
- [Renovate `gitlabci-include` manager](https://docs.renovatebot.com/modules/manager/gitlabci-include/)
- [Renovate `gitlabci` manager](https://docs.renovatebot.com/modules/manager/gitlabci/)
- [Renovate discussion — GitLab CI Catalog Version Support](https://github.com/renovatebot/renovate/discussions/43356)
- [Renovate issue #23431](https://github.com/renovatebot/renovate/issues/23431)
- [`dependabot-gitlab` — unaffiliated, alpha-quality third-party wrapper](https://dependabot-gitlab.gitlab.io/dependabot/guide/index.html)
- [GitLab Component Helper — VS Code extension (eFAILution)](https://github.com/eFAILution/gitlab-component-helper)
- [GitLab Component Helper — VS Code Marketplace listing](https://marketplace.visualstudio.com/items?itemName=eFAILution.gitlab-component-helper)
- [[MOC-specs]] — all specifications

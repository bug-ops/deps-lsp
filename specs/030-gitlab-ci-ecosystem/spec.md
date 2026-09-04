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
version information from the GitLab REST API with rate-limit-aware caching — the repository-tags endpoint
for `project:` includes and the releases endpoint for `component:` includes (FR-004); conditional requests;
optional Personal Access Token via `PRIVATE-TOKEN` header for unauthenticated budget overflow, and surfaces hover (ref → resolved tag + latest available), outdated diagnostics, inlay hints,
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
- Self-hosted GitLab instance host resolution beyond an explicit, hardcoded host in the include path or
  an explicitly user-configured `registries.gitlab_instance_host` (FR-011a, added 2026-09-04) — resolving
  `$CI_SERVER_FQDN`-relative references from *inferred* context (a git remote, a guessed default) remains
  out of scope, a wholly new problem class not present in #208's design.
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
GIVEN two or more GitLab CI YAML files **detected by FR-001** (`.gitlab-ci.yml` and
      `.gitlab/ci/*.yml|*.yaml`) with equivalent include-pin scenarios
WHEN the server processes both files
THEN the diagnostics, hover, inlay hints, and code action behavior SHALL be identical across both
```

> [!warning] Detection-convention limit
> This story covers the split-pipeline layout GitLab itself documents (`.gitlab/ci/`). A child
> pipeline kept at a conventionless path (`ci/build.yml`) is not detected at all in v1, so
> "identical behavior" is vacuously true for it rather than delivered — see FR-001.

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `.gitlab-ci.yml` and any `.yml`/`.yaml` file under `.gitlab/ci/` by path/filename pattern and register them as manifest documents, routed through the existing LSP document-lifecycle handlers. Child pipelines kept at conventionless paths (`ci/build.yml`, `templates/*.yml`, arbitrary `include: - local:` targets) are **not** detected in v1 — no filename convention distinguishes them from any other YAML file in the repository, and reading them out of a parent's `include: - local:` list is nested-include resolution, which §1 excludes | must |
| FR-002 | THE SYSTEM SHALL parse YAML GitLab CI files, extract all `include:` list entries, and identify `project:`+`ref:` pairs and `component:` references in the form `host/org/project/name@ref` | must |
| FR-003 | THE SYSTEM SHALL skip and gracefully handle (without error or false diagnostic) `include: - template: ...` (built-in templates) and `include: - remote: ...` (arbitrary URLs) — these are not version-pinnable by this feature | must |
| FR-004 | THE SYSTEM SHALL fetch version information from the GitLab REST API using the existing `HttpCache` with conditional-request validation, selecting the endpoint by include kind: `GET /projects/:id/repository/tags` for `project:`+`ref:` includes (a `ref:` is a plain git ref) and `GET /projects/:id/releases` for `component:` includes (a CI/CD Catalog component version **is** a project Release — a tag with no release is not a resolvable component version, so the tags endpoint over-reports for this form). Both endpoints are served by one client and one credential path; only the URL and the response shape differ | must |
| FR-005 | THE SYSTEM SHALL advertise optional configuration for a GitLab Personal/Project Access Token to increase the unauthenticated rate-limit budget — via the `GITLAB_TOKEN` environment variable, mirroring the `GITHUB_TOKEN` precedent in `crates/deps-swift/src/registry.rs` and `crates/deps-core/src/github.rs`, sent as the `PRIVATE-TOKEN` header (distinct scheme from GitHub's `Authorization: Bearer`) | must |
| FR-005a | THE SYSTEM SHALL attach the `PRIVATE-TOKEN` header **only** when the target host is the single *token host*: `gitlab.com` when `registries.gitlab_instance_host` (FR-011a) is unset, and the configured host — **replacing**, not extending, `gitlab.com` — when it is set. Any other host SHALL still be fetched, subject to the existing `HostClass` gate, but **unauthenticated**. The comparison SHALL run on the normalized, ASCII-serialized origin, never the raw host string. Rationale: an include's host segment is content read out of a checked-in manifest, so without a bound an untrusted repository could exfiltrate the user's `GITLAB_TOKEN` to a host of its choosing — and a *union* would exfiltrate a corporate self-hosted PAT to `gitlab.com` for any cloned repo naming `gitlab.com` in a `component:` include, since one `GITLAB_TOKEN` is only ever valid for one instance (added 2026-09-04, revised 2026-09-04 after design review; see §9.9) | must |
| FR-006 | WHEN a `project:`+`ref:` include is pinned to a semantic-version tag or SHA THE SYSTEM SHALL surface hover content showing the resolved tag, resolved commit SHA (if ref is a SHA), latest tag, and outdated status | must |
| FR-007 | WHEN a `component:` include is pinned to a version pin THE SYSTEM SHALL resolve it against the project's **published releases** (FR-004), per GitLab's documented CI/CD Catalog priority order — commit SHA (exact match) > release tag (exact match; a same-named tag and SHA resolve to the SHA) > branch (exact match; a same-named tag and branch resolve to the tag) > `~latest` (highest published semver release) > a partial semantic version (e.g. `1.2` selects the highest published `1.2.*` release, `1` selects the highest published `1.*.*` release) — using `semver::VersionReq`-based range matching for the partial-version and `~latest` forms (no hand-rolled comparison, per `.claude/rules/rust-code.md`), and display the concrete resolved version. A candidate SHALL NOT be selected from the repository-tags list: an unreleased tag is not a usable component version, and pinning to one via FR-010 would break the user's pipeline | must |
| FR-008 | THE SYSTEM SHALL produce an outdated diagnostic (warning or info level, consistent with existing ecosystems) on any include pin where the resolved version is behind the latest resolvable tag/release | must |
| FR-009 | THE SYSTEM SHALL produce inlay hints showing the latest version for each include, consistent with the format and per-ecosystem `EcosystemConfig` already used elsewhere | must |
| FR-010 | THE SYSTEM SHALL expose a code action (via `textDocument/codeAction`) on any include pin, offering to update it to the latest tag/release, applied as a `WorkspaceEdit` | must |
| FR-011 | WHEN a `project:` or `component:` include's host segment is a literal, hardcoded GitLab hostname (not `$CI_SERVER_FQDN` or another CI-time variable) THE SYSTEM SHALL resolve version data against that host's API | must |
| FR-011a | THE SYSTEM SHALL expose an optional `registries.gitlab_instance_host` LSP setting (default unset). WHEN set, it SHALL be the host that `include: - project:` entries and `$CI_SERVER_FQDN`-relative `component:` entries resolve against, and it SHALL **become** FR-005a's token host in place of `gitlab.com`. WHEN unset, behavior SHALL be exactly FR-012's skip-with-informational-diagnostic. The configured value SHALL pass the same host validation as a manifest-read host (https-only, no userinfo, `HostClass` policy check); a value failing validation SHALL be logged and treated as unset. The setting SHALL take full effect for every document opened after it is applied; for documents **already open** when it changes, see SC-007b's stated limitation. Rationale: `include: - project:` carries **no host segment in GitLab's syntax at all** (the instance is always implicit), so without this FR-011 is unreachable for `project:` includes and US-001 is undeliverable (added 2026-09-04, see §9.9) | must |
| FR-012 | WHEN a `project:` or `component:` include's host segment is `$CI_SERVER_FQDN` (or another unresolved CI-time variable), **and `registries.gitlab_instance_host` (FR-011a) is unset**, THE SYSTEM SHALL skip version resolution and surface an informational (not error/warning) diagnostic explaining that the host cannot be statically determined and naming that setting as the remedy — no default host is guessed and no git-remote inference is performed (see Open Questions resolution: the codebase has no existing git-plumbing utility, and guessing a host risks showing version data from the wrong GitLab instance, violating NFR-003) | must |
| FR-013 | THE SYSTEM SHALL produce equivalent behavior (hover, diagnostics, inlay hints, code actions) across all GitLab CI files and all include references, not introducing ecosystem-specific divergence from the other 12+ supported ecosystems, per the cross-ecosystem-consistency rule | must |
| FR-014 | WHEN the GitLab API returns `429` (rate limited) or `401`/`403` (auth required / insufficient scope) without a valid access token configured THE SYSTEM SHALL display a user-facing error message recommending the user configure a Personal/Project Access Token, mirroring `deps_core::github::github_rate_limit_error` (`crates/deps-core/src/github.rs:129`) for the message shape and `GithubActionsRegistry::map_tags_error` (`crates/deps-github-actions/src/registry.rs:216`) for the status-code-to-`DepsError` mapping. Note that GitLab's status semantics differ from GitHub's — GitHub signals rate limiting with `403`, GitLab with `429` — so the mapping SHALL NOT be copied arm-for-arm | must |
| FR-015 | WHEN parsing a GitLab CI file where an include entry is unparseable or the `project:`/`component:` path is malformed THE SYSTEM SHALL log a warning and skip that reference gracefully | should |
| FR-016 | THE SYSTEM SHALL NOT parse or version-check `image:` / `services:` entries under this ecosystem — those are explicitly out of scope | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Fetching tag/release lists from the GitLab API SHALL use conditional requests to avoid quota consumption on cache hits; hover/code-action latency on a cached include SHALL be dominated by in-memory YAML parsing and cached lookup, not network I/O |
| NFR-002 | Rate limiting | GitLab.com's unauthenticated API rate limit is converging toward the same order of magnitude as GitHub's 60 req/hr (down from a historical 500 req/min); the system SHALL use long TTLs and aggressive conditional-request revalidation to fit within this budget; an optional access token SHALL transparently increase the limit when configured |
| NFR-003 | Reliability | When the GitLab API is unreachable, rate-limited, or the target host cannot be resolved (`$CI_SERVER_FQDN` case), the system SHALL degrade gracefully: cached data (if available) is served; otherwise diagnostics/hovers show a minimal/loading state, never a false positive |
| NFR-004 | Consistency | Include-pin behavior (hover format, diagnostics language, inlay-hint presentation, code-action wording) SHALL be identical to all other supported ecosystems, per `.claude/rules/continuous-improvement.md`'s cross-ecosystem-consistency rule — any divergence is a first-class bug. **One carve-out, declared here rather than discovered later:** for `component:` includes only, the project link is rendered as a line in the hover body instead of as the hover heading's link, because a component's dependency name ends in the component segment and so is not a project URL. `project:` includes keep the standard heading link, and no other surface (diagnostics, inlay hints, code actions) diverges for either kind |
| NFR-005 | YAML parsing | GitLab CI YAML files are parsed using the existing `yaml-rust2` crate (already used in `deps-dart`, hardened in #174/#176); no new YAML dependency SHALL be introduced |
| NFR-006 | Authentication | Access-token transport SHALL use the `PRIVATE-TOKEN` header per GitLab's API convention — this is a distinct scheme from GitHub's `Authorization: Bearer` used by `crates/deps-swift/src/registry.rs`; the two SHALL NOT be conflated in shared HTTP-client code without an explicit auth-scheme abstraction |
| NFR-007 | Caching | Conditional-GET support already exists in `HttpCache` (RFC 7232, ETag/If-None-Match, `crates/deps-core/src/cache.rs` lines ~1072-1252); no new caching infrastructure is required, but cache keys must account for per-instance host (self-hosted GitLab installs are not all `gitlab.com`) |
| NFR-008 | Host generality | Unlike GitHub Actions (#208), which always resolves against the single fixed host `api.github.com`, GitLab CI/CD references may target self-hosted instances; the system SHALL treat the target host as a per-reference variable, not a hardcoded constant |

## 5. Data Model

No new persistent entities. Include references are parsed as dependencies and reuse the existing
`Dependency` trait and `cached_versions`/`resolved_versions` maps from `DocumentState`.

A dependency's `name` is **host-qualified** (`{host}/{project-path}[/{component-name}]`) whenever its
host is known, so that every name-keyed structure — `DocumentState::cached_versions`, the crate's tag
index, the `PackageName`-keyed registry cache — is automatically keyed per instance, satisfying
NFR-007. The *routing* target (which host, which endpoint) travels separately, in the dependency's
`DependencySource`, because `Registry::get_versions` receives only a `&PackageName` and a
host-embedded-in-name scheme is not decodable (a group path may legally contain dots, so `a/b/c`
cannot be split into host + path by inspection).

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Project include (derived) | A `project:`+`ref:` entry in `include:` | host (always implicit — FR-011a), org/project path, ref (tag/branch/SHA), resolved_sha (if applicable), latest_tag |
| Component include (derived) | A `component:` entry in `include:` | host (literal or unresolved CI variable), org/project/component path, pin (release name / tag / SHA / branch / `~latest` / partial semver), resolved_release, latest_release |
| GitLab route (derived, in-memory) | The `(host, endpoint-kind)` pair a dependency resolves against, registered at parse time under an opaque key carried in `DependencySource::AlternateRegistry.index` | normalized origin, endpoint kind (tags \| releases) |
| GitLab tag list (cached) | Response from `/projects/:id/repository/tags`, cached per (host, project) — backs `project:`+`ref:` | tag names, commit SHAs |
| GitLab release list (cached) | Response from `/projects/:id/releases`, cached per (host, project) — backs `component:` (FR-004/FR-007) | release tag names, commit SHAs, release timestamps |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| GitLab CI file with zero `include:` entries, or none matching `project:`/`component:` forms | No diagnostics returned (empty list) |
| `include: - template: ...` entry | Parsed but skipped gracefully — no diagnostic, no version check, no hover |
| `include: - remote: https://...` entry | Parsed but skipped — arbitrary URLs are not version-pinnable |
| `image:` / `services:` entries anywhere in the file | Not parsed by this ecosystem at all (explicitly out of scope, FR-016) |
| `project:`/`component:` include host is `$CI_SERVER_FQDN` (self-hosted-instance variable), `registries.gitlab_instance_host` unset | Version resolution skipped; informational diagnostic explains the host could not be statically determined and names the setting as the remedy (FR-012) — the parsed reference is still shown in hover, without version data |
| Same, but `registries.gitlab_instance_host` is set | Resolved against the configured host; no informational diagnostic (FR-011a) |
| `include: - project:` entry (which never carries a host segment) | Treated exactly as the `$CI_SERVER_FQDN` case above — skipped when the setting is unset, resolved against it when set (FR-011a) |
| `component:` include names a literal host that is **not** the token host (e.g. `attacker.example`, or any self-hosted host with the setting unset) | Fetched **without** the `PRIVATE-TOKEN` header — never authenticated. Public data still resolves; private data returns 404/403 and degrades per the rows below (FR-005a) |
| `component:` names `gitlab.com` while `registries.gitlab_instance_host` is set to a self-hosted instance | Fetched **unauthenticated**: the configured host replaces `gitlab.com` as the token host, so a corporate PAT is never sent to `gitlab.com` (FR-005a) |
| `component:` host is a suffix lookalike of the token host (`gitlab.com.attacker.example`) or differs only by case/trailing dot | Not treated as the token host — the comparison runs on the normalized ASCII-serialized origin, so no token is attached (FR-005a) |
| A single GitLab CI file names many distinct `component:` hosts | At most 8 distinct literal hosts per document are routed; further distinct hosts are logged and skipped (no version resolution, no diagnostic beyond FR-012's informational one). Bounds the per-`didOpen` DNS/TLS/HTTP-client fan-out that would otherwise be driven directly by file content |
| A `component:` pin resolves to a tag that exists in the repository but was never published as a release | Treated as unresolvable, not as a version: the release list is the only candidate source (FR-004/FR-007), so no outdated diagnostic and no FR-010 code action offers it |
| A GitLab CI file uses the multi-document `spec:` header form (`spec: … \n--- \n job:`) | Both documents are parsed; per-document parser state is reset at the document boundary, so document 1's nesting never mis-scopes document 2's top-level `include:` |
| `registries.gitlab_instance_host` is set to a non-https, userinfo-bearing, loopback, link-local, private or cloud-metadata host | Logged **and surfaced to the user via `window/showMessage`**, and treated as unset for host resolution — but, unlike a genuinely unset setting, the token host is **not** `gitlab.com`: `PRIVATE-TOKEN` is disabled entirely until the value is corrected. A rejected value must never become — nor silently fall back to — a token destination the user did not configure (FR-005a/FR-011a; #466 review security fix) |
| Hover on a `component:` include vs. a `project:` include | A `project:` include renders the standard hover heading link to the project. A `component:` include renders no heading link — its name ends in the component segment, which is not part of the project URL — and instead carries the project link as a line in the hover body. Declared NFR-004 carve-out; every other surface is identical for both kinds |
| Version completion invoked on an include whose host is unresolved (FR-012) | Returns no completion items. The include has no resolvable host, so it has no version list to complete from — consistent with its lack of hover version data and outdated diagnostic, not an additional divergence |
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
| SC-003 | Hover shows current + latest version for `component:` includes | 100% of resolvable component includes show hover content listing current release-name pin and latest matching release, resolved from the project's **release** list (never the raw tag list) using semver-range matching rather than literal-tag equality |
| SC-004 | Outdated diagnostics match version comparison | 100% agreement between outdated diagnostics count and the actual count of include pins behind their latest resolvable version |
| SC-005 | GitLab API quota preservation | Conditional-request hit rate ≥ 80% on repeated hovers of unchanged GitLab CI files |
| SC-006 | Cross-ecosystem consistency | GitLab CI behavior (hover format, diagnostic language, inlay-hint templates) verified identical to same scenarios in other ecosystems, documented in `.local/testing/coverage.md` LSP Feature Matrix |
| SC-007 | Access-token support | Optional access-token environment variable correctly increases GitLab API quota when configured, sent via `PRIVATE-TOKEN` header, verified via mock rate-limit responses |
| SC-007a | Token-host containment (FR-005a) | `PRIVATE-TOKEN` is present on the wire for exactly one host — `gitlab.com` with the setting unset, the configured `gitlab_instance_host` with it set — and absent for every other host, including `gitlab.com` once a self-hosted instance is configured and including a suffix lookalike of the token host; verified on mocked requests, not on an internal predicate |
| SC-007b | Instance-host resolution (FR-011a) | For a document opened **after** the setting is applied: with `registries.gitlab_instance_host` unset, a `project:` include produces the FR-012 informational diagnostic and zero registry calls; with it set, the same include resolves and shows current + latest version. **Known limitation:** a `workspace/didChangeConfiguration` that changes this setting does not re-parse or re-fetch documents that are already open — the server has no re-parse-on-config-change mechanism for any ecosystem (`did_change_configuration` refreshes diagnostics but never re-parses), so an already-open file picks the change up on its next edit or reopen. The same limitation applies today to `registries.workspace_registries` and `registries.nuget_user_profile_sources`; closing it server-wide is tracked as a separate follow-up, not as part of this ecosystem |
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
  Questions): a new `GitlabApiClient` struct, parallel to but not derived from
  `deps_core::github::GithubTagsClient`, taking the host as a per-call argument instead of a module
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
  This bans *inference only*. An explicitly user-configured `registries.gitlab_instance_host`
  (FR-011a) is not covered by it — the user declared that host, the system did not guess it.
- Attach `PRIVATE-TOKEN` to any host other than FR-005a's single token host, or compare a
  host against it as a raw string rather than as a normalized origin. In particular, never
  keep `gitlab.com` authenticated once `registries.gitlab_instance_host` names a different
  instance — one `GITLAB_TOKEN` is valid for one instance, so a union would send a corporate
  PAT to `gitlab.com`.
- Resolve a `component:` pin against the repository-tags list. Component versions come from
  the releases endpoint (FR-004/FR-007); an unreleased tag is not a component version.

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
   `GitlabApiClient`, parallel to `deps_core::github::GithubTagsClient` but taking the target host as a
   per-call argument rather than a fixed module constant, since GitLab references may target self-hosted
   instances per NFR-008; it serves both the tags and the releases endpoint over one credential path).
   The `component:` release-name/semver-range resolution layers on top of that shared client as a
   separate, focused function — not a second registry implementation.
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
9. **Instance-host configuration and the single token host** (FR-005a, FR-011a — added
   2026-09-04 during `/sdd plan`, resolved by the issue owner the same day). The plan phase
   surfaced two gaps in the FR set above that the `specify` phase had not anticipated:
   - `include: - project:` carries **no host segment in GitLab's syntax at all** — the
     instance is always implicit. FR-011 as originally written is therefore unreachable for
     `project:` includes, and under Decision 1 alone every one of them would fall into
     FR-012's skip, making US-001 undeliverable and SC-002 vacuous.
   - Nothing constrained which host `GITLAB_TOKEN` may be sent to. Since an include's host
     segment is content read out of a checked-in manifest, an untrusted repository could
     direct the token to a host of its choosing via `PRIVATE-TOKEN`.

   Both are answered by one opt-in setting, `registries.gitlab_instance_host` (default
   unset): it names the instance that host-less and `$CI_SERVER_FQDN`-relative references
   resolve against, and it names the one host the token may be sent to, **replacing** the
   `gitlab.com` default rather than being added to it. The replace-not-union shape was
   corrected during design review on 2026-09-04: a union would attach a corporate
   self-hosted PAT to any `component:` include naming `gitlab.com` that appears in a cloned
   repository, and a GitLab PAT is only ever valid for the instance that issued it, so the
   union has no legitimate use to trade against that leak.
   With the setting unset, behavior is byte-identical to Decision 1 — nothing is guessed.
   This does **not** reverse Decision 1: that decision rejected *inferring* a host (a
   hardcoded default, or git-remote inference); an explicit user declaration is not an
   inference, and it is the same mechanism Renovate exposes as `endpoint`. Rejected
   alternatives: accepting US-001 as a permanent no-op, and narrowing v1 to `component:`
   includes only.

No `[NEEDS CLARIFICATION]` markers remain in this spec.

## 10. See Also

- #208 — GitHub Actions workflow `uses:` pins ecosystem candidate, spec [[014-github-actions-ecosystem/spec]]
  (still unimplemented, P4). Same git-tags-datasource pattern, sibling new-ecosystem candidate; the
  `project:`+`ref:` include form here is structurally identical to GHA's `owner/repo@ref`.
- #466 — implementation follow-up issue for this spec. Was blocked on #208 shipping and on resolving 8
  open `[NEEDS CLARIFICATION]` items; both are now resolved (see §9) — ready for `/sdd plan`.
- `crates/deps-core/src/github.rs` — the hosted-git-platform REST integration this one parallels: token
  env-var handling, `github_rate_limit_error` (line 129, the rate-limit message shape FR-014 mirrors),
  `validate_owner_repo`, and the tags pagination loop. GitHub-specific auth scheme (`Authorization: Bearer`),
  not directly reusable for GitLab's `PRIVATE-TOKEN` header
- `crates/deps-github-actions/src/registry.rs` (`map_tags_error`, line 216) — the status-code-to-`DepsError`
  mapping FR-014's GitLab variant is shaped after (with different arms: GitLab rate-limits with `429`)
- `crates/deps-go/src/registry.rs` + `crates/deps-go/src/ecosystem.rs` — the per-dependency routing precedent
  (`register_chain`, `alternates`, `MAX_ALTERNATE_REGISTRIES`, `get_versions_from` dispatch) this spec's
  host routing and its fan-out bound follow
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

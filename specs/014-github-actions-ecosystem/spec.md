---
aliases:
  - GitHub Actions Ecosystem
  - GHA Version Hints
tags:
  - sdd
  - spec
  - research
  - ecosystem/github-actions
  - new-ecosystem
  - priority/p4
created: 2026-08-23
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: New ecosystem — GitHub Actions workflow `uses:` pins

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-github-actions`]
> **Type**: research / new ecosystem

## 1. Overview

### Problem Statement

GitHub Actions workflows (YAML files in `.github/workflows/`) use the `uses:` syntax to reference
external actions and reusable workflows. These references take the form `owner/repo@ref` where `ref`
can be a branch name, a moving major tag (e.g., `v3`), a full semver tag (e.g., `v3.5.1`), or a
specific commit SHA.

deps-lsp currently provides no support for `.github/workflows/*.yml` files, leaving users without
in-editor visibility into whether their action pins are outdated or resolvable. This is a
particularly acute gap: GitHub Actions are the most-used CI/CD platform on GitHub (~every GitHub
repository has workflows), making this the largest-audience new-ecosystem candidate. The closest
competitor (Dependi) has an open, unserved feature request for this capability (#239, user
demand), while Dependabot and Renovate both support it natively.

The 2025 supply-chain security wave around action pinning (spurred by high-profile compromises in
widely-used actions like tj-actions) has made "this SHA equals which tag? Is a newer version
available?" a relevant security/maintenance question for production workflows.

### Goal

deps-lsp detects `.github/workflows/*.yml` (and `.yml`/`.yaml` variants) as manifest files,
parses `uses: owner/repo@ref` actions (and reusable workflow calls `owner/repo/.github/workflows/x.yml@ref`,
skipping `./local` and `docker://` forms gracefully), fetches version information from GitHub REST API tags/releases
with rate-limit-aware caching (conditional requests with ETag/If-None-Match; optional GitHub Personal Access Token for
unauthenticated budget overflow), and surfaces hover (ref → resolved tag + latest available), outdated diagnostics,
inlay hints, and update code actions — consistent with all other 11 supported ecosystems.

### Out of Scope

- `pre-commit` hook `rev:` pins (`.pre-commit-config.yaml` — same git-tags datasource, but a
  separate manifest format; filed as a follow-up for after this ecosystem is shipped).
- Composite action calls within action subdirectories (e.g., `owner/repo/path/to/action@ref`) beyond
  the basic parsing and graceful skip documented in requirements.
- GitHub App rate-limit headers (X-RateLimit-*) beyond the existing ETag-based conditional-request
  quota preservation.
- Rollback/undo semantics for batch updates to multiple action pins in one `WorkspaceEdit`.
- Workspace-wide aggregation or "update all actions in all workflows" — scoped to per-document
  (per-workflow) scope, consistent with other manifests.

## 2. User Stories

### US-001: See outdated action pins in-editor

AS A DevOps engineer maintaining GitHub Actions workflows with explicit commit SHAs pinned for
supply-chain security
I WANT to see at a glance which action pins are outdated (i.e., which SHAs correspond to older tags
than the latest available) and what newer versions are available
SO THAT I can decide whether to accept security/feature updates without leaving the editor to check
GitHub release pages.

**Acceptance criteria:**
```
GIVEN a workflow file with one or more actions pinned to specific commit SHAs or
      semantic-version tags
WHEN the editor requests hover over an action reference (e.g., `uses: actions/setup-node@v3.5.1`)
THEN the server SHALL show:
     - The resolved tag (if the ref is a SHA, what tag does it map to?)
     - The latest available tag
     - Whether the current pin is outdated
     - A code action to update the pin to the latest version
```

### US-002: Hover on a moving major tag shows the resolved commit

AS A user with a workflow pinning to a moving major tag (e.g., `actions/setup-node@v3`)
I WANT to hover over that pin and see what specific version that major tag currently resolves to
(e.g., "v3.5.1", commit SHA xyz)
SO THAT I understand the exact behavior my workflow will get.

**Acceptance criteria:**
```
GIVEN a workflow file with an action pinned to a moving tag (e.g., `uses: owner/repo@v3`)
WHEN the editor requests hover for that reference
THEN the server SHALL resolve that tag to the latest matching release and display the concrete
     semver or commit SHA it resolves to
```

### US-003: Update action pins with SHA-to-tag conventions

AS A user updating an action pin from a SHA to a newer commit
I WANT the update code action to preserve the Dependabot/Renovate convention of trailing comments
(e.g., `uses: actions/setup-node@abc123def456 # v4.2.0`) documenting which tag that SHA maps to
SO THAT future readers (including automation) can quickly see which version the SHA corresponds to.

**Acceptance criteria:**
```
GIVEN a workflow file with an action pinned to a SHA (with or without a trailing tag comment)
WHEN the user invokes an "update action pin" code action
THEN the system SHALL produce a new SHA pinned to the latest tag and include a trailing
     comment (e.g., `# v4.2.0`) indicating the tag, following Dependabot/Renovate convention
```

### US-004: Consistent diagnostics and hints across all workflows

AS A developer with multiple workflows in `.github/workflows/`
I WANT the outdated diagnostics, hover, inlay hints, and update actions to work identically
across all workflows I open
SO THAT I don't have to learn workflow-specific quirks.

**Acceptance criteria:**
```
GIVEN two or more workflow files with equivalent action-pin scenarios
WHEN the server processes both files
THEN the diagnostics, hover, inlay hints, and code action behavior SHALL be identical
     across both, per the project's cross-ecosystem-consistency rule
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect `.github/workflows/*.yml` and `.github/workflows/*.yaml` files by path pattern (not filename match) and register them as manifest documents — routing through the existing LSP document-lifecycle handlers (didOpen, didChange, didClose) | must |
| FR-002 | THE SYSTEM SHALL parse YAML workflow files, extract all `uses:` entries in `steps[]` and (open question: reusable workflow calls) sections, and identify action/workflow references in the form `owner/repo@ref` or `owner/repo/.github/workflows/name.yml@ref` | must |
| FR-003 | THE SYSTEM SHALL skip and gracefully handle (without error or false diagnostic) `uses: ./local` (relative path actions) and `uses: docker://image:tag` (container actions) — these are not version-pinnable and should not surface diagnostics | must |
| FR-004 | THE SYSTEM SHALL fetch version information from GitHub REST API tags endpoint (`GET /repos/{owner}/{repo}/tags`) using the existing `HttpCache` with conditional-request validation (ETag/If-None-Match headers) to minimize API quota consumption — unauthenticated requests have a 60 req/hr budget; conditional requests (304 Not Modified) do not consume quota | must |
| FR-005 | THE SYSTEM SHALL advertise optional configuration for a GitHub Personal Access Token (PAT) to increase the unauthenticated rate limit from 60 req/hr to 5000 req/hr — via environment variable `GITHUB_TOKEN` (matching the convention already established in `crates/deps-swift/src/registry.rs`, lines 48-56) | must |
| FR-006 | WHEN an action reference uses a semantic-version tag (e.g., `v3.5.1`) THE SYSTEM SHALL surface hover content showing the tag, resolved commit SHA, latest tag, and outdated status — consistent with how other ecosystems display version information | must |
| FR-007 | WHEN an action reference uses a moving major tag (e.g., `v3`) THE SYSTEM SHALL resolve the tag to the latest matching release and display the concrete version (e.g., "v3.5.1") and commit SHA in hover content | must |
| FR-008 | WHEN an action reference uses a commit SHA (with or without a trailing `# vX.Y.Z` comment) THE SYSTEM SHALL resolve the SHA to the tag it maps to (if it exists) and surface that tag in hover alongside the latest available tag | must |
| FR-009 | THE SYSTEM SHALL produce an outdated diagnostic (warning or info level, consistent with how diagnostics treat "outdated" in other ecosystems) on any action pin where the current reference is behind the latest resolvable tag | must |
| FR-010 | THE SYSTEM SHALL produce inlay hints showing the latest version for each action, consistent with the format and configuration (per-ecosystem `EcosystemConfig`) already used in other ecosystems | must |
| FR-011 | THE SYSTEM SHALL expose a code action (via `textDocument/codeAction`) on any action pin, offering to update it to the latest tag — the update SHALL include a trailing comment documenting the tag (e.g., `uses: actions/setup-node@abc123def456 # v4.2.0`), following Dependabot/Renovate convention [NEEDS CLARIFICATION: trailing comment format — exact conventions used by Dependabot/Renovate] | must |
| FR-012 | THE SYSTEM SHALL route GitHub API requests through the existing `deps-lsp.executeCommand` handler (or extend it) rather than introducing a parallel execution pathway; the "update action pin" command SHALL apply the version change as a `WorkspaceEdit` consistent with how other ecosystems perform updates | should |
| FR-013 | THE SYSTEM SHALL produce equivalent behavior (hover, diagnostics, inlay hints, code actions) across all workflows and all action references, not introducing ecosystem-specific divergence — any GitHub-ecosystem-specific behavior must be documented and justified | must |
| FR-014 | WHEN the GitHub API returns a 403 Forbidden (rate limit exceeded) without a valid `GITHUB_TOKEN` set THE SYSTEM SHALL display a user-facing error message recommending the user set `GITHUB_TOKEN` to increase the quota, consistent with how `crates/deps-swift/src/registry.rs` lines 82-86 handles the same situation | must |
| FR-015 | WHEN parsing a workflow file where an action reference is unparseable or the owner/repo is malformed THE SYSTEM SHALL log a warning and skip that reference gracefully (no diagnostic, no crash) — the workflow itself remains parseable | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Fetching action version lists from GitHub API SHALL use conditional requests (ETag/If-None-Match) to avoid quota consumption on cache hits; response time for `textDocument/hover` or `textDocument/codeAction` on a cached action reference SHALL be dominated by in-memory YAML parsing and cached lookup, not network I/O |
| NFR-002 | Rate limiting | Unauthenticated GitHub API budget (60 req/hr) is the primary constraint; the system SHALL use long TTLs and aggressive conditional-request revalidation (304s) to fit within this budget for typical workflows; optional PAT support SHALL transparently increase the limit to 5000 req/hr when `GITHUB_TOKEN` is set |
| NFR-003 | Reliability | When GitHub API is unreachable (network error, timeout) or rate-limited (403 with no token), the system SHALL degrade gracefully: cached action data (if available) is served; if no cache exists, diagnostics/hovers show loading state or minimal information, not false positives or errors |
| NFR-004 | Consistency | Action-pin behavior (hover format, diagnostics language, inlay-hint presentation, code-action wording) SHALL be identical across all 12 supported ecosystems (the existing 11 + GitHub Actions), per the cross-ecosystem-consistency rule in `.claude/rules/continuous-improvement.md` — any divergence is a first-class bug |
| NFR-005 | YAML parsing | YAML workflow files are parsed using the existing `yaml-rust2` crate (already used in `deps-dart` for `pubspec.yaml`, and hardened in recent PRs #174/#176); no new YAML dependency SHALL be introduced |
| NFR-006 | Path detection | `.github/workflows/*.yml` and `.*.yaml` detection SHALL be added to the manifest-detection routing without breaking existing filename-based detection; [NEEDS CLARIFICATION: whether path-pattern-based detection requires a new trait method on `Ecosystem` or can be hardcoded in the server's manifest router] |
| NFR-007 | Caching | Conditional-GET support already exists in `HttpCache` (RFC 7232, ETag/If-None-Match, verified in `crates/deps-core/src/cache.rs` lines 109-144); no new caching infrastructure is required |

## 5. Data Model

No new persistent entities. Action references are parsed as dependencies (with `name = "owner/repo"`,
`version_requirement = "ref"`) and reuse the existing `Dependency` trait and `cached_versions`/`resolved_versions`
maps from `DocumentState`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Action reference (derived) | Per-action entry in a workflow, identified by `uses:` key | owner, repo, ref (tag/SHA/branch), resolved_sha (if applicable), resolved_tag (if applicable), latest_tag |
| GitHub tag list (cached) | Response from GitHub REST API `/repos/{owner}/{repo}/tags`, cached per (owner/repo) | tag names, commit SHAs, creation timestamps |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Workflow file with zero action references | No diagnostics returned (empty list) |
| Action reference using `./local` (relative path action) | Parsed but skipped gracefully — no diagnostic, no version check, no hover |
| Action reference using `docker://image:tag` | Parsed but skipped — container images are not version-pinnable in the same way |
| Action reference with a malformed `owner/repo` (e.g., missing `/`, extra segments) | Logged as a warning, skipped gracefully; workflow parsing continues |
| Action reference where the repository does not exist (404 from GitHub API) | Diagnostic: "Repository not found: owner/repo"; no version data shown |
| Workflow file is edited while version data is being fetched | Subsequent `textDocument/hover` request on the new content SHALL trigger a fresh parse and fetch; old loading state is discarded |
| GitHub API returns 403 Forbidden (rate limit exhausted) and no `GITHUB_TOKEN` is set | User-facing error message: "GitHub API rate limit (60 req/hr unauthenticated) exhausted. Set GITHUB_TOKEN to increase limit to 5000 req/hr: export GITHUB_TOKEN=$(gh auth token)" |
| Action reference to a moving major tag (e.g., `v3`) at a time when the tag exists but has no associated GitHub release | Tag is resolved to its current commit SHA and displayed in hover; if no release exists, latest resolved tag (not pre-release) is shown |
| Workflow file is not valid YAML | Parse error is logged; no diagnostics produced; handlers gracefully return empty results (consistent with how other ecosystems handle malformed manifests) |
| Very large workflow (hundreds of action references) | Parsing and hover latency SHALL remain acceptable (<1s per request); no new registry calls are made beyond one per unique (owner/repo) pair, cached thereafter |
| Action reference with a tag that has been deleted but still exists in cached ETag data | Conditional request returns 304 Not Modified, cached data served (tag still exists in cache) — will age out when TTL expires [NEEDS CLARIFICATION: should deleted tags trigger a forced refresh, or accept stale cached data?] |
| Action in a composite action (e.g., `uses: ./my-composite-action`) with a nested `uses:` inside its `action.yml` file | Out of scope — composite actions are a more complex multi-file parsing problem. See Also / Follow-up work |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Path-pattern detection for `.github/workflows/*.yml` | Detected and routed to the GitHub Actions ecosystem for all supported `.yml` and `.yaml` extensions |
| SC-002 | Hover shows current + latest tag for action pins | 100% of action references with resolvable tags show hover content listing current tag/SHA and latest available tag |
| SC-003 | Outdated diagnostics match version comparison | 100% agreement between outdated diagnostics count and the actual count of action pins behind their latest tag |
| SC-004 | GitHub API quota preservation | Conditional-request (ETag/If-None-Match) hit rate ≥ 80% on repeated hovers of unchanged workflows (measured via log inspection and rate-limit header observation) |
| SC-005 | Code action produces valid YAML + trailing comment | Code actions that update action pins produce syntactically valid YAML and include trailing `# vX.Y.Z` comments per Dependabot/Renovate convention, verified via round-trip parse |
| SC-006 | Cross-ecosystem consistency | GitHub Actions behavior (hover format, diagnostic language, inlay-hint templates) verified identical to same scenarios in other ecosystems, documented in `.local/testing/coverage.md` LSP Feature Matrix |
| SC-007 | PAT support | Optional `GITHUB_TOKEN` environment variable correctly increases GitHub API quota from 60 to 5000 req/hr, verified via mock rate-limit headers |
| SC-008 | Graceful degradation | Workflows with invalid action references or unreachable repositories do not prevent other actions in the same workflow from being processed; malformed actions log warnings and are skipped |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing patterns in `crates/deps-core/` for ecosystem implementation (trait-based `Ecosystem`,
  `Registry`, `ParseResult`, `Dependency`; reuse `HttpCache` for API calls).
- Use `yaml-rust2` (already a deps-dart dependency, hardened in #174/#176) for YAML parsing.
- Reuse the existing `deps-swift` GitHub API token handling pattern (`GITHUB_TOKEN` environment variable,
  60 vs 5000 req/hr messaging).
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features
  --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any
  implementation complete.

### Ask First
- Introducing a new path-pattern-based manifest detection method (vs. extending the existing
  filename/extension routing in `EcosystemRegistry`); the `get_for_uri()` implementation currently
  extracts only the final path segment (filename) and may need architectural change to support patterns.
- Changing the `Ecosystem` trait to add a new detection method (e.g., `manifest_path_patterns()`) vs.
  hardcoding the `.github/workflows/*.yml` pattern in the server's manifest router.
- Adding configuration UI for the GitHub PAT beyond environment-variable support (e.g., `initializationOptions`,
  config file, or workspace settings).

### Never
- Introduce ecosystem-specific divergence in hover format, diagnostic wording, or code-action behavior
  without a documented, justified reason — all 12 ecosystems must be consistent per the
  cross-ecosystem-consistency rule.
- Recursively parse composite-action definitions or reusable-workflow calls beyond the single-level
  `owner/repo/.github/workflows/name.yml@ref` syntax.
- Attempt to resolve version constraints *within* action inputs (e.g., action parameters that
  themselves contain version-like values) — only the `uses:` pin itself is versioned.

## 9. Open Questions

- [NEEDS CLARIFICATION: Should reusable workflow calls (`uses: owner/repo/.github/workflows/x.yml@ref`)
  be parsed and version-checked, or are they out of scope for the first iteration? Current parity
  research shows Dependabot/Renovate both support them, but the spec as written assumes single-level
  action references only.]
- [NEEDS CLARIFICATION: When a composite action declares its own `uses:` in its `action.yml`, should
  the system recursively parse and check those nested references, or treat composite actions as
  atomic/opaque? Multi-file parsing is likely out of scope for phase 1.]
- [NEEDS CLARIFICATION: Exact trailing-comment format convention — is `# v3.5.1` the de facto standard,
  or do Dependabot/Renovate use a different format (e.g., `# v3.5.1` vs `# vX.Y.Z` vs `# tag: v3.5.1`)?
  Should the format be configurable, or hardcoded?]
- [NEEDS CLARIFICATION: When a tag is deleted from the repository, should cached data for that tag
  age out at TTL expiry, or should the system detect deletion via a forced refresh (e.g., if GitHub
  returns a new tag list without the old tag)?]
- [NEEDS CLARIFICATION: How should the system handle actions in private repositories? GitHub API 404s
  for repos the token doesn't have access to, but the user might have the repo cloned locally. Should
  the system attempt to fall back to local git data, or accept "private repo, no version info available"?]
- [NEEDS CLARIFICATION: Should path-pattern detection be added as a new trait method on `Ecosystem`
  (e.g., `manifest_path_patterns() -> &[&str]`), or hardcoded in the server's manifest router as a
  special case for GitHub Actions?]
- [NEEDS CLARIFICATION: No project constitution exists at `.local/specs/constitution.md` — cannot yet
  validate this spec against project-wide architectural principles. Recommend running `/sdd init` before
  `/sdd plan` for this feature.]
- [NEEDS CLARIFICATION: Should "pin to latest" code action also offer a "pin to latest with major filter"
  (e.g., if current is v3.x, pin to latest v3.y, not v4)? Dependi's #231 suggests this is a user expectation.]

## 10. See Also

- `crates/deps-swift/src/registry.rs` (lines 12-95) — closest existing precedent for GitHub REST API
  integration, including GITHUB_TOKEN env var handling and rate-limit messaging
- `crates/deps-core/src/cache.rs` (lines 109-144) — HttpCache implementation with RFC 7232 conditional
  requests (ETag/If-None-Match) already in place; no new caching work needed
- `crates/deps-dart/src/parser.rs` — YAML parsing with yaml-rust2; established pattern for YAML
  manifest files
- `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` — consistency rule
  requiring identical behavior across all ecosystems; violations are first-class bugs
- [GitHub Actions workflow syntax documentation](https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions)
- [GitHub REST API: List repository tags](https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#list-repository-tags)
- [Dependabot supported ecosystems](https://docs.github.com/en/code-security/dependabot/ecosystems-supported-by-dependabot/supported-ecosystems-and-repositories)
- [Renovate managers](https://docs.renovatebot.com/modules/manager/) (includes `github-actions`)
- [NX10 GitHub Actions Version Checker](https://marketplace.visualstudio.com/items?itemName=nx10.gha-version-checker) — existing VS Code extension in this domain
- Dependi feature request: [#239 — GitHub Actions support](https://github.com/filllabs/dependi/issues/239) (open, unserved)
- [[MOC-specs]] — all specifications
- [[007-lightweight-registry-metadata/spec]] — related registry-optimization work
- [[002-osv-vulnerability-diagnostics/spec]] — related diagnostics work
- Pre-commit ecosystem (`.pre-commit-config.yaml` with `rev:` pins) — same git-tags datasource
  as GitHub Actions, filed as follow-up work in the playbook

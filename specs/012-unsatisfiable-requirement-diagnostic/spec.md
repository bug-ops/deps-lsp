---
aliases:
  - Unsatisfiable Requirement Diagnostic
  - No Matching Version Diagnostic
tags:
  - sdd
  - spec
  - enhancement
  - parity-gap
  - diagnostics
  - priority/p3
created: 2026-08-23
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Diagnostic for version requirements matching zero published versions

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-unsatisfiable-requirement-diagnostic`]
> **Type**: enhancement / competitive-parity gap — this spec documents WHAT is missing and WHY;
> the HOW (diagnostic severity, code action target, prerelease interaction) is deferred to a future `/sdd plan` session.

## 1. Overview

### Problem Statement

deps-lsp computes and renders three types of version-status diagnostics for dependencies:
1. **Unknown package** (WARNING) — package name does not exist in registry
2. **Yanked version** (WARNING) — the matching version was yanked
3. **Newer version available** (HINT, `Outdated` status) — requirement is satisfied by current version, but not by latest

There is no fourth type: **unsatisfiable requirement**. When a declared requirement matches zero
published versions (e.g., `serde = "2"` while latest is 1.x, or a constraint like `>=3.0 <3.1`
that no release satisfies), the dependency is currently **silent** — it appears neither outdated
nor current. The user discovers the problem only at build/install time, when their package manager
rejects the requirement.

Verified by:
- Live reproduction: `serde = "2"` in a `Cargo.toml` shows no diagnostic until build-time failure.
- Competitive evidence: crates.nvim (Neovim Rust tooling) renders an explicit "No match" indicator;
  Dependi (VS Code dependency extension, closest competitor) has this filed as a bug (#221:
  "higher versions accepted in Cargo, no error").
- Registry data availability: deps-lsp already fetches the full version list per package
  (`.local/testing/playbooks/competitive-parity.md`, Scan Notes 2026-08-23); this diagnostic
  requires pure comparison logic, not new data sources.

### Goal

deps-lsp detects when a declared requirement matches zero published versions in the fetched
version list and renders a warning diagnostic ("no published version satisfies requirement;
latest is X") at the requirement span. A code action suggests updating the requirement to a
satisfiable value (reusing the existing version-update WorkspaceEdit pathway).

### Out of Scope

- Exact wording, icon, or UI placement of the diagnostic message — these are HOW details for
  `/sdd plan`.
- Interaction with prerelease-only matches (requirement satisfiable only by pre-release versions)
  — whether this is a distinct diagnostic, a flag on the primary one, or a separate state is a
  HOW decision; marked as open question below.
- Requirements the ecosystem's own resolver would reject anyway (e.g., syntax errors, invalid
  operators) — those are typically caught by the ecosystem's parser, not deps-lsp's version
  comparison.
- Graceful degradation when offline or version-list unavailable (must not false-positive on
  network failure) — this is covered by existing diagnostics' graceful-degradation behavior
  (no diagnostic if version list is empty/loading) and inherited here without redesign.
- Cross-file / workspace-wide aggregation of unsatisfiable requirements — this is a per-dependency,
  per-document diagnostic scoped to the same level as "Newer version available."

## 2. User Stories

### US-001: Surface impossible requirements early

AS A developer with a manifest containing a requirement that no published version can satisfy
(e.g., `serde = "2"` when the latest stable is 1.x)
I WANT an in-editor warning diagnostic at that requirement line
SO THAT I catch the error during editing rather than at build/install time.

**Acceptance criteria:**
```
GIVEN a manifest with a dependency whose declared requirement matches zero published versions
WHEN the editor requests textDocument/diagnostic for that document
THEN the server SHALL return a warning diagnostic at the requirement span communicating that
     no version satisfies it, and optionally showing the latest version (e.g., "no published
     version satisfies requirement; latest is 1.5.0")
```

### US-002: Distinguish from "up to date"

AS A developer reviewing a manifest
I WANT to immediately tell the difference between:
  - a dependency where the current version is up to date (no diagnostic)
  - a dependency where the current version is outdated but a newer one exists ("Newer version available" HINT)
  - a dependency where **no version ever satisfies** the requirement (warning diagnostic)
SO THAT I understand the urgency and nature of each issue.

**Acceptance criteria:**
```
GIVEN a manifest with three dependencies:
     - dep-a@1.0 (requirement "^1" matches latest 1.5.0, up to date)
     - dep-b@1.0 (requirement "^1" but latest is 2.0.0, outdated)
     - dep-c@2 (requirement "2" but latest is 1.5.0, unsatisfiable)
WHEN the editor requests textDocument/diagnostic
THEN the server SHALL return:
     - no diagnostic for dep-a
     - HINT diagnostic "Newer version available: 2.0.0" for dep-b
     - WARNING diagnostic communicating unsatisfiable requirement for dep-c
```

### US-003: Consistent behavior across all 11 supported ecosystems

AS A developer using deps-lsp with any of the 11 supported ecosystems (Cargo, npm, PyPI, Go,
Bundler, Dart, Maven, Composer, Gradle, Swift, NuGet)
I WANT the unsatisfiable-requirement diagnostic to appear consistently when a requirement
matches zero versions, regardless of ecosystem
SO THAT I don't have to learn ecosystem-specific diagnostic quirks.

**Acceptance criteria:**
```
GIVEN manifests from different ecosystems (e.g., Cargo.toml, package.json, pyproject.toml)
     each containing a requirement that matches zero published versions
WHEN textDocument/diagnostic is requested for each
THEN the diagnostic SHALL be present for all, with equivalent severity and message format,
     per the project's cross-ecosystem-consistency rule
     (`.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing`)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a dependency's parsed requirement is submitted to the ecosystem-specific version-comparison logic AND no published version in the fetched registry version list satisfies it THE SYSTEM SHALL generate a warning diagnostic at the requirement span (not the package name span, consistent with "Newer version available" placement) | must |
| FR-002 | THE SYSTEM SHALL reuse the existing version-list data already fetched and cached for diagnostics/inlay hints (no new registry calls) by computing "zero matching versions" within the `generate_diagnostics_from_cache` / `generate_diagnostics` pathway in `deps-core/src/lsp_helpers.rs` | must |
| FR-003 | THE SYSTEM SHALL include in the diagnostic message the latest stable version (or a note that no stable version exists, if all versions are pre-release or yanked) to guide the user toward a satisfiable alternative | must |
| FR-004 | THE SYSTEM SHALL NOT emit this diagnostic when the version list is empty, still loading, or unavailable (offline) — the existing graceful-degradation behavior for cached versions applies unchanged | must |
| FR-005 | THE SYSTEM SHALL NOT emit this diagnostic for special requirement forms that are not subject to version-list matching: wildcard requirements (`*`, `latest`, etc. per ecosystem), workspace dependencies, path dependencies, git/URL dependencies, or unresolved variables (Gradle `$var`, Maven `${property}`) — these are handled by `requirement_is_unresolved()` logic or ecosystem-specific guards and must remain unchanged | must |
| FR-006 | THE SYSTEM SHALL provide a code action (invoked from the diagnostic) that suggests updating the requirement to a satisfiable value, reusing the existing `deps-lsp.updateVersion` command pathway or a new variant of it to specify the target version (one of: latest stable, highest available non-prerelease, or configurable per ecosystem) | should |
| FR-007 | THE SYSTEM SHALL produce equivalent unsatisfiable-requirement detection across all 11 supported ecosystem crates (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-go`, `deps-bundler`, `deps-dart`, `deps-maven`, `deps-composer`, `deps-gradle`, `deps-swift`, `deps-nuget`), per the cross-ecosystem-consistency rule | must |
| FR-008 | WHEN a manifest is edited (requirement text changes) the next textDocument/diagnostic request SHALL reflect the new unsatisfiable state — no stale caching of "this requirement is unsatisfiable" across requirement changes | must |
| FR-009 | [NEEDS CLARIFICATION: prerelease handling] WHEN a requirement matches zero stable versions but does match one or more pre-release versions, THE SYSTEM SHALL either: (A) emit an unsatisfiable diagnostic anyway (pre-releases don't count as satisfying), or (B) emit a distinct diagnostic ("matches only pre-release versions; latest stable is X"), or (C) suppress the diagnostic and rely on a separate prerelease-awareness feature. The choice determines whether prerelease-only matches are treated as unsatisfiable or a separate state. | depends-on-design |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Computing the unsatisfiable-requirement check SHALL NOT introduce additional registry (network) fetches beyond what diagnostics already perform — it SHALL operate on already-cached per-dependency version lists |
| NFR-002 | Performance | Checking "does any version in the list match the requirement" SHALL be O(N) in the number of versions per dependency, dominated by the existing version-comparison logic; diagnostic rendering SHALL NOT add measurable latency to `textDocument/diagnostic` responses |
| NFR-003 | Consistency | Unsatisfiable-requirement detection SHALL be identical across all 11 ecosystems — any ecosystem-specific divergence (e.g., one ecosystem emits the diagnostic, another silently ignores the same requirement) is a first-class bug per `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` |
| NFR-004 | Compatibility | Introducing unsatisfiable-requirement diagnostics SHALL NOT alter existing "Unknown package," "Yanked version," or "Newer version available" diagnostics' behavior — this is an additive diagnostic type |
| NFR-005 | Reliability | If the unsatisfiable-requirement check encounters an error during comparison (e.g., a version-parsing panic in the ecosystem's comparison logic), the system SHALL NOT crash the server or emit a malformed diagnostic — error handling SHALL be consistent with existing diagnostic-generation error modes |

## 5. Data Model

No new persistent entities. This feature adds a new case to the existing `RequirementStatus` enum
and/or version-matching logic in `deps-core`.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Unsatisfiable requirement (derived) | A dependency whose declared requirement matches zero versions in the fetched registry list | dependency name, declared requirement string, latest version (for diagnostic message), ecosystem-specific version-comparison result (no matches) |

The detection logic is computed on-the-fly during `generate_diagnostics_from_cache` /
`generate_diagnostics` by checking: for a given `(requirement_string, available_versions_list)`
pair, does the ecosystem's version-comparison predicate (already used for "Outdated" detection)
report that any version in the list satisfies the requirement? If not, emit diagnostic.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Requirement matches zero versions | Emit unsatisfiable-requirement warning diagnostic (primary case) |
| Requirement matches only yanked versions | [NEEDS CLARIFICATION: emit unsatisfiable, or treat yanked versions as non-existent for the purposes of this check?] — behavior depends on whether "no stable version matches" and "no version at all matches" are distinguished |
| Requirement matches only pre-release versions | [NEEDS CLARIFICATION: see FR-009; depends on prerelease-interaction design decision] |
| Manifest has empty version list (offline, network unavailable) | No diagnostic rendered (consistent with existing graceful degradation for "Unknown package" and "Newer version available") |
| Manifest has version list still loading | No diagnostic rendered (existing `LoadingState::Loading` skip applies) |
| Requirement is a wildcard (`*`, `latest`, etc.) or workspace/path/git/URL dependency | No diagnostic rendered (these are excluded by `requirement_is_unresolved()` or ecosystem-specific guards) |
| Requirement text contains environment markers or other conditional syntax (e.g., PEP 508 markers in PyPI) | Ecosystem's existing requirement-parsing logic applies; if the conditional is unresolvable, treated as `Unresolved`; if resolvable, unsatisfiable check proceeds (OR: ecosystem may short-circuit certain conditionals — behavior inherited from existing parsing, not redesigned here) |
| Very old requirement that used to match but no longer does (e.g., requirement `^1.0` when 1.x versions were published, now deleted) | Treated as unsatisfiable (no version exists that satisfies it today) — this is the expected behavior |
| Typo in requirement (e.g., `serde = "2.0.0.0"`, syntactically malformed) | Ecosystem's parser catches syntax errors; if the requirement parses to a valid constraint that matches zero versions, diagnostic is emitted; if parsing fails, handled by existing error paths (no version-match diagnostic rendered, possibly a parse error instead) |
| Registry response includes new versions since last fetch, now satisfying the requirement | On next cache refresh and diagnostic re-run, diagnostic disappears (requirement is no longer unsatisfiable); no sticky "was unsatisfiable" state |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Unsatisfiable-requirement diagnostic emitted for all test cases where requirement matches zero versions | 100% of manually-tested unsatisfiable cases produce the diagnostic |
| SC-002 | No false positives for satisfiable requirements | 0 diagnostics for requirements matching at least one version (stable, pre-release, or otherwise available) |
| SC-003 | Cross-ecosystem consistency | Unsatisfiable-requirement diagnostic verified present and equivalent across all 11 ecosystem manifest types in a live-testing session, logged in `.local/testing/coverage.md`'s LSP Feature Matrix |
| SC-004 | No additional registry calls introduced | 0 new outbound HTTP requests attributable to unsatisfiable-requirement detection, verified via debug log inspection per the project's live-testing protocol |
| SC-005 | Diagnostic does not render when version list unavailable | 0 false-positive unsatisfiable diagnostics when server is offline, cache is empty, or versions are still loading |
| SC-006 | Code action (if implemented) successfully updates requirement | Code action to "Update to latest version" or equivalent SHALL produce a valid, satisfiable requirement string via WorkspaceEdit, tested against at least one unsatisfiable case per ecosystem |

## 8. Agent Boundaries

### Always (without asking)
- Reuse existing version-matching logic in `deps-core`; do not duplicate comparison code.
- Emit the diagnostic in `generate_diagnostics_from_cache` / `generate_diagnostics` alongside
  existing diagnostics (Unknown package, Yanked, Newer version available).
- Respect the existing graceful-degradation behavior: no diagnostic if version list is empty,
  loading, or unavailable.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets
  --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`)
  before considering any implementation of this spec complete.
- Test the diagnostic across all 11 ecosystems via the project's live-testing protocol
  (`.local/testing/playbooks/`) before marking the feature done.

### Ask First
- Whether to emit a distinct diagnostic for "matches only pre-release versions" or fold it into
  the unsatisfiable category (depends on prerelease design decision in `/sdd plan`).
- Whether to emit a distinct diagnostic for "matches only yanked versions" — if yanked versions
  are treated as "non-existent" for matching purposes.
- Modifying the `RequirementStatus` enum or the `EcosystemFormatter` trait interface to surface
  a new state beyond `Unresolved` / `UpToDate` / `Outdated` (if that redesign is chosen over
  treating unsatisfiable as a fourth variant).
- Adding a new code action or command distinct from the existing `deps-lsp.updateVersion` to
  handle the "update to satisfiable" suggestion.

### Never
- Emit this diagnostic for requirements that are unresolved (Gradle `$var`, Maven `${property}`)
  — those already have separate handling and must remain unchanged.
- Emit this diagnostic for workspace, path, git, or URL dependencies — those are not version-list
  matched and must remain unchanged.
- Silence the existing "Unknown package," "Yanked version," or "Newer version available"
  diagnostics as a side effect of adding this one — all four types are independent.
- Introduce ecosystem-specific unsatisfiable-requirement logic that diverges from other ecosystems
  without an explicit, documented rationale approved in `/sdd plan`.

## 9. Open Questions

- [NEEDS CLARIFICATION: Prerelease-only matches (FR-009) — when a requirement matches zero
  stable versions but one or more pre-release versions, should this emit an unsatisfiable
  diagnostic (pre-releases don't count), a distinct "matches only pre-release" diagnostic, or
  no diagnostic at all? This design decision belongs in `/sdd plan` and affects SC-001 criteria.]

- [NEEDS CLARIFICATION: Yanked-only matches — if a requirement matches only yanked versions
  (no stable, no pre-release, only yanked), is this treated as unsatisfiable (yanked are dead)
  or a distinct "only yanked versions available" diagnostic? Affects message wording and severity.]

- [NEEDS CLARIFICATION: Diagnostic severity — WARNING or ERROR? "Newer version available" is
  HINT; unknown/yanked packages are WARNING. Unsatisfiable requirement is a build-time hard
  failure, so semantically closer to ERROR, but may be rendered as WARNING for consistency with
  other version-mismatch diagnostics. This is a `/sdd plan` detail.]

- [NEEDS CLARIFICATION: Code action target version — should "Update to satisfiable" suggest
  (A) the latest stable version, (B) the highest pre-release if no stable exists, (C) the
  highest available (stable or pre-release), or (D) be ecosystem-specific? How should it
  interact with prerelease policies? This is a `/sdd plan` detail.]

- [NEEDS CLARIFICATION: Should unsatisfiable-requirement detection be gated behind a config
  flag (e.g., `disable_unsatisfiable_diagnostics: true`) or always enabled? Existing diagnostics
  are always enabled; this decision belongs in `/sdd plan` / constitution if one is created.]

- [NEEDS CLARIFICATION: No project constitution exists yet at `.local/specs/constitution.md`
  — this spec cannot yet be checked against project-wide architectural principles. Recommend
  running `/sdd init` before `/sdd plan` for this feature to establish default severity,
  message templates, and code-action conventions.]

## 10. See Also

- `crates/deps-core/src/lsp_helpers.rs` — `generate_diagnostics_from_cache` (~line 752),
  `RequirementStatus` enum (~line 250), `EcosystemFormatter::requirement_status()` (~line 434),
  `EcosystemFormatter::requirement_is_unresolved()` (~line 397), existing diagnostic emission
  (~lines 777, 800, 1122, 1148, 1162 for Unknown/Yanked/Newer patterns)
- `crates/deps-lsp/src/handlers/diagnostics.rs` — diagnostic handler entry point, delegates to
  ecosystem via `generate_diagnostics()`
- `crates/deps-core/src/registry.rs` — `Version` trait (~line 135), version-comparison logic
  used by formatters
- `.local/testing/playbooks/competitive-parity.md` — original finding, row "unsatisfiable-
  requirement diagnostic", verified live by crates.nvim "No match" state and Dependi bug #221
- `.local/testing/issue-drafts-2026-08-23.md` — draft 4, full issue body and sources
- [LSP 3.17 Diagnostic specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#diagnostic)
- [[MOC-specs]] — all specifications
- [[008-codelens-update-all-outdated/spec]] — related LSP feature; both reuse version-comparison
  logic and WorkspaceEdit pathways
- [[002-osv-vulnerability-diagnostics/spec]] — related diagnostics work using the same
  per-dependency version data

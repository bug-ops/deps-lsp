---
aliases:
  - Deprecation/Abandoned Package Diagnostics
  - Deprecation with Replacement Suggestions
tags:
  - sdd
  - spec
  - research
  - parity-gap
  - priority/p3
created: 2026-08-23
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: Deprecation/abandoned-package diagnostics with suggested replacement (distinct from yanked)

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-deprecation-diagnostics`]
> **Type**: research / competitive-parity gap — this spec documents WHAT is missing and WHY;
> the HOW (ecosystem-specific integration, severity mapping, diagnostic on-by-default policy) is deferred to a future `/sdd plan` session.

## 1. Overview

### Problem Statement

deps-lsp handles **yanked versions** (versions withdrawn from a registry) but not **package-level deprecation/abandonment** — a registry-native signal distinct from yanked, with first-class metadata that often includes a suggested successor package name.

Today:
- **npm**: `deprecated` field is fetched in the abbreviated packument (per-version message, e.g., "Use package X instead") but currently mapped to the `yanked` trait without surfacing the message
- **Composer/Packagist**: `abandoned` field is fetched and mapped to `yanked`, already differentiates as "*(abandoned)*" in hover (not "*(yanked)*")
- **NuGet**: Does not currently fetch deprecation metadata (flat-container endpoint lacks it; registration endpoint carries `deprecationMessage` + `alternatePackage` but is not yet integrated)
- **Dart/pub.dev**: Does not currently fetch `discontinued` or `replacedBy` fields
- **PyPI**: Does not currently fetch project status (archived/quarantined) — available from deps.dev or direct PyPI endpoint inspection
- **Go, Bundler, Maven, Gradle, Swift**: No registry-native deprecation signal observed; would require registry research before integration

Verified across the 2026-08-23 on-demand competitive-parity scan:
```
rg -n "deprecated|abandonm" crates/deps-*/src/types.rs --type rust
# => npm/composer matched; nuget/dart/pypi/others showed zero deprecation-specific fields beyond yanked
```

The distinction matters:
- **Yanked**: A version was withdrawn; the package itself may be healthy. User should upgrade to a newer version of the same package.
- **Deprecated/Abandoned**: The package itself is no longer maintained. User should migrate to a different (replacement) package.

In-editor competition is weak — no scanned competitor surfaces replacement suggestions — while the data is already in (or adjacent to) payloads we fetch. Dependi's most-reacted open feature (#68, 13 reactions, 2x their next request) is license display; deprecation with replacement is the third finding (unfiled, draft 3 in `.local/testing/issue-drafts-2026-08-23.md`).

### Goal

deps-lsp emits a **warning diagnostic** on deps declared against a deprecated/abandoned package (with the registry's deprecation reason when available), shows deprecation reason + suggested replacement in hover (when the registry provides one), and offers a **"Replace with X" code action** (reusing the existing update-version `WorkspaceEdit` pathway) where a replacement is named. Per-version vs package-level deprecation distinction is scoped per ecosystem.

### Out of Scope

- Transitive dependency deprecation — only direct (manifest-declared) dependencies trigger diagnostics.
- Automated migration of import statements or code that uses the package (rename in manifest only).
- Yanked-version deprecation (orthogonal to this feature; already handled).
- Custom severity configuration or suppression comments in this initial phase — whether the diagnostic is on-by-default and how a user might silence it are deferred to `/sdd plan`.
- Version-scoped deprecation where only some versions of a package are deprecated (e.g., npm per-version `deprecated` field behavior vs package-level abandonment); per-ecosystem scoping is a HOW question.

## 2. User Stories

### US-001: Discover that a package is deprecated

AS A developer using a deprecated/abandoned package (e.g., Lodash alternatives, old build tooling, retired frameworks)
I WANT the editor to warn me that the package is no longer maintained
SO THAT I can prioritize migrating to an actively-maintained replacement.

**Acceptance criteria:**
```
GIVEN a manifest with a dependency on a deprecated/abandoned package (verified as deprecated in the registry)
WHEN the editor loads the manifest
THEN the server SHALL emit a warning diagnostic (e.g., "This package is deprecated") at the dependency line
     AND the diagnostic text SHALL include the registry's deprecation message (e.g., "Use package X instead" when provided)
```

### US-002: Learn the replacement package name

AS A developer reading the deprecation warning
I WANT to see the suggested replacement package (if the registry names one) both in hover and in a code action
SO THAT I can quickly jump to the right alternative without consulting external docs.

**Acceptance criteria:**
```
GIVEN a deprecated/abandoned package whose registry entry names a replacement (e.g., npm's "Use X instead" string, Packagist's abandoned: "other/package")
WHEN the user hovers over the dependency
THEN the hover SHALL include the deprecation reason AND the suggested replacement package name in a human-readable format (e.g., "Suggested replacement: other/package")
     AND the server SHALL advertise a code action "Replace with other/package" that, when invoked, rewrites the manifest to depend on other/package instead
```

### US-003: Handle packages with no suggested replacement

AS A developer with a deprecated package that has no replacement suggestion
I WANT to see the deprecation warning and reason
SO THAT I understand why the package is not recommended and can research alternatives manually.

**Acceptance criteria:**
```
GIVEN a deprecated/abandoned package whose registry entry does NOT name a replacement
WHEN the user hovers over the dependency
THEN the hover SHALL include the deprecation reason or a generic message (e.g., "This package is no longer maintained")
     AND the server SHALL NOT advertise a "Replace with X" code action (because no replacement is known)
```

### US-004: Consistent behavior across supported ecosystems

AS A developer using deps-lsp with any of the 11 supported ecosystems (Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Composer, Gradle, Swift, NuGet)
I WANT deprecation diagnostics to behave consistently regardless of which manifest format I'm editing
SO THAT I don't have to learn ecosystem-specific quirks in the deprecation workflow.

**Acceptance criteria:**
```
GIVEN two open manifests from different ecosystems (e.g., package.json and composer.json), each with a deprecated/abandoned dependency
WHEN the editor requests diagnostics for each
THEN the diagnostic presence, severity, title format, and code-action behavior SHALL be equivalent across both, per the project's cross-ecosystem-consistency rule
     (`.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing`)
     AND any ecosystem-specific divergence SHALL be documented as a first-class bug
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL detect when a resolved version's package (per-ecosystem metadata) is marked deprecated/abandoned by the registry | must |
| FR-002 | WHEN a manifest dependency is declared against a deprecated/abandoned package THE SYSTEM SHALL emit a warning diagnostic at the dependency line, titled "This package is [deprecated\|abandoned]" (ecosystem-specific phrasing per formatter) | must |
| FR-003 | THE SYSTEM SHALL include the registry's deprecation reason/message in the diagnostic text when available (e.g., npm's `deprecated` string, NuGet's `deprecationMessage`, Packagist's `abandoned` replacement name) | must |
| FR-004 | THE SYSTEM SHALL surface the deprecation reason and any suggested replacement in hover markdown, reusing the existing hover pathway (crates/deps-core/src/lsp_helpers.rs ~line 600-700) | must |
| FR-005 | WHEN a registry provides a suggested replacement package name THE SYSTEM SHALL advertise a code action "Replace with {replacement}" that, when invoked, reuses the existing update `WorkspaceEdit` pathway (crates/deps-lsp/src/server.rs `mod commands` / `execute_command` handler ~line 450-460) to change the dependency identifier to the replacement package | should |
| FR-006 | THE SYSTEM SHALL distinguish between package-level deprecation (entire package no longer maintained) and yanked-version deprecation (a specific version withdrawn) in both diagnostics and hover labels — ecosystem-specific handling per registry capabilities (e.g., npm per-version `deprecated` vs Packagist boolean `abandoned`) | must |
| FR-007 | THE SYSTEM SHALL produce equivalent deprecation diagnostics and code actions across all 11 supported ecosystem crates, per the cross-ecosystem-consistency rule — any ecosystem-specific divergence requires documented rationale | must |
| FR-008 | WHEN a manifest is edited or registry data is refreshed THE SYSTEM SHALL recompute deprecation state on the next diagnostic/hover request rather than serving stale cached deprecation status | must |
| FR-009 | THE SYSTEM SHALL NOT emit a deprecation diagnostic for a dependency when the registry provides no deprecation metadata (i.e., only emit when deprecation is confirmed, not on missing data) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Deprecation detection SHALL NOT trigger additional registry fetches beyond what diagnostics/hover/inlay hints already perform for the same document — it SHALL reuse already-cached per-version/per-package metadata |
| NFR-002 | Performance | Deprecation computation (checking the flag and formatting the message) SHALL be dominated by in-memory state traversal, not I/O; target latency in the same order of magnitude as the existing `textDocument/hover` handler |
| NFR-003 | Consistency | Deprecation diagnostic title, code-action label format, and hover presentation SHALL be identical across all 11 ecosystems — any ecosystem-specific divergence is a first-class bug per `.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing` |
| NFR-004 | Compatibility | Adding deprecation diagnostics SHALL NOT alter existing `hover`, `completion`, `inlay_hint`, `code_action` (for non-replacement updates), `diagnostic` (for non-deprecation categories), or `execute_command` behavior — this is an additive feature |
| NFR-005 | Ecosystem coverage | Deprecation detection is a best-effort feature per ecosystem registry capabilities: ecosystems with no registry-native deprecation signal (e.g., current Go, Bundler, Maven) remain silent until registry research identifies a signal source — they are not failures |

## 5. Data Model

Deprecation is a property of a resolved package (or per-version, per ecosystem). No new persistent entities beyond the existing `Version` trait.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Deprecation status (derived) | Per-package or per-version flag indicating deprecated/abandoned state, with optional reason and replacement name | package name, ecosystem, is_deprecated: bool, deprecation_reason: Option<String>, suggested_replacement: Option<String> |
| Deprecation diagnostic | Diagnostic entry emitted when a manifest declares a dependency on a deprecated/abandoned package | diagnostic title (e.g., "This package is deprecated"), message (reason + replacement if provided), range (dependency line), severity (warning) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Package is deprecated but registry provides no reason | Emit diagnostic with generic message (e.g., "This package is deprecated") and no hover replacement suggestion |
| Package is deprecated and registry provides a reason but no replacement | Emit diagnostic + hover with reason, no code action (because replacement is unknown) |
| Package is deprecated and registry provides both reason and replacement | Emit diagnostic + hover with reason and replacement, advertise "Replace with X" code action |
| Registry returns stale/cached data that misses a deprecation flag | System operates on the data it has; upon next registry refresh (cache expiry), deprecation state is recomputed — no immediate resolution required |
| Per-version deprecation (npm `deprecated` field is present for version 1.0.0 but not 1.0.1) | [NEEDS CLARIFICATION: Should the deprecation diagnostic fire if the user's requirement matches a deprecated version, or only if ALL matching versions are deprecated, or per-package only?] |
| A replacement package is itself deprecated | No special handling in this spec; the code action rewrites to the registry-suggested name; if that name is also deprecated, the next diagnostic refresh will flag it. User's recursive responsibility to follow chains. |
| Manifest has unsaved edits when a "Replace with X" code action is invoked | [NEEDS CLARIFICATION: Does the code action operate on the last-synced document state via `WorkspaceEdit`, consistent with how the existing `deps-lsp.updateVersion` command already handles this?] |
| Very large manifest with many deprecated dependencies | System SHALL emit one warning diagnostic per deprecated dependency, not a single aggregate diagnostic — consistent with how existing diagnostics (outdated, unknown, yanked) are per-dependency |
| Registry is unavailable (e.g., offline mode) | System degrades gracefully: existing cached deprecation state (if any) is used; new packages cannot be checked for deprecation — consistent with how diagnostics/hover already degrade under the same condition |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Deprecation detection works for all ecosystems with registry-native deprecation signals | npm (deprecated), Composer (abandoned) confirmed functional; NuGet, Dart, PyPI integrated with verification against live registries |
| SC-002 | Deprecation diagnostic presence matches registry state | 100% agreement between whether a diagnostic is emitted and whether the registry marks the package deprecated/abandoned, verified via spot checks in `.local/testing/coverage.md` LSP Feature Matrix |
| SC-003 | Replacement code action is offered when and only when a replacement is available | 100% of cases where the registry provides a replacement name have a working "Replace with X" code action; cases without a replacement name show no such action |
| SC-004 | Cross-ecosystem consistency | Deprecation diagnostic title, severity, and hover format verified equivalent across all ecosystems supporting the feature in a live-testing session, logged in `.local/testing/coverage.md` |
| SC-005 | No duplicate registry fetches | 0 additional HTTP calls attributable to deprecation detection beyond what diagnostics already perform, verified via debug log inspection per the project's live-testing protocol |

## 8. Agent Boundaries

### Always (without asking)
- Follow existing patterns in ecosystem crate formatters (`crates/deps-*/src/formatter.rs`) for trait method overrides (e.g., Composer already overrides `yanked_message()` and `yanked_label()`).
- Reuse the existing `hover` and `code_action` pathways in deps-core and deps-lsp; do not duplicate logic.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any implementation of this spec complete.

### Ask First
- Introducing a new diagnostic category distinct from yanked/unknown/outdated vs. leveraging an existing category with custom formatting.
- Per-ecosystem scope decisions (e.g., whether npm treats per-version `deprecated` or package-level deprecation, or both).
- Any change to the `Version` trait that might affect yanked-version handling or other ecosystems.

### Never
- Emit deprecation diagnostics based on assumption; only emit when the registry explicitly marks a package deprecated/abandoned.
- Modify existing yanked/unknown diagnostic logic as a side effect of adding deprecation — they must remain fully functional and independent.
- Introduce ecosystem-specific deprecation behavior (e.g., only checking npm, skipping others) without an explicit, documented rationale in the `/sdd plan` and code comments.

## 9. Open Questions

- [NEEDS CLARIFICATION: Should "Replace with X" code action be offered unconditionally when a replacement exists, or should it require user confirmation due to risk of migrating to a wrong package (e.g., typosquatting)? Current design offers the action without gating; revisit if security concern is raised.]
- [NEEDS CLARIFICATION: Per-version vs package-level deprecation scope per ecosystem: npm's `deprecated` field is per-version, but other ecosystems (Packagist, pub.dev) may treat deprecation as package-wide. Should the spec enforce one model across all ecosystems, or allow ecosystem-specific variation with clear documentation?]
- [NEEDS CLARIFICATION: Should the deprecation diagnostic be on-by-default or gated by a config option (e.g., like yanked/outdated diagnostics)? Deferred to `/sdd plan`.]
- [NEEDS CLARIFICATION: Atomicity/rollback guarantee when the "Replace with X" code action is invoked — does the `WorkspaceEdit` reuse the same batching logic as the single-version update command, or does it require special handling?]
- [NEEDS CLARIFICATION: No project constitution exists yet at `.local/specs/constitution.md` — this spec cannot yet be checked against project-wide architectural principles. Recommend running `/sdd init` before `/sdd plan` for this feature.]
- [NEEDS CLARIFICATION: Which registries actually provide a replacement package name in their deprecation metadata, and in what field/format? Live registry API verification needed for: NuGet (`alternatePackage` in registration endpoint), Dart pub.dev (`replacedBy`), PyPI project status (deps.dev `isDeprecated` vs direct endpoint), Go, Bundler, Maven, Gradle, Swift — to ground the "replacement available" condition in FR-005/US-002.]

## 10. See Also

- `crates/deps-core/src/lsp_helpers.rs` (~line 448-456) — existing `yanked_message()` / `yanked_label()` trait methods that deprecation will extend or parallel
- `crates/deps-core/src/lsp_helpers.rs` (~line 600-700) — hover markdown generation pathway that will surface deprecation reason + replacement
- `crates/deps-lsp/src/server.rs` (~line 450-460) — `execute_command` handler / `mod commands` that code actions reuse
- `crates/deps-npm/src/registry.rs` (~line 229) — npm `deprecated` field already parsed; comment notes it's per-version with optional message string
- `crates/deps-composer/src/formatter.rs` (~line 24-30) — Composer formatter already differentiates abandonment with custom `yanked_message()` / `yanked_label()`
- `crates/deps-composer/src/registry.rs` (~line 167-179) — Packagist `abandoned` field handling: can be bool or string (replacement name)
- `.local/testing/issue-drafts-2026-08-23.md` — draft 3 with full issue body for filing
- `.local/testing/playbooks/competitive-parity.md` → Scan Notes (2026-08-23) — original research finding and ecosystem registry survey
- [[MOC-specs]] — all specifications
- [[002-osv-vulnerability-diagnostics/spec]] — related diagnostics work on the same per-dependency diagnostic pipeline

---
aliases:
  - Per-Package Diagnostic Suppression
  - LSP Package Allow List
tags:
  - sdd
  - spec
  - lsp
  - diagnostics
  - config
  - cross-ecosystem
  - research/parity
created: 2026-11-08
status: draft
related:
  - "[[constitution]]"
  - "[[011-deprecation-replacement-diagnostics/spec|Deprecation and Replacement Diagnostics]]"
  - "[[068-cli-update-subcommand/spec|deps-cli update Subcommand]]"
---

# Feature: Per-Package Diagnostic Suppression (LSP)

> [!info] Metadata
> **Author**: continuous-improvement cycle (research/parity finding)
> **Priority**: P3, enhancement/parity
> **Branch**: (none yet, spec stage)

## 1. Overview

### Problem Statement

The LSP has no way to silence diagnostics for one specific package. The only
knobs are global: a severity per diagnostic kind and on/off toggles such as
`vulnerabilities_enabled` (see `crates/deps-lsp/src/config.rs` and
`book/src/configuration.md`). A project that intentionally keeps a deprecated,
outdated or license-flagged dependency sees its warning on every open, with
no recourse short of disabling the whole diagnostic kind for every package.

Verified live 2026-11-08: a `package.json` depending on `request@^2.88.2`
(npm-deprecated) publishes the `deprecated-package` warning on every open.
Sending `initializationOptions` `{"ignore":["request"]}` or
`{"deprecated":{"allow":["request"]}}` is rejected: the server logs
`failed to parse deps-lsp configuration (keeping previous configuration)
error=unknown field ...` and the diagnostic still fires. Config parsing
(`deny_unknown_fields`) correctly rejects the keys, so there is no silent
acceptance, but also no supported alternative.

The only per-package ignore in the repository is deps-cli's `[update].ignore`
([[068-cli-update-subcommand/spec]], `crates/deps-cli/src/update/ignore.rs`).
It affects `deps-cli update` only, never editor diagnostics, hints, or
`deps-cli check`.

### Parity Evidence

| Tool | Mechanism | Notes |
|------|-----------|-------|
| `mpiton/zed-depsy` v2.1.2+ (PR #432, 2026-11-04) | `deprecated` settings section: `show_in_hints`, `show_diagnostics`, `allow: ["fxhash", "@types/*"]` | Glob matcher shared with its package `ignore` list. Allowed packages still get version and vulnerability checks, unlike `ignore`. RustSec "unmaintained" advisories are hidden together with the deprecation so they do not resurface as a vulnerability. |
| Red Hat Dependency Analytics | In-manifest `exhortignore` suppression comments | Per-dependency, lives next to the declaration. |
| Dependabot | Per-dependency `ignore` list | PR-side only, not editor-side. |

### Goal

A user can declare, in typed configuration, that specific packages are exempt
from specific diagnostic kinds, and every ecosystem honors that declaration
identically through shared `deps-core` logic, while the packages are still
fetched and checked for all kinds that were not suppressed.

### Out of Scope

- In-manifest suppression comments (`exhortignore`-style). Deferred, see
  [[#9. Open Questions]] Q1. Comment syntax differs per manifest format
  (TOML, JSON with no comments, XML, YAML, Gradle DSL), so it is a separate,
  larger feature.
- Changing the semantics of `deps-cli update`'s `[update].ignore`
  ([[068-cli-update-subcommand/spec]]). This spec must not alter it.
- Time-boxed or expiring suppressions, and suppression by advisory ID
  (`osv.ignore`-style). Advisory-ID suppression is a distinct, finer
  granularity; tracked as [[#9. Open Questions]] Q4.
- Per-workspace-member or per-manifest-path scoping of rules.
- Any change to global severity semantics.

## 2. User Stories

### US-001: Allow a known-deprecated package
AS A maintainer who knowingly depends on a deprecated package
I WANT to exempt that package from the deprecation diagnostic
SO THAT my editor stops warning about a decision I have already made.

**Acceptance criteria:**
```
GIVEN a package.json depending on request@^2.88.2
  AND configuration that suppresses the deprecated kind for "request"
WHEN the document is opened
THEN no deprecated-package diagnostic is published for request
  AND outdated and vulnerability diagnostics for request are still published when applicable
```

### US-002: Glob-based suppression
AS A maintainer with many scoped packages
I WANT one pattern such as `@types/*` to cover a family of packages
SO THAT I do not enumerate every package.

**Acceptance criteria:**
```
GIVEN a suppression rule with pattern "@types/*" for kind deprecated
WHEN a manifest declares @types/node and @types/react
THEN neither produces a deprecated diagnostic
  AND a package named "types-extra" is unaffected
```

### US-003: Suppress several kinds for one package
AS A maintainer pinning a legacy dependency on purpose
I WANT to silence outdated and yanked diagnostics for it
SO THAT intentional pins do not generate noise.

**Acceptance criteria:**
```
GIVEN a rule for package "left-pad" listing kinds [outdated, yanked]
WHEN the manifest is opened
THEN outdated and yanked diagnostics are absent for left-pad
  AND deprecated, vulnerability and license diagnostics for left-pad are unchanged
```

### US-004: Ecosystem-correct name matching
AS A Python user
I WANT `Django`, `django` and `django_` style spellings to match one rule
SO THAT PEP 503 normalization does not defeat my configuration.

**Acceptance criteria:**
```
GIVEN a rule naming "Typing_Extensions" in a PyPI project
WHEN requirements.txt declares typing-extensions
THEN the rule matches, using the same normalization the PyPI formatter applies elsewhere
```

### US-005: Predictable unmaintained advisories
AS A Rust maintainer allowing a deprecated crate
I WANT its RustSec "unmaintained" advisory handled consistently with the deprecation
SO THAT suppressing one does not make the other reappear as a vulnerability.

**Acceptance criteria:**
```
GIVEN crate "fxhash" with a deprecated rule and an OSV advisory classed as unmaintained
WHEN diagnostics are generated
THEN the deprecation and the unmaintained advisory are both suppressed
  AND a genuine vulnerability advisory for fxhash is still published
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL accept a typed, per-package suppression rule set in the LSP configuration (initialization options and `workspace/didChangeConfiguration`), parsed through the same `parse_config` path as all other settings, with no separate validation path. | must |
| FR-002 | Each rule SHALL identify packages by a pattern and SHALL list one or more diagnostic kinds to suppress, drawn from a closed typed set: deprecated, outdated, yanked, license. The set deliberately has no `vulnerability` kind: LSP workspace settings (`.vscode/settings.json`, `.zed/settings.json`) can be controlled by the repository being opened, so a repo-supplied rule must never be able to hide a security advisory (see [[#9. Open Questions]] Q2, resolved). | must |
| FR-003 | WHEN a package matches a rule for kind K THE SYSTEM SHALL NOT publish diagnostics of kind K for that package, and SHALL publish all other kinds unchanged. | must |
| FR-004 | THE SYSTEM SHALL match patterns against package names normalized through the owning ecosystem's `EcosystemFormatter::normalize_package_name`, applied to both the rule pattern literal parts and the dependency name, reusing the normalization already used by deps-cli `[update].ignore`. | must |
| FR-005 | THE SYSTEM SHALL support exact names and glob patterns with at least a trailing and leading `*` wildcard (for example `@types/*`). The matcher SHALL be a single implementation in `deps-core`, shared by every ecosystem. | must |
| FR-006 | WHEN a package is suppressed for some kinds only THE SYSTEM SHALL still fetch registry metadata and run OSV and license checks needed by the remaining kinds. | must |
| FR-007 | THE SYSTEM SHALL apply suppression inside the shared diagnostic generation path in `deps-core::lsp_helpers`, not in per-ecosystem crates, so a rule behaves identically for all 14 ecosystems. | must |
| FR-008 | WHEN the deprecated kind is suppressed for a package THE SYSTEM SHALL also suppress that package's advisories classified as unmaintained, and SHALL NOT suppress other advisory classes. | must |
| FR-009 | WHEN a suppressed package also carries a deprecation hint, hover, or inlay-hint annotation THE SYSTEM SHALL apply the same suppression rule to those surfaces. | should (deferred) |
| FR-010 | THE SYSTEM SHALL provide a distinct whole-package ignore (no diagnostics of any kind, no hints) separate from per-kind suppression, so "skip checks entirely" and "allow this one condition" are different, typed choices. | should (deferred) |
| FR-011 | WHEN a rule pattern is syntactically invalid, or lists an unknown kind, THE SYSTEM SHALL reject the configuration with a typed error and keep the previous configuration, consistent with existing config behavior. | must |
| FR-012 | WHEN a rule matches no dependency in an open manifest THE SYSTEM SHALL do nothing and SHALL NOT log above debug level. | should |
| FR-013 | THE SYSTEM SHALL document the new settings in `book/src/configuration.md` and each affected ecosystem reference page. | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Type safety | Diagnostic kinds in rules SHALL be a closed exhaustive enum with no catch-all arm, and package patterns a validated newtype. No raw `String`/`bool` flags at the config boundary. |
| NFR-002 | Performance | Rule evaluation SHALL add no network calls and SHALL stay O(rules) per dependency, with patterns compiled once at config load. Hover and completion latency SHALL NOT regress measurably. |
| NFR-003 | Consistency | Behavior SHALL be identical across all ecosystems; a divergence is a cross-ecosystem bug per `.claude/rules/continuous-improvement.md`. |
| NFR-004 | Security | Pattern matching SHALL be linear-time (no backtracking regex on user input), and rule names SHALL pass through the existing diagnostic name redaction before appearing in logs. |
| NFR-005 | Compatibility | Existing configurations without the new section SHALL behave exactly as before. |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| SuppressionRule | One user-declared exemption | package pattern, set of suppressed kinds |
| PackagePattern | Validated name or glob | literal or wildcard form, normalized per ecosystem at match time |
| SuppressibleKind | Closed enum of user-suppressible diagnostic kinds | deprecated, outdated, yanked, license |
| SuppressionSet | Compiled rule collection held in the policy config | rules in declaration order |

> [!note]
> `SuppressibleKind` is intentionally narrower than `deps_core::diagnostic::DiagnosticKind`
> (which also carries advisory IDs, typosquat, mutable-ref and other variants).
> Mapping from `DiagnosticKind` to `SuppressibleKind` must be total and
> compiler-enforced; kinds that are not user-suppressible map to none.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Rule names a package absent from the manifest | No effect, no warning above debug. |
| Two rules match one package | Suppressed kinds are the union. |
| Pattern is `*` | Rejected or accepted only as an explicit whole-ecosystem choice, see Q3. |
| Rule lists `vulnerability` | Rejected by the typed kind set; previous config kept (FR-011). Only advisories typed informational (unmaintained) are hidden, and only with `deprecated` (FR-008). |
| `yanked` suppressed where R6b (yanked-only match) fires | R6b stops the dependency's pipeline before the outdated rule, so outdated is absent too; FR-003 still holds (no kind other than the listed one is lost that was not already absent). |
| "Update N outdated" code lens and update-all | Still include outdated-suppressed packages; deferred together with FR-009/FR-010. |
| Auto-discovered `deps.toml` with `diagnostics.suppress` (`deps-cli check`) | Dropped with a warning, like every other gate-relevant section (spec 062 F1); only an explicit `--config` is honored. |
| Scoped npm name `@scope/name` with glob `@scope/*` | Matches; slash is an ordinary character. |
| PyPI `Foo_Bar` vs rule `foo-bar` | Match via formatter normalization. |
| Unknown config key under the new section | Rejected by `deny_unknown_fields`, previous config kept. |
| Config reload removes a rule | Diagnostics return on next publish; documents are re-published. |
| GitHub Actions or GitLab CI references | Names are action or project refs; matching uses that ecosystem's normalization. |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live repro: `request@^2.88.2` with a deprecated rule for `request` | 0 deprecated diagnostics; outdated and vulnerability diagnostics still present |
| SC-002 | Ecosystems covered by the same rule semantics | 14 of 14, verified by a cross-ecosystem live check |
| SC-003 | Ecosystem-local suppression code added | 0 lines outside `deps-core` and config wiring |
| SC-004 | Behavior change for configs without the new section | none |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps-core` shared helpers and `normalize_package_name`; check `lsp_helpers`, `json_helpers` first.
- Keep `DiagnosticKind` handling exhaustive.
- Verify behavior live against the LSP harness before claiming parity.

### Ask First
- Adding a glob-matching dependency to the workspace.
- Sharing a config file or schema with deps-cli (`deps.toml`).
- Changing the severity semantics of existing diagnostics.

### Never
- Add per-ecosystem suppression logic outside `deps-core`.
- Silently accept unknown keys or weaken `deny_unknown_fields`.
- Alter deps-cli `[update].ignore` semantics.
- Edit `crates/deps-zed`.

## 9. Open Questions

All questions are resolved or deferred; none block implementation.

| Q | Question | Outcome |
|---|----------|---------|
| Q1 | In-manifest comment suppression (`exhortignore`-style)? | Deferred; out of scope for this feature. |
| Q2 | Allow vulnerability suppression at all? | No `vulnerability` kind in the MVP (user decision). Workspace settings can be repository-controlled, so advisories are never suppressible; only unmaintained advisories follow `deprecated` (FR-008). |
| Q3 | Allow a bare `*` pattern? | Rejected; a single leading or trailing `*` is the only wildcard. |
| Q5 | Config location? | `PolicyConfig.diagnostics.suppress`, shared by deps-lsp and deps-cli; no separate file. |
| Q6 | Should `deps-cli check` honor suppressions? | Explicit `--config` only; an auto-discovered `deps.toml`'s `suppress` is dropped with a warning (spec 062 F1). No bypass flag. |
| Q7 | Config shape? | A flat list of `{ package, kinds }` rules. |
| Q8 | How is "unmaintained" identified? | RustSec informational-unmaintained only, via the typed `VulnSeverity::Informational`, which only the unmaintained allowlist produces. |
| Q9 | Surface suppressed diagnostics for auditability? | No user-visible surface and no log in the MVP. |

> [!question] Deferred
> - Q4: suppression by advisory ID (finer than per-package) is a separate, later spec.

## 10. See Also

- [[constitution]] - project principles
- [[MOC-specs]] - all specifications
- [[011-deprecation-replacement-diagnostics/spec|Deprecation and Replacement Diagnostics]] - the diagnostic being silenced
- [[068-cli-update-subcommand/spec|deps-cli update Subcommand]] - existing per-package ignore (update only)
- `crates/deps-lsp/src/config.rs`, `crates/deps-core/src/lsp_helpers/diagnostics.rs`, `crates/deps-cli/src/update/ignore.rs` - reference code

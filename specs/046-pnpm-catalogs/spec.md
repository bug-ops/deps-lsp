---
aliases:
  - pnpm Catalogs
  - catalog: protocol
tags:
  - sdd
  - spec
  - npm
  - pnpm
  - ecosystem-parity
created: 2026-09-04
status: ready
related:
  - "[[constitution]]"
---

# Feature: pnpm Catalogs + `workspace:` Protocol Resolution Support

> [!info] Metadata
> **Author**: continuous-improvement research cycle
> **Branch**: (none yet — spec stage)

## 1. Overview

### Problem Statement

pnpm, a popular Node.js package manager, supports a "catalogs" feature: a
`pnpm-workspace.yaml` file at the workspace root defines one or more named
version catalogs (a default `catalog:` map and/or additional
`catalogs.<name>:` maps), and individual `package.json` files reference a
catalog entry via `"dependency-name": "catalog:"` (default catalog) or
`"dependency-name": "catalog:<name>"` (named catalog) instead of a literal
semver range. Resolving the actual installed version requires reading
`pnpm-workspace.yaml` and cross-referencing the catalog entry by dependency
name.

deps-lsp's npm support (`crates/deps-npm/`) currently has zero handling of
this — confirmed via `grep -ril catalog crates/deps-npm/src/` (no hits) and
`grep -ril pnpm-workspace crates/` (no hits anywhere in the workspace). A
`catalog:` or `catalog:<name>` value is not a valid semver range, so it
currently either fails to parse in `crates/deps-npm/src/parser.rs` /
`crates/deps-npm/src/formatter.rs` or is silently skipped/misreported —
hover, completion, diagnostics, and inlay hints give the user nothing useful
on these lines.

This is a known competitive gap, tracked informally as "Candidate, unfiled"
in `.local/testing/playbooks/competitive-parity.md`'s Known Gaps table
across continuous-improvement cycles 026, 028, 029, and 036. This spec acts
on it instead of deferring again. It matters for two reasons: (1) real pnpm
monorepo users get incorrect or absent version information for a
mainstream, increasingly common dependency-declaration pattern, and (2)
dedicated competing tooling already exists for exactly this gap (see
[[#10. See Also]]), so parity is measurable and overdue.

### Goal

When a `package.json` dependency value is `catalog:` or `catalog:<name>`,
deps-lsp resolves it against the workspace's `pnpm-workspace.yaml` catalog
definitions and provides the same hover / completion / diagnostic /
inlay-hint experience it already provides for a literal semver range —
reusing the existing npm registry client and `node-semver` comparison logic
unchanged.

### Out of Scope

- Package managers other than pnpm reusing similar syntax (none currently
  exist in the wild; not addressed here).
- Editing/writing back to `pnpm-workspace.yaml` from a code action (this
  spec covers read/resolve only, matching deps-lsp's existing read-only
  posture toward workspace config elsewhere).
- Yarn/npm workspace `protocol` equivalents that are *not* pnpm catalogs
  (e.g. Yarn's own `workspace:` handling is a separate ecosystem and not
  covered).

## 2. User Stories

### US-001: Hover shows resolved catalog version

AS A developer working in a pnpm monorepo
I WANT hovering over `"react": "catalog:"` in a member package's
`package.json` to show the same rich hover deps-lsp shows for a literal
range (resolved version, latest/outdated status, etc.)
SO THAT I don't have to manually open `pnpm-workspace.yaml` to find out what
version I'm actually depending on

**Acceptance criteria:**
```
GIVEN a workspace root containing pnpm-workspace.yaml with
  catalog:
    react: ^18.3.0
AND a member package.json containing "react": "catalog:"
WHEN the user hovers over the "react" dependency line
THEN deps-lsp shows the same hover content it would show for a literal
  "^18.3.0" range, including registry latest-version comparison
```

### US-002: Named catalog resolution

AS A developer using multiple named catalogs (e.g. to pin a legacy React 17
subset of packages)
I WANT `"react": "catalog:react17"` to resolve against the `catalogs.react17`
section of `pnpm-workspace.yaml`, not the default `catalog:` section
SO THAT hover/diagnostics reflect the version actually installed for that
package

**Acceptance criteria:**
```
GIVEN pnpm-workspace.yaml with
  catalog:
    react: ^18.3.0
  catalogs:
    react17:
      react: ^17.0.2
AND a member package.json containing "react": "catalog:react17"
WHEN the user hovers over the "react" dependency line
THEN deps-lsp resolves against ^17.0.2, not ^18.3.0
```

### US-003: Diagnostics for catalog-referenced dependencies

AS A developer
I WANT the existing "newer version available" / "unresolvable" diagnostics
to fire for `catalog:`-referenced dependencies exactly as they do for
literal ranges
SO THAT catalog usage doesn't create a blind spot in outdated-dependency
detection

**Acceptance criteria:**
```
GIVEN a catalog entry resolves to a range with a newer version published
  on the npm registry
WHEN the file is opened or edited
THEN the existing "newer version available" diagnostic appears on the
  package.json dependency line, consistent with literal-range behavior
```

### US-004: Graceful degradation when catalog entry is missing or workspace file is absent

AS A developer
I WANT a clear, non-crashing signal when `catalog:` is used but no matching
entry exists (or no `pnpm-workspace.yaml` is found)
SO THAT I know to fix my workspace config instead of seeing silent nothing
or a confusing error

**Acceptance criteria:**
```
GIVEN a package.json with "left-pad": "catalog:missing-entry"
AND pnpm-workspace.yaml has no "left-pad" key in the relevant catalog
WHEN the user hovers over that line
THEN deps-lsp shows a clear message (e.g. "no catalog entry named
  'left-pad' found in <catalog-name>") instead of crashing, showing a raw
  registry lookup for the literal string "catalog:missing-entry", or
  showing nothing
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a `package.json` file is opened or changed within a directory tree containing a `pnpm-workspace.yaml` at or above the workspace root THE SYSTEM SHALL locate and parse that file's `catalog:` (default) and `catalogs.<name>:` (named) sections into an in-memory catalog map keyed by dependency name and catalog name | must |
| FR-002 | WHEN a `package.json` dependency value equals exactly `catalog:` THE SYSTEM SHALL resolve it against the default catalog entry for that dependency name | must |
| FR-003 | WHEN a `package.json` dependency value matches `catalog:<name>` (non-empty name) THE SYSTEM SHALL resolve it against the `catalogs.<name>` entry for that dependency name | must |
| FR-004 | WHEN a catalog entry is successfully resolved to a semver range THE SYSTEM SHALL feed that range into the existing npm registry lookup and `node-semver` comparison logic unchanged, producing hover, completion, diagnostic, and inlay-hint output identical in shape to a literal-range dependency | must |
| FR-005 | WHEN a `catalog:` or `catalog:<name>` specifier has no corresponding entry in the resolved catalog map THE SYSTEM SHALL report a distinct, actionable message (not a raw registry-lookup failure and not silent omission) identifying the missing catalog name and dependency name | must |
| FR-006 | WHEN no `pnpm-workspace.yaml` is found in any ancestor directory of the `package.json` being processed AND a `catalog:` specifier is present THE SYSTEM SHALL report a distinct message indicating no pnpm workspace catalog file was found, rather than treating the specifier as an invalid semver range | must |
| FR-007 | WHEN `pnpm-workspace.yaml` changes on disk THE SYSTEM SHALL invalidate/refresh its cached catalog map so subsequent hover/diagnostic requests reflect the update | must |
| FR-008 | WHEN a `package.json` dependency value is a literal semver range (not a `catalog:` specifier) THE SYSTEM SHALL continue to parse and resolve it exactly as before this feature, with no behavior change | must |
| FR-009 | WHEN a `package.json` dependency value uses the `workspace:` protocol (e.g. `workspace:*`, `workspace:^`, `workspace:~`) THE SYSTEM SHALL leave existing behavior unchanged — `workspace:` protocol resolution is out of scope for this spec (resolves against sibling workspace *packages*, not the catalog map, and needs separate package-discovery logic) and is tracked as a follow-up (see [[#9. Open Questions]] and [[#10. See Also]]) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | `pnpm-workspace.yaml` SHALL be parsed at most once per file-change event (open/save/external change), not re-parsed on every keystroke or every hover/completion/diagnostic request — cached and invalidated on file-watcher change, consistent with how deps-lsp already caches other manifest/lockfile parses |
| NFR-002 | Correctness | Existing literal-semver-range parsing, hover, completion, and diagnostic behavior for `package.json` MUST NOT regress — verified by the existing `deps-npm` test suite passing unchanged plus new catalog-specific tests |
| NFR-003 | Robustness | Malformed `pnpm-workspace.yaml` (invalid YAML, unexpected shape) SHALL degrade gracefully — dependencies using `catalog:` fall back to the "no catalog file found" style message from FR-006 rather than panicking or blocking the rest of the file's diagnostics |
| NFR-004 | Consistency | Catalog resolution SHALL reuse the existing npm registry client, cache, and `node-semver` comparison machinery unchanged — no parallel/duplicate version-comparison code path introduced for catalog-resolved dependencies |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| PnpmWorkspaceConfig | Parsed representation of a `pnpm-workspace.yaml` file relevant to catalogs | workspace root path, default catalog entries, named catalogs map |
| CatalogEntry | A single dependency-name → version-range mapping within a catalog | dependency name, semver range string, owning catalog name (`default` or `<name>`) |
| CatalogSpecifier | A parsed `catalog:` / `catalog:<name>` value found in a `package.json` dependency | raw specifier text, referenced catalog name (`None` = default) |

**Resolved**: per `pnpm.io/catalogs` and `pnpm.io/pnpm-workspace_yaml`, both `catalog:` (default) and each `catalogs.<name>:` entry are a flat `dependency-name: semver-range` string map — no nested metadata forms are documented or shown in any example. `CatalogEntry`/`PnpmWorkspaceConfig` parse targets a `HashMap<String, String>` per catalog, keyed by dependency name.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `catalog:` used but no `pnpm-workspace.yaml` anywhere in ancestor tree | Distinct "no pnpm workspace found" message (FR-006), not a raw invalid-semver error |
| `catalog:<name>` references a catalog name that doesn't exist in `catalogs:` | Distinct "unknown catalog '<name>'" message, not a silent fallback to default catalog |
| `catalog:<name>` catalog exists but has no entry for this dependency name | Distinct "no catalog entry for '<dep>' in catalog '<name>'" message (FR-005) |
| `pnpm-workspace.yaml` exists but has no `catalog:` or `catalogs:` key at all | Same as "no entry" case — every `catalog:` specifier in the workspace reports missing-entry |
| Multiple nested `pnpm-workspace.yaml` files (monorepo of monorepos) | **Resolved**: use the nearest-ancestor `pnpm-workspace.yaml` relative to the `package.json` being processed. This matches pnpm's own `find-workspace-dir` behavior (searches upward from cwd and stops at the first match) and its documented stance that nested/multiple workspace roots are not officially supported (pnpm/pnpm#10267, pnpm/pnpm#11656) |
| `package.json` is not under any pnpm workspace but still contains `"dep": "catalog:"` (e.g. copy-pasted, or npm/Yarn project) | Same as FR-006 — reported as no workspace catalog file found; specifier is not silently treated as a valid range |
| `pnpm-workspace.yaml` is malformed YAML | Graceful degradation per NFR-003; existing YAML-parsing pattern in the codebase (`fast-yaml`/`serde_norway`, per project dependency conventions) should be reused rather than introducing a new YAML parser dependency |
| Catalog entry's version range itself is invalid semver (typo in `pnpm-workspace.yaml`) | Resolved range is fed into existing range-validation/diagnostic logic, which already handles invalid ranges for literal dependencies — no new error path needed per FR-004/FR-008 |
| `pnpm-workspace.yaml` catalog entry uses a non-npm-registry specifier itself (e.g. `workspace:*`, a git URL, or `catalog:` recursively) | **Resolved**: every documented pnpm catalog example uses a plain semver range; no chained resolution is implemented. If a catalog entry's value fails to parse as a semver range, treat it the same as any other unparseable range value elsewhere in `deps-npm` (e.g. `git+`/`file:` literals) — resolve the specifier to that raw string, show it in hover without a registry/latest-version comparison, and do not crash or chain further |

## 7. Success Criteria

Measurable metrics that prove the feature works:

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Hover on a `catalog:`-referenced dependency in a real pnpm monorepo fixture shows resolved version + registry comparison | 100% match with equivalent literal-range hover output |
| SC-002 | Existing `deps-npm` test suite (literal-range parsing/hover/diagnostics) | 0 regressions after this feature ships |
| SC-003 | `pnpm-workspace.yaml` re-parse frequency during a sustained editing session (per NFR-001) | Re-parsed only on file-watcher change events, not per keystroke — verified via debug log inspection per `.claude/rules/continuous-improvement.md` live-testing gate |
| SC-004 | Missing-catalog-entry and missing-workspace-file scenarios produce distinct, non-crashing messages | 100% of edge cases in [[#6. Edge Cases and Error Handling]] covered by tests |

## 8. Agent Boundaries

### Always (without asking)
- Run the full `deps-npm` and workspace-wide test suite after changes
- Follow existing manifest-parsing and caching patterns already established in `crates/deps-npm/src/parser.rs`, `lockfile.rs`, and the project's YAML-handling convention (`fast-yaml`/`serde_norway`, never `serde_yaml`/`serde_yml` per project dependency rules)
- Reuse the existing npm registry client and `node-semver` comparison logic without duplication

### Ask First
- Adding any new dependency (e.g. a YAML parsing crate, if `serde_norway` is not already a `deps-npm` dependency)
- Deciding whether `catalog:` resolution logic lives in `deps-npm` (ecosystem-specific) or is promoted to a shared `deps-core` primitive (cross-cutting design decision — see Open Questions)

### Never
- Write back to `pnpm-workspace.yaml` (no code actions/quick-fixes that modify workspace config in this spec's scope)
- Silently treat an unresolved `catalog:` specifier as a valid semver range or suppress it without any diagnostic/hover signal

## 9. Open Questions

All items below were open `[NEEDS CLARIFICATION]` markers; resolved on 2026-09-04
against current pnpm documentation (`pnpm.io/catalogs`, `pnpm.io/pnpm-workspace_yaml`,
`pnpm.io/workspaces`) and pnpm's own issue tracker (pnpm/pnpm#10267, pnpm/pnpm#11656)
prior to implementation:

- **`workspace:` protocol resolution scope**: out of scope for this spec (see FR-009).
  It resolves against sibling workspace *packages* by their own `package.json` version,
  not against a catalog map, and needs separate workspace-package discovery (glob
  patterns in `pnpm-workspace.yaml`'s `packages:` key). Tracked as a follow-up spec
  (e.g. 047) once this spec ships.
- **`catalogs.<name>` YAML shape**: always a flat `dependency-name: semver-range`
  string map — no nested metadata forms exist in pnpm's documented schema (see
  [[#5. Data Model]]).
- **Workspace-root discovery**: nearest-ancestor `pnpm-workspace.yaml` relative to the
  `package.json` being processed, matching pnpm's own `find-workspace-dir` algorithm
  and its documented single-root-per-tree design (see [[#6. Edge Cases and Error
  Handling]]).
- **`deps-npm`-local vs. `deps-core` shared primitive**: implemented as
  npm-ecosystem-specific code inside `crates/deps-npm/` — `pnpm-workspace.yaml` is
  pnpm-specific syntax with no analog in other ecosystems today, so a `deps-core`
  primitive would be speculative generalization ahead of a second concrete use case.
  Revisit only if a structurally similar named-version-alias pattern appears in
  another ecosystem.
- **Chained resolution for non-registry catalog values**: no chaining is implemented.
  A catalog entry value that isn't a parseable semver range (e.g. `workspace:*`, a git
  URL, or `catalog:` recursively — none of which appear in pnpm's documented catalog
  examples) is treated the same as any other unparseable range value elsewhere in
  `deps-npm`: shown as-is in hover with no registry comparison, never a crash or a
  silently dropped diagnostic (see [[#6. Edge Cases and Error Handling]]).

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [antfu/vscode-pnpm-catalog-lens](https://github.com/antfu/vscode-pnpm-catalog-lens) — dedicated VS Code extension providing inline hints for pnpm catalog entries; direct competitive-parity reference for this feature
- [pnpm catalogs documentation](https://pnpm.io/catalogs) — authoritative source for `pnpm-workspace.yaml` catalog schema, referenced for FR-001/FR-003 parsing rules
- [pnpm workspace protocol documentation](https://pnpm.io/workspaces#workspace-protocol-workspace) — the closely related but distinct `workspace:*`/`workspace:^`/`workspace:~` resolution mechanism; see [[#9. Open Questions]] for in-scope-vs-follow-up decision
- `.local/testing/playbooks/competitive-parity.md` — Known Gaps table where this item was tracked as "Candidate, unfiled" across cycles 026, 028, 029, 036

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
| FR-007 | WHEN `pnpm-workspace.yaml` changes on disk THE SYSTEM SHALL invalidate/refresh its cached catalog map so that the *next pull request* (hover, diagnostics, completion, inlay hints, or a reparse triggered by opening/editing/saving the referencing `package.json`) reflects the update — matching `.npmrc`'s existing mtime-gated refresh contract exactly, not a proactive push. There is no dedicated file watcher for `pnpm-workspace.yaml` (`deps-lsp`'s watcher only covers lockfile patterns); an already-**pushed** diagnostic on an open `package.json` is not proactively re-issued until that document's own next reparse. Implementation review finding (critic S1, 2026-09-04): this is the same residual gap `.npmrc` already ships with — tracked as a shared follow-up, not specific to catalogs | must |
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

> [!important] Invariant across every unresolved case below
> Whenever a `catalog:` specifier does not resolve to a parseable semver range, the
> dependency's version requirement is left **unset** while its version *range* (the
> manifest span) is retained. This holds for *every* failure to obtain a catalog map,
> including ones that are not about the file's contents at all: a `package.json` opened
> from a non-`file:` URI (virtual filesystem, remote or web workspace) has no directory
> to search upward from, and a workspace file can vanish or turn out not to be a regular
> file between discovery and read. Each of those is an **outcome** — reported as
> [[#3. Functional Requirements|FR-006]]'s "no workspace file found" — never a silently
> skipped resolution step, because skipping the step is what leaves the raw specifier in
> the requirement. Leaving the raw `catalog:…` text in the requirement
> instead makes the shared LSP layer read it as a version: it compares as
> [`Outdated`](#3.%20Functional%20Requirements) and emits a spurious "Newer version
> available", and — because the requirement then matches the manifest text
> byte-for-byte — it arms both the update quick-fix and "Update all outdated
> dependencies" to rewrite `"react": "catalog:"` into a literal version, destroying the
> catalog reference. That is precisely what [[#8. Agent Boundaries]]'s Never clause
> forbids, so the unset requirement is a correctness requirement, not an implementation
> detail. The raw specifier text remains available for hover.

| Scenario | Expected Behavior |
|----------|-------------------|
| `catalog:` used but no `pnpm-workspace.yaml` anywhere in ancestor tree | Distinct "no pnpm workspace found" message (FR-006), not a raw invalid-semver error |
| `catalog:default` (the documented long form of `catalog:`) | **Resolved**: `catalog:default` and the `catalog:` shorthand are the same reference (pnpm.io/catalogs: *"These version ranges can be referenced through `catalog:default`. For the default catalog only, a special `catalog:` shorthand can also be used."*). The default catalog has **two** valid definition sites — a top-level `catalog:` block or a `catalogs.default:` section — and either alone defines it |
| Both a top-level `catalog:` block **and** a `catalogs.default:` section are present | **Resolved**: unresolvable, with a message naming the duplicate definition. pnpm's `getCatalogsFromWorkspaceManifest` calls `checkDefaultCatalogIsDefinedOnce` and throws `INVALID_CATALOGS_CONFIGURATION` *before* returning any catalog map, so the entire workspace manifest is unusable — the defect therefore applies to every `catalog:` specifier in the workspace, not only to those referencing the default catalog. deps-lsp deliberately does **not** merge the two blocks: a merge resolves entries pnpm itself resolves from neither source, and for a read-only tool, showing a confidently-resolved version for a workspace `pnpm install` would reject is the wrong direction of error |
| `catalog:<name>` references a catalog name that doesn't exist in `catalogs:` | Distinct "unknown catalog '<name>'" message, not a silent fallback to default catalog |
| `catalog:<name>` catalog exists but has no entry for this dependency name | Distinct "no catalog entry for '<dep>' in catalog '<name>'" message (FR-005) |
| `pnpm-workspace.yaml` exists but has no `catalog:` or `catalogs:` key at all | Same as "no entry" case — every `catalog:` specifier in the workspace reports missing-entry |
| Multiple nested `pnpm-workspace.yaml` files (monorepo of monorepos) | **Resolved**: use the nearest-ancestor `pnpm-workspace.yaml` relative to the `package.json` being processed. This matches pnpm's own `find-workspace-dir` behavior (searches upward from cwd and stops at the first match) and its documented stance that nested/multiple workspace roots are not officially supported (pnpm/pnpm#10267, pnpm/pnpm#11656) |
| `package.json` is not under any pnpm workspace but still contains `"dep": "catalog:"` (e.g. copy-pasted, or npm/Yarn project) | Same as FR-006 — reported as no workspace catalog file found; specifier is not silently treated as a valid range |
| `pnpm-workspace.yaml` parses as YAML but has the wrong shape (`catalog: "a string"`, `catalogs: [a, b]`, a `catalogs.<name>` that is not a mapping) | Treated as malformed, same message and severity as unparseable YAML. A catalog **entry** whose value is not a scalar string (e.g. `react: {version: ^18}`) is the narrower case: that entry alone gets its own distinct "not a version string" message (naming the dependency and catalog it was found in) rather than the missing-entry wording, and rather than failing the whole file — a wrong-shape *leaf* must not be conflated with "no such key" (implementation review finding: the entry is right there, just unusable). Neither case may be implemented by unwrapping the node as a mapping — a panic there would take down the parse of every dependency in the document, which NFR-003 forbids |
| A `catalog:`/`catalogs:`/`catalogs.<name>` key is present with a null/empty YAML value (e.g. `catalog:` with nothing after the colon — a common result of commenting a block out) | **Resolved** (implementation review finding, matches pnpm's own `manifest.catalog != null` check): treated as *absent*, not malformed — falls through to whatever else defines that catalog (e.g. `catalogs.default:` alone still defines the default catalog), and a null top-level `catalog:` does **not** trigger the duplicate-default-catalog defect even when `catalogs.default:` is also present |
| `pnpm-workspace.yaml` is malformed YAML | Graceful degradation per NFR-003, with its own distinct message ("pnpm-workspace.yaml could not be parsed") rather than reusing FR-006's "no workspace file found" text — the file's existence is known, so the accurate message is the more diagnosable one, and SC-004's "distinct, non-crashing messages" is satisfied either way. Reuses the codebase's established YAML parser (`yaml-rust2`, already a workspace dependency used by `deps-core`/`deps-dart`/`deps-github-actions`) behind `deps_core::check_yaml_nesting_depth`/`check_yaml_expansion`, rather than introducing a second YAML stack |
| Catalog entry's version range itself is invalid semver (typo in `pnpm-workspace.yaml`), **or** uses a non-npm-registry specifier (e.g. `workspace:*`, a git URL, a dist-tag, or `catalog:` recursively) | **Resolved**: every documented pnpm catalog example uses a plain semver range; no chained resolution is implemented. Both cases are handled by one rule — if the entry's value does not parse as a semver range, the dependency's version requirement is left **unset**, the raw value is shown in hover with no registry/latest-version comparison, and no diagnostic is emitted (a typo cannot be told apart from a legitimate dist-tag or `workspace:` value without re-implementing npm's specifier grammar, and a false warning is worse than silence). Deliberately *not* "feed the raw value into the existing range-validation logic": that path produces a spurious "Newer version available" diagnostic **and** arms the update quick-fix to overwrite the `catalog:` specifier, which [[#8. Agent Boundaries]]'s Never clause forbids |

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

---
aliases:
  - pnpm-workspace.yaml as a dependency file
  - pnpm catalog entry editing
tags:
  - sdd
  - spec
  - enhancement
  - ecosystem/npm
  - pnpm
  - competitive-parity
  - priority/p3
created: 2026-10-06
status: specify
related:
  - "[[plan]]"
  - "[[tasks]]"
  - "[[MOC-specs]]"
  - "[[046-pnpm-catalogs/spec]]"
  - "[[052-pnpm-lockfile-provider/spec]]"
  - "[[014-github-actions-ecosystem/spec]]"
  - "[[056-gitlab-ci-yaml-scalar-anchor-alias/spec]]"
  - "[[062-cli-check-mode/spec]]"
  - "[[064-deps-cli-lsp-isolation/spec]]"
  - "[[066-canonical-document-identity/spec]]"
---

# Feature: Open `pnpm-workspace.yaml` itself as a dependency file (catalog entry hints, diagnostics, code actions)

> [!info] Metadata
> **Author**: continuous-improvement research cycle (2026-10-06), competitive-parity finding
> **Type / priority**: enhancement, P3
> **Branch**: suggested `feat/1788-pnpm-workspace-catalog-entries`
> **Issue**: #1788 (P3, enhancement, research, cross-ecosystem)
> **Phase**: specify, plan and tasks. All nine former open questions are resolved in section 9 (design vetted by architect and critic review, 2026-10-21).

> [!abstract]
> deps-lsp already resolves `catalog:` / `catalog:<name>` specifiers in `package.json` against
> `pnpm-workspace.yaml` ([[046-pnpm-catalogs/spec|spec 046]]), but treats the workspace file only as
> a *watched config*. The catalog entries themselves, the place where a pnpm user actually edits
> versions, get no inlay hints, diagnostics, hover, completion, code actions or code lenses when
> the file is opened. This spec makes a catalog entry a first-class dependency, so the same
> outdated / deprecated / yanked / vulnerable / unknown-package signals deps-lsp gives for
> `package.json` also appear on the line a user edits.

## 1. Overview

### Problem Statement

In a pnpm workspace that uses catalogs, a member `package.json` declares `"react": "catalog:"` and
the version range lives in one place: `pnpm-workspace.yaml` under `catalog:` (default) or
`catalogs.<name>:` (named). The version a developer wants to bump is therefore *in the YAML file*,
and that is exactly where deps-lsp is silent.

Live-verified 2026-10-06 against a debug build at HEAD `a113e2aba` (harness
`.local/testing/lsp_test.py`):

| Document opened via `didOpen` | Content | Result |
|---|---|---|
| `pnpm-workspace.yaml` | `catalog: {react: ^16.0.0, lodash: 4.17.0}` and `catalogs: {legacy: {left-pad: ^1.0.0}}` | `[diagnostics] none received` |
| sibling `package.json` | `"react": "catalog:"`, `"left-pad": "catalog:legacy"` | 3 diagnostics: outdated (19.3.0), deprecated, vulnerability data not checked |

Two gaps follow:

1. **No signal on the edited file.** The YAML file is never routed to a dependency handler. The npm
   `Ecosystem` registers only `package.json` as a manifest filename; `pnpm-workspace.yaml` is
   registered only as a watched config (`RewritesRequirements`) that invalidates the referencing
   `package.json`.
2. **Signal on the wrong file.** The three diagnostics above point at the `package.json` reference,
   not at the catalog entry whose range is outdated. The fix (bumping the range) lives in the other
   file, and a code action offered on the reference has no sound way to edit it (see US-002).

> [!note] On the line-0 anchoring in the live result
> The live `package.json` fixture was a single-line JSON document, so "all anchored at line 0" is
> partly an artifact of the fixture and is not by itself proof of mis-anchoring. The gap is that
> the diagnostics are on the reference, never on the catalog entry. The tester should re-run with a
> pretty-printed manifest when verifying (see SC-001).

### Demand Signal

- `mpiton/zed-depsy` v2.1.1 (released 2026-10-05) shipped PR #407, "support pnpm-workspace.yaml as a
  dependency file", in both its LSP and its scan mode. This is a direct competitor to deps-lsp's Zed
  integration.
- GitHub Dependabot supports pnpm workspace catalogs (GA):
  [Dependabot now supports pnpm workspace catalogs](https://github.blog/changelog/2025-02-04-dependabot-now-supports-pnpm-workspace-catalogs-ga/).
- pnpm catalogs reference: [pnpm.io/catalogs](https://pnpm.io/catalogs).

### Goal

When a user opens a `pnpm-workspace.yaml`, every registry-resolvable catalog entry gets the same
hints, diagnostics, hover, completion, code actions and code lenses a `package.json` dependency
gets, positioned on the entry's own version text, with no duplicate or contradictory reporting
between the two files and no weakening of the existing resource caps.

### Out of Scope

> [!danger] Excluded
> - Resolving `workspace:` protocol references against sibling packages (already tracked as a
>   follow-up of [[046-pnpm-catalogs/spec|spec 046]]; not a catalog concern).
> - Package managers other than pnpm: Yarn's `.yarnrc.yml` catalogs and Bun's `catalog` /
>   `catalogs` fields inside `package.json` are separate formats and need their own spec.
> - Editing `pnpm-workspace.yaml` settings that are not dependency version specifiers (`packages:`
>   globs, `onlyBuiltDependencies`, `minimumReleaseAge` and similar).
> - Changing how `package.json` resolves `catalog:` specifiers, except the de-duplication
>   decision in D-2.
> - Any edit under `crates/deps-zed` (a separate repository and PR workflow; see D-8).
> - `overrides:` and every other non-catalog section of `pnpm-workspace.yaml` (D-3); follow-up issue F-1.
> - A "used by N packages" consumer list on hover (D-7); follow-up issue F-2.
> - Parsing the `catalogs:` section of `pnpm-lock.yaml` (D-4).
> - Registering the YAML language for this file in the Zed extension (D-8); follow-up issue F-3 in `bug-ops/deps-zed`.

## 2. User Stories

### US-001: See catalog freshness where I edit it
AS A developer maintaining a pnpm workspace
I WANT outdated, deprecated, yanked, vulnerable and unknown-package signals on each catalog entry
in `pnpm-workspace.yaml`
SO THAT I learn a shared version is stale at the moment I am looking at the file that controls it.

**Acceptance criteria:**
```
GIVEN a pnpm-workspace.yaml with `catalog: {react: ^16.0.0}` and a registry whose latest react is newer
WHEN the file is opened in the editor
THEN an outdated hint/diagnostic is anchored on the `^16.0.0` text of that entry
```

### US-002: Update a catalog entry from the editor
AS A developer
I WANT code actions and code lenses on a catalog entry that rewrite its version range in place
SO THAT one edit updates every workspace package that references the catalog.

**Acceptance criteria:**
```
GIVEN a catalog entry flagged outdated
WHEN I invoke the update code action on it
THEN only that entry's version text is replaced, in the same quoting style, and no other YAML byte changes
```

### US-003: Hover and completion inside a catalog
AS A developer adding a new catalog entry
I WANT package-name completion on the key and version completion on the value
SO THAT I edit the YAML with the same assistance as `package.json`.

**Acceptance criteria:**
```
GIVEN the cursor on the value of `catalog: {lodash: <cursor>}`
WHEN completion is requested
THEN versions of lodash from the npm registry are offered, ranked like package.json version completion
```

### US-004: No duplicate noise
AS A developer with both files open
I WANT one coherent report per outdated catalog entry
SO THAT I am not shown the same finding twice at different locations with different wording.

**Acceptance criteria:**
```
GIVEN package.json (`"react": "catalog:"`) and pnpm-workspace.yaml (`catalog: {react: ^16.0.0}`) both open
WHEN diagnostics are published for both
THEN the reporting follows the policy of D-2 (FR-031) and is identical on every run
```

## 3. Functional Requirements

EARS notation. Priority: must / should / could.

### 3.1 Recognition and routing

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a document whose file name is `pnpm-workspace.yaml` is opened or changed THE SYSTEM SHALL treat it as a dependency file and run the dependency pipeline on its catalog entries (routing per D-1: one npm ecosystem, content-dispatched by manifest kind) | must |
| FR-002 | THE SYSTEM SHALL NOT attempt to parse a `pnpm-workspace.yaml` document with the `package.json` (JSON) parser, nor a `package.json` document with the YAML parser | must |
| FR-003 | WHEN `pnpm-workspace.yaml` is both an open dependency file and a watched config of open `package.json` documents THE SYSTEM SHALL do both: refresh the file's own results and refresh every referencing `package.json` | must |
| FR-004 | WHEN a document has a non-`file:` URI (untitled, virtual) THE SYSTEM SHALL still produce entry-level results from the supplied text and SHALL NOT read the filesystem for ancestor config lookups it cannot anchor | should |

### 3.2 Catalog entries as dependencies

| ID | Requirement | Priority |
|----|------------|----------|
| FR-005 | WHEN the document has a top-level `catalog:` mapping THE SYSTEM SHALL treat each entry as a dependency of the default catalog | must |
| FR-006 | WHEN the document has `catalogs.<name>:` mappings THE SYSTEM SHALL treat each entry as a dependency of the named catalog `<name>` | must |
| FR-007 | WHEN `catalogs.default:` is used in place of a top-level `catalog:` THE SYSTEM SHALL treat its entries as default-catalog entries, identical to FR-005 | must |
| FR-008 | WHEN an entry's range is a registry range (semver range, dist-tag, exact version) THE SYSTEM SHALL resolve it through the same npm registry client, cache, comparison, cooldown, OSV and deps.dev machinery `package.json` dependencies use, with no parallel version-comparison path | must |
| FR-009 | WHEN an entry's specifier is a non-registry form already classified for `package.json` (`npm:` alias, `git`, `file:`, `link:`, URL) THE SYSTEM SHALL apply the same classification, not silently treat it as a registry range | must |
| FR-010 | WHEN an entry's value is a non-scalar (mapping, sequence) THE SYSTEM SHALL skip that entry without failing the rest of the file | must |
| FR-011 | WHEN the same package name appears in more than one catalog (default and `legacy`) THE SYSTEM SHALL report each entry independently at its own location | must |
| FR-012 | WHEN `catalog:` and `catalogs.default:` are both present THE SYSTEM SHALL keep surfacing entries per FR-005/FR-007 and SHALL handle the pnpm-rejected duplicate-default state per FR-030 | must |

### 3.3 LSP capabilities on catalog entries

| ID | Requirement | Priority |
|----|------------|----------|
| FR-013 | WHEN a catalog entry is outdated, deprecated, yanked, vulnerable, unknown or unsatisfiable THE SYSTEM SHALL publish the same diagnostic categories, severities and messages as for an equivalent `package.json` dependency, anchored on the entry's version text | must |
| FR-014 | THE SYSTEM SHALL provide inlay hints for catalog entries with the same latest/outdated markers as `package.json` | must |
| FR-015 | WHEN the cursor is on a catalog entry's key or version THE SYSTEM SHALL return hover content equivalent to `package.json` hover for the same package | must |
| FR-016 | WHEN completion is requested on a catalog entry's value THE SYSTEM SHALL offer registry versions, and WHEN requested on a key position THE SYSTEM SHALL offer package-name completion, both with the same ranking and limits as `package.json` | should |
| FR-017 | WHEN a catalog entry has an available update THE SYSTEM SHALL offer update and vulnerability-fix code actions that replace only that entry's version text, preserving its original quoting style | must |
| FR-018 | WHEN a catalog entry's version text is a placeholder, template or otherwise not a literal span the edit machinery can verify THE SYSTEM SHALL NOT offer a rewriting action for it (same guard that stops `"catalog:"` being rewritten in `package.json`) | must |
| FR-019 | THE SYSTEM SHALL provide the "update all outdated" code action and code lens for the file, covering every eligible entry across all catalogs | should |
| FR-020 | THE SYSTEM SHALL provide a document link for an entry equivalent to the existing `package.json` document links (registry page) | could |

### 3.4 Interaction with `package.json`

| ID | Requirement | Priority |
|----|------------|----------|
| FR-021 | WHEN several `package.json` files in a workspace reference the same catalog entry THE SYSTEM SHALL report that entry at most once in `pnpm-workspace.yaml` (one finding per entry, not per consumer) | must |
| FR-022 | WHEN both files are open and an entry is flagged THE SYSTEM SHALL apply the duplicate-reporting policy of D-2 deterministically (see FR-031) | must |
| FR-023 | WHEN an open `pnpm-workspace.yaml` is saved with a changed catalog entry THE SYSTEM SHALL refresh the diagnostics of referencing open `package.json` documents without requiring them to be re-edited. The refresh reads the on-disk file through the existing watched-config path, so unsaved keystrokes do not propagate (disk is the single source for LSP and CLI) | should |

### 3.5 Positions and YAML fidelity

| ID | Requirement | Priority |
|----|------------|----------|
| FR-024 | THE SYSTEM SHALL compute each entry's key range and version range from YAML source marks so that LSP ranges are correct for plain, single-quoted and double-quoted scalars (version range covers exactly the text a replacement must overwrite), for numeric-looking unquoted scalars (`react: 1.2`, cf. closed #721), and for flow-style mappings (`catalog: {react: ^16}`) | must |
| FR-025 | WHEN the file uses CRLF line endings, a BOM, non-ASCII content, comments between entries, or multiple YAML documents THE SYSTEM SHALL still produce correct UTF-16 LSP positions for every entry of the first document pnpm reads | must |
| FR-026 | WHEN an entry's value is a YAML alias or anchor, or a block scalar THE SYSTEM SHALL behave as specified in FR-032 and SHALL NEVER emit an edit whose range does not exactly cover the scalar it was computed from | must |
| FR-027 | WHEN the file is syntactically invalid YAML THE SYSTEM SHALL publish no entry-level findings, SHALL NOT panic, and SHALL leave `package.json` diagnostics behavior unchanged from today's defective-workspace messages. Duplicate YAML mapping keys count as malformed (`Malformed`, matching main's behavior) | must |

### 3.6 Overrides and related sections

| ID | Requirement | Priority |
|----|------------|----------|
| FR-028 | THE SYSTEM SHALL ignore the `overrides:` subtree and every section other than `catalog:` and `catalogs:` (D-3); it produces no dependency, finding or edit | must |
| FR-029 | WHEN the document contains `overrides:` selector syntax (`parent>child`, `pkg@range`) THE SYSTEM SHALL NOT mis-parse it as a catalog entry | must |

### 3.7 Resolved behavior (from section 9 decisions)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | WHEN both `catalog:` and `catalogs.default:` are present THE SYSTEM SHALL publish one Error-severity diagnostic of kind `DuplicateDefaultCatalog` (code `pnpm-duplicate-default-catalog`) in the YAML file, anchored on the `catalogs.default` key, stating that pnpm rejects the workspace, AND SHALL still surface the entries per FR-005/FR-007. `package.json` defect messages are unchanged | must |
| FR-031 | WHEN a `package.json` dependency uses a `catalog:` specifier and the referenced entry is located in `pnpm-workspace.yaml` THE SYSTEM SHALL keep the existing finding on the reference, append the suffix `(set in pnpm-workspace.yaml, catalog <id>)` to its message, and attach `related_information` pointing at that entry's version range (canonical file URI per spec 066). THE SYSTEM SHALL NOT offer a rewrite on the reference | must |
| FR-032 | WHEN an entry value is an alias (`react: *r`) THE SYSTEM SHALL anchor findings on the alias token span (including `*`) and offer no edit, update-all membership or completion. WHEN it is an anchor-defining scalar (`react: &r ^18`) THE SYSTEM SHALL treat it as an ordinary literal whose range excludes `&r`. WHEN it is a block scalar THE SYSTEM SHALL anchor findings (diagnostics, inlay hints, hover) on the block scalar indicator token in its header (`>-`, `|`, ...), because the scanner mark of a block scalar points at the first content line and using the content range would let the literal-span guard allow an edit; no edit or quickfix is offered and the version text is trimmed. WHEN it is a tagged non-string scalar or an escape-bearing quoted scalar THE SYSTEM SHALL produce findings only, no edit (same policy as [[056-gitlab-ci-yaml-scalar-anchor-alias/spec\|spec 056]]) | must |
| FR-036 | WHEN a catalog entry's value is empty (`react:` with no value) THE SYSTEM SHALL produce a zero-width, completable entry (`EntryValue::Empty`) so version completion works on the value position, with no finding and no edit other than completion | must |
| FR-033 | THE SYSTEM SHALL resolve the in-use version of an entry from the root `pnpm-lock.yaml` found by walking up from the YAML file, selecting the lock version that satisfies the entry's own range (importer pool plus the #649 candidate disambiguation) | should |
| FR-034 | WHEN `deps-cli check` or `deps-cli update` walks a workspace containing `pnpm-workspace.yaml` THE SYSTEM SHALL process it like any other manifest. An outdated entry is therefore reported once from the YAML and once from each referencing `package.json`, and `--fail-on` counts each report | must |
| FR-035 | THE SYSTEM SHALL classify `DuplicateDefaultCatalog` as `Category::Other` in the exhaustive `deps-cli` `classify` match and SHALL NOT add it to the default `--fail-on` set (`vulnerable,yanked,unsatisfiable`), so the CLI default is unchanged. The code `pnpm-duplicate-default-catalog` is the LSP diagnostic code only (editor filtering); the SARIF rule id follows the existing category mapping (`other`) and `sarif_rule_id` is not changed for typed diagnostics. Users can gate on it with `--fail-on other` | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Security (CWE-400) | All parsing of `pnpm-workspace.yaml` SHALL go through the existing YAML nesting-depth and alias-expansion bounds (`check_yaml_bounds`) and the file-size-capped read path (`fs_probe`), and each entry's range SHALL be length-capped before reaching the semver parser (`MAX_REQUIREMENT_LEN`, #1483/#1490). A crafted 7 MB file SHALL NOT reproduce the #1483 memory growth |
| NFR-002 | Security (CWE-400) | The per-document dependency count cap (`MAX_DEPENDENCIES_PER_DOCUMENT`) SHALL apply to catalog entries and its truncation SHALL be surfaced the same way as for other ecosystems |
| NFR-003 | Responsiveness | Handlers SHALL remain non-blocking: parsing happens off the request path or is cached, registry fetches are spawned, and hover/completion return from cached state. Parsing a typical catalog file (tens of entries) SHALL add no perceptible latency to `didOpen` |
| NFR-004 | Consistency | Shared behavior (YAML bounds, scalar normalization, anchor handling, position mapping, capped reads, ancestor `.npmrc` lookup) SHALL be reused from `deps-core` and the existing catalog parser, not re-implemented; the existing `catalog.rs` parse and this feature SHALL NOT disagree about which entries exist or what their value is (single interpretation of the file) |
| NFR-005 | Type safety | Catalog identity SHALL be a typed value that distinguishes the default catalog from a named one, so a user catalog literally named `default` cannot collide with the default catalog by string equality (the existing reserved-key string `"default"` is the anti-pattern to avoid). New enums SHALL be exhaustive with no catch-all arm. No new stringly-typed or `as_any()`-driven dispatch |
| NFR-006 | Identity | Document identity SHALL use the canonical-identity mechanism of [[066-canonical-document-identity/spec|spec 066]] so the same file reached through different URIs does not produce divergent state |
| NFR-007 | Compatibility | Existing `package.json` parsing, hover, completion and diagnostics SHALL NOT regress, except the additive message suffix and `related_information` of FR-031 (FR-035 changes no CLI default) (pre-1.0: documented in CHANGELOG, no deprecation shim) |
| NFR-008 | Observability | Failures to read or parse the workspace file SHALL be logged via `tracing` with the redaction rules already applied to paths and URLs |
| NFR-010 | Type safety (origin) | A dependency's provenance SHALL be one exhaustive `NpmDependencyOrigin` so a catalog entry that also carries a catalog reference is unrepresentable; `NpmDependencySection` stays `Copy`. Call sites SHALL use an exhaustive `match` on the origin, with no helper that defaults a missing section to `Dependencies` (peer/optional semantics) |
| NFR-011 | Known limitation | Because FR-023 is save-only, a related-information range may be stale against an unsaved YAML buffer until the next save. This is documented in the book |
| NFR-009 | Testability | Behavior SHALL be covered by unit tests, the existing YAML fuzz target retargeted at the new parser (cf. #727), a snapshot or protocol-level test, CLI `check`/`update` tests, and a live end-to-end run per the project's Registry Integration Gate |

## 5. Data Model

Conceptual only; representation is a plan-phase decision.

| Entity | Description | Key attributes |
|--------|-------------|----------------|
| Workspace catalog document | An opened `pnpm-workspace.yaml` | URI, text version, set of catalogs, parse defect (none / malformed / duplicate default) |
| Catalog | A named or default group of entries | typed identity (default vs named), definition site (`catalog:`, `catalogs.default:`, `catalogs.<name>:`) |
| Catalog entry | One package-to-range pair | package name, specifier text, key range, version range, quoting style, classification (registry / non-registry / malformed / aliased) |
| Catalog reference | A `package.json` dependency with a `catalog:` specifier (exists today) | package name, referenced catalog, resolution outcome |
| Entry finding | A diagnostic, hint, or action tied to an entry | entry identity, category, location in the YAML file |

> [!note]
> Today's catalog parser keeps only a name-to-range map and discards source positions, so entry
> locations do not exist anywhere yet. That is the central new information this feature needs.
> The typed representation is in [[plan]]: `CatalogId`, `CatalogSite`, `NpmDependencyOrigin`.

## 6. Edge Cases and Error Handling

| Scenario | Expected behavior |
|----------|-------------------|
| Entry `react: ^16.0.0`, `lodash: 4.17.0`, `left-pad: ^1.0.0` (the live fixture) | One finding set per entry, each anchored on its own range; `lodash` exact pin gets outdated and vulnerability findings |
| Same package in default and a named catalog with different ranges | Two independent findings at two locations |
| Quoted range `"^16.0.0"` / `'^16.0.0'` | Range and any edit preserve quotes; replacement never leaves unbalanced quotes |
| Unquoted numeric range `react: 1.2` | Treated as the string `1.2` (cf. #721), position correct, not "malformed" |
| `react: ${REACT_VERSION}`, `{{ X }}` placeholders | Treated as unresolved placeholder; no rewrite action (FR-018) |
| `react: npm:preact@^10` | Non-registry classification (FR-009), no registry lookup for `react` |
| `react: {version: ^18}` (mapping leaf) | Entry skipped (FR-010); rest of file unaffected |
| `catalog:` and `catalogs.default:` both present | FR-030: one `DuplicateDefaultCatalog` Error on the `catalogs.default` key, entries still surfaced; no panic; consumers' existing defect diagnostics unchanged |
| `catalog:` key present but null (commented-out block) | No entries, no finding, not malformed |
| YAML anchors/aliases in values | FR-032 |
| 7 MB crafted file / deep nesting / alias bomb | Rejected by existing bounds with a defective-file outcome; no memory spike |
| More than 5000 entries | Truncated at the cap with the standard truncation notice |
| Invalid YAML mid-edit (user is typing) | Previous stable results are not replaced by a flood of errors; no entry-level findings until the file parses (FR-027) |
| Scoped package `@scope/pkg` with a scoped registry in an ancestor `.npmrc` | Registry routing resolved from the YAML file's own directory, same as for a sibling `package.json` |
| Registry unreachable | Same degradation as `package.json`: no false "outdated", cached data used where available |
| File opened but no `catalog`/`catalogs` section | Silent: no diagnostics, no errors |
| Editor not attached to the server for YAML files | Out of server control; see D-8 |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Live replay of the finding's fixture (`catalog: {react: ^16.0.0, lodash: 4.17.0}`, `catalogs: {legacy: {left-pad: ^1.0.0}}`) with a pretty-printed sibling `package.json` | `didOpen` of the YAML yields at least one finding on each of the three entries, each anchored on that entry's own version text (before: zero) |
| SC-002 | Update code action on `react: ^16.0.0` | Resulting YAML differs from the original only in that scalar; re-parse yields the new range; idempotent on a second run |
| SC-003 | Position accuracy matrix (plain / single / double quoted, numeric, flow mapping, CRLF, BOM, non-ASCII, comments) | 100% of entries have exact ranges in a table-driven test |
| SC-004 | Resource-cap regression: 7 MB `pnpm-workspace.yaml`, deep nesting, alias bomb | Peak RSS stays within the bounds already asserted for #1483; handler returns without panic |
| SC-005 | Duplicate-reporting scenario (both files open) | Exactly the outcome specified by FR-031 (finding in both files, suffix plus related information on the reference, one finding per entry in the YAML), verified live |
| SC-006 | `package.json` regression | Existing `deps-npm` and `deps-lsp` tests pass unchanged except the FR-031 message-suffix expectation |
| SC-009 | `deps-cli update` on catalog entries | `current` is empty for a catalog entry exactly as for a `package.json` entry when there is no lock file (parity, SC-007); with a root `pnpm-lock.yaml` the in-use version is shown |
| SC-008 | CLI: `deps-cli check` and `update` on the fixture workspace | The YAML is processed; an outdated entry is reported once from the YAML and once per referencing `package.json`; a duplicate-default fixture is reported as `other` and does not change the exit code under the default `--fail-on` |
| SC-007 | Cross-ecosystem consistency check | Hover, diagnostics and inlay hints for a catalog entry match those of the same package in a `package.json` (same wording, category, version badge format) |

## 8. Agent Boundaries

### Always (without asking)
- Reuse `deps-core` helpers (`check_yaml_bounds`, `yaml_scalar_string`, `yaml_anchor`, `yaml_walk`, `fs_probe::read_to_string_capped`, `MAX_DEPENDENCIES_PER_DOCUMENT`) before writing ecosystem-local code.
- Run the registry integration gate live against the npm registry and add the repro to `.local/testing/regressions.md`.
- Keep `EcosystemId` and any new enum exhaustive with no `_ =>` arm.
- Update `CHANGELOG.md` (one line, PR link), the mdBook ecosystem reference for npm, and the testing knowledge base (`coverage.md`, npm playbook).

### Ask first
- Introducing a new `EcosystemId` variant or a second `Ecosystem` implementation (rejected in D-1).
- Removing or rewording `package.json` findings for `catalog:` references beyond FR-031 (D-2 keeps them).
- Adding any dependency, or any new YAML parsing approach beyond the existing `yaml-rust2` stack.
- Widening scope to `overrides:` or consumer discovery (D-3, D-7).

### Never
- Edit files under `crates/deps-zed`.
- Weaken or bypass the YAML depth/expansion bounds, the capped read, or the requirement-length cap.
- Emit a rewrite whose range was not computed from the scalar it replaces, or rewrite a `catalog:` specifier into a literal version.
- Use `serde_yaml` / `serde_yml`.
- Introduce stringly-typed catalog identity.

## 9. Resolved Decisions

> [!success] All nine former `[NEEDS CLARIFICATION]` items are resolved (architect design 2026-10-21, critic-reviewed). Open items: 0.

| ID | Former question | Decision |
|----|-----------------|----------|
| D-1 | OQ-1 Routing | One ecosystem, two formats. Add `pnpm-workspace.yaml` to npm `manifest_filenames()`; no 15th `EcosystemId`. `parse_manifest` dispatches on the exhaustive `NpmManifestKind { PackageJson, PnpmWorkspace }` (precedent: `PypiManifestKind::from_uri`). Manifest routing (`for_uri`) and `for_watched_config` are independent pipelines, so both keep running and FR-003 holds with no precedence logic. The npm `ecosystem_conformance!` pin is updated. A second `Ecosystem` was rejected: it forces a new `EcosystemId` arm everywhere and duplicates registry and formatter wiring. |
| D-2 | OQ-2 Duplicate reporting | Option (c): `package.json` keeps its findings for `catalog:` references and gains the message suffix plus `related_information` (FR-031); the YAML gets one finding per entry (FR-021). Removing the `package.json` findings (b) would drop shipped behavior for users who never open the YAML. CLI duplicates are accepted and documented (FR-034). |
| D-3 | OQ-3 `overrides` | Out of v1. Selector grammar is a different parser; the receiver classifies the subtree as irrelevant (FR-028). Follow-up F-1. |
| D-4 | OQ-4 Lockfile | In-use version from the existing pnpm-lock provider: `locate_lockfile` walks up from the YAML file to the root `pnpm-lock.yaml`; importer pool plus #649 candidates select the version satisfying each entry's own range (FR-033). No `catalogs:` lockfile section parsing, so no new lockfile code. |
| D-5 | OQ-5 Anchors | Same policy as spec 056 (FR-032). |
| D-6 | OQ-6 Surface | (a) CLI parity is in this PR: `deps-cli` routes through `registry.for_uri` so it picks the file up automatically, and excluding it would need a deliberate filter (FR-034). (b) Duplicate default yields one YAML diagnostic (FR-030) with its own kind and code, classified `Other` with no CLI default change (FR-035). |
| D-7 | OQ-7 Consumers | No "used by N packages" in v1 (needs workspace-wide discovery). Follow-up F-2. |
| D-8 | OQ-8 Client | Server side is done here. The mdBook npm page documents client association (VS Code `documentSelector`, Neovim filetypes/root). The Zed side is follow-up F-3 in `bug-ops/deps-zed`. |
| D-9 | OQ-9 Tracking | Tracking issue is #1788. |

### Follow-up issues to file (by the lead; links to external repositories wrapped in backticks)

| ID | Title | Labels |
|----|-------|--------|
| F-1 | pnpm-workspace.yaml: dependency hints for `overrides:` entries (selector grammar `a>b`, `pkg@range`) | `enhancement`, `P4` |
| F-2 | Hover on a catalog entry: "used by N packages" via workspace-wide discovery of referencing `package.json` files | `enhancement`, `P4` |
| F-3 | (`bug-ops/deps-zed`) Associate `pnpm-workspace.yaml` with deps-lsp in the Zed extension (the YAML language is also claimed by other servers) | `enhancement`, `P3` |

## 10. See Also

- [[MOC-specs]] — all specifications
- [[plan]] and [[tasks]] — technical design and implementation tasks for this spec
- [[046-pnpm-catalogs/spec|046 pnpm catalogs]] — the read side this spec extends; its Out of Scope explicitly excluded write-back to `pnpm-workspace.yaml`, which this spec reverses for entry-level edits
- [[052-pnpm-lockfile-provider/spec|052 pnpm lockfile provider]] — in-use version source (D-4)
- [[014-github-actions-ecosystem/spec|014 GitHub Actions ecosystem]] and [[056-gitlab-ci-yaml-scalar-anchor-alias/spec|056 GitLab CI anchors/aliases]] — prior YAML-as-manifest precedents in this workspace
- [[062-cli-check-mode/spec|062 CLI check mode]] and [[064-deps-cli-lsp-isolation/spec|064 CLI/LSP isolation]] — CLI parity constraints (D-6)
- [[066-canonical-document-identity/spec|066 canonical document identity]] — NFR-006
- Closed issues: #587, #590 (catalog resolution and watch), #721 (YAML numeric scalar positions), #1483, #1490 (CWE-400 range caps)
- [pnpm catalogs](https://pnpm.io/catalogs), [Dependabot catalog support](https://github.blog/changelog/2025-02-04-dependabot-now-supports-pnpm-workspace-catalogs-ga/)
- Competitor: `mpiton/zed-depsy` v2.1.1, PR #407

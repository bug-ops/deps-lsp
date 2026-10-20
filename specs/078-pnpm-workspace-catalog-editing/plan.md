---
tags:
  - sdd
  - plan
  - ecosystem/npm
  - pnpm
created: 2026-10-21
status: plan
related:
  - "[[spec]]"
  - "[[tasks]]"
  - "[[MOC-specs]]"
  - "[[046-pnpm-catalogs/spec|046 pnpm catalogs]]"
  - "[[052-pnpm-lockfile-provider/spec|052 pnpm lockfile provider]]"
  - "[[056-gitlab-ci-yaml-scalar-anchor-alias/spec|056 YAML anchors/aliases]]"
  - "[[066-canonical-document-identity/spec|066 canonical document identity]]"
---

# Plan: `pnpm-workspace.yaml` catalog entries as npm dependencies

Implements [[spec]] (issue #1788). Crates: `deps-npm` (almost everything), `deps-core` (one `DiagnosticKind`),
`deps-cli` (category + help text), `deps-lsp` (conformance pin only). Docs: book `npm.md`.

## 1. Architecture

```
didOpen/didChange pnpm-workspace.yaml
  -> EcosystemRegistry::for_uri (basename in npm manifest_filenames)
  -> NpmEcosystem::parse_manifest
       NpmManifestKind::from_uri -> PnpmWorkspace
       parse_workspace_document(content) -> WorkspaceDocument      (single interpretation)
       WorkspaceDocument -> NpmParseResult { dependencies: Vec<NpmDependency{origin: CatalogEntry}> , defects }
  -> existing fetch / diagnostics / hover / completion / code-action pipeline
package.json (catalog: reference)
  -> PnpmWorkspaceConfig derived from the same WorkspaceDocument (disk read via watched config)
  -> CatalogOrigin { id, entry: Option<CatalogEntryLocation> }
```

`for_watched_config` keeps invalidating referencing `package.json` documents independently of manifest routing, so
FR-003 needs no new precedence rule.

## 2. Typed design

```rust
pub enum NpmManifestKind { PackageJson, PnpmWorkspace }          // from_uri, exhaustive

pub enum CatalogId { Default, Named(CatalogName) }               // from_catalogs_key("default") == Default
pub enum CatalogSite { TopLevelCatalog, CatalogsDefault, CatalogsNamed }

pub enum NpmDependencyOrigin {
    Manifest { section: NpmDependencySection, catalog_ref: Option<CatalogOrigin> },
    CatalogEntry { id: CatalogId, site: CatalogSite },
}

pub struct CatalogEntryLocation { pub file: Url, pub range: Range }   // canonical URI (spec 066)
pub struct CatalogOrigin { /* existing */ pub entry: Option<CatalogEntryLocation> }
```

- `NpmDependency.section` and `NpmDependency.catalog` are replaced by `origin`. `NpmDependencySection` is unchanged and `Copy`.
  A catalog entry carrying a catalog reference is unrepresentable (NFR-010).
- The 19 non-test `.section` reads become exhaustive matches on `origin`. No `section() -> Option` helper (a `None`
  defaulting to `Dependencies` would silently apply peer/optional semantics).
- `DEFAULT_CATALOG_KEY` is removed; catalog maps key on `CatalogId`.
- `DiagnosticKind::DuplicateDefaultCatalog` (deps-core): code `pnpm-duplicate-default-catalog`, severity Error. The
  exhaustive `deps-cli` `classify` match maps it to `Category::Other`; the default fail set is unchanged, so there is
  no CLI behavior change and no `### Changed` entry. The code stays for editor filtering and the SARIF rule id.

## 3. Parser

`parse_workspace_document(content) -> WorkspaceDocument` replaces the `YamlLoader` parse in `catalog.rs`. Built on
`deps_core::yaml_walk::FrameStack`, `yaml_anchor::ScalarAnchorTable`, `LineOffsetTable`/`MarkedScalar` and
`check_yaml_bounds`, with the `deps-dart` receiver as the template.

- Reads only `catalog:` and `catalogs:`; every other key (`packages`, `overrides`, settings) is skipped by the walker.
- Entry value classes: plain / quoted literal, numeric-looking scalar (string `1.2`, cf. #721), alias (finding on the
  `*r` span, `version_literal = None`), anchor-defining scalar (range excludes `&r`), block scalar / tagged scalar
  (findings only), mapping / sequence (skipped).
- Capture the quoting style so edits preserve it; apply `MAX_REQUIREMENT_LEN` and `MAX_DEPENDENCIES_PER_DOCUMENT`.
- A syntactically invalid document yields a defect and zero entries (FR-027).
- Duplicate default (`catalog:` plus `catalogs.default:`) yields entries from both and a `DuplicateDefaultCatalog`
  defect anchored on the `catalogs.default` key.
- The existing fuzz target is retargeted to this parser.

## 4. package.json side (OQ-2 option c)

`CatalogOrigin.entry` is filled from the positioned parse. The npm diagnostics override appends
`(set in pnpm-workspace.yaml, catalog <id>)` and attaches `related_information` pointing at the entry range. The file
URI is built from the canonical path used by the spec 066 identity (`find_workspace_file` path, canonicalized) and
mapped by deps-lsp through `lsp_types_interop::canonicalize_uri`. No code action is offered on the reference.

## 5. In-use version

`locate_lockfile` walks up from the YAML to the root `pnpm-lock.yaml`; the flattened importer pool plus #649 candidates
pick the version satisfying the entry's own range. No `catalogs:` lockfile parsing.

## 6. Ecosystem wiring

- `manifest_filenames()` gains `"pnpm-workspace.yaml"`; the npm `ecosystem_conformance!` pin is updated.
- `NpmEcosystem::parse_manifest` dispatches on `NpmManifestKind`; formatter and code-action edit paths reuse
  `NpmDependency` unchanged (FR-009 classification, FR-017 edits), with `CatalogEntry` literal ranges.
- Registry routing for scoped packages uses the YAML file's own directory (ancestor `.npmrc`).
- Non-`file:` URIs use the supplied text only and skip ancestor lookups (FR-004).

## 7. Testing strategy

| Layer | Cases |
|-------|-------|
| Unit (deps-npm) | position matrix SC-003 (plain/single/double quoted, numeric, flow mapping, CRLF, BOM, non-ASCII, comments, multi-document); alias/anchor/block-scalar policy; `CatalogId` default vs `Named("default")` collision; `NpmDependencyOrigin` exhaustiveness; duplicate default; invalid YAML |
| Cap/bounds | 7 MB file, deep nesting, alias bomb (SC-004); 5001 entries truncation |
| Edits | update only the entry scalar, quoting preserved, idempotent re-parse (SC-002); no edit for placeholders/aliases |
| Protocol (deps-lsp) | open YAML yields hints, diagnostics, hover, completion, code actions; `package.json` suffix and `related_information`; save refreshes referencing `package.json` |
| CLI | `check`/`update` on a fixture workspace (SC-008); duplicate-default reported as `other`, exit code unchanged under default `--fail-on`; `--fail-on` counts both reports |
| Snapshot | insta snapshot of YAML diagnostics vs the equivalent `package.json` (SC-007) |
| Live | Registry Integration Gate against npm with the SC-001 fixture; add to `.local/testing/regressions.md`, `coverage.md` npm row and playbook |

## 8. Security, performance, risks

- NFR-001/002 bounds are mandatory; no new dependency; `yaml-rust2` only.
- Handlers stay non-blocking: parse is synchronous and bounded, fetches spawn as for `package.json`.
- Risk: other YAML language servers also attach to the file (client side, documented). Risk: some yaml-rust2 scalar
  marks exclude quotes (covered by the position matrix). Known limitation NFR-011 (stale related range until save).

## 9. Constitution and compliance

Exhaustive enums without `_ =>`, no `as_any()`, no stringly identity, typed `thiserror` errors, `///` docs with
doctests on new pub items, CHANGELOG one line with PR link, book npm page plus editor-setup section.

## 10. Rollout

Single PR. Docs: book `npm.md` (catalog editing, editor association for VS Code and Neovim, CLI duplicate note, stale
range limitation), CLI chapter (note that `DuplicateDefaultCatalog` is `other`).

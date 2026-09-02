---
aliases:
  - Deno/JSR Ecosystem Support
  - New Ecosystem: Deno
tags:
  - sdd
  - spec
  - research
  - ecosystem/deno
  - new-ecosystem
  - priority/p3
created: 2026-08-23
status: draft
related:
  - "[[MOC-specs]]"
---

# Feature: New ecosystem — Deno/JSR (deno.json / deno.jsonc)

> [!info] Metadata
> **Author**: on-demand competitive-parity scan 2026-08-23 (research finding)
> **Branch**: [NEEDS CLARIFICATION: assign issue number before branching, e.g. `feat/<issue>-deno-jsr`]
> **Type**: research / new ecosystem — this spec documents WHAT is missing and WHY; the HOW (exact client reuse strategy, JSONC comment handling, JSR API versioning) is deferred to a future `/sdd plan` session.

## 1. Overview

### Problem Statement

deps-lsp currently supports 11 package ecosystems (Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Gradle, Swift, Composer, NuGet). Deno is a JavaScript/TypeScript runtime with growing adoption in the developer tools and LSP-editor communities — particularly among Zed users. Deno manifests (`deno.json` / `deno.jsonc`) declare dependencies as `jsr:` (JSR registry) and `npm:` (npm registry) specifiers in an `imports` map, with full version lists and yanked-version metadata available via a keyless JSR API.

Three reference projects have shipped Deno support in 2026 or recently: Dependi (shipped v0.7.24 by user request #294), Dependabot (ecosystem added 2026), and Renovate (dedicated `deno` manager). Version Lens also lists Deno. This represents the strongest cross-project consensus among new-ecosystem candidates in the 2026-08-23 competitive-parity scan.

Cheapest true new ecosystem to add: manifest is JSON (like npm's `package.json`, parsing is straightforward); `jsr:` specifiers use the JSR API (verified live at `https://jsr.io/@{scope}/{pkg}/meta.json`); `npm:` specifiers reuse the existing `deps-npm` registry client and `node-semver` comparison logic — both are already-written and battle-tested. No new version-comparison crate needed.

### Goal

deps-lsp recognizes `deno.json` and `deno.jsonc` manifest files, parses the `imports` map, routes JSR-specifier packages to a new JSR registry client, routes npm-specifier packages to the existing npm client, and renders `hover`, `latest-version inlay hints`, `outdated+yanked diagnostics`, `version completion`, and `update code actions` with the same fidelity and consistency as other supported ecosystems.

### Out of Scope

- The `scopes` field in Deno manifests (`"scopes": { "@myorg/": "https://..." }`) — an alternative imports mechanism with lower prevalence. [NEEDS CLARIFICATION: confirm, or lift into FR.]
- Import maps referenced via `importMap` field (e.g., a separate `deno.importMap.json` file) — distinct from direct `imports` in the manifest itself.
- https:// URL imports (legacy `deno.land/x` ecosystem — now migrating to JSR; out of scope as a separate, manual versioning burden).
- `package.json` interoperability in Deno projects (Deno v1.40+ reads `package.json` for npm dependencies) — already handled by `deps-npm` when a `package.json` file is opened; Deno + package.json coexistence in the same project is transparent at the LSP handler level.
- `deno.lock` resolved-version support — lockfile parsing is not required for the initial MVP (same as npm's `package-lock.json` — hover/completion/diagnostics work on the manifest alone); lockfile support is a possible future increment if demand arises.

## 2. User Stories

### US-001: See and update JSR package versions in deno.json

AS A Deno developer with a manifest file declaring JSR dependencies (e.g., `"jsr:@std/fs@1.2"`)
I WANT to hover over a JSR package name, see the latest version and whether my declared version is outdated, and have a code action to update to the latest
SO THAT I can keep JSR dependencies current without manually checking the JSR registry.

**Acceptance criteria:**
```
GIVEN an open deno.json with a JSR specifier (e.g., "jsr:@std/fs@1.2")
WHEN the editor requests hover for that specifier
THEN the server SHALL return metadata including the package name, description (if available),
     latest version, and outdated/up-to-date status
AND a code action SHALL be available to update to the latest version
```

### US-002: See and update npm package versions in deno.json

AS A Deno developer with npm dependencies declared via `npm:` specifiers (e.g., `"npm:react@18"`)
I WANT the same hover/completion/diagnostic experience for npm packages as I would see in a
`package.json` file, applied to the `npm:` specifier in deno.json
SO THAT switching between npm and JSR dependencies is transparent and consistent.

**Acceptance criteria:**
```
GIVEN an open deno.json with an npm specifier (e.g., "npm:react@18")
WHEN the editor requests hover for that specifier
THEN the server SHALL return the same metadata and code actions as would be rendered for the
     same package in a package.json file, using the existing deps-npm registry client
```

### US-003: No noise for valid, up-to-date versions

AS A Deno developer with a manifest file where all declared dependencies match their latest
available versions
I WANT no diagnostics or "outdated" inlay hints to appear for those dependencies
SO THAT the manifest is clean and I can focus on actual version work.

**Acceptance criteria:**
```
GIVEN an open deno.json where every dependency's declared version matches (or is a valid range
     accepting) the latest published version
WHEN the editor requests diagnostics/inlay hints
THEN the server SHALL NOT render outdated warnings or badges for those dependencies
```

### US-004: Consistent behavior across JSR, npm, and other ecosystems

AS A Deno developer working in a polyglot monorepo with Cargo.toml, package.json, and deno.json
files
I WANT the hover format, diagnostic wording, code-action labels, and version-comparison logic to
be identical across all three files
SO THAT I can use deps-lsp consistently across the whole project without context-switching.

**Acceptance criteria:**
```
GIVEN three open manifests (Cargo.toml, package.json, deno.json) each with one outdated
     dependency of the same degree of outdatedness (e.g., all one major version behind latest)
WHEN the editor requests diagnostics for each
THEN the diagnostic message text, severity, and suggested version SHALL be equivalent across
     all three, per the cross-ecosystem-consistency rule
     (`.claude/rules/continuous-improvement.md#Cross-Ecosystem Consistency Testing`)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL advertise recognition of `deno.json` and `deno.jsonc` manifest files, detected by exact filename match in `crates/deps-core/src/ecosystem_registry.rs`'s `filename_map` (alongside `Cargo.toml`, `package.json`, etc.) | must |
| FR-002 | THE SYSTEM SHALL add `Deno` to the `EcosystemId` enum in `crates/deps-core/src/ecosystem.rs` (exhaustive match enforcer for all code that branches on ecosystem identity) | must |
| FR-003 | THE SYSTEM SHALL implement `Ecosystem` trait in a new crate `crates/deps-deno/src/ecosystem.rs` providing `manifest_filenames()` returning `["deno.json", "deno.jsonc"]`, `parse_manifest()` that decodes JSON/JSONC and extracts the `imports` map, and `registry()` returning a `Box<dyn Registry>` | must |
| FR-004 | WHEN parsing `deno.json`/`deno.jsonc` THE SYSTEM SHALL handle JSONC comment syntax (line comments `//`, block comments `/* */`) without crashing — [NEEDS CLARIFICATION: reuse existing JSONC library or strip comments before serde_json::parse?] | must |
| FR-005 | FOR each import in the `imports` map THE SYSTEM SHALL classify it as either `jsr:` (routed to JSR registry) or `npm:` (routed to existing npm registry) and extract the scope/package name and version requirement — [NEEDS CLARIFICATION: exact parsing of `jsr:@scope/pkg@req` and `npm:pkg@req` format, including prerelease/tag suffixes] | must |
| FR-006 | THE SYSTEM SHALL implement a JSR registry client in `crates/deps-deno/src/registry.rs` that fetches package metadata from the JSR API (`https://jsr.io/@{scope}/{pkg}/meta.json`), parses the response to extract version list and yanked flags, and implements the `Registry` trait (get_versions, get_latest_matching, search, package_url) | must |
| FR-007 | FOR `npm:` specifiers in deno.json THE SYSTEM SHALL route to the existing `deps-npm` registry client — [NEEDS CLARIFICATION: instantiate a separate NpmRegistry within the Deno ecosystem implementation, or reference it from `deps-core` / a shared location?] | must |
| FR-008 | THE SYSTEM SHALL compute version-comparison status (outdated/up-to-date/unknown/yanked) for JSR specifiers using existing `deps-core` version-comparison traits and logic (not a per-ecosystem duplicate) | must |
| FR-009 | THE SYSTEM SHALL compute version-comparison status for `npm:` specifiers using the existing `node-semver` comparison logic (reuse, no duplication) | must |
| FR-010 | THE SYSTEM SHALL render `hover`, `inlay_hint`, `diagnostic`, `completion`, and `code_action` for Deno manifests using the existing LSP handlers (generic across ecosystems), with no Deno-specific handler code — handlers dispatch via `EcosystemRegistry::get_for_uri()` which now returns the Deno ecosystem for `deno.json`/`deno.jsonc` URIs | must |
| FR-011 | THE SYSTEM SHALL support version completion (via LSP `completion` request) for Deno specifiers, offering version suggestions from the JSR or npm registry as appropriate | should |
| FR-012 | THE SYSTEM SHALL support code actions (via LSP `code_action` request) to update an outdated Deno specifier to its latest version, reusing the existing `deps-lsp.updateVersion` execute_command pathway | must |
| FR-013 | THE SYSTEM SHALL produce equivalent hoverers across all 12 ecosystems (the existing 11 + Deno), with no ecosystem-specific divergence in format, wording, or metadata displayed — any divergence is a first-class bug | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | JSR API fetches SHALL use the existing HTTP cache (`crates/deps-core/src/http_cache.rs`) with appropriate TTL tuning (no additional network calls beyond what other ecosystems incur) |
| NFR-002 | Performance | Parsing JSONC in deno.json/deno.jsonc SHALL NOT add measurable latency vs. parsing package.json; target the same sub-50ms cold-start window |
| NFR-003 | Compatibility | Adding Deno support SHALL NOT alter existing Cargo/npm/PyPI/Go/Bundler/Dart/Maven/Gradle/Swift/Composer/NuGet behavior — ecosystem detection is additive, no breaking changes to other ecosystems |
| NFR-004 | Consistency | Hover format, inlay hint badge style, diagnostic severity, and code-action labels SHALL be identical across JSR, npm (in deno.json), and all other ecosystems — no Deno-specific formatting exceptions |
| NFR-005 | Maintainability | The JSR registry client SHALL be co-located in `crates/deps-deno/src/registry.rs`, not in a shared `crates/deps-core` location — ecosystem-specific clients are already per-ecosystem (npm, Cargo, etc.), not shared |
| NFR-006 | Maintainability | Code SHALL follow existing patterns from `crates/deps-npm/` for JSON parsing, version handling, and registry API calls — consistency across ecosystem crates makes future maintenance easier |

## 5. Data Model

No new persistent entities. Deno dependencies are parsed into the same `Dependency` trait interface used by all ecosystems.

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| Deno manifest | `deno.json` or `deno.jsonc` file | File URI, parsed `imports` map |
| Deno import entry | An entry in the `imports` map (e.g., `"@std/fs": "jsr:@std/fs@1.2.0"`) | import alias (key), specifier (value: `jsr:` or `npm:` form), package name (extracted), version requirement (extracted) |
| JSR version list | Response from JSR API `https://jsr.io/@{scope}/{pkg}/meta.json` | Latest version string, full version array, yanked flags per version |
| JSR/npm dependency (derived) | Unified representation of a parsed Deno import as the `Dependency` trait interface | Name, requirement string, status (outdated/up-to-date/unknown/yanked) |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| deno.json with malformed JSON | File is not recognized as a Deno manifest (fails to parse); graceful degradation (no hover/diagnostics) — same behavior as malformed package.json |
| deno.jsonc with unclosed block comment | File is not recognized; graceful degradation |
| deno.json with empty `imports` map | File is recognized and opened; zero dependencies parsed; no diagnostics/hints (consistent with an empty package.json) |
| deno.json with unsupported specifier format (e.g., `http://` or `file://` URL) | Import is skipped/ignored during parsing; no error message to user (same pattern as how unknown/unparseable entries are handled in other ecosystems) |
| JSR registry API unreachable or returns 404 for a package | Package status is marked as `Unknown` (same as when npm registry is unreachable); diagnostic shows "Unknown package"; no hover metadata |
| JSR API returns malformed metadata | Registry error is logged; package treated as `Unknown` (graceful degradation) |
| `npm:` specifier in deno.json, npm registry unreachable | Reuses existing npm registry error handling (package marked `Unknown`) |
| deno.json declares `npm:react@^18` (a range), npm registry returns yanked versions in the range | Version comparison uses existing `node-semver` logic; yanked flag is respected (consistent with npm's own behavior in package.json) |
| deno.json has both `jsr:` and `npm:` specifiers in the same `imports` map | Both are parsed and displayed correctly; JSR uses JSR registry, npm uses npm registry; no crosstalk |
| deno.json with duplicate import keys (e.g., two `"@std/fs"` entries) | JSON parser fails or last entry wins (JSON spec dictates last-wins); behavior is deterministic and consistent with package.json handling |
| `@scope/pkg` package name in JSR (scope required) vs. unscoped npm | JSR API requires scope in the URL path; parsing correctly extracts `@scope/pkg` and routes to `jsr.io/@scope/pkg/meta.json`; no collisions |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `Deno` variant present in `EcosystemId` enum (`crates/deps-core/src/ecosystem.rs`) | Compile error if missing (exhaustive match) |
| SC-002 | `deno.json` and `deno.jsonc` filenames registered in ecosystem detection (`crates/deps-core/src/ecosystem_registry.rs`) | Both filenames resolve to Deno ecosystem via `get_for_filename()` |
| SC-003 | JSR package versions fetched and compared correctly | Live test: open deno.json with JSR specifier, hover shows latest version and outdated/up-to-date status matching JSR API response; diagnostic count and code actions agree with other ecosystems |
| SC-004 | npm specifiers in deno.json use existing npm registry client | Live test: open deno.json with `npm:react@18`, hover/diagnostics/completions match behavior in package.json for the same package |
| SC-005 | No regressions in existing 11 ecosystems | Full regression suite: `cargo nextest run --workspace --all-features` passes; no changes to Cargo/npm/PyPI/Go/Bundler/Dart/Maven/Gradle/Swift/Composer/NuGet behavior |
| SC-006 | Cross-ecosystem consistency verified | Live test session (documented in `.local/testing/coverage.md`): open identical dependency-update scenarios in Cargo.toml, package.json, and deno.json; verify hover format, diagnostic wording, inlay hints, and code actions are identical across all three |
| SC-007 | Feature flag wired correctly | `deno` feature in root `Cargo.toml`; `deps-deno` crate builds when enabled; `deps-lsp` server sees Deno ecosystem when compiled with `cargo build --all-features` |
| SC-008 | Coverage and playbook added | Row added to `.local/testing/coverage.md` for Deno ecosystem; new playbook file `.local/testing/playbooks/deno.md` with verified test manifests and known issues |

## 8. Agent Boundaries

### Always (without asking)
- Reuse existing `deps-core` version-comparison traits and logic (no duplication).
- Reuse existing npm registry client for `npm:` specifiers (no reimplementation).
- Use the same LSP handlers (hover, completion, diagnostics, code actions, inlay hints) that are already generic across ecosystems — no Deno-specific handler code should be written.
- Follow the existing pattern from `crates/deps-npm/` for JSON parsing, error handling, and registry API calls.
- Run the full check suite (`cargo +nightly fmt --check`, `cargo clippy --all-targets --all-features --workspace -- -D warnings`, `cargo nextest run --workspace --all-features`) before considering any implementation complete.

### Ask First
- If the `scopes` field should be supported (currently marked out of scope) — clarify scope before implementation.
- If the `importMap` field (import maps from a separate file) should be supported — needs design discussion.
- If JSONC parsing should use a dedicated library vs. stripping comments with regex before `serde_json::parse` — implementation trade-off worth discussing.
- How to structure the npm registry client usage within `deps-deno`: instantiate a new `NpmRegistry` within the Deno ecosystem, or reference it from a shared location in `deps-core`? (Registry trait is already per-ecosystem, so instantiation in `deps-deno` is the pattern, but confirm.)
- Whether `deno.lock` resolved-version support is desired for the initial MVP, or deferred as a future increment.

### Never
- Introduce Deno-specific LSP handlers — all handlers (hover, completion, etc.) remain generic and dispatch via `EcosystemRegistry`.
- Diverge from other ecosystems' hover format, diagnostic wording, or inlay hint style — cross-ecosystem consistency is non-negotiable.
- Create a parallel, separate version-comparison implementation for JSR — reuse `deps-core` traits.
- Modify the existing 11 ecosystems' behavior as a side effect of adding Deno.

## 9. Open Questions

- [NEEDS CLARIFICATION: Should `scopes` field in deno.json be supported? (Currently out of scope per Overview, but confirm if it is needed for initial MVP or Phase 2.)]
- [NEEDS CLARIFICATION: Exact JSONC parsing strategy — reuse a library like `jsonc-parser` crate, strip comments with regex, or use a different approach? What does deps-npm do for package.json, and would the same pattern work for JSONC?]
- [NEEDS CLARIFICATION: How to instantiate the npm registry client within the Deno ecosystem implementation? Should `NpmRegistry` be instantiated inside `deps-deno::DenoEcosystem::new()`, or referenced from `deps-core`? (Existing pattern: each ecosystem crate has its own registry, e.g., `deps-npm::NpmRegistry`.)]
- [NEEDS CLARIFICATION: Version requirement format for `npm:` specifiers in Deno (e.g., is `npm:react@^18.0` vs. `npm:react@18.0` the format, or does Deno use a different specifier syntax?) — verify against live deno.json examples.]
- [NEEDS CLARIFICATION: Should locked versions from `deno.lock` be parsed and used for resolved-version inlay hints (similar to lockfile support in other ecosystems)? Or is manifest-only comparison sufficient for MVP?]
- [NEEDS CLARIFICATION: Does the JSR API include a search endpoint for package-name completion, or should completion use an exact-match-only approach (like some ecosystems do)?]
- [NEEDS CLARIFICATION: No project constitution exists yet at `.local/specs/constitution.md` — this spec cannot yet be checked against project-wide architectural principles. Recommend running `/sdd init` before `/sdd plan` for this feature.]

## 10. See Also

- `.local/testing/issue-drafts-2026-08-23.md` (Draft 5: Deno/JSR) — original research finding with live API verification
- `.local/testing/playbooks/competitive-parity.md` (Known Gaps table, Deno/JSR row, 2026-08-23 scan notes) — competitive evidence and JSR API verification
- `docs/ECOSYSTEM_GUIDE.md` — architecture of ecosystem crate structure; shows how to add a new ecosystem
- `crates/deps-core/src/ecosystem.rs` — `Ecosystem` and `EcosystemId` trait definitions
- `crates/deps-core/src/ecosystem_registry.rs` — manifest file detection via `get_for_filename()` / `get_for_uri()`
- `crates/deps-npm/src/` — reference implementation for JSON-based ecosystem (parser, registry, types, error handling)
- `crates/deps-lsp/src/lib.rs` — ecosystem registration (`ecosystem!` and `register!` macros, `register_ecosystems()`)
- `crates/deps-lsp/Cargo.toml` (root) — feature flags for per-ecosystem enablement
- [JSR API documentation](https://jsr.io/docs/api) — meta.json endpoint and response schema
- [GitHub Dependabot Deno support documentation](https://docs.github.com/en/code-security/dependabot/ecosystems-supported-by-dependabot/supported-ecosystems-and-repositories)
- [Renovate Deno manager documentation](https://docs.renovatebot.com/modules/manager/)
- [[MOC-specs]] — all specifications

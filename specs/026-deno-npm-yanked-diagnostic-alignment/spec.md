---
aliases:
  - Deno npm: Yanked Diagnostic Alignment
  - Deno/npm Cross-Ecosystem Yanked Consistency
tags:
  - sdd
  - spec
  - bug
  - deps-deno
  - deps-npm
  - cross-ecosystem-consistency
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Align Deno `npm:` Yanked Diagnostic with npm's Suppressed Behavior

> [!info] Metadata
> **Status**: Shipped — PR #456 (issue #448)
> **Priority**: P2 (bug, cross-ecosystem consistency)
> **Type**: bug

## 1. Overview

### Problem Statement

Issue #436 changed `NpmFormatter::yanked_diagnostic_applies_to` to return `false`
unconditionally: npm's `deprecated` field is genuinely per-version but commonly applied
package-wide, so even an exact-pin `package.json` dependency no longer surfaced the
manifest-requirement "yanked" diagnostic — that signal is superseded by the dedicated
package-level deprecation diagnostic (issue #205).

`DenoFormatter::yanked_diagnostic_applies_to` was out of scope for #436/#439 and kept its
pre-existing behavior: restrict the diagnostic to exact-pin requirements, applied uniformly to
both `jsr:` and `npm:` specifiers, because the hook's signature took only a `&VersionReq` —
with no way to tell which scheme a dependency used, since the scheme lives in the package name
(`npm:lodash`, `jsr:@std/fs`), not in the version-requirement text.

The consequence: an exact-pin `npm:` dependency in `deno.json` (e.g. `npm:lodash@4.17.20`)
still surfaced the yanked-worded diagnostic, while the equivalent exact-pin `package.json`
dependency (`"lodash": "4.17.20"`) no longer did — the same underlying npm registry signal
(`deprecated`) produced inconsistent LSP behavior depending only on which manifest format
referenced it. This divergence was self-documented in `DenoFormatter`'s own doc comment
("Known cross-ecosystem divergence (#436 M1, not fixed here...)") as a known, deliberately
deferred gap; issue #448 formalized tracking it.

### Goal (as shipped)

`EcosystemFormatter::yanked_diagnostic_applies_to` gained a `dep: &dyn Dependency` parameter
alongside the existing `requirement: &VersionReq`, so an implementor can key its decision off
the dependency's package name. `DenoFormatter` uses this to branch on scheme: `npm:`
specifiers now return `false` unconditionally, mirroring `NpmFormatter`'s post-#436 behavior
exactly; `jsr:` specifiers keep the pre-existing exact-pin-only restriction, unchanged by this
PR.

### Out of Scope

- Relaxing the `jsr:` exact-pin-only restriction itself — tracked separately as issue #454,
  documented in [[029-deno-jsr-yanked-exact-pin-restriction-drop/spec|a follow-up spec]].
- Any change to `ComposerFormatter`, which does not override this hook at all (it opts out at
  the registry level, `Registry::reports_yanked() == false`, independently justified by #233
  R2).
- Any change to npm's or JSR's per-version yank/deprecation data sources themselves.

## 2. User Stories

### US-001: Consistent yanked signal across manifest formats for the same npm package

AS A developer with an `npm:` dependency in `deno.json`
I WANT the manifest-requirement "yanked" diagnostic to behave exactly as it does for the same
package referenced from a `package.json`
SO THAT the LSP's signal for the same underlying npm registry data does not depend on which
manifest format happens to declare the dependency

**Acceptance criteria:**
```
GIVEN an exact-pin npm: dependency in deno.json (e.g. npm:lodash@4.17.20) whose pinned
  version is npm-deprecated
WHEN diagnostics are generated for that document
THEN the manifest-requirement-level "yanked" diagnostic does NOT fire, exactly as it would
  not fire for the equivalent package.json dependency
```

### US-002: No regression for `jsr:` specifiers

AS A maintainer of the OSV/yanked diagnostic pipeline
I WANT jsr: specifiers to keep their existing exact-pin-only behavior unchanged
SO THAT fixing the npm: divergence does not silently change JSR's already-correct behavior

**Acceptance criteria:**
```
GIVEN an exact-pin jsr: dependency (e.g. jsr:@std/fs@1.0.0) whose pinned version is yanked
WHEN diagnostics are generated for that document
THEN the manifest-requirement-level "yanked" diagnostic still fires, identical to pre-#448
  behavior
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | `EcosystemFormatter::yanked_diagnostic_applies_to` SHALL accept `dep: &dyn Dependency` in addition to `requirement: &VersionReq`, so implementors can discriminate by package name/scheme | must |
| FR-002 | WHEN `DenoFormatter::yanked_diagnostic_applies_to` is called for a dependency whose name carries the `npm:` scheme THE SYSTEM SHALL return `false` unconditionally, regardless of requirement shape | must |
| FR-003 | WHEN `DenoFormatter::yanked_diagnostic_applies_to` is called for a dependency whose name carries the `jsr:` scheme (or is unscoped, treated as `jsr:`) THE SYSTEM SHALL retain the pre-existing exact-pin-only behavior, unchanged | must |
| FR-004 | `NpmFormatter::yanked_diagnostic_applies_to` SHALL continue returning `false` unconditionally under the new signature, with zero behavioral change from its post-#436 state | must |
| FR-005 | The sole call site (`generate_diagnostics_from_cache`) SHALL pass the same `dep` whose `version_requirement()` produced `requirement`, so the two parameters are never independently sourced | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Compatibility | The trait's default implementation (used by formatters that do not override the hook) SHALL remain `true` for any `dep`/`requirement` pair, preserving today's behavior for every ecosystem that does not need scheme-awareness |
| NFR-002 | Maintainability | The doc comment on `EcosystemFormatter::yanked_diagnostic_applies_to` SHALL document why each overriding formatter (`Deno`, `Npm`) answers the way it does, including the now-tracked `jsr:` follow-up (#454), so the rationale is not lost the way the original #436 M1 divergence was |

## 5. Data Model

No new persistent entities. This is a trait-signature change:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `EcosystemFormatter::yanked_diagnostic_applies_to` (changed) | Hook deciding whether the manifest-requirement yanked diagnostic may fire for a given dependency | New parameter `dep: &dyn Dependency` alongside existing `requirement: &VersionReq`; default `true` |
| `DenoFormatter::yanked_diagnostic_applies_to` (changed) | Deno's override | Branches on `split_scheme(dep.name().as_str())`: `Scheme::Npm` -> `false`; `Scheme::Jsr` (or `None`, unreachable in practice) -> exact-pin check |
| `NpmFormatter::yanked_diagnostic_applies_to` (changed signature only) | npm's override | Unconditional `false`, unchanged behavior under the new signature |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `npm:` dependency, any requirement shape (exact pin, range, wildcard) | Diagnostic never fires (FR-002) |
| `jsr:` exact-pin dependency, pinned version yanked | Diagnostic fires, unchanged (FR-003) |
| `jsr:` range-requirement dependency | Diagnostic does not fire, unchanged pre-existing behavior (out of scope here, see #454) |
| `split_scheme` returns `None` (unscoped name) | Unreachable in practice — every parser-produced `DenoDependency` name is scheme-qualified — folded into the `jsr:` exact-pin path as a harmless default |
| `package.json` dependency (not Deno) | Unaffected — `NpmFormatter`'s behavior and call sites are unchanged beyond the signature |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Unit tests for `DenoFormatter::yanked_diagnostic_applies_to` | `test_yanked_diagnostic_applies_to_npm_scheme_always_false` verifies `false` across `["1.2.3", "^1.2.3", "~1.2.3", "*"]` for `npm:lodash`; `test_yanked_diagnostic_applies_to_jsr_exact_pin_only` verifies the unchanged `jsr:` behavior — both pass |
| SC-002 | Unit test for `NpmFormatter::yanked_diagnostic_applies_to` | `test_yanked_diagnostic_applies_to_always_false` updated for the new signature, passes unchanged in behavior |
| SC-003 | End-to-end regression test through the real diagnostics pipeline | `test_handle_diagnostics_npm_scheme_exact_pin_yanked_stays_suppressed` (deno_tests, `crates/deps-lsp/src/handlers/diagnostics.rs`) confirms an exact-pin `npm:lodash@4.17.20` dependency with a deprecated pinned version produces zero diagnostics |
| SC-004 | End-to-end companion test proving the scheme split discriminates | `test_handle_diagnostics_jsr_scheme_exact_pin_yanked_still_fires` confirms an exact-pin `jsr:@std/fs@1.0.0` dependency with a yanked pinned version still produces exactly one diagnostic |
| SC-005 | Documentation | `docs/ECOSYSTEM_GUIDE.md`'s ecosystem coverage table and restriction prose updated: npm (and Deno's `npm:` specifiers) marked as unconditionally disabled rather than "exact pins only" |

## 8. Agent Boundaries

### Always (without asking)
- Keep `NpmFormatter`'s behavior byte-for-byte unchanged when touching the shared trait
  signature — only its parameter list changed, not its logic.
- Update `docs/ECOSYSTEM_GUIDE.md`'s yanked-diagnostic restriction prose and ecosystem
  coverage table whenever a formatter's `yanked_diagnostic_applies_to` behavior changes.

### Ask First
- Relaxing the `jsr:` exact-pin restriction (routed to issue #454 /
  [[029-deno-jsr-yanked-exact-pin-restriction-drop/spec|spec 029]] instead).

### Never
- Reintroduce a scheme-blind hook signature for `EcosystemFormatter::yanked_diagnostic_applies_to`
  — the whole point of this change was giving implementors access to the dependency, not just
  the requirement.

## 9. Open Questions

None. This spec documents already-shipped, merged work; the one adjacent open item (relaxing
the `jsr:` restriction) is tracked by issue #454 and
[[029-deno-jsr-yanked-exact-pin-restriction-drop/spec|spec 029]], not by this spec.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[029-deno-jsr-yanked-exact-pin-restriction-drop/spec|Drop jsr: exact-pin-only restriction on yanked diagnostic]] — the tracked follow-up this PR deliberately left open
- `crates/deps-deno/src/formatter.rs` — `DenoFormatter::yanked_diagnostic_applies_to`
- `crates/deps-npm/src/formatter.rs` — `NpmFormatter::yanked_diagnostic_applies_to`
- `crates/deps-core/src/lsp_helpers/mod.rs` — `EcosystemFormatter::yanked_diagnostic_applies_to` trait definition
- `crates/deps-core/src/lsp_helpers/diagnostics.rs` — `generate_diagnostics_from_cache`, the sole call site
- Issue #436 — established npm's unconditional-`false` behavior this PR aligns Deno's `npm:` scheme with
- Issue #448 — this spec's tracking issue
- PR #456, commit `d8b2b578` — the shipped fix

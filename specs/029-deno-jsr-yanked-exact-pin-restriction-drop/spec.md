---
aliases:
  - JSR Yanked Exact-Pin Restriction Drop
  - jsr: Yanked Range Signal Gap
tags:
  - sdd
  - spec
  - bug
  - deps-deno
  - jsr
  - cross-ecosystem-consistency
created: 2026-09-02
status: shipped
related:
  - "[[constitution]]"
  - "[[026-deno-npm-yanked-diagnostic-alignment/spec|Align deno npm: yanked diagnostic with npm's suppressed behavior]]"
---

# Feature: Drop the jsr: Exact-Pin-Only Restriction on the Deno Yanked Diagnostic

> [!info] Metadata
> **Author**: Andrei G. (k05h31@gmail.com)
> **Status**: Shipped — PR #459 (issue #454)
> **Priority**: P2 (bug — silent diagnostic gap)
> **Type**: bug

## 1. Overview

### Problem Statement

[[026-deno-npm-yanked-diagnostic-alignment/spec|PR #456]] (issue #448) gave
`DenoFormatter::yanked_diagnostic_applies_to` scheme awareness — it can now
tell `jsr:` and `npm:` specifiers apart, so `npm:` could be made to match
`NpmFormatter`'s unconditional `false`. That PR deliberately left `jsr:`'s
pre-existing exact-pin-only restriction untouched, since removing it was out
of #448's scope, and filed the follow-up as issue #454.

The exact-pin-only restriction predated scheme awareness entirely: before
#448, the hook took only a `&VersionReq`, with no way to distinguish `jsr:`
from `npm:`, so both schemes had to share one answer, and exact-pin-only was
that shared, historically-npm-motivated answer. Once `jsr:` could be treated
on its own terms, its restriction's original justification —
"avoid conflating with the `#205` package-level deprecation diagnostic" —
turned out not to hold for JSR at all:
`JsrVersion`'s `deps_core::impl_version!` invocation
(`crates/deps-deno/src/types.rs:93-95`) leaves `deprecation` unset, so
`Version::deprecation()` is structurally `None` for every JSR version and
the `#205` diagnostic never fires for `jsr:` dependencies in the first
place — there was nothing to conflate with.

The concrete, previously-silent consequence: a `jsr:@std/fs@^1.0.0`
dependency where every version matching the range was yanked produced
**zero** diagnostic signal, because three independent diagnostics all
missed it:

- The manifest-requirement-level yanked diagnostic (`#247`) was suppressed
  — `^1.0.0` is not an exact pin.
- The `#205` package-level deprecation diagnostic never fires for `jsr:`,
  per the structural `None` above.
- The `#263`-style "in-use version" diagnostic does not apply to Deno
  either — Deno has no lockfile support, and
  `bare_version_is_a_range` (`crates/deps-core/src/lsp_helpers/
  in_use_version.rs:30`) includes `EcosystemId::Deno` among the ecosystems
  it treats as range-only.

Cargo/PyPI/Dart — which have comparable per-version yank signal quality —
already report this case, since none of them override
`yanked_diagnostic_applies_to` and so keep the trait's unconditional-`true`
default. This was a cross-ecosystem inconsistency with no technical
justification, only a carried-over historical one.

### Goal (shipped)

`DenoFormatter::yanked_diagnostic_applies_to` now applies unconditionally
(`true`) for `jsr:` specifiers, for any requirement shape — matching the
`EcosystemFormatter` trait default that Cargo/PyPI/Dart already rely on. A
`jsr:` range requirement satisfiable only by yanked versions now surfaces
the `#247` diagnostic instead of producing zero signal. `npm:` specifiers
are unaffected by this change and keep the unconditional `false` `#448`
shipped.

### Out of Scope

- Any change to `npm:` specifier behavior — untouched, still unconditional
  `false` per `#448`.
- Adding a package-level deprecation-style diagnostic for JSR — out of
  scope; JSR genuinely has no such signal (structural `None`, see above).
- Deno lockfile support / the `#263`-style in-use-version diagnostic for
  Deno — a separate, larger gap, not addressed here.
- Changing `EcosystemFormatter::yanked_diagnostic_applies_to`'s trait
  default or signature beyond dropping the now-unused `requirement`
  parameter's role for the `jsr:` branch (the hook itself already gained
  `dep: &dyn Dependency` access in `#448`; this PR does not change the
  signature further, only the `jsr:` branch's return value).

## 2. User Stories

### US-001: JSR range requirement satisfiable only by yanked versions surfaces a diagnostic

AS A developer with a `jsr:` dependency in `deno.json` declared as a range
I WANT to be warned when every version matching that range has been yanked
SO THAT I don't silently keep depending on a package with no viable
resolvable version, the same protection Cargo/PyPI/Dart already give me

**Acceptance criteria (verified shipped):**
```
GIVEN a deno.json importing "@std/fs": "jsr:@std/fs@^1.0.0"
  AND every version satisfying ^1.0.0 (1.0.0, 1.0.1) is yanked on JSR
WHEN diagnostics are computed
THEN exactly one diagnostic fires: the #247 manifest-requirement-level
  yanked diagnostic, with a message naming the latest version
  (test_handle_diagnostics_jsr_scheme_range_yanked_only_now_fires,
  crates/deps-lsp/src/handlers/diagnostics.rs)
```

### US-002: No regression for npm: specifiers or jsr: exact pins

AS A maintainer of the Deno ecosystem crate
I WANT `npm:` specifier behavior (`#448`) and the pre-existing `jsr:`
exact-pin case to keep working exactly as before
SO THAT closing the range-requirement gap does not reintroduce the
`npm:`/`package.json` divergence `#448` fixed, or regress the already-working
exact-pin path

**Acceptance criteria (verified shipped):**
```
GIVEN an npm: specifier in deno.json, any requirement shape
WHEN yanked_diagnostic_applies_to is evaluated
THEN it returns false unconditionally, unchanged from #448
  (test_yanked_diagnostic_applies_to_npm_scheme_* — untouched by this PR)

GIVEN a jsr: specifier with an exact-pin requirement satisfiable only by a
  yanked version
WHEN diagnostics are computed
THEN the #247 diagnostic still fires, exactly as it did before this PR
  (test_handle_diagnostics_jsr_scheme_exact_pin_yanked_still_fires)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `DenoFormatter::yanked_diagnostic_applies_to` is evaluated for a `jsr:`-scheme dependency THE SYSTEM SHALL return `true` unconditionally, regardless of requirement shape (exact pin, caret/tilde range, or wildcard) | must |
| FR-002 | WHEN `DenoFormatter::yanked_diagnostic_applies_to` is evaluated for an `npm:`-scheme dependency THE SYSTEM SHALL continue to return `false` unconditionally, unchanged from `#448` | must |
| FR-003 | THE SYSTEM SHALL NOT introduce any additional network fetch to support this change — JSR's `meta.json` (`JsrRegistry::get_versions`) already returns every version's `yanked` flag in one fetch, identical whether the manifest requirement is a range or an exact pin | must |
| FR-004 | THE SYSTEM SHALL update the doc comments on `EcosystemFormatter::yanked_diagnostic_applies_to` (trait-level) and `DenoFormatter::yanked_diagnostic_applies_to` (impl-level) to state the corrected rationale (JSR's `yanked` has no package-level counterpart to conflate with) rather than the superseded "restriction carried over from before scheme-awareness" rationale | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Zero additional OSV/registry round-trips — resolved per FR-003; the issue's pre-implementation open question ("does the underlying deps-deno registry client have per-version yank data cheaply available outside the exact-pin fetch path?") is answered yes, the data was already fetched unconditionally |
| NFR-002 | Reliability | No regression to `npm:` specifier handling or `jsr:` exact-pin handling — verified by the existing test suite plus the new range-requirement test, all passing |
| NFR-003 | Consistency | Deno's `jsr:` yanked-diagnostic coverage now matches Cargo/PyPI/Dart's (unconditional trait default), closing the cross-ecosystem divergence noted in `docs/ECOSYSTEM_GUIDE.md`'s yanked-diagnostic coverage table |

## 5. Data Model

No new entities. This change narrows one existing trait method's behavior
for one existing scheme branch.

| Entity | Description | Change |
|--------|-------------|--------|
| `EcosystemFormatter::yanked_diagnostic_applies_to` (existing) | Per-dependency gate deciding whether the `#247` manifest-requirement yanked diagnostic may fire | Doc comment corrected (FR-004); signature unchanged from `#448` (`dep: &dyn Dependency`, `requirement: &VersionReq`) |
| `DenoFormatter::yanked_diagnostic_applies_to` (existing impl) | Scheme-branching implementation | `jsr:` branch changed from `node_semver::Version::parse(requirement.as_str().trim()).is_ok()` (exact-pin check) to unconditional `true`; the `requirement` parameter is now unused for this impl and renamed `_requirement` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior (shipped) |
|----------|-------------------|
| `jsr:` exact pin, pinned version yanked | Diagnostic fires — unchanged from before this PR |
| `jsr:` range (`^`, `~`, wildcard `*`), every matching version yanked | Diagnostic now fires (the fixed bug) |
| `jsr:` range, at least one matching version not yanked | Diagnostic does not fire — `yanked_diagnostic_applies_to` returning `true` only gates *eligibility*; the actual yanked-only-match computation (unchanged by this PR) still requires every satisfying version to be yanked |
| `npm:` specifier, any requirement shape | Diagnostic never fires — untouched, `#448` behavior preserved |
| `jsr:` dependency with a package-level deprecation payload | Not applicable — JSR versions structurally never carry one (`impl_version!`'s `deprecation` left unset), so there is no diagnostic to conflate with, confirming the original restriction's justification never held |

## 7. Success Criteria

| ID | Metric | Target (verified shipped) |
|----|--------|--------|
| SC-001 | `jsr:` range requirement satisfiable only by yanked versions surfaces the `#247` diagnostic | Pass — `test_handle_diagnostics_jsr_scheme_range_yanked_only_now_fires` |
| SC-002 | `jsr:` exact-pin and `npm:` behavior unchanged | Pass — `test_handle_diagnostics_jsr_scheme_exact_pin_yanked_still_fires` and existing `npm:`-scheme tests pass unmodified |
| SC-003 | Unit-level coverage of the relaxed `jsr:` branch across requirement shapes | Pass — `test_yanked_diagnostic_applies_to_jsr_scheme_always_true` asserts `true` for `"1.2.3"`, `"^1.2.3"`, `"~1.2.3"`, `"*"` |
| SC-004 | No additional OSV/registry round-trip introduced | Confirmed by code inspection — `JsrRegistry::get_versions` fetch shape is unchanged; only the formatter-level gate changed |

## 8. Agent Boundaries

### Always (without asking)
- Keep `npm:` and `jsr:` branches independently testable — do not
  reintroduce a shared code path that could silently recouple their
  behavior (the original bug's root cause).
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest,
  rustdoc gate) per project convention before any follow-up PR touching
  this area.

### Ask First
- Adding a Deno-specific package-level deprecation-style diagnostic for
  JSR — JSR has no such upstream signal today; inventing one would be a
  new feature, not a bug fix, and needs its own spec.

### Never
- Reintroduce the exact-pin-only restriction for `jsr:` without a new,
  concrete technical justification — the original one is documented here
  as unfounded.
- Conflate this fix with `#448`'s `npm:` scope or with Deno lockfile
  support (`#263`-style in-use-version diagnostic) — both are explicitly
  out of scope (see Overview).

## 9. Open Questions

None. The issue's one pre-implementation question — whether verifying
yanked status for a range costs an extra fetch — is resolved by FR-003/
NFR-001: JSR's `meta.json` already returns every version's `yanked` flag
in the single fetch the ecosystem performs regardless of requirement
shape, so no design trade-off remained to defer.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[026-deno-npm-yanked-diagnostic-alignment/spec|Align deno npm: yanked diagnostic with npm's suppressed behavior]] — the direct predecessor (`#448`/PR #456) that made this hook scheme-aware and deferred this `jsr:` follow-up
- `crates/deps-deno/src/formatter.rs` — `DenoFormatter::yanked_diagnostic_applies_to`, the `jsr:` branch this PR relaxed
- `crates/deps-deno/src/types.rs` — `JsrVersion`, `RemovalStatus::from_yanked`
- `crates/deps-core/src/lsp_helpers/mod.rs` — `EcosystemFormatter::yanked_diagnostic_applies_to` trait doc
- `crates/deps-core/src/lsp_helpers/in_use_version.rs` — `bare_version_is_a_range`, why the `#263`-style diagnostic does not cover Deno
- `docs/ECOSYSTEM_GUIDE.md` — yanked-diagnostic ecosystem coverage table, updated by this PR
- Issue #454, PR #459 (commit `209c7587`)

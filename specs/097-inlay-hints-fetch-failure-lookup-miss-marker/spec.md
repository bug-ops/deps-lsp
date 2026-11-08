---
aliases:
  - Inlay Hint Failure Marker
  - Inlay Hints Outcomes Wiring
tags:
  - sdd
  - spec
  - lsp
  - inlay-hints
  - cross-ecosystem
  - bug
created: 2026-11-08
status: ready
related:
  - "[[constitution]]"
  - "[[MOC-specs]]"
---

# Feature: Inlay hints render the warning marker for a failed registry lookup or a registry miss

> [!info] Metadata
> **Author**: continuous-improvement cycle (live-testing finding, ci-107)
> **Priority**: P2, bug, cross-ecosystem
> **Branch**: (none yet, spec stage)
> **Related issues**: #1884, #1891 (original false "up to date" reports), PRs #1896, #1898 (partial fix), 4.0.0 CHANGELOG "Fixed" entry

## 1. Overview

### Problem Statement

PRs #1896 and #1898 (CHANGELOG 4.0.0, issues #1884 and #1891) promised that "a failed registry
fetch, 404 or missing comparable version for a lockfile dependency gives a diagnostic or notice
and a warning inlay instead of 'up to date'". The diagnostic half works. The inlay half does not
work in the running LSP server.

`generate_inlay_hints` (`crates/deps-core/src/lsp_helpers/inlay_hints.rs`, branch
`let Some(latest) = latest_version else { ... }`) emits a `⚠ <resolved>` hint when
`VersionData::fetch_failure_for(&key)` is an attempted failure, or when
`VersionData::reportable_lookup_miss(dep, &key, formatter)` is `Some`. Both accessors read
`VersionData::outcomes`, which is populated only by `with_outcomes`.

The LSP handler (`crates/deps-lsp/src/handlers/inlay_hints.rs`) builds its snapshot with
`snapshot().with_resolved_version_candidates().with_latest_status(osv_checks).finish()` and never
requests the outcomes dimension. `SignalsSnapshot::version_data()`
(`crates/deps-lsp/src/document/state/signals.rs`) attaches `outcomes` only when the snapshot was
built with them ("every dimension it doesn't request simply isn't cloned"). The accessors
therefore always return `None` on the LSP inlay path, and the generic fallback
(`config.show_up_to_date_hints` then `up_to_date_text + resolved`) renders a checkmark.

The hover, diagnostics and code-action handlers do attach outcomes. Only inlay hints (and, to be
audited, code lens) omit them. The unit tests in `inlay_hints.rs` pass because they attach
outcomes by hand, so no test exercises the handler path.

The effect is the exact false "up to date" signal that #1884 and #1891 were filed to remove, on
the always-visible editor surface, while diagnostics (and `deps-cli check`) report the problem.
The surfaces disagree.

### Live Reproduction (debug build of main `713d6368e`, real registries)

Fixtures: `.local/testing/fixtures/ci107/lockmiss/{cargo,npm2,pypi,composer,dart,go,bundler,nuget,pnpm}`.
Each holds a manifest, a lock file pinning `zzz-nonexistent-ci107...` at `1.0.0`, and one real
package. Harness: `python3 -I .local/testing/lsp_probe_ci107_dir.py <deps-lsp binary> <log> <manifest>`
(prints diagnostics and inlay hints).

| Scenario | Diagnostic (correct) | Inlay hint observed | Inlay hint expected |
|----------|----------------------|---------------------|---------------------|
| 404, `cargo/Cargo.toml` | `'zzz-nonexistent-ci107-crate' not found in the registry; lock-file version in use` (Information) | `✅ 1.0.0` | `⚠ 1.0.0`, tooltip "Package not found in the registry; latest version unknown" |
| 404, npm2, pypi, composer, dart, go, bundler, nuget, pnpm | per-ecosystem equivalent | `✅ 1.0.0` for the missing package | `⚠ 1.0.0` |
| Transport failure (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` set to `http://127.0.0.1:9`), `cargo/Cargo.toml` | `Registry lookup failed for 2 packages; package status could not be determined` (Warning) | `✅ 1.0.100` (serde), `✅ 1.0.0` (missing crate) | `⚠ <resolved>`, tooltip "Registry lookup failed; latest version unknown" |
| Transport failure, npm2 `package.json`, pypi `pyproject.toml` | Warning published | `✅ 1.1.0`, `✅ 1.0.0` | `⚠ <resolved>` |

### Related, Distinct Gap: `NotLookedUp`

`reportable_lookup_miss` returns `None` for `LookupMiss::NotLookedUp`. A dependency that is
bypassed locally (for example Go modules under `GOPROXY=direct|off` or `GOPRIVATE`, where no
registry request is made) also renders `✅ vX`. The generator already carries a tooltip string
"Package not looked up; latest version unknown" for this case, but the branch is unreachable
because the gate filters the variant out. The Go bypass is filed as a separate issue; this spec
records the required inlay behavior for the variant (see FR-008 and Q1).

### Goal

For every dependency whose registry lookup was attempted and failed, or produced a reportable
lookup miss, the LSP inlay hint is the warning marker (`⚠ <resolved>`) with the matching tooltip,
in every ecosystem, so hints and diagnostics agree.

### Out of Scope

- Changing the marker glyph, label format, or tooltip wording already defined in
  `generate_inlay_hints` (`⚠ {resolved}` and the four existing tooltip strings).
- Changing diagnostic text, severity, or the set of conditions under which diagnostics fire.
- Changing which registry sources are reportable (`AlternateRegistry` stays suppressed; sources
  the formatter cannot resolve stay suppressed). This spec only makes the existing gate reachable.
- The Go `GOPROXY`/`GOPRIVATE` bypass diagnostic itself (separate issue); only its inlay rendering
  is in scope here, and only as Q1.
- New configuration options for the warning marker (it remains fixed text, independent of
  `show_up_to_date_hints`, as documented on `generate_inlay_hints`).

## 2. User Stories

### US-001: Warning instead of checkmark when the registry could not be reached

AS A developer with a lock file and a registry that is unreachable or erroring
I WANT the inlay hint beside each affected dependency to show a warning marker with the resolved version
SO THAT I am not told a dependency is up to date when the server could not check

**Acceptance criteria:**
```
GIVEN a manifest with a lock file pinning serde at 1.0.100
  AND every registry request fails with a transport error
WHEN the editor requests inlay hints for the manifest
THEN the hint for serde is "⚠ 1.0.100"
  AND its tooltip is "Registry lookup failed; latest version unknown"
  AND no hint for that dependency contains the configured up-to-date text
```

### US-002: Warning for a package the registry does not know

AS A developer whose lock file pins a package the registry answers 404 for
I WANT the inlay hint to show the warning marker
SO THAT I notice a yanked, renamed, private or mistyped package at a glance

**Acceptance criteria:**
```
GIVEN a lock file pinning "zzz-nonexistent-ci107-crate" at 1.0.0
  AND the registry answers 404 for it
WHEN inlay hints are requested
THEN the hint on that line is "⚠ 1.0.0"
  AND its tooltip is "Package not found in the registry; latest version unknown"
```

### US-003: Hints and diagnostics tell the same story

AS A developer reading both squiggles and inlay hints
I WANT the two surfaces to agree about which dependencies could not be checked
SO THAT I can trust either one

**Acceptance criteria:**
```
GIVEN any of the eight supported lock-file ecosystems under the 404 scenario or the transport-failure scenario
WHEN diagnostics and inlay hints are collected for the same manifest
THEN every dependency with a fetch-failure or lookup-miss diagnostic has a "⚠" hint
  AND no dependency has a "⚠" lookup-failure hint without that diagnostic
```

### US-004: A future wiring omission is caught by the test suite

AS A maintainer
I WANT a regression test that drives the real handler
SO THAT dropping the outcomes dimension from a handler's snapshot again fails CI instead of shipping

**Acceptance criteria:**
```
GIVEN a document state whose signals record an attempted fetch failure and a NotFound miss
WHEN handle_inlay_hints is invoked (not only generate_inlay_hints with hand-attached outcomes)
THEN the returned hints contain the warning marker for both dependencies
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-001 | WHEN an inlay-hint request is served for a document whose recorded outcomes include an attempted fetch failure for a dependency that has a lock-file-resolved version, THE SYSTEM SHALL return `⚠ <resolved>` with tooltip "Registry lookup failed; latest version unknown" for that dependency, regardless of `show_up_to_date_hints`. | must |
| FR-002 | WHEN an inlay-hint request is served for a dependency with a reportable `LookupMiss::NotFound` or `LookupMiss::NoComparableVersions` and a resolved version, THE SYSTEM SHALL return `⚠ <resolved>` with tooltip "Package not found in the registry; latest version unknown" or "No comparable registry version; latest version unknown" respectively. (Verification: the 404 case live for cargo, npm2 and pypi; `NoComparableVersions` and the `NotLookedUp` `ℹ` marker by generator unit tests and the `handle_inlay_hints` handler test only, not live.) | must |
| FR-003 | THE SYSTEM SHALL supply the same per-dependency outcome data to the inlay-hint renderer in the LSP handler as it supplies to the diagnostics renderer for the same document state, so that the two surfaces cannot disagree about failure or miss status. | must |
| FR-004 | WHEN a fetch-failure record has not been attempted (a `NotAttempted` placeholder), THE SYSTEM SHALL NOT render the failure marker for that dependency. | must |
| FR-005 | WHILE the session is offline, THE SYSTEM SHALL render the offline marker (`📴`, with the resolved version when one exists) and SHALL NOT render the failure or miss marker, even if outcomes recorded before going offline exist. | must |
| FR-006 | WHEN a dependency's source is one for which `reportable_lookup_miss` suppresses reporting (an alternate registry, or a source the formatter cannot resolve), THE SYSTEM SHALL NOT render a lookup-miss marker for it, matching diagnostics. | must |
| FR-007 | WHEN the dependency has no lock-file-resolved version, THE SYSTEM SHALL keep existing behavior (no failure or miss marker, since there is no resolved version to display). | must |
| FR-008 | WHEN the recorded miss is `LookupMiss::NotLookedUp` (decided locally, no registry request made), THE SYSTEM SHALL NOT render the up-to-date checkmark for that dependency; the replacement rendering is the neutral marker `ℹ <resolved>` with tooltip "Package not looked up; latest version unknown" (Q1 resolution), rendered regardless of `show_up_to_date_hints`. | must |
| FR-009 | THE SYSTEM SHALL apply FR-001 through FR-008 identically for all supported ecosystems, through the shared `deps-core` generator and the shared handler path, with no per-ecosystem inlay logic. | must |
| FR-010 | THE SYSTEM SHALL include a regression test that invokes `handle_inlay_hints` against a `ServerState` whose document signals hold a recorded fetch failure and a recorded `NotFound` miss, and asserts the warning hints, so that omitting the outcomes dimension from the handler snapshot fails the test. | must |
| FR-011 | THE SYSTEM SHALL include a per-ecosystem or table-driven check that, for each of the eight ecosystems under both the 404 and the transport-failure scenarios, the set of dependencies with failure or miss diagnostics equals the set with a warning hint. | should |
| FR-012 | WHEN a registry fetch completes with a failure or miss after hints were already rendered as loading or up to date, THE SYSTEM SHALL cause the editor to re-request inlay hints so the marker appears without a manual edit. | should (Q3: NOT verified live; no refresh trigger was added or tested in this PR, remains open, tracked in #1955) |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Attaching outcomes to the inlay snapshot SHALL NOT add a registry request or any blocking work to the handler; it clones already-held in-memory state, consistent with hover and diagnostics. Hint latency from cached state SHALL stay within the existing handler budget. |
| NFR-002 | Type safety | The fix SHOULD make the omission unrepresentable or a compile-time error where practicable (for example a renderer declaring the snapshot dimensions it requires) rather than relying only on a runtime test. (mechanism: test-only enforcement, Q2) |
| NFR-003 | Security | Hint labels and tooltips SHALL continue to pass the resolved version through `sanitize_hint_version`; no registry-supplied text (error bodies, URLs) enters the label or tooltip. Tooltips remain the fixed strings listed in FR-001/FR-002. |
| NFR-004 | Consistency | Behavior SHALL be implemented once in `deps-core` and the `deps-lsp` handler; a per-ecosystem divergence is a defect (project cross-ecosystem consistency rule). |

## 5. Data Model

No new data. Existing entities involved:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `DependencyOutcomes` / `PackageSignals::outcomes` | Per-package recorded results of registry lookups | yanked, deprecation, `fetch_failure`, `lookup_miss` |
| `FetchFailure` | Typed registry failure; `was_attempted()` distinguishes real attempts from placeholders | Transient, Actionable, NotAttempted |
| `LookupMiss` | Typed reason no latest version could be determined | `NotFound`, `NoComparableVersions`, `NotLookedUp` |
| `SignalsSnapshot` / `SignalsSnapshotBuilder` | Per-request clone of only the signal dimensions a handler asked for | `outcomes: Option<DependencyOutcomes>` |
| `VersionData` | Borrowed read view handed to every renderer | `fetch_failure_for`, `lookup_miss_for`, `reportable_lookup_miss`, `network` |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Registry fetch still in flight, no outcome recorded yet | Loading hint (if enabled) or no failure marker; never a failure marker without a recorded outcome. |
| Dependency has a cached latest version AND a stale recorded failure | Normal status rendering from the cached latest; failure marker applies only on the no-cached-latest branch (current generator contract, unchanged). |
| Offline session with outcomes recorded earlier | Offline marker wins (FR-005). Note: the handler passes the offline flag through `EcosystemConfig`, while `reportable_lookup_miss` also reads `VersionData::network`; the plan must ensure both signals agree on the inlay path. |
| Duplicate dependency names in one manifest (for example dev and normal sections) | Each occurrence is keyed by `PackageKey`; both receive the marker. |
| Dependency from an alternate registry that 404s | No miss marker (FR-006), matching diagnostics. |
| Dependency without lock-file resolution and a failed lookup | No marker from this feature (FR-007); no resolved version to show. |
| `show_up_to_date_hints = false` | Failure and miss markers still render (fixed status markers). |
| Diagnostics disabled by user configuration | Hints still render the marker. (Q4: yes, the marker still renders) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Ecosystems (cargo, npm incl. `npm2` and `pnpm` lock variants, pypi, composer, dart, go, bundler, nuget) where the 404 fixture's missing package renders `⚠ 1.0.0` instead of `✅ 1.0.0` | 8 of 8 (9 of 9 fixtures) |
| SC-002 | Same ecosystems under the transport-failure scenario: every dependency with the "Registry lookup failed" diagnostic renders `⚠ <resolved>` | 8 of 8 |
| SC-003 | Dependencies with a failure/miss diagnostic but a checkmark hint, across the ci107 `lockmiss` fixtures under both scenarios | 0 |
| SC-004 | Regression test driving `handle_inlay_hints` fails when `.with_outcomes()` is removed from the handler snapshot (verified by mutation) | fails as required |
| SC-005 | Live re-run of the ci107 reproduction (harness `lsp_probe_ci107_dir.py`) after the fix | matches the "expected" column of the table in section 1 |

## 8. Agent Boundaries

### Always (without asking)
- Reuse the shared `deps-core` generator and the existing `LookupMiss`/`FetchFailure` gates; add no ecosystem-local logic.
- Verify against the live LSP harness with the ci107 fixtures, not by unit tests alone (project live-testing rule).
- Run the full pre-PR check suite from `.claude/rules/branching.md` and update `CHANGELOG.md` (one line plus PR link) under `[Unreleased]`.

### Ask First
- Choosing the compile-time mechanism for NFR-002 if it changes public `deps-core` signatures (breaking-change policy applies).
- Any new marker glyph or tooltip text for `NotLookedUp` (Q1).
- Changing `SignalsSnapshot`'s builder shape in a way that affects hover, diagnostics, or code actions.

### Never
- Edit `crates/deps-zed` (separate submodule repository).
- Weaken the offline, alternate-registry, or unresolvable-source suppression gates to make a hint appear.
- Put registry-supplied text into hint labels or tooltips.
- Use `.local/specs/`; spec artifacts live in tracked `specs/`.

## 9. Resolved Questions

> [!success] Resolutions (architect plan 2026-11-08, spec phase closed)
> - [x] **Q1** `LookupMiss::NotLookedUp` renders the neutral fixed marker `ℹ <resolved>` with the existing tooltip "Package not looked up; latest version unknown". It is not `⚠` because nothing failed and diagnostics stay silent (#1901). Like `📴` and `⚠` it ignores `show_up_to_date_hints`. It is not routed through `reportable_lookup_miss`, whose `AlternateRegistry` suppression is exactly the Go bypass source. Offline still wins.
> - [x] **Q2** Test-only enforcement: FR-010 regression test plus a mutation check (removing `.with_outcomes()` must fail it).
> - [ ] **Q3** Open: whether recording an outcome triggers `workspace/inlayHint/refresh` was not verified live; deferred to #1955.
> - [x] **Q4** Yes: the marker is a status, not a diagnostic, and renders with diagnostics disabled.
> - [x] **Q5** Resolved: `code_lenses.rs` reads no outcomes (grep verified); no change there.
>
> `NoComparableVersions` is untouched by the related hover issue #1936: only `NotFound` suppresses the `Cmd+.` footer and the all-clear OSV line.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `crates/deps-core/src/lsp_helpers/inlay_hints.rs` — generator with the (currently unreachable in the LSP path) marker branches
- `crates/deps-lsp/src/handlers/inlay_hints.rs` — handler snapshot that omits `.with_outcomes()`
- `crates/deps-lsp/src/document/state/signals.rs` — `SignalsSnapshotBuilder` / `SignalsSnapshot::version_data`
- `crates/deps-core/src/lsp_helpers/version_data.rs` — `fetch_failure_for`, `lookup_miss_for`, `reportable_lookup_miss`
- Issues #1884, #1891; PRs #1896, #1898, #1904

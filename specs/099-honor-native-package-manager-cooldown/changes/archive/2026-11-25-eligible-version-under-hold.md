---
aliases:
  - Eligible version under a held latest
tags:
  - sdd
  - delta
  - cross-ecosystem
  - deps-core
  - deps-cli
  - deps-lsp
created: 2026-11-25
status: archived
related:
  - "[[099-honor-native-package-manager-cooldown/spec|099 Honor native package-manager cooldown]]"
  - "[[075-cli-update-cooldown-fallback/spec|075 CLI update cooldown fallback]]"
  - "[[076-cli-update-cooldown-fallback-no-lockfile/spec|076 CLI update cooldown fallback, no lockfile]]"
  - "[[004-release-freshness-signal/spec|004 Release freshness signal]]"
  - "[[020-freshness-cooldown-diagnostics-blind/spec|020 Freshness cooldown diagnostics]]"
---

# Delta: eligible version under a held latest

> [!info] Scope
> Issues #2190 and #2191. Merged into [[099-honor-native-package-manager-cooldown/spec|spec 099]] at spec sync (2026-11-25); PR pending.

Terminology: `latest` is **held** when a native release-age window (**native hold**) or the freshness cooldown, local or GOSSIP (**freshness hold**), excludes it; the native hold takes precedence in the explanation. The **newest eligible version** is the first version, in the registry's newest-first order, that is older than `latest`, newer than the in-use floor, has a known publish time and is cleared by both the freshness cooldown (when enabled) and the native window.

## ADDED

### FR-018 (update lens and code actions never write a held version, #2191)

WHEN a version is held THE SYSTEM SHALL NOT write it through the "Update N outdated" lens or its command, and SHALL NOT offer a refactor action "Update to <that version>". The lens count SHALL exclude held dependencies. A held dependency SHALL be a typed planner outcome that keeps current and target and is never written; an OSV `Flagged` or `Unverified` outcome takes precedence over it. For refactor actions, a version with an unknown publish time counts as eligible. With no window in effect, output is identical to the previous behavior.

### FR-019 (security fix under a hold)

WHEN a vulnerability fix target is held THE SYSTEM SHALL keep the target unchanged and name the hold in the action title: `inside <source>` for a native hold (wins when both apply), else `published <age> ago, inside the release cooldown` whenever the target's publish time is known (GOSSIP holds included). Only for a GOSSIP hold without a known publish time is the suffix exactly `; inside the release cooldown (deps.dev/GOSSIP)`.

### FR-020 (unsatisfiable fix under a hold)

WHEN `latest` is held THE SYSTEM SHALL NOT offer the unsatisfiable-requirement fix that would write it.

### FR-021 (outdated diagnostic judged against the newest eligible version, #2190)

WHEN `latest` is held and its OSV verdict is `Verified` or `NotApplicable` THE SYSTEM SHALL decide the outdated diagnostic as below, identically in `deps-cli check` and the LSP for the same data. `e` is the newest eligible version.

| Case | Result |
|------|--------|
| `e` exists, is newer than the in-use version (lock file or concrete pin), is not admitted by the requirement, and is not OSV `Flagged` | Diagnostic names `e` and says why `latest` is held; suffix `(not yet verified against OSV)` when `e` is `Unverified` |
| `e` is not newer than the in-use version, or is admitted by the requirement, or no eligible version exists | No outdated diagnostic (no `check` finding) |
| Eligibility cannot be determined, the in-use version is unknown, or `e` is `Flagged` | The previous message for the held `latest` |

A `Flagged` or `Unverified` `latest` is unchanged. Vulnerability diagnostics are unaffected (FR-011).

Eligibility cannot be determined when: a range requirement has no lock-file version; an undated entry precedes the answer; the candidate list was cut (128 entries) or ended on an ecosystem-unsafe pick; the in-use floor cannot be located; or `latest` is not in the version list (for example a Go pseudo-version).

> [!note] Ordering limit
> "Newest" is the registry's newest-first list order, not a separate version comparison.

### FR-024 (inlay hints follow the outdated-diagnostic verdict)

WHEN `latest` is held THE SYSTEM SHALL derive the inlay hint from the FR-021 decision (user-approved):

| FR-021 outcome | Inlay hint |
|----------------|------------|
| Diagnostic names `e` | Needs-update hint with `e`; tooltip `<latest> is held: <window>`, plus `not yet verified against OSV` when `e` is `Unverified` |
| No outdated diagnostic | Up to date |
| Previous message (undetermined, unknown in-use version, `e` flagged) | As before |

A `Flagged` or `Unverified` `latest` is unchanged. Hover stays advisory.

### FR-022 (OSV verification of the named version)

WHEN a diagnostic or an update would name or write `e` THE SYSTEM SHALL verify `e` against OSV on both surfaces, in a verdict map separate from the one for `latest`. In the LSP the round shares the phase-B deadline and is committed under the same content and generation guard as the `latest` verdicts; a cut round, or an `e` re-picked after the last scan, shows the unverified suffix until the next scan.

### FR-023 (`deps-cli update` under a hold)

WHEN `latest` is held and a newest eligible version exists THE SYSTEM SHALL let `deps-cli update` propose it through the existing fallback pipeline ([[075-cli-update-cooldown-fallback/spec|075]] and [[076-cli-update-cooldown-fallback-no-lockfile/spec|076]] guards unchanged), under a native hold as well as a freshness hold, and under a native hold whether or not the freshness cooldown is enabled (user-approved). Held items that are not written SHALL report current and target in table, JSON and PR body, for native holds as well as freshness holds.

### Lens exception

> [!warning] Exception to FR-002 and FR-016 (user-approved)
> The LSP bulk lens skips a held dependency, while `deps-cli update` may write its newest eligible version, so the two edit sets can differ for held dependencies only. Code actions still offer eligible versions among their listed targets. Closing the gap is follow-up #2192 (P3).

## MODIFIED

### FR-002

- **Old:** held versions are ineligible in hover, update code actions, the lens and `deps-cli update`, and the newest eligible version is proposed. "Phase 1 narrows this to explain-only: the held version is named and never proposed, and no older version is proposed in its place."
- **New:** the explain-only narrowing is lifted. Held versions are never written, except a security-fix target (FR-019); `check`, LSP diagnostics and inlay hints are judged against the newest eligible version (FR-021, FR-024) and `deps-cli update` proposes it (FR-023). Hover stays advisory. The lens follows the exception above.

### FR-016

- **Old:** `deps-cli update` and the LSP produce identical edits for the same manifest.
- **New:** same, except that the LSP bulk lens skips held dependencies (exception above).

### NFR-004

- **Old:** "The feature SHALL add no deps.dev or OSV request."
- **New:** no deps.dev request; one additional OSV round, only when an eligible version would be named or written (FR-022). GOSSIP is not consulted when candidates are collected at fetch time. Publish-time fetch rules are unchanged.

### NFR-008 and SC-003

- **Old:** with no native config, output is byte-identical to current behavior; existing snapshots do not change.
- **New:** same for the native feature itself, but freshness holds now change outdated diagnostics (FR-021), inlay hints (FR-024), lens edits and counts and refactor and fix actions (FR-018 to FR-020), including with no native config. Snapshots covering those cases may change.

### Phase 1 resolution

- **Item 3, old:** `freshness.cooldown_secs` keeps its advisory role unchanged. **New:** it also decides the outdated diagnostic and what the lens and code actions may write; hover stays advisory.
- **"Narrowed FR-002 / US-001" (explain-only):** superseded by this delta. A version in `Cargo.lock` stays eligible, as before.
- **US-001 acceptance, "the newest eligible version is the one proposed":** implemented by FR-021 and FR-023.

### Spec 075 behavior relied on here

- The fallback is no longer a single candidate chosen at fetch time: fetch stores a bounded newest-first candidate list and the pick is made at read time.
- 075 FR-001 (no retry past an ecosystem-unsafe pick) is kept: such a pick ends the list.
- 075 NFR-001 step 0 is amended: a native window collects candidates even with freshness disabled.
- 075 NFR-004 is amended: `deps-cli check` runs the fallback OSV round too.
- 075 statements that other `deps-lsp` surfaces are unchanged no longer hold for diagnostics, inlay hints, the lens and code actions.

## REMOVED

- The Phase 1 "within native cooldown" unplannable outcome, replaced by the held planner outcome (FR-018).

## Deviations

- Inlay hints (FR-024) are a surface beyond the approved plan (user-approved). The up-to-date hint depends on up-to-date hints being enabled. A held-but-admitted `e` newer than the lock reads up to date, unlike an unheld `latest` in the same position.
- The "Update N outdated" command now plans from the same inputs as the lens, so it never writes an OSV-flagged or unverified `latest` (pre-existing defect, scope addition, user-approved). Run before the OSV round finishes, it reports nothing to update.
- Security-fix title wording follows the architect ruling in FR-019.
- `deps-cli update` names the native window in the fallback reason; it can exit 1 under a long native window when the fallback is flagged or unverified.
- Refactor actions fall back to publish times stored at fetch time, so registries that add publish times only with freshness settings also skip held versions.
- Candidate collection is also bounded by selection turns (2 x 128); hitting the bound makes eligibility undetermined.
- With OSV checking on and no fallback round, `e` counts as unverified.
- NuGet re-parses versions on each candidate pick; follow-up #2199 (P4).

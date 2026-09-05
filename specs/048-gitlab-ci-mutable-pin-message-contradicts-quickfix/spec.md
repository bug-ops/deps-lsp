---
aliases:
  - GitLab CI Mutable-Pin Message Contradicts Quickfix
tags:
  - sdd
  - spec
  - bug
  - deps-gitlab-ci
created: 2026-09-05
status: approved
related:
  - "[[constitution]]"
  - "[[030-gitlab-ci-ecosystem/spec]]"
  - "[[031-github-actions-sha-pin-diagnostic/spec]]"
---

# Feature: Fix "no automated fix available" claim on GitLab CI component Latest/Partial mutable-ref-pin diagnostic

> [!info] Metadata
> **Author**: k05h31@gmail.com
> **Branch**: feat/640-643-gitlab-ci-pin-parity (issue #643, implemented alongside #640)
> **Source**: continuous-improvement cycle-045, live-tested against real `gitlab.com` API data

## 1. Overview

### Problem Statement

PR #637 (`feat(deps-gitlab-ci): mutable-ref-pin diagnostic and quickfix`, merged to `main` as
commit `ce5c4c15`) ported [[031-github-actions-sha-pin-diagnostic/spec|GitHub Actions' mutable-ref-pin
diagnostic + SHA-pin quickfix]] pattern to `deps-gitlab-ci`. The diagnostic-message builder,
`mutable_ref_pin_diagnostics` in `crates/deps-gitlab-ci/src/ecosystem.rs` (function starting at
line 501), constructs three distinct messages depending on `PinStyle`:

- `PinStyle::Tag` (line 562-566): no "manual edit" suffix — correct, since
  [[031-github-actions-sha-pin-diagnostic/spec|`build_sha_pin_action`]] provides a working quickfix
  for this style.
- `PinStyle::Latest` / `PinStyle::Partial` component includes (line 567-573): appends
  `"(manual edit — no automated fix available for this ref)"`.
- Ref-less `project:` includes and `PinStyle::Branch` (line 574-579, and the ref-less case at
  line 524-537): same suffix.

The same PR also added `build_dynamic_component_pin_action` (line 674) and its `did_open`/hover-time
sibling at line 321, which call `GitlabCiRegistry::resolve_component_pin` (FR-007 resolution ladder)
specifically to resolve `PinStyle::Latest` and `PinStyle::Partial` component pins to a real commit
SHA and offer a "Pin `{name}` to commit SHA" quickfix — bounded by
`COMPONENT_PIN_RESOLUTION_TIMEOUT` (5s, line 76). The doc comment above `mutable_ref_pin_diagnostics`
(line 486-500) explicitly states that `Latest`/`Partial` component includes "always resolve to
whichever release currently matches ... so they are mutable by construction", but its closing
paragraph incorrectly groups them with the two genuinely-unfixable cases ("None of the last three
get the 'Pin to commit SHA' quickfix").

This is a copy-paste carryover: the `else` fallback (line 574-579, handling ref-less `project:` and
`PinStyle::Branch`) is the ONE case where the suffix is accurate — no quickfix exists for those forms
by deliberate design (see `build_sha_pin_action`'s doc comment on branch/tag name-collision risk,
line 603-610). The `Latest`/`Partial` branch (line 567) duplicated that suffix even though
`build_dynamic_component_pin_action` was built, in the same PR, specifically to cover it.

**Live evidence** (cycle-045, real `gitlab.com` API data, fixture `.gitlab-ci.yml`):

```yaml
include:
  - component: gitlab.com/components/opentofu/full-pipeline@~latest
  - component: gitlab.com/components/opentofu/full-pipeline@4.8
```

1. `textDocument/didOpen` → `publishDiagnostics` fires `gitlab-ci-mutable-ref-pin` for both lines,
   message ending `"...pin to an exact release and commit SHA to guard against ref mutation
   (manual edit — no automated fix available for this ref)"`.
2. `textDocument/codeAction` with `range`/`context.diagnostics` from that exact diagnostic returns
   1 action: `title='Pin gitlab.com/components/opentofu/full-pipeline to commit SHA'`,
   `kind=quickfix`, with a correct `TextEdit` replacing the `~latest`/`4.8` ref text with a real
   40-hex commit SHA (`24eeefe08dae99c7f1a33b1ad2af0bf52590f57e` for `~latest`,
   `3b1244300f2ded8a5c4157492cf90d0c66dac18f` for `4.8`), resolved against real GitLab CI/CD
   Catalog release data.
3. Zero WARN/ERROR/panics in the debug log for this scenario.

Positive controls confirmed unaffected: `PinStyle::Tag` project/component pins get the correct
message (no suffix) and their own working quickfix; `PinStyle::Sha` and unconfirmed
`PinStyle::Branch` pins correctly get no diagnostic at all.

### Goal

The `gitlab-ci-mutable-ref-pin` diagnostic message for a `PinStyle::Latest`/`PinStyle::Partial`
component pin no longer asserts that no automated fix is available when
`textDocument/codeAction` in fact returns one — the diagnostic text and the actual quickfix
behavior agree.

### Out of Scope

- Any change to `build_dynamic_component_pin_action`'s resolution logic, timeout, or the FR-007
  resolution ladder in `GitlabCiRegistry::resolve_component_pin` — this spec is about the
  diagnostic *message text* only, not the quickfix's resolution behavior.
- The ref-less `project:` include message (line 524-537) and the `PinStyle::Branch`/unconfirmed
  cases (line 574-579, `else` fallback) — their "no automated fix available" wording is accurate
  and stays as-is.
- Porting any equivalent fix back to `deps-github-actions` — that ecosystem's mutable-ref-pin
  diagnostic only has one non-`Tag` case (unconfirmed `Branch`, which gets no diagnostic at all),
  so this specific message/quickfix mismatch does not exist there. Out of scope unless a
  follow-up audit finds otherwise.

## 2. User Stories

### US-001: Diagnostic message matches available quickfix

AS A developer using an LSP-integrated editor (e.g. Zed, VS Code, Neovim) on a `.gitlab-ci.yml`
file with a `component:` include pinned via `@~latest` or a partial version like `@4.8`
I WANT the mutable-ref-pin diagnostic to tell me a quickfix is (or may be) available
SO THAT I don't dismiss the diagnostic as "manual work only" and skip checking `Cmd+.`/quick-fix,
missing a one-click automated correction that already exists

**Acceptance criteria:**
```
GIVEN a .gitlab-ci.yml with a component: include pinned via PinStyle::Latest (e.g. @~latest)
  or PinStyle::Partial (e.g. @4.8)
WHEN the gitlab-ci-mutable-ref-pin diagnostic is published for that include
THEN the diagnostic message text does not claim "no automated fix available for this ref"
```

```
GIVEN the same scenario
WHEN textDocument/codeAction is requested over the diagnostic's range with the diagnostic in
  context.diagnostics
THEN build_dynamic_component_pin_action's existing quickfix behavior is unchanged — this is a
  message-text-only fix, not a functional change to the quickfix
```

### US-002: Unfixable cases keep their accurate message

AS A developer with a ref-less `project:` include or a `PinStyle::Branch`/`else`-fallback pin
I WANT the diagnostic to continue accurately stating that no automated fix exists
SO THAT I am not misled into looking for a quickfix that genuinely isn't offered

**Acceptance criteria:**
```
GIVEN a ref-less project: include, or a PinStyle::Branch include reaching the else fallback
WHEN the gitlab-ci-mutable-ref-pin diagnostic is published
THEN the message text is unchanged from current behavior (still states no automated fix is
  available)
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN `mutable_ref_pin_diagnostics` builds a message for a `component:` include with `PinStyle::Latest` or `PinStyle::Partial` **whose `DependencySource` is `AlternateRegistry` with a route registered in `GitlabCiRegistry::routes`** THE SYSTEM SHALL NOT include the literal suffix `"(manual edit — no automated fix available for this ref)"` in that message | must |
| FR-001a | WHEN the same include's host is `HostRef::Unresolved` or `HostRef::CapacityRefused` (so its source is `CustomRegistry`, or its route is unregistered, and `build_dynamic_component_pin_action` therefore cannot offer a quickfix) THE SYSTEM SHALL continue to include the existing "no automated fix available for this ref" wording | must |
| FR-002 | WHEN `mutable_ref_pin_diagnostics` builds a message for a ref-less `project:` include (no `ref:` key) THE SYSTEM SHALL continue to include the existing "no automated fix available" wording unchanged | must |
| FR-003 | WHEN `mutable_ref_pin_diagnostics` builds a message for the `else` fallback case (`PinStyle::Branch` confirmed via `is_registry_confirmed_tag`, and any other pin style reaching that arm) THE SYSTEM SHALL continue to include the existing "no automated fix available for this ref" wording unchanged | must |
| FR-004 | WHEN the doc comment above `mutable_ref_pin_diagnostics` describes which pin styles get no quickfix THE SYSTEM's documentation SHALL accurately list only the ref-less `project:` include and the `PinStyle::Branch`/`else`-fallback case — not `Latest`/`Partial` component pins | must |
| FR-005 | WHERE the resolution to FR-001's message text depends on whether `build_dynamic_component_pin_action` can fail at click time (timeout, transient fetch error) THE SYSTEM SHALL phrase the new message in a way that does not overclaim guaranteed success if resolution can legitimately return `None` | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Consistency | The corrected message text must not regress any existing snapshot/unit test asserting the old (incorrect) wording for `Latest`/`Partial` — those tests are expected to change as part of this fix, not silently pass by coincidence |
| NFR-002 | Maintainability | The doc comment fix (FR-004) must remove the ambiguity that let this bug happen (a single sentence grouping three cases together) rather than just patching the message string in isolation |

## 5. Data Model

No data model changes. This is a message-text and doc-comment change only; no new fields, types,
or diagnostic codes are introduced. `MUTABLE_REF_PIN_DIAGNOSTIC_CODE` stays the same.

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `component:` pin is `PinStyle::Latest`/`Partial` but `resolve_component_pin` times out or fails at quickfix-request time (after the diagnostic already published a "fix may be available" message) | Diagnostic message must not claim a fix is *guaranteed* — see FR-005; `textDocument/codeAction` legitimately returns zero actions in this case (existing degrade-to-nothing behavior, unchanged) |
| `component:` pin is `PinStyle::Latest`/`Partial` but its host is `HostRef::Unresolved` (`$CI_SERVER_FQDN`, FR-012) or `HostRef::CapacityRefused`, so it has no registered route | Message keeps the "no automated fix available for this ref" suffix (FR-001a). `build_dynamic_component_pin_action` requires `DependencySource::AlternateRegistry` **and** a registered route, so no quickfix is offered for these includes and the suffix is accurate — this is the one `Latest`/`Partial` case FR-001 does not cover |
| Ref-less `project:` include | Message unchanged (FR-002) |
| `PinStyle::Branch` confirmed via `is_registry_confirmed_tag`, reaching the `else` arm | Message unchanged (FR-003) |
| `PinStyle::Tag` | Message unchanged (already correct, no suffix) |
| `PinStyle::Sha` / unconfirmed `PinStyle::Branch` | No diagnostic at all (unchanged, out of scope) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | `gitlab-ci-mutable-ref-pin` diagnostic message for `Latest`/`Partial` component pins no longer contains "no automated fix available for this ref" | 100% of such diagnostics, verified by unit test and live re-test of the cycle-045 fixture |
| SC-002 | Ref-less `project:` and `Branch`/`else`-fallback messages remain byte-identical to current behavior | verified by existing/updated unit tests, zero regression |
| SC-003 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo nextest run -p deps-gitlab-ci` pass after the change | 0 warnings, 0 test failures |

## 8. Agent Boundaries

### Always (without asking)
- Update the doc comment on `mutable_ref_pin_diagnostics` (line 486-500) to match the corrected
  behavior (FR-004)
- Update/add unit tests in `crates/deps-gitlab-ci/src/ecosystem.rs`'s `#[cfg(test)]` module
  covering the exact message text for `Latest`, `Partial`, ref-less `project:`, and the `else`
  fallback
- Run `cargo +nightly fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D
  warnings`, `cargo nextest run -p deps-gitlab-ci`, and the rustdoc gate before considering the
  fix complete
- Add a `CHANGELOG.md` entry under `[Unreleased]`

### Ask First
- Which exact replacement wording to use for FR-001 (see Open Questions — two options given in
  the finding, implementer should pick one and confirm, or ask if a third phrasing is clearer)
- Whether to also adjust `build_dynamic_component_pin_action`'s own doc comment (line 667-673) if
  it references the diagnostic message's old wording

### Never
- Change `build_dynamic_component_pin_action`'s resolution logic, `COMPONENT_PIN_RESOLUTION_TIMEOUT`,
  or `GitlabCiRegistry::resolve_component_pin`'s FR-007 ladder as part of this fix — this is a
  message-text bug, not a resolution-logic bug
- Touch the ref-less `project:` or `PinStyle::Branch`/`else`-fallback message text (FR-002, FR-003)
- Port this change to `deps-github-actions` without first confirming (per Out of Scope) that the
  same mismatch actually exists there

## 9. Resolved Questions

Both original clarification items are resolved; none remain open. (This section deliberately
contains no open-clarification marker text, so a grep-based gate over `specs/` reads this spec as
implementation-ready.)

**Q1 — message wording: resolved as option (a)** (omit the suffix entirely, matching
`PinStyle::Tag`'s phrasing). Option (b) existed to hedge against `COMPONENT_PIN_RESOLUTION_TIMEOUT`
returning no action at click time, but `PinStyle::Tag` already has the identical failure mode — its
quickfix returns `None` on a `TagIndex` cache miss — and its message hedges nothing. Option (a) is
therefore consistent with the precedent this diagnostic family already set for the same situation,
and satisfies FR-005 because a message that makes no availability claim cannot overclaim. Option (b)
would also introduce a third message state, weakening the message/quickfix agreement invariant from
a binary one to a three-way one.

**Q2 — tracking issue: resolved.** Issue #643 is filed and assigned; implemented on branch
`feat/640-643-gitlab-ci-pin-parity` alongside #640.

## 9a. Amendments

**2026-09-05 — FR-001 narrowed, FR-001a added.** As originally written, FR-001 was unconditional for
every `Latest`/`Partial` `component:` include. That conflicted with the spec's own Goal ("the
diagnostic text and the actual quickfix behavior agree") and with US-001's acceptance criteria: a
`Latest`/`Partial` component on a `HostRef::Unresolved`/`CapacityRefused` host gets
`DependencySource::CustomRegistry` and no registered route, so
`build_dynamic_component_pin_action` (`ecosystem.rs:696-699`) offers **no** quickfix for it — and
dropping the suffix there would have replaced one message/behavior mismatch with another, in the
opposite direction.

The original wording was an oversight rather than a scope decision: the finding's live evidence came
exclusively from a resolved `gitlab.com` host, where the unresolved-host case cannot arise. FR-001
now carries the source/route condition, FR-001a states the complementary case, and §6 gains the
corresponding Edge Cases row. No change to the Goal, user stories, or Out of Scope.

## 10. See Also

- [[constitution]] — project principles (not yet created for this project; see `specs/MOC-specs.md`'s Project Foundation section)
- [[MOC-specs]] — all specifications
- [[030-gitlab-ci-ecosystem/spec]] — GitLab CI/CD ecosystem base spec
- [[031-github-actions-sha-pin-diagnostic/spec]] — the GitHub Actions mutable-ref-pin diagnostic/quickfix pattern this feature ported, and whose message-text discipline this bug deviated from
- PR #637 (`ce5c4c15`) — introduced both the incorrect message and the quickfix that contradicts it
- Issue #634 — original mutable-ref-pin diagnostic/quickfix feature request referenced in the code's doc comments

---
aliases:
  - GitHub Actions SHA-Pin Diagnostic
  - Mutable Ref Pin Security Diagnostic
tags:
  - sdd
  - spec
  - research
  - security
  - github-actions
  - deps-core
created: 2026-09-02
status: draft
related:
  - "[[constitution]]"
  - "[[014-github-actions-ecosystem/spec|New ecosystem: GitHub Actions workflow uses: pins]]"
issue: 473
---

# Feature: GitHub Actions Mutable-Ref-Pin Security Diagnostic (SHA-Pin Recommendation)

> [!info] Metadata
> **Author**: continuous-improvement cycle (research/parity stream)
> **Branch**: feat/473-github-actions-sha-pin-diagnostic
> **Priority**: P2
> **Type**: research (security/parity gap)
> **Issue**: #473

## 1. Overview

### Problem Statement

PR #471 (merged, closes issue #208) added the `deps-github-actions` ecosystem
crate: hover, inlay hints, outdated-version diagnostics, code actions, and
code lens for `uses:` steps in `.github/workflows/*.yml`. It correctly
resolves and updates tag pins (`actions/checkout@v4`), SHA pins with a
trailing `# vX.Y.Z` comment, and recognizes (but does not resolve) branch
pins. All of this machinery is about *outdated version* detection — "is
there a newer tag/SHA available."

It does not implement a distinct, well-established security-hardening
check: flagging a `uses:` step pinned to a **mutable ref** (a tag like `@v4`
or a branch like `@main`) as a supply-chain risk, with a code action to
convert it to an immutable **full commit SHA** pin
(`@<40-hex-sha> # v4`). This is a different concern from staleness — a
workflow can be "up to date" on its tag and still be vulnerable to tag
mutation (a compromised or republished tag silently changes what code runs
in CI without the workflow file changing at all).

This is an industry-recognized, actively-recommended practice, not a novel
idea — see [[#10-see-also|See Also]] for the four independent reference
sources (GitHub's own hardening docs, Renovate, `zizmor`, StepSecurity) plus
OpenSSF Scorecard's Pinned-Dependencies check. At least two independent,
actively-maintained reference projects (Renovate, `zizmor`) plus a
dedicated commercial tool (StepSecurity) implement this exact capability,
meeting the project's P2 parity bar ("meaningful capability that 2+
reference projects have and users would notice").

**Why deps-lsp is well-positioned to close this gap cheaply**: the crate
already has everything needed as a byproduct of existing outdated-version
machinery:

- `GithubActionsRegistry`'s tag index (`crates/deps-github-actions/src/registry.rs`,
  `tag_index()` accessor returning `Arc<DashMap<PackageName, Arc<TagIndex>>>`)
  already maintains a `tag <-> sha` cross-reference (`TagIndex.tag_to_sha` /
  `TagIndex.sha_to_tag`), populated for free from the existing
  `/repos/{name}/tags` fetch — no new network calls required.
- `GithubActionsFormatter::format_version_replacing_for`
  (`crates/deps-github-actions/src/formatter.rs`, the `EcosystemFormatter`
  hook added in #471) already knows how to emit `{sha} # {tag}` replacement
  text for a SHA-pin update via the `PinStyle::Sha { .. }` branch — the same
  formatting a "convert tag to SHA" code action would need, just triggered
  on a different condition (pin style is `Tag`/`Branch`, not "a newer
  version exists").
- `PinStyle` (`crates/deps-github-actions/src/types.rs`) already
  distinguishes `Tag`, `Sha { comment_tag }`, and `Branch` — `parser.rs`
  already recognizes and classifies branch-shaped refs, it just doesn't
  resolve their target SHA today (`format_version_replacing_for` returns
  `current` unchanged for `PinStyle::Branch`, by design, to avoid a
  destructive downgrade edit).

### Goal

A `uses:` step pinned to a mutable ref (`PinStyle::Tag` or `PinStyle::Branch`)
surfaces a distinct diagnostic recommending SHA pinning, with an
accompanying code action that rewrites the pin to `{sha} # {tag_or_ref}`
using the already-populated `TagIndex` — with zero new network calls beyond
what the existing outdated-version check already performs.

### Out of Scope

- Any change to the existing outdated-version diagnostic, hover, inlay
  hint, or code lens behavior for GitHub Actions — this spec adds a new,
  independent signal, it does not modify the staleness check.
- **Branch pins (`PinStyle::Branch`, e.g. `@main`).** `TagIndex` is
  populated only from `/repos/{name}/tags`, so it has no branch-to-SHA
  mapping; resolving one would require a new network call, violating
  NFR-001. Deferred to a dedicated follow-up issue once a branch-SHA
  resolution strategy (and its network-cost trade-off) is designed and
  spec'd on its own. This iteration (#473) implements `PinStyle::Tag`
  only — FR-002 is removed from this spec's scope.
- Any generic, cross-ecosystem "mutable ref" diagnostic or a shared
  `deps-core` diagnostic kind — this spec is scoped to GitHub Actions
  only, with the diagnostic kind living locally in `deps-github-actions`.
  Generalizing into `deps-core` is deferred until a second ecosystem
  (e.g. GitLab CI `include:` per #466) actually needs the same shape —
  extracting shared logic without a second caller is premature
  abstraction the project's MVP guidance rejects.
- Reusable-workflow calls (`owner/repo/.github/workflows/x.yml@ref`) —
  already parsed as `DependencySource::Url` per #471 and excluded from
  version resolution; out of scope for this spec. May get an equivalent
  recommendation in a future follow-up if requested, not assumed here.
- `./local` action references and `docker://image:tag` uses — both already
  excluded from version resolution in #471 for unrelated reasons (no
  resolvable ref) and are out of scope here for the same reason.
- Workspace/client configuration to disable the diagnostic — it ships
  on by default (consistent with every other deps-lsp diagnostic), using
  the existing `DiagnosticSeverities`-style mechanism a user already has
  to lower its severity or silence it; no new opt-in toggle is introduced.

## 2. User Stories

### US-001: Flag mutable-ref pins as a supply-chain risk

AS A developer maintaining a GitHub Actions workflow in a repository
deps-lsp is attached to
I WANT a diagnostic when a `uses:` step is pinned to a tag or branch
instead of a full commit SHA
SO THAT I know which steps are exposed to tag/branch mutation even when the
workflow shows no "outdated" warnings

**Acceptance criteria:**
```
GIVEN a workflow step `uses: actions/checkout@v4` (a PinStyle::Tag, currently
  the latest available tag — no outdated-version diagnostic fires)
WHEN the document is scanned
THEN a mutable-ref-pin diagnostic fires on that step, independent of and in
  addition to (not instead of) the outdated-version check
```

### US-002: One-click conversion to an immutable SHA pin

AS A developer who wants to harden a workflow step
I WANT a code action that rewrites `actions/checkout@v4` to
`actions/checkout@<40-hex-sha> # v4` in one click
SO THAT I don't have to manually look up the commit SHA for the currently
pinned tag

**Acceptance criteria:**
```
GIVEN a workflow step `uses: actions/checkout@v4` and a populated TagIndex
  entry for `actions/checkout` mapping `v4` -> `<sha>`
WHEN the user invokes the code action for the mutable-ref-pin diagnostic
THEN the edit rewrites the step's ref to `<sha> # v4`, matching the same
  `{sha} # {tag}` shape `format_version_replacing_for`'s
  `PinStyle::Sha { .. }` branch already produces for outdated-SHA updates
```

### US-003: No duplicate/conflicting signal with the outdated-version diagnostic

AS A developer reading deps-lsp diagnostics for a workflow file
I WANT the mutable-ref-pin diagnostic and the outdated-version diagnostic to
be clearly distinguishable
SO THAT I don't confuse "this tag is stale" with "this tag is mutable" —
they require different fixes (bump the version vs. pin the SHA) and a
step can have either, both, or neither independently

**Acceptance criteria:**
```
GIVEN a workflow step `uses: actions/checkout@v3` (a PinStyle::Tag that is
  both mutable AND stale relative to the latest available tag)
WHEN the document is scanned
THEN both diagnostics fire on the same step with distinguishable messages/
  codes/severities, and both code actions are independently offered
  (bump to latest tag; OR pin current tag to its SHA) without either
  suppressing the other
```

## 3. Functional Requirements

Use EARS notation. Prefix with FR-NNN.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a `uses:` step's `pin` is `PinStyle::Tag` THE SYSTEM SHALL emit a mutable-ref-pin diagnostic recommending conversion to a full commit SHA pin | must |
| FR-002 | *(removed — branch-pin diagnostics deferred to a follow-up issue; see Out of Scope. `PinStyle::Branch` steps get no diagnostic from this feature.)* | n/a |
| FR-003 | WHEN a `uses:` step's `pin` is already `PinStyle::Sha { .. }` (with or without a `comment_tag`) THE SYSTEM SHALL NOT emit the mutable-ref-pin diagnostic for that step | must |
| FR-004 | WHEN the mutable-ref-pin diagnostic fires for a `PinStyle::Tag` step AND the shared `TagIndex` (already populated by the existing outdated-version resolution path) has an entry for the step's current tag THE SYSTEM SHALL offer a code action that rewrites the ref to `{sha} # {tag}`, reusing the same replacement shape `GithubActionsFormatter::format_version_replacing_for`'s `PinStyle::Sha { .. }` branch already produces | must |
| FR-005 | WHEN the `TagIndex` has no entry for the step's current tag (cache miss, e.g. document opened before the registry fetch completed) THE SYSTEM SHALL still emit the diagnostic but SHALL NOT offer a code action with an unresolved or incorrect SHA — no destructive/no-op edit, consistent with the existing miss-handling precedent in `format_version_replacing_for` | must |
| FR-006 | WHEN both the mutable-ref-pin diagnostic and the existing outdated-version diagnostic apply to the same step THE SYSTEM SHALL emit both independently, with distinct diagnostic codes/sources, and SHALL NOT suppress either one in favor of the other | must |
| FR-007 | WHEN the mutable-ref-pin diagnostic's code action is applied THE SYSTEM SHALL preserve the step's existing trailing comment convention (`# {tag}`), matching the format already used by the outdated-SHA-update code action, so the two code actions are visually consistent to the user | should |
| FR-008 | WHEN the mutable-ref-pin diagnostic fires THE SYSTEM SHALL use `Hint` severity by default, configurable through the same `DiagnosticSeverities`-style mechanism as other deps-lsp diagnostics (`crates/deps-core/src/lsp_helpers/diagnostics.rs`) | must |
| FR-009 | THE SYSTEM SHALL emit the mutable-ref-pin diagnostic without requiring any new workspace or client configuration to opt in — it ships enabled by default, matching every other deps-lsp diagnostic | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Performance | Zero new network calls — the diagnostic and its code action must be computed entirely from data already fetched for the existing outdated-version check (the shared `TagIndex`, populated from the existing `/repos/{name}/tags` call). No new endpoint, no per-step extra request. |
| NFR-002 | Performance | Diagnostic computation must not measurably regress per-document scan latency — it is a pure classification over already-parsed `PinStyle` values plus an already-cached map lookup (`O(1)` `TagIndex` lookup per mutable-pinned step), not a new scan pass over the registry. |
| NFR-003 | Consistency | The diagnostic's severity, message format, and code-action title must follow the same `DiagnosticSeverities`-style configurability precedent already established for other deps-lsp diagnostics (`crates/deps-core/src/lsp_helpers/diagnostics.rs`), rather than hardcoding a severity that cannot be tuned per client/workspace. Default severity is `Hint` (FR-008). |
| NFR-004 | Backward compatibility | Introducing this diagnostic must not change any existing diagnostic's code, severity, or message for the outdated-version check (US-003) — this is strictly additive. |

## 5. Data Model

No new persistent entities. This feature is a new *interpretation* of
already-parsed/already-fetched data:

| Entity | Description | Key Attributes |
|--------|-------------|----------------|
| `PinStyle` (existing, `crates/deps-github-actions/src/types.rs`) | How a `uses:` step's ref is pinned | `Tag`, `Sha { comment_tag: Option<String> }`, `Branch` — this feature's trigger condition reads this enum, does not extend it |
| `TagIndex` (existing, `crates/deps-github-actions/src/registry.rs`) | Per-repository `tag <-> sha` cross-reference | `tag_to_sha: HashMap<String, String>`, `sha_to_tag: HashMap<String, String>` — this feature's code action reads `tag_to_sha`, does not extend it |
| Mutable-ref-pin diagnostic code/kind (new) | New variant distinguishing this diagnostic from the existing outdated-version one | Lives locally in `deps-github-actions` (e.g. a new variant on the crate's existing diagnostic-code enum, or an equivalent local type) — not a shared `deps-core` kind. Generalizing is deferred until a second ecosystem needs the same shape (see Out of Scope). |

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| `uses: actions/checkout@v4` where `v4` is the latest available tag | Mutable-ref-pin diagnostic fires (mutability, not staleness); outdated-version diagnostic does not fire — the two are orthogonal (US-001, US-003) |
| `uses: actions/checkout@v3` where `v4` is now latest | Both diagnostics fire independently (US-003, FR-006) |
| `uses: actions/checkout@<sha> # v4` (already SHA-pinned with comment) | No mutable-ref-pin diagnostic (FR-003); existing outdated-SHA-update diagnostic behavior unchanged |
| `uses: actions/checkout@<sha>` (SHA-pinned, no comment) | No mutable-ref-pin diagnostic (FR-003) — already immutable regardless of comment presence |
| `uses: some-org/some-action@main` (branch pin) | No diagnostic in this iteration — branch pins are deferred to a follow-up issue (Out of Scope); `PinStyle::Branch` is treated the same as "no signal" by this feature |
| `TagIndex` has no entry yet for the step's repository (registry fetch still in flight, or repository/tag lookup failed) | Diagnostic still fires (mutability is knowable from `PinStyle` alone, no registry data needed); code action is withheld until an entry exists (FR-005) |
| `TagIndex` entry exists for the repository but not for this specific tag (e.g. a moved/deleted tag, or a non-semver tag not indexed) | Diagnostic fires; code action withheld (same as above, FR-005) |
| Reusable-workflow call (`owner/repo/.github/workflows/x.yml@ref`) | Out of scope per this spec (`DependencySource::Url`, not `Registry`) — no diagnostic, consistent with existing exclusion from version resolution |
| `./local` action reference or `docker://image:tag` | No diagnostic — no resolvable ref, consistent with existing exclusion (`source` is `Path`/`Url`, not `Registry`) |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | New network calls attributable to this diagnostic, per document scan | 0 (NFR-001) |
| SC-002 | Existing outdated-version diagnostic behavior (message, severity, trigger condition) after this change | Unchanged (byte-for-byte identical for any workflow file that does not additionally trigger the new diagnostic) |
| SC-003 | Steps pinned by tag (`PinStyle::Tag`) in a test workflow fixture | 100% receive the mutable-ref-pin diagnostic; branch-pinned steps receive none in this iteration (deferred, see Out of Scope) |
| SC-004 | Steps already SHA-pinned (with or without comment) in the same fixture | 0% receive the mutable-ref-pin diagnostic (FR-003) |
| SC-005 | Code action correctness | Applying the code action on a `TagIndex`-hit step produces a byte-identical result to what `format_version_replacing_for`'s existing `PinStyle::Sha { .. }` formatting would produce for the same `(name, tag)` pair |

## 8. Agent Boundaries

### Always (without asking)
- Read `crates/deps-github-actions/src/types.rs` (`PinStyle`),
  `crates/deps-github-actions/src/registry.rs` (`TagIndex`,
  `GithubActionsRegistry::tag_index`), and
  `crates/deps-github-actions/src/formatter.rs`
  (`format_version_replacing_for`) in full before implementing — all three
  already carry the exact data and formatting shape this feature reuses.
- Reuse the existing `TagIndex` and its `tag_to_sha` map rather than adding
  a new cache, index, or network call (NFR-001).
- Keep the existing outdated-version diagnostic's code, severity, and
  message untouched (NFR-004) — add a new, additive diagnostic path
  alongside it, never merge or replace it.
- Run full CI checks (`cargo +nightly fmt --check`, clippy, nextest,
  rustdoc gate) per project convention before any PR.
- Add a live-test pass against a real workflow file with mixed tag/SHA/
  branch pins before marking this shipped, per the project's Live Testing
  Principle (`.claude/rules/continuous-improvement.md`).

### Ask First
- Any change that would require a new network call to resolve branch-pin
  SHAs — branch pins are out of scope for this iteration; if implementation
  reveals a cheap way to include them, confirm with the user before
  expanding scope rather than assuming it's welcome.
- Whether to file a separate follow-up issue for branch-pin support now vs.
  after this PR ships.

### Never
- Silently fold this into the existing outdated-version diagnostic's code
  path such that the two become indistinguishable to the user (violates
  US-003/FR-006).
- Introduce a new network call or a second registry index to resolve
  branch-pin SHAs without first resolving the open question on branch
  scope — a naive implementation could accidentally add a per-branch API
  call, violating NFR-001.
- File this as shipped without empirical live-test verification, per the
  project's Live Testing Principle.

## 9. Open Questions

All items resolved during `/sdd specify` iteration (2026-09-02):

- **Default state**: on by default, no new opt-in configuration (FR-009).
  Consistent with every other deps-lsp diagnostic; a user who disagrees
  already has `DiagnosticSeverities` to silence it.
- **Severity**: `Hint` by default, configurable via the existing
  `DiagnosticSeverities` mechanism (FR-008, NFR-003).
- **Branch pins (FR-002)**: deferred out of scope for this iteration —
  no `TagIndex` branch-to-SHA mapping exists today and adding one would
  require a new network call (violates NFR-001). Tracked as a follow-up
  once a branch-SHA resolution strategy is designed and spec'd.
- **Reusable-workflow calls**: out of scope, unchanged from the original
  draft — no equivalent recommendation in this spec.
- **Diagnostic kind location**: local to `deps-github-actions`, not a
  shared `deps-core` kind — no second ecosystem consumer exists yet, so
  extracting a shared abstraction now would be premature (project MVP
  guidance). Revisit if/when #466 (GitLab CI `include:`) or a similar
  ecosystem needs the same mutable-ref-pin shape.
- **GitHub issue**: filed as #473, referenced in this spec's frontmatter
  and metadata.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[014-github-actions-ecosystem/spec|New ecosystem: GitHub Actions workflow uses: pins]] — original spec for the ecosystem this feature extends
- PR #471 — merged, added `deps-github-actions` (hover, inlay hints,
  outdated-version diagnostics, code actions, code lens); closed issue #208
- Issue #208 — original GitHub Actions ecosystem tracking issue
- [GitHub Docs: Security hardening for GitHub Actions — pinning actions to a full-length commit SHA](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Renovate docs: GitHub Actions manager, `helpers:pinGitHubActionDigests` preset](https://docs.renovatebot.com/modules/manager/github-actions/)
- [Renovate discussion: `pinGitHubActionDigestsToSemver` variant](https://github.com/renovatebot/renovate/discussions/42031)
- [`zizmor` audits reference — `unpinned-uses` rule](https://docs.zizmor.sh/audits/)
- [`zizmor` GitHub repository — audits documentation source](https://github.com/zizmorcore/zizmor/blob/main/docs/audits.md)
- [StepSecurity: Pinning GitHub Actions for Enhanced Security — a Complete Guide](https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide)

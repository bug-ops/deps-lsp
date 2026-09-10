---
aliases:
  - Ecosystem sealing inversion decision record
  - Invert Ecosystem's extension point for compiler-enforced sealing
tags:
  - sdd
  - spec
  - research
  - decision-record
  - deps-core
created: 2026-09-10
status: shipped
related:
  - "[[constitution]]"
---

# Feature: Ecosystem sealing inversion — decision record (won't-do)

> [!info] Metadata
> **Author**: architect + critic (research session, 2026-09-10), recorded by sdd
> **Branch**: N/A (research finding, no implementation branch)
> **Related issues**: #770, #772, #774

## 1. Overview

### Problem Statement

Issue #774 ("research: invert Ecosystem's extension point for compiler-enforced
sealing") proposes restructuring `crates/deps-core/src/ecosystem.rs` so that the
public extension point an ecosystem crate implements is no longer `Ecosystem`
itself, but a smaller component trait, with `Ecosystem` (and its
`Arc<dyn Ecosystem>` runtime-polymorphism contract) synthesized from it via a
blanket impl or wrapper. The motivation, inherited from #770 and #772, is that
today's sealing — `Ecosystem: private::Sealed`, `private::Sealed` sitting behind
`#[doc(hidden)] pub mod private` (`crates/deps-core/src/ecosystem.rs:29`) — is
only a documented convention, not a compiler-enforced guarantee: any of the 14
sibling `deps-<ecosystem>` crates (and, identically, any external crates.io
consumer) can implement `Ecosystem` directly, because Rust has no
workspace-scoped visibility modifier. #772 already shipped a doc-only fix for
the sealed-trait documentation and broken intra-doc links, and #774 was filed
anyway — the empirical proof that a doc comment does not settle whether a
structural fix is warranted.

This is not a bug — it is an open architectural question that needs a
documented decision, backed by verification in a throwaway scratch workspace,
so that a fourth pass over the same idea (after #770 → #772 → #774) does not
re-derive this analysis from scratch.

### Goal

Produce a documented, evidence-based decision on whether to invert
`Ecosystem`'s extension point to achieve compiler-enforced sealing, including a
concrete assessment of every shape considered, so the decision is a
first-class, revisitable artifact rather than tribal knowledge repeatedly
re-litigated across issues.

### Decision

**Won't-do.** Do not implement the `Ecosystem` → component-trait inversion.
Close #774 referencing this spec as the recorded rationale.

### Headline Finding

> [!important] The guarantee costs a crate boundary, not a trait shape.
> No rearrangement of traits inside the current crate layout can seal
> `Ecosystem`, because Rust has no workspace-scoped visibility: any mechanism
> the 14 sibling `deps-<ecosystem>` crates can use, an arbitrary crates.io
> consumer can use identically. Sealing is achievable only by removing the
> boundary that forces the extension point to be public.
>
> What Variants C and D actually share is that the extension point stops
> being a trait that other crates implement — either it becomes a closed enum
> (C) or the implementors stop being other crates (D).

### Out of Scope

- Implementing any of the four shapes evaluated below (this is a `specify`-only
  decision record — no `/sdd plan` or `/sdd tasks` phase).
- Re-litigating the four alternatives #770/#772 already rejected:
  `pub(crate) mod private`, a capability token, feature-gating, and
  `macro_rules!`-based sealing. A "sealed bound on the blanket impl's generic
  parameter" (Variant A with an added seal) collapses to today's design for the
  same reason those were rejected.
- Decomposing `Ecosystem` into parse/format/registry component traits for
  reasons *other* than sealing — `EcosystemFormatter` already covers most of
  that separation and is an orthogonal concern from this decision.
- Editing any file under `crates/**` — this is a decision record, not an
  implementation. `#[doc(hidden)] pub mod private`'s doc comment already
  disclaims any guarantee to an outside implementor; updating it to point at
  this spec is an optional, separately-scoped follow-up, not part of this
  chain.

## 2. User Stories

### US-001: Maintainer avoids re-litigating a settled architectural question
AS A project maintainer or future research session evaluating `Ecosystem`'s
extension point
I WANT a recorded decision with verified evidence, not just a conclusion
SO THAT I don't have to reconstruct the scratch-workspace proof and migration
counts every time this idea resurfaces

**Acceptance criteria:**
```
GIVEN a future session proposes inverting Ecosystem's extension point again
WHEN it reads this spec's Revisit Trigger section
THEN it can determine immediately whether the trigger condition has occurred,
     without re-deriving the zero-delta construction argument or re-running
     the scratch-workspace verification
```

### US-002: Reviewer verifies the "won't-do" conclusion without redoing the analysis
AS A code reviewer or architect evaluating whether #774 was closed correctly
I WANT the evidence (verified facts, migration counts, rejected shapes) laid
out separately from the conclusion
SO THAT I can audit the reasoning rather than trust the recommendation blindly

**Acceptance criteria:**
```
GIVEN this spec
WHEN a reviewer reads the Functional Requirements and Data Model sections
THEN they can independently confirm the zero-semver-delta claim, the four
     shapes' costs, and the corrected migration counts without re-reading
     crates/deps-core/src/ecosystem.rs from scratch
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN a session evaluates inverting `Ecosystem`'s extension point THE SYSTEM (research process) SHALL first check whether an external (non-workspace) `impl Ecosystem` has been observed in the wild | must |
| FR-002 | WHEN FR-001's condition has not occurred THE SYSTEM SHALL classify any such proposal as "already evaluated, won't-do" and reference this spec instead of re-deriving the analysis | must |
| FR-003 | WHEN FR-001's condition occurs AND the project is willing to accept a crate-boundary change THE SYSTEM SHALL re-open this decision and evaluate Variant C (move `EcosystemRegistry` out of `deps-core` into `deps-lsp`, dispatch over a closed enum keyed on `EcosystemId`) or Variant D (collapse the 14 ecosystem crates into `deps-core` modules) as the only two shapes that deliver a compiler-enforced guarantee | must |
| FR-004 | WHEN re-evaluating per FR-003 THE SYSTEM SHALL re-derive the migration-site counts against current source (line numbers and totals drift with unrelated changes) rather than reusing this spec's counts verbatim | must |
| FR-005 | THE SYSTEM SHALL NOT treat reaching a 1.0 release as a trigger for re-evaluation — the zero-semver-delta argument (see Data Model) holds at every version, so a 1.0 boundary changes nothing about the recommendation | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | API stability | Any adopted shape must not increase the semver-breaking surface of adding a new required `Ecosystem` method beyond what exists today — Variants A and B fail this trivially by construction (see Data Model); this is the primary criterion ruling them out |
| NFR-002 | Documentation posture | Any adopted shape must not require promoting today's `#[doc(hidden)]`, guarantee-disclaiming extension point into a first-class, rustdoc-documented, doctested authoring path unless it also delivers a genuine compiler-enforced guarantee in return — a documented-but-still-unsealed component trait is strictly worse than the current hidden, disclaimed one |
| NFR-003 | Migration risk | Any adopted shape touching the ~105 sites enumerated in the Data Model must be assessed for rebase-churn risk given this repository's high rate of concurrent merges to `main`, independent of whether the migration itself is compiler-enforced end-to-end |

## 5. Data Model

This section documents the verified evidence, not persisted entities — the
evidence *is* the decision-relevant content for future audits.

### Verified in a throwaway scratch workspace (not committed to the repo)

- `Arc<dyn Ecosystem>` heterogeneous storage and filename-based routing survive
  trait inversion.
- Per-ecosystem `generate_*` overrides survive when the shared defaults live on
  the component trait and the `Ecosystem` façade only forwards to it.
- `as_any()` downcasting to the concrete ecosystem type — the contract
  `ecosystem_conformance!` relies on — still works.
- `generate_completions` having no default implementation is a non-issue: it
  remains a required method, simply forwarded through the façade.
- The result compiles clean under clippy `pedantic` + `nursery` + `-D
  warnings`. This answers the issue's central open question — compatibility
  with `Box`/`Arc<dyn Trait>` runtime polymorphism — with a verified **yes**.

### The zero-delta construction argument (why inversion buys nothing)

The seal itself becomes compiler-enforced: an external `impl Ecosystem`
produces `E0277`, and naming `private::Sealed` directly produces `E0603`. But
an external crate implementing the necessarily-public, necessarily-unsealed
component trait obtains `Arc<dyn Ecosystem>` anyway, through the blanket impl
— verified compiling. **The semver delta is zero by construction, not merely
"reduced":** any new method the trait requires must be added somewhere the
blanket impl's body can call, which is the component trait — exactly as
breaking as adding it to `Ecosystem` is today. Conversely, anything the
blanket impl can synthesize purely from existing component-trait methods is,
by definition, a default method — already non-breaking today, with no
inversion needed. This equivalence holds at every version, independent of
whether the project is pre- or post-1.0, which is why FR-005 rules out a "1.0
trigger."

### Why component-trait decomposition specifically cannot help (M2)

It is not that `generate_*` overrides span multiple components in a way that
would resist decomposition: `deps-core::lsp_helpers`'s public functions
already take `&dyn EcosystemFormatter` and zero `&dyn Ecosystem`, so that
decomposition already exists at the free-function layer (e.g. npm's override
is plain composition over it). The actual blocker is that the `generate_*`
default implementations are **self-dispatching** — they call
`self.formatter()` and `self.registry()` — so whichever trait carries the
defaults must also carry those accessors, which collapses the "component
trait" to `Ecosystem` minus `Sealed`: a rename plus a forwarding façade, not a
real decomposition. Overrides are the norm, not a worst case — **9 of 14**
ecosystem crates override at least one `generate_*`/`fetch_license` method
(npm, nuget, github-actions, gitlab-ci override `generate_hover`; npm,
github-actions, gitlab-ci override `generate_diagnostics`; github-actions,
gitlab-ci override `generate_code_actions` and
`collect_pin_all_to_sha_edits`; pypi overrides `generate_document_links`;
dart, deno, gradle, swift override `fetch_license`/`license_source`).

### The four shapes considered

| Variant | Description | Cost | Delivers the guarantee? |
|---|---|---|---|
| A — blanket impl | `impl<T: EcosystemParts> Ecosystem for T`, with `mod private` kept genuinely inaccessible | Cheapest: zero changes to registration call sites in `crates/deps-lsp/src/lib.rs`, `as_any` preserved | No |
| B — wrapper struct | `EcosystemAdapter<..>` — the issue's literal proposal | Strictly worse than A: its constructor must be `pub` (making it `pub(crate)` just recreates the sibling-crate problem one level down), breaks the `as_any` downcast unless hand-forwarded, and rewrites every registration site | No |
| C — enum dispatch, moved out of deps-core | No public extension trait at all: move `EcosystemRegistry` out of `deps-core` into `deps-lsp` and dispatch over a closed enum keyed on the already-exhaustive `EcosystemId`; `deps-core::lsp_helpers` stays the free-function layer it already is (its public functions take `&dyn EcosystemFormatter`, never `&dyn Ecosystem`) | Moves `EcosystemRegistry` across a crate boundary and swaps trait dispatch for a closed enum | **Yes** |
| D — collapse crates into deps-core | Fold all 14 `deps-<ecosystem>` crates into `deps-core` modules behind their existing feature flags; `mod private` then becomes genuinely `pub(crate)` with no trait inversion at all | Removes 14 `publish = true` crates | **Yes** |

C and D are the only shapes that deliver a compiler-enforced guarantee, and
both are far more expensive than A — which is precisely the headline finding.

### Dead ends considered and refuted (recorded so they are not re-litigated)

- **F7 — "E0034 ambiguous-method permanent papercut"**: withdrawn.
  `deps-cargo` and `deps-npm` name `Ecosystem` only in their `use` list and the
  `impl` header; under Variant A they would import the component trait
  instead, and no ambiguity arises. `deps-lsp` works exclusively through
  `Arc<dyn Ecosystem>` values and is unaffected. This is an import-hygiene
  detail, not a cost — a recommendation resting on an inflated cost invites a
  future reader to reopen the question on false grounds.
- **"No gate catches a partial migration"**: false. Migration is
  compiler-enforced end to end — dropping an `impl Ecosystem` without adding
  the component-trait impl breaks the `Arc::new(X)` → `Arc<dyn Ecosystem>`
  coercion at every registration site, and any straggler direct `impl
  Ecosystem` fails with `E0277`/`E0603`. Only orphaned `Sealed` impls would
  compile silently, and those are cosmetic. The real migration risk is rebase
  churn from touching ~105 sites in one PR against a repository with frequent
  concurrent merges to `main`, not a missing gate.
- **The "0.x, so it isn't worth the churn yet" rationale and a "revisit at
  1.0" trigger**: both rejected. Pre-1.0 is actually the *cheap* window for a
  breaking rework, which argues *for* it, not against — so this reasoning
  cannot be why the recommendation is won't-do. The recommendation stands
  solely because the benefit is zero by construction (see above), which holds
  independent of version. Recording a 1.0 trigger would manufacture a fake
  future obligation and guarantee exactly the fourth re-litigation this spec
  exists to prevent.

### Migration-site counts (corrected; would apply only if FR-003 is triggered)

| Site kind | Count |
|---|---|
| `impl ..Ecosystem for` | 28 total (26 in compiled source + 2 in doctests: `crates/deps-core/src/ecosystem.rs:611`, `crates/deps-core/src/conformance.rs:507`) |
| `impl ..Sealed for` | 28 code sites (26 in compiled source + 2 in doctests: `ecosystem.rs:609`, `conformance.rs:506`), plus 1 non-compiling prose mention (`ecosystem.rs:21`, backtick-quoted inside the `private` module's doc comment) |
| `ecosystem_conformance!` invocations | 30 |
| `dyn Ecosystem` references in `deps-lsp` | 18 |
| Total touched sites | ~105 (28 + 29 + 30 + 18, counting the prose mention) |

### Posture comparison

Today, `private::Sealed` sits behind `#[doc(hidden)] pub mod private`
(`crates/deps-core/src/ecosystem.rs:29`), with prose explicitly disclaiming
any guarantee to an outside implementor. Any of Variants A/B would instead
require the component trait to become a first-class, rustdoc-visible,
documented authoring path — taught by a doctest and `ECOSYSTEM_GUIDE.md` —
i.e. an advertised public extension point *replacing* a hidden, disclaimed
one, while still providing zero additional guarantee. This is strictly worse
on documentation posture (NFR-002).

## 6. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| An external (non-workspace) crate is observed implementing `Ecosystem` directly | Triggers FR-003 re-evaluation — but only in combination with the project accepting a crate-boundary change (Variant C or D); observing the impl alone is not sufficient, since Variants A/B still deliver nothing even then |
| The project reaches 1.0 with no external `impl Ecosystem` observed | Not a trigger (FR-005) — re-affirm this spec's conclusion without a full re-analysis |
| A future proposal reframes Variant B (wrapper struct) with a `pub(crate)` constructor to avoid the "constructor must be pub" cost | Recognize this recreates the sibling-crate visibility problem one level down (any of the 14 ecosystem crates is already "the crate," so `pub(crate)` there is exactly as porous as `pub` across crates) — does not change the conclusion |
| A future proposal suggests a sealed bound on Variant A's blanket-impl generic parameter | Recognize this collapses to today's design for the same reason `pub(crate) mod private` was rejected in #770/#772 — the bound would need to be satisfiable by the same 14 sibling crates and no one else, which Rust cannot express without a crate-boundary change |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | Time to re-affirm or re-open this decision on a future pass | A future session determines applicability directly from the Revisit Trigger, without re-running the scratch-workspace verification or re-deriving the zero-delta argument |
| SC-002 | False re-implementation attempts avoided | 0 PRs opened implementing Variant A or B against `crates/deps-core/src/ecosystem.rs` before the Revisit Trigger condition is met |

## 8. Agent Boundaries

### Always (without asking)
- Reference this spec instead of re-deriving the analysis when the sealing
  question resurfaces and the Revisit Trigger has not fired
- Re-verify the migration-site counts against current source before quoting
  them, if a future session does trigger FR-003 (line numbers and totals drift)

### Ask First
- Proposing a `/sdd plan` phase for this spec (only once the Revisit Trigger
  condition is met)
- Any edit to `#[doc(hidden)] pub mod private`'s doc comment to point at this
  spec (a legitimate, cheap follow-up, but a separately-scoped PR, not part of
  this chain)

### Never
- Modify any file under `crates/**` as part of this decision record — this
  spec's sole artifact is the recorded rationale, per the architect/critic's
  explicit scope recommendation to stop at `specify`
- Re-litigate `pub(crate) mod private`, a capability token, feature-gating, or
  `macro_rules!`-based sealing — #770/#772 already rejected these

## 9. Revisit Trigger

Re-open this decision only if **both** conditions hold:

1. An external (non-workspace) `impl Ecosystem` is observed in the wild, and
2. The project is willing to accept a crate-boundary change (Variant C: move
   `EcosystemRegistry` out of `deps-core`; or Variant D: collapse the 14
   ecosystem crates into `deps-core`).

Reaching a 1.0 release is explicitly **not** a trigger on its own (FR-005) —
this analysis gives the identical answer at any version, since the zero-delta
construction argument does not depend on semver stage.

## 10. Open Questions

None — the architect and critic converged with no unresolved
`[NEEDS CLARIFICATION]` items; this decision record is ready to close #774
directly.

## 11. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- #770 — original sealed-trait hardening
- #772 — sealed-trait documentation fix and broken intra-doc link correction
  (shipped doc-only; did not preempt #774 being filed)
- #774 — this decision record's source issue
- `crates/deps-core/src/ecosystem.rs` — the `Ecosystem` trait, `private::Sealed`,
  and the `#[doc(hidden)] pub mod private` posture this decision preserves

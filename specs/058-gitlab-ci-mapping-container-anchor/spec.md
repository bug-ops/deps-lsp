---
aliases:
  - GitLab CI mapping-shaped container anchor support
  - "include: entry aliased as a whole mapping (- *tpl / - <<: *tpl)"
tags:
  - sdd
  - spec
  - enhancement
  - deps-gitlab-ci
  - yaml
created: 2026-09-13
status: draft
related:
  - "[[constitution]]"
  - "[[056-gitlab-ci-yaml-scalar-anchor-alias/spec]]"
---

# Feature: Mapping-Shaped Container Anchor Support for `include:` Entries

> [!info] Metadata
> **Author**: architect + critic (two adversarial rounds, 2026-09-13), recorded by sdd
> **Branch**: `feat/916-deps-gitlab-ci-mapping-shaped` (this worktree)
> **Related issues**: #916 (this feature), #912 (hard prerequisite, reopened for implementation),
> #917 (sequence-shaped sibling, won't-fix-by-design), #918 (`!reference` tag, out of scope), #919
> (cross-ecosystem completion literal-span guard, out of scope)
> **Precedent**: `specs/056-gitlab-ci-yaml-scalar-anchor-alias/spec.md` (#912) filed this feature as
> its own Follow-Up #1; `crates/deps-dart/src/parser.rs` (#910, merged) is the shipped
> `RecordingFrame`/replay-through-dispatch precedent this design lifts and extends.

## 0. Foundational Design Principle (P0)

**deps-lsp's contract for this feature is "what GitLab will actually resolve" — the observable
behavior of Ruby Psych, GitLab's real YAML loader — not "what the abstract YAML 1.1 merge-key
extension spec says."** Where the two disagree, Psych wins. The entire purpose of #916 is to avoid
reporting a version GitLab will not use; a spec-faithful answer that GitLab does not produce is a
defect, not a defensible reading.

Two consequences that shape every precedence requirement below:

- The oracle for every merge-precedence functional requirement is the **10-row Psych verification
  table** in §3 (FR-006), not prose reasoning about the YAML 1.1 spec. YAML 1.1's
  position-independent "own keys always win" rule is explicitly **not** what Psych implements, and
  a first design round that assumed it was correct produced the wrong answer in 5 of 10 cases
  (S5, see §9).
- This pins a dependency on an *external implementation's* behavior, so the verification must be
  reproducible: every row was checked against **Ruby Psych 5.3.1**, `YAML.safe_load(src,
  aliases: true)` (the same merge-key resolution path GitLab's config processor relies on). Record
  the Psych version alongside the table so a future loader-behavior change (Psych major version
  bump) is *detectable* — a regression here is silent and produces plausible-looking wrong versions,
  the exact failure class this feature exists to close.

## 1. Overview

### Problem Statement

Issue #912 (this feature's direct prerequisite) closes the gap where a **scalar** anchor
(`.pin: &pin v1.2.3`) is aliased as a `ref:`/`project:`/`component:` *value* inside an `include:`
entry. It deliberately excludes the case where the **anchor itself is a whole entry mapping**:

```yaml
.tpl: &tpl
  project: group/template-project
  ref: v1.0.0

include:
  - *tpl
  - <<: *tpl
    ref: v2.0.0
```

Both `- *tpl` and `- <<: *tpl` are valid, commonly used GitLab CI patterns (whole-job/whole-include
template reuse) and both currently produce **zero** dependency records: the anchor's definition site
sits in a `FrameRole::Irrelevant` frame (anchors are recorded, but their fields are only ever
captured when the frame doing the capturing is `FrameRole::IncludeEntry`), and there is no mechanism
today that re-interprets a recorded mapping anchor's fields at its later alias site.

Unlike #912's scalar case, this is structurally placeable: one alias token maps to exactly one
`include:` entry, exactly the shape `Dependency`'s one-name/one-range model already handles. It was
deferred out of #912 specifically because it requires two things #912's scalar-only design does not:
**merge-key precedence** (a local `ref:` must correctly override or be overridden by `<<: *tpl`,
matching what GitLab's loader actually resolves — getting this wrong yields a *wrong* pinned version,
worse than today's silently dropped dependency) and **re-interpreting a mapping anchor's fields
outside the frame that originally captured them**, which is a real instance of #909's rejected
guard-context-bypass risk class unless done through the structural guard machinery itself, not
around it.

### Goal

A mapping-shaped YAML anchor aliased as a whole `include:` entry — `- *tpl` (plain alias), `include:
*tpl` (single-entry, non-sequence alias), `- <<: *tpl` (merge key), or `- <<: [*a, *b]` (merge-key
sequence) — produces exactly the dependency record(s) GitLab's own loader will resolve for that
entry: correct `project`/`ref`/`component` values under the precedence rules in §3 (FR-006), with
hover, diagnostics, code lenses, and inlay hints all working at the alias/merge site the same as they
would for a literal entry, while every SHA-pin code action, bulk-edit lens, and version-completion
write path stays withheld at any field whose value came from an alias rather than a literal token in
the entry itself.

### Non-Goal: Sequence-Shaped Container Anchors

**This is a deliberate scope decision carried over from #912's own Non-Goal, not an oversight — do
not re-litigate without re-running the verification that established it.**

`include: *incs` — aliasing a whole **sequence** of N entries from one token — stays out of scope
and is closed as won't-fix-by-design (tracked separately as #917). `Dependency`'s one-name/one-range
model cannot give N inner entries N distinct ranges from one alias token, the same structural limit
#912's spec documents for GitHub Actions' container case (#913). This feature's recording mechanism
enforces the exclusion **by construction**: only `FrameKind::Mapping` anchors are ever recorded, so a
sequence anchor is never in the anchor table regardless of where it is aliased — #917 cannot be
silently reopened by a future edit that forgets a runtime check, because there is no check to forget.

### Out of Scope

- `include: *incs` (sequence-shaped container anchor) — #917, won't-fix-by-design, see Non-Goal above.
- `ref: !reference [.t]` — GitLab's own recommended cross-file template-reuse tag — #918, unaffected
  by this feature either way.
- The cross-ecosystem `detect_completion_context` literal-span-guard gap (#919) — this feature's
  `complete_version` gate is a local, per-field instance of that class, same as #912's; the
  `deps-core` class fix stays tracked separately.
- Extending recording to job-body anchors (`script:`/`before_script:`/`image:`) — this crate never
  parses job bodies at all (see #912 spec §1), unaffected by this feature.
- Any new automated edit or completion capability at an alias-derived field — this feature only
  extends *detection*, never *mutation*, of mapping-anchor-derived entries (mirrors #912 US-002).

### Prerequisite Dependency

**This feature has a hard, blocking dependency on #912 (its implementation, not only its spec, which
already exists at `specs/056-gitlab-ci-yaml-scalar-anchor-alias/spec.md`) landing first.** #916's
`Event::Alias` handling is written as an extension of #912's corrected handler, not a parallel one:

- #912 fixes the `? *k` (alias in explicit key position) desync at `parser.rs:235` by splitting the
  transition on `scalar_position()`. #916's handler adds its container-anchor branch to that same
  split rather than reintroducing the bug by rewriting the arm from scratch.
- #912 introduces the value table, `is_alias_occurrence`, and the bounded alias-token-span locator
  that this feature's range-provenance mechanism (§3, FR-011) reuses and promotes into a shared
  `deps-core::lsp_helpers` helper (`alias_token_span`, which does not exist in either crate today).
- Both issues rewrite the *same* `Event::Alias` arm; implementing them out of order, or #916 without
  #912, means re-deriving #912's key-position fix inside this feature's code — duplicated,
  divergence-prone work this spec explicitly does not want.

As of this spec's writing, #912 was closed by its spec PR (#920) alone; `parser.rs:235` still reads
`Event::Alias(_) => self.stack.consume_value()`, with no value table, `is_alias_occurrence`, or span
locator present in the tree. **#916 implementation must not begin before #912's implementation PR
merges.**

## 2. User Stories

### US-001: A whole-entry template reused by alias or merge key is analyzed at its own site

AS A pipeline author who defines one `include:` entry template once (`.tpl: &tpl {project: ...,
ref: ...}`) and reuses it across several entries via `- *tpl` or `- <<: *tpl` to avoid repeating the
same project/ref pair
I WANT hover, mutable-ref-pin diagnostics, code lenses, and inlay hints to appear at every alias/merge
site, not only if I had repeated the literal entry out in full each time
SO THAT using a mapping anchor for whole-entry reuse costs me no analysis coverage compared to writing
each entry out literally.

**Acceptance criteria:**
```
GIVEN a .gitlab-ci.yml with `.tpl: &tpl {project: group/proj, ref: v1.0.0}` and
  two include: entries, one `- *tpl` and one `- <<: *tpl` with a local `ref: v2.0.0`
WHEN the document is parsed
THEN 2 dependency records are produced, each with correct project/ref values and
  working hover/diagnostics/inlay hints at their own alias/merge site
```

### US-002: Merge-key precedence matches what GitLab will actually resolve, not the YAML 1.1 spec's abstract rule

AS A pipeline author combining a template via `<<:` with local overrides, or merging several
templates via `<<: [*a, *b]`
I WANT the reported project/ref/component values to match exactly what GitLab's own YAML loader
(Ruby Psych) will resolve for that entry
SO THAT deps-lsp never reports a version GitLab will not actually use — a plausible-looking wrong
version is worse than no annotation at all.

**Acceptance criteria:**
```
GIVEN any of the 10 precedence shapes in the Psych acceptance table (§3, FR-006)
WHEN the document is parsed
THEN the resolved project/ref/component value matches the table's "GitLab/Psych
  resolves to" column exactly, including the counter-intuitive cases where an own
  key positioned BEFORE `<<:` loses to the merged value
```

### US-003: A pathological or adversarial merge chain cannot corrupt unrelated dependencies

AS A maintainer of this crate
I WANT a document engineered to exceed the replay-event budget (deeply nested or highly fanned-out
merges) to degrade gracefully for the alias that trips the budget, without affecting any other entry
in the same document
SO THAT this feature cannot be used to make deps-lsp silently drop dependencies it has no reason to
drop, via a `did_change`-reparse-reachable denial-of-service shape.

**Acceptance criteria:**
```
GIVEN a document with 1 pathological merge chain designed to exceed
  MAX_REPLAYED_EVENTS, alongside 4 ordinary anchor-free `- project:` entries
WHEN the document is parsed
THEN the pathological entry degrades to 0 records for itself, and all 4
  anchor-free entries are still reported correctly
```

### US-004: An alias- or merge-derived field can never be corrupted by an automated edit

AS A pipeline author using a mapping anchor/alias/merge key for whole-entry reuse
I WANT the "Pin to SHA" code action, the dynamic-component-pin action, the "pin all to SHA" bulk edit,
and version-completion at the cursor to all withhold themselves at any field whose final value came
from an alias, while still working normally at a field in the same entry that is a real local literal
SO THAT no automated fix or completion accept ever rewrites an alias/merge-derived field into a bare
SHA, a spliced version fragment, or a dangling alias — the same corruption class #912's US-002 guards
against, extended to mapping-anchor fields.

**Acceptance criteria:**
```
GIVEN a dependency record where is_alias_occurrence = true for the version field
  but the entry also has a local, non-alias-derived project field
WHEN sha_pin_quickfix_kind, generate_code_actions, collect_pin_all_to_sha_edits,
  or complete_version runs over that record
THEN no edit and no version-completion item is produced for the alias-derived
  field, while any quickfix/completion reachable via the non-alias-derived field
  is unaffected
```

## 3. Functional Requirements

### Mechanism 1 — Recording

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | THE SYSTEM SHALL maintain one flat, append-only `event_log: Vec<(Event, Marker)>` and `recording: Vec<RecordingFrame>` (`{anchor_id, kind, depth, start}`) during the parser's single existing event-stream pass, finalizing a `container_anchors: HashMap<usize, Range<usize>>` entry (anchor id → index range into `event_log`) on each anchored container's closing event. Cost is O(1) per event and zero allocation for an anchor-free document | must |
| FR-002 | THE SYSTEM SHALL record an anchored container **only** when its `FrameKind` is `Mapping` — a `Sequence`-kind anchor is never recorded, under any anchor id, regardless of where it is later aliased. This is the sole and complete mechanism by which #917 stays out of scope: there is no separate runtime check that could be deleted or bypassed | must |
| FR-003 | THE SYSTEM SHALL guard both `event_log` appends and `recording.push` with `replay_depth == 0` — an anchor whose definition is encountered *while replaying* another anchor (a nested anchor, e.g. `&i` inside `&o`) is never (re-)recorded. Without this guard, a nested anchor's `RecordingFrame` captures indices into the wrong pass and stores garbage ranges | must |

### Mechanism 2 — Entry-Replay (`- *tpl`; `include: *tpl`)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-004 | WHEN `Event::Alias(id)` is encountered AND `id` is present in `container_anchors` THE SYSTEM SHALL replay that anchor's recorded slice through the **normal dispatch path** — `replay_depth += 1` → `push_container(FrameKind::Mapping)` → for each `(event, marker)` in the slice, `self.on_event(event, marker)` → `pop_container()` → `replay_depth -= 1` — never through a parallel/ad-hoc interpreter. `push_container` computes the replayed frame's role from the *live* stack top at the alias site, so a replayed mapping is interpreted exactly as a literal `MappingStart` at that same position would be. This is the complete answer to the guard-context-bypass risk class #909's rejected design fell into (verified distinct: `crates/deps-dart/src/parser.rs`'s merged #910 precedent is guard-safe for the same reason) | must |
| FR-005 | THE SYSTEM SHALL extract the child-role computation used by `push_container` into `fn child_role(&self, kind: FrameKind) -> FrameRole`, consulted **before** replaying an anchor's slice, purely as a cost guard to skip replaying a subtree whose computed role is `FrameRole::Irrelevant` (e.g. a job-body anchor aliased somewhere never reachable from `include:`) — never as a correctness gate, since role is still recomputed for real by `push_container` on any subtree that is replayed | must |

### Mechanism 3 — Merge-Replay (`- <<: *tpl`; `- <<: [*a, *b]`)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-006 | THE SYSTEM SHALL treat `<<` as a merge key — producing `PendingKey::Merge` from `key_for(role, "<<")` — for **both plain and quoted** scalar text (`<<`, `"<<"`, `'<<'` all resolve to the merge key). Do **not** gate this on `TScalarStyle::Plain`; Ruby Psych merges a quoted `"<<"` (verified against 5.3.1), and gating on style would introduce a divergence from GitLab under P0 that does not exist today | must |
| FR-007 | THE SYSTEM SHALL introduce `FrameRole::MergeSequence` (child of `IncludeEntry` \| `MergeSource`, `PendingKey::Merge`, kind `Sequence` — i.e. `<<: [*a, *b]`) and `FrameRole::MergeSource` (child of `IncludeEntry` \| `MergeSource`, `PendingKey::Merge`, kind `Mapping`; **and** child of `MergeSequence`, any pending key, kind `Mapping`). The `MergeSource` arms reachable from another `MergeSource` are required for transitive merges (`.b: &b {<<: *a, ref: v2}` then `- <<: *b`) to resolve instead of degrading to `Irrelevant` | must |
| FR-008 | THE SYSTEM SHALL make `key_for` return `PendingKey::Merge` for a `<<` key encountered while the current frame's role is `MergeSource`, in addition to `IncludeEntry` — both roles already share the entry-field key table via `captures_entry_fields(role)` (`IncludeEntry \| MergeSource`) — which is what makes a merge nested inside a merged template resolve rather than degrade | must |
| FR-009 | THE SYSTEM SHALL replay a merged anchor (reached via `<<:`) as its own `MergeSource` (or `MergeSequence` member) frame — never by splicing its scalars directly into the live entry frame — accumulating its own `RawEntry` payload exactly as an `IncludeEntry` does | must |

### Mechanism 4 — Precedence (the fold)

| ID | Requirement | Priority |
|----|------------|----------|
| FR-010 | ON `pop_container` of a closed frame THE SYSTEM SHALL dispatch by the closed frame's role: `IncludeEntry` → push its payload to `entries` (unchanged from today); `MergeSource` \| `MergeSequence` → `fold_merged(&mut parent.payload, payload, mode)`, where `parent` is the **immediate** parent frame (exactly one hop, `debug_assert`ed, never searched — every frame already carries a `RawEntry` payload, including `MergeSequence`); anything else → discard (unchanged) | must |
| FR-011 | THE SYSTEM SHALL choose `fold_merged`'s `FoldMode` by the **closing frame's parent's role**, not by the closing frame's own role: parent role `MergeSequence` → `FoldMode::FillIfAbsent` (first-wins *within* one `<<: [*a, *b]` sequence only); parent role `IncludeEntry` or `MergeSource` → `FoldMode::Overwrite`. Live `Event::Scalar` capture (a real literal key in the entry) stays unconditional overwrite, unchanged from today. This is the corrected rule (see §9, S5) — stating fold mode by *parent role* rather than as a fixed `MergeSource → MergeSequence` edge is what makes it cover the transitive `MergeSource → MergeSource` case correctly | must |
| FR-012 | `FoldMode::Overwrite` SHALL write **only present values**: `if merged.field.is_some() { target.field = merged.field }`, never an unconditional assignment — a merged template with no `ref:` must not clear an existing `ref:` in the target. Merge unions keys and resolves only *conflicting* ones | must |
| FR-013 | Boolean provenance flags (`has_template`/`has_remote`/`has_local`, or equivalent) SHALL be combined with `\|=` under **both** fold modes — these track distinct keys that are never in conflict with `project`/`ref`/`component`, so there is no precedence question for them | must |
| FR-014 | THE SYSTEM SHALL verify the fold rule against the **10-row Psych acceptance table** below (verified against Ruby Psych 5.3.1, `YAML.safe_load(src, aliases: true)`) before this feature is considered correct. Each row is a required regression test | must |

**Psych acceptance table (the oracle, per P0):**

| # | Case | GitLab/Psych resolves to | Fold rule this spec requires |
|---|------|---------------------------|-------------------------------|
| 1 | own key AFTER `<<:` | v2 (own key) | `Overwrite` writes the entry's own live scalar last → v2 |
| 2 | own key BEFORE `<<:` | v1 (merged value) | live scalar writes first; `Overwrite` fold of the merge runs later and overwrites it → v1 |
| 3 | `<<: [*a, *b]` (both define the same key) | value from `*a` | `FillIfAbsent` inside `MergeSequence`: `*a` folds into empty slot, `*b` sees `Some`, skips |
| 4 | duplicate `<<:` keys in one mapping | value from the **second** `<<:` (`*b`) | two `Overwrite` folds directly into the entry, in document order → last (`*b`) wins |
| 5 | own key before AND after `<<:` | the AFTER value | same as row 1; the later live scalar is the final overwrite |
| 6 | inner anchor's own key BEFORE its own `<<:` | v1 (the inner anchor's merged value) | same as row 2, one level down: inner `MergeSource`'s `Overwrite` fold runs after its own live scalar |
| 7 | inner anchor's own key AFTER its own `<<:` | v2 (the inner anchor's own key) | same as row 1, one level down |
| 8 | entry's own key BEFORE `<<: [*a, *b]` | value from `*a` | the entry's live scalar is overwritten by the `MergeSequence`'s folded (first-wins) value, same mechanism as row 2 |
| 9 | 3-level merge chain, middle anchor's own key BEFORE its `<<:` | v1 (the middle anchor's merged value) | transitive case; `MergeSource → MergeSource` uses the same parent-role-determined `Overwrite`, proving the rule needs no role-pair special case |
| 10 | `<<: [*x, *y]`, both `*x` and `*y` merge further | value resolved from `*x`'s chain | `FillIfAbsent` at the outer sequence, `Overwrite` at each inner chain, composed with no additional rule |

### Mechanism 5 — Null/Absent Scalar Handling

| ID | Requirement | Priority |
|----|------------|----------|
| FR-015 | THE SYSTEM SHALL port `deps-dart`'s `is_plain_null` guard (`deps-dart/src/parser.rs`, `on_scalar`) into the `Event::Scalar` value-capture arm: a plain-styled scalar whose text is empty or null-like (`~`, `null`, `Null`, `NULL`) is treated as **absent**, i.e. **never written** to the target slot — it does not occupy the slot as `Some("")`. `fold_merged`'s own absence predicate stays the plain `Option::is_none()`; correctness comes from never letting a non-value occupy the slot in the first place, not from a special case inside the fold | must |
| FR-016 | An explicit null/empty scalar that overwrites an already-`Some` slot (i.e. it is the *target* of a later positional write, per FR-011's `Overwrite` mode or a later live scalar) SHALL be treated as a **positional write of absence** — it sets the slot to `None`, not "skip and leave the previous value." This is the P0-faithful behavior (approved as a direct consequence of P0, not a separate design choice): it keeps the uniform "last write in document order wins" law intact for null writes, matching Psych's `nil`, at the cost of one keystroke of less-helpful-but-honest output while a `ref:` is mid-typing after a `<<:` | must |

### Mechanism 6 — Range Provenance

| ID | Requirement | Priority |
|----|------------|----------|
| FR-017 | THE SYSTEM SHALL maintain `alias_site: Option<Marker>`, set when `replay_depth` transitions 0→1 and cleared on the way back to 0. Any field captured while a replay is active SHALL be built from that **outermost** alias marker (the live-document `Event::Alias` that started the chain), flagged as alias-derived, rather than from the anchor definition's own marker — a replayed scalar's `Marker` otherwise points at the template's own literal, which would collapse every alias site onto one identical range (the `HashMap<Range, String>` collision documented at `deps-core/src/osv/types.rs:851-856`). **The marker must be the outermost, not the innermost** (critic S1, 2026-09-14): for a transitive merge (`- <<: *b` where `.b: &b {<<: *a, ref: v2}`) a field arriving at `replay_depth == 2` would otherwise take `*a`'s marker *inside the `.b:` definition* — `locate_alias_span` finds a real `*` there and returns `Some`, so no range check rejects it and the record ships with a range pointing outside `include:`, reintroducing the very collision this requirement exists to prevent. An `Option` rather than a stack makes that error unrepresentable. Any test for a transitive-merge row (§3 row 9) MUST assert the resulting **range**, not only the resolved value — the value is identical either way | must |
| FR-018 | THE SYSTEM SHALL introduce a new shared helper `deps_core::lsp_helpers::alias_token_span(...)` (does not exist in `deps-core` or `deps-gitlab-ci` today) that computes an alias token's span as: start = `marker_byte_offset` of the alias marker; end = forward scan over yaml-rust2's actual anchor-name charset (every character except space, tab, `\n`, `\r`, NUL, `,`, `[`, `]`, `{`, `}` — not an identifier-charset guess), line-bounded, char-boundary-safe (`char_indices().take_while(...)`, never a byte-indexed slice), **including the leading `*`**. This promotes #912's inline locator into a shared helper both crates use, since #912 and #916 both need it. **SUPERSEDED by lead ruling B3 (2026-09-14) — do not implement.** The stated rationale no longer holds: #912 shipped this as `locate_alias_span` (`deps-gitlab-ci/src/parser.rs:440`) and `deps-dart` does not consume it (it uses `FieldValue::Unpositioned` instead), so promoting a one-consumer helper would be premature sharing. Keep it local; revisit if #909 lands a GitHub Actions consumer. See `.local/handoff/2026-09-14T14-31-46-architect.md` | superseded |
| FR-019 | A replayed `component:` field SHALL bypass `build_component_dependency`'s normal offset arithmetic (`name_end = raw_start + prefix.len()`, which assumes literal underlying text) and collapse **both** `name_range` and `version_range` onto the alias token span — the underlying text at an alias site is `*x` (2+ characters), not the component literal that arithmetic assumes | must |
| FR-020 | WHEN `alias_token_span` returns `None` (locator miss) THE SYSTEM SHALL degrade to a synthetic-range fallback (mirroring `deps-dart`'s `name_range_is_synthetic()`) rather than emitting a wrong range. `name_range_is_synthetic` is **not** overridden in `deps-gitlab-ci` today (trait default `false`, `deps-core/src/ecosystem.rs:410`) — this feature requires a new `impl` for this crate, not just calling an existing one. **SUPERSEDED by lead ruling B2 (2026-09-14) — do not implement.** A locator miss requires a non-`*` byte at a real `Event::Alias` marker, which is structurally unreachable; the shipped behavior is to drop the record (the `?` at `parser.rs:613`/`:722`), which already satisfies EC-017's actual requirement of never emitting a misleading range. Implementing it would cost a new `pub` field on a `#[non_exhaustive]` struct plus abandoning `deps_core::impl_dependency!` for a hand-written impl. Note for anyone reopening this: `name_range_is_synthetic() == true` *suppresses* hover (`lsp_helpers/hover.rs:88`) and diagnostics (`diagnostics.rs:664`), so it must never be set for alias-derived records generally — that would silently defeat US-001. See `.local/handoff/2026-09-14T14-31-46-architect.md` | superseded |
| FR-021 | Mixed provenance within one dependency record is expected and correct: e.g. in `- <<: *tpl` with a local `ref: v2`, `name_range` (from the merged `project:`) sits on `*tpl`'s alias token while `version_range` (from the local live scalar) sits on the real literal `v2` — the two ranges are independently alias-derived or not, per field | should |

### Mechanism 7 — Edit/Completion Withholding

| ID | Requirement | Priority |
|----|------------|----------|
| FR-022 | THE SYSTEM SHALL add a new field `version_from_alias: bool` to `GitlabCiDependency`, set `true` when the field(s) contributing to `version_range` were captured while `replay_depth > 0` at any point in their fold chain (i.e. the final value traces back through at least one alias, whether or not a later literal overwrote it — see FR-021: only the field whose *final* write was alias-derived carries the flag) | superseded |
| | **SUPERSEDED by lead ruling B1 (2026-09-14) — do not add a new field.** #912 shipped `GitlabCiDependency::is_alias_occurrence` with precisely these semantics already, scoped to the field backing `version_range` (`types.rs:183`, `parser.rs:621-644`) — which is verbatim FR-025 — and it already gates both call sites (`ecosystem.rs:97` and `:290-296`). Because a replayed field becomes `RawField::Alias` and `fold_merged` moves whole `Option<RawField>`s, provenance travels with the value and FR-022-FR-025 hold with zero new state. A second parallel flag would recreate the two-guards-that-drift shape issue #643's single-funnel invariant exists to prevent. **Read `version_from_alias` as `is_alias_occurrence` throughout this spec.** Add tests only. See `.local/handoff/2026-09-14T14-31-46-architect.md` | |
| FR-023 | THE SYSTEM SHALL gate `sha_pin_quickfix_kind` (`ecosystem.rs`) with a first arm `is_alias_occurrence == true` → return `None`, evaluated before any other match arm — **already shipped by #912 at `ecosystem.rs:97`** (ruling B1), so this requirement is satisfied by existing code and needs tests, not a new arm. This single predicate is the complete withholding gate for all three SHA-pin call sites (`build_sha_pin_action`, `build_dynamic_component_pin_action`, `bulk_sha_pin_text_edit_for` reached via `collect_pin_all_to_sha_edits`) and is also what `mutable_ref_pin_diagnostics` reads for its `has_quickfix` suffix decision — mirrors #912's FR-010 pattern exactly, preserving issue #643's single-funnel invariant | must |
| FR-024 | THE SYSTEM SHALL gate `complete_version` **independently** — it is not reached through `sha_pin_quickfix_kind` — returning `Completions::default()` when the resolved dependency's `is_alias_occurrence == true`, rather than proceeding to `complete_versions_generic_from` — **already shipped by #912 at `ecosystem.rs:290-296`** (ruling B1); tests only | must |
| FR-025 | This gate SHALL be a **refinement over #912's whole-dependency `is_alias_occurrence`**: in `- <<: *tpl` with a local `ref:`, the local `ref:` is a real editable literal (its final write is a live scalar, not alias-derived) and **keeps** its quickfix and completion, even though the same entry also has an alias-derived `project:`. Withholding is per the field that backs `version_range`/`name_range`, not per whole dependency | must |

### Mechanism 8 — Replay Budget and Safe Abandonment

| ID | Requirement | Priority |
|----|------------|----------|
| FR-026 | THE SYSTEM SHALL bound total dispatched replayed events with a single **stream-scoped** `MAX_REPLAYED_EVENTS = 20_000` counter on the receiver, decremented once per event **inside** the replay loop and checked **before** each `self.on_event(...)` call — shared across all replays in the whole parse (nested/repeated replays decrement the same counter), so a fanout-driven exponential blow-up is capped flat rather than per-replay. **Stream-scoped, not per-document** (critic M3, 2026-09-14): this crate genuinely parses multi-document files (the `spec:` header form), and a per-document reset would let a 1,000-document stream spend 20,000 events each. The counter is therefore never reset at `Event::DocumentStart`/`DocumentEnd` — only `stack` and `recording` are per-document. `20_000` sits ~9x above the ~2,200-event legitimate worst case (a 100-entry `include:` section where every entry merges a 10-key template) and well below the ~131,070-event bomb a 400-byte adversarial file can dispatch (critic's measured worst case) | must |
| FR-027 | THE SYSTEM SHALL capture `depth_before = self.stack.depth()` **before** `push_container` on **every** replay, unconditionally — not only on the replay that ends up tripping the budget. ON budget exhaustion THE SYSTEM SHALL then: (1) unwind with **raw `self.stack.pop()`** — never `pop_container`, which would fold a half-built payload into the parent — repeated until `self.stack.depth() == depth_before`; (2) set `replay_disabled = true`; (3) return, and **not** call `consume_value()` on this abandon path (the unwind's final `pop()` already performs that transition; a second one would desync the parent in the opposite direction) | must |
| FR-028 | THE SYSTEM SHALL assert `debug_assert_eq!(self.stack.depth(), depth_before)` after **every** replay, successful or abandoned — this is the acceptance property that a tripped budget can only ever degrade to today's zero-record path for the alias it interrupts, and must never corrupt the parse state for any other, unrelated entry in the same document | must |
| FR-029 | ONCE `replay_disabled` is set THE SYSTEM SHALL route every subsequent `Event::Alias` **for the rest of the stream** through today's `consume_value()` path (no further replay attempts), so both the successful and abandoned paths converge on identical, well-defined parent state. Stream-scoped, matching FR-026's counter (critic M3, 2026-09-14): a bomb in document 1 therefore also disables this feature's detection for document 2, the deliberate safe-side trade | must |

### Mechanism 9 — Non-Regression of #912's `? *k` Fix

| ID | Requirement | Priority |
|----|------------|----------|
| FR-030 | THE SYSTEM SHALL preserve #912's key-position `Event::Alias` transition (its FR-003/FR-005: the key-position transition fires regardless of table hit or miss) when adding this feature's container-anchor handling to the same arm — the new handler branches on `scalar_position()`, adding a value-position container-anchor case without removing or altering the existing key-position case. A `? *k` regression test (both scalar-hit and container-miss variants, from #912's own suite) SHALL be re-run as part of this feature's suite, not only #912's, since both features touch the same code | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness/oracle | Every precedence-sensitive requirement's correctness is defined by the Psych acceptance table (§3, FR-006/FR-014), not by prose reasoning about the YAML 1.1 merge-key spec. A future change to this feature's fold logic MUST be checked against all 10 rows before merging |
| NFR-002 | Resource bounds (correct quantity) | The bound that matters is **dispatched (replayed) events**, not source-text length or replay depth — both of those were independently measured to undercount the actual cost by 2-3 orders of magnitude for a fanout-driven bomb. `MAX_REPLAYED_EVENTS` (FR-026) is the only primary bound; a depth cap may exist only as a cheap secondary guard that trips before the event budget on pathological nesting, never as the primary bound |
| NFR-003 | Resource bounds (behavior-preservation guarantee) | Exceeding `MAX_REPLAYED_EVENTS` can only ever withhold *this feature's* detection for the alias that trips it — it must never regress, corrupt, or drop a dependency record for any other entry in the same document (FR-027/FR-028's unwind is what makes this true; a naive "stop the loop and call `pop_container` once" implementation does **not** satisfy this NFR, verified to drop an entire document's dependencies) |
| NFR-004 | Correctness/safety | No code path may allow an edit-producing action or a version-completion item to be produced for any field whose final write was alias-derived (`is_alias_occurrence == true` — flag renamed per ruling B1). This must hold independently for both `sha_pin_quickfix_kind`'s three funneled call sites (FR-023) and `complete_version` (FR-024) |
| NFR-005 | Recording invariant | `replay_depth == 0` is load-bearing for both `event_log` appends and `recording.push` (FR-003) — this must remain a single, shared guard, not duplicated or reimplemented per call site, so it cannot drift out of sync |
| NFR-006 | Structural (not conventional) scope enforcement | The exclusion of sequence-shaped container anchors (#917) is enforced by recording `FrameKind::Mapping` only (FR-002) — a future change MUST NOT introduce an alternate runtime check for this exclusion; if sequence-shaped support is ever wanted, it must change FR-002 itself, in a new spec |
| NFR-007 | Compatibility | This feature must not change the record count, position, or precedence result for any `.gitlab-ci.yml` document already covered by #912's scalar-alias fix or by today's literal-entry parsing — every existing passing fixture with no mapping-anchor-in-`include:` shape stays byte-for-byte unaffected |
| NFR-008 | Reproducibility of the oracle | The Psych version used to build the acceptance table (5.3.1) and the exact verification command (`YAML.safe_load(src, aliases: true)`) MUST be recorded alongside the table (§3) so a future GitLab/Psych version bump can be checked for a behavior drift, rather than silently invalidating this feature's correctness claim |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `event_log` | Flat, append-only, per-parse `Vec<(Event, Marker)>`, guarded by `replay_depth == 0` | Shared across all recorded anchors in one document |
| `RecordingFrame` | One open anchor recording, mirrors `deps-dart`'s shipped type | `{anchor_id: usize, kind: FrameKind, depth: usize, start: usize}` |
| `container_anchors` | Finalized recordings, keyed by anchor id | `HashMap<usize, Range<usize>>` — index range into `event_log`; populated **only** for `FrameKind::Mapping` (FR-002) |
| `FrameRole::MergeSequence` | New role for the `Sequence` value of a `<<:` key (`<<: [*a, *b]`) | Carries a `RawEntry` payload like every frame; fold mode into its own parent is always `FillIfAbsent` |
| `FrameRole::MergeSource` | New role for a replayed anchor reached via `<<:` (single or sequence member), also reachable from another `MergeSource` (transitive merge) | Carries a `RawEntry` payload; fold mode into its parent depends on the **parent's** role (FR-011) |
| `PendingKey::Merge` | New pending-key variant, produced by `key_for(role, "<<")` for `IncludeEntry` and `MergeSource` roles, matched on text only (not scalar style — FR-006) | — |
| `FoldMode` | `{Overwrite, FillIfAbsent}` — selects `fold_merged`'s behavior, chosen by the **parent** of the frame being folded (FR-011) | — |
| `fold_merged(&mut RawEntry, RawEntry, FoldMode)` | The entire precedence algorithm, unit-testable in isolation against the Psych table | `Overwrite`: writes only present merged values (FR-012); `FillIfAbsent`: writes only into empty slots. Boolean flags always `\|=` (FR-013) |
| `replay_depth` | Counter, incremented/decremented around each entry- or merge-replay | Guards recording (FR-003) and determines whether a captured field is alias-derived (FR-022) |
| `alias_site: Option<Marker>` | The outermost active replay's alias marker — set on the `replay_depth` 0→1 transition, cleared on the way back (FR-017) | The single marker used for range provenance; an `Option` rather than a stack so an inner marker is unrepresentable (critic S1) |
| `MAX_REPLAYED_EVENTS` | `20_000`, stream-scoped budget (FR-026) | Decremented per dispatched event inside every replay loop, shared across nested replays and across documents |
| `replay_disabled: bool` | Set on budget exhaustion (FR-027); once set, no further replay is attempted for the rest of the stream (FR-029) | — |
| `depth_before: usize` | Captured before each replay's `push_container`, used for the raw-`pop()` unwind on abandonment (FR-027) and the `debug_assert_eq!` check (FR-028) | — |
| `locate_alias_span` | #912's existing local helper (`deps-gitlab-ci/src/parser.rs:440`); the FR-018 promotion into `deps-core` is superseded by ruling B3 | Computes an alias token's byte-range span from its `Marker`, including the leading `*` |
| `GitlabCiDependency::is_alias_occurrence: bool` | #912's existing field — reused, not duplicated, per ruling B1 (FR-022 superseded). Becomes `true` for a replayed field because the capture builds a `RawField::Alias` | Gates FR-023/FR-024; already scoped to the field backing `version_range`, which is FR-025 |

## 6. Edge Cases and Error Handling

| ID | Scenario | Expected Behavior |
|----|----------|--------------------|
| EC-001 | `- *tpl` (plain alias to a mapping anchor as a sequence item under `include:`) | In scope; one dependency record, fields from the template, ranges on the alias token (FR-004, FR-017-FR-020) |
| EC-002 | `include: *tpl` (the entire `include:` value is a single aliased mapping, not a sequence) | In scope; child-role table's `Root`/`PendingKey::Include` → `IncludeEntry` arm covers this distinctly from EC-001's `Sequence` parent arm |
| EC-003 | `- <<: *tpl` (single merge key) | In scope; `MergeSource` replay, `Overwrite` fold into the entry (FR-007-FR-011) |
| EC-004 | `- <<: [*a, *b]` (merge-key sequence) | In scope; `MergeSequence` replay, `FillIfAbsent` fold within the sequence, then one `Overwrite`/`FillIfAbsent` fold (by the sequence's own parent role) into the entry — first-wins for a key defined by both `*a` and `*b`, matching Psych table row 3 |
| EC-005 | Own key positioned AFTER `<<:` | Psych table row 1: own key wins (v2) |
| EC-006 | Own key positioned BEFORE `<<:` | Psych table row 2: the merged value wins (v1) — counter-intuitive relative to a naive "own keys always win" reading, but this is GitLab's actual behavior (P0) and MUST be the test's expected value, not the intuitive one |
| EC-007 | Duplicate `<<:` keys in one mapping | Psych table row 4: last `<<:` wins (its value overwrites the first's) — this is **not** the same result as `<<: [*a, *b]` (EC-004), and both must be tested distinctly |
| EC-008 | 3-level merge chain with the middle anchor's own key BEFORE its own `<<:` | Psych table row 9: transitive case, resolves to the middle anchor's merged (not own) value — the acceptance fixture for the `MergeSource → MergeSource` fold arm (FR-007's transitive requirement) |
| EC-009 | Quoted merge key: `"<<": *tpl` or `'<<': *tpl` | Merges, same as plain `<<:` (FR-006) — a regression test asserting it does **not** merge would be asserting the wrong (PyYAML, not Psych) behavior |
| EC-010 | `<<: *seq_anchor` or `<<: *scalar_anchor` (merge key aliasing a non-mapping anchor) | Resolves to nothing under Psych — becomes a literal, inert `<<` key. Degrading to "no merge applied" here is **correct-by-verification**, not merely a safe fallback |
| EC-011 | `? *k` in explicit key position, where `*k` resolves to a scalar (table hit, #912) or a container (table miss, this feature) | Must not regress: the following real `ref:`/`project:` value in the same entry is still captured correctly in both cases (FR-030) |
| EC-012 | An adversarial document engineered to exceed `MAX_REPLAYED_EVENTS` via nested/fanned-out merges | The alias that trips the budget degrades to zero records for itself; every other entry in the same document — including ones that never touch an anchor — is parsed identically to a document with `replay_disabled` compiled out (FR-027/FR-028's acceptance property) |
| EC-013 | An anchor defined *during* a replay (nested anchor definition inside an already-anchored mapping, e.g. `&i` nested inside `&o`) | Not (re-)recorded — `replay_depth == 0` guard (FR-003); this is a load-bearing, easy-to-omit invariant, not an incidental detail |
| EC-014 | Two separate `- *tpl` items aliasing the same anchor | Two distinct dependency records with two distinct `version_range`s, each anchored at its own alias site's own `Marker` — never collapsed onto one range (FR-017) |
| EC-015 | `- <<: *tpl` with a local `ref:` also present in the same entry | Mixed provenance is correct: `name_range` (from the merged `project:`) may be alias-derived while `version_range` (from the local literal `ref:`) is not, or vice versa — `is_alias_occurrence` reflects only the field it gates (FR-021, FR-025) |
| EC-016 | A replayed mapping anchor supplies `component:` | Both `name_range` and `version_range` collapse onto the alias token span; `build_component_dependency`'s literal-text offset arithmetic is bypassed entirely for this site (FR-019) |
| EC-017 | `locate_alias_span` returns `None` (locator miss, e.g. a marker at a document boundary) | The dependency record is **dropped** — `build_project_dependency`/`build_component_dependency`'s existing `?` on the span already does this, and it satisfies the requirement that matters: never a wrong, misleading range. The synthetic-range fallback FR-020 originally specified is superseded by lead ruling B2 (2026-09-14) as unreachable-in-practice; see that row |
| EC-018 | `&e1` anchored on a *live* `include:` entry, then a separate `- *e1` elsewhere | **2 dependency records is correct** — GitLab genuinely includes the template twice. Not a duplicate to suppress (resolved: architect's original OQ-4, confirmed by direct probe) |
| EC-019 | An explicit null/empty scalar (e.g. `ref:` with nothing after it) positioned AFTER a `<<:` that supplied a value for the same key | The slot becomes `None` (positional write of absence, FR-016), not "keep the merged value" — one keystroke of less-helpful-but-honest output while `ref:` is mid-typing, a deliberate, P0-faithful choice, not a bug |
| EC-020 | `include: *incs` where `*incs` is a **sequence** anchor | Out of scope by construction (#917): `container_anchors` has no entry for a sequence-kind anchor id (FR-002), so this falls through to today's zero-record path, unaffected by this feature |
| EC-021 | An anchor whose recorded slice, if replayed, would land entirely in `FrameRole::Irrelevant` (e.g. a job-body template anchor aliased somewhere reachable but not under `include:`) | `child_role` cost guard (FR-005) skips replaying it — same zero-record result as today, at lower cost, not a correctness-relevant distinction |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | US-001/US-002 repro: `- *tpl`, `include: *tpl`, `- <<: *tpl`, `- <<: [*a, *b]` each produce a correct dependency record | 1 record per entry, fields matching what Psych would resolve, hover/diagnostics/code lens/inlay hints all functional at the alias/merge site |
| SC-002 | Psych acceptance table (§3) | All 10 rows pass as dedicated regression tests, using the exact expected values in the table (not the "intuitive" YAML-1.1-spec values, several of which are wrong per P0) |
| SC-003 | Budget/abandonment safety (FR-026-FR-029) | A document engineered to trip `MAX_REPLAYED_EVENTS` produces correct records for every entry that does not touch the tripping alias — verified by a dedicated test with ≥1 anchor-free entry alongside the pathological one, asserting the anchor-free entry's record is unaffected |
| SC-004 | #917 non-regression | `include: *incs` (sequence-shaped) continues to produce 0 records, verified by a dedicated regression test, not only by code inspection of FR-002 |
| SC-005 | #912 `? *k` non-regression (FR-030) | Both the scalar-hit and container-miss `? *k` variants from #912's suite pass unmodified under this feature's code |
| SC-006 | Edit/completion withholding (US-004) | 0 edits via `sha_pin_quickfix_kind`'s three funneled call sites and 0 completion items via `complete_version` for every field with `is_alias_occurrence == true` (flag renamed per ruling B1); a mixed-provenance entry (EC-015) keeps its quickfix/completion for the field that is *not* alias-derived |
| SC-007 | NFR-007 compatibility | 0 changes to dependency count, position, or precedence result for every existing passing test fixture with no mapping-anchor-in-`include:` shape |

## 8. Agent Boundaries

### Always (without asking)
- Confirm #912's implementation PR has merged into `main` before starting any implementation work on
  this feature (§2) — if it has not, stop and report back rather than proceeding on the unmerged spec
  alone
- Implement recording (FR-001-FR-003), entry-replay (FR-004-FR-005), merge-replay (FR-006-FR-009),
  the fold (FR-010-FR-014), null/absent handling (FR-015-FR-016), range provenance (FR-017-FR-021),
  edit/completion withholding (FR-022-FR-025), and the replay budget (FR-026-FR-029) inside
  `crates/deps-gitlab-ci/src/parser.rs`, `crates/deps-gitlab-ci/src/types.rs`, and
  `crates/deps-gitlab-ci/src/ecosystem.rs`
- ~~Add the new `alias_token_span` helper (FR-018) to `crates/deps-core/src/lsp_helpers`~~ —
  withdrawn by ruling B3; reuse #912's local `locate_alias_span` instead. The one `deps-core` change
  that *is* wanted: promote `is_plain_null`/`is_null_tag` out of `deps-dart/src/parser.rs:98-122`,
  since FR-015 makes this crate their second consumer
- Write all 10 Psych-table rows (§3) as dedicated regression tests, using the table's stated expected
  values, not a naive YAML-1.1 reading
- Write the FR-027/FR-028 abandonment-safety test with an anchor-free entry alongside the pathological
  one (SC-003) — a test that only checks the pathological entry itself is insufficient
- Add a regression test for every FR, EC, and SC in this spec before merging
- Run the full check suite (`fmt`, `clippy -D warnings`, `nextest`, rustdoc gate) per
  `.claude/rules/branching.md` before any PR

### Ask First
- Any change to `MAX_REPLAYED_EVENTS` (20,000) — FR-026's rationale (~9x headroom over the legitimate
  worst case, far below the measured bomb) establishes this as deliberately chosen, not a placeholder
- Extracting recording/replay machinery into a fully shared `deps-core` module (FR-018's
  `alias_token_span` sharing is withdrawn by ruling B3, so this boundary now covers everything
  beyond the `is_plain_null` promotion named above) — this crate's `MergeSource`/
  `MergeSequence` roles are GitLab-CI-specific (merge-key semantics); premature sharing risks forcing
  an ill-fitting abstraction on `deps-dart`'s simpler (no-merge) replay
- Re-opening any of §9's resolved S1-S5/C1/M1-M4 findings without new empirical evidence against
  Psych — if new evidence emerges, bring it back through the architect/critic cycle, not directly

### Never
- Implement any part of this feature before #912's implementation has merged (§2) — the two rewrite
  the same `Event::Alias` arm and this feature is written as an extension, not a parallel path
- Gate `PendingKey::Merge` on scalar style (`TScalarStyle::Plain`) — this was proposed (R5), verified
  wrong against real Psych (M1 retraction, §9), and would introduce a divergence from GitLab that
  does not exist today
- Implement precedence as "own keys always win regardless of position" (the YAML 1.1 spec's abstract
  rule) — this produced the wrong answer in 5 of 10 Psych-verified cases (S5, §9) and is exactly the
  "silently wrong version" failure class this feature exists to prevent
- Abandon a replay by simply breaking the dispatch loop and calling `pop_container()` once — this
  drops every dependency in the document, not just the interrupted one (C1, §9); the raw-`pop()`
  unwind to `depth_before` (FR-027) is mandatory
- Call `consume_value()` on the abandonment path — the unwind's final raw `pop()` already performs
  that transition; a second call desyncs the parent frame (FR-027)
- Treat `<<: *seq_anchor` or duplicate `<<:` keys as either a bug to fix beyond FR-011's uniform rule
  or a case needing a special-purpose "withhold edits" flag — both fall out correctly from the
  corrected fold with zero additional state (§9, M2/M4)
- Attempt sequence-shaped container-anchor support (`include: *incs`, #917) as part of this feature —
  separate issue, won't-fix-by-design (Non-Goal above)

## 9. Design Decisions

Resolved across four adversarial architect/critic rounds (2026-09-13; final verdict: the fold and
abandonment logic both required a real correction, not a minor one — see C1/S5 below). No open
`[NEEDS CLARIFICATION]` items remain; the one item still marked "open" in the design handoffs (the
S2 residual — positional null-write vs. a friendlier merged-value-preserving alternative) was
resolved by the team lead as a direct, deliberate consequence of P0 and is recorded here as FR-016,
not as an open question.

- **P0 (the contract) is stated first because every precedence decision below derives from it.**
  deps-lsp's job is to predict what GitLab will actually resolve, not to implement the YAML 1.1
  merge-key spec faithfully in the abstract. See §0.
- **Replay-through-normal-dispatch (mechanism 2/3) is the guard-context-bypass-safe answer, verified
  not to be #909's rejected antipattern.** Every replayed event goes through `on_event`/
  `push_container`; role is recomputed from the *live* stack, never carried over from the anchor's
  definition site. Contrast the two rejected alternatives below.
- **S1 (round-1 critic finding) — the original design's fold-target bound and its own transitive-merge
  case were mutually exclusive.** A `MergeSource` reached from another `MergeSource` (transitive
  merge) needs the same "0-or-1 hops" property as every other case; the fix was completing the
  `child_role` table with the missing `MergeSource → MergeSource` arm (FR-007) and stating the fold
  target uniformly as "the immediate parent frame's payload, always exactly one hop" (FR-010) — no
  role-dependent search, ever.
- **S2 (round-1) — an empty scalar is `Some("")`, not `None`, under `Option::is_none()`-based
  absence.** Fixed by porting `deps-dart`'s `is_plain_null` guard (FR-015): a plain-styled empty/
  null-like scalar never occupies the slot as a value in the first place. This also fixes a
  pre-existing, `#916`-independent bug (a zero-width, out-of-entry `version_range` for an empty
  `ref:`) as a side effect — must ship with its own regression test and CHANGELOG line, since it is a
  user-visible behavior change on every keystroke through that mid-typing state.
- **S3 (round-1) — neither of the original two bounds (`MAX_RECORDED_ANCHOR_EVENTS`,
  `MAX_MERGE_REPLAY_DEPTH`) bounded the actual threat.** Measured: a 400-byte adversarial file
  dispatches 131,070 events via fanout, while depth stays shallow (7) and `event_log` length stays
  small (~130) — neither original constant ever trips. Replaced with one stream-scoped
  `MAX_REPLAYED_EVENTS` budget decremented per dispatched event (FR-026), which caps the actual
  quantity that matters regardless of fanout or nesting shape.
- **S4 (round-1) — `? *k` already silently drops the whole `include:` block today, in the exact arm
  this feature also rewrites.** Not re-fixed here (that is #912's fix); carried forward as a
  non-regression requirement (FR-030) since both issues touch the same code and could otherwise
  reintroduce or half-fix it.
- **M1 (round-1) proposed, then retracted (round 2) — gating the merge key on plain style.** Verified
  wrong against real Ruby Psych 5.3.1: a quoted `"<<"` merges. The retraction is recorded because the
  round-1 recommendation would have shipped a real divergence from GitLab if not caught by testing the
  actual loader rather than reasoning from the spec plus a different implementation (PyYAML).
- **M2 (round-1) — `<<: *seq_anchor` is uncovered but degrades safely — upgraded (round 2) to
  correct-by-verification.** Psych does not merge a non-mapping-anchor alias under `<<:` either; it
  becomes an inert literal key. No special handling needed beyond the recording-is-mappings-only rule
  already in place for other reasons (FR-002).
- **M3 (round-1) — the `replay_depth == 0` recording guard is load-bearing and was originally
  unstated.** Now a first-class requirement (FR-003) with its own fixture (EC-013).
- **M4 (round-1) — duplicate `<<:` and `<<: [*a, *b]` were claimed equivalent; false, then dissolved.**
  Round-1 architect's claim that both cases could share one "first-wins for free" outcome was
  empirically wrong (Psych gives FROM_B for duplicate `<<:`, FROM_A for the sequence form — Psych
  table rows 3 and 4). Round-2's corrected fold (S5 below) produces both correct outcomes with **zero**
  additional state — no flag, no special case — once fold mode is properly parent-role-determined.
- **C1 (round-2, critical) — budget abandonment, as first specified, silently destroyed every
  dependency in the document, not just the interrupted one.** A recorded slice is balanced; stopping
  mid-slice dispatches an unbalanced prefix, leaving N frames open, and a single subsequent
  `pop_container()` call closes the *wrong* frame, permanently desyncing the stack for the rest of the
  document. Measured: 0 dependencies instead of 5 in a fixture where four of the five entries never
  touched an anchor at all. Fixed by the `depth_before`-capture-then-raw-`pop()`-unwind mechanism
  (FR-027), verified across a depth-2-to-6 × budget-1-to-79 sweep with zero corruption.
- **S5 (round-2, significant) — the fold's precedence rule, as first specified ("own keys always
  win"), diverged from GitLab/Psych in 5 of 10 verified cases.** This is the central correction of
  this feature's design history: Psych applies `<<` **positionally** (`revive_hash` treats it like any
  other key, applied in document order), not as a position-independent "explicit keys win" rule. The
  corrected rule — fold mode determined by the **parent** frame's role, `FillIfAbsent` only inside a
  `MergeSequence`, `Overwrite` everywhere else — was independently re-verified against all 10 rows and
  is what §3's acceptance table encodes (FR-006, FR-011).
- **Alternatives rejected:**
  - *Parallel-interpreter event replay* (#909's rejected antipattern) — re-derives guard state outside
    the structural machinery. Every replayed event in this design instead goes through
    `on_event`/`push_container` (FR-004).
  - *Splice merged scalars directly into the live frame* — requires an unbounded stack search for the
    `<<: [*a, *b]` merge target (would fire wrongly for an alias nested under an unrelated key like
    `inputs:`) and smears precedence logic across per-scalar writes instead of one testable function.
  - *Synthetic ranges only, no span locator* — cheaper, but no hover/diagnostic/inlay at the alias
    site at all; kept only as the fallback on an actual locator miss (FR-020), not as the primary
    design.
  - *Content-based record filter* (record only anchored mappings whose keys look like entry keys) —
    would re-interpret keys outside the guard machinery and break `<<:` chains; superseded by the
    replay-budget fix (FR-026), which solves the cost problem this alternative targeted without
    reinterpreting anything.
  - *Two-pass parse* (collect aliased ids first, then record only those) — doubles parse cost on every
    document, including anchor-free ones; rejected on cost.
  - *AST route via `YamlLoader`* — loses all position info needed for ranges, and is not confirmed to
    resolve `<<:` merge keys at all; rejected, not pursued further.

### Follow-Up Issues

None filed by this spec. #916's remaining known-deferred items — sequence-shaped container anchors
(#917), `!reference` support (#918), and the cross-ecosystem completion literal-span guard (#919) —
were already filed under #912's spec (`specs/056-.../spec.md`) and are unaffected by this feature;
this spec's scope decisions (Non-Goal, Out of Scope above) reaffirm rather than reopen them.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- [[056-gitlab-ci-yaml-scalar-anchor-alias/spec]] — #912, this feature's hard prerequisite; filed
  this feature as its own Follow-Up #1, and this spec's range-provenance/withholding mechanisms
  (FR-017-FR-025) are direct extensions of #912's FR-006-FR-012
- GitHub `#916` — this feature's source issue
- GitHub `#912` — hard prerequisite; must be implemented (not only spec'd) before this feature begins
- GitHub `#917` — sequence-shaped container-anchor sibling, won't-fix-by-design (this spec's Non-Goal)
- GitHub `#918` — `!reference` tag support, out of scope
- GitHub `#919` — cross-ecosystem `detect_completion_context` literal-span guard, out of scope
- GitHub `#909` — the GitHub Actions sibling gap and the source of the guard-context-bypass
  antipattern this feature's replay-through-dispatch design (FR-004) is verified not to repeat
- GitHub `#910` — `deps-dart`'s merged `RecordingFrame`/replay-through-dispatch precedent, lifted and
  extended (with merge-key precedence and a stream-scoped budget added) for this feature
- GitHub `#643` — introduced `sha_pin_quickfix_kind` as the single funnel this feature's FR-023
  extends with a new first arm, preserving the message/dispatch anti-drift invariant
- `crates/deps-gitlab-ci/src/parser.rs` — `key_for`, `push_container`, the `Event::Alias` arm this
  feature extends (shared with #912)
- `crates/deps-gitlab-ci/src/types.rs` — `GitlabCiDependency`, whose existing `is_alias_occurrence`
  is reused rather than joined by a second flag (ruling B1)
- `crates/deps-gitlab-ci/src/ecosystem.rs` — `sha_pin_quickfix_kind`, `mutable_ref_pin_diagnostics`,
  `complete_version`
- `crates/deps-core/src/yaml_walk.rs` — `FrameStack`, driven **unchanged**: `pop`, `depth`, and
  `is_complex_key_position` are already `pub` and suffice. `FrameRole::MergeSequence`/`MergeSource`
  and `PendingKey::Merge` are `deps-gitlab-ci`'s own `R`/`K` generic parameters, not `deps-core`
  types — an earlier draft of this line wrongly implied otherwise
- `crates/deps-core/src/lsp_helpers` — target module for the `is_plain_null`/`is_null_tag`
  promotion (FR-015); the FR-018 `alias_token_span` promotion is withdrawn (ruling B3)
- `crates/deps-dart/src/parser.rs` — `RecordingFrame`, `on_alias`, `is_plain_null` — the shipped #910
  precedent this feature's recording and null-guard mechanisms are lifted from
- `crates/deps-core/src/osv/types.rs` — the `HashMap<Range, String>` identity constraint that makes
  range-provenance correctness (FR-017) load-bearing, not cosmetic

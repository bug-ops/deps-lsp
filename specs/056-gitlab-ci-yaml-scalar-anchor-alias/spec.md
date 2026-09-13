---
aliases:
  - GitLab CI scalar YAML anchor alias detection
  - include: value not recognized when aliased
tags:
  - sdd
  - spec
  - bug
  - deps-gitlab-ci
  - yaml
created: 2026-09-13
status: draft
related:
  - "[[constitution]]"
---

# Feature: Recognize a Scalar YAML Anchor Used Directly as an `include:` Value When Aliased

> [!info] Metadata
> **Author**: architect + critic (two adversarial rounds, 2026-09-13), recorded by sdd
> **Branch**: `fix/912-gitlab-ci-yaml-anchor-alias` (this worktree)
> **Related issues**: #912 (this fix), #909 (`deps-github-actions`'s equivalent gap, unmerged,
> spec-only), #913 (aggregate-annotation research idea for the container case, GitHub Actions side)

## 1. Overview

### Problem Statement

Issue #912's own title ("job `uses:`/`image:`/`script:` values ignore YAML anchors") and its
"likely higher impact than #909" claim are both **false** and are corrected here, the same way
#909's spec corrected its own issue (see `specs/055-gha-yaml-scalar-anchor-alias/spec.md` on branch
`fix/909-gha-yaml-anchor-alias`, not yet merged). `GitlabCiReceiver` extracts dependencies from
**only** the top-level `include:` subtree — capture is gated on `frame.role ==
FrameRole::IncludeEntry` (`crates/deps-gitlab-ci/src/parser.rs:233`), and
`test_image_and_services_never_parsed` pins that `image:`/`services:`/job-body keys land in
`FrameRole::Irrelevant` and are never captured. There is no `uses:`, no `image:`, no `script:`, no
job-body dependency extraction in this crate at all. GitLab's own documented anchor usage
(`script:`/`before_script:` block scalars, whole job templates reused via `<<:`) therefore does not
overlap this crate's extraction surface **anywhere**.

The only reachable gap is an anchor **defined and aliased inside the same file's top-level
`include:` subtree** — a same-file scalar alias for one of `ref:`, `project:`, or `component:`:

```yaml
.pin: &pin v1.2.3

include:
  - project: group/project-a
    ref: *pin
  - project: group/project-b
    ref: *pin
```

The first `include:` entry's `ref: *pin` is not detected as a dependency occurrence at all: no
hover, no diagnostic, no code action, no inlay hint, no completion at that line. GitLab documents
that anchors are file-scoped (*"You can't use YAML anchors across multiple files when using the
`include` keyword. Anchors are only valid in the file they were defined in"*) and does not itself
demonstrate this exact same-file `include:`-alias pattern in its docs, but it is valid GitLab
config, reachable by same-file YAML alias expansion (which happens before GitLab's own config
processor runs), and it is real: one `ref:` shared by several project templates without repeating
the literal version string.

A first-cut implementation shape (mirror #909's original design verbatim) was rejected across two
adversarial critic rounds for four defects, all structural:

- **S1**: the correct withholding gate is a single predicate in `sha_pin_quickfix_kind`
  (`ecosystem.rs:89`), not three independently-gated call sites — gating the three edit sites
  separately re-opens exactly the message/dispatch drift issue #643 was written to prevent.
- **S2**: completion is a fourth, previously-safe write sink that this fix newly opens if left
  unguarded — `detect_completion_context` has no literal-span guard, so an alias site would offer
  cursor-splicing version completions once `version_range` becomes `Some`.
- **S3**: the naive fix ("route a table hit through the same scalar path a literal takes")
  correctly fixes the pre-existing `? *k` key-position desync **only on a table hit**, leaving it
  broken for a table-miss (container) alias in key position.
- **S4**: an unbounded value table would clone every anchored scalar in the document, including
  `script:`/`before_script:` block scalars — GitLab's actual documented anchor use, which can never
  be aliased inside `include:` — for a feature that only ever needs a handful of short strings.

### Goal

A scalar YAML anchor used as a `ref:`, `project:`, or `component:` value inside GitLab CI's
`include:` subtree, when aliased (`ref: *pin`) elsewhere in the same file's `include:` subtree,
produces exactly one additional dependency record — positioned at the **alias token itself**, not
the anchor's definition — with hover, diagnostics, and inlay hints all working at that alias site
the same as they would for a literal value, while never allowing any SHA-pin code action, bulk-edit
lens, or version-completion write path to touch an alias token (an alias is not an editable
literal; `ref: *pin` must never become `ref: <sha>` or offer a version to insert at the cursor).

### Non-Goal: Container-Anchor Sites Receive No New Annotation

**This is a deliberate scope decision, not an oversight — do not re-litigate it without re-running
the verification below.**

Unlike #909's GitHub Actions case, this crate's `uses:`-equivalent detection is **not**
path-agnostic — it is gated to `FrameRole::IncludeEntry`. So an anchor defined **outside**
`include:` (e.g. a root-level `.tpl: &tpl {project: …, ref: …}`) is captured **nowhere**, at
neither its definition site nor any alias site — a total loss, not the zero-loss #909 established
for GitHub Actions' container case. This fix does not close that gap; it splits the container case
by shape and defers both parts on cost/complexity grounds, not on a false "no loss" claim:

- **Sequence-shaped** (`include: *incs`, aliasing a whole sequence of N entries from one token):
  genuinely unplaceable. `Dependency`'s one-name/one-range model (mirrors the same
  `HashMap<Range, String>` identity constraint #909's spec documents at
  `crates/deps-core/src/osv/types.rs`) cannot give N inner entries N distinct ranges from one alias
  token. Closed as won't-fix-by-design — the GitLab-CI sibling of #913.
- **Mapping-shaped** (`- *tpl`, `- <<: *tpl`, aliasing one entry-mapping from one token):
  structurally placeable — one alias token, one dependency, same shape as the scalar case — but
  excluded here on cost grounds, not correctness grounds. Filed as a separate P3 follow-up (see
  §9's Follow-Up Issues) because it additionally requires YAML merge-key **precedence** handling (a
  local `ref:` must override `<<: *tpl`; for `<<: [*a, *b]` the earlier entry wins) — getting that
  wrong produces a **wrong** version, which is worse than today's dropped dependency — and because
  replaying an anchored mapping's keys re-interprets keys originally captured in a
  `FrameRole::Irrelevant` frame, which is a real instance of #909's guard-context-bypass risk class
  (this fix's own scalar-only design is free of that risk; the mapping case is not).

### Out of Scope

- Per-alias-site annotation for sequence- or mapping-shaped container anchors (see Non-Goal above;
  tracked as two separate follow-up issues, §9).
- `ref: !reference [.t]` — GitLab's own **recommended** cross-file template-reuse tag. Verified
  silently dropped today (`SequenceStart(tag=!reference)` has no handling). This may be
  higher-value than anchors precisely because it is GitLab's documented mechanism, not an
  undocumented same-file trick; needs its own research issue, including confirming GitLab's config
  processor even accepts `!reference` inside `include:` (open question, not resolved here).
- ~~The cross-ecosystem class of bug this fix's completion guard (A-7) is one instance of:
  `deps_core::completion::detect_completion_context` has no literal-span guard analogous to
  `literal_span_matches`~~ — **already shipped as #922** (`crates/deps-core/src/lsp_helpers/mod.rs`'s
  `dependency_version_range_is_literal`, merged to `main` before this fix's implementation began; see
  commit `23f440811`). `detect_completion_context` now rejects a `*`-leading (or `$`-containing)
  `version_range` generically, so this crate's local FR-011 check is defense-in-depth over that
  shared guard, not the sole barrier this section originally described. Follow-Up #4 (§9) is
  correspondingly already closed — see its updated status there.
- Extracting the value-table + alias-token-span mechanism into a shared `deps-core::yaml_anchors`
  helper now. `fix/909-gha-yaml-anchor-alias` is spec-only (no merged source), so there is nothing
  to share yet; extraction is filed as its own follow-up once **both** #909 and #912 have landed,
  per this project's DRY/cross-ecosystem-consistency rule (see `.claude/rules/*` — do not attempt
  the extraction speculatively).
- A pre-existing, unrelated false-negative noted during review: a `ref:` aliased to a **sequence**
  anchor (`&s [a, b]`) is a table miss under this design, so `mutable_ref_pin_diagnostics` still
  fires its "project has no `ref:`" message — which is then factually wrong, since a `ref:` *is*
  present, just unresolvable. Pre-existing (a sequence-valued `ref:` is nonsensical GitLab config
  regardless of aliasing), made no worse by this fix; recorded as a known limit (EC-011), not fixed
  here.

## 2. User Stories

### US-001: A project include's ref aliased to a scalar anchor is analyzed at its own alias site

AS A pipeline author who pins one `ref:` once (`.pin: &pin v1.2.3`) and reuses it by alias
(`ref: *pin`) across several `include:` entries to avoid repeating the version string
I WANT hover, mutable-ref-pin diagnostics, and inlay hints to appear at every alias site, not only
if I had repeated the literal `ref:` value at each entry
SO THAT using a YAML anchor for `ref:` reuse costs me no analysis coverage compared to writing the
literal value out N times.

**Acceptance criteria:**
```
GIVEN a .gitlab-ci.yml with `.pin: &pin v1.2.3` and two `include:` entries each
  using `ref: *pin`
WHEN the document is parsed
THEN 2 dependency records are produced (one per include entry), each with
  name_range at its own project:/component: value and version_range at its own
  alias token — distinct ranges, not collapsed onto one another or onto the
  anchor's definition
```

### US-002: An alias to a pinned ref/project/component can never be corrupted by an automated edit

AS A pipeline author using a scalar anchor/alias for `ref:`/`project:`/`component:` reuse
I WANT the "Pin to SHA" code action, the dynamic-component-pin action, the "pin all to SHA" bulk
edit, and version-completion at the cursor to all withhold themselves at an alias token
SO THAT no automated fix or completion accept ever rewrites `ref: *pin` into a bare SHA, a spliced
version fragment, or a dangling alias — the #898/#900 corruption class.

**Acceptance criteria:**
```
GIVEN a dependency record produced at an alias token (is_alias_occurrence = true)
WHEN sha_pin_quickfix_kind, generate_code_actions, collect_pin_all_to_sha_edits, or
  complete_version runs over that record
THEN no edit and no version-completion item is produced for it, and
  mutable_ref_pin_diagnostics's message carries the "(manual edit — no automated
  fix available for this ref)" suffix, honestly reflecting that no quickfix exists
```

### US-003: The alias-in-key-position desync is fixed as a side effect, not left half-fixed

AS A maintainer reviewing this fix
I WANT the pre-existing `? *k` (alias in explicit key position) desync — which silently drops the
next real scalar in the entry — fixed for **every** alias, including one that resolves to a
container (table miss), not only the scalar (table-hit) case
SO THAT this fix does not trade "aliased `ref:` values are invisible" for "a table-miss alias in
key position still silently drops the following `ref:`".

**Acceptance criteria:**
```
GIVEN an include entry containing `? *k` where `k` aliases either a scalar or a
  container anchor, followed by a real `ref: v1.0.0`
WHEN the document is parsed
THEN the `ref:` value is captured correctly regardless of whether `*k` was a
  table hit or a table miss
```

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-001 | WHEN the parser's single event-stream pass encounters a `Scalar` event carrying a non-zero anchor id THE SYSTEM SHALL record that anchor id's text in a value table (`HashMap<usize, String>`), built during the existing pass, with no additional pass over the document | must |
| FR-002 | WHEN the recorded text for an anchor id exceeds `MAX_ANCHOR_VALUE_CHARS` (512) OR the table already holds `MAX_ANCHOR_TABLE_ENTRIES` (256) distinct entries THE SYSTEM SHALL skip recording that anchor id, so any alias to it degrades to the table-miss path (FR-003) — the existing, safe, current-behavior path — rather than being recorded partially or rejected outright | must |
| FR-003 | WHEN `Event::Alias(id)` is processed THE SYSTEM SHALL perform exactly one of the following two state transitions, chosen by position, regardless of whether `id` is present in the value table: <br>— **key position**: `pending_key = PendingKey::None; awaiting_key = false;` <br>— **value position**: `awaiting_key = true; pending_key = PendingKey::None;` (≡ today's `consume_pending_value()`) <br>These transitions are the complete, literal specification — they are not "whatever a literal scalar in the same position would do," since a literal's value-position transition additionally writes a field, which the miss case must not do (see FR-004) | must |
| FR-004 | WHEN, in addition to FR-003's value-position transition, `id` IS present in the value table AND `frame.role == FrameRole::IncludeEntry` THE SYSTEM SHALL additionally capture the tabled text into the matching entry field (`project`/`ref_field`/`component`, keyed by `frame.pending_key`, exactly as `Event::Scalar`'s literal branch does at `parser.rs:239-242`) — this capture is conditional on the table hit; the transition in FR-003 is not | must |
| FR-005 | WHEN `id` is **absent** from the value table (a sequence- or mapping-shaped container anchor; a dangling/forward-referencing id is already a whole-document load error before this code runs, per §9's verified-safe claim) THE SYSTEM SHALL perform only FR-003's transition and capture nothing, matching today's behavior except for the corrected key-position transition | must |
| FR-006 | WHEN a dependency record is produced from an alias-site capture (FR-004) THE SYSTEM SHALL locate its `version_range` (and, for a `component:` alias, its `name_range` too — see FR-008) via a bounded forward scan from the `Alias` event's own marker (located via `marker_byte_offset`, never `Marker::index()`, per #879), over yaml-rust2's actual anchor-name charset (`is_anchor_char`: every character except space, tab, `\n`, `\r`, NUL, `,`, `[`, `]`, `{`, `}` — not an identifier-charset guess such as `[A-Za-z0-9_-]`, which would truncate a verified-parsing name like `*пин` or `*a/b@c`), bounded to the alias token's own line, char-boundary-safe (`char_indices().take_while(...)`, never a byte-indexed slice) — never via a literal-text search (which finds nothing at an alias site) | must |
| FR-007 | WHEN FR-006's span is computed THE SYSTEM SHALL include the leading `*` character in the span | must |
| FR-008 | WHEN the alias-site dependency is a `component:` alias THE SYSTEM SHALL set both `name_range` and `version_range` to the same alias-token span (FR-006/FR-007), and SHALL NOT run `build_component_dependency`'s normal offset arithmetic (`name_end = raw_start + prefix.len()`) against the alias site — at an alias site the underlying document text is 2 characters (`*x`), and that arithmetic would slice into unrelated document text | must |
| FR-009 | WHEN an alias-site dependency record is produced THE SYSTEM SHALL set a new field `GitlabCiDependency::is_alias_occurrence: bool` to `true` (and `false` for every other dependency); this is the sole state introduced by this fix for edit/completion withholding — not `is_plain_scalar` (already documented at `ecosystem.rs:2377-2381` as deliberately not gating the SHA-pin path, since a quoted `ref: "v1.0.0"` must still round-trip) and not `pin = None` (which would silently drop the mutable-ref-pin diagnostic entirely via `filter_map`, defeating the primary purpose of this fix — see §9 Design Decisions, P1) | must |
| FR-010 | WHEN `sha_pin_quickfix_kind` (`ecosystem.rs:89`) evaluates a dependency with `is_alias_occurrence == true` THE SYSTEM SHALL return `None` as its first arm, before any other match — this single predicate is the complete withholding gate for all three call sites (`build_sha_pin_action:708`, `build_dynamic_component_pin_action:777`, `bulk_sha_pin_text_edit_for:874`, reached via `collect_pin_all_to_sha_edits:848`), and is also what `mutable_ref_pin_diagnostics:639` reads for its `has_quickfix` suffix decision — so the diagnostic message becomes truthful at an alias site (it gains the "(manual edit — no automated fix available for this ref)" suffix) as a consequence of this one gate, with no separate message-consistency logic required | must |
| FR-011 | WHEN `complete_version` (`ecosystem.rs:254`) resolves a dependency at the request position AND that dependency's `is_alias_occurrence == true` THE SYSTEM SHALL return `Completions::default()` rather than proceeding to `complete_versions_generic_from` | must |
| FR-012 | WHEN this fix ships THE SYSTEM SHALL NOT populate `version_literal` for any alias-site dependency (it stays `None`) — `version_literal` is defined as "what `version_range` should slice to" (`code_actions.rs:539-551`); setting it to the alias text (`*pin`) would make `literal_span_matches` pass and thereby open the two shared `deps-core` edit paths (`code_actions.rs:542`, `code_lenses.rs:203`) that are otherwise safe for free, since the alias-token slice `*pin` never textually equals the anchor's real value (`v1.2.3`) | must |
| FR-013 | WHEN this fix ships THE SYSTEM SHALL correct the now-false comment at `parser.rs:257-260` ("mirroring `deps-github-actions`'s identical fix") — `deps-github-actions` (issue #909) is unmerged, and once it does land it will not be "identical" to this fix's shape in every particular (see §9, D2) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-001 | Correctness/safety | No code path may allow an edit-producing action or a version-completion item to be produced for a dependency with `is_alias_occurrence == true`. This must hold for all three SHA-pin call sites funneled through `sha_pin_quickfix_kind` (FR-010) and for `complete_version` (FR-011) independently — completion is not reached through `sha_pin_quickfix_kind` and needs its own gate |
| NFR-002 | Resource bounds | Per-document work added by this fix is O(document size): one `HashMap` entry per anchored scalar under `MAX_ANCHOR_TABLE_ENTRIES`, one O(1) lookup per alias event, one line-bounded scan per hit. An anchor-free document allocates no entries in the value table |
| NFR-003 | Resource bounds (named constants) | `MAX_ANCHOR_VALUE_CHARS = 512` and `MAX_ANCHOR_TABLE_ENTRIES = 256` (mirroring this crate's own precedent: `MAX_TAG_INDEX_ENTRIES = 256` at `registry.rs:92`, `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS = 128` at `ecosystem.rs:38`). 512 is generous: neither `is_valid_path_segment` nor `is_valid_gitlab_coordinate` (`host.rs:165,180`) imposes a length bound, so a deep namespace path is theoretically long, and 512 clears every realistic one |
| NFR-004 | Resource bounds (behavior-preservation guarantee) | An anchor that exceeds either NFR-003 bound degrades to the table-miss path (FR-005) — today's existing, safe behavior. This bound can therefore only ever withhold this new feature on absurd input; it can never regress a case that works today. This is why the bounds are fixed as concrete numbers in this spec rather than left as a tuning placeholder |
| NFR-005 | Compatibility | This fix must not change the record count or positions for any anchor-free `.gitlab-ci.yml` document, and must not change the record count for the `<<:` merge-key case (already safe by construction, EC-006) |
| NFR-006 | Load-bearing assumption (must be re-checked on future change) | The completion guard (FR-011) is the only reachable protection for a `project:`/`component:` alias whose `name_range == version_range`, where `detect_completion_context`'s `name_range`-first check makes `CompletionContext::Version` unreachable regardless of FR-011 (see §9, P2). For that shape, the **only** actual barrier against a bogus completion is `complete_package_name` being unimplemented in this crate (`ecosystem.rs:242-245`, pinned by `test_generate_completions_package_name_context_returns_empty_non_incomplete` at `:2502`). A future implementation of `complete_package_name` for this crate MUST re-verify this shape does not regress before merging |
| NFR-007 | No new depth/replay bound needed | Unlike #909/#910's `MAX_ALIAS_REPLAY_DEPTH` precedent, no depth cap is required here: an anchor-on-alias (`&y *x`) and a forward/dangling reference are both whole-document **load errors** in yaml-rust2, so a table miss can only ever mean "this alias references a container anchor" — never an unresolved chain |
| NFR-008 | No new multiplication/dedup bound needed | At most one dependency record is produced per alias **token**, bounded by document size — aliasing cannot multiply records the way #909's rejected first attempt (event replay) could, so `MAX_DEPENDENCIES_PER_DOCUMENT`/`MAX_HOSTS_PER_DOCUMENT` cannot be tripped by this fix |

## 5. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| Scalar-anchor value table | A per-parse, transient `HashMap<usize, String>` mapping a yaml-rust2 anchor id to the anchored scalar's text, built during the single existing event-stream pass, bounded by NFR-003 | key: anchor id (`usize`, monotonic, never reused per document — cross-document aliasing is already a load error, so no per-document reset is needed); value: the scalar's text only, capped at `MAX_ANCHOR_VALUE_CHARS`; capped overall at `MAX_ANCHOR_TABLE_ENTRIES` |
| Alias-site dependency record | A `GitlabCiDependency` occurrence produced when `Event::Alias(id)` hits the value table inside an `IncludeEntry` frame (FR-004) | `name`/`version_req`/`pin` classified from the anchor's recorded text; `name_range`/`version_range` both span the alias token for a `component:` alias (FR-008), or `version_range` alone spans it for `ref:` (`name_range` stays at the entry's own `project:`/`component:` value); `is_alias_occurrence = true`; `version_literal = None` (FR-012) |
| Container-anchor alias site | An `Event::Alias(id)` where `id` is absent from the value table | Produces no capture (FR-005); only FR-003's state transition runs; no change to existing definition-site behavior (which, per the Non-Goal above, was already zero for a container defined outside `include:`) |

## 6. Edge Cases and Error Handling

| ID | Scenario | Expected Behavior |
|----|----------|--------------------|
| EC-001 | `ref: *pin` (scalar anchor aliased as a `ref:` value) | In scope, most plausible pattern (FR-001–FR-010) |
| EC-002 | `project: *proj` (scalar anchor aliased as a `project:` value) | In scope; today total dep loss (`build_dependency` → `None`), fixed the same way as EC-001 |
| EC-003 | `component: *c` (scalar anchor aliased as a `component:` value) | In scope; `name_range == version_range`, both the alias token (FR-008); `build_component_dependency`'s normal offset arithmetic is bypassed for this site |
| EC-004 | `? *k` where `*k` aliases a **scalar** anchor (table hit), followed by a real `ref: v1.0.0` in the same entry | Fixed: FR-003's key-position transition plus FR-004's capture behave like the literal `? ref` control; the following `ref:` is captured correctly |
| EC-005 | `? *k` where `*k` aliases a **container** anchor (table miss), followed by a real `ref: v1.0.0` in the same entry | Fixed as a side effect of making FR-003's transition unconditional: the following `ref:` is captured correctly even though `*k` itself yields no dependency (US-003) |
| EC-006 | `<<: *anything` (merge key aliasing any anchor) | Safe by construction, unaffected by this fix: `key_for(IncludeEntry, "<<") == PendingKey::None`, so no field is ever targeted for capture regardless of table hit/miss. Regression test only |
| EC-007 | `- *tpl` (a whole mapping anchor aliased as a sequence item under `include:`) | Deferred (Non-Goal, mapping-shaped case) — table miss, FR-005 applies, zero records, same as today |
| EC-008 | `include: *incs` (a whole sequence anchor aliased at the `include:` key) | Deferred (Non-Goal, sequence-shaped case, won't-fix-by-design) — table miss, FR-005 applies, zero records, same as today |
| EC-009 | A dangling or forward-referencing alias id (`*nope` with no matching `&nope` anywhere, or an alias appearing before its anchor's definition) | `parser.load()` fails the whole document (yaml-rust2 behavior) before this fix's code runs — not reachable in practice; harmless if it were (falls into FR-005) |
| EC-010 | `ref: !reference [.t]` (GitLab's own recommended cross-file reuse tag) | Out of scope (see §1 Out of Scope); verified silently dropped today and unaffected by this fix either way |
| EC-011 | `ref:` aliased to a **sequence** anchor (`&s [a, b]`) | Table miss (FR-005); `mutable_ref_pin_diagnostics` still fires "project has no `ref:`", which is then factually wrong (a `ref:` is present, just unresolvable to a scalar). Pre-existing false-negative-adjacent limit, not introduced or worsened by this fix — documented, not fixed, here |
| EC-012 | An anchored **empty** scalar (`x: &e` / `ref: *e`) | Table hit whose text is `""`, the one hit whose text is not a plausible value. Must remain safe at every downstream guard: `version_req` empty → `code_actions.rs:531`'s early return; `is_valid_gitlab_coordinate("")` is `false`; a `component:` alias to it has no `@` to split on. No panic, no false dependency-looking record with a misleading non-empty display |
| EC-013 | Two aliases to the same scalar anchor on one flow-style line (`{ref: *p}, {ref: *p}`) | Each `Alias` event carries its own distinct `Marker` — two distinct records with two distinct `version_range`s. The span locator (FR-006) must anchor at the event's own marker, never do a line-text search, or both records collapse onto one range |
| EC-014 | Anchor name collides with a plausible version literal (`&v1 v1.2.3` / `*v1`) | The alias-site span (FR-007) must include the leading `*`; a span starting after it would slice to a version-shaped string, satisfy `literal_span_matches`, and open an edit path meant to stay closed at an alias site |
| EC-015 | An anchor definition exceeding `MAX_ANCHOR_VALUE_CHARS` or the table already at `MAX_ANCHOR_TABLE_ENTRIES` | Degrades to the table-miss path (FR-002, NFR-004) — zero records at any alias to it, same as today; no partial/truncated capture |
| EC-016 | Version completion requested with the cursor inside a `ref: *pin` alias token (a `project:`/`ref:` shape where `name_range != version_range`) | `complete_version` returns `Completions::default()` (FR-011) — this is the shape where the gate is actually reachable and must be the one exercised by the FR-011 regression test |
| EC-017 | Version completion requested with the cursor inside a `component: *c` alias token | `CompletionContext::Version` is unreachable at all for this shape (`name_range == version_range`, `detect_completion_context` resolves `PackageName` first per NFR-006) — no completion appears, but via the unimplemented `complete_package_name` path, not via FR-011. A test asserting "FR-011 withholds completion here" would pass vacuously and must not be written for this shape |

## 7. Success Criteria

| ID | Metric | Target |
|----|--------|--------|
| SC-001 | US-001 repro (`.pin: &pin v1.2.3` aliased by two `include:` entries' `ref:`) | 2 dependency records, distinct `version_range`s, both with working hover/diagnostics/inlay hints |
| SC-002 | US-002: edit- and completion-safety | 0 edits produced via `sha_pin_quickfix_kind`'s three funneled call sites, and 0 completion items via `complete_version`, for every dependency with `is_alias_occurrence == true`; `mutable_ref_pin_diagnostics`'s message carries the manual-edit suffix for such a dependency |
| SC-003 | US-003: `? *k` desync fix | The scalar-hit case (EC-004) and the container-miss case (EC-005) both correctly capture a following real `ref:` — two separate regression tests, since only the scalar case existed as a repro before this fix |
| SC-004 | NFR-005: no regression on anchor-free or `<<:`-only documents | 0 changes to dependency count or position for every existing passing test fixture with no scalar-anchor-in-`include:` shape in it |
| SC-005 | NFR-003/004: bound holds and degrades safely | An anchor exceeding `MAX_ANCHOR_VALUE_CHARS` or pushing the table past `MAX_ANCHOR_TABLE_ENTRIES` produces the same (zero-record) result as today for any alias to it — verified by a dedicated over-cap test, not only by code inspection |
| SC-006 | EC-017's vacuous-test trap avoided | The FR-011 regression test targets a `project:`/`ref:` alias shape (`name_range != version_range`), not a `component:` alias shape, and a comment or test name makes that choice explicit so a future edit does not "simplify" it into the vacuous shape |

## 8. Agent Boundaries

### Always (without asking)
- Implement the value table, the FR-003/FR-004 split transition, the FR-006/FR-007 span locator,
  and the `is_alias_occurrence` field inside `crates/deps-gitlab-ci/src/parser.rs` and
  `crates/deps-gitlab-ci/src/types.rs`
- Gate all three SHA-pin sites through `sha_pin_quickfix_kind`'s single new first-arm predicate
  (FR-010) — do not add separate gates at `build_sha_pin_action`, `build_dynamic_component_pin_action`,
  or `bulk_sha_pin_text_edit_for` individually
- Gate `complete_version` independently (FR-011) — this is not reached through
  `sha_pin_quickfix_kind` and needs its own check
- Leave `version_literal` at `None` for every alias-site record (FR-012) — do not populate it "for
  completeness"
- Correct the `parser.rs:257-260` comment (FR-013)
- Add a regression test for every FR (FR-001 through FR-013) and every EC (EC-001 through EC-017)
  before merging, plus the SC-001 through SC-006 checks in §7 — in particular, the two `? *k`
  variants (EC-004/EC-005) as separate tests, and the FR-011 test using the `project:`/`ref:` shape
  (EC-016), never the `component:` shape (EC-017)
- Run the full check suite (`fmt`, `clippy -D warnings`, `nextest`, rustdoc gate) per
  `.claude/rules/branching.md` before any PR

### Ask First
- Extracting the value-table mechanism into a shared `deps-core` helper now, ahead of #909 landing
  — the Out of Scope section defers this; only ask if circumstances change (e.g. #909 merges mid-implementation)
- Changing `MAX_ANCHOR_VALUE_CHARS` (512) or `MAX_ANCHOR_TABLE_ENTRIES` (256) — NFR-003/004
  establish these as safe-to-fix-now precisely because exceeding them only withholds the new
  feature, never regresses existing behavior; a request to tighten or loosen them should be a
  deliberate, separate decision
- Implementing `complete_package_name` for this crate in the same PR — NFR-006 flags that doing so
  would reopen the completion hole for the `component:`-alias shape and requires its own re-verification

### Never
- Gate the three SHA-pin sites independently instead of through `sha_pin_quickfix_kind` — this was
  the first design's S1 defect and reopens issue #643's drift
- Use `is_plain_scalar` or `pin = None` as the withholding signal — both were considered and
  rejected (FR-009); `is_plain_scalar` is documented elsewhere as deliberately not gating this path,
  and `pin = None` would silently delete the diagnostic this fix exists to restore
- Attempt per-alias-site annotation for a sequence- or mapping-shaped container anchor as part of
  this fix — those are separate follow-up issues (§9), not this issue's scope
- Write a completion-withholding test using the `component:` alias shape and label it as proof
  FR-011 works — that shape's `Version` context is unreachable regardless of FR-011 (EC-017); such a
  test passes vacuously and must not be presented as coverage for FR-011

## 9. Design Decisions

Resolved across two adversarial architect/critic rounds (2026-09-13, final verdict: minor); no
open `[NEEDS CLARIFICATION]` items remain. The four corrections below (P1–P4) come from the final
critic pass and are carried here **verbatim in substance**, since they correct the *reasoning*
behind otherwise-correct conclusions — reasoning that would mislead a future reader if only the
conclusion survived into the spec.

- **P1 — `version_range = Some(alias span)` stands, for the correct reason.** The cheaper-looking
  alternative (`version_range = None`, `name_range = alias span`) was tested and rejected. The
  decisive reason is **not** "it causes a #643-style message/dispatch drift" — `mutable_ref_pin_diagnostics`
  evaluates `let range = gl_dep.version_range?` at `ecosystem.rs:621`, strictly *before*
  `let has_quickfix = sha_pin_quickfix_kind(...)` at `:639`. With `version_range = None` the whole
  diagnostic is dropped by `filter_map` — nothing is promised, so there is no drift to speak of. The
  real defect is stronger: `version_range = None` would **silently suppress the mutable-ref-pin
  diagnostic entirely**, which is the primary signal #912 exists to restore. Losing it outright is
  worse than a drift. The secondary, sufficient-on-its-own reason stands unchanged: `inlay_hints.rs:24`
  and `code_lenses.rs:155` both `let Some(version_range) = dep.version_range() else { continue };`,
  so `None` would also silence the inlay hint and code lens for every alias-site dependency.
- **P2 — FR-011's gate is unreachable for a `component:` alias; the test must target `project:`/`ref:`.**
  `position_in_range` is inclusive of `range.end` (`lsp_helpers/mod.rs:828-839`), and
  `detect_completion_context` tries `name_range` first. Per FR-008, a `component:` alias has
  `name_range == version_range` (both the alias token), so **every** position at that site resolves
  to `PackageName`, and `CompletionContext::Version` — the context FR-011 gates — is unreachable
  there, independent of whether FR-011 exists. A test claiming "version completion withheld at a
  `component:` alias" would pass vacuously (see EC-017, SC-006). For the component-alias shape, the
  **only** actual protection is `complete_package_name` being unimplemented in this crate — not
  defense-in-depth alongside FR-011, but the sole barrier (NFR-006). A future implementation of
  `complete_package_name` must re-check this shape before merging.
- **P3 — the FR-003/FR-004 state-transition split must be specified literally, not as "whatever a
  literal scalar would do."** An earlier phrasing ("byte-identical to what a literal scalar in the
  same position performs") is unimplementable on a table miss — there is no text to route through
  the literal path — and its natural workaround (feeding empty text through that path anyway) is
  actively harmful: in value position with `pending_key == PendingKey::Ref` and
  `role == FrameRole::IncludeEntry`, the literal path (`parser.rs:239-242`) would write
  `frame.entry.ref_field = Some(("", style, line, col))`, fabricating an empty `ref:` for a
  container alias. That flips `pin` from `None` to `Some(PinStyle::Branch)`, which **suppresses**
  the correct "project has no `ref:`" diagnostic (`ecosystem.rs:592-609`) and emits nothing in its
  place — a regression versus today's behavior. FR-003/FR-004 instead specify three separate,
  literal rules: an unconditional key-position transition, an unconditional value-position
  transition, and a capture that is conditional on table hit **and** value position **and**
  `IncludeEntry` role, all together.
- **P4 — the value-table bound needs concrete numbers, following this crate's own precedent.**
  "A plausible value, a few hundred bytes" and "cap the entry count" are not implementable as
  stated. `MAX_ANCHOR_VALUE_CHARS = 512` and `MAX_ANCHOR_TABLE_ENTRIES = 256` (NFR-003) follow the
  shape of `MAX_TAG_INDEX_ENTRIES = 256` (`registry.rs:92`) and
  `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS = 128` (`ecosystem.rs:38`) already in this crate.
  Because exceeding either bound degrades to the existing, safe table-miss path (NFR-004), fixing
  concrete numbers now carries no regression risk and does not need to wait for real-world tuning
  data.
- **Mechanism: value table, not event replay.** Chosen for the same reason as #909's design: replay
  cannot satisfy `name_range`/`version_range` uniqueness (an anchor referenced by M alias sites
  would replay at the anchor's own marker M times, colliding), and it re-derives ambient parser
  state (here, `pending_key`/`awaiting_key`) incorrectly across sites — exactly the class of defect
  that produced the `? *k` desync this fix also closes.
- **Arity split: scalar anchor → 1 record; sequence/mapping container anchor → 0 records.** A
  scalar anchor's alias site is one token that can host exactly one dependency's identity. A
  container anchor's alias site is also one token, but represents either N inner entries
  (sequence-shaped, structurally unplaceable) or 1 inner entry with a merge-key precedence hazard
  (mapping-shaped, placeable but deferred on cost). Neither container shape is fixed by this issue.
- **`is_alias_occurrence: bool`, not `is_plain_scalar` reuse, not `pin = None`.** All three were
  considered. `is_plain_scalar` is documented at `ecosystem.rs:2377-2381` as deliberately *not*
  gating the SHA-pin path (a quoted `ref: "v1.0.0"` must still round-trip through a quickfix), so
  overloading it here would either break that round-trip or require a second, conflicting meaning
  for the same field. `pin = None` was rejected per P1. A new, single-purpose boolean is the
  smallest correct carrier.
- **Single gate in `sha_pin_quickfix_kind`, not three gates at the call sites.** That function is
  already the sole source of truth `mutable_ref_pin_diagnostics:639` reads for its message suffix,
  introduced by issue #643 specifically so the message and the quickfix dispatch "can never
  independently drift." Gating the three call sites separately would reopen exactly that drift
  class for the new alias case. One gate closes all three sites and keeps the diagnostic message
  honest as a side effect, not a separately-implemented consistency check.
- **`complete_version` gated independently, not folded into `sha_pin_quickfix_kind`.** Completion
  is not reached through that function at all — it needs its own check on `is_alias_occurrence`.
- **No recursion/depth cap needed (unlike #909/#910's `MAX_ALIAS_REPLAY_DEPTH` precedent).**
  `&y *x` (an anchor placed on an alias) and a forward/dangling reference are both whole-document
  **load errors** in yaml-rust2 — the document fails to parse at all before this fix's code runs.
  A table miss can therefore only ever mean "this alias references a container anchor," never an
  unresolved or circular chain, so the value table needs no depth tracking.
- **No multiplication/dedup risk (unlike #909's rejected first replay attempt).** At most one
  dependency record is produced per alias token, bounded by document size — there is no mechanism
  by which aliasing could multiply records the way full event-replay did in #909's first, rejected
  design, so `MAX_DEPENDENCIES_PER_DOCUMENT`/`MAX_HOSTS_PER_DOCUMENT` are unaffected.
- **Sequencing: safe to implement standalone now.** `fix/909-gha-yaml-anchor-alias` is spec-only —
  no source code merged or pending (`git diff --stat main...fix/909-gha-yaml-anchor-alias` shows
  only `specs/055-.../spec.md` and one `MOC-specs.md` line). #912 has no dependency on it and no
  collision risk beyond that one shared `MOC-specs.md` line, which is the docs-only fast path per
  `.claude/rules/branching.md`. A shared `deps-core` extraction of the anchor-alias-scalar pattern
  is deliberately deferred to a follow-up filed once **both** #909 and #912 have landed.
- **Process: specify phase only, no plan/tasks.** Per `.claude/rules/specs.md` ("not every spec
  needs all three phases") and mirroring `specs/055-.../spec.md`'s own precedent for the sibling
  #909 fix: the remaining work is one value table, one split state transition, one bounded scanner,
  and two independent withholding gates, with every FR/EC/AC already enumerated above. Hand
  implementation directly to a developer from §3/§6/§9 of this spec.

### Follow-Up Issues (filed after this spec's commit)

1. **Mapping-shaped container anchor support** (`- *tpl`, `- <<: *tpl`) — #916, P3, enhancement.
   Body: same-file scalar-anchor-alias support for `include:` entries landed in #912. A mapping
   anchor aliased as a whole `include:` entry (`- *tpl` or `- <<: *tpl`) is still not detected —
   the anchor's fields are never captured because the definition site sits in a
   `FrameRole::Irrelevant` frame. This is structurally placeable (one alias token → one entry → one
   dependency, unlike the sequence-shaped case), but requires: (a) YAML merge-key precedence
   handling — a local `ref:` must override `<<: *tpl`, and `<<: [*a, *b]` resolves in first-wins
   order — getting this wrong yields a *wrong* pinned version, worse than today's dropped
   dependency; (b) re-interpreting keys captured in an `Irrelevant` frame, which reintroduces
   #909's guard-context-bypass risk class in a form #912's scalar-only design avoided. Design and
   critique this as its own spec before implementing.
2. **Sequence-shaped container anchor** (`include: *incs`) — #917, won't-fix-by-design, research/decision-record, P4.
   Body: aliasing a whole sequence of `include:` entries from one token (`include: *incs`) cannot
   give each of the N entries a distinct `name_range`/`version_range` from `Dependency`'s
   one-name/one-range model, the same structural limit `#913` documents for GitHub Actions'
   container case. Close as won't-fix-by-design, referencing #913 as the GitHub Actions sibling and
   this spec's Non-Goal section for the analysis.
3. **`ref: !reference [.t]` support** — #918, research, P3.
   Body: GitLab's own recommended cross-file template-reuse tag (`!reference`) is silently dropped
   by this crate today — verified via event trace, `SequenceStart(tag=!reference)` has no handling
   path. This may be higher-value than YAML-anchor support since it is GitLab's documented
   mechanism, not an undocumented same-file trick. First question to resolve: does GitLab's own
   config processor accept `!reference` inside `include:` at all, or only inside job bodies (which
   this crate does not parse regardless)? Needs its own research spike before scoping.
4. ~~**Cross-ecosystem: `detect_completion_context` has no literal-span guard** — #919, bug,
   `cross-ecosystem` label, P2.~~ **Already shipped — do not file.** (#912 critic review, S3):
   `#919` already existed and was already resolved by `#922`
   (`fix(deps-core): reject non-literal version spans in completion guard`, merged to `main`
   before this fix's implementation began) — `deps_core::completion::detect_completion_context` now
   routes through `lsp_helpers::dependency_version_range_is_literal`, which rejects a `*`-leading (or
   `$`-containing) `version_range` before ever returning `CompletionContext::Version`. `deps-gitlab-ci`
   (#912) keeps its own `is_alias_occurrence` gate (FR-011) as local defense-in-depth — not because
   the shared guard is missing, but because it is the gate FR-011 was specified against, and it also
   covers `sha_pin_quickfix_kind`'s three SHA-pin call sites, which `#922`'s completion-only guard
   does not. This paragraph originally proposed filing #919 as a new issue without checking whether it
   already existed — a process lesson, not a design error: always check `gh issue view <N>` /
   `gh issue list` for an issue number before assuming it is unfiled.

## 10. See Also

- [[constitution]] — project principles
- [[MOC-specs]] — all specifications
- `specs/055-gha-yaml-scalar-anchor-alias/spec.md` (branch `fix/909-gha-yaml-anchor-alias`, unmerged)
  — the sibling GitHub Actions fix this spec's problem framing and process-only-specify precedent
  follow; **not identical in mechanism** (see FR-013, §9 D2) because this crate's SHA-pin path is
  gated differently and its parser is `include:`-scoped rather than path-agnostic
- GitHub `#912` — this fix's source issue (title/"higher impact than #909" claim corrected by this spec)
- GitHub `#909` — the GitHub Actions sibling gap, unmerged, spec-only
- GitHub `#913` — GitHub Actions' aggregate per-alias-site annotation research idea for the
  container case; this spec's sequence-shaped follow-up (§9, Follow-Up #2) is its GitLab-CI sibling
- GitHub #916, #917, #918 — this spec's three filed follow-up issues (§9 Follow-Up Issues); the
  fourth (a `detect_completion_context` literal-span guard) was going to be filed as `#919` but that
  number already existed and was already resolved by `#922` before this fix's implementation began
  (#912 critic review, S3) — not filed again
- GitHub `#643` — introduced `sha_pin_quickfix_kind` as the single source of truth for the
  mutable-ref-pin diagnostic's quickfix-availability suffix; this spec's FR-010 preserves that invariant
- `crates/deps-gitlab-ci/src/parser.rs` — `key_for`, the `Event::Scalar`/`Event::Alias` handling
  this fix changes, and the stale comment corrected by FR-013
- `crates/deps-gitlab-ci/src/types.rs` — `GitlabCiDependency`, where `is_alias_occurrence` is added
- `crates/deps-gitlab-ci/src/ecosystem.rs` — `sha_pin_quickfix_kind`, `mutable_ref_pin_diagnostics`,
  `complete_version`, the three SHA-pin call sites this fix gates
- `crates/deps-core/src/completion.rs` — `detect_completion_context`, `position_in_range`, the
  cross-ecosystem gap tracked as this spec's Follow-Up #4

//! `.gitlab-ci.yml`-syntax parser using `yaml-rust2`'s event-driven
//! (`MarkedEventReceiver`) API.
//!
//! Tracks the top-level `include:` key's value and, within it, each entry's
//! `project:`/`ref:`/`component:`/`template:`/`remote:`/`local:` keys — `template:`,
//! `remote:` and a `local:` key (or a bare-string `include:` list item, GitLab's `local:`
//! shorthand) are recognized and skipped gracefully (spec FR-003); `image:`/`services:`
//! entries are never visited at all, since they never appear under `include:` (FR-016
//! falls out for free).
//!
//! # Multi-document input
//!
//! A GitLab CI **component** file uses the `spec:` header form (`spec: … \n--- \n job:`).
//! Per-document parser state is reset at each `Event::DocumentStart`/`DocumentEnd`, so
//! document 1's nesting never mis-scopes document 2's top-level `include:`.
//!
//! # Host resolution and the per-document fan-out cap
//!
//! Every dependency's host is resolved here (not deferred to the registry), since the
//! per-document cap on distinct literal `component:` hosts (spec plan §4.6) must be
//! enforced at the point a host string first turns into a fetch target. A `project:`
//! include (which never carries a host segment) and a `$CI_SERVER_FQDN`-relative
//! `component:` include resolve against `registries.gitlab_instance_host` when set, or are
//! left [`crate::types::HostRef::Unresolved`] otherwise (spec FR-011a/FR-012) — unless the
//! resolved value is rejected specifically by the `registries.workspace_registries`
//! reachability policy, in which case it becomes [`crate::types::HostRef::PolicyBlocked`]
//! instead (issue #967).

use crate::host::{
    GitlabHost, GitlabInstanceHost, InstanceHostOutcome, is_valid_gitlab_coordinate,
    is_valid_path_segment,
};
use crate::types::{
    EndpointKind, GitlabCiDependency, GitlabCiParseResult, GitlabRoute, HostRef, IncludeKind,
    PinStyle,
};
use deps_core::lsp_helpers::{
    LineOffsetTable, MarkedScalar, byte_span_to_range, is_full_sha, is_plain_null, is_tag_shaped,
    marker_byte_offset, warn_rejected_value,
};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::parser::DependencySource;
use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{DepsError, Result};
use std::collections::{HashMap, HashSet};
use url::Url;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Bound on distinct literal `component:` hosts admitted per document (spec plan §4.6) —
/// the bound that matters for a `didOpen` burst, protecting `HttpCache`'s unbounded
/// per-origin transport pool from a `.gitlab-ci.yml` naming N distinct hosts on one parse.
const MAX_HOSTS_PER_DOCUMENT: usize = 8;

/// Placeholder display text for a `project:` include's implicit host, and for a
/// `$CI_SERVER_FQDN`-relative `component:` include with no configured instance host.
const CI_SERVER_FQDN: &str = "$CI_SERVER_FQDN";

/// Maximum character length of one anchored scalar's text recorded into
/// [`GitlabCiReceiver::anchors`] (spec FR-002/NFR-003). An anchor exceeding this degrades
/// to the table-miss path (FR-005) — today's existing, safe behavior — rather than being
/// recorded truncated.
const MAX_ANCHOR_VALUE_CHARS: usize = 512;

/// Maximum number of distinct anchor ids recorded into [`GitlabCiReceiver::anchors`] (spec
/// FR-002/NFR-003), mirroring this crate's own `MAX_TAG_INDEX_ENTRIES` precedent
/// (`registry.rs:92`). An anchor pushing the table past this bound degrades to the
/// table-miss path (FR-005) the same as [`MAX_ANCHOR_VALUE_CHARS`].
const MAX_ANCHOR_TABLE_ENTRIES: usize = 256;

/// Bound on [`GitlabCiReceiver::event_log`]'s length (spec 058 critic M2) — bounds the
/// *memory* cost of a mapping-shaped container-anchor recording (one clone per event
/// while any anchor is open), a distinct concern from [`MAX_REPLAYED_EVENTS`]'s *CPU x
/// fanout* bound on replay dispatch. The two constants coincide in value only by
/// convenience, not derivation — do not assume raising one implies raising the other.
/// Tripping this stops recording (never truncates a range mid-recording, which would
/// replay an unbalanced event prefix — see [`GitlabCiReceiver::record_event`]).
const MAX_RECORDED_EVENTS: usize = 20_000;

/// Secondary, cheap guard against unbounded replay recursion (spec 058 critic M1) — a
/// linear merge chain (`&a_n { <<: *a_(n-1) }`) costs only 2 budget units per nesting
/// level, so [`MAX_REPLAYED_EVENTS`] alone permits far deeper recursion than any
/// legitimate template chain needs; this is the cheap secondary bound
/// [`crate::parser`]'s own NFR-002 explicitly permits, never the primary one.
const MAX_REPLAY_DEPTH: usize = 32;

/// Stream-scoped ceiling on total events dispatched through
/// [`GitlabCiReceiver::replay_anchor`] (spec FR-026) — the primary resource bound for
/// mapping-shaped container-anchor replay, decremented once per dispatched event and
/// checked before each dispatch, shared across every replay (nested or repeated) for the
/// whole parse. Deliberately never reset at a document boundary (spec FR-029): a
/// pathological document earlier in a multi-document `spec:`-header stream also safely
/// disables replay for the rest of the stream, rather than letting each document spend
/// its own budget.
const MAX_REPLAYED_EVENTS: usize = 20_000;

/// Bound on [`GitlabCiReceiver::container_anchors`]'s entry count (critic L1) — mirrors
/// [`MAX_ANCHOR_TABLE_ENTRIES`]'s own precedent for the sibling scalar-anchor table. Without
/// this, an *empty* mapping anchor (`.a: &a {}`) finalizes a zero-length `event_log` range —
/// contributing nothing towards [`MAX_RECORDED_EVENTS`] — so a flood of them grows
/// `container_anchors` unboundedly even though the event-log bound never trips (measured:
/// 150,000 empty anchors allocate ~19 MiB of map entries alone). A new anchor id beyond this
/// cap is simply never finalized into the table — the same "degrades to a table miss"
/// behavior [`MAX_ANCHOR_TABLE_ENTRIES`] already produces for the scalar-anchor case.
const MAX_CONTAINER_ANCHOR_ENTRIES: usize = 256;

/// What a frame means for include-entry extraction purposes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRole {
    /// The document's root mapping — scanned only for a top-level `include:` key.
    Root,
    /// The value of a top-level `include:` key, when it is a sequence of entries.
    IncludeValue,
    /// One include entry mapping — either a `include:`'s single-mapping form, or one
    /// mapping item inside an [`FrameRole::IncludeValue`] sequence. Its direct scalar keys
    /// (`project`/`ref`/`component`/`template`/`remote`/`local`) are captured into the
    /// frame's own [`RawEntry`] payload.
    IncludeEntry,
    /// A mapping-shaped anchor's replayed frame, reached via a `<<:` merge key (either
    /// directly, `- <<: *tpl`, or as one member of a `<<: [*a, *b]` sequence) — spec 058
    /// FR-007. Shares [`FrameRole::IncludeEntry`]'s key table and field-capture logic
    /// ([`key_for`]'s combined arm), and is itself a valid parent for another `<<:` (a
    /// transitive merge chain), so this role is reachable both directly under an
    /// [`FrameRole::IncludeEntry`]/[`FrameRole::MergeSource`] pending a `<<:` key and as a
    /// [`FrameRole::MergeSequence`] member.
    MergeSource,
    /// The `Sequence` value of a `<<:` key (`<<: [*a, *b]`) — spec 058 FR-007. Each mapping
    /// member replays as its own [`FrameRole::MergeSource`], folded `FillIfAbsent` into
    /// this frame's own [`RawEntry`] payload (first-wins within the sequence, Psych table
    /// row 3), which then folds into its own parent the same way any other
    /// [`FrameRole::MergeSource`] does (FR-011).
    MergeSequence,
    /// Anything else — a job body, `inputs:`, `rules:`, or any other structure this parser
    /// does not need to look inside. Also covers a complex YAML key's subtree (`?
    /// <mapping>`/`? <sequence>`) — [`deps_core::yaml_walk::FrameStack`] handles the
    /// key/value-alternation bookkeeping for that case generically, so this parser never
    /// needs its own dedicated role for it.
    Irrelevant,
}

/// Which key (if any) a [`FrameRole::Root`] or [`FrameRole::IncludeEntry`] mapping frame is
/// currently awaiting the value for.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum PendingKey {
    #[default]
    None,
    Include,
    Project,
    Ref,
    Component,
    Template,
    Remote,
    Local,
    /// `<<:` (or a quoted `"<<":`/`'<<':`, FR-006 — matched on text alone, never gated on
    /// scalar style) — a merge key, produced by [`key_for`] for [`FrameRole::IncludeEntry`]
    /// and [`FrameRole::MergeSource`] alike.
    Merge,
}

/// Resolves `text` (a scalar key's own text, or — since #942 — an alias's resolved anchor
/// text on a value-table hit) to the key `role`'s mapping frame is now awaiting the value
/// for.
///
/// Because an alias-resolved key is treated identically to a literal one, this reaches every
/// consequence a literal key has, not just the ones #942 set out to fix: a `*i: [...]` whose
/// anchor resolves to `"include"` now opens the top-level `include:` gate exactly as the
/// literal token would (`FrameRole::Root` arm), and a `*t: true`/`*l: /x.yml` entry whose
/// anchor resolves to `"template"`/`"local"` now marks that entry non-version-pinnable and
/// suppresses the whole dependency (`FrameRole::IncludeEntry` arm — see
/// [`RawEntry::has_template`]/[`RawEntry::has_local`]/[`RawEntry::has_remote`] and
/// `build_dependency`'s early return), the same as the literal key already did. Both are the
/// correct reading of the YAML (an alias key genuinely is the resolved text), not an
/// oversight — but both are new *reachability*, not just new capture, so each direction has
/// its own regression test (`test_alias_key_resolving_to_include_opens_top_level_gate`,
/// `test_alias_key_resolving_to_template_suppresses_the_whole_entry`,
/// `test_alias_key_resolving_to_local_suppresses_the_whole_entry`).
fn key_for(role: FrameRole, text: &str) -> PendingKey {
    match role {
        FrameRole::Root => {
            if text == "include" {
                PendingKey::Include
            } else {
                PendingKey::None
            }
        }
        // spec 058 FR-008: `MergeSource` shares `IncludeEntry`'s key table — including
        // `<<:` itself — so a merge nested inside a merged template (a transitive merge
        // chain) resolves instead of degrading to `Irrelevant`.
        FrameRole::IncludeEntry | FrameRole::MergeSource => match text {
            "project" => PendingKey::Project,
            "ref" => PendingKey::Ref,
            "component" => PendingKey::Component,
            "template" => PendingKey::Template,
            "remote" => PendingKey::Remote,
            "local" => PendingKey::Local,
            "<<" => PendingKey::Merge,
            _ => PendingKey::None,
        },
        FrameRole::IncludeValue | FrameRole::MergeSequence | FrameRole::Irrelevant => {
            PendingKey::None
        }
    }
}

/// One raw value captured from an include entry: a literal scalar (see [`MarkedScalar`],
/// whose `span()` resolves the byte span only after parsing completes, via a
/// `line`/`col`-based lookup rather than `Marker::index()`, #879), or a same-file alias
/// resolved through [`GitlabCiReceiver::anchors`] (spec FR-004). An alias variant's span is
/// the alias **token** itself (`*name`), never the anchor's resolved text — see
/// [`locate_alias_span`] — since the document text at the alias's marker is the token, not
/// the text `text` holds.
enum RawField {
    /// A literal scalar value, captured directly from an `Event::Scalar`.
    Literal(MarkedScalar),
    /// A same-file alias to a tabled scalar anchor (spec FR-004) — `text` is the anchor's
    /// recorded text (used for classification, exactly like a literal's), `line`/`col` are
    /// the `Event::Alias`'s own marker (used only to locate the alias token's span).
    Alias {
        text: String,
        line: usize,
        col: usize,
    },
}

impl RawField {
    /// The field's resolved text — the anchor's text for an alias, matching what a literal
    /// scalar's `MarkedScalar::text` would hold for the same value.
    fn text(&self) -> &str {
        match self {
            Self::Literal(scalar) => scalar.text(),
            Self::Alias { text, .. } => text,
        }
    }

    /// Consumes the field, returning its resolved text (see [`Self::text`]).
    fn into_text(self) -> String {
        match self {
            Self::Literal(scalar) => scalar.into_text(),
            Self::Alias { text, .. } => text,
        }
    }

    /// Whether the field was written as a plain (unquoted) literal scalar — always `false`
    /// for an alias: an alias token has no quoting style of its own to be "plain" about.
    fn is_plain(&self) -> bool {
        match self {
            Self::Literal(scalar) => scalar.is_plain(),
            Self::Alias { .. } => false,
        }
    }

    /// Whether this field was captured from a same-file alias (spec FR-009's
    /// `is_alias_occurrence` carrier).
    const fn is_alias(&self) -> bool {
        matches!(self, Self::Alias { .. })
    }

    /// Resolves the field's raw byte span within `content` — a literal's via
    /// [`MarkedScalar::span`], an alias's via [`locate_alias_span`] (spec
    /// FR-006/FR-007): the alias token itself, never the anchor's resolved text.
    fn span(&self, content: &str, table: &LineOffsetTable) -> Option<(usize, usize)> {
        match self {
            Self::Literal(scalar) => scalar.span(content, table),
            Self::Alias { line, col, .. } => locate_alias_span(content, table, *line, *col),
        }
    }
}

/// One `include:` entry's raw, not-yet-classified field values, collected during the event
/// stream and finalized into a [`GitlabCiDependency`] after parsing completes.
// Five independent flags, not a state machine: three recognized-non-pinnable-key presence
// markers (`has_template`/`has_remote`/`has_local`, pre-existing) plus two orthogonal
// replay-provenance markers (`abandoned`/`merge_poison`, spec 058 critic S2/M4) that can be
// set in any combination — an enum would force a false ordering/exclusivity between them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct RawEntry {
    project: Option<RawField>,
    ref_field: Option<RawField>,
    component: Option<RawField>,
    has_template: bool,
    has_remote: bool,
    has_local: bool,
    /// Set when a replay contributing to this entry (directly, or through a merge fold)
    /// was cut off by [`MAX_REPLAYED_EVENTS`] (spec 058 critic S2) — the entry is
    /// untrustworthy (a plausible-looking wrong version is worse than none, per P0) and
    /// [`GitlabCiReceiver::pop_container`]'s `IncludeEntry` arm discards it instead of
    /// pushing it to `entries`. Propagated unconditionally by [`fold_merged`], before and
    /// independent of [`Self::merge_poison`]'s early return, since a budget cutoff can
    /// occur anywhere in a merge chain regardless of whether the sequence itself is
    /// poisoned.
    abandoned: bool,
    /// Set on a [`FrameRole::MergeSequence`] frame when one of its `<<: [..]` members is
    /// not a mapping (spec 058 critic M4) — mirrors Ruby Psych's `revive_hash`, which
    /// wraps the whole sequence-merge loop in one `rescue TypeError`, so a single bad
    /// member discards the **entire** sequence's contribution (not just that member) while
    /// leaving the entry's own literal keys untouched. Deliberately a separate flag from
    /// [`Self::abandoned`]: the two failure modes have different blast radii (one entry vs.
    /// one merge sequence) and must not be conflated into one flag.
    merge_poison: bool,
}

/// Which precedence rule [`fold_merged`] applies — selected by the closing frame's
/// **parent's** role (spec 058 FR-011), never by the closing frame's own role: this is
/// what makes the transitive `MergeSource -> MergeSource` case (Psych table row 9) resolve
/// with no additional role-pair special case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FoldMode {
    /// A merged value overwrites the target's current value for that field — used when the
    /// parent frame is an [`FrameRole::IncludeEntry`] or [`FrameRole::MergeSource`]. Matches
    /// Psych's `hash.merge!` applied *at the `<<` position* in document order (own key
    /// before `<<:` loses; own key after `<<:` wins, Psych table rows 1/2).
    Overwrite,
    /// A merged value is written only into an empty slot — used when the parent frame is a
    /// [`FrameRole::MergeSequence`] (first-wins within one `<<: [*a, *b]`, Psych table row
    /// 3).
    FillIfAbsent,
}

/// The entire merge-precedence algorithm (spec 058 FR-010-FR-014), unit-testable in
/// isolation against the 10-row Psych acceptance table. Called from
/// [`GitlabCiReceiver::pop_container`] with `target` the immediate parent frame's payload
/// (exactly one hop, never searched) and `merged` the just-closed
/// [`FrameRole::MergeSource`]/[`FrameRole::MergeSequence`] frame's own payload.
///
/// `target.abandoned` is propagated unconditionally, before and independent of the
/// [`RawEntry::merge_poison`] early return (critic S2/M4): a budget cutoff and a
/// non-mapping sequence member are orthogonal failure conditions, and the abandon flag
/// must reach the enclosing entry regardless of whether this particular merge also turns
/// out to be poisoned.
fn fold_merged(target: &mut RawEntry, merged: RawEntry, mode: FoldMode) {
    target.abandoned |= merged.abandoned;
    if merged.merge_poison {
        return;
    }
    match mode {
        FoldMode::Overwrite => {
            if merged.project.is_some() {
                target.project = merged.project;
            }
            if merged.ref_field.is_some() {
                target.ref_field = merged.ref_field;
            }
            if merged.component.is_some() {
                target.component = merged.component;
            }
        }
        FoldMode::FillIfAbsent => {
            if target.project.is_none() {
                target.project = merged.project;
            }
            if target.ref_field.is_none() {
                target.ref_field = merged.ref_field;
            }
            if target.component.is_none() {
                target.component = merged.component;
            }
        }
    }
    // FR-013: distinct keys, never in conflict with project/ref/component, so there is no
    // precedence question — combined the same way under both fold modes.
    target.has_template |= merged.has_template;
    target.has_remote |= merged.has_remote;
    target.has_local |= merged.has_local;
}

/// The generic frame-stack mechanics ([`deps_core::yaml_walk::FrameStack`]) driven by
/// [`GitlabCiReceiver`], parameterized on this crate's own role/key vocabulary and
/// per-frame payload (each open `IncludeEntry`/`MergeSource`/`MergeSequence` mapping's
/// [`RawEntry`] under construction).
type Stack = FrameStack<FrameRole, PendingKey, RawEntry>;

/// Tracks one mapping-shaped anchor while its subtree streams past, so its extent within
/// [`GitlabCiReceiver::event_log`] can be recorded on its closing event — see
/// [`GitlabCiReceiver::container_anchors`]. Mirrors `deps-dart`'s shipped `RecordingFrame`
/// (`crates/deps-dart/src/parser.rs`, #910), minus its `kind` field: spec FR-002 records
/// mapping-shaped anchors only, so there is no second kind to distinguish.
struct RecordingFrame {
    anchor_id: usize,
    /// Net count of `MappingStart`/`SequenceStart` minus `MappingEnd`/`SequenceEnd` events
    /// seen since this frame opened — reaches `0` exactly when this frame's own closing
    /// event arrives (YAML containers are well-nested, so the innermost open frame's
    /// `depth` is always the one to check).
    depth: usize,
    /// Index into `event_log` of the first event *inside* this container (i.e. right after
    /// its own `MappingStart`, which is not itself replayed).
    start: usize,
}

/// Collects every `include:` entry's raw field values, gated to exactly the top-level
/// `include:` key's subtree — reachable via a literal `include:` scalar key or, since #942,
/// an alias key whose resolved anchor text is `"include"` (see [`key_for`]).
struct GitlabCiReceiver {
    stack: Stack,
    entries: Vec<RawEntry>,
    /// Anchor id -> anchored scalar text plus its own style/tag, built during this same
    /// event-stream pass (spec FR-001). Not scoped to `include:` — an anchor can be defined
    /// anywhere in the document (e.g. at the document root) and aliased later inside
    /// `include:`. Bounded by [`MAX_ANCHOR_VALUE_CHARS`]/[`MAX_ANCHOR_TABLE_ENTRIES`]
    /// (FR-002); never reset between this crate's multi-document `spec:`-header parses,
    /// since a cross-document alias id collision is already a whole-document load error in
    /// `yaml-rust2` before this code runs (spec Data Model). The style/tag metadata (mirrors
    /// the null-filtering approach used in `deps-dart`'s shipped `on_alias`, applied here to
    /// the value-position arm) lets `Event::Alias` re-check [`is_plain_null`] against the
    /// anchor's own definition, matching a literal `Event::Scalar`'s handling (#1029).
    anchors: ScalarAnchorTable<(TScalarStyle, Option<Tag>)>,
    /// Every event seen on the live pass while at least one [`RecordingFrame`] is open, in
    /// document order — the single backing store [`Self::container_anchors`]' ranges index
    /// into (spec 058 FR-001). Bounded by [`MAX_RECORDED_EVENTS`] (critic M2); stays empty
    /// for a document with no mapping-shaped anchor at all. Stream-scoped: never cleared at
    /// a document boundary, since a `container_anchors` range from an earlier document
    /// stays valid (a cross-document alias id collision is already a whole-document parse
    /// error before this code runs).
    event_log: Vec<(Event, Marker)>,
    /// Mapping-shaped anchors' extents within [`Self::event_log`], keyed by anchor id (spec
    /// FR-001/FR-002) — populated **only** for [`FrameKind::Mapping`] anchors, which is the
    /// sole and complete mechanism by which #917 (sequence-shaped container anchors) stays
    /// out of scope. Finalized by [`Self::record_event`] on each anchored mapping's closing
    /// event; resolved by [`Self::replay_anchor`].
    container_anchors: HashMap<usize, std::ops::Range<usize>>,
    /// Currently-open [`RecordingFrame`]s, one per anchored mapping whose closing event has
    /// not yet arrived — LIFO by nesting. Per-document: cleared at
    /// `Event::DocumentStart`/`Event::DocumentEnd` so an unbalanced document can never leak
    /// an open frame into the next document's depth accounting.
    recording: Vec<RecordingFrame>,
    /// Latched `true` once [`MAX_RECORDED_EVENTS`] trips (critic M2) — stops
    /// [`Self::event_log`] from growing further and prevents any *new* anchor recording
    /// from starting; existing, already-finalized [`Self::container_anchors`] entries stay
    /// valid and replayable regardless. Stream-scoped, matching `event_log`/
    /// `container_anchors` — a trip in one document also disables recording for the rest of
    /// the stream, the same safe-side trade [`Self::replay_disabled`] makes for replay.
    recording_disabled: bool,
    /// Nesting depth of container-anchor replay (see [`Self::replay_anchor`]) — `0` on the
    /// live event stream. Guards both [`Self::event_log`]/[`Self::recording`] mutation
    /// (FR-003/NFR-005: an anchor whose definition is encountered while replaying another
    /// anchor is never (re-)recorded) and, via [`Self::alias_site`], whether a captured
    /// field is alias-derived.
    replay_depth: usize,
    /// The **outermost** active replay's alias marker — spec FR-017, amended per critic S1:
    /// set only on the `replay_depth` `0`->`1` transition and cleared on the way back to
    /// `0`, so an inner alias's marker (e.g. `*a`'s marker inside a `.b: &b {<<: *a, ...}`
    /// definition, reached at `replay_depth == 2` from `- <<: *b`) can never be observed —
    /// an `Option` rather than a stack makes that bug unrepresentable rather than merely
    /// fixed. Every field captured while this is `Some` is built from it instead of the
    /// live event's own marker, and is alias-derived (`RawField::Alias`).
    alias_site: Option<Marker>,
    /// Stream-scoped [`MAX_REPLAYED_EVENTS`] budget (spec FR-026), decremented once per
    /// event dispatched inside [`Self::replay_anchor`]'s loop and checked before each
    /// dispatch — shared across every replay (nested or repeated) in the whole parse, so a
    /// fanout-driven blow-up is capped flat regardless of shape.
    replay_budget: usize,
    /// Latched `true` on budget exhaustion (spec FR-027/FR-029) — once set, every
    /// subsequent `Event::Alias` for the rest of the stream is routed through the ordinary
    /// scalar-table path with no further replay attempt, so both the successful and
    /// abandoned paths converge on identical, well-defined parent state.
    replay_disabled: bool,
}

impl GitlabCiReceiver {
    fn new() -> Self {
        Self {
            stack: Stack::new(),
            entries: Vec::new(),
            anchors: ScalarAnchorTable::new(AnchorLimits::bounded(
                MAX_ANCHOR_VALUE_CHARS,
                MAX_ANCHOR_TABLE_ENTRIES,
            )),
            event_log: Vec::new(),
            container_anchors: HashMap::new(),
            recording: Vec::new(),
            recording_disabled: false,
            replay_depth: 0,
            alias_site: None,
            replay_budget: MAX_REPLAYED_EVENTS,
            replay_disabled: false,
        }
    }

    /// Computes the role a container of kind `kind` would take if pushed right now, from
    /// the *live* stack's current top — extracted out of [`Self::push_container`] (spec
    /// FR-005) so [`Self::replay_anchor`] can consult it as a cost guard *before* replaying
    /// a subtree whose computed role would be [`FrameRole::Irrelevant`] (e.g. a job-body
    /// anchor aliased somewhere never reachable from `include:`). Never a correctness gate
    /// on its own — [`Self::push_container`] recomputes role for real on every subtree that
    /// is actually replayed, live-stack state and all.
    fn child_role(&self, kind: FrameKind) -> FrameRole {
        match self.stack.top() {
            None => {
                if kind == FrameKind::Mapping {
                    FrameRole::Root
                } else {
                    FrameRole::Irrelevant
                }
            }
            Some(parent) if parent.kind() == FrameKind::Sequence => match (*parent.role(), kind) {
                (FrameRole::IncludeValue, FrameKind::Mapping) => FrameRole::IncludeEntry,
                (FrameRole::MergeSequence, FrameKind::Mapping) => FrameRole::MergeSource,
                _ => FrameRole::Irrelevant,
            },
            Some(parent) => match (*parent.role(), *parent.pending_key(), kind) {
                (FrameRole::Root, PendingKey::Include, FrameKind::Sequence) => {
                    FrameRole::IncludeValue
                }
                (FrameRole::Root, PendingKey::Include, FrameKind::Mapping) => {
                    FrameRole::IncludeEntry
                }
                (
                    FrameRole::IncludeEntry | FrameRole::MergeSource,
                    PendingKey::Merge,
                    FrameKind::Sequence,
                ) => FrameRole::MergeSequence,
                (
                    FrameRole::IncludeEntry | FrameRole::MergeSource,
                    PendingKey::Merge,
                    FrameKind::Mapping,
                ) => FrameRole::MergeSource,
                _ => FrameRole::Irrelevant,
            },
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        // Computed from the stack's state *before* `FrameStack::push` transitions the
        // parent (a complex YAML key's subtree included) — matching `key_for`'s own
        // reliance on the parent's still-live `pending_key`/`role`.
        let role = self.child_role(kind);
        self.stack.push(kind, role, RawEntry::default());
    }

    fn pop_container(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        let closed_role = *frame.role();

        if let Some(top) = self.stack.top_mut() {
            // Critic M4, site 1: a `<<: [..]` sequence member that is not itself a mapping
            // (a nested sequence, a scalar-shaped container, or any other closed
            // non-`MergeSource` frame) poisons the whole sequence's contribution — mirrors
            // Psych's `revive_hash`, which aborts the entire sequence merge on one
            // `TypeError`. `MergeSequence`'s only container children are `Mapping ->
            // MergeSource` and `Sequence -> Irrelevant` (verified against `child_role`), so
            // this can never fire for a genuine mapping member.
            if *top.role() == FrameRole::MergeSequence && closed_role != FrameRole::MergeSource {
                top.payload.merge_poison = true;
            }
        }

        match closed_role {
            FrameRole::IncludeEntry => {
                // Critic S2: an entry interrupted by a tripped replay budget anywhere in
                // its own fold chain is untrustworthy (a plausible-looking wrong version is
                // worse than none, per P0) — discarded here rather than pushed.
                if !frame.payload.abandoned {
                    self.entries.push(frame.payload);
                }
            }
            FrameRole::MergeSource | FrameRole::MergeSequence => {
                // FR-010: exactly one hop, never searched — a `MergeSource`/`MergeSequence`
                // frame is only ever pushed as a child of `IncludeEntry`/`MergeSource`
                // (direct merge) or `MergeSequence` (a `<<: [..]` member), so it always has
                // a parent frame by role construction; the `if let` is defensive, not a
                // reachable `None` case.
                if let Some(top) = self.stack.top_mut() {
                    // FR-011: fold mode is determined by the *parent's* role, not the
                    // closing frame's own — `FillIfAbsent` only inside a `MergeSequence`,
                    // `Overwrite` everywhere else (including the transitive `MergeSource ->
                    // MergeSource` case, which needs no role-pair special case).
                    let mode = if *top.role() == FrameRole::MergeSequence {
                        FoldMode::FillIfAbsent
                    } else {
                        FoldMode::Overwrite
                    };
                    fold_merged(&mut top.payload, frame.payload, mode);
                } else {
                    debug_assert!(
                        false,
                        "a MergeSource/MergeSequence frame must always have a parent frame \
                         (FR-010's one-hop invariant)"
                    );
                }
            }
            FrameRole::Root | FrameRole::IncludeValue | FrameRole::Irrelevant => {}
        }
    }

    /// Appends every event to [`Self::event_log`], and finalizes the innermost open
    /// [`RecordingFrame`] into [`Self::container_anchors`] when its closing event arrives.
    /// Called for every event on the live (non-replay) pass, before that event's normal
    /// dispatch — mirrors `deps-dart`'s shipped `record_event` (#910), plus the
    /// [`MAX_RECORDED_EVENTS`] bound (critic M2).
    fn record_event(&mut self, event: &Event, marker: Marker) {
        if matches!(event, Event::MappingEnd | Event::SequenceEnd)
            && let Some(frame) = self.recording.pop_if(|frame| frame.depth == 0)
        {
            // Critic L1: capped independently of `MAX_RECORDED_EVENTS` — an empty mapping
            // anchor contributes a zero-length range and never trips that bound.
            if self.container_anchors.len() < MAX_CONTAINER_ANCHOR_ENTRIES {
                self.container_anchors
                    .insert(frame.anchor_id, frame.start..self.event_log.len());
            }
        }

        if !self.recording.is_empty() {
            if self.event_log.len() >= MAX_RECORDED_EVENTS {
                // Critic M2: truncating mid-recording (simply stopping the push below,
                // without also clearing `recording`) would let a still-open
                // `RecordingFrame` finalize a range whose slice is an *unbalanced* event
                // prefix — replaying that would desync the stack, reintroducing C1's
                // failure class through a different door. Abandoning every open recording
                // and latching `recording_disabled` is what makes this a safe cap:
                // already-finalized `container_anchors` entries index into a fully
                // recorded, balanced prefix and stay valid and replayable regardless.
                tracing::debug!(
                    open_recordings = self.recording.len(),
                    "gitlab-ci: container-anchor event_log exceeded MAX_RECORDED_EVENTS \
                     ({MAX_RECORDED_EVENTS}); disabling further anchor recording for this stream"
                );
                self.recording.clear();
                self.recording_disabled = true;
            } else {
                self.event_log.push((event.clone(), marker));
            }
        }

        let is_start = matches!(event, Event::MappingStart(..) | Event::SequenceStart(..));
        let is_end = matches!(event, Event::MappingEnd | Event::SequenceEnd);
        if is_start || is_end {
            for frame in &mut self.recording {
                if is_start {
                    frame.depth += 1;
                } else {
                    frame.depth -= 1;
                }
            }
        }
    }

    /// Replays anchor `anchor_id`'s recorded mapping subtree — if any — through the normal
    /// event dispatch, exactly as a live `MappingStart` in this same position would be
    /// interpreted (spec FR-004; the guard-context-bypass-safe answer verified against
    /// #909's rejected antipattern). Returns `false` when there is nothing to replay (no
    /// recorded mapping anchor under this id — EC-020's #917 fall-through included) or
    /// replay is unavailable (`replay_disabled`/[`MAX_REPLAY_DEPTH`]/[`Self::child_role`]
    /// cost guard), in which case the caller falls back to today's scalar-table path — a
    /// caller MUST NOT call `self.stack.consume_value()` when this returns `true`: both the
    /// success and the abandon path already perform that transition internally (FR-027).
    fn replay_anchor(&mut self, anchor_id: usize, marker: Marker) -> bool {
        // Review regression fix: the `container_anchors` lookup MUST run before the
        // `replay_disabled`/`MAX_REPLAY_DEPTH` guard, not after — `replay_anchor` is tried
        // speculatively for *every* alias in `Value`/`Outside` position, including an
        // ordinary scalar alias with no merge involved at all. Checking the guard first (as
        // an earlier version of this fix did) poisoned the *live top* for every such alias
        // once `replay_disabled` latched anywhere earlier in the stream, silently dropping
        // unrelated, non-merge entries — a direct NFR-003/SC-003 violation this feature
        // exists to prevent. Only an anchor id that genuinely IS a recorded container
        // anchor (i.e., would otherwise have been a legitimate replay attempt) may poison
        // anything when blocked.
        let Some(range) = self.container_anchors.get(&anchor_id).cloned() else {
            return false;
        };
        if self.replay_disabled || self.replay_depth >= MAX_REPLAY_DEPTH {
            // Critic M1 (ruled): without this, a `<<:` that cannot even attempt replay
            // (already-latched `replay_disabled`, or a merge chain deep enough to trip
            // `MAX_REPLAY_DEPTH`) would silently contribute nothing while the entry still
            // ships as if complete — a plausible-looking *wrong* version whenever an own
            // key was supposed to lose to the merge (Psych table rows 2/6's shape), worse
            // than no annotation at all (P0). Poisoning here makes all three
            // replay-unavailable guards (this one, `MAX_REPLAY_DEPTH`, and budget
            // exhaustion below) degrade identically — but only for an alias that was
            // actually a container-anchor merge attempt (see the note above).
            if let Some(top) = self.stack.top_mut() {
                top.payload.abandoned = true;
            }
            return false;
        }
        // Critic M2 (ruled): also excludes `FrameRole::Root` — a bare alias occupying an
        // entire document's root (the `Outside` position also covers an empty stack) must
        // never be replayed, closing the hole structurally rather than relying on
        // `yaml-rust2`'s own per-document anchor-name-table reset to make the shape
        // unreachable (see `test_bare_alias_at_document_root_yields_zero_dependencies_overall`).
        if matches!(
            self.child_role(FrameKind::Mapping),
            FrameRole::Irrelevant | FrameRole::Root
        ) {
            return false;
        }
        let Some(slice) = self.event_log.get(range) else {
            debug_assert!(
                false,
                "container_anchors[{anchor_id}] range is out of bounds for event_log"
            );
            return false;
        };
        let events: Vec<(Event, Marker)> = slice.to_vec();

        let depth_before = self.stack.depth();
        let outermost = self.replay_depth == 0;
        if outermost {
            self.alias_site = Some(marker);
        }
        self.replay_depth += 1;
        debug_assert!(!self.stack.is_complex_key_position());
        self.push_container(FrameKind::Mapping);

        let mut abandoned = false;
        for (event, event_marker) in events {
            if self.replay_budget == 0 {
                abandoned = true;
                break;
            }
            self.replay_budget -= 1;
            self.on_event(event, event_marker);
        }

        if abandoned {
            // Raw `pop()`, never `pop_container` — the recorded slice is balanced, so
            // stopping mid-slice leaves N frames open; `pop_container` would fold a
            // half-built payload and close the *wrong* frame, permanently desyncing the
            // stack for the rest of the document (critic C1). `FrameStack::pop`'s own
            // `consume_value()` on the unwind's final pop is exactly the transition the
            // success path's `pop_container` performs — the caller must not also call it.
            while self.stack.depth() > depth_before {
                self.stack.pop();
            }
            self.replay_disabled = true;
            // Critic S2: poison the surviving parent frame so an entry interrupted
            // mid-replay degrades to 0 records for itself, not a partial/wrong one.
            if let Some(parent) = self.stack.top_mut() {
                parent.payload.abandoned = true;
            }
        } else {
            self.pop_container();
        }
        self.replay_depth -= 1;
        if outermost {
            self.alias_site = None;
        }
        debug_assert_eq!(self.stack.depth(), depth_before);
        true
    }
}

impl MarkedEventReceiver for GitlabCiReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        // FR-003/NFR-005: guards both `event_log` appends and starting a new recording — an
        // anchor whose definition is encountered *while replaying* another anchor is never
        // (re-)recorded; it was already fully recorded during its own earlier live
        // definition, by YAML's forward-reference-only parse order.
        if self.replay_depth == 0 {
            self.record_event(&event, marker);
            // FR-002: only a `Mapping`-kind anchor is ever recorded — the sole and complete
            // mechanism by which #917 (sequence-shaped container anchors) stays out of
            // scope; there is no separate runtime check that could be deleted or bypassed.
            if let Event::MappingStart(id, _) = &event
                && *id != 0
                && !self.recording_disabled
            {
                self.recording.push(RecordingFrame {
                    anchor_id: *id,
                    depth: 0,
                    // `event_log.len()` here is exactly the index the first *inner* event
                    // will land at, regardless of whether this is a nested anchor (where
                    // `record_event` above just appended this container's own `Start` event,
                    // because an *outer* recording was already open) or the outermost one
                    // (where `recording` was empty when `record_event` ran above, so its own
                    // `Start` event was never appended at all) — either way, `event_log`'s
                    // current length is the boundary this container's own replay must start
                    // from, not before it.
                    start: self.event_log.len(),
                });
            }
        }
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => self.pop_container(),
            Event::Scalar(value, style, anchor_id, tag) => {
                // FR-001: recorded regardless of scalar position — an anchor can be
                // defined anywhere in the document (e.g. `.pin: &pin v1.2.3` at the
                // document root, entirely outside `include:`), and this is the only
                // event-stream pass this parser makes. The style/tag are kept alongside the
                // text so a later `Event::Alias` can re-run `is_plain_null` against the
                // anchor's own definition (#1029).
                if anchor_id != 0 {
                    self.anchors.record(anchor_id, &value, (style, tag.clone()));
                }
                match self.stack.scalar_position() {
                    // A bare scalar sequence item (e.g. `include: - templates/x.yml`, the
                    // `local:` shorthand) carries nothing to record. Critic M4, site 2: but
                    // a scalar member of an open `<<: [..]` sequence poisons it — Psych
                    // discards the whole sequence's contribution on one non-mapping member.
                    ScalarPosition::Outside => {
                        if let Some(top) = self.stack.top_mut()
                            && *top.role() == FrameRole::MergeSequence
                        {
                            top.payload.merge_poison = true;
                        }
                    }
                    ScalarPosition::Key => {
                        let role = self.stack.top_role_or(FrameRole::Irrelevant);
                        self.stack.observe_key(key_for(role, &value));
                    }
                    ScalarPosition::Value => {
                        if let Some(top) = self.stack.top_mut()
                            && matches!(
                                *top.role(),
                                FrameRole::IncludeEntry | FrameRole::MergeSource
                            )
                        {
                            // S1 invariant: an active replay always carries an outermost
                            // alias marker, and vice versa.
                            debug_assert_eq!(self.alias_site.is_some(), self.replay_depth > 0);
                            // FR-015/FR-016: a plain-styled empty/null-like scalar is never
                            // written as a value (never `Some("")`) — assigning `None`
                            // unconditionally is also the positional write of absence a
                            // later null must produce over an earlier merged value.
                            let field = if is_plain_null(style, tag.as_ref(), &value) {
                                None
                            } else if let Some(outer) = self.alias_site {
                                // FR-017: any field captured while a replay is active is
                                // built from the *outermost* alias marker, flagged
                                // alias-derived — never the live event's own marker, which
                                // would point at the template's own literal text.
                                Some(RawField::Alias {
                                    text: value,
                                    line: outer.line(),
                                    col: outer.col(),
                                })
                            } else {
                                Some(RawField::Literal(MarkedScalar::new(value, style, &marker)))
                            };
                            match *top.pending_key() {
                                PendingKey::Project => top.payload.project = field,
                                PendingKey::Ref => top.payload.ref_field = field,
                                PendingKey::Component => top.payload.component = field,
                                PendingKey::Template => top.payload.has_template = true,
                                PendingKey::Remote => top.payload.has_remote = true,
                                PendingKey::Local => top.payload.has_local = true,
                                PendingKey::None | PendingKey::Include | PendingKey::Merge => {}
                            }
                        }
                        self.stack.consume_value();
                    }
                }
            }
            // Spec FR-003/FR-004/FR-005 (FR-003's key-position `pending_key` amended by
            // #942): unlike a literal scalar, an alias's `awaiting_key` transition depends
            // on position alone (key vs. value) and is unconditional regardless of a table
            // hit — closing the pre-existing `? *k` key-position desync (US-003/EC-004/
            // EC-005): a key-position alias previously left the frame awaiting a key,
            // silently misreading the entry's next real scalar as a key instead of a value.
            // The *value* assigned to `pending_key` on a hit (#942) and the value-position
            // *capture* (FR-004) both additionally depend on a value-table hit. Spec 058
            // FR-030: this key-position arm is untouched by the container-anchor handling
            // added to the other two positions below.
            Event::Alias(id) => match self.stack.scalar_position() {
                ScalarPosition::Outside => {
                    // Spec 058 FR-004: `- *tpl`/`include: *tpl` (a whole-entry alias) fires
                    // here — the live top is a `Sequence` (or the stack is empty at a
                    // document-root bare alias), never a `Mapping` awaiting a value.
                    if !self.replay_anchor(id, marker) {
                        if let Some(top) = self.stack.top_mut()
                            && *top.role() == FrameRole::MergeSequence
                        {
                            // Critic M4, site 2: an unresolvable/non-mapping anchor aliased
                            // as a `<<: [..]` member poisons the sequence the same as a
                            // literal scalar member does.
                            top.payload.merge_poison = true;
                        }
                        self.stack.consume_value();
                    }
                }
                ScalarPosition::Key => {
                    // Table hit resolves the alias's text the same way a scalar key would
                    // (`key_for`); a table miss (e.g. a container anchor) falls through to
                    // `PendingKey::None`, matching `key_for`'s own catch-all for an
                    // unrecognized text key. Either way `awaiting_key` is flipped
                    // unconditionally by `observe_key` — the load-bearing half of this
                    // transition — so this alone doesn't desync the mapping regardless of a
                    // table hit or miss.
                    let role = self.stack.top_role_or(FrameRole::Irrelevant);
                    let key = self
                        .anchors
                        .get(id)
                        .map_or(PendingKey::None, |(text, _)| key_for(role, text));
                    self.stack.observe_key(key);
                }
                ScalarPosition::Value => {
                    // Spec 058 FR-004: `- <<: *tpl` (a merge key) and a nested container
                    // alias inside a replayed template both fire here — try the
                    // container-anchor replay first; a table miss/ineligible replay falls
                    // through to today's scalar-anchor lookup unchanged.
                    if self.replay_anchor(id, marker) {
                        return;
                    }
                    if let Some(top) = self.stack.top_mut()
                        && matches!(
                            *top.role(),
                            FrameRole::IncludeEntry | FrameRole::MergeSource
                        )
                        && let Some((text, (style, tag))) = self.anchors.get(id)
                    {
                        debug_assert_eq!(self.alias_site.is_some(), self.replay_depth > 0);
                        // Re-checks `is_plain_null` against the *anchor's own* style/tag
                        // (mirrors the null-filtering approach used in deps-dart's
                        // `on_alias`, applied here to the value-position arm, #1029) — the
                        // literal `Event::Scalar` arm above already filters a null-like plain
                        // scalar
                        // before it ever becomes a `RawField`, but that check happens at the
                        // anchor's definition site, not at each alias resolving it, so
                        // without re-running it here a null-like scalar anchor aliased here
                        // (`.pin: &pin ~` then `ref: *pin`) would resolve to
                        // `Some(Alias{text: "~"})` instead of being treated as absent like
                        // the literal arm treats a direct null.
                        let field = if is_plain_null(*style, tag.as_ref(), text) {
                            None
                        } else {
                            let (line, col) = match self.alias_site {
                                // FR-017: a nested scalar-anchor alias resolved while a
                                // container replay is active still takes the *outermost*
                                // marker, not this inner alias's own — see critic S1.
                                Some(outer) => (outer.line(), outer.col()),
                                None => (marker.line(), marker.col()),
                            };
                            Some(RawField::Alias {
                                text: text.to_string(),
                                line,
                                col,
                            })
                        };
                        match *top.pending_key() {
                            PendingKey::Project => top.payload.project = field,
                            PendingKey::Ref => top.payload.ref_field = field,
                            PendingKey::Component => top.payload.component = field,
                            // FR-004 scopes the capture to project/ref/component only — a
                            // `template:`/`remote:`/`local:` alias (or an unrecognized key,
                            // or `<<:`, EC-006) is left uncaptured, matching FR-005's
                            // "capture nothing" default for every other pending key.
                            PendingKey::Template
                            | PendingKey::Remote
                            | PendingKey::Local
                            | PendingKey::None
                            | PendingKey::Include
                            | PendingKey::Merge => {}
                        }
                    }
                    self.stack.consume_value();
                }
            },
            Event::DocumentStart | Event::DocumentEnd => {
                // A GitLab CI **component** file's `spec:` header form is multi-document
                // (`spec: … \n--- \n job:`); resetting here stops document 1's nesting from
                // mis-scoping document 2's top-level `include:` in either direction.
                self.stack.clear();
                // Cheap insurance (architect's multi-document hygiene note): an anchored
                // mapping should never remain open across a document boundary. `event_log`/
                // `container_anchors`/`replay_budget`/`replay_disabled`/`recording_disabled`
                // stay stream-scoped (critic M3) — only `stack` and `recording` reset here.
                debug_assert!(self.recording.is_empty());
                self.recording.clear();
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}

/// Whether `origin` is already admitted, or can be newly admitted under
/// [`MAX_HOSTS_PER_DOCUMENT`]. Mutates `admitted` on a successful new admission.
fn admit_origin(admitted: &mut HashSet<String>, origin: &str) -> bool {
    if admitted.contains(origin) {
        return true;
    }
    if admitted.len() >= MAX_HOSTS_PER_DOCUMENT {
        return false;
    }
    admitted.insert(origin.to_string());
    true
}

/// Whether `c` is a character `yaml-rust2`'s scanner accepts inside an anchor/alias name
/// (spec FR-006) — mirrors `yaml_rust2::char_traits::is_anchor_char` exactly: every
/// character except space, tab, `\n`, `\r`, NUL, the BOM (`\u{feff}`), and the flow
/// indicators `,`/`[`/`]`/`{`/`}`. Not an identifier-charset guess (`[A-Za-z0-9_-]`), which
/// would truncate a verified-parsing name like `*пин` or `*a/b@c`.
const fn is_gitlab_ci_alias_char(c: char) -> bool {
    !matches!(
        c,
        ' ' | '\t' | '\n' | '\r' | '\0' | '\u{feff}' | ',' | '[' | ']' | '{' | '}'
    )
}

/// Locates an `Event::Alias`'s own token span (`*name`) in `content` — spec FR-006/FR-007.
///
/// Anchored at the alias marker's own byte offset (via [`marker_byte_offset`], never
/// `Marker::index()`, per #879) — never a literal-text search, which finds nothing at an
/// alias site (the document text there is the token, not the anchor's resolved value).
/// `yaml-rust2`'s alias marker points exactly at the leading `*`, which this span includes
/// (FR-007): without it, an anchor name that happens to look version-shaped (`&v1 v1.2.3` /
/// `*v1`, EC-014) would satisfy `literal_span_matches` and reopen an edit path meant to stay
/// closed at an alias site. The scan is implicitly bounded to the marker's own line and is
/// char-boundary-safe: [`is_gitlab_ci_alias_char`] excludes `\n`/`\r`, and advancing by
/// `char::len_utf8()` never splits a multi-byte character.
///
/// Returns `None` if `(line, col)` does not resolve to a `*` (should not happen for a real
/// `Event::Alias` marker, but this is a defensive guard, not an assumed invariant).
fn locate_alias_span(
    content: &str,
    table: &LineOffsetTable,
    line: usize,
    col: usize,
) -> Option<(usize, usize)> {
    let start = marker_byte_offset(content, table, line, col);
    let rest = content.get(start..)?;
    let mut chars = rest.chars();
    if chars.next() != Some('*') {
        return None;
    }
    let mut end = start + '*'.len_utf8();
    for c in chars.take_while(|&c| is_gitlab_ci_alias_char(c)) {
        end += c.len_utf8();
    }
    Some((start, end))
}

/// Classifies a `project:` include's `ref:` text — the same two-way SHA/tag-shape test
/// `deps-github-actions` uses, with no third "confirmed by the registry" state (this crate
/// has no per-repository tag/SHA cross-reference the way GHA's `TagIndex` does).
fn classify_project_pin(ref_text: &str) -> PinStyle {
    if is_full_sha(ref_text) {
        PinStyle::Sha
    } else if is_tag_shaped(ref_text) {
        PinStyle::Tag
    } else {
        PinStyle::Branch
    }
}

fn host_qualified_name(host: &HostRef, project_path: &str, component_name: Option<&str>) -> String {
    let base = match host {
        HostRef::Literal(h) => format!("{}/{project_path}", h.host()),
        HostRef::Unresolved(_) | HostRef::CapacityRefused(_) | HostRef::PolicyBlocked { .. } => {
            project_path.to_string()
        }
    };
    match component_name {
        Some(name) => format!("{base}/{name}"),
        None => base,
    }
}

fn build_source_and_route(
    host: &HostRef,
    endpoint: EndpointKind,
) -> (DependencySource, Option<(String, GitlabRoute)>) {
    match host {
        HostRef::Literal(h) => {
            let route_key =
                deps_core::hash_routing_key("gitlab", [h.origin(), endpoint.as_str()].into_iter());
            let route = GitlabRoute {
                origin: h.origin().to_string(),
                endpoint,
            };
            (
                DependencySource::AlternateRegistry {
                    index: route_key.clone(),
                    mirrors_crates_io: false,
                },
                Some((route_key, route)),
            )
        }
        HostRef::Unresolved(raw) => (DependencySource::CustomRegistry { url: raw.clone() }, None),
        HostRef::CapacityRefused(origin) => (
            DependencySource::CustomRegistry {
                url: origin.clone(),
            },
            None,
        ),
        HostRef::PolicyBlocked { raw, .. } => {
            (DependencySource::CustomRegistry { url: raw.clone() }, None)
        }
    }
}

/// Declaration key shared by every dependency resolving through the
/// `registries.gitlab_instance_host` setting (#967 S3): a config-global setting applies
/// identically to every dependency it affects, so `deps_core::lsp_helpers`' diagnostic
/// grouping collapses them into one occurrence instead of fanning out per dependency.
const INSTANCE_HOST_DECLARATION_KEY: &str = "gitlab_instance_host";

fn resolve_project_host(instance_host: &GitlabInstanceHost) -> HostRef {
    resolve_instance_host_ref(instance_host, CI_SERVER_FQDN)
}

/// Resolves a `$CI_SERVER_FQDN`-relative host (either a `project:` include, which always
/// resolves this way, or a `$`-prefixed `component:` host expression) against the
/// `registries.gitlab_instance_host` setting, distinguishing a policy-blocked value (issue
/// #967) from a genuinely unset/malformed one.
///
/// `raw` is used only for the `Unresolved` case (the unresolved expression as written in the
/// manifest, e.g. `$CI_SERVER_FQDN`) — the `PolicyBlocked` case instead carries the actual
/// configured `registries.gitlab_instance_host` string from [`InstanceHostOutcome::Blocked`]
/// (#967 S1): that setting, not the manifest expression, is the value a user must change.
///
/// Resolves against one [`GitlabInstanceHost::resolve`] call (#967 M1): matching `get()` and
/// a separate blocked-check call could observe two different outcomes if the setting or
/// policy changed between them.
fn resolve_instance_host_ref(instance_host: &GitlabInstanceHost, raw: &str) -> HostRef {
    match instance_host.resolve() {
        InstanceHostOutcome::Valid(host) => HostRef::Literal(host),
        InstanceHostOutcome::Blocked {
            raw: configured_raw,
            class,
        } => HostRef::PolicyBlocked {
            raw: configured_raw,
            class,
            declaration_key: INSTANCE_HOST_DECLARATION_KEY.to_string(),
        },
        InstanceHostOutcome::Unset | InstanceHostOutcome::Invalid => {
            HostRef::Unresolved(raw.to_string())
        }
    }
}

fn resolve_component_host(
    host_expr: &str,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
    admitted_origins: &mut HashSet<String>,
) -> HostRef {
    if host_expr.starts_with('$') {
        return resolve_instance_host_ref(instance_host, host_expr);
    }
    match GitlabHost::parse(host_expr, policy) {
        Ok(host) if admit_origin(admitted_origins, host.origin()) => HostRef::Literal(host),
        // M-a (#466 review): the host itself validated fine — only the per-document cap
        // refused it — so this is `CapacityRefused`, not `Unresolved`: its origin is a known,
        // usable value, unlike a genuinely unresolvable host.
        Ok(host) => {
            warn_rejected_value(
                "admit_origin",
                "gitlab-ci component: host (per-document cap)",
                host_expr,
            );
            HostRef::CapacityRefused(host.origin().to_string())
        }
        Err(deps_core::net_policy::IndexUrlError::BlockedHost { class }) => {
            HostRef::PolicyBlocked {
                raw: host_expr.to_string(),
                class,
                // #967 S3: one per distinct literal host string, unlike the instance-setting
                // path's single shared key — two different `component:` hosts blocked by policy
                // are two independently declared literals, not one config declaration.
                // Lowercased (code-review follow-up): hostnames are case-insensitive per
                // DNS/HTTP, so `FOO.internal` and `foo.internal` must collapse into the same
                // declaration, not fan out into two.
                declaration_key: format!("component-host:{}", host_expr.to_ascii_lowercase()),
            }
        }
        Err(_) => HostRef::Unresolved(host_expr.to_string()),
    }
}

fn build_project_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    instance_host: &GitlabInstanceHost,
    project_field: RawField,
    ref_field: Option<RawField>,
) -> Option<(GitlabCiDependency, Option<(String, GitlabRoute)>)> {
    if !is_valid_gitlab_coordinate(project_field.text()) {
        warn_rejected_value(
            "is_valid_gitlab_coordinate",
            "gitlab-ci project: value",
            project_field.text(),
        );
        return None;
    }

    let (raw_start, raw_end) = project_field.span(content, line_table)?;
    let name_range = byte_span_to_range(content, line_table, raw_start, raw_end);
    let project_is_plain = project_field.is_plain();
    let project_is_alias = project_field.is_alias();

    let host = resolve_project_host(instance_host);
    let name = host_qualified_name(&host, project_field.text(), None);

    let (version_req, version_range, pin, is_plain_scalar, is_alias_occurrence) = match ref_field {
        Some(ref_field) => {
            let (rs, re) = ref_field.span(content, line_table)?;
            let range = byte_span_to_range(content, line_table, rs, re);
            let pin = classify_project_pin(ref_field.text());
            let plain = ref_field.is_plain();
            // #912 critic S1: scoped to the field that actually backs `version_range` —
            // every SHA-pin/completion write path this flag gates only ever touches
            // `version_range` (never `name_range`, which `literal_span_matches` already
            // can't satisfy against a host-qualified name regardless). An OR with
            // `project_is_alias` here withheld a fully auto-fixable literal `ref:` and
            // appended a factually false "no automated fix available" suffix whenever
            // `project:` alone was aliased.
            let is_alias = ref_field.is_alias();
            (
                Some(ref_field.into_text().into()),
                Some(range),
                Some(pin),
                plain,
                is_alias,
            )
        }
        None => (None, None, None, project_is_plain, project_is_alias),
    };

    let (source, route) = build_source_and_route(&host, EndpointKind::Tags);

    Some((
        GitlabCiDependency {
            name: name.into(),
            name_range,
            version_req,
            version_range,
            version_literal: None,
            source,
            is_plain_scalar,
            is_alias_occurrence,
            kind: IncludeKind::Project,
            host,
            pin,
            project_path: project_field.into_text(),
        },
        route,
    ))
}

fn build_component_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
    admitted_origins: &mut HashSet<String>,
    component_field: RawField,
) -> Option<(GitlabCiDependency, Option<(String, GitlabRoute)>)> {
    let is_alias_occurrence = component_field.is_alias();
    let raw_component = component_field.text();
    let Some((prefix, ref_text)) = raw_component.split_once('@') else {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (missing @version)",
            raw_component,
        );
        return None;
    };
    if ref_text.is_empty() {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (empty version)",
            raw_component,
        );
        return None;
    }

    // `<fqdn>/<full-path-to-component-directory>@<version>`: the last path segment before
    // `@` is the component name (GitLab's own documented shape — see this crate's `lib.rs`
    // pin-contract table); everything between the host and the component name is the
    // project path. Minimum 4 segments: host + at least a 2-segment project path + the
    // component name.
    let segments: Vec<&str> = prefix.split('/').collect();
    if segments.len() < 4 {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (too few path segments)",
            raw_component,
        );
        return None;
    }
    let [host_expr, project_segments @ .., component_name] = segments.as_slice() else {
        return None;
    };
    let (host_expr, component_name) = (*host_expr, *component_name);
    let project_path = project_segments.join("/");
    if !is_valid_gitlab_coordinate(&project_path) || !is_valid_path_segment(component_name) {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (malformed path)",
            raw_component,
        );
        return None;
    }

    let (raw_start, raw_end) = component_field.span(content, line_table)?;
    // FR-008: at an alias site the document text is the alias token itself (`*x`), not
    // `component@version` — `name_end = raw_start + prefix.len()` would slice into
    // unrelated document text, so both ranges collapse onto the whole alias-token span
    // instead of the usual name/version split.
    let (name_range, version_range) = if is_alias_occurrence {
        let alias_range = byte_span_to_range(content, line_table, raw_start, raw_end);
        (alias_range, alias_range)
    } else {
        let name_end = raw_start + prefix.len();
        let ref_start = name_end + 1; // skip '@'
        (
            byte_span_to_range(content, line_table, raw_start, name_end),
            byte_span_to_range(content, line_table, ref_start, raw_end),
        )
    };

    let host = resolve_component_host(host_expr, policy, instance_host, admitted_origins);
    let name = host_qualified_name(&host, &project_path, Some(component_name));
    let pin = crate::component::classify_component_pin_style(ref_text);
    let (source, route) = build_source_and_route(&host, EndpointKind::Releases);

    Some((
        GitlabCiDependency {
            name: name.into(),
            name_range,
            version_req: Some(ref_text.into()),
            version_range: Some(version_range),
            version_literal: None,
            source,
            is_plain_scalar: component_field.is_plain(),
            is_alias_occurrence,
            kind: IncludeKind::Component,
            host,
            pin: Some(pin),
            project_path,
        },
        route,
    ))
}

fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
    admitted_origins: &mut HashSet<String>,
    entry: RawEntry,
) -> Option<(GitlabCiDependency, Option<(String, GitlabRoute)>)> {
    // `template:`/`remote:`/a `local:` key are recognized and skipped gracefully — not
    // version-pinnable (spec FR-003).
    if entry.has_template || entry.has_remote || entry.has_local {
        return None;
    }
    if let Some(component_field) = entry.component {
        return build_component_dependency(
            content,
            line_table,
            policy,
            instance_host,
            admitted_origins,
            component_field,
        );
    }
    if let Some(project_field) = entry.project {
        return build_project_dependency(
            content,
            line_table,
            instance_host,
            project_field,
            entry.ref_field,
        );
    }
    tracing::debug!("gitlab-ci include entry has neither project: nor component:; skipping");
    None
}

/// Parses a `.gitlab-ci.yml`-syntax file and returns every `include:` dependency found,
/// with LSP position tracking, host resolution, and routing.
///
/// Gated first by [`deps_core::check_yaml_nesting_depth`]/[`deps_core::check_yaml_expansion`],
/// which return a real [`DepsError::ParseError`]. A downstream YAML syntax error degrades to
/// an **empty** [`GitlabCiParseResult`] (logged at `debug`) rather than propagating.
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] only when `content` exceeds the shared YAML
/// nesting-depth or expansion-size gate.
///
/// # Examples
///
/// ```
/// use deps_core::Dependency;
/// use deps_core::net_policy::RegistryAccessPolicy;
/// use deps_gitlab_ci::GitlabInstanceHost;
/// use deps_gitlab_ci::parse_gitlab_ci_yaml;
/// use std::sync::{Arc, RwLock};
///
/// let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
/// let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
/// let policy = RegistryAccessPolicy::default();
/// let instance_host = GitlabInstanceHost::new(Arc::new(RwLock::new(None)), Arc::new(policy));
///
/// let policy = RegistryAccessPolicy::default();
/// let result = parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();
/// assert_eq!(result.dependencies.len(), 1);
/// ```
pub fn parse_gitlab_ci_yaml(
    content: &str,
    uri: &Url,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
) -> Result<GitlabCiParseResult> {
    if let Err(depth) =
        deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "gitlab-ci.yml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_YAML_NESTING_DEPTH
            ))),
        });
    }
    if let Err(bytes) = deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES)
    {
        return Err(DepsError::ParseError {
            file_type: "gitlab-ci.yml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML expansion {bytes} bytes exceeds maximum of {} bytes",
                deps_core::MAX_YAML_EXPANDED_BYTES
            ))),
        });
    }

    let mut receiver = GitlabCiReceiver::new();
    let mut parser = Parser::new_from_str(content);
    // `multi: true` — unlike `deps-github-actions`'s workflow files, a GitLab CI
    // **component** file's `spec:` header form is genuinely multi-document
    // (`spec: … \n--- \n job:`); `Parser::load(_, false)` stops after the first document.
    if let Err(e) = parser.load(&mut receiver, true) {
        tracing::debug!(error = %e, "failed to parse GitLab CI YAML, treating as empty");
        return Ok(GitlabCiParseResult {
            dependencies: Vec::new(),
            routes: Vec::new(),
            uri: uri.clone(),
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        });
    }

    let line_table = LineOffsetTable::new(content);
    let mut admitted_origins = HashSet::new();
    let mut seen_route_keys = HashSet::new();
    let mut routes = Vec::new();
    let mut dependencies = Vec::new();
    // #796: checked before `build_dependency` (the expensive step — policy/host
    // resolution, range computation) rather than after, so an entry beyond the ceiling
    // never reaches it.
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    for entry in receiver.entries {
        if !budget.allow() {
            continue;
        }
        let Some((dep, route)) = build_dependency(
            content,
            &line_table,
            policy,
            instance_host,
            &mut admitted_origins,
            entry,
        ) else {
            continue;
        };
        if let Some((key, route_value)) = route
            && seen_route_keys.insert(key.clone())
        {
            routes.push((key, route_value));
        }
        dependencies.push(dep);
    }

    // Issue #967: a `HostRef::PolicyBlocked` dependency is reported through
    // `ParseResult::blocked_registries` (an informational diagnostic naming the blocked host
    // class) rather than through `crate::ecosystem`'s unresolved-host diagnostic, which would
    // misattribute the cause to `registries.gitlab_instance_host` being unset.
    let blocked_registries = dependencies
        .iter()
        .filter_map(|dep| match &dep.host {
            HostRef::PolicyBlocked {
                raw,
                class,
                declaration_key,
            } => Some(deps_core::BlockedRegistryOccurrence {
                range: dep.name_range,
                class: *class,
                raw_value: raw.clone(),
                declaration_key: declaration_key.clone(),
            }),
            HostRef::Literal(_) | HostRef::Unresolved(_) | HostRef::CapacityRefused(_) => None,
        })
        .collect();

    Ok(GitlabCiParseResult {
        dependencies,
        routes,
        uri: uri.clone(),
        dependency_truncation: budget.truncation(),
        blocked_registries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::Dependency;
    use deps_core::net_policy::WorkspaceRegistryAccess;
    use deps_core::position::Range;
    use std::sync::{Arc, RwLock};

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/repo/.gitlab-ci.yml")
    }

    fn ctx() -> (RegistryAccessPolicy, GitlabInstanceHost) {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);
        let instance_host = GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(RegistryAccessPolicy::new(
                WorkspaceRegistryAccess::PublicOnly,
            )),
        );
        (policy, instance_host)
    }

    fn ctx_with_instance_host(host: &str) -> (RegistryAccessPolicy, GitlabInstanceHost) {
        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);
        let instance_host = GitlabInstanceHost::new(
            Arc::new(RwLock::new(Some(host.to_string()))),
            Arc::new(RegistryAccessPolicy::new(
                WorkspaceRegistryAccess::PublicOnly,
            )),
        );
        (policy, instance_host)
    }

    #[allow(clippy::string_slice)] // single-line ASCII fixtures
    fn slice(content: &str, range: Range) -> String {
        let start_line = range.start.line as usize;
        let end_line = range.end.line as usize;
        if start_line == end_line {
            let line = content.lines().nth(start_line).unwrap();
            line[range.start.character as usize..range.end.character as usize].to_string()
        } else {
            panic!("multi-line ranges not supported by this test helper");
        }
    }

    #[test]
    fn test_project_ref_include_parses() {
        let (policy, instance_host) = ctx_with_instance_host("gitlab.com");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.kind, IncludeKind::Project);
        assert_eq!(slice(content, dep.name_range), "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
        assert_eq!(dep.pin, Some(PinStyle::Tag));
        assert!(matches!(dep.host, HostRef::Literal(_)));
        assert_eq!(dep.name(), "gitlab.com/org/proj");
        assert!(matches!(
            dep.source(),
            DependencySource::AlternateRegistry { .. }
        ));
        assert_eq!(result.routes.len(), 1);
    }

    #[test]
    fn test_project_ref_unresolved_host_when_instance_host_unset() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert!(matches!(dep.host, HostRef::Unresolved(_)));
        assert!(matches!(
            dep.source(),
            DependencySource::CustomRegistry { .. }
        ));
        assert_eq!(dep.name(), "org/proj");
        assert!(result.routes.is_empty());
    }

    #[test]
    fn test_project_sha_ref() {
        let (policy, instance_host) = ctx();
        let sha = "a".repeat(40);
        let content = format!("include:\n  - project: org/proj\n    ref: {sha}\n");
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies[0].pin, Some(PinStyle::Sha));
    }

    #[test]
    fn test_project_branch_ref() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    ref: main\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies[0].pin, Some(PinStyle::Branch));
    }

    #[test]
    fn test_project_no_ref_has_no_pin() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert!(dep.pin.is_none());
        assert!(dep.version_range().is_none());
    }

    #[test]
    fn test_component_include_parses_exact_version() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.kind, IncludeKind::Component);
        assert_eq!(slice(content, dep.name_range), "gitlab.com/org/proj/comp");
        assert_eq!(slice(content, dep.version_range().unwrap()), "1.0.0");
        assert_eq!(dep.name(), "gitlab.com/org/proj/comp");
        assert_eq!(dep.project_path, "org/proj");
        assert!(matches!(dep.host, HostRef::Literal(_)));
    }

    #[test]
    fn test_component_ci_server_fqdn_unresolved_when_instance_host_unset() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: $CI_SERVER_FQDN/org/proj/comp@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.host, HostRef::Unresolved("$CI_SERVER_FQDN".to_string()));
        assert!(matches!(
            dep.source(),
            DependencySource::CustomRegistry { .. }
        ));
    }

    #[test]
    fn test_component_ci_server_fqdn_resolves_when_instance_host_set() {
        let (policy, instance_host) = ctx_with_instance_host("gitlab.mycorp.dev");
        let content = "include:\n  - component: $CI_SERVER_FQDN/org/proj/comp@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "gitlab.mycorp.dev/org/proj/comp");
    }

    /// Issue #967: a `component:` host blocked by `registries.workspace_registries` must
    /// resolve to `HostRef::PolicyBlocked` (not `HostRef::Unresolved`) and populate
    /// `blocked_registries`, so the diagnostic never misattributes the cause to
    /// `registries.gitlab_instance_host`.
    #[test]
    fn test_component_literal_host_blocked_by_policy_populates_blocked_registries() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: 10.0.0.1/org/proj/comp@1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert!(matches!(
            &dep.host,
            HostRef::PolicyBlocked { raw, .. } if raw == "10.0.0.1"
        ));
        assert!(matches!(
            dep.source(),
            DependencySource::CustomRegistry { .. }
        ));
        assert_eq!(result.blocked_registries.len(), 1);
        let occurrence = &result.blocked_registries[0];
        assert_eq!(
            occurrence.class,
            deps_core::net_policy::HostClass::PrivateV4
        );
        assert_eq!(occurrence.raw_value, "10.0.0.1");
        // #967 S3: one declaration key per distinct literal `component:` host string.
        assert_eq!(occurrence.declaration_key, "component-host:10.0.0.1");
        assert!(result.routes.is_empty());
    }

    /// Issue #967, `$CI_SERVER_FQDN`-relative path: `registries.gitlab_instance_host` itself
    /// blocked by policy must resolve to `HostRef::PolicyBlocked`, not `HostRef::Unresolved`,
    /// and (S1) the diagnostic must name the real configured setting value — not the
    /// `$CI_SERVER_FQDN` placeholder, which appears nowhere in the user's file or config.
    #[test]
    fn test_component_ci_server_fqdn_blocked_instance_host_populates_blocked_registries() {
        let (policy, instance_host) = ctx_with_instance_host("10.0.0.1");
        let content = "include:\n  - component: $CI_SERVER_FQDN/org/proj/comp@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.host,
            HostRef::PolicyBlocked {
                raw: "10.0.0.1".to_string(),
                class: deps_core::net_policy::HostClass::PrivateV4,
                declaration_key: INSTANCE_HOST_DECLARATION_KEY.to_string(),
            }
        );
        assert_eq!(result.blocked_registries.len(), 1);
        assert_eq!(result.blocked_registries[0].raw_value, "10.0.0.1");
    }

    /// Issue #967, `project:` path: same as the component test above, but for the
    /// unconditional `$CI_SERVER_FQDN` resolution every `project:` include goes through.
    #[test]
    fn test_project_ref_blocked_instance_host_populates_blocked_registries() {
        let (policy, instance_host) = ctx_with_instance_host("10.0.0.1");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        let dep = &result.dependencies[0];
        assert!(matches!(dep.host, HostRef::PolicyBlocked { .. }));
        assert_eq!(dep.name(), "org/proj");
        assert_eq!(result.blocked_registries.len(), 1);
        // S1: the diagnostic must name the real configured host, not `$CI_SERVER_FQDN`.
        assert_eq!(result.blocked_registries[0].raw_value, "10.0.0.1");
        assert_eq!(
            result.blocked_registries[0].declaration_key,
            INSTANCE_HOST_DECLARATION_KEY
        );
        assert!(result.routes.is_empty());
    }

    /// Issue #967 S3: a `project:` include and a `$`-relative `component:` include, both
    /// resolving through the same blocked `registries.gitlab_instance_host` setting, must
    /// share one declaration key — the shared `deps_core::lsp_helpers` diagnostic grouping
    /// collapses same-key occurrences, so this file must not fan out into two diagnostics for
    /// what is really one blocked setting.
    #[test]
    fn test_project_and_component_instance_host_share_one_declaration_key() {
        let (policy, instance_host) = ctx_with_instance_host("10.0.0.1");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n  - component: $CI_SERVER_FQDN/org/proj/comp@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.blocked_registries.len(), 2);
        let keys: std::collections::HashSet<_> = result
            .blocked_registries
            .iter()
            .map(|occ| occ.declaration_key.as_str())
            .collect();
        assert_eq!(
            keys,
            std::collections::HashSet::from([INSTANCE_HOST_DECLARATION_KEY])
        );
    }

    /// Code-review follow-up to #967 S3: two `component:` hosts blocked by the same policy,
    /// differing only in letter case, must collapse into one declaration key — hostnames are
    /// case-insensitive per DNS/HTTP, so `FOO.internal` and `foo.internal` are the same
    /// declaration, not two independently-declared literals.
    #[test]
    fn test_component_literal_hosts_differing_only_in_case_share_one_declaration_key() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: FOO.internal/org/a/c@1.0\n  - component: foo.internal/org/b/c@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.blocked_registries.len(), 2);
        let keys: std::collections::HashSet<_> = result
            .blocked_registries
            .iter()
            .map(|occ| occ.declaration_key.as_str())
            .collect();
        assert_eq!(
            keys,
            std::collections::HashSet::from(["component-host:foo.internal"])
        );
    }

    #[test]
    fn test_component_missing_version_is_malformed() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: gitlab.com/org/proj/comp\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_component_too_few_segments_is_malformed() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - component: gitlab.com/proj@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_template_include_skipped() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - template: Security/SAST.gitlab-ci.yml\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_remote_include_skipped() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - remote: 'https://example.com/ci.yml'\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_local_key_include_skipped() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - local: 'ci/other.yml'\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_bare_string_local_shorthand_skipped() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - 'ci/other.yml'\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_single_mapping_include_form() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  project: org/proj\n  ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_bare_string_include_shorthand_at_top_skipped() {
        let (policy, instance_host) = ctx();
        let content = "include: 'ci/other.yml'\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_no_include_key_yields_empty() {
        let (policy, instance_host) = ctx();
        let content = "stages:\n  - build\n  - test\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    // --- deps-lsp#908: complex YAML key (`? <mapping>`/`? <sequence>`) no longer desyncs
    // the root mapping's key/value alternation — the shared `FrameStack` walker's fix,
    // which `deps-dart` already had before this refactor.

    #[test]
    fn test_complex_mapping_key_before_include_does_not_desync_root_mapping() {
        let (policy, instance_host) = ctx();
        // The root mapping's first entry uses an explicit complex key (a mapping key) —
        // before the shared walker, popping its subtree unconditionally reset the root to
        // "awaiting a key" instead of "awaiting this entry's value", so the complex key's
        // own value scalar was misread as the next key, and every following key/value pair
        // (including `include:`) desynced.
        let content = "? { a: 1 }\n: unused\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].project_path, "org/proj");
    }

    #[test]
    fn test_complex_sequence_key_before_include_does_not_desync_root_mapping() {
        let (policy, instance_host) = ctx();
        let content = "? [a, b]\n: unused\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].project_path, "org/proj");
    }

    #[test]
    fn test_image_and_services_never_parsed() {
        let (policy, instance_host) = ctx();
        let content = "image: alpine:3.18\nservices:\n  - postgres:14\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_duplicate_includes_get_distinct_ranges() {
        let (policy, instance_host) = ctx();
        let content =
            "include:\n  - project: org/a\n    ref: v1.0.0\n  - project: org/b\n    ref: v2.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_ne!(
            result.dependencies[0].version_range(),
            result.dependencies[1].version_range()
        );
    }

    #[test]
    fn test_multi_document_include_in_second_document_found() {
        let (policy, instance_host) = ctx();
        let content = "spec:\n  inputs:\n    version:\n---\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1);
    }

    #[test]
    fn test_multi_document_nested_key_in_second_document_not_mistaken_for_top_level() {
        let (policy, instance_host) = ctx();
        // Document 1 has no `include:` at its own top level; document 2's `include:` is
        // nested inside `job:`, which must NOT be mistaken for a top-level key.
        let content = "spec:\n  inputs:\n    version:\n---\njob:\n  include:\n    - project: org/proj\n      ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_deeply_nested_yaml_rejected_as_parse_error() {
        let (policy, instance_host) = ctx();
        let payload = format!("{}1", "- ".repeat(deps_core::MAX_YAML_NESTING_DEPTH + 1));
        let result = parse_gitlab_ci_yaml(&payload, &test_uri(), &policy, &instance_host);
        assert!(matches!(result, Err(DepsError::ParseError { .. })));
    }

    #[test]
    fn test_invalid_yaml_returns_empty_result_not_error() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - [unterminated\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_empty_content() {
        let (policy, instance_host) = ctx();
        let result = parse_gitlab_ci_yaml("", &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_host_fan_out_cap_admits_at_most_eight_distinct_hosts() {
        let (policy, instance_host) = ctx();
        let mut content = String::from("include:\n");
        for i in 0..12 {
            content.push_str(&format!(
                "  - component: host{i}.example.com/org/proj/comp@1.0\n"
            ));
        }
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 12);
        let resolved = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.host, HostRef::Literal(_)))
            .count();
        assert_eq!(resolved, MAX_HOSTS_PER_DOCUMENT);
        // M-a (#466 review): a per-document cap refusal is `CapacityRefused`, not
        // `Unresolved` — the host itself validated fine.
        let capacity_refused = result
            .dependencies
            .iter()
            .filter(|d| matches!(d.host, HostRef::CapacityRefused(_)))
            .count();
        assert_eq!(capacity_refused, 12 - MAX_HOSTS_PER_DOCUMENT);
    }

    #[test]
    fn test_project_and_component_same_project_produce_distinct_names() {
        // §3.1's documented residual collision case: same host + same project path but
        // different `IncludeKind` (Tags vs Releases route) still coexist as distinct
        // `PackageName`s as long as the component keeps its trailing component segment.
        let (policy, instance_host) = ctx_with_instance_host("gitlab.com");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n  - component: gitlab.com/org/proj/comp@1.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_ne!(result.dependencies[0].name(), result.dependencies[1].name());
    }

    #[test]
    fn test_routes_deduplicated_across_dependencies_sharing_a_host() {
        let (policy, instance_host) = ctx_with_instance_host("gitlab.com");
        let content =
            "include:\n  - project: org/a\n    ref: v1.0.0\n  - project: org/b\n    ref: v2.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        // Both `project:` includes resolve to the same instance host and the same
        // (origin, Tags) route, so exactly one route entry is registered.
        assert_eq!(result.routes.len(), 1);
    }

    // --- issue #879: yaml-rust2 block-scalar byte-offset drift ---
    //
    // See `deps_github_actions::parser`'s identical section for the root-cause summary;
    // GitLab CI is affected the same way since `build_project_dependency` resolves spans
    // via the same shared `deps_core::lsp_helpers::marker_byte_offset`. A job's `script:`
    // block scalar is never itself visited for dependency extraction (`GitlabCiReceiver`
    // only tracks the top-level `include:` subtree), but the marker corruption it caused
    // upstream previously desynced every later scalar's resolved offset regardless.
    // Content lines here are long enough (well over 16 chars around the multi-byte char)
    // to force yaml-rust2's lookahead-buffer refill — the actual trigger condition, not
    // merely "any non-ASCII char present".

    #[test]
    fn test_issue_879_literal_block_scalar_multibyte_then_include_resolves() {
        let (policy, instance_host) = ctx();
        let content = "some_job:\n  script: |\n    echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.name_range), "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    #[test]
    fn test_issue_879_folded_block_scalar_multibyte_then_include_resolves() {
        let (policy, instance_host) = ctx();
        let content = "some_job:\n  script: >\n    echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    #[test]
    fn test_issue_879_multiple_block_scalars_drift_does_not_compound() {
        // Two prior block scalars each containing a multi-byte char must not accumulate
        // drift onto the `include:` entry's resolved offset.
        let (policy, instance_host) = ctx();
        let content = "job_one:\n  script: |\n    echo one \u{2014} first multibyte char here padded to be long enough for the scanner buffer refill\njob_two:\n  script: |\n    echo two \u{2014} second multibyte char here also padded long enough for another scanner buffer refill\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    #[test]
    fn test_issue_879_include_before_multibyte_block_scalar_unaffected() {
        // Regression guard: an `include:` entry preceding the block scalar was never
        // affected by the drift — must keep working exactly as before the fix.
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\nsome_job:\n  script: |\n    echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    #[test]
    fn test_issue_879_multibyte_on_last_line_of_block_scalar_then_include() {
        let (policy, instance_host) = ctx();
        let content = "some_job:\n  script: |\n    first regular line long enough for buffer padding without any multibyte characters at all\n    echo hello \u{2014} world this final line of the block scalar is long enough too\ninclude:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    // --- #912: scalar YAML anchor/alias support inside `include:` (spec 056) ---

    /// EC-001/US-001/SC-001: a scalar anchor used as `ref:`, aliased across two `include:`
    /// entries, produces two dependency records — one per entry — each with its own
    /// `version_range` at its own alias token, never collapsed onto one another or onto the
    /// anchor's definition.
    #[test]
    fn test_ref_aliased_to_scalar_anchor_produces_one_dependency_per_entry() {
        let (policy, instance_host) = ctx();
        let content = ".pin: &pin v1.2.3\ninclude:\n  - project: group/project-a\n    ref: *pin\n  - project: group/project-b\n    ref: *pin\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        for dep in &result.dependencies {
            assert!(dep.is_alias_occurrence);
            assert_eq!(slice(content, dep.version_range().unwrap()), "*pin");
            assert_eq!(
                dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
                Some("v1.2.3")
            );
            assert_eq!(dep.pin, Some(PinStyle::Tag));
        }
        assert_ne!(
            result.dependencies[0].version_range(),
            result.dependencies[1].version_range()
        );
    }

    /// EC-002: `project: *proj` — a scalar anchor aliased directly as the `project:` value
    /// — today a total dependency loss, fixed the same way as EC-001.
    #[test]
    fn test_project_aliased_to_scalar_anchor_resolves() {
        let (policy, instance_host) = ctx();
        let content =
            ".proj: &proj group/project-a\ninclude:\n  - project: *proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        // #912 critic S1: `ref:` here is a literal, so `is_alias_occurrence` (scoped to
        // the field backing `version_range`) must be `false` — an aliased `project:`
        // alone must not withhold this fully auto-fixable `ref:`'s SHA-pin quickfix.
        assert!(!dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "group/project-a");
        assert_eq!(slice(content, dep.name_range), "*proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    /// #912 critic S1 regression: an aliased `project:` next to a **literal** `ref:` must
    /// not widen `is_alias_occurrence` — only a field that actually backs `version_range`
    /// (here, the literal `ref:`) may set it, so this dependency is NOT an alias
    /// occurrence and every downstream SHA-pin/completion path stays available for it.
    #[test]
    fn test_project_aliased_ref_literal_is_not_an_alias_occurrence() {
        let (policy, instance_host) = ctx();
        let content =
            ".proj: &proj group/project-a\ninclude:\n  - project: *proj\n    ref: v2.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert!(!result.dependencies[0].is_alias_occurrence);
    }

    /// #912 critic S1: conversely, an aliased `ref:` next to a literal `project:` IS an
    /// alias occurrence — `version_range` (what every gated write path targets) is the
    /// alias token here.
    #[test]
    fn test_literal_project_aliased_ref_is_an_alias_occurrence() {
        let (policy, instance_host) = ctx();
        let content = ".pin: &pin v1.2.3\ninclude:\n  - project: org/proj\n    ref: *pin\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert!(result.dependencies[0].is_alias_occurrence);
    }

    /// EC-003/FR-008: `component: *c` — both `name_range` and `version_range` span the
    /// alias token itself, and `build_component_dependency`'s normal `prefix.len()` offset
    /// arithmetic is not run against the 2-character alias site.
    #[test]
    fn test_component_aliased_to_scalar_anchor_collapses_name_and_version_range() {
        let (policy, instance_host) = ctx();
        let content = ".c: &c gitlab.com/org/proj/comp@1.0.0\ninclude:\n  - component: *c\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(dep.name_range, dep.version_range().unwrap());
        assert_eq!(slice(content, dep.name_range), "*c");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("1.0.0")
        );
    }

    /// EC-004/US-003: `? *k` where `*k` aliases a **scalar** anchor (table hit), followed
    /// by real `project:`/`ref:` scalars in the same entry — the key-position transition
    /// must not desync the rest of the mapping's key/value alternation.
    #[test]
    fn test_alias_in_key_position_table_hit_does_not_desync_following_entry() {
        let (policy, instance_host) = ctx();
        let content = ".k: &k dummy\ninclude:\n  - ? *k\n    : ignored\n    project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(!dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    /// EC-005/US-003: `? *k` where `*k` aliases a **container** anchor (table miss),
    /// followed by real `project:`/`ref:` scalars — fixed as a side effect of making the
    /// key-position transition unconditional (independent of table hit/miss).
    #[test]
    fn test_alias_in_key_position_table_miss_does_not_desync_following_entry() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {a: 1}\ninclude:\n  - ? *tpl\n    : ignored\n    project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(!dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    /// EC-006: `<<: *anything` (merge key aliasing any anchor) is safe by construction —
    /// `key_for` never maps `"<<"` to `Project`/`Ref`/`Component`, so no field is ever
    /// targeted for capture regardless of table hit/miss. Regression test only.
    #[test]
    fn test_merge_key_alias_does_not_produce_a_second_dependency() {
        let (policy, instance_host) = ctx();
        let content =
            ".pin: &pin v1.2.3\ninclude:\n  - <<: *pin\n    project: org/proj\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(!dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "org/proj");
    }

    /// #942: an *implicit* alias key (`*k: value`, not the explicit `? *k` form) whose
    /// resolved text matches a recognized key name (`ref`) IS now reinterpreted as that
    /// key, the same `deps-dart`-style `key_for(role, &text)` resolution a table-hit
    /// explicit complex key already got from #912. Was previously pinned as a known limit
    /// (`PendingKey::None` unconditionally on FR-003's key-position transition); #942 fixes
    /// it via the shared `ScalarAnchorTable` migration.
    #[test]
    fn test_implicit_alias_key_resolving_to_recognized_name_is_reinterpreted() {
        let (policy, instance_host) = ctx();
        let content = ".k: &k ref\ninclude:\n  - *k : v1.0.0\n    project: org/p\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/p");
        assert_eq!(dep.pin, Some(PinStyle::Tag));
        assert_eq!(slice(content, dep.version_range().unwrap()), "v1.0.0");
    }

    /// #942: an alias key resolving to a **recognized non-pinnable** field name
    /// (`"template"`) suppresses the whole entry, exactly as the literal `template:` key
    /// already does (`build_dependency`'s `entry.has_template` early return) — the
    /// dependency-*losing* direction of the same `key_for` resolution that
    /// `test_implicit_alias_key_resolving_to_recognized_name_is_reinterpreted` pins the
    /// dependency-gaining direction of. Semantically correct (the YAML really does say
    /// `template:`), but user-visible: `project:`/`ref:` in the same entry are captured and
    /// then discarded along with it.
    #[test]
    fn test_alias_key_resolving_to_template_suppresses_the_whole_entry() {
        let (policy, instance_host) = ctx();
        // A clean sibling entry proves the suppression is scoped to the aliased entry, not a
        // side effect of the whole document failing to parse (which would also produce zero
        // dependencies, indistinguishable from `test_dangling_alias_is_a_parse_error_...`).
        let content = ".t: &t template\ninclude:\n  - *t : true\n    project: org/p\n    ref: v1.0.0\n  - project: org/q\n    ref: v2.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].project_path, "org/q");
    }

    /// #942: the `"local"` sibling of
    /// `test_alias_key_resolving_to_template_suppresses_the_whole_entry` — same suppression,
    /// different recognized non-pinnable key.
    #[test]
    fn test_alias_key_resolving_to_local_suppresses_the_whole_entry() {
        let (policy, instance_host) = ctx();
        // See test_alias_key_resolving_to_template_suppresses_the_whole_entry's comment for why
        // a clean sibling entry is needed here.
        let content = ".l: &l local\ninclude:\n  - *l : /x.yml\n    project: org/p\n    ref: v1.0.0\n  - project: org/q\n    ref: v2.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].project_path, "org/q");
    }

    /// #942: an alias key resolving to `"include"` opens the top-level `include:` gate itself
    /// — [`GitlabCiReceiver`]'s "gated to exactly the top-level `include:` key's subtree" is
    /// still accurate, but that gate is reachable through a resolved alias key, not only the
    /// literal `include:` token. Correct per the same YAML-resolution logic #942 relies on
    /// elsewhere, but newly reachable and previously untested.
    #[test]
    fn test_alias_key_resolving_to_include_opens_top_level_gate() {
        let (policy, instance_host) = ctx();
        let content = ".i: &i include\n*i :\n  - project: org/p\n    ref: v1.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].project_path, "org/p");
    }

    /// spec 058 EC-001/US-001 (supersedes the old #912-era EC-007 non-goal pinning): `-
    /// *tpl` (a whole mapping anchor aliased as an `include:` sequence item) is now in
    /// scope — one dependency record, both `project:`/`ref:` alias-derived and positioned
    /// at the alias token itself (`*tpl`), never the anchor's own definition site.
    #[test]
    fn test_mapping_anchor_aliased_as_sequence_item_resolves_one_dependency() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {project: org/proj, ref: v1.0.0}\ninclude:\n  - *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert!(dep.is_alias_occurrence);
        assert_eq!(slice(content, dep.name_range), "*tpl");
        assert_eq!(slice(content, dep.version_range().unwrap()), "*tpl");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
    }

    /// EC-008: `include: *incs` (a whole sequence anchor aliased at the `include:` key) —
    /// won't-fix-by-design non-goal, must stay a table miss with zero records.
    #[test]
    fn test_sequence_anchor_aliased_as_include_value_produces_no_dependency() {
        let (policy, instance_host) = ctx();
        let content = ".incs: &incs\n  - project: org/proj\n    ref: v1.0.0\ninclude: *incs\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty(), "{:?}", result.dependencies);
    }

    /// EC-012 (#1029): an anchored empty scalar (`x: &e` / `ref: *e`) is a table hit whose
    /// text is `""` — must resolve without panicking, and (since #1029, matching how
    /// [`test_empty_ref_on_anchor_free_entry_ships_no_version`] treats the same empty text
    /// on the literal path) without producing a misleading non-empty `Some("")` display —
    /// `is_plain_null` is now re-checked against the anchor's own style at the alias site,
    /// so this ships no version instead.
    #[test]
    fn test_alias_to_empty_anchor_is_safe() {
        let (policy, instance_host) = ctx();
        let content = "x: &e\ninclude:\n  - project: org/proj\n    ref: *e\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range().is_none());
        assert!(dep.pin.is_none());
    }

    /// #1029: an alias to an anchor holding each of Psych's four null spellings (`~`,
    /// `null`, `Null`, `NULL`) must ship no version, agreeing with how the literal path
    /// (`is_plain_null`, see [`crate::parser`]'s `Event::Scalar` arm) treats the same text
    /// written directly instead of through an anchor/alias.
    #[test]
    fn test_alias_to_each_null_spelling_anchor_ships_no_version() {
        let (policy, instance_host) = ctx();
        for spelling in ["~", "null", "Null", "NULL"] {
            let content =
                format!(".n: &n {spelling}\ninclude:\n  - project: org/proj\n    ref: *n\n");
            let result =
                parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
            assert_eq!(
                result.dependencies.len(),
                1,
                "{spelling}: {:?}",
                result.dependencies
            );
            let dep = &result.dependencies[0];
            assert!(
                dep.version_req.is_none(),
                "{spelling}: {:?}",
                dep.version_req
            );
            assert!(
                dep.version_range().is_none(),
                "{spelling}: unexpected range"
            );
        }
    }

    /// #1029: literal and aliased paths must now agree on a null-like value — a non-null
    /// anchor text must still resolve normally through the alias path (regression guard
    /// against the null-check accidentally swallowing real values too).
    #[test]
    fn test_alias_to_non_null_anchor_still_resolves() {
        let (policy, instance_host) = ctx();
        let content = ".v: &v v1.2.3\ninclude:\n  - project: org/proj\n    ref: *v\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.is_alias_occurrence);
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("v1.2.3")
        );
    }

    /// #1029 cross-ecosystem parity: `is_plain_null` checks the anchor's own `style`/`tag`,
    /// so a non-plain null-shaped scalar (here `!!str null`) must NOT be treated as null when
    /// aliased — mirrors `deps-dart`'s sibling regression
    /// `test_aliased_str_tagged_null_like_scalar_resolves_to_literal_text`.
    #[test]
    fn test_alias_to_str_tagged_null_like_anchor_resolves_to_literal_text() {
        let (policy, instance_host) = ctx();
        let content = ".n: &n !!str null\ninclude:\n  - project: org/proj\n    ref: *n\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("null")
        );
    }

    /// Critic M1: the two common shapes #1029's fix actually targets — a null alias reached
    /// through `<<:` — had no direct regression test; every existing #1029 test used the
    /// non-merge `ref: *n` shape. Own key AFTER a merge key still resolves through the
    /// value-position `Event::Alias` arm with `alias_site == None` (this is the entry's own
    /// live scalar, not a replayed one) — the null must still override the merged
    /// `v1.0.0`, matching row 1's precedence (own key after `<<:` wins) but writing `None`.
    #[test]
    fn test_null_alias_as_own_key_after_merge_overrides_merged_value() {
        let (policy, instance_host) = ctx();
        let content = ".n: &n ~\n.t: &t {ref: v1.0.0}\ninclude:\n  - project: org/proj\n    <<: *t\n    ref: *n\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range().is_none());
        assert!(dep.pin.is_none());
    }

    /// Critic M1, second shape: a null alias inside a *container* anchor replayed through a
    /// merge key exercises `parser.rs`'s value-position `Event::Alias` arm with
    /// `alias_site == Some(outer)`/`replay_depth > 0` — `*n`'s own container-anchor replay
    /// attempt misses (it is scalar-shaped, not mapping-shaped) and falls through to the
    /// scalar-anchor `is_plain_null` re-check, which must still suppress the version.
    #[test]
    fn test_null_alias_inside_container_anchor_replayed_through_merge_suppresses_version() {
        let (policy, instance_host) = ctx();
        let content = ".n: &n ~\n.t: &t {ref: *n}\ninclude:\n  - project: org/proj\n    <<: *t\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range().is_none());
        assert!(dep.pin.is_none());
    }

    /// EC-013: two aliases to the same scalar anchor on one flow-style line each carry
    /// their own `Marker`, so the span locator (FR-006) must not collapse them onto one
    /// range.
    #[test]
    fn test_two_aliases_to_same_anchor_on_one_line_get_distinct_ranges() {
        let (policy, instance_host) = ctx();
        let content =
            ".p: &p v1.0.0\ninclude: [{project: org/a, ref: *p}, {project: org/b, ref: *p}]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        assert_ne!(
            result.dependencies[0].version_range(),
            result.dependencies[1].version_range()
        );
        for dep in &result.dependencies {
            assert_eq!(slice(content, dep.version_range().unwrap()), "*p");
        }
    }

    /// EC-014/FR-007: the alias span must include the leading `*` — an anchor name that
    /// happens to look version-shaped (`&v1 v1.2.3` / `*v1`) must not resolve to a span
    /// that itself looks like the literal version text.
    #[test]
    fn test_alias_span_includes_leading_asterisk_even_when_name_looks_version_shaped() {
        let (policy, instance_host) = ctx();
        let content = ".pin: &v1 v1.2.3\ninclude:\n  - project: org/proj\n    ref: *v1\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(slice(content, dep.version_range().unwrap()), "*v1");
    }

    /// EC-015/NFR-004/SC-005: an anchor whose text exceeds [`MAX_ANCHOR_VALUE_CHARS`]
    /// degrades to the table-miss path — the alias to it captures nothing, same as today.
    #[test]
    fn test_anchor_value_over_char_cap_degrades_to_table_miss() {
        let (policy, instance_host) = ctx();
        let long_value = "v".repeat(MAX_ANCHOR_VALUE_CHARS + 1);
        let content =
            format!(".pin: &pin {long_value}\ninclude:\n  - project: org/proj\n    ref: *pin\n");
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(!dep.is_alias_occurrence);
        assert!(dep.pin.is_none());
        assert!(dep.version_range().is_none());
    }

    /// EC-015/NFR-004/SC-005: once [`MAX_ANCHOR_TABLE_ENTRIES`] distinct anchors are
    /// already recorded, one more degrades to the table-miss path the same way.
    #[test]
    fn test_anchor_table_over_entry_cap_degrades_to_table_miss() {
        let (policy, instance_host) = ctx();
        let mut content = String::new();
        for i in 0..MAX_ANCHOR_TABLE_ENTRIES {
            content.push_str(&format!(".a{i}: &a{i} filler\n"));
        }
        content
            .push_str(".extra: &extra v9.9.9\ninclude:\n  - project: org/proj\n    ref: *extra\n");
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(!dep.is_alias_occurrence);
        assert!(dep.pin.is_none());
        assert!(dep.version_range().is_none());
    }

    /// EC-009/NFR-007: a dangling alias (`*nope` with no matching `&nope` anywhere) is a
    /// whole-document load error in `yaml-rust2`, degrading to an empty result — not a
    /// panic, and not reached by this fix's own code.
    #[test]
    fn test_dangling_alias_is_a_parse_error_degrading_to_empty_result() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    ref: *nope\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty());
    }

    // --- spec 058 / #933/#916: mapping-shaped container anchor support ---

    /// EC-002: `include: *tpl` — the entire `include:` value is a single aliased mapping,
    /// not a sequence. Distinct code path from `- *tpl` (EC-001): the child-role table's
    /// `(Root, Include, Mapping)` arm covers this directly.
    #[test]
    fn test_include_value_aliased_to_mapping_anchor_resolves() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {project: org/proj, ref: v1.0.0}\ninclude: *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert!(dep.is_alias_occurrence);
        assert_eq!(slice(content, dep.name_range), "*tpl");
    }

    /// EC-018: a mapping anchor defined directly on a *live* `include:` entry, then aliased
    /// again elsewhere — 2 dependency records is correct (GitLab genuinely includes the
    /// template twice), not a duplicate to suppress.
    #[test]
    fn test_anchor_defined_on_live_entry_and_aliased_elsewhere_produces_two_records() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - &e1\n    project: org/proj\n    ref: v1.0.0\n  - *e1\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        assert!(
            result
                .dependencies
                .iter()
                .all(|d| d.project_path == "org/proj")
        );
        // The live occurrence keeps its own literal range; the aliased one is alias-derived.
        assert!(!result.dependencies[0].is_alias_occurrence);
        assert!(result.dependencies[1].is_alias_occurrence);
        assert_ne!(
            result.dependencies[0].version_range(),
            result.dependencies[1].version_range()
        );
    }

    /// EC-009/FR-006: a quoted merge key (`"<<": *tpl`) merges exactly like a plain `<<:` —
    /// Psych does not gate merge-key recognition on scalar style, so a test asserting
    /// non-merging here would pin the wrong (PyYAML, not Psych) behavior.
    #[test]
    fn test_quoted_merge_key_merges_same_as_plain() {
        let (policy, instance_host) = ctx();
        let content =
            ".tpl: &tpl {ref: v1.0.0}\ninclude:\n  - project: org/proj\n    \"<<\": *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
    }

    /// EC-010: `<<: *anything` merging a **non-mapping** anchor (scalar or sequence)
    /// resolves to nothing under Psych — an inert literal `<<` key. The entry's own other
    /// literal fields are unaffected. (EC-006's own dedicated regression test already
    /// covers a scalar anchor specifically — see `test_merge_key_alias_does_not_produce_a_second_dependency`.)
    #[test]
    fn test_merge_key_aliasing_non_mapping_anchor_is_inert() {
        let (policy, instance_host) = ctx();
        let content = ".s: &s v1.0.0\n.seq: &seq\n  - a\n  - b\ninclude:\n  - project: org/proj\n    <<: *s\n    ref: v2.0.0\n  - project: org/other\n    <<: *seq\n    ref: v3.0.0\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v2.0.0")
        );
        assert_eq!(
            result.dependencies[1]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v3.0.0")
        );
    }

    /// EC-019: an explicit null/empty scalar positioned AFTER a `<<:` that supplied a value
    /// for the same key becomes `None` (a positional write of absence, FR-016) — not "keep
    /// the merged value".
    #[test]
    fn test_explicit_null_after_merge_is_a_positional_write_of_absence() {
        let (policy, instance_host) = ctx();
        let content =
            ".tpl: &tpl {ref: v1.0.0}\ninclude:\n  - project: org/proj\n    <<: *tpl\n    ref:\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range().is_none());
        assert!(dep.pin.is_none());
    }

    /// NFR-007 behavior change: a **literal** inline `<<: {...}` (no anchor/alias
    /// involved at all) now folds, per Psych — previously `<<` was just an unrecognized
    /// key (`PendingKey::None`), capturing nothing. Correct per P0, but a documented
    /// behavior change on an otherwise anchor-free document (CHANGELOG entry required).
    #[test]
    fn test_literal_inline_merge_map_now_folds_nfr007_behavior_change() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    <<: {ref: v1.0.0}\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
    }

    /// B4 (architect/critic finding, not a bug): Psych distinguishes *key absent* from
    /// *key present but nil*; `Option<RawField>` cannot represent that third state, so a
    /// doubly-nested explicit null diverges from real Psych here. Real Psych resolves
    /// `ref: nil` (the null literal wins positionally, same as any other value); this
    /// crate's `FoldMode::Overwrite` only overwrites a **present** merged value (FR-012),
    /// so `ref: v9`'s own earlier literal survives instead. Accepted, deliberate
    /// divergence (three-state `Absent | Null | Value` plumbing through every field is
    /// disproportionate to this shape's rarity) — flagged as a named regression, not fixed.
    #[test]
    fn test_b4_doubly_nested_explicit_null_diverges_from_psych() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {<<: *a, ref: ~}\ninclude:\n  - project: org/proj\n    ref: v9\n    <<: *b\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        // Real Psych: ref resolves to nil (absent). This crate's documented divergence: the
        // entry's own earlier `ref: v9` literal survives, because `FoldMode::Overwrite`
        // never overwrites with an *absent* merged value (FR-012).
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v9")
        );
    }

    /// M4 (critic finding): a scalar member inside `<<: [..]` poisons the **whole**
    /// sequence's contribution, matching Psych's `revive_hash`, which wraps the whole
    /// sequence-merge loop in one `rescue TypeError` — one bad member discards
    /// everything `*a` would have contributed, not just the bad member. The entry's own
    /// other literal fields are untouched.
    #[test]
    fn test_scalar_member_in_merge_sequence_poisons_the_whole_sequence() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\ninclude:\n  - project: org/proj\n    <<: [*a, \"x\"]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.project_path, "org/proj");
        assert!(dep.version_req.is_none(), "{dep:?}");
    }

    /// M4: a non-mapping **container** member (a nested sequence) inside `<<: [..]` also
    /// poisons the whole sequence — `pop_container`'s site-1 check, not only the
    /// scalar/unresolvable-anchor site-2 check above. The entry's own literal `ref:` is
    /// untouched (Psych's `revive_hash` failure never poisons the entry itself, only the
    /// sequence's own contribution).
    #[test]
    fn test_nested_sequence_member_in_merge_sequence_poisons_only_the_sequence() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n    <<: [[1, 2]]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
    }

    /// Counter-example to the two poison tests above: a genuine **mapping** member inside
    /// `<<: [..]` does not poison anything and folds normally.
    #[test]
    fn test_literal_mapping_member_in_merge_sequence_folds_normally() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/proj\n    <<: [{ref: v9.0.0}]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v9.0.0")
        );
    }

    /// Critic S2: a document engineered to exceed [`MAX_REPLAYED_EVENTS`] via a fanned-out
    /// merge chain (7 anchors, each merging the previous one 4 times — the critic's own
    /// measured recipe for ~17-70k dispatched events from a few hundred bytes) must
    /// degrade only the entry that touches the pathological alias — to **0 records for
    /// itself**, not a partial/wrong one — while leaving anchor-free sibling entries
    /// completely unaffected (SC-003). The mixed-entry shape (a real literal `project:`
    /// alongside the budget-tripping `<<:`) is required: with no own keys at all,
    /// `build_dependency` would return `None` regardless, masking the hazard S2 found.
    #[test]
    fn test_budget_abandoned_merge_degrades_only_its_own_mixed_entry() {
        let (policy, instance_host) = ctx();
        let mut content = String::from(".p0: &p0 {a: 1}\n");
        for i in 1..=7 {
            let prev = i - 1;
            content.push_str(&format!(
                ".p{i}: &p{i} {{<<: [*p{prev}, *p{prev}, *p{prev}, *p{prev}]}}\n"
            ));
        }
        content.push_str(
            "include:\n  - project: org/bomb\n    <<: *p7\n  - project: org/a\n    ref: v1.0.0\n  - project: org/b\n    ref: v2.0.0\n",
        );
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        let names: std::collections::HashSet<&str> = result
            .dependencies
            .iter()
            .map(|d| d.project_path.as_str())
            .collect();
        assert!(
            !names.contains("org/bomb"),
            "budget-tripping entry must degrade to 0 records: {:?}",
            result.dependencies
        );
        assert!(names.contains("org/a"), "{:?}", result.dependencies);
        assert!(names.contains("org/b"), "{:?}", result.dependencies);
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
    }

    /// Review regression: once `replay_disabled` latches anywhere in the stream (here, via
    /// the same budget-tripping fixture as the test above), a *later, completely
    /// unrelated* entry using an ordinary scalar alias (no merge, no container anchor
    /// involved at all) must still be captured normally. `replay_anchor` is tried
    /// speculatively for every alias, so a first version of the M1 fix poisoned the live
    /// top for this entry too, silently dropping it — a direct NFR-003/SC-003 violation.
    #[test]
    fn test_budget_trip_does_not_poison_a_later_unrelated_scalar_alias_entry() {
        let (policy, instance_host) = ctx();
        let mut content = String::from(".p0: &p0 {a: 1}\n");
        for i in 1..=7 {
            let prev = i - 1;
            content.push_str(&format!(
                ".p{i}: &p{i} {{<<: [*p{prev}, *p{prev}, *p{prev}, *p{prev}]}}\n"
            ));
        }
        content.push_str(".pin: &pin v9.9.9\n");
        content.push_str(
            "include:\n  - project: org/bomb\n    <<: *p7\n  - project: org/c\n    ref: *pin\n",
        );
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        let names: std::collections::HashSet<&str> = result
            .dependencies
            .iter()
            .map(|d| d.project_path.as_str())
            .collect();
        assert!(!names.contains("org/bomb"), "{:?}", result.dependencies);
        assert!(
            names.contains("org/c"),
            "an unrelated ordinary scalar-alias entry after a budget trip must survive: {:?}",
            result.dependencies
        );
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
    }

    /// M5 (critic N3), strengthened per validate-critique M2: a bare `*tpl` occupying an
    /// entire document's root. The `Outside` scalar-position arm also covers an *empty*
    /// stack, so `child_role(Mapping)` there returns `Root` — `replay_anchor`'s guard now
    /// excludes `FrameRole::Root` explicitly (this crate's own structural fix, not reliance
    /// on a `yaml-rust2` internal), so replay can never happen here regardless of whether
    /// the surrounding document would otherwise parse.
    ///
    /// A **valid `include:` entry in document 1** is the discriminator this test needs: if
    /// the fixture asserted only "zero dependencies from document 2", that couldn't tell
    /// "the whole multi-document stream failed to parse" (losing document 1's real entry
    /// too — `parse_gitlab_ci_yaml`'s `Err` path discards everything) apart from "replay
    /// correctly contributed nothing at `Root`, and document 1 was otherwise fine". Verified
    /// empirically (not assumed): `yaml-rust2` 0.12 clears its anchor *name*->id lookup
    /// table at every document boundary, so document 2's bare alias to a document-1 anchor
    /// is a hard parse error for the **whole stream** — document 1's otherwise-valid entry
    /// is lost too, which is exactly what "zero dependencies overall" pins.
    #[test]
    fn test_bare_alias_at_document_root_yields_zero_dependencies_overall() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {project: org/proj, ref: v1.0.0}\ninclude:\n  - project: org/valid\n    ref: v2.0.0\n---\n*tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty(), "{:?}", result.dependencies);
    }

    /// Critic M1 (ruled): a merge chain deep enough to trip [`MAX_REPLAY_DEPTH`] (linear,
    /// so the event budget never trips first — each level costs only 1 dispatched event)
    /// must degrade the entry to 0 records, not silently keep its own earlier `ref: v0`
    /// literal as if the merge had simply not applied (which would ship a plausible-looking
    /// wrong version, since Psych's real merge would have overwritten it).
    #[test]
    fn test_replay_depth_cap_poisons_the_entry() {
        let (policy, instance_host) = ctx();
        let mut content = String::from(".p0: &p0 {a: 1}\n");
        for i in 1..=40 {
            let prev = i - 1;
            content.push_str(&format!(".p{i}: &p{i} {{<<: *p{prev}}}\n"));
        }
        content.push_str("include:\n  - project: org/proj\n    ref: v0\n    <<: *p40\n");
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty(), "{:?}", result.dependencies);
    }

    /// Critic L1 (ruled): once [`MAX_CONTAINER_ANCHOR_ENTRIES`] distinct mapping anchors are
    /// already finalized, one more degrades to a table miss — mirrors
    /// [`MAX_ANCHOR_TABLE_ENTRIES`]'s identical precedent for the sibling scalar table.
    #[test]
    fn test_container_anchor_table_over_entry_cap_degrades_to_table_miss() {
        let (policy, instance_host) = ctx();
        let mut content = String::new();
        for i in 0..MAX_CONTAINER_ANCHOR_ENTRIES {
            content.push_str(&format!(".a{i}: &a{i} {{}}\n"));
        }
        content.push_str(".extra: &extra {project: org/proj, ref: v1.0.0}\ninclude:\n  - *extra\n");
        let result = parse_gitlab_ci_yaml(&content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty(), "{:?}", result.dependencies);
    }

    /// Validate-critique M3: the live (non-merge, anchor-free) parse path also changed —
    /// `Event::Scalar`'s value arm now applies `is_plain_null` unconditionally, so an empty
    /// `ref:` (no merge involved at all) now ships **no version** instead of the old
    /// `version_req == Some("")` with a zero-width range. Correct per Psych, but a real
    /// behavior change on an ordinary anchor-free document (see CHANGELOG), and previously
    /// only implicitly exercised inside a merge fixture (EC-019) — this pins the non-merge
    /// path on its own.
    #[test]
    fn test_empty_ref_on_anchor_free_entry_ships_no_version() {
        let (policy, instance_host) = ctx();
        let content = "include:\n  - project: org/p\n    ref:\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range().is_none());
        assert!(dep.pin.is_none());
    }

    /// EC-016/FR-019: a `component:` field supplied through a mapping-anchor replay/merge
    /// (not a literal, and not a scalar-anchor alias — #912's existing coverage) must still
    /// bypass `build_component_dependency`'s normal `prefix.len()` offset arithmetic, the
    /// same way a direct scalar-anchor alias to `component:` already does.
    #[test]
    fn test_component_supplied_through_merge_collapses_name_and_version_range() {
        let (policy, instance_host) = ctx();
        let content =
            ".tpl: &tpl {component: gitlab.com/org/proj/comp@1.0.0}\ninclude:\n  - <<: *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.kind, IncludeKind::Component);
        assert!(dep.is_alias_occurrence);
        assert_eq!(dep.project_path, "org/proj");
        assert_eq!(dep.name_range, dep.version_range().unwrap());
        assert_eq!(slice(content, dep.name_range), "*tpl");
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("1.0.0")
        );
    }

    // --- spec 058 §3 FR-014: the 10-row Psych acceptance table (Ruby Psych 5.3.1,
    // `YAML.safe_load(src, aliases: true)`) — the oracle for every merge-precedence
    // requirement in this feature (P0). Each row is a required regression test.

    /// Row 1: own key AFTER `<<:` -> the own key wins (`Overwrite` writes the entry's own
    /// live scalar last).
    #[test]
    fn test_psych_row1_own_key_after_merge_wins() {
        let (policy, instance_host) = ctx();
        let content =
            ".tpl: &tpl {ref: v1}\ninclude:\n  - project: org/proj\n    <<: *tpl\n    ref: v2\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v2")
        );
    }

    /// Row 2: own key BEFORE `<<:` -> the merged value wins (the later `Overwrite` fold of
    /// the merge runs after the live scalar) — counter-intuitive relative to a naive "own
    /// keys always win" reading, but this is GitLab's actual behavior (P0).
    #[test]
    fn test_psych_row2_own_key_before_merge_loses() {
        let (policy, instance_host) = ctx();
        let content =
            ".tpl: &tpl {ref: v1}\ninclude:\n  - project: org/proj\n    ref: v2\n    <<: *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v1")
        );
    }

    /// Row 3: `<<: [*a, *b]` where both define the same key -> value from `*a`
    /// (`FillIfAbsent` inside the `MergeSequence`: `*a` folds into the empty slot first,
    /// `*b` sees `Some` and skips).
    #[test]
    fn test_psych_row3_merge_sequence_first_wins() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {ref: vb}\ninclude:\n  - project: org/proj\n    <<: [*a, *b]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("va")
        );
    }

    /// Row 4: duplicate `<<:` keys in one mapping -> the value from the **second** `<<:`
    /// wins (two `Overwrite` folds directly into the entry, in document order) — distinct
    /// from row 3's `<<: [*a, *b]` first-wins result, and both must be tested separately.
    #[test]
    fn test_psych_row4_duplicate_merge_keys_last_wins() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {ref: vb}\ninclude:\n  - project: org/proj\n    <<: *a\n    <<: *b\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("vb")
        );
    }

    /// Row 5: own key both BEFORE and AFTER `<<:` -> the AFTER value wins (same mechanism
    /// as row 1; the later live scalar is the final write).
    #[test]
    fn test_psych_row5_own_key_before_and_after_merge_after_wins() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {ref: v1}\ninclude:\n  - project: org/proj\n    ref: v0\n    <<: *tpl\n    ref: v2\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("v2")
        );
    }

    /// Row 6: an inner anchor's own key BEFORE its own `<<:` -> the inner anchor's merged
    /// value wins (same as row 2, one level down: the inner `MergeSource`'s `Overwrite`
    /// fold runs after its own live scalar).
    #[test]
    fn test_psych_row6_inner_anchor_own_key_before_its_merge_loses() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {ref: vb, <<: *a}\ninclude:\n  - project: org/proj\n    <<: *b\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("va")
        );
    }

    /// Row 7: an inner anchor's own key AFTER its own `<<:` -> the inner anchor's own key
    /// wins (same as row 1, one level down).
    #[test]
    fn test_psych_row7_inner_anchor_own_key_after_its_merge_wins() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {<<: *a, ref: vb}\ninclude:\n  - project: org/proj\n    <<: *b\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("vb")
        );
    }

    /// Row 8: the entry's own key BEFORE `<<: [*a, *b]` -> value from `*a` (the entry's
    /// live scalar is overwritten by the `MergeSequence`'s folded first-wins value, same
    /// mechanism as row 2).
    #[test]
    fn test_psych_row8_entry_own_key_before_merge_sequence_loses_to_first() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: va}\n.b: &b {ref: vb}\ninclude:\n  - project: org/proj\n    ref: v0\n    <<: [*a, *b]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("va")
        );
    }

    /// Row 9: a 3-level merge chain (`.c` merges `.b`, `.b`'s own key comes BEFORE its own
    /// `<<: *a`) -> resolves transitively to `.a`'s value (the middle anchor `.b`'s own
    /// merged value, per row 6, propagated up through `.c` with no additional role-pair
    /// special case — proving FR-011's parent-role rule needs none).
    ///
    /// Critic S1: this is the row that must assert the **range**, not only the resolved
    /// value — a first design round took the *innermost* alias marker (`*a`'s marker
    /// inside `.b:`'s own definition) instead of the *outermost* (the live entry's own
    /// `*c` token), which would ship green on every other row since they don't
    /// distinguish the two.
    #[test]
    fn test_psych_row9_transitive_merge_chain_resolves_and_uses_outermost_marker() {
        let (policy, instance_host) = ctx();
        let content = ".a: &a {ref: v1.0.0}\n.b: &b {ref: v9.9.9, <<: *a}\n.c: &c {<<: *b}\ninclude:\n  - project: org/proj\n    <<: *c\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("v1.0.0")
        );
        assert!(dep.is_alias_occurrence);
        // S1: the range must land on the live entry's own `*c` token — never inside `.a:`'s
        // or `.b:`'s own definitions.
        assert_eq!(slice(content, dep.version_range().unwrap()), "*c");
    }

    /// Row 10: `<<: [*x, *y]`, both `*x` and `*y` merge further -> the value resolved from
    /// `*x`'s own chain (`FillIfAbsent` at the outer sequence, `Overwrite` at each inner
    /// chain, composed with no additional rule).
    #[test]
    fn test_psych_row10_merge_sequence_of_two_further_merging_anchors() {
        let (policy, instance_host) = ctx();
        let content = ".p: &p {ref: vp}\n.q: &q {ref: vq}\n.x: &x {<<: *p}\n.y: &y {<<: *q}\ninclude:\n  - project: org/proj\n    <<: [*x, *y]\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(
            result.dependencies[0]
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str),
            Some("vp")
        );
    }
}

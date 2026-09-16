//! `pubspec.yaml` parser using `yaml-rust2`'s event-driven (`MarkedEventReceiver`) API.
//!
//! Positions are derived from the YAML scanner's own token markers via
//! `deps_core::lsp_helpers::marker_byte_offset` + `locate_value_span`, the same approach
//! `deps-github-actions` and `deps-gitlab-ci` use — O(1) per lookup and exact for quoted,
//! flow-style, and aliased-scalar values, unlike a text-search-based scan over the raw
//! document (#899: the previous implementation's hand-rolled `find_key_range`/
//! `find_value_range_after_key` re-scanned the whole document per dependency, and reviewing
//! a bounded-cursor patch on top of that approach kept surfacing further correctness gaps —
//! see the module's git history for the abandoned intermediate attempts).
//!
//! # Known limitations
//!
//! Scalar YAML anchors are tracked directly (see the receiver's own `anchors` field); a whole
//! anchored mapping/sequence is additionally buffered and replayed through the normal event
//! dispatch on alias resolution (see `container_anchors`, `RecordingFrame`), so `dependencies:
//! *shared_map` (aliasing an entire `dependencies:` section) and `environment: *shared_env`
//! (aliasing the whole `environment:` mapping) resolve correctly, alongside a scalar alias
//! into `environment: sdk:` directly (`sdk: *shared_version`).
//!
//! A single dependency's own value aliasing a whole mapping (`pkg: *shared_entry`, as opposed
//! to the section or environment key itself) is deliberately left out of this change's scope
//! — the anchor itself is just as resolvable as `dependencies: *shared_map`'s, but resolving
//! it here would require enabling container-anchor replay for
//! `FrameRole::DependencySectionValue`, which needs its own fix for a separate mechanical
//! issue first (`is_replay` is currently derived per-*frame*, at push/pop time, not per-*name*
//! — enabling replay there would falsely zero a live, literal dependency name's `name_range`
//! whenever that same section also contains an aliased entry). Tracked as a follow-up. Until
//! then the dependency still appears (its name is real, literal text) but with no
//! version/source info — see `test_aliased_dependency_to_unresolvable_anchor_still_present`.

use crate::types::{DartDependency, DependencySection, DependencySource};
use deps_core::lsp_helpers::{LineOffsetTable, MarkedScalar, is_plain_null};
use deps_core::position::Range;
use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{DependencyBudget, DepsError, Result};
use std::collections::HashMap;
use url::Url;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Result of parsing a `pubspec.yaml` file.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct DartParseResult {
    /// Dependencies found across all sections.
    pub dependencies: Vec<DartDependency>,
    /// The `environment: sdk:` constraint string, if declared.
    pub sdk_constraint: Option<String>,
    /// URI of the manifest this result was parsed from.
    pub uri: Url,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// Builds a scalar's [`FieldValue`], forcing [`FieldValue::Unpositioned`] while replaying a
/// buffered container-anchor subtree (`replay_depth > 0`) — the marker on a replayed event
/// points at the anchor's own definition site, not this occurrence, so reusing it would
/// resurrect the duplicate-range bug [`FieldValue::Unpositioned`]'s own docs describe, one
/// level up (two aliases of the same whole section would otherwise get identical ranges).
fn scalar_field(
    replay_depth: usize,
    value: String,
    style: TScalarStyle,
    marker: &Marker,
) -> FieldValue {
    if replay_depth > 0 {
        FieldValue::Unpositioned(value)
    } else {
        FieldValue::Positioned(MarkedScalar::new(value, style, marker))
    }
}

/// A field's resolved text, plus its position in `content` when one genuinely exists.
enum FieldValue {
    /// A scalar seen directly in the event stream — its own marker gives an exact position.
    Positioned(MarkedScalar),
    /// Resolved from a YAML alias to a scalar anchor. The text is correct, but the literal
    /// text at the alias's own site is `*anchor`, not this value — [`FieldValue::range`]
    /// deliberately returns `None` rather than reusing the anchor definition's position, which
    /// review found produces duplicate, overlapping ranges when more than one alias resolves
    /// the same anchor (each got the *same* range, so "update all" emitted two `TextEdit`s over
    /// identical spans — invalid per LSP) and can point at a wholly unrelated line when the
    /// anchor sits outside the dependency's own section.
    Unpositioned(String),
}

impl FieldValue {
    fn into_text(self) -> String {
        match self {
            Self::Positioned(scalar) => scalar.into_text(),
            Self::Unpositioned(text) => text,
        }
    }

    fn range(&self, content: &str, line_table: &LineOffsetTable) -> Option<Range> {
        match self {
            Self::Positioned(scalar) => scalar.range(content, line_table),
            Self::Unpositioned(_) => None,
        }
    }
}

/// What a frame means for dependency-extraction purposes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRole {
    /// The document's root mapping.
    Root,
    /// The value of the root's `environment:` key.
    EnvironmentValue,
    /// The value of one of the root's `dependencies:`/`dev_dependencies:`/
    /// `dependency_overrides:` keys — a mapping whose own keys are arbitrary dependency names.
    DependencySectionValue,
    /// One dependency's own nested-map value (`pkg:\n  version: ...\n  git: ...`).
    DependencyEntryValue,
    /// A dependency entry's `git:` value, when given as its own nested map (as opposed to the
    /// `git: <url>` shorthand).
    GitValue,
    /// A dependency entry's `hosted:` value, when given as its own nested map (`hosted: {name,
    /// url}`) as opposed to the `hosted: <url>` shorthand.
    HostedValue,
    /// Anything else — `name:`, `flutter:`, `rules:`, or any other structure this parser does
    /// not need to look inside. Also covers a complex YAML key's subtree (`? <mapping>`/`?
    /// <sequence>`) used where a plain scalar key is normally expected —
    /// [`deps_core::yaml_walk::FrameStack`] handles the key/value-alternation bookkeeping for
    /// that case generically (previously a dedicated `ComplexKey` role existed here solely to
    /// make that bookkeeping work; the walker now owns it, so this parser never resolves such
    /// a key to a literal name, the same as an alias that fails to resolve).
    Irrelevant,
}

/// Which key (if any) a fixed-vocabulary mapping frame is currently awaiting the value for.
/// Not used by [`FrameRole::DependencySectionValue`], whose keys are arbitrary dependency
/// names rather than a fixed set — see [`FramePayload::pending_dep_name`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum PendingKey {
    #[default]
    None,
    Environment,
    Section(DependencySection),
    EnvSdk,
    EntryVersion,
    EntryGit,
    EntryPath,
    EntrySdk,
    EntryHosted,
    GitUrl,
    GitRef,
    GitPath,
    HostedName,
    HostedUrl,
}

fn key_for(role: FrameRole, text: &str) -> PendingKey {
    match role {
        FrameRole::Root => match text {
            "environment" => PendingKey::Environment,
            "dependencies" => PendingKey::Section(DependencySection::Dependencies),
            "dev_dependencies" => PendingKey::Section(DependencySection::DevDependencies),
            "dependency_overrides" => PendingKey::Section(DependencySection::DependencyOverrides),
            _ => PendingKey::None,
        },
        FrameRole::EnvironmentValue => {
            if text == "sdk" {
                PendingKey::EnvSdk
            } else {
                PendingKey::None
            }
        }
        FrameRole::DependencyEntryValue => match text {
            "version" => PendingKey::EntryVersion,
            "git" => PendingKey::EntryGit,
            "path" => PendingKey::EntryPath,
            "sdk" => PendingKey::EntrySdk,
            "hosted" => PendingKey::EntryHosted,
            _ => PendingKey::None,
        },
        FrameRole::GitValue => match text {
            "url" => PendingKey::GitUrl,
            "ref" => PendingKey::GitRef,
            "path" => PendingKey::GitPath,
            _ => PendingKey::None,
        },
        FrameRole::HostedValue => match text {
            "name" => PendingKey::HostedName,
            "url" => PendingKey::HostedUrl,
            _ => PendingKey::None,
        },
        FrameRole::DependencySectionValue | FrameRole::Irrelevant => PendingKey::None,
    }
}

/// A `git:` sub-value, either the `git: <url>` shorthand or the `git: {url, ref, path}` map
/// form.
enum RawGitValue {
    Scalar(FieldValue),
    Map {
        url: Option<FieldValue>,
        rev: Option<FieldValue>,
        path: Option<FieldValue>,
    },
}

/// A `hosted:` sub-value, either the `hosted: <url>` shorthand (remote package name is the
/// manifest's own dependency key) or the `hosted: {name, url}` map form (remote name may
/// differ from the key; a legacy `url`-only map form is also valid pub syntax). `build_dependency`
/// reads `name` only to decide whether the public-registry URL normalization in
/// [`classify_hosted_url`] is safe to apply (critic finding N3) — this LSP has no client
/// wiring to query a registry under a name other than the manifest's own dependency key, so a
/// `name` that disagrees with the key must keep the dependency classified as `CustomRegistry`
/// even when `url` is the public registry, or a renamed package would falsely resolve as
/// "unknown package".
enum RawHostedValue {
    Scalar(FieldValue),
    Map {
        name: Option<FieldValue>,
        url: Option<FieldValue>,
    },
}

/// One dependency's value shape, as accumulated from the event stream.
enum RawDependencyValue {
    /// `pkg: ^1.0.0` — a plain version-requirement string.
    Simple(FieldValue),
    /// `pkg:\n  version: ...\n  git: ...` etc. — a nested mapping.
    Entry {
        version: Option<FieldValue>,
        git: Option<Box<RawGitValue>>,
        path: Option<FieldValue>,
        sdk: Option<FieldValue>,
        hosted: Option<Box<RawHostedValue>>,
    },
    /// The value's shape could not be resolved to a concrete field (e.g. an alias to a
    /// mapping, or a sequence) — still emitted as a `Registry`-source, position-only entry,
    /// matching the pre-#899-fix behavior's own fallback for a value that was neither a
    /// string nor a map.
    Unresolved,
}

/// One `dependencies:`/`dev_dependencies:`/`dependency_overrides:` entry's raw fields,
/// finalized into a [`DartDependency`] after parsing completes.
struct RawDependency {
    section: DependencySection,
    name: MarkedScalar,
    /// Whether `name` was captured while replaying a buffered container-anchor subtree (see
    /// [`PubspecReceiver::container_anchors`]) rather than from the live event stream — if so,
    /// `name`'s marker points at the anchor's own definition site, not this occurrence, so
    /// [`build_dependency`] must not resolve a range from it (same rationale as
    /// [`FieldValue::Unpositioned`]).
    name_is_replay: bool,
    value: RawDependencyValue,
}

/// Per-frame accumulated state — the [`deps_core::yaml_walk::FrameStack`] generic
/// `payload`, carrying everything a frame's role means beyond the walker's own
/// structural kind/key-toggling mechanics.
#[derive(Default)]
struct FramePayload {
    /// Which section this frame belongs to — set on a [`FrameRole::DependencySectionValue`]
    /// frame when it is created; read back from the parent frame when a child
    /// [`FrameRole::DependencyEntryValue`] finalizes.
    section: Option<DependencySection>,
    /// `DependencySectionValue` only: the dependency name just read as a key, awaiting its
    /// value.
    pending_dep_name: Option<MarkedScalar>,
    /// `DependencyEntryValue` only: the name carried down from the parent
    /// `DependencySectionValue` frame at push time, used to finalize on `MappingEnd`.
    dep_name: Option<MarkedScalar>,
    /// `DependencyEntryValue` only: fields accumulated so far.
    version: Option<FieldValue>,
    git: Option<Box<RawGitValue>>,
    path: Option<FieldValue>,
    sdk: Option<FieldValue>,
    hosted: Option<Box<RawHostedValue>>,
    /// `GitValue` only: fields accumulated so far.
    git_url: Option<FieldValue>,
    git_ref: Option<FieldValue>,
    git_path: Option<FieldValue>,
    /// `HostedValue` only: fields accumulated so far.
    hosted_name: Option<FieldValue>,
    hosted_url: Option<FieldValue>,
}

impl FramePayload {
    /// Assigns `value` to whichever field `key` designates — the single point where
    /// `on_scalar`'s (`FieldValue::Positioned`) and `on_alias`'s
    /// (`FieldValue::Unpositioned`) otherwise-identical `DependencyEntryValue`/`GitValue`/
    /// `HostedValue` field dispatch converge, differing only in which `FieldValue`
    /// constructor the caller passes in. Every role's keys are handled unconditionally since a frame's `pending_key`
    /// only ever holds a key valid for its own role — an unrecognized key (`PendingKey::None`
    /// or a root/environment key that reached here by construction error) is a silent no-op.
    fn assign_field(&mut self, key: PendingKey, value: FieldValue) {
        match key {
            PendingKey::EntryVersion => self.version = Some(value),
            PendingKey::EntryGit => self.git = Some(Box::new(RawGitValue::Scalar(value))),
            PendingKey::EntryPath => self.path = Some(value),
            PendingKey::EntrySdk => self.sdk = Some(value),
            PendingKey::EntryHosted => self.hosted = Some(Box::new(RawHostedValue::Scalar(value))),
            PendingKey::GitUrl => self.git_url = Some(value),
            PendingKey::GitRef => self.git_ref = Some(value),
            PendingKey::GitPath => self.git_path = Some(value),
            PendingKey::HostedName => self.hosted_name = Some(value),
            PendingKey::HostedUrl => self.hosted_url = Some(value),
            PendingKey::None
            | PendingKey::Environment
            | PendingKey::Section(_)
            | PendingKey::EnvSdk => {}
        }
    }
}

/// The generic frame-stack mechanics ([`deps_core::yaml_walk::FrameStack`]) driven by
/// [`PubspecReceiver`], parameterized on this crate's own role/key vocabulary and
/// per-frame [`FramePayload`].
type Stack = FrameStack<FrameRole, PendingKey, FramePayload>;

/// Tracks one anchored mapping/sequence while its subtree streams past, so its extent within
/// [`PubspecReceiver::event_log`] can be recorded on its closing event — see
/// [`PubspecReceiver::container_anchors`].
///
/// Critic finding S2: an earlier version of this design gave each frame its own cloned
/// `Vec<(Event, Marker)>`, appended to on every event via a loop over all open frames — O(open
/// anchors) *clones* of every event, not just O(open anchors) integer increments, which
/// measured ~150x memory and ~4x latency from 60 anchors nested around one large subtree.
/// Storing only a `start` index into one flat, shared `event_log` makes recording O(1) per
/// event regardless of how many anchors are concurrently open, and defers the one real clone
/// (a slice-to-`Vec` copy) to actual replay — paid only for anchors that are ever aliased, and
/// only once per alias occurrence, rather than once per event for every anchor whether or not
/// it's ever used.
struct RecordingFrame {
    anchor_id: usize,
    kind: FrameKind,
    /// Net count of `MappingStart`/`SequenceStart` minus `MappingEnd`/`SequenceEnd` events seen
    /// since this frame opened — reaches `0` exactly when this frame's own closing event
    /// arrives (YAML containers are well-nested, so the innermost open frame's `depth` is
    /// always the one to check).
    depth: usize,
    /// Index into `event_log` of the first event *inside* this container (i.e. right after its
    /// own `MappingStart`/`SequenceStart`, which is not itself replayed — see
    /// [`PubspecReceiver::on_alias`]'s replay branch, which calls `push_container`/
    /// `pop_container` directly for the boundary).
    start: usize,
}

/// Collects every dependency's raw field values from the event stream, gated to exactly the
/// three top-level dependency sections' subtrees (plus `environment: sdk:`).
struct PubspecReceiver {
    stack: Stack,
    entries: Vec<RawDependency>,
    sdk: Option<String>,
    /// Scalar text, style, and tag seen under a YAML anchor (`&name`), keyed by
    /// `yaml-rust2`'s internal anchor id — looked up on `Event::Alias` so an aliased
    /// dependency value (`pkg: *shared`) still resolves to real text instead of being
    /// silently dropped. Only the text (and the style/tag needed to re-check
    /// [`is_plain_null`] at the alias site) is kept, not the anchor's own position — see
    /// [`FieldValue::Unpositioned`] for why. An alias can only refer to an anchor already
    /// seen earlier in the document (a YAML parse-order requirement), so this is always
    /// populated by the time an `Alias` event needing it arrives. Populated only for
    /// *scalar* anchors — a mapping/sequence-valued anchor is recorded in
    /// `container_anchors` instead. Unbounded (spec 056 §8 "Ask First" reserves cap changes
    /// to a deliberate, separate decision; this crate's own table was already unbounded
    /// before #942's extraction) — safe because the sum of all anchored scalar texts is
    /// bounded by the source file itself, on top of `check_yaml_expansion`'s 32 MB gate.
    anchors: ScalarAnchorTable<(TScalarStyle, Option<Tag>)>,
    /// Every event seen on the live pass while at least one [`RecordingFrame`] is open, in
    /// document order — the single backing store `container_anchors`' ranges index into. See
    /// [`RecordingFrame`]'s docs (critic finding S2) for why this is one flat, append-only log
    /// rather than a per-anchor buffer. Stays empty for a document with no anchors at all
    /// (critic finding S2-residual): [`Self::record_event`] only appends while `recording` is
    /// non-empty, so a document that never opens an anchor never touches this field.
    event_log: Vec<(Event, Marker)>,
    /// Mapping/sequence-shaped anchors' extents within `event_log`, keyed by anchor id,
    /// finalized (via [`Self::record_event`]) when each anchored container's closing event
    /// arrives. Resolved on `Event::Alias` by replaying the indexed slice through the normal
    /// `on_event`/`push_container`/`pop_container` dispatch — see [`Self::on_alias`]. Only
    /// populated on the live (non-replay) pass; a nested anchor inside an anchored subtree is
    /// always fully recorded before any alias referencing the outer anchor can fire, by YAML's
    /// own forward-reference-only parse order, so replay never needs to record further.
    container_anchors: HashMap<usize, (FrameKind, std::ops::Range<usize>)>,
    /// Currently-open [`RecordingFrame`]s, one per anchored container whose closing event has
    /// not yet arrived — a stack in practice (LIFO by nesting), stored as a `Vec` so every
    /// still-open ancestor frame's `depth` can be updated in one pass per event.
    recording: Vec<RecordingFrame>,
    /// Nesting depth of container-anchor replay (see [`Self::on_alias`]) — `0` on the live
    /// event stream. A counter, not a `bool`, as cheap insurance against a chained container
    /// alias nesting one replay inside another — though replay is currently only entered from
    /// `FrameRole::Root`, and `compute_child_role` degrades every replayed child to
    /// `DependencySectionValue`/`Irrelevant` (neither of which re-enters at `Root`), so nesting
    /// is not actually reachable today; a counter costs nothing over a `bool` here and remains
    /// correct if replay is ever enabled for another role (see the module docs' "Known
    /// limitations" note on `FrameRole::DependencySectionValue`).
    replay_depth: usize,
    /// Per-document ceiling on how many dependencies are retained — checked before a
    /// [`RawDependency`] is ever constructed (#906), not after the fact.
    budget: DependencyBudget,
}

impl PubspecReceiver {
    fn new(cap: usize) -> Self {
        Self {
            stack: Stack::new(),
            entries: Vec::new(),
            sdk: None,
            anchors: ScalarAnchorTable::new(AnchorLimits::UNBOUNDED),
            event_log: Vec::new(),
            container_anchors: HashMap::new(),
            recording: Vec::new(),
            replay_depth: 0,
            budget: DependencyBudget::new(cap),
        }
    }

    /// The shared budget-check-then-push chokepoint for all 4 sites that finalize a
    /// dependency into `entries` (`push_container`'s non-entry-shaped-value branch,
    /// `pop_container`'s `DependencyEntryValue` arm, and `on_scalar`/`on_alias`'s
    /// `DependencySectionValue` arms). Takes `entries`/`budget` as plain `&mut` parameters
    /// rather than `&mut self` because every call site already holds a live mutable borrow of
    /// `self.stack` (via a `Frame` reference) that a `&mut self` method would conflict with.
    ///
    /// `value` is a closure, not an already-built [`RawDependencyValue`], so construction work
    /// (e.g. resolving a [`FieldValue`]) only happens once `budget.allow()` confirms the cap
    /// has not been reached — preserving the "check the budget before building the entry"
    /// contract (#906 item 7) rather than reintroducing the check-after-construction shape
    /// this chokepoint is meant to prevent call sites from drifting back into.
    fn push_entry(
        entries: &mut Vec<RawDependency>,
        budget: &mut DependencyBudget,
        section: Option<DependencySection>,
        name: MarkedScalar,
        name_is_replay: bool,
        value: impl FnOnce() -> RawDependencyValue,
    ) {
        if budget.allow() {
            entries.push(RawDependency {
                section: section.unwrap_or_default(),
                name,
                name_is_replay,
                value: value(),
            });
        }
    }

    /// Appends every event to [`Self::event_log`], and finalizes the innermost open
    /// [`RecordingFrame`] into [`Self::container_anchors`] when its closing event arrives.
    /// Called for every event on the live (non-replay) pass, before that event's normal
    /// dispatch. O(1) plus O(open anchors) cheap integer `depth` updates per event — see
    /// [`RecordingFrame`]'s docs for why this no longer clones event data per open frame.
    fn record_event(&mut self, event: &Event, marker: Marker) {
        if matches!(event, Event::MappingEnd | Event::SequenceEnd)
            && let Some(frame) = self.recording.pop_if(|frame| frame.depth == 0)
        {
            // `event_log.len()` here is the about-to-be-occupied index of the closing event,
            // so this range covers exactly the events strictly between the container's own
            // start and end — matching what `on_alias`'s replay branch expects.
            self.container_anchors.insert(
                frame.anchor_id,
                (frame.kind, frame.start..self.event_log.len()),
            );
        }

        // Only logged while an anchor is being recorded, so an anchor-free document never
        // touches `event_log` — O(1) space for the common case.
        if !self.recording.is_empty() {
            self.event_log.push((event.clone(), marker));
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

    /// Determines the role (and, for a dependency section, which one) a new child container
    /// should have, given the current top-of-stack frame.
    ///
    /// Deliberately unaware of complex-key positioning: while the top frame is a `Mapping`
    /// awaiting a key, its `pending_key`/payload's `pending_dep_name` are still at their
    /// defaults (nothing has resolved a key yet), so every match arm below already falls
    /// through to `Irrelevant` for that case with no special-casing needed —
    /// [`deps_core::yaml_walk::FrameStack::push`] handles the complex-key bookkeeping itself.
    fn compute_child_role(&self, kind: FrameKind) -> (FrameRole, Option<DependencySection>) {
        let Some(top) = self.stack.top() else {
            return if kind == FrameKind::Mapping {
                (FrameRole::Root, None)
            } else {
                (FrameRole::Irrelevant, None)
            };
        };
        if kind == FrameKind::Mapping {
            match *top.role() {
                FrameRole::Root => match top.pending_key() {
                    PendingKey::Environment => return (FrameRole::EnvironmentValue, None),
                    PendingKey::Section(section) => {
                        return (FrameRole::DependencySectionValue, Some(*section));
                    }
                    _ => {}
                },
                FrameRole::DependencySectionValue if top.payload.pending_dep_name.is_some() => {
                    return (FrameRole::DependencyEntryValue, None);
                }
                FrameRole::DependencyEntryValue if *top.pending_key() == PendingKey::EntryGit => {
                    return (FrameRole::GitValue, None);
                }
                FrameRole::DependencyEntryValue
                    if *top.pending_key() == PendingKey::EntryHosted =>
                {
                    return (FrameRole::HostedValue, None);
                }
                _ => {}
            }
        }
        (FrameRole::Irrelevant, None)
    }

    fn push_container(&mut self, kind: FrameKind) {
        let (new_role, new_section) = self.compute_child_role(kind);
        let is_replay = self.replay_depth > 0;
        let Self {
            stack,
            entries,
            budget,
            ..
        } = self;

        let mut payload = FramePayload {
            section: new_section,
            ..FramePayload::default()
        };

        // Carries a pending dependency name down into the child's `DependencyEntryValue`
        // payload, or finalizes it as `Unresolved` if the child isn't one (e.g. a sequence
        // value). No-op while the parent awaits a key, since `pending_dep_name` is `None` then.
        if let Some(top) = stack.top_mut()
            && *top.role() == FrameRole::DependencySectionValue
            && let Some(name) = top.payload.pending_dep_name.take()
        {
            if new_role == FrameRole::DependencyEntryValue {
                payload.dep_name = Some(name);
            } else {
                let section = top.payload.section;
                Self::push_entry(entries, budget, section, name, is_replay, || {
                    RawDependencyValue::Unresolved
                });
            }
        }

        stack.push(kind, new_role, payload);
    }

    fn pop_container(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        let is_replay = self.replay_depth > 0;
        let Self {
            stack,
            entries,
            budget,
            ..
        } = self;
        match *frame.role() {
            FrameRole::DependencyEntryValue => {
                if let Some(name) = frame.payload.dep_name
                    && let Some(parent) = stack.top()
                    && *parent.role() == FrameRole::DependencySectionValue
                {
                    let section = parent.payload.section;
                    Self::push_entry(entries, budget, section, name, is_replay, || {
                        RawDependencyValue::Entry {
                            version: frame.payload.version,
                            git: frame.payload.git,
                            path: frame.payload.path,
                            sdk: frame.payload.sdk,
                            hosted: frame.payload.hosted,
                        }
                    });
                }
            }
            FrameRole::GitValue => {
                if let Some(parent) = stack.top_mut()
                    && *parent.role() == FrameRole::DependencyEntryValue
                {
                    parent.payload.git = Some(Box::new(RawGitValue::Map {
                        url: frame.payload.git_url,
                        rev: frame.payload.git_ref,
                        path: frame.payload.git_path,
                    }));
                }
            }
            FrameRole::HostedValue => {
                if let Some(parent) = stack.top_mut()
                    && *parent.role() == FrameRole::DependencyEntryValue
                {
                    parent.payload.hosted = Some(Box::new(RawHostedValue::Map {
                        name: frame.payload.hosted_name,
                        url: frame.payload.hosted_url,
                    }));
                }
            }
            _ => {}
        }
    }

    fn on_scalar(
        &mut self,
        value: String,
        style: TScalarStyle,
        anchor_id: usize,
        tag: Option<Tag>,
        marker: &Marker,
    ) {
        if anchor_id != 0 {
            self.anchors.record(anchor_id, &value, (style, tag.clone()));
        }
        // A value-less key (`pkg:` mid-typing) surfaces as an empty plain scalar — without this
        // check it would resolve to `version_req = Some("")` anchored on the *next* key's
        // position, since `locate_value_span` short-circuits for an empty needle. Treated as
        // absent instead, matching `Yaml::Null` handling. An explicit non-null tag
        // (`!!str null`) overrides this — see [`is_plain_null`].
        let is_null = is_plain_null(style, tag.as_ref(), &value);
        let replay_depth = self.replay_depth;

        match self.stack.scalar_position() {
            ScalarPosition::Outside => {}
            ScalarPosition::Key => {
                let role = self.stack.top_role_or(FrameRole::Irrelevant);
                if role == FrameRole::DependencySectionValue {
                    if let Some(top) = self.stack.top_mut() {
                        top.payload.pending_dep_name =
                            Some(MarkedScalar::new(value, style, marker));
                    }
                    self.stack.observe_key(PendingKey::None);
                } else {
                    let key = key_for(role, &value);
                    self.stack.observe_key(key);
                }
            }
            ScalarPosition::Value => {
                let Self {
                    stack,
                    entries,
                    sdk,
                    budget,
                    ..
                } = self;
                let Some(top) = stack.top_mut() else {
                    return;
                };
                match *top.role() {
                    FrameRole::DependencySectionValue => {
                        if let Some(name) = top.payload.pending_dep_name.take() {
                            let section = top.payload.section;
                            Self::push_entry(
                                entries,
                                budget,
                                section,
                                name,
                                replay_depth > 0,
                                || {
                                    if is_null {
                                        RawDependencyValue::Unresolved
                                    } else {
                                        RawDependencyValue::Simple(scalar_field(
                                            replay_depth,
                                            value,
                                            style,
                                            marker,
                                        ))
                                    }
                                },
                            );
                        }
                    }
                    FrameRole::Root | FrameRole::Irrelevant => {}
                    FrameRole::EnvironmentValue => {
                        if *top.pending_key() == PendingKey::EnvSdk && !is_null {
                            *sdk = Some(value);
                        }
                    }
                    FrameRole::DependencyEntryValue
                    | FrameRole::GitValue
                    | FrameRole::HostedValue
                        if !is_null =>
                    {
                        let key = *top.pending_key();
                        top.payload
                            .assign_field(key, scalar_field(replay_depth, value, style, marker));
                    }
                    // A null value for one of the keys above — treated the same as the key
                    // being absent entirely.
                    FrameRole::DependencyEntryValue
                    | FrameRole::GitValue
                    | FrameRole::HostedValue => {}
                }
                stack.consume_value();
            }
        }
    }

    fn on_alias(&mut self, anchor_id: usize, marker: &Marker) {
        // Re-checks `is_plain_null` against the anchor's own style/text — `on_scalar`'s null
        // filter runs at the anchor's definition site, not per alias, so without this an
        // aliased null (`shared: &s ~` / `pkg: *shared`) would resolve to `Some("~")` instead
        // of absent (review finding #1).
        let resolved = self
            .anchors
            .get(anchor_id)
            .filter(|(text, (style, tag))| !is_plain_null(*style, tag.as_ref(), text))
            .map(|(text, (style, _tag))| (text.to_string(), *style));

        match self.stack.scalar_position() {
            ScalarPosition::Outside => {}
            // Mirrors `on_scalar`'s key branch. Previously left `awaiting_key` stuck `true`
            // for an alias-as-key, reinterpreting every later scalar alternately as
            // name/value and corrupting the rest of the section (review finding #2). An
            // unresolvable alias still flips the state correctly, just with no name attached.
            ScalarPosition::Key => {
                let role = self.stack.top_role_or(FrameRole::Irrelevant);
                match (role, resolved) {
                    (FrameRole::DependencySectionValue, Some((text, style))) => {
                        // The marker comes from this alias occurrence, but the text and style
                        // are the anchor's own — `MarkedScalar` never reads `style` when
                        // computing a range, and using the anchor's style keeps this consistent
                        // with the `is_plain_null` check against the anchor's style above.
                        if let Some(top) = self.stack.top_mut() {
                            top.payload.pending_dep_name =
                                Some(MarkedScalar::new(text, style, marker));
                        }
                        self.stack.observe_key(PendingKey::None);
                    }
                    (_, Some((text, _style))) => {
                        let key = key_for(role, &text);
                        self.stack.observe_key(key);
                    }
                    (_, None) => self.stack.observe_key(PendingKey::None),
                }
            }
            ScalarPosition::Value => {
                // A whole-section/mapping alias (`dependencies: *shared_map`, `environment:
                // *shared_env`) — replay the anchor's buffered subtree so `push_container`'s
                // `compute_child_role` routes it as a live start event would. Scoped to `Root`
                // only: `environment: *shared_env` itself fires with the root frame on top (the
                // alias is the value of the `environment:` key, before any `EnvironmentValue`
                // frame is pushed). A dependency's own value aliasing a whole mapping
                // (`pkg: *shared_entry`) is deliberately left to the scalar-only resolution
                // below — see `test_aliased_dependency_to_unresolvable_anchor_still_present`.
                let role = self.stack.top_role_or(FrameRole::Irrelevant);
                if role == FrameRole::Root
                    && let Some((kind, range)) = self.container_anchors.get(&anchor_id).cloned()
                {
                    // The one clone this design pays for replay (see `RecordingFrame`'s docs) —
                    // once per actual alias occurrence, not per event for every open anchor.
                    let Some(slice) = self.event_log.get(range) else {
                        // A miss means the container_anchors/event_log invariant broke. Fail
                        // loudly in debug/tests; in release, skip the alias gracefully rather
                        // than panicking the LSP server.
                        debug_assert!(
                            false,
                            "container_anchors[{anchor_id}] range is out of bounds for event_log"
                        );
                        return;
                    };
                    let events: Vec<(Event, Marker)> = slice.to_vec();
                    self.replay_depth += 1;
                    // Replay pushes/pops directly, out of band from any live key/value position
                    // — this branch only runs in `ScalarPosition::Value`, so it can never be
                    // mistaken for a complex key's subtree.
                    debug_assert!(!self.stack.is_complex_key_position());
                    self.push_container(kind);
                    for (event, event_marker) in events {
                        self.on_event(event, event_marker);
                    }
                    self.pop_container();
                    self.replay_depth -= 1;
                    return;
                }

                let replay_depth = self.replay_depth;
                let Self {
                    stack,
                    entries,
                    sdk,
                    budget,
                    ..
                } = self;
                let Some(top) = stack.top_mut() else {
                    return;
                };
                match *top.role() {
                    FrameRole::DependencySectionValue => {
                        if let Some(name) = top.payload.pending_dep_name.take() {
                            let section = top.payload.section;
                            Self::push_entry(
                                entries,
                                budget,
                                section,
                                name,
                                replay_depth > 0,
                                || {
                                    resolved.map_or(RawDependencyValue::Unresolved, |(text, _)| {
                                        RawDependencyValue::Simple(FieldValue::Unpositioned(text))
                                    })
                                },
                            );
                        }
                    }
                    FrameRole::DependencyEntryValue
                    | FrameRole::GitValue
                    | FrameRole::HostedValue => {
                        if let Some((text, _style)) = resolved {
                            let key = *top.pending_key();
                            top.payload
                                .assign_field(key, FieldValue::Unpositioned(text));
                        }
                    }
                    // Mirrors `on_scalar`'s `EnvironmentValue` arm (critic finding C1): an
                    // alias to a scalar anchor used as `sdk:`'s value must resolve like a
                    // direct scalar, not fall through as a no-op.
                    FrameRole::EnvironmentValue => {
                        if *top.pending_key() == PendingKey::EnvSdk
                            && let Some((text, _style)) = resolved
                        {
                            *sdk = Some(text);
                        }
                    }
                    // `Root` already tried the container-anchor replay above; this arm now
                    // only catches a genuinely unresolvable alias in this position (e.g. an
                    // unknown anchor id) — a graceful no-op, same as `Irrelevant`.
                    FrameRole::Root | FrameRole::Irrelevant => {}
                }
                stack.consume_value();
            }
        }
    }
}

impl MarkedEventReceiver for PubspecReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        // Buffer every event into any open container-anchor recording, only on the live event
        // stream — a nested anchor inside a replayed subtree was already recorded during its
        // own earlier live definition (YAML's forward-reference-only parse order).
        if self.replay_depth == 0 {
            self.record_event(&event, marker);
            if let Event::MappingStart(id, _) | Event::SequenceStart(id, _) = &event
                && *id != 0
            {
                let kind = if matches!(event, Event::MappingStart(..)) {
                    FrameKind::Mapping
                } else {
                    FrameKind::Sequence
                };
                self.recording.push(RecordingFrame {
                    anchor_id: *id,
                    kind,
                    depth: 0,
                    // `record_event` above already appended this container's own `Start`
                    // event to `event_log`, so its length here is exactly the index the
                    // first *inner* event will land at.
                    start: self.event_log.len(),
                });
            }
        }
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => self.pop_container(),
            Event::Scalar(value, style, anchor, tag) => {
                self.on_scalar(value, style, anchor, tag, &marker);
            }
            Event::Alias(anchor) => self.on_alias(anchor, &marker),
            // A `pubspec.yaml` is a single document (`Parser::load(_, false)` stops after the
            // first anyway), but reset defensively rather than assume.
            Event::DocumentStart | Event::DocumentEnd => self.stack.clear(),
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}

/// pub's implicit default package source.
const DEFAULT_PUB_SOURCE: &str = "https://pub.dev";

/// pub's legacy default source alias — still accepted as an explicit `hosted:` value.
const LEGACY_PUB_SOURCE: &str = "https://pub.dartlang.org";

/// Classifies a `hosted:` URL: the implicit default (`pub.dev`, or its legacy
/// `pub.dartlang.org` alias) resolves as `Registry`; anything else has no client this LSP can
/// query, so it becomes `CustomRegistry` — mirroring Bundler's `source "..."` and Cargo's
/// `registry = "..."` handling (#248/#980). Thin wrapper around the shared
/// `deps_core::classify_default_registry_url` (code-review finding #2: this was
/// byte-identical logic duplicated with `deps-bundler`'s `classify_registry_url`).
///
/// Critic finding S3: without this, an explicit `hosted: https://pub.dev` (a legal pubspec
/// pinning the public registry by name rather than relying on the implicit default) was
/// unconditionally classified as `CustomRegistry`, silently losing hover/version-data/
/// diagnostics/OSV for a package that is genuinely on the public registry.
fn classify_hosted_url(url: String) -> DependencySource {
    deps_core::classify_default_registry_url(url, &[DEFAULT_PUB_SOURCE, LEGACY_PUB_SOURCE])
}

fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    raw: RawDependency,
) -> DartDependency {
    // `name_range` is a required (non-`Option`) field on `DartDependency`, unlike
    // `version_range` — a miss here (vanishingly rare for a real dependency name) falls back
    // to `Range::default()`, same as before this fix; only the *optional* fields computed via
    // `FieldValue::range` below propagate a genuine `None`. A replay-derived name (see
    // `RawDependency::name_is_replay`) always forces `Range::default()`, bypassing the lookup
    // entirely — its marker points at the container anchor's own definition site, which would
    // otherwise resolve to a real-but-wrong (and, across multiple aliases, duplicate) range.
    let name_range = if raw.name_is_replay {
        Range::default()
    } else {
        raw.name.range(content, line_table).unwrap_or_default()
    };
    let name_range_is_synthetic = raw.name_is_replay;
    let name = raw.name.into_text();

    match raw.value {
        RawDependencyValue::Simple(ver_field) => {
            let version_range = ver_field.range(content, line_table);
            DartDependency {
                name: name.into(),
                name_range,
                version_req: Some(ver_field.into_text().into()),
                version_range,
                section: raw.section,
                source: DependencySource::Registry,
                git_path: None,
                name_range_is_synthetic,
            }
        }
        RawDependencyValue::Entry {
            version,
            git,
            path,
            sdk,
            hosted,
        } => {
            let (version_req, version_range) = match version {
                Some(field) => {
                    let range = field.range(content, line_table);
                    (Some(field.into_text().into()), range)
                }
                None => (None, None),
            };
            let (source, git_path) = match git.map(|boxed| *boxed) {
                Some(RawGitValue::Scalar(url_field)) => (
                    DependencySource::Git {
                        url: url_field.into_text(),
                        rev: None,
                    },
                    None,
                ),
                Some(RawGitValue::Map { url, rev, path }) => (
                    DependencySource::Git {
                        url: url.map_or_else(String::new, FieldValue::into_text),
                        rev: rev.map(FieldValue::into_text),
                    },
                    path.map(FieldValue::into_text),
                ),
                // `hosted:` declares a non-default pub registry — no client this LSP can
                // query, so it becomes `CustomRegistry` (mirroring Bundler's `source "..."`
                // and Cargo's `registry = "..."` handling, #248/#980) rather than silently
                // falling through to the public `Registry` and leaking a private package
                // name to pub.dev.
                None => match hosted.map(|boxed| *boxed) {
                    Some(RawHostedValue::Scalar(url_field)) => {
                        (classify_hosted_url(url_field.into_text()), None)
                    }
                    Some(RawHostedValue::Map {
                        name: hosted_name,
                        url,
                    }) => {
                        let url_text = url.map_or_else(String::new, FieldValue::into_text);
                        // Critic finding N3: the map form's `name` (if present) is the
                        // *remote* package name, which may differ from the manifest's own
                        // dependency key. Normalizing to `Registry` here would make every
                        // later lookup query pub.dev under the manifest key, not `name` —
                        // this LSP has no client wiring to query under a different remote
                        // name (`hosted.name` is captured but unread, see `RawHostedValue`),
                        // so a renamed package would falsely resolve as "unknown package".
                        // Only normalize when there is no remote-name override, or it agrees
                        // with the manifest key.
                        let remote_name_matches_key = hosted_name
                            .map(FieldValue::into_text)
                            .is_none_or(|remote_name| remote_name == name);
                        let source = if remote_name_matches_key {
                            classify_hosted_url(url_text)
                        } else {
                            DependencySource::CustomRegistry { url: url_text }
                        };
                        (source, None)
                    }
                    None => match (path, sdk) {
                        (Some(path), _) => (
                            DependencySource::Path {
                                path: path.into_text(),
                            },
                            None,
                        ),
                        (None, Some(sdk)) => (
                            DependencySource::Sdk {
                                sdk: sdk.into_text(),
                            },
                            None,
                        ),
                        (None, None) => (DependencySource::Registry, None),
                    },
                },
            };
            DartDependency {
                name: name.into(),
                name_range,
                version_req,
                version_range,
                section: raw.section,
                source,
                git_path,
                name_range_is_synthetic,
            }
        }
        RawDependencyValue::Unresolved => DartDependency {
            name: name.into(),
            name_range,
            version_req: None,
            version_range: None,
            section: raw.section,
            source: DependencySource::Registry,
            git_path: None,
            name_range_is_synthetic,
        },
    }
}

/// Parses a `pubspec.yaml` document into a [`DartParseResult`].
///
/// # Errors
///
/// Returns [`DepsError::ParseError`] if the YAML nesting depth or expanded
/// size exceeds the configured limits, or if the content is not valid YAML.
///
/// # Examples
///
/// ```
/// use deps_dart::parse_pubspec_yaml;
///
/// let content = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
/// let uri = deps_core::test_util::test_uri("/repo/pubspec.yaml");
/// let result = parse_pubspec_yaml(content, &uri).unwrap();
///
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name, "http");
/// assert_eq!(result.dependencies[0].version_req, Some("^1.0.0".into()));
/// ```
pub fn parse_pubspec_yaml(content: &str, doc_uri: &Url) -> Result<DartParseResult> {
    if let Err(depth) =
        deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "pubspec.yaml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_YAML_NESTING_DEPTH
            ))),
        });
    }

    if let Err(bytes) = deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES)
    {
        return Err(DepsError::ParseError {
            file_type: "pubspec.yaml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML expansion {bytes} bytes exceeds maximum of {} bytes",
                deps_core::MAX_YAML_EXPANDED_BYTES
            ))),
        });
    }

    let mut receiver = PubspecReceiver::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
    let mut parser = Parser::new_from_str(content);
    parser
        .load(&mut receiver, false)
        .map_err(|e| DepsError::ParseError {
            file_type: "pubspec.yaml".into(),
            source: Box::new(std::io::Error::other(e.to_string())),
        })?;

    let line_table = LineOffsetTable::new(content);
    let dependency_truncation = receiver.budget.truncation();
    let dependencies = receiver
        .entries
        .into_iter()
        .map(|raw| build_dependency(content, &line_table, raw))
        .collect();

    Ok(DartParseResult {
        dependencies,
        sdk_constraint: receiver.sdk,
        uri: doc_uri.clone(),
        dependency_truncation,
    })
}

deps_core::impl_parse_result!(
    DartParseResult,
    DartDependency {
        dependencies: dependencies,
        uri: uri,
        dependency_truncation: dependency_truncation,
    }
);

#[cfg(test)]
// One test slices a raw line fixture directly to compute an expected UTF-16 offset.
#[allow(clippy::string_slice)]
mod tests {
    use super::*;

    use std::assert_matches;

    fn test_uri() -> Url {
        #[cfg(windows)]
        let path = "C:/test/pubspec.yaml";
        #[cfg(not(windows))]
        let path = "/test/pubspec.yaml";
        Url::from_file_path(path).unwrap()
    }

    #[test]
    fn test_parse_simple_deps() {
        let yaml = r"
name: my_app
dependencies:
  provider: ^6.0.0
  http: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_eq!(result.dependencies[0].name, "provider");
        assert_eq!(result.dependencies[0].version_req, Some("^6.0.0".into()));
        assert_eq!(result.dependencies[1].name, "http");
    }

    #[test]
    fn test_parse_dev_dependencies() {
        let yaml = r"
name: my_app
dev_dependencies:
  flutter_test:
    sdk: flutter
  build_runner: ^2.4.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_matches!(
            result.dependencies[0].section,
            DependencySection::DevDependencies
        );
        assert_matches!(result.dependencies[0].source, DependencySource::Sdk { .. });
    }

    #[test]
    fn test_parse_git_dependency() {
        let yaml = r"
name: my_app
dependencies:
  my_pkg:
    git:
      url: https://github.com/user/repo.git
      ref: main
      path: packages/my_pkg
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert_eq!(rev, &Some("main".into()));
            }
            _ => panic!("Expected Git source"),
        }
        assert_eq!(
            result.dependencies[0].git_path,
            Some("packages/my_pkg".into())
        );
    }

    #[test]
    fn test_parse_path_dependency() {
        let yaml = r"
name: my_app
dependencies:
  local_pkg:
    path: ../local_pkg
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Path { .. });
    }

    #[test]
    fn test_parse_sdk_constraint() {
        let yaml = r"
name: my_app
environment:
  sdk: '>=3.0.0 <4.0.0'
dependencies:
  http: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.sdk_constraint, Some(">=3.0.0 <4.0.0".into()));
    }

    #[test]
    fn test_parse_empty_pubspec() {
        let yaml = "name: empty_app\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
        assert!(result.sdk_constraint.is_none());
    }

    #[test]
    fn test_parse_dependency_overrides() {
        let yaml = r"
name: my_app
dependency_overrides:
  http: ^2.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_matches!(
            result.dependencies[0].section,
            DependencySection::DependencyOverrides
        );
    }

    #[test]
    fn test_dependency_overrides_scalar_form_has_version_range() {
        // Critic finding S2: the cursor-based intermediate fix regressed `version_range` from
        // `Some` to `None` for `dependency_overrides:`'s scalar form specifically — the
        // canonical Dart override pattern (pinning an exact version to override a transitive
        // dependency). The marker-based rewrite has no such regression: every dependency's
        // value position comes directly from its own event, independent of section or of any
        // other dependency's text.
        let yaml = "dependencies:\n  http: ^1.0.0\ndependency_overrides:\n  http: 1.2.3\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let overridden = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, DependencySection::DependencyOverrides))
            .unwrap();
        assert_eq!(overridden.version_req, Some("1.2.3".into()));
        assert!(overridden.version_range.is_some());
    }

    /// Security regression (#980): the `hosted:` shorthand was previously unparsed at any
    /// layer, so a `hosted:` dependency fell through to `Registry` — leaking the private
    /// package name to pub.dev via hover/OSV/completion.
    #[test]
    fn test_parse_hosted_with_version() {
        let yaml = r"
name: my_app
dependencies:
  custom_pkg:
    hosted: https://custom-registry.example.com
    version: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("^1.0.0".into()));
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://custom-registry.example.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// The map form `hosted: {name, url}` — the remote package name may differ from the
    /// manifest's own dependency key.
    #[test]
    fn test_parse_hosted_map_form_with_differing_name() {
        let yaml = r"
name: my_app
dependencies:
  custom_pkg:
    hosted:
      name: internal_custom_pkg
      url: https://custom-registry.example.com
    version: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name, "custom_pkg");
        assert_eq!(result.dependencies[0].version_req, Some("^1.0.0".into()));
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://custom-registry.example.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// The legacy `url`-only map form (no `name:`) is also valid pub syntax.
    #[test]
    fn test_parse_hosted_map_form_url_only() {
        let yaml = r"
name: my_app
dependencies:
  custom_pkg:
    hosted:
      url: https://custom-registry.example.com
    version: ^1.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://custom-registry.example.com");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// `hosted:` must still lose to an explicit `git:` option, mirroring the existing
    /// `git`/`path`/`sdk` precedence in `build_dependency`.
    #[test]
    fn test_hosted_does_not_override_explicit_git_source() {
        let yaml = r"
name: my_app
dependencies:
  my_pkg:
    git: https://github.com/user/repo.git
    hosted: https://custom-registry.example.com
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_matches!(result.dependencies[0].source, DependencySource::Git { .. });
    }

    /// Security/functional regression (impl-critic S3): an explicit `hosted:` value naming the
    /// public registry itself (a legal pubspec pattern for pinning the default explicitly)
    /// must classify as `Registry`, not `CustomRegistry` — otherwise the package silently
    /// loses hover/version-data/diagnostics/OSV even though it genuinely is on pub.dev.
    #[test]
    fn test_hosted_public_registry_url_classified_as_registry() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted: https://pub.dev
    version: ^6.0.0
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// The legacy `pub.dartlang.org` alias for the public registry must also classify as
    /// `Registry`.
    #[test]
    fn test_hosted_legacy_public_registry_url_classified_as_registry() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted: https://pub.dartlang.org
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// The map form of `hosted:` must apply the same public-registry normalization as the
    /// shorthand.
    #[test]
    fn test_hosted_map_form_public_registry_url_classified_as_registry() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted:
      url: https://pub.dev
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// The map form's `name` matching the manifest key is the common, correct case for an
    /// explicit public-registry pin and must still normalize to `Registry`.
    #[test]
    fn test_hosted_map_form_public_registry_with_matching_name_classified_as_registry() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted:
      name: provider
      url: https://pub.dev
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    /// Regression (impl-critic N3): a `hosted:` map whose `name` differs from the manifest
    /// key must stay `CustomRegistry` even when `url` is the public registry — this LSP has
    /// no client wiring to query pub.dev under a name other than the manifest key, so
    /// normalizing to `Registry` here would cause a false "unknown package" lookup under the
    /// wrong (local) name.
    #[test]
    fn test_hosted_map_form_public_registry_with_differing_name_stays_custom_registry() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted:
      name: other_pkg
      url: https://pub.dev
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::CustomRegistry { url } => {
                assert_eq!(url, "https://pub.dev");
            }
            other => panic!("expected CustomRegistry, got {other:?}"),
        }
    }

    /// impl-critic M1: a trailing slash on the public registry URL must not cause a
    /// misclassification as `CustomRegistry`.
    #[test]
    fn test_hosted_public_registry_url_ignores_trailing_slash() {
        let yaml = r"
name: my_app
dependencies:
  provider:
    hosted: https://pub.dev/
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies[0].source, DependencySource::Registry);
    }

    #[test]
    fn test_parse_git_shorthand() {
        let yaml = r"
name: my_app
dependencies:
  my_pkg:
    git: https://github.com/user/repo.git
";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        match &result.dependencies[0].source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo.git");
                assert!(rev.is_none());
            }
            _ => panic!("Expected Git source"),
        }
        assert!(result.dependencies[0].git_path.is_none());
    }

    #[test]
    fn test_position_tracking() {
        let yaml = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // Name should be on line 2 (0-indexed)
        assert_eq!(dep.name_range.start.line, 2);
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;
        let yaml = "name: app\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<DartParseResult>());
    }

    #[test]
    fn test_line_offset_table() {
        let content = "abc\ndef";
        let table = LineOffsetTable::new(content);
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos.line, 1);
        assert_eq!(pos.character, 0);
    }

    #[test]
    fn test_name_range_crosses_multibyte_accented_character() {
        // "é" is a 2-byte UTF-8 character but a single UTF-16 code unit — the name
        // range's end offset lands immediately after it, so position computation must
        // count UTF-16 units (not bytes) and must not panic when slicing content up to
        // that offset (deps-npm's test_line_offset_table_emoji, deps-composer's
        // test_find_positions_no_panic_on_multibyte_utf8_boundary; #542 dedups
        // deps-dart onto the same shared LineOffsetTable).
        let yaml = "dependencies:\n  café: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let dep = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "café")
            .expect("café dependency should be parsed");

        assert_eq!(dep.name_range.start.line, 1);
        assert_eq!(dep.name_range.start.character, 2); // "  " indent
        assert_eq!(dep.name_range.end.character, 6); // indent + "café" (4 UTF-16 units)
    }

    #[test]
    fn test_version_range_crosses_multibyte_emoji_in_same_line() {
        // The emoji is a 4-byte UTF-8 character (2 UTF-16 code units) placed before the
        // `version` key on the same line, so computing `version_range` must walk past it
        // using UTF-16 counting rather than byte counting, and must not panic on the
        // subsequent slice.
        let yaml = "dependencies:\n  http: {description: \"🚀\", version: \"^1.0.0\"}\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let dep = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "http")
            .expect("http dependency should be parsed");
        let version_range = dep.version_range.expect("version range should be found");

        let line = yaml.lines().nth(1).unwrap();
        let quoted_version = "\"^1.0.0\"";
        let byte_offset_in_line = line.find(quoted_version).unwrap() + 1; // skip opening quote
        let expected_character: u32 = line[..byte_offset_in_line]
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum();

        assert_eq!(version_range.start.line, 1);
        assert_eq!(version_range.start.character, expected_character);
        assert_eq!(dep.version_req, Some("^1.0.0".into()));
    }

    #[test]
    fn test_flow_style_dependencies_section() {
        // Critic finding S1: flow-style mappings (`{a: ^1, b: ^1}`) barely benefited from the
        // abandoned cursor-based intermediate fix, since the false-key-line-start check baked
        // into that approach's text search doesn't apply to flow style. The marker-based
        // rewrite has no such gap: `MappingStart`/`Scalar` events fire identically whether the
        // mapping is block- or flow-style.
        let yaml = "dependencies: {provider: ^6.0.0, http: ^1.0.0}\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let provider = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "provider")
            .unwrap();
        let http = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "http")
            .unwrap();
        assert_eq!(provider.version_req, Some("^6.0.0".into()));
        assert_eq!(http.version_req, Some("^1.0.0".into()));
        assert_ne!(provider.name_range, http.name_range);
    }

    #[test]
    fn test_quoted_dependency_name() {
        // Critic finding S1: a quoted map key (`"dep": ^1.0.0`) — valid YAML, but not literally
        // `dep` at the byte level the way the abandoned text-search approach assumed. The
        // scanner's own key-scalar event already gives the dequoted name text directly, so
        // this needs no special handling here.
        let yaml = "dependencies:\n  \"http\": ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name.as_ref(), "http");
        assert_eq!(result.dependencies[0].version_req, Some("^1.0.0".into()));
    }

    #[test]
    fn test_aliased_dependency_version_resolves_text_but_not_range() {
        // Critic finding M1 (original): an aliased dependency value (`http: *shared`) made the
        // abandoned intermediate fix's `find_key_colon_after` scan unbounded on every miss. The
        // marker-based rewrite tracks scalar anchors as they are seen and resolves an
        // `Event::Alias` against them directly — no scanning at all, bounded or otherwise.
        //
        // Critic finding S1 (rewrite review): reusing the anchor definition's own position for
        // `version_range` made every alias of the same anchor resolve to the *identical* range,
        // so "update all" emitted duplicate, overlapping `TextEdit`s (invalid per LSP) — and a
        // range pointing at an unrelated line when the anchor sits outside the dependency's own
        // section. Fixed by failing closed: `version_req` still resolves from the anchor (a
        // genuine improvement over main, which had neither), but `version_range` is `None`,
        // since no position in *this* dependency's own text corresponds to the resolved value.
        let yaml =
            "shared_version: &shared_version \"^1.0.0\"\ndependencies:\n  http: *shared_version\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name.as_ref(), "http");
        assert_eq!(dep.version_req, Some("^1.0.0".into()));
        assert!(dep.version_range.is_none());
    }

    #[test]
    fn test_two_aliases_of_the_same_anchor_do_not_share_a_version_range() {
        // The exact shape critic used to demonstrate the duplicate-`TextEdit` regression: two
        // dependencies both aliasing the same scalar anchor must not resolve to the same
        // `version_range` (previously both got the anchor definition's own range, identical
        // for both — an invalid pair of overlapping "update all" edits).
        let yaml = "shared: &shared ^1.0.0\ndependencies:\n  a: *shared\n  b: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        for dep in &result.dependencies {
            assert_eq!(dep.version_req, Some("^1.0.0".into()));
            assert!(dep.version_range.is_none());
        }
    }

    #[test]
    fn test_aliased_dependency_to_unresolvable_anchor_still_present() {
        // An alias to a *mapping*-shaped anchor (rather than a scalar) is not resolved to a
        // concrete field — matching `deps-github-actions`/`deps-gitlab-ci`'s own convention for
        // unresolvable alias values — but the dependency itself must still appear (its name is
        // real, literal text; only the value is unresolvable), so hover/completion/diagnostics
        // still know the package is declared.
        let yaml = "shared: &shared\n  version: ^1.0.0\ndependencies:\n  http: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name.as_ref(), "http");
        assert!(dep.version_req.is_none());
    }

    #[test]
    fn test_aliased_null_anchor_treated_as_absent() {
        // Review finding #1: `on_alias` did not re-run `is_plain_null` against the resolved
        // anchor text, so an alias to a null-shaped anchor (`&s ~`) resolved to
        // `version_req = Some("~")` instead of being treated as absent, unlike a direct null
        // scalar (which `on_scalar` already filters).
        let yaml = "shared: &shared ~\ndependencies:\n  http: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name.as_ref(), "http");
        assert!(dep.version_req.is_none());
        assert!(dep.version_range.is_none());
    }

    #[test]
    fn test_alias_as_mapping_key_does_not_corrupt_the_rest_of_the_section() {
        // Review finding #2 (most severe): an alias used in *key* position left
        // `awaiting_key` stuck in a state that reinterpreted every later scalar in the
        // mapping alternately as a name/value, corrupting the whole rest of the section —
        // `next_pkg`/`^2.0.0` would otherwise vanish or turn into a bogus entry.
        // (The space before `:` is required — `yaml-rust2`'s scanner otherwise folds the
        // colon into the alias name token itself and rejects it as an unknown anchor.)
        let yaml = "shared_name: &shared_name unused\ndependencies:\n  *shared_name : ^1.0.0\n  next_pkg: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let next_pkg = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "next_pkg")
            .expect("next_pkg must still parse correctly after an aliased key earlier in the same section");
        assert_eq!(next_pkg.version_req, Some("^2.0.0".into()));
    }

    #[test]
    fn test_sequence_valued_complex_key_does_not_corrupt_the_rest_of_the_section() {
        // Sibling bug to the alias-as-key desync (same root cause: `push_container` only
        // special-cased plain scalar/alias keys, so a `SequenceStart` arriving in key position
        // for an explicit complex key (`? <sequence>`) fell through to `FrameRole::Irrelevant`
        // without ever flipping `awaiting_key`, leaving the parent stuck awaiting another key.
        // Without the fix, this produced exactly one bogus dependency
        // (`name="^1.0.0", version_req=Some("simple")`) and silently dropped the real `simple`
        // dependency entirely.
        let yaml = "dependencies:\n  ? - a\n    - b\n  : ^1.0.0\n  simple: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let simple = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "simple")
            .expect(
                "simple must still parse correctly after a sequence-valued complex key earlier \
                 in the same section",
            );
        assert_eq!(simple.version_req, Some("^2.0.0".into()));
        assert!(
            !result
                .dependencies
                .iter()
                .any(|d| d.name.as_ref() == "^1.0.0"),
            "the complex key's own (unresolvable) text must not leak out as a bogus dependency \
             name"
        );
    }

    #[test]
    fn test_map_valued_complex_key_does_not_corrupt_the_rest_of_the_section() {
        // Same hazard as the sequence-key test above, for a map-valued complex key
        // (`? {a: 1}`) — the other shape named in the review.
        let yaml = "dependencies:\n  ? {a: 1}\n  : ^1.0.0\n  simple: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();

        let simple = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "simple")
            .expect(
                "simple must still parse correctly after a map-valued complex key earlier in \
                 the same section",
            );
        assert_eq!(simple.version_req, Some("^2.0.0".into()));
        assert!(
            !result
                .dependencies
                .iter()
                .any(|d| d.name.as_ref() == "^1.0.0"),
            "the complex key's own (unresolvable) text must not leak out as a bogus dependency \
             name"
        );
    }

    #[test]
    fn test_field_range_none_on_locate_value_span_miss_falls_back_to_name_range_downstream() {
        // Review finding #3: `field_range`/`FieldValue::range` used to fabricate
        // `Some(Range::default())` — document-start (0,0)-(0,0) — when `locate_value_span`
        // could not find the value's literal text (e.g. inside a folded block scalar), which
        // bypassed `deps-core`'s `version_range().unwrap_or_else(|| name_range())` fallback and
        // rendered diagnostics at document start. A folded scalar (`a: >\n  >=1.0.0\n  <2.0.0`)
        // reproduces the miss: the block-scalar content is not literally the string
        // `yaml-rust2` resolves it to (folding rewrites line breaks to spaces), so the direct
        // check fails and the bounded same-line fallback cannot find it either (it spans
        // multiple lines).
        let yaml = "dependencies:\n  a: >\n    >=1.0.0\n    <2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(
            dep.version_range.is_none(),
            "an unresolvable value's range must be None, not a fabricated document-start range"
        );
    }

    #[test]
    fn test_aliased_whole_dependencies_section_resolves_all_entries() {
        // Issue #905: an alias to a whole mapping (`dependencies: *shared_deps`) is now
        // reconstructed by buffering the anchor's subtree and replaying it through the normal
        // event dispatch on `Event::Alias` — see `PubspecReceiver::container_anchors`.
        let yaml = "shared_deps: &shared_deps\n  http: ^1.0.0\n  logging: ^1.1.0\ndependencies: *shared_deps\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let http = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "http")
            .expect("http must resolve from the aliased whole section");
        let logging = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "logging")
            .expect("logging must resolve from the aliased whole section");
        assert_eq!(http.version_req, Some("^1.0.0".into()));
        assert_eq!(logging.version_req, Some("^1.1.0".into()));

        // Pitfall 1 (debugger handoff): a replay-derived field's marker points at the anchor's
        // own definition site, not this occurrence, so it must never resolve to a `Positioned`
        // range (which would look plausible for a single alias use but produce duplicate
        // ranges the moment the same anchor is aliased twice — see the test below).
        assert!(http.version_range.is_none());
        assert!(logging.version_range.is_none());
        assert_eq!(http.name_range, Range::default());
        assert_eq!(logging.name_range, Range::default());

        // Critic finding S1: `name_range_is_synthetic()` is the hook `deps-core`'s shared
        // diagnostics/hover code checks before trusting `name_range()` as a real, unique
        // per-dependency position — must be `true` for every replay-derived dependency here.
        use deps_core::Dependency;
        assert!(http.name_range_is_synthetic());
        assert!(logging.name_range_is_synthetic());
    }

    #[test]
    fn test_live_dependency_name_range_is_not_synthetic() {
        // Counterpart to the assertion above: an ordinary, non-aliased dependency's
        // `name_range_is_synthetic()` must stay `false` — only replay-derived dependencies
        // opt into the synthetic-range convention.
        use deps_core::Dependency;
        let yaml = "dependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(!result.dependencies[0].name_range_is_synthetic());
    }

    #[test]
    fn test_two_aliases_of_the_same_whole_section_anchor_do_not_share_a_range() {
        // Pitfall 1: the exact hazard `FieldValue::Unpositioned` already exists to avoid for
        // scalar anchors, reproduced one level up for container anchors — aliasing the same
        // whole section from two different keys must not give both copies of `http` the
        // identical (and thus invalid, once diagnostics emit "update all" text edits) range.
        let yaml =
            "shared: &shared\n  http: ^1.0.0\ndependencies: *shared\ndev_dependencies: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let deps_http = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, DependencySection::Dependencies))
            .expect("dependencies:'s http must be present");
        let dev_http = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, DependencySection::DevDependencies))
            .expect("dev_dependencies:'s http must be present");

        assert_eq!(deps_http.version_req, Some("^1.0.0".into()));
        assert_eq!(dev_http.version_req, Some("^1.0.0".into()));
        assert!(deps_http.version_range.is_none());
        assert!(dev_http.version_range.is_none());
    }

    // deps-lsp#908: `on_alias`'s whole-section container-anchor replay pushes/pops the
    // `FrameStack` directly, out of band from any live key/value position. It must never be
    // mistaken for a complex YAML key's subtree (`FrameStack::is_complex_key_position`) —
    // `on_alias` only enters the replay branch from `ScalarPosition::Value`, which already
    // implies the live top frame is not awaiting a key, so the two can never coincide; a
    // `debug_assert!` in `on_alias` locks this in. This test exercises the replay path in the
    // same document as an explicit complex key elsewhere, so a regression that made them
    // interfere would surface here as either a panic (debug builds) or a dropped/corrupted
    // dependency (release builds).
    #[test]
    fn test_complex_key_inside_a_replayed_whole_section_anchor_does_not_disturb_it() {
        // The complex key sits *inside* the anchored subtree itself, so replaying it (via
        // `on_alias`'s `push_container`/`pop_container` out-of-band calls) drives the
        // complex-key subtree through `FrameStack` a second time, this time under a live
        // `DependencySectionValue` role (from `dependencies: *shared`) rather than the
        // `Irrelevant` role it had on its first, live pass under the unrecognized `shared:`
        // key — exercising the actual replay/complex-key interaction the
        // `is_complex_key_position` debug_assert in `on_alias` guards, unlike a complex key
        // that closes *before* the alias ever replays it.
        let yaml =
            "shared: &shared\n  ? [a, b]\n  : unused\n  http: ^1.0.0\ndependencies: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let http = &result.dependencies[0];
        assert_eq!(http.name.as_ref(), "http");
        assert_eq!(http.version_req, Some("^1.0.0".into()));
        assert!(matches!(http.section, DependencySection::Dependencies));
    }

    #[test]
    fn test_nested_anchor_inside_an_aliased_mapping_still_resolves() {
        // Proves the `RecordingFrame::depth` bookkeeping: a scalar anchor defined *inside* the
        // whole-section anchor's own subtree, and aliased again inside that same subtree, must
        // still resolve correctly once the whole section is itself aliased and replayed.
        let yaml = "shared_deps: &shared_deps\n  http: &http_version ^1.0.0\n  logging: *http_version\ndependencies: *shared_deps\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let http = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "http")
            .unwrap();
        let logging = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "logging")
            .unwrap();
        assert_eq!(http.version_req, Some("^1.0.0".into()));
        assert_eq!(
            logging.version_req,
            Some("^1.0.0".into()),
            "the nested alias inside the replayed subtree must resolve via the already-\
             populated scalar anchor map"
        );
    }

    #[test]
    fn test_self_referential_alias_does_not_hang() {
        // Pitfall 2: `a: &a\n  x: *a` is valid YAML (yaml-rust2 emits `Alias` for it rather
        // than erroring) — the alias fires while the anchor's own `container_anchors` entry is
        // still being recorded (not yet finalized on its `MappingEnd`), so the lookup misses
        // and falls through to the existing graceful "unresolvable" no-op rather than
        // recursing.
        let yaml = "dependencies:\n  shared: &shared\n    x: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name.as_ref(), "shared");
    }

    #[test]
    fn test_aliased_environment_sdk_resolves_the_constraint() {
        // Issue #905's other named case: `environment: *shared_env` aliasing the whole
        // `environment:` mapping (rather than just its `sdk:` value).
        let yaml = "shared_env: &shared_env\n  sdk: '>=3.0.0 <4.0.0'\nenvironment: *shared_env\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.sdk_constraint, Some(">=3.0.0 <4.0.0".into()));
    }

    #[test]
    fn test_aliased_environment_sdk_scalar_resolves_the_constraint() {
        // Critic finding C1: issue #905's *other* literal reproduction — a scalar alias into
        // `environment: sdk:` directly (sharing one constraint string, not a whole mapping),
        // verbatim from the issue body. `on_alias`'s `FrameRole::EnvironmentValue` arm used to
        // be part of a no-op catch-all, so this resolved to `None` even though `on_scalar`'s
        // equivalent arm (a direct, non-aliased `sdk:` value) already worked.
        let yaml = "sdk_ref: &sdk_ref \">=2.12.0 <3.0.0\"\nenvironment:\n  sdk: *sdk_ref\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.sdk_constraint, Some(">=2.12.0 <3.0.0".into()));
    }

    #[test]
    fn test_value_less_dependency_does_not_steal_next_dependencys_range() {
        // Critic finding S2 (rewrite review): a value-less key (`a:` with nothing after it —
        // the normal mid-typing state right after a user types `a:` and presses Enter) used to
        // yield `version_req = Some("")` with a zero-width `version_range` landing on the
        // *next* dependency's own name — `yaml-rust2` synthesizes an empty `Scalar` event for
        // the implicit null, whose marker points at the following token, and
        // `locate_value_span` short-circuits `Some((from, from))` for an empty needle rather
        // than reporting "not found". Hover and inlay hints have no empty-string guard, so this
        // rendered constantly while a user was typing. A value-less key must resolve to no
        // version info at all, matching main's behavior.
        let yaml = "dependencies:\n  a:\n  b: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let a = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "a")
            .unwrap();
        let b = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "b")
            .unwrap();

        assert!(a.version_req.is_none());
        assert!(a.version_range.is_none());
        assert_eq!(b.version_req, Some("^2.0.0".into()));
        assert_eq!(b.name_range.start.line, 2);
    }

    #[test]
    fn test_value_less_nested_field_treated_as_absent() {
        // Same hazard as the value-less top-level test above, but for a nested field
        // (`version:` with nothing after it inside a dependency's own map) — must not set
        // `version_req`/`version_range` at all, matching main's `Yaml::Null` handling (a
        // pattern match against `Yaml::String` simply fails for `Yaml::Null`).
        let yaml = "dependencies:\n  pkg:\n    version:\n    path: ../local\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.version_req.is_none());
        assert!(dep.version_range.is_none());
        assert_matches!(dep.source, DependencySource::Path { .. });
    }

    #[test]
    fn test_explicit_quoted_empty_string_is_not_treated_as_value_less() {
        // The counterpart to the value-less tests above: an *explicit* quoted empty string
        // (`pkg: ""`) is a real, if unusual, value — `is_plain_null` must only fire for a
        // plain (unquoted) empty/null-keyword scalar, matching `Yaml::from_str`'s own
        // `style != Plain => always Yaml::String(v)` rule.
        let yaml = "dependencies:\n  pkg: \"\"\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.version_req, Some(String::new().into()));
    }

    #[test]
    fn test_invalid_yaml() {
        let yaml = "{{invalid yaml";
        let result = parse_pubspec_yaml(yaml, &test_uri());
        assert_matches!(
            result,
            Err(DepsError::ParseError { file_type, .. }) if file_type == "pubspec.yaml"
        );
    }

    #[test]
    fn test_deeply_nested_yaml_rejected_not_crashed() {
        // 6000 comfortably exceeds the empirically bisected real
        // `yaml-rust2` 0.12 crash threshold for this exact payload shape
        // (compact dash chain: aborts at depth 4536 on a 2 MiB debug
        // stack), so this is a genuine regression test for the pre-fix
        // SIGABRT, not just proof the 64 limit fires.
        let yaml = format!("{}1", "- ".repeat(6000));
        let result = parse_pubspec_yaml(&yaml, &test_uri());
        assert!(result.is_err());
    }

    #[test]
    fn test_deeply_nested_yaml_with_apostrophe_rejected_not_crashed() {
        // impl-critic C1: a `'`/`"` inside a plain scalar earlier in the
        // file (e.g. in a description) must not blind the guard to real
        // nesting later in the same file.
        let yaml = format!(
            "name: my_app\ndescription: A package that doesn't panic\ndependencies:\n  foo:\n{}1",
            "- ".repeat(6000)
        );
        let result = parse_pubspec_yaml(&yaml, &test_uri());
        assert!(result.is_err());
    }

    #[test]
    fn test_anchor_alias_expansion_bomb_rejected_not_oomed() {
        // #175: a shallow (depth-2) doubling chain of anchor/alias
        // references, which `check_yaml_nesting_depth` cannot catch since
        // nesting depth stays constant — must be rejected by the expansion
        // budget instead of handed to the event-driven parser, which would
        // OOM/SIGKILL the process on this shape.
        let mut yaml = String::from("name: app\na0: &a0 [x, x]\n");
        for i in 1..=30 {
            yaml.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}]\n", prev = i - 1));
        }
        let result = parse_pubspec_yaml(&yaml, &test_uri());
        // Asserting on the message (not just `is_err()`) pins that this is
        // rejected by the expansion guard specifically, so a future reorder
        // that lets a different guard fire first would be caught.
        match result {
            Err(DepsError::ParseError { source, .. }) => {
                let message = source.to_string();
                assert!(
                    message.contains("YAML expansion"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected DepsError::ParseError, got {other:?}"),
        }
    }

    #[test]
    fn test_asterisk_in_description_not_misread_as_alias() {
        let yaml = "name: my_app\ndescription: A widget *multiplier* helper\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri());
        assert!(result.is_ok());
    }

    #[test]
    fn test_realistic_deeply_nested_pubspec_still_parses() {
        // A legitimately deep (but realistic) pubspec.yaml must still parse
        // successfully — the guard's margin must not produce false
        // positives on real-world manifests.
        let yaml = r"
name: my_app
dependencies:
  http: ^1.0.0
flutter:
  fonts:
    - family: Schyler
      fonts:
        - asset: fonts/Schyler-Regular.ttf
        - asset: fonts/Schyler-Italic.ttf
          style: italic
";
        let result = parse_pubspec_yaml(yaml, &test_uri());
        assert!(result.is_ok());
    }

    /// Builds a `pubspec.yaml` with `n` simple `dependencies` entries, for scaling tests.
    fn many_dependencies_yaml(n: usize) -> String {
        let mut yaml = String::from("name: my_app\ndependencies:\n");
        for i in 0..n {
            yaml.push_str(&format!("  dep_{i:05}: ^1.{i}.0\n"));
        }
        yaml
    }

    /// Builds a document with `depth` levels of nested, mutually-unrelated anchored mappings
    /// (`a0: &a0\n  a1: &a1\n    ...`), each concurrently open while the innermost `inner_lines`
    /// filler fields stream past, followed by a real `dependencies:` section — for
    /// `test_deeply_nested_anchors_resolve_dependency_position_correctly` below.
    fn nested_anchors_then_dependencies_yaml(depth: usize, inner_lines: usize) -> String {
        let mut yaml = String::from("padding:\n");
        for i in 0..depth {
            yaml.push_str(&"  ".repeat(i + 1));
            yaml.push_str(&format!("a{i}: &a{i}\n"));
        }
        let indent = "  ".repeat(depth + 1);
        for i in 0..inner_lines {
            yaml.push_str(&indent);
            yaml.push_str(&format!("field_{i:04}: value_{i:04}\n"));
        }
        yaml.push_str("dependencies:\n  http: ^1.0.0\n");
        yaml
    }

    #[test]
    fn test_deeply_nested_anchors_resolve_dependency_position_correctly() {
        // Critic finding S2: an earlier design cloned every event into every currently-open
        // anchored container's own buffer (a loop over all open `RecordingFrame`s, each
        // appending a clone), so N concurrently-open (nested) anchors wrapping the same inner
        // content multiplied both time and memory by N — measured ~150x memory and ~4x
        // latency from 60 anchors wrapped around a 480 KB payload, none of them ever aliased.
        // Recording via one flat, shared `event_log` (see `RecordingFrame`'s docs) makes this
        // O(1) per event regardless of how many anchors are concurrently open. Scaling behavior
        // is observed (not gated) via `cargo bench -p deps-dart` (`benches/dart_benchmarks.rs`,
        // `anchor_nesting` group) rather than a wall-clock assertion here, which was flaky
        // under CI scheduling contention — this test only checks correctness at depth.
        const INNER_LINES: usize = 2000;
        const SHALLOW_DEPTH: usize = 2;
        const DEEP_DEPTH: usize = 40;

        let shallow_yaml = nested_anchors_then_dependencies_yaml(SHALLOW_DEPTH, INNER_LINES);
        let shallow_result = parse_pubspec_yaml(&shallow_yaml, &test_uri()).unwrap();

        let deep_yaml = nested_anchors_then_dependencies_yaml(DEEP_DEPTH, INNER_LINES);
        let deep_result = parse_pubspec_yaml(&deep_yaml, &test_uri()).unwrap();

        assert_eq!(shallow_result.dependencies.len(), 1);
        assert_eq!(deep_result.dependencies.len(), 1);

        // A dependency count alone wouldn't catch a regression in marker resolution under deep
        // nesting (e.g. every anchor's marker resolving to the wrong position); verify the
        // resolved name/version/position too.
        let shallow_dep = &shallow_result.dependencies[0];
        assert_eq!(shallow_dep.name.as_ref(), "http");
        assert_eq!(shallow_dep.version_req, Some("^1.0.0".into()));
        assert_eq!(
            shallow_dep.name_range.start.line,
            u32::try_from(SHALLOW_DEPTH + INNER_LINES + 2).unwrap()
        );
        assert!(shallow_dep.version_range.is_some());

        let deep_dep = &deep_result.dependencies[0];
        assert_eq!(deep_dep.name.as_ref(), "http");
        assert_eq!(deep_dep.version_req, Some("^1.0.0".into()));
        assert_eq!(
            deep_dep.name_range.start.line,
            u32::try_from(DEEP_DEPTH + INNER_LINES + 2).unwrap()
        );
        assert!(deep_dep.version_range.is_some());
    }

    #[test]
    fn test_many_dependencies_resolve_correct_position_at_scale() {
        // #899: the original hand-rolled `find_key_range`/`find_value_range_after_key` used
        // to re-scan the *entire* document from byte 0 for every single dependency, making
        // parsing O(N x document length). The marker-based rewrite resolves every dependency's
        // position from its own event's marker — O(1) per lookup, independent of N or document
        // length. Scaling behavior is observed (not gated) via `cargo bench -p deps-dart`
        // (`benches/dart_benchmarks.rs`, `many_dependencies` group) rather than a wall-clock
        // ratio assertion here, which was flaky under CI scheduling contention — this test only
        // checks correctness at a large N.
        const SMALL: usize = 1250;
        const LARGE: usize = SMALL * 4;

        let small_yaml = many_dependencies_yaml(SMALL);
        let small_result = parse_pubspec_yaml(&small_yaml, &test_uri()).unwrap();

        let large_yaml = many_dependencies_yaml(LARGE);
        let large_result = parse_pubspec_yaml(&large_yaml, &test_uri()).unwrap();

        assert_eq!(small_result.dependencies.len(), SMALL);
        assert_eq!(large_result.dependencies.len(), LARGE);

        // Bounded lookups must still resolve each dependency's own position, not just be
        // fast.
        let first = &large_result.dependencies[0];
        assert_eq!(first.name.as_ref(), "dep_00000");
        assert_eq!(first.version_req, Some("^1.0.0".into()));
        assert_eq!(first.name_range.start.line, 2);

        let last = &large_result.dependencies[LARGE - 1];
        assert_eq!(last.name.as_ref(), format!("dep_{:05}", LARGE - 1));
        assert_eq!(last.version_req, Some(format!("^1.{}.0", LARGE - 1).into()));
        assert_eq!(
            last.name_range.start.line,
            u32::try_from(LARGE + 1).unwrap()
        );
        assert!(last.version_range.is_some());
    }

    #[test]
    fn test_quoted_keys_resolve_correct_position_at_scale() {
        // Critic finding S1: quoted keys (`"dep": ^1.0.0`) specifically defeated the abandoned
        // cursor-based intermediate fix's line-start text check, reproducing near-quadratic
        // scaling (3.71x -> 3.61x measured for a 2x size step, i.e. essentially unfixed). The
        // marker-based rewrite does not distinguish quoted from plain keys at all. Scaling
        // behavior is observed (not gated) via `cargo bench -p deps-dart`
        // (`benches/dart_benchmarks.rs`, `quoted_keys` group) rather than a wall-clock ratio
        // assertion here, which was flaky under CI scheduling contention — this test only
        // checks correctness at a large N.
        const SMALL: usize = 1250;
        const LARGE: usize = SMALL * 4;

        fn build(n: usize) -> String {
            let mut yaml = String::from("name: my_app\ndependencies:\n");
            for i in 0..n {
                yaml.push_str(&format!("  \"dep_{i:05}\": ^1.{i}.0\n"));
            }
            yaml
        }

        let small_result = parse_pubspec_yaml(&build(SMALL), &test_uri()).unwrap();
        assert_eq!(small_result.dependencies.len(), SMALL);

        let large_result = parse_pubspec_yaml(&build(LARGE), &test_uri()).unwrap();
        assert_eq!(large_result.dependencies.len(), LARGE);

        // A regression collapsing every quoted-key position to a fixed offset (the exact bug
        // class this test exists to catch) would still pass the length checks above, so verify
        // each dependency's own dequoted name and position are resolved correctly.
        let first = &large_result.dependencies[0];
        assert_eq!(first.name.as_ref(), "dep_00000");
        assert_eq!(first.version_req, Some("^1.0.0".into()));
        assert_eq!(first.name_range.start.line, 2);

        let last = &large_result.dependencies[LARGE - 1];
        assert_eq!(last.name.as_ref(), format!("dep_{:05}", LARGE - 1));
        assert_eq!(last.version_req, Some(format!("^1.{}.0", LARGE - 1).into()));
        assert_eq!(
            last.name_range.start.line,
            u32::try_from(LARGE + 1).unwrap()
        );
        assert!(last.version_range.is_some());
    }

    #[test]
    fn test_section_order_independent_of_file_position() {
        // Sections are processed in whatever order they physically appear in the document
        // (the event stream is driven by document order); this exercises that a section
        // appearing earlier than usual — `dev_dependencies:` before `dependencies:` — still
        // resolves both entries' positions correctly.
        let yaml = "name: my_app\ndev_dependencies:\n  build_runner: ^2.4.0\ndependencies:\n  http: ^1.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let dep = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "http")
            .unwrap();
        let dev_dep = result
            .dependencies
            .iter()
            .find(|d| d.name.as_ref() == "build_runner")
            .unwrap();

        assert_eq!(dev_dep.name_range.start.line, 2);
        assert_eq!(dev_dep.version_req, Some("^2.4.0".into()));
        assert_eq!(dep.name_range.start.line, 4);
        assert_eq!(dep.version_req, Some("^1.0.0".into()));
    }

    #[test]
    fn test_duplicate_dependency_name_across_sections_resolves_own_position() {
        // A structural improvement over both the original and the abandoned intermediate fix:
        // since each occurrence's position comes from its own event marker (not a text
        // search), the same package name repeated across sections (e.g. pinned in both
        // `dependencies` and `dependency_overrides`) now correctly resolves to its own line,
        // rather than both resolving to the first occurrence found anywhere in the document.
        let yaml = "dependencies:\n  http: ^1.0.0\ndependency_overrides:\n  http: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);

        let dependencies_entry = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, DependencySection::Dependencies))
            .unwrap();
        let overrides_entry = result
            .dependencies
            .iter()
            .find(|d| matches!(d.section, DependencySection::DependencyOverrides))
            .unwrap();

        assert_eq!(dependencies_entry.version_req, Some("^1.0.0".into()));
        assert_eq!(overrides_entry.version_req, Some("^2.0.0".into()));
        assert_ne!(dependencies_entry.name_range, overrides_entry.name_range);
        assert_ne!(
            dependencies_entry.version_range,
            overrides_entry.version_range
        );
    }

    #[test]
    fn test_version_range_not_lost_to_sibling_field_containing_the_word_version() {
        // A sibling field's own value containing text shaped like a key (here, `description`
        // containing the literal substring "version:") cannot confuse marker-based lookup at
        // all, since there is no text search involved — the scanner's own `version:` key event
        // is unambiguous regardless of what any other field's value contains.
        let yaml = "dependencies:\n  pkg:\n    description: \"see version: 2 notes\"\n    version: \"^1.0.0\"\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.version_req, Some("^1.0.0".into()));
        let version_range = dep
            .version_range
            .expect("version_range must resolve to the real `version:` key");
        assert_eq!(version_range.start.line, 3);
    }

    #[test]
    fn test_version_range_not_lost_to_sibling_field_containing_the_word_version_flow_style() {
        // Same hazard as the block-style test above, but inside a flow-style mapping.
        let yaml =
            "dependencies:\n  pkg: {description: \"see version: 2 notes\", version: \"^1.0.0\"}\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        assert_eq!(dep.version_req, Some("^1.0.0".into()));
        assert!(dep.version_range.is_some());
    }

    #[test]
    fn test_duplicate_dependency_keys_in_one_section_are_both_accepted() {
        // Intentional: this parser (like the pre-rewrite `Yaml`-AST one) does not deduplicate
        // repeated keys within a mapping — the event stream simply yields both scalar pairs,
        // and nothing here rejects or merges them. YAML itself treats duplicate mapping keys
        // as an error in the strictest reading of the spec, but neither `yaml-rust2` nor this
        // parser enforce that; pinning the current (permissive) behavior rather than claiming
        // it is the only valid interpretation.
        let yaml = "dependencies:\n  http: ^1.0.0\n  http: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert!(
            result
                .dependencies
                .iter()
                .all(|d| d.name.as_ref() == "http")
        );
        let reqs: Vec<_> = result
            .dependencies
            .iter()
            .filter_map(|d| d.version_req.as_ref().map(deps_core::VersionReq::as_str))
            .collect();
        assert_eq!(reqs, vec!["^1.0.0", "^2.0.0"]);
    }

    #[test]
    fn test_git_null_value_falls_through_to_sibling_path() {
        // Intentional: a `git:` key with no value (null) never populates `frame.git` (the
        // null guard on `on_scalar`'s `FrameRole::DependencyEntryValue` arm skips the
        // assignment entirely), so `build_dependency` falls through to the `path:`/`sdk:`
        // sibling fields exactly as if `git:` had never been declared at all.
        let yaml = "dependencies:\n  local_pkg:\n    git:\n    path: ../local\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        match &result.dependencies[0].source {
            DependencySource::Path { path } => assert_eq!(path, "../local"),
            other => panic!("expected Path source, got {other:?}"),
        }
    }

    #[test]
    fn test_non_string_yaml_typed_dependency_value_resolves_version_req() {
        // Intentional: this parser never interprets a plain scalar's YAML-implied type (int,
        // float, bool) — every non-null plain scalar's literal text is taken as-is for
        // `version_req`, so a YAML-numeric-looking value like `1.2` (unquoted) resolves to the
        // literal string `"1.2"` rather than `None`.
        let yaml = "dependencies:\n  foo: 1.2\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("1.2".into()));
    }

    #[test]
    fn test_non_string_dependency_key_is_accepted_as_name() {
        // Intentional: a dependency section's key text is taken verbatim regardless of what
        // YAML type it would otherwise imply — an unquoted `123` or `true` key is accepted as
        // a dependency literally named `"123"`/`"true"`, matching how the value side already
        // treats every plain scalar as its literal text (see the sibling non-string-value
        // test above).
        let yaml = "dependencies:\n  123: ^1.0.0\n  true: ^2.0.0\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert!(result.dependencies.iter().any(|d| d.name.as_ref() == "123"));
        assert!(
            result
                .dependencies
                .iter()
                .any(|d| d.name.as_ref() == "true")
        );
    }

    #[test]
    fn test_explicit_str_tag_on_null_like_text_is_not_treated_as_null() {
        // Real fix (#906): `is_plain_null` used to ignore `Event::Scalar`'s tag entirely, so
        // an explicitly-tagged `!!str null` (forcing the literal string `"null"`, per YAML's
        // own tag-resolution rules — see `is_plain_null`'s doc comment) was still treated as
        // an absent value. It must now resolve to the literal string `"null"`.
        let yaml = "dependencies:\n  pkg:\n    version: !!str null\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("null".into()));
    }

    #[test]
    fn test_explicit_null_tag_on_untagged_null_text_is_still_absent() {
        // Companion to the `!!str null` fix above: an explicit `tag:yaml.org,2002:null` tag
        // on null-shaped text must still resolve to absent, the same as an untagged plain
        // null scalar — the fix only changes behavior for a tag that is *not* `null`.
        let yaml = "dependencies:\n  pkg:\n    version: !!null null\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    /// `is_plain_null` was promoted into `deps-core` and widened there to also recognize
    /// `Null`/`NULL` (case-insensitive), driven by `deps-gitlab-ci`'s Psych oracle — this
    /// pins the same widened behavior for `deps-dart`'s own ecosystem specifically. Dart's
    /// own YAML implementation (`package:yaml`, YAML 1.2 core schema) also resolves
    /// `Null`/`NULL` as null, so an untagged `Null`/`NULL` scalar must resolve to absent
    /// here too, not the literal text.
    #[test]
    fn test_capitalized_null_spellings_are_treated_as_absent() {
        let yaml = "dependencies:\n  pkg:\n    version: Null\n  other:\n    version: NULL\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        assert!(result.dependencies[0].version_req.is_none());
        assert!(result.dependencies[1].version_req.is_none());
    }

    #[test]
    fn test_explicit_non_null_tag_on_empty_value_is_still_absent() {
        // impl-critic S1: the `!!str null` fix's `Some(tag)` arm originally returned `false`
        // for *any* non-null tag, including when the scalar text is empty — reintroducing the
        // #899 misanchored-empty-version defect: `version: !!str` (a value-less key, just like
        // `version:` alone) was wrongly resolving to `Some("")` with a bogus zero-width range
        // at the next sibling key's position, instead of staying absent. An empty plain scalar
        // is a value-less key regardless of any tag attached to it.
        let yaml = "dependencies:\n  local_pkg:\n    version: !!str\n    path: ../local\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(
            dep.version_req.is_none(),
            "an empty `!!str`-tagged scalar must be absent, not Some(\"\")"
        );
        assert!(dep.version_range.is_none());
        match &dep.source {
            DependencySource::Path { path } => assert_eq!(path, "../local"),
            other => panic!("expected Path source, got {other:?}"),
        }
    }

    #[test]
    fn test_explicit_non_null_tag_on_empty_dependency_value_is_still_absent() {
        // Same hazard as above, at the dependency-value (section) level rather than a nested
        // entry field: `pkg: !!str` is the section-shorthand form's value-less key.
        let yaml = "dependencies:\n  pkg: !!str\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name.as_ref(), "pkg");
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_aliased_str_tagged_null_like_scalar_resolves_to_literal_text() {
        // The alias path re-runs `is_plain_null` against the anchor's own stored style/tag
        // (see `on_alias`'s comment) — this pins that the tag-aware fix applies identically
        // whether the tagged scalar is seen directly or resolved through an alias.
        let yaml = "shared: &shared !!str null\ndependencies:\n  pkg:\n    version: *shared\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("null".into()));
    }

    #[test]
    fn test_verbatim_null_tag_is_recognized_the_same_as_the_shorthand() {
        // Code-review finding: `is_null_tag` originally only recognized the `!!null`
        // shorthand form (`Tag { handle: "tag:yaml.org,2002:", suffix: "null" }`). The
        // equivalent verbatim tag `!<tag:yaml.org,2002:null>` resolves to a differently
        // shaped `Tag { handle: "", suffix: "tag:yaml.org,2002:null" }` (the whole URI in
        // `suffix`, empty `handle`) — measured directly against `yaml-rust2`'s scanner. Both
        // forms must resolve `~`/`null` text to absent identically.
        let yaml = "dependencies:\n  pkg:\n    version: !<tag:yaml.org,2002:null> null\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(result.dependencies[0].version_req.is_none());
    }

    #[test]
    fn test_verbatim_str_tag_on_null_like_text_is_not_treated_as_null() {
        // Companion to the verbatim-null test above, mirroring the `!!str null` vs.
        // `!!null null` pair: a verbatim tag for a *different* type (`!<tag:yaml.org,2002:str>`)
        // must still force the literal text, not absence.
        let yaml = "dependencies:\n  pkg:\n    version: !<tag:yaml.org,2002:str> null\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].version_req, Some("null".into()));
    }

    #[test]
    fn test_dependency_budget_truncation_follows_physical_document_order_not_section_order() {
        // Intentional: truncation order tracks the event stream's (i.e. the document's
        // physical) order, not a canonical `dependencies`/`dev_dependencies`/
        // `dependency_overrides` section order. Putting `dev_dependencies:` physically first
        // in an oversized manifest means its entries are kept and `dependencies:`'s entries
        // (appearing later in the file) are the ones dropped once the cap is hit.
        let cap = deps_core::MAX_DEPENDENCIES_PER_DOCUMENT;
        let mut yaml = String::from("name: my_app\ndev_dependencies:\n");
        for i in 0..cap {
            yaml.push_str(&format!("  dev_dep_{i:05}: ^1.0.0\n"));
        }
        yaml.push_str("dependencies:\n  http: ^1.0.0\n");

        let result = parse_pubspec_yaml(&yaml, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), cap);
        assert_eq!(result.dependency_truncation, Some((cap, cap + 1)));
        assert!(
            result
                .dependencies
                .iter()
                .all(|d| matches!(d.section, DependencySection::DevDependencies)),
            "the physically-later `dependencies:` section's entry must be the one truncated"
        );
    }

    #[test]
    fn test_dependency_budget_enforced_during_parsing_not_after() {
        // #906 / impl-critic S2: `budget.allow()` used to be checked only in a second pass
        // over `receiver.entries`, after every entry (including ones beyond the cap) had
        // already been collected as a full `RawDependency`. The externally-observable
        // `dependencies.len()`/`dependency_truncation` contract (see the physical-order test
        // above) is identical either way, so it cannot discriminate old from new — this test
        // instead inspects `PubspecReceiver` directly (available within this module) to pin
        // that `receiver.entries` itself, the collection the fix targets, never grows past the
        // cap in the first place.
        let cap = 3;
        let total = cap + 2;
        let yaml = many_dependencies_yaml(total);

        let mut receiver = PubspecReceiver::new(cap);
        let mut parser = Parser::new_from_str(&yaml);
        parser.load(&mut receiver, false).unwrap();

        assert_eq!(
            receiver.entries.len(),
            cap,
            "the receiver's own entry buffer must never exceed the budget's cap"
        );
        assert_eq!(receiver.budget.truncation(), Some((cap, total)));
    }
}

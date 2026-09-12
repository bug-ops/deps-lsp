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
//! Only *scalar* YAML anchors are tracked (see the receiver's own `anchors` field), so an alias to a
//! scalar value (`version: *shared_version`) resolves correctly, but an alias to a whole
//! mapping or sequence does not — `dependencies: *shared_map` (aliasing an entire
//! `dependencies:` section) or `environment: *shared_env` silently yields no dependencies /
//! no `sdk_constraint` for that alias, rather than resolving the aliased structure the way
//! `main`'s `Yaml`-AST-based parser did. Reconstructing this would need buffering and
//! replaying a whole anchored subtree's events, which is a materially larger change than
//! scalar-anchor tracking; tracked as a follow-up rather than attempted here. See
//! `test_aliased_whole_dependencies_section_is_a_known_limitation_losing_all_entries` and
//! `test_aliased_environment_sdk_is_a_known_limitation_losing_the_constraint`, which pin this
//! behavior rather than claim it is correct.

use crate::types::{DartDependency, DependencySection, DependencySource};
use deps_core::lsp_helpers::{LineOffsetTable, locate_value_span, marker_byte_offset};
use deps_core::{DepsError, Result};
use std::collections::HashMap;
use tower_lsp_server::ls_types::{Range, Uri};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
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
    pub uri: Uri,
    /// `Some((kept, total))` once the manifest declared more dependencies than
    /// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (#796), read by
    /// [`deps_core::ParseResult::dependency_truncation`]'s override below.
    pub dependency_truncation: Option<(usize, usize)>,
}

/// A scalar value captured from the event stream: its resolved (dequoted) text, plus the
/// `yaml-rust2` marker line (1-indexed) and column (0-indexed char count) it was read at — for
/// span re-derivation after parsing completes via [`marker_byte_offset`], not
/// `Marker::index()` (#879).
type RawField = (String, usize, usize);

fn raw_field(value: String, marker: &Marker) -> RawField {
    (value, marker.line(), marker.col())
}

/// Whether a plain (unquoted) scalar's text denotes YAML's implicit null (`pkg:` with nothing
/// after the colon, or explicit `~`/`null`) — mirrors `yaml_rust2::Yaml::from_str`'s own
/// `"" | "~" | "null" => Yaml::Null` rule for a plain scalar, which is what the pre-rewrite
/// `Yaml`-AST-based parser relied on to treat a value-less key as "no value" rather than an
/// empty string. A *quoted* empty string (`pkg: ""`) is a real, if unusual, explicit value and
/// must not be treated as absent, matching `Yaml::from_str`'s check applying only when
/// `style == Plain`.
fn is_plain_null(style: TScalarStyle, value: &str) -> bool {
    style == TScalarStyle::Plain && matches!(value, "" | "~" | "null")
}

/// A field's resolved text, plus its position in `content` when one genuinely exists.
enum FieldValue {
    /// A scalar seen directly in the event stream — its own marker gives an exact position.
    Positioned(RawField),
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
            Self::Positioned((text, ..)) | Self::Unpositioned(text) => text,
        }
    }

    fn range(&self, content: &str, line_table: &LineOffsetTable) -> Option<Range> {
        match self {
            Self::Positioned(field) => field_range(content, line_table, field),
            Self::Unpositioned(_) => None,
        }
    }
}

/// Which kind of container a [`Frame`] represents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Mapping,
    Sequence,
}

/// What a [`Frame`] means for dependency-extraction purposes.
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
    /// Anything else — `name:`, `flutter:`, `rules:`, or any other structure this parser does
    /// not need to look inside.
    Irrelevant,
}

/// Which key (if any) a fixed-vocabulary mapping frame is currently awaiting the value for.
/// Not used by [`FrameRole::DependencySectionValue`], whose keys are arbitrary dependency
/// names rather than a fixed set — see [`Frame::pending_dep_name`].
#[derive(Clone, PartialEq, Eq)]
enum PendingKey {
    None,
    Environment,
    Section(DependencySection),
    EnvSdk,
    EntryVersion,
    EntryGit,
    EntryPath,
    EntrySdk,
    GitUrl,
    GitRef,
    GitPath,
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
            _ => PendingKey::None,
        },
        FrameRole::GitValue => match text {
            "url" => PendingKey::GitUrl,
            "ref" => PendingKey::GitRef,
            "path" => PendingKey::GitPath,
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

/// One dependency's value shape, as accumulated from the event stream.
enum RawDependencyValue {
    /// `pkg: ^1.0.0` — a plain version-requirement string.
    Simple(FieldValue),
    /// `pkg:\n  version: ...\n  git: ...` etc. — a nested mapping.
    Entry {
        version: Option<FieldValue>,
        git: Option<RawGitValue>,
        path: Option<FieldValue>,
        sdk: Option<FieldValue>,
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
    name: RawField,
    value: RawDependencyValue,
}

struct Frame {
    kind: FrameKind,
    role: FrameRole,
    /// Which section this frame belongs to — set on a [`FrameRole::DependencySectionValue`]
    /// frame when it is created; read back from the parent frame when a child
    /// [`FrameRole::DependencyEntryValue`] finalizes.
    section: Option<DependencySection>,
    /// Only meaningful for `kind == Mapping`.
    awaiting_key: bool,
    /// Only meaningful for `kind == Mapping`, and not [`FrameRole::DependencySectionValue`].
    pending_key: PendingKey,
    /// `DependencySectionValue` only: the dependency name just read as a key, awaiting its
    /// value.
    pending_dep_name: Option<RawField>,
    /// `DependencyEntryValue` only: the name carried down from the parent
    /// `DependencySectionValue` frame at push time, used to finalize on `MappingEnd`.
    dep_name: Option<RawField>,
    /// `DependencyEntryValue` only: fields accumulated so far.
    version: Option<FieldValue>,
    git: Option<RawGitValue>,
    path: Option<FieldValue>,
    sdk: Option<FieldValue>,
    /// `GitValue` only: fields accumulated so far.
    git_url: Option<FieldValue>,
    git_ref: Option<FieldValue>,
    git_path: Option<FieldValue>,
}

impl Frame {
    fn new(kind: FrameKind, role: FrameRole) -> Self {
        Self {
            kind,
            role,
            section: None,
            awaiting_key: true,
            pending_key: PendingKey::None,
            pending_dep_name: None,
            dep_name: None,
            version: None,
            git: None,
            path: None,
            sdk: None,
            git_url: None,
            git_ref: None,
            git_path: None,
        }
    }
}

/// Collects every dependency's raw field values from the event stream, gated to exactly the
/// three top-level dependency sections' subtrees (plus `environment: sdk:`).
struct PubspecReceiver {
    stack: Vec<Frame>,
    entries: Vec<RawDependency>,
    sdk: Option<String>,
    /// Scalar text and style seen under a YAML anchor (`&name`), keyed by `yaml-rust2`'s
    /// internal anchor id — looked up on `Event::Alias` so an aliased dependency value
    /// (`pkg: *shared`) still resolves to real text instead of being silently dropped. Only
    /// the text (and the style needed to re-check [`is_plain_null`] at the alias site) is
    /// kept, not the anchor's own position — see [`FieldValue::Unpositioned`] for why. An
    /// alias can only refer to an anchor already seen earlier in the document (a YAML
    /// parse-order requirement), so this is always populated by the time an `Alias` event
    /// needing it arrives. Only *scalar* anchors are recorded — a mapping/sequence-valued
    /// anchor (`dependencies: *shared_map` aliasing a whole section) cannot currently be
    /// resolved; see the module-level docs' "Known limitations" note.
    anchors: HashMap<usize, (String, TScalarStyle)>,
}

impl PubspecReceiver {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            entries: Vec::new(),
            sdk: None,
            anchors: HashMap::new(),
        }
    }

    /// Determines the role (and, for a dependency section, which one) a new child container
    /// should have, given the current top-of-stack frame.
    fn compute_child_role(&self, kind: FrameKind) -> (FrameRole, Option<DependencySection>) {
        let Some(top) = self.stack.last() else {
            return if kind == FrameKind::Mapping {
                (FrameRole::Root, None)
            } else {
                (FrameRole::Irrelevant, None)
            };
        };
        if kind == FrameKind::Mapping {
            match top.role {
                FrameRole::Root => match &top.pending_key {
                    PendingKey::Environment => return (FrameRole::EnvironmentValue, None),
                    PendingKey::Section(section) => {
                        return (FrameRole::DependencySectionValue, Some(section.clone()));
                    }
                    _ => {}
                },
                FrameRole::DependencySectionValue if top.pending_dep_name.is_some() => {
                    return (FrameRole::DependencyEntryValue, None);
                }
                FrameRole::DependencyEntryValue if top.pending_key == PendingKey::EntryGit => {
                    return (FrameRole::GitValue, None);
                }
                _ => {}
            }
        }
        (FrameRole::Irrelevant, None)
    }

    fn push_container(&mut self, kind: FrameKind) {
        let (new_role, new_section) = self.compute_child_role(kind);
        let mut carried_name = None;
        let Self { stack, entries, .. } = self;

        if let Some(top) = stack.last_mut() {
            if top.role == FrameRole::DependencySectionValue {
                if let Some(name) = top.pending_dep_name.take() {
                    if new_role == FrameRole::DependencyEntryValue {
                        carried_name = Some(name);
                    } else {
                        // A dependency's value is a sequence, or some other shape this parser
                        // does not resolve a concrete field from.
                        let section = top.section.clone().unwrap_or_default();
                        entries.push(RawDependency {
                            section,
                            name,
                            value: RawDependencyValue::Unresolved,
                        });
                    }
                }
                top.awaiting_key = true;
            } else if top.kind == FrameKind::Mapping {
                top.awaiting_key = true;
                top.pending_key = PendingKey::None;
            }
        }

        let mut frame = Frame::new(kind, new_role);
        frame.section = new_section;
        frame.dep_name = carried_name;
        stack.push(frame);
    }

    fn pop_container(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        let Self { stack, entries, .. } = self;
        match frame.role {
            FrameRole::DependencyEntryValue => {
                if let Some(name) = frame.dep_name
                    && let Some(parent) = stack.last()
                    && parent.role == FrameRole::DependencySectionValue
                {
                    let section = parent.section.clone().unwrap_or_default();
                    entries.push(RawDependency {
                        section,
                        name,
                        value: RawDependencyValue::Entry {
                            version: frame.version,
                            git: frame.git,
                            path: frame.path,
                            sdk: frame.sdk,
                        },
                    });
                }
            }
            FrameRole::GitValue => {
                if let Some(parent) = stack.last_mut()
                    && parent.role == FrameRole::DependencyEntryValue
                {
                    parent.git = Some(RawGitValue::Map {
                        url: frame.git_url,
                        rev: frame.git_ref,
                        path: frame.git_path,
                    });
                }
            }
            _ => {}
        }
        if let Some(top) = stack.last_mut()
            && top.role != FrameRole::DependencySectionValue
            && top.kind == FrameKind::Mapping
        {
            top.awaiting_key = true;
            top.pending_key = PendingKey::None;
        }
    }

    fn on_scalar(&mut self, value: String, style: TScalarStyle, anchor_id: usize, marker: &Marker) {
        if anchor_id != 0 {
            self.anchors.insert(anchor_id, (value.clone(), style));
        }
        // A value-less key (`pkg:` with nothing after it, the normal mid-typing state in a
        // live editor) surfaces here as an empty plain scalar — review found this otherwise
        // yielded `version_req = Some("")` anchored on the *next* key's position (the
        // synthesized empty-scalar event's marker lands there, and `locate_value_span`
        // short-circuits `Some((from, from))` for an empty needle). Treated as absent instead,
        // matching the pre-rewrite `Yaml`-AST parser's own `Yaml::Null` handling.
        let is_null = is_plain_null(style, &value);

        let Self {
            stack,
            entries,
            sdk,
            ..
        } = self;
        let Some(frame) = stack.last_mut() else {
            return;
        };
        if frame.kind != FrameKind::Mapping {
            return;
        }
        if frame.awaiting_key {
            if frame.role == FrameRole::DependencySectionValue {
                frame.pending_dep_name = Some(raw_field(value, marker));
            } else {
                frame.pending_key = key_for(frame.role, &value);
            }
            frame.awaiting_key = false;
            return;
        }

        match frame.role {
            FrameRole::DependencySectionValue => {
                if let Some(name) = frame.pending_dep_name.take() {
                    let section = frame.section.clone().unwrap_or_default();
                    let dep_value = if is_null {
                        RawDependencyValue::Unresolved
                    } else {
                        RawDependencyValue::Simple(FieldValue::Positioned(raw_field(value, marker)))
                    };
                    entries.push(RawDependency {
                        section,
                        name,
                        value: dep_value,
                    });
                }
            }
            FrameRole::Root | FrameRole::Irrelevant => {}
            FrameRole::EnvironmentValue => {
                if frame.pending_key == PendingKey::EnvSdk && !is_null {
                    *sdk = Some(value);
                }
            }
            FrameRole::DependencyEntryValue if !is_null => match frame.pending_key {
                PendingKey::EntryVersion => {
                    frame.version = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                PendingKey::EntryGit => {
                    frame.git = Some(RawGitValue::Scalar(FieldValue::Positioned(raw_field(
                        value, marker,
                    ))));
                }
                PendingKey::EntryPath => {
                    frame.path = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                PendingKey::EntrySdk => {
                    frame.sdk = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                _ => {}
            },
            FrameRole::GitValue if !is_null => match frame.pending_key {
                PendingKey::GitUrl => {
                    frame.git_url = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                PendingKey::GitRef => {
                    frame.git_ref = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                PendingKey::GitPath => {
                    frame.git_path = Some(FieldValue::Positioned(raw_field(value, marker)));
                }
                _ => {}
            },
            // A null value for one of the keys above — treated the same as the key being
            // absent entirely.
            FrameRole::DependencyEntryValue | FrameRole::GitValue => {}
        }
        frame.awaiting_key = true;
        frame.pending_key = PendingKey::None;
    }

    fn on_alias(&mut self, anchor_id: usize, marker: &Marker) {
        // Re-checks `is_plain_null` against the *anchor's own* style/text — `on_scalar`
        // filters a null-like plain scalar before it ever becomes a `FieldValue`, but that
        // check happens at the anchor's definition site, not at each alias resolving it, so
        // without re-running it here an aliased null (`shared: &s ~` / `pkg: *shared`) would
        // resolve to `Some("~")` instead of being treated as absent like `on_scalar` treats a
        // direct null (review finding #1).
        let resolved = self
            .anchors
            .get(&anchor_id)
            .cloned()
            .filter(|(text, style)| !is_plain_null(*style, text))
            .map(|(text, _)| text);

        let Self { stack, entries, .. } = self;
        let Some(top) = stack.last_mut() else {
            return;
        };
        if top.kind != FrameKind::Mapping {
            return;
        }

        if top.awaiting_key {
            // Mirrors `on_scalar`'s key branch. An alias in key position is unusual, but
            // review found the previous code left `awaiting_key` unconditionally `true`
            // afterwards (the same as it already was) instead of flipping it to `false` the
            // way a real key does — every later scalar in the mapping was then reinterpreted
            // alternately as a name/value, corrupting the rest of the section (review finding
            // #2). Best-effort: an alias resolving to real text is treated exactly as a
            // scalar key would be; an unresolvable one (e.g. a mapping-valued anchor) still
            // flips the state correctly, just without a name to attach a value to — the same
            // graceful no-op a `None` `pending_dep_name`/`pending_key` already produces below.
            if let Some(text) = resolved {
                if top.role == FrameRole::DependencySectionValue {
                    top.pending_dep_name = Some(raw_field(text, marker));
                } else {
                    top.pending_key = key_for(top.role, &text);
                }
            } else {
                top.pending_key = PendingKey::None;
            }
            top.awaiting_key = false;
            return;
        }

        match top.role {
            FrameRole::DependencySectionValue => {
                if let Some(name) = top.pending_dep_name.take() {
                    let section = top.section.clone().unwrap_or_default();
                    let value = resolved.map_or(RawDependencyValue::Unresolved, |text| {
                        RawDependencyValue::Simple(FieldValue::Unpositioned(text))
                    });
                    entries.push(RawDependency {
                        section,
                        name,
                        value,
                    });
                }
            }
            FrameRole::DependencyEntryValue => {
                if let Some(text) = resolved {
                    match top.pending_key {
                        PendingKey::EntryVersion => {
                            top.version = Some(FieldValue::Unpositioned(text));
                        }
                        PendingKey::EntryGit => {
                            top.git = Some(RawGitValue::Scalar(FieldValue::Unpositioned(text)));
                        }
                        PendingKey::EntryPath => {
                            top.path = Some(FieldValue::Unpositioned(text));
                        }
                        PendingKey::EntrySdk => {
                            top.sdk = Some(FieldValue::Unpositioned(text));
                        }
                        _ => {}
                    }
                }
            }
            FrameRole::GitValue => {
                if let Some(text) = resolved {
                    match top.pending_key {
                        PendingKey::GitUrl => {
                            top.git_url = Some(FieldValue::Unpositioned(text));
                        }
                        PendingKey::GitRef => {
                            top.git_ref = Some(FieldValue::Unpositioned(text));
                        }
                        PendingKey::GitPath => {
                            top.git_path = Some(FieldValue::Unpositioned(text));
                        }
                        _ => {}
                    }
                }
            }
            // A whole-section/mapping alias (`dependencies: *shared_map`,
            // `environment: *shared_env`) is not resolved — see the module-level docs' "Known
            // limitations" note.
            FrameRole::Root | FrameRole::EnvironmentValue | FrameRole::Irrelevant => {}
        }
        top.awaiting_key = true;
        top.pending_key = PendingKey::None;
    }
}

impl MarkedEventReceiver for PubspecReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => self.pop_container(),
            Event::Scalar(value, style, anchor, _tag) => {
                self.on_scalar(value, style, anchor, &marker);
            }
            Event::Alias(anchor) => self.on_alias(anchor, &marker),
            // A `pubspec.yaml` is a single document (`Parser::load(_, false)` stops after the
            // first anyway), but reset defensively rather than assume.
            Event::DocumentStart | Event::DocumentEnd => self.stack.clear(),
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}

/// Resolves `field`'s range in `content`, or `None` if `locate_value_span` cannot find it
/// (e.g. a folded/multiline or escaped-quote scalar) — callers must not fabricate a
/// zero-position range on a miss, since `deps-core`'s diagnostics fall back from
/// `version_range` to `name_range` specifically when the former is `None` (a bogus
/// `Some((0,0),(0,0))` would bypass that fallback and render at document start instead).
fn field_range(content: &str, line_table: &LineOffsetTable, field: &RawField) -> Option<Range> {
    let (text, line, col) = field;
    let value_start = marker_byte_offset(content, line_table, *line, *col);
    locate_value_span(content, value_start, text).map(|(start, end)| {
        Range::new(
            line_table.byte_offset_to_position(content, start),
            line_table.byte_offset_to_position(content, end),
        )
    })
}

fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    raw: RawDependency,
) -> DartDependency {
    // `name_range` is a required (non-`Option`) field on `DartDependency`, unlike
    // `version_range` — a miss here (vanishingly rare for a real dependency name) falls back
    // to `Range::default()`, same as before this fix; only the *optional* fields computed via
    // `FieldValue::range` below propagate a genuine `None`.
    let name_range = field_range(content, line_table, &raw.name).unwrap_or_default();
    let name = raw.name.0;

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
            }
        }
        RawDependencyValue::Entry {
            version,
            git,
            path,
            sdk,
        } => {
            let (version_req, version_range) = match version {
                Some(field) => {
                    let range = field.range(content, line_table);
                    (Some(field.into_text().into()), range)
                }
                None => (None, None),
            };
            let (source, git_path) = match git {
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
            };
            DartDependency {
                name: name.into(),
                name_range,
                version_req,
                version_range,
                section: raw.section,
                source,
                git_path,
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
pub fn parse_pubspec_yaml(content: &str, doc_uri: &Uri) -> Result<DartParseResult> {
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

    let mut receiver = PubspecReceiver::new();
    let mut parser = Parser::new_from_str(content);
    parser
        .load(&mut receiver, false)
        .map_err(|e| DepsError::ParseError {
            file_type: "pubspec.yaml".into(),
            source: Box::new(std::io::Error::other(e.to_string())),
        })?;

    let line_table = LineOffsetTable::new(content);
    let mut dependencies = Vec::new();
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);

    for raw in receiver.entries {
        if !budget.allow() {
            continue;
        }
        dependencies.push(build_dependency(content, &line_table, raw));
    }

    Ok(DartParseResult {
        dependencies,
        sdk_constraint: receiver.sdk,
        uri: doc_uri.clone(),
        dependency_truncation: budget.truncation(),
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

    fn test_uri() -> Uri {
        #[cfg(windows)]
        let path = "C:/test/pubspec.yaml";
        #[cfg(not(windows))]
        let path = "/test/pubspec.yaml";
        Uri::from_file_path(path).unwrap()
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
    fn test_aliased_whole_dependencies_section_is_a_known_limitation_losing_all_entries() {
        // Review finding #4, assessed and deferred (see module-level "Known limitations"
        // docs): only *scalar* anchors are tracked, so an alias to a whole mapping
        // (`dependencies: *shared_deps`) cannot currently be reconstructed. This pins the
        // resulting data loss as a documented, intentional limitation rather than silently
        // letting it regress further — `main` resolved this correctly via `doc["dependencies"]`
        // regardless of whether it came through an alias.
        let yaml = "shared_deps: &shared_deps\n  http: ^1.0.0\ndependencies: *shared_deps\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(
            result.dependencies.is_empty(),
            "known limitation: an aliased whole `dependencies:` section currently loses all \
             its entries — see the module-level docs and the P2 follow-up issue"
        );
    }

    #[test]
    fn test_aliased_environment_sdk_is_a_known_limitation_losing_the_constraint() {
        // Same limitation as above, for `environment: *shared_env` aliasing a whole
        // `environment:` mapping (rather than just its `sdk:` value).
        let yaml = "shared_env: &shared_env\n  sdk: '>=3.0.0 <4.0.0'\nenvironment: *shared_env\n";
        let result = parse_pubspec_yaml(yaml, &test_uri()).unwrap();
        assert!(
            result.sdk_constraint.is_none(),
            "known limitation: an aliased whole `environment:` mapping currently loses \
             sdk_constraint — see the module-level docs and the P2 follow-up issue"
        );
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

    #[test]
    fn test_many_dependencies_key_and_value_lookup_scales_linearly_not_quadratically() {
        // #899: the original hand-rolled `find_key_range`/`find_value_range_after_key` used
        // to re-scan the *entire* document from byte 0 for every single dependency, making
        // parsing O(N x document length). The marker-based rewrite resolves every dependency's
        // position from its own event's marker — O(1) per lookup, independent of N or document
        // length — so this asserts on the *scaling ratio* (4x input size should cost roughly
        // 4x time, not 16x) rather than an absolute wall-clock ceiling, which would not catch
        // a reintroduced quadratic regression at sizes this small.
        const SMALL: usize = 1250;
        const LARGE: usize = SMALL * 4;

        let small_yaml = many_dependencies_yaml(SMALL);
        let start = std::time::Instant::now();
        let small_result = parse_pubspec_yaml(&small_yaml, &test_uri()).unwrap();
        let small_elapsed = start.elapsed();

        let large_yaml = many_dependencies_yaml(LARGE);
        let start = std::time::Instant::now();
        let large_result = parse_pubspec_yaml(&large_yaml, &test_uri()).unwrap();
        let large_elapsed = start.elapsed();

        assert_eq!(small_result.dependencies.len(), SMALL);
        assert_eq!(large_result.dependencies.len(), LARGE);

        // Floor the divisor so a near-instant `small_elapsed` (a very fast machine) cannot
        // make the ratio spuriously huge.
        let floor = std::time::Duration::from_micros(200);
        let ratio = large_elapsed.as_secs_f64() / small_elapsed.max(floor).as_secs_f64();
        assert!(
            ratio < 8.0,
            "parsing {LARGE} dependencies took {large_elapsed:?} vs {small_elapsed:?} for \
             {SMALL} (ratio {ratio:.1}x for a 4x size increase) — expected roughly linear \
             (~4x), not quadratic (~16x) scaling"
        );

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
    fn test_quadratic_scan_stays_bounded_with_quoted_keys() {
        // Critic finding S1: quoted keys (`"dep": ^1.0.0`) specifically defeated the abandoned
        // cursor-based intermediate fix's line-start text check, reproducing near-quadratic
        // scaling (3.71x -> 3.61x measured for a 2x size step, i.e. essentially unfixed). The
        // marker-based rewrite does not distinguish quoted from plain keys at all.
        const SMALL: usize = 1250;
        const LARGE: usize = SMALL * 4;

        fn build(n: usize) -> String {
            let mut yaml = String::from("name: my_app\ndependencies:\n");
            for i in 0..n {
                yaml.push_str(&format!("  \"dep_{i:05}\": ^1.{i}.0\n"));
            }
            yaml
        }

        let small_elapsed = {
            let yaml = build(SMALL);
            let start = std::time::Instant::now();
            let result = parse_pubspec_yaml(&yaml, &test_uri()).unwrap();
            assert_eq!(result.dependencies.len(), SMALL);
            start.elapsed()
        };
        let large_elapsed = {
            let yaml = build(LARGE);
            let start = std::time::Instant::now();
            let result = parse_pubspec_yaml(&yaml, &test_uri()).unwrap();
            assert_eq!(result.dependencies.len(), LARGE);
            start.elapsed()
        };

        let floor = std::time::Duration::from_micros(200);
        let ratio = large_elapsed.as_secs_f64() / small_elapsed.max(floor).as_secs_f64();
        assert!(
            ratio < 8.0,
            "parsing {LARGE} quoted-key dependencies took {large_elapsed:?} vs \
             {small_elapsed:?} for {SMALL} (ratio {ratio:.1}x) — expected roughly linear \
             scaling"
        );
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
}

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
    LineOffsetTable, MarkedScalar, byte_span_to_range, is_full_sha, is_tag_shaped,
    marker_byte_offset, warn_rejected_value,
};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::parser::DependencySource;
use deps_core::yaml_anchor::{AnchorLimits, ScalarAnchorTable};
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{DepsError, Result};
use std::collections::HashSet;
use tower_lsp_server::ls_types::Uri;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

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
        FrameRole::IncludeEntry => match text {
            "project" => PendingKey::Project,
            "ref" => PendingKey::Ref,
            "component" => PendingKey::Component,
            "template" => PendingKey::Template,
            "remote" => PendingKey::Remote,
            "local" => PendingKey::Local,
            _ => PendingKey::None,
        },
        FrameRole::IncludeValue | FrameRole::Irrelevant => PendingKey::None,
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
#[derive(Default)]
struct RawEntry {
    project: Option<RawField>,
    ref_field: Option<RawField>,
    component: Option<RawField>,
    has_template: bool,
    has_remote: bool,
    has_local: bool,
}

/// The generic frame-stack mechanics ([`deps_core::yaml_walk::FrameStack`]) driven by
/// [`GitlabCiReceiver`], parameterized on this crate's own role/key vocabulary and
/// per-frame payload (each open `IncludeEntry` mapping's [`RawEntry`] under
/// construction).
type Stack = FrameStack<FrameRole, PendingKey, RawEntry>;

/// Collects every `include:` entry's raw field values, gated to exactly the top-level
/// `include:` key's subtree — reachable via a literal `include:` scalar key or, since #942,
/// an alias key whose resolved anchor text is `"include"` (see [`key_for`]).
struct GitlabCiReceiver {
    stack: Stack,
    entries: Vec<RawEntry>,
    /// Anchor id -> anchored scalar text, built during this same event-stream pass (spec
    /// FR-001). Not scoped to `include:` — an anchor can be defined anywhere in the
    /// document (e.g. at the document root) and aliased later inside `include:`. Bounded by
    /// [`MAX_ANCHOR_VALUE_CHARS`]/[`MAX_ANCHOR_TABLE_ENTRIES`] (FR-002); never reset between
    /// this crate's multi-document `spec:`-header parses, since a cross-document alias id
    /// collision is already a whole-document load error in `yaml-rust2` before this code
    /// runs (spec Data Model).
    anchors: ScalarAnchorTable,
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
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        // Computed from the stack's state *before* `FrameStack::push` transitions the
        // parent (a complex YAML key's subtree included) — matching `key_for`'s own
        // reliance on the parent's still-live `pending_key`/`role`.
        let role = match self.stack.top() {
            None => {
                if kind == FrameKind::Mapping {
                    FrameRole::Root
                } else {
                    FrameRole::Irrelevant
                }
            }
            Some(parent) if parent.kind() == FrameKind::Sequence => {
                if *parent.role() == FrameRole::IncludeValue && kind == FrameKind::Mapping {
                    FrameRole::IncludeEntry
                } else {
                    FrameRole::Irrelevant
                }
            }
            Some(parent) => match (*parent.role(), *parent.pending_key(), kind) {
                (FrameRole::Root, PendingKey::Include, FrameKind::Sequence) => {
                    FrameRole::IncludeValue
                }
                (FrameRole::Root, PendingKey::Include, FrameKind::Mapping) => {
                    FrameRole::IncludeEntry
                }
                _ => FrameRole::Irrelevant,
            },
        };
        self.stack.push(kind, role, RawEntry::default());
    }

    fn pop_container(&mut self) {
        if let Some(frame) = self.stack.pop()
            && *frame.role() == FrameRole::IncludeEntry
        {
            self.entries.push(frame.payload);
        }
    }
}

impl MarkedEventReceiver for GitlabCiReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => self.pop_container(),
            Event::Scalar(value, style, anchor_id, _tag) => {
                // FR-001: recorded regardless of scalar position — an anchor can be
                // defined anywhere in the document (e.g. `.pin: &pin v1.2.3` at the
                // document root, entirely outside `include:`), and this is the only
                // event-stream pass this parser makes.
                self.anchors.record(anchor_id, &value, ());
                match self.stack.scalar_position() {
                    // A bare scalar sequence item (e.g. `include: - templates/x.yml`, the
                    // `local:` shorthand) carries nothing to record; irrelevant items are
                    // ignored the same way.
                    ScalarPosition::Outside => {}
                    ScalarPosition::Key => {
                        let role = self.stack.top_role_or(FrameRole::Irrelevant);
                        self.stack.observe_key(key_for(role, &value));
                    }
                    ScalarPosition::Value => {
                        if let Some(top) = self.stack.top_mut()
                            && *top.role() == FrameRole::IncludeEntry
                        {
                            let field = RawField::Literal(MarkedScalar::new(value, style, &marker));
                            match *top.pending_key() {
                                PendingKey::Project => top.payload.project = Some(field),
                                PendingKey::Ref => top.payload.ref_field = Some(field),
                                PendingKey::Component => top.payload.component = Some(field),
                                PendingKey::Template => top.payload.has_template = true,
                                PendingKey::Remote => top.payload.has_remote = true,
                                PendingKey::Local => top.payload.has_local = true,
                                PendingKey::None | PendingKey::Include => {}
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
            // *capture* (FR-004) both additionally depend on a value-table hit.
            Event::Alias(id) => match self.stack.scalar_position() {
                ScalarPosition::Outside => self.stack.consume_value(),
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
                        .map_or(PendingKey::None, |(text, ())| key_for(role, text));
                    self.stack.observe_key(key);
                }
                ScalarPosition::Value => {
                    if let Some(top) = self.stack.top_mut()
                        && *top.role() == FrameRole::IncludeEntry
                        && let Some((text, ())) = self.anchors.get(id)
                    {
                        let field = RawField::Alias {
                            text: text.to_string(),
                            line: marker.line(),
                            col: marker.col(),
                        };
                        match *top.pending_key() {
                            PendingKey::Project => top.payload.project = Some(field),
                            PendingKey::Ref => top.payload.ref_field = Some(field),
                            PendingKey::Component => top.payload.component = Some(field),
                            // FR-004 scopes the capture to project/ref/component only — a
                            // `template:`/`remote:`/`local:` alias (or an unrecognized key,
                            // or `<<:`, EC-006) is left uncaptured, matching FR-005's
                            // "capture nothing" default for every other pending key.
                            PendingKey::Template
                            | PendingKey::Remote
                            | PendingKey::Local
                            | PendingKey::None
                            | PendingKey::Include => {}
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
        InstanceHostOutcome::Blocked(configured_raw, class) => HostRef::PolicyBlocked {
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
                declaration_key: format!("component-host:{host_expr}"),
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
    uri: &Uri,
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
    use std::sync::{Arc, RwLock};
    use tower_lsp_server::ls_types::Range;

    fn test_uri() -> Uri {
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

    /// EC-007: `- *tpl` (a whole mapping anchor aliased as an `include:` sequence item) —
    /// deferred non-goal, must stay a table miss with zero records, matching today.
    #[test]
    fn test_mapping_anchor_aliased_as_sequence_item_produces_no_dependency() {
        let (policy, instance_host) = ctx();
        let content = ".tpl: &tpl {project: org/proj, ref: v1.0.0}\ninclude:\n  - *tpl\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert!(result.dependencies.is_empty(), "{:?}", result.dependencies);
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

    /// EC-012: an anchored empty scalar (`x: &e` / `ref: *e`) is a table hit whose text is
    /// `""` — must resolve without panicking and without producing a misleading non-empty
    /// display.
    #[test]
    fn test_alias_to_empty_anchor_is_safe() {
        let (policy, instance_host) = ctx();
        let content = "x: &e\ninclude:\n  - project: org/proj\n    ref: *e\n";
        let result = parse_gitlab_ci_yaml(content, &test_uri(), &policy, &instance_host).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert!(dep.is_alias_occurrence);
        assert_eq!(
            dep.version_req.as_ref().map(deps_core::VersionReq::as_str),
            Some("")
        );
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
}

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
//! left [`crate::types::HostRef::Unresolved`] otherwise (spec FR-011a/FR-012).

use crate::host::{
    GitlabHost, GitlabInstanceHost, is_valid_gitlab_coordinate, is_valid_path_segment,
};
use crate::types::{
    EndpointKind, GitlabCiDependency, GitlabCiParseResult, GitlabRoute, HostRef, IncludeKind,
    PinStyle,
};
use deps_core::lsp_helpers::{
    CharOffsets, LineOffsetTable, is_full_sha, is_tag_shaped, locate_value_span,
    warn_rejected_value,
};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::parser::DependencySource;
use deps_core::{DepsError, Result};
use std::collections::HashSet;
use tower_lsp_server::ls_types::{Range, Uri};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Bound on distinct literal `component:` hosts admitted per document (spec plan §4.6) —
/// the bound that matters for a `didOpen` burst, protecting `HttpCache`'s unbounded
/// per-origin transport pool from a `.gitlab-ci.yml` naming N distinct hosts on one parse.
const MAX_HOSTS_PER_DOCUMENT: usize = 8;

/// Placeholder display text for a `project:` include's implicit host, and for a
/// `$CI_SERVER_FQDN`-relative `component:` include with no configured instance host.
const CI_SERVER_FQDN: &str = "$CI_SERVER_FQDN";

/// Which container kind a [`Frame`] represents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Mapping,
    Sequence,
}

/// What a [`Frame`] means for include-entry extraction purposes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameRole {
    /// The document's root mapping — scanned only for a top-level `include:` key.
    Root,
    /// The value of a top-level `include:` key, when it is a sequence of entries.
    IncludeValue,
    /// One include entry mapping — either a `include:`'s single-mapping form, or one
    /// mapping item inside an [`FrameRole::IncludeValue`] sequence. Its direct scalar keys
    /// (`project`/`ref`/`component`/`template`/`remote`/`local`) are captured into
    /// [`Frame::entry`].
    IncludeEntry,
    /// Anything else — a job body, `inputs:`, `rules:`, or any other structure this parser
    /// does not need to look inside.
    Irrelevant,
}

/// Which key (if any) a [`FrameRole::Root`] or [`FrameRole::IncludeEntry`] mapping frame is
/// currently awaiting the value for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKey {
    None,
    Include,
    Project,
    Ref,
    Component,
    Template,
    Remote,
    Local,
}

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

/// One raw scalar value captured from an include entry: its text, YAML scalar style, and
/// `yaml-rust2` char index (for span re-derivation after parsing completes).
type RawField = (String, TScalarStyle, usize);

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

struct Frame {
    kind: FrameKind,
    role: FrameRole,
    /// Only meaningful for `kind == Mapping`.
    awaiting_key: bool,
    /// Only meaningful for `kind == Mapping`.
    pending_key: PendingKey,
    /// Only meaningful for `role == IncludeEntry`.
    entry: RawEntry,
}

/// Collects every `include:` entry's raw field values, gated to exactly the top-level
/// `include:` key's subtree.
struct GitlabCiReceiver {
    stack: Vec<Frame>,
    entries: Vec<RawEntry>,
}

impl GitlabCiReceiver {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        let role = match self.stack.last() {
            None => {
                if kind == FrameKind::Mapping {
                    FrameRole::Root
                } else {
                    FrameRole::Irrelevant
                }
            }
            Some(parent) if parent.kind == FrameKind::Sequence => {
                if parent.role == FrameRole::IncludeValue && kind == FrameKind::Mapping {
                    FrameRole::IncludeEntry
                } else {
                    FrameRole::Irrelevant
                }
            }
            Some(parent) => match (parent.role, parent.pending_key, kind) {
                (FrameRole::Root, PendingKey::Include, FrameKind::Sequence) => {
                    FrameRole::IncludeValue
                }
                (FrameRole::Root, PendingKey::Include, FrameKind::Mapping) => {
                    FrameRole::IncludeEntry
                }
                _ => FrameRole::Irrelevant,
            },
        };
        self.consume_pending_value();
        self.stack.push(Frame {
            kind,
            role,
            awaiting_key: true,
            pending_key: PendingKey::None,
            entry: RawEntry::default(),
        });
    }

    fn consume_pending_value(&mut self) {
        if let Some(top) = self.stack.last_mut()
            && top.kind == FrameKind::Mapping
        {
            top.awaiting_key = true;
            top.pending_key = PendingKey::None;
        }
    }

    fn pop_container(&mut self) {
        if let Some(frame) = self.stack.pop()
            && frame.role == FrameRole::IncludeEntry
        {
            self.entries.push(frame.entry);
        }
        self.consume_pending_value();
    }
}

impl MarkedEventReceiver for GitlabCiReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => self.pop_container(),
            Event::Scalar(value, style, _anchor, _tag) => {
                let Some(frame) = self.stack.last_mut() else {
                    return;
                };
                if frame.kind != FrameKind::Mapping {
                    // A bare scalar sequence item (e.g. `include: - templates/x.yml`, the
                    // `local:` shorthand) carries nothing to record; irrelevant items are
                    // ignored the same way.
                    return;
                }
                if frame.awaiting_key {
                    frame.pending_key = key_for(frame.role, &value);
                    frame.awaiting_key = false;
                } else {
                    if frame.role == FrameRole::IncludeEntry {
                        match frame.pending_key {
                            PendingKey::Project => {
                                frame.entry.project = Some((value, style, marker.index()));
                            }
                            PendingKey::Ref => {
                                frame.entry.ref_field = Some((value, style, marker.index()));
                            }
                            PendingKey::Component => {
                                frame.entry.component = Some((value, style, marker.index()));
                            }
                            PendingKey::Template => frame.entry.has_template = true,
                            PendingKey::Remote => frame.entry.has_remote = true,
                            PendingKey::Local => frame.entry.has_local = true,
                            PendingKey::None | PendingKey::Include => {}
                        }
                    }
                    frame.awaiting_key = true;
                    frame.pending_key = PendingKey::None;
                }
            }
            // A `*anchor` alias value must still clear the pending-key slot, mirroring
            // `deps-github-actions`'s identical fix — GitLab CI files use YAML anchors
            // heavily for job reuse, so this is a real, not merely defensive, case here.
            Event::Alias(_) => self.consume_pending_value(),
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
        HostRef::Unresolved(_) | HostRef::CapacityRefused(_) => project_path.to_string(),
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
    }
}

fn resolve_project_host(instance_host: &GitlabInstanceHost) -> HostRef {
    instance_host.get().map_or_else(
        || HostRef::Unresolved(CI_SERVER_FQDN.to_string()),
        HostRef::Literal,
    )
}

fn resolve_component_host(
    host_expr: &str,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
    admitted_origins: &mut HashSet<String>,
) -> HostRef {
    if host_expr.starts_with('$') {
        return instance_host.get().map_or_else(
            || HostRef::Unresolved(host_expr.to_string()),
            HostRef::Literal,
        );
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
        Err(_) => HostRef::Unresolved(host_expr.to_string()),
    }
}

fn make_range(line_table: &LineOffsetTable, content: &str, start: usize, end: usize) -> Range {
    Range::new(
        line_table.byte_offset_to_position(content, start),
        line_table.byte_offset_to_position(content, end),
    )
}

fn build_project_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    char_offsets: &CharOffsets,
    instance_host: &GitlabInstanceHost,
    project_field: RawField,
    ref_field: Option<RawField>,
) -> Option<(GitlabCiDependency, Option<(String, GitlabRoute)>)> {
    let (raw_project, project_style, project_char_index) = project_field;
    if !is_valid_gitlab_coordinate(&raw_project) {
        warn_rejected_value(
            "is_valid_gitlab_coordinate",
            "gitlab-ci project: value",
            &raw_project,
        );
        return None;
    }

    let value_start = char_offsets.byte_offset(project_char_index);
    let (raw_start, raw_end) = locate_value_span(content, value_start, &raw_project)?;
    let name_range = make_range(line_table, content, raw_start, raw_end);

    let host = resolve_project_host(instance_host);
    let name = host_qualified_name(&host, &raw_project, None);

    let (version_req, version_range, pin, is_plain_scalar) = match ref_field {
        Some((ref_text, ref_style, ref_char_index)) => {
            let ref_value_start = char_offsets.byte_offset(ref_char_index);
            let (rs, re) = locate_value_span(content, ref_value_start, &ref_text)?;
            let range = make_range(line_table, content, rs, re);
            let pin = classify_project_pin(&ref_text);
            let plain = ref_style == TScalarStyle::Plain;
            (Some(ref_text.into()), Some(range), Some(pin), plain)
        }
        None => (None, None, None, project_style == TScalarStyle::Plain),
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
            kind: IncludeKind::Project,
            host,
            pin,
            project_path: raw_project,
        },
        route,
    ))
}

fn build_component_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    char_offsets: &CharOffsets,
    policy: &RegistryAccessPolicy,
    instance_host: &GitlabInstanceHost,
    admitted_origins: &mut HashSet<String>,
    component_field: RawField,
) -> Option<(GitlabCiDependency, Option<(String, GitlabRoute)>)> {
    let (raw_component, style, char_index) = component_field;
    let Some((prefix, ref_text)) = raw_component.split_once('@') else {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (missing @version)",
            &raw_component,
        );
        return None;
    };
    if ref_text.is_empty() {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (empty version)",
            &raw_component,
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
            &raw_component,
        );
        return None;
    }
    let host_expr = segments[0];
    let component_name = segments[segments.len() - 1];
    let project_path = segments[1..segments.len() - 1].join("/");
    if !is_valid_gitlab_coordinate(&project_path) || !is_valid_path_segment(component_name) {
        warn_rejected_value(
            "classify_component_value",
            "gitlab-ci component: value (malformed path)",
            &raw_component,
        );
        return None;
    }

    let value_start = char_offsets.byte_offset(char_index);
    let (raw_start, raw_end) = locate_value_span(content, value_start, &raw_component)?;
    let name_end = raw_start + prefix.len();
    let ref_start = name_end + 1; // skip '@'
    let name_range = make_range(line_table, content, raw_start, name_end);
    let version_range = make_range(line_table, content, ref_start, raw_end);

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
            is_plain_scalar: style == TScalarStyle::Plain,
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
    char_offsets: &CharOffsets,
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
            char_offsets,
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
            char_offsets,
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
        });
    }

    let line_table = LineOffsetTable::new(content);
    let char_offsets = CharOffsets::new(content);
    let mut admitted_origins = HashSet::new();
    let mut seen_route_keys = HashSet::new();
    let mut routes = Vec::new();
    let mut dependencies = Vec::new();

    for entry in receiver.entries {
        let Some((dep, route)) = build_dependency(
            content,
            &line_table,
            &char_offsets,
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

    Ok(GitlabCiParseResult {
        dependencies,
        routes,
        uri: uri.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::Dependency;
    use deps_core::net_policy::WorkspaceRegistryAccess;
    use std::sync::{Arc, RwLock};

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
}

//! `.github/workflows/*.yml`/`*.yaml` parser using `yaml-rust2`'s event-driven
//! (`MarkedEventReceiver`) API.
//!
//! An event-driven parser, rather than a tree-and-text-search approach (`deps-dart`'s), is
//! what makes duplicate `uses:` lines addressable with distinct ranges — the common case in
//! real workflows (the same action pinned at the same or different refs across several
//! jobs).
//!
//! # Reusable-workflow calls
//!
//! `owner/repo/.github/workflows/x.yml@ref` is parsed, its `owner/repo` truncated for
//! display, and recognized — but deliberately treated as **non-resolvable**, the same shape
//! as `./local`/`docker://`. The complexity here is semantic, not syntactic: such a call is
//! versioned by the *host repository's* tags, which for a reusable-workflow host are
//! routinely its unrelated package releases rather than that specific workflow's — "outdated
//! → update to vX" would then rewrite the pin to a tag that may not even contain the
//! workflow. A wrong diagnostic on a supply-chain feature is worse than none. Subdirectory
//! actions (`github/codeql-action/init@v3`) are unaffected: their repo's tags genuinely are
//! the correct versioning, so they stay fully resolvable. The discriminator is whether the
//! path segments after `owner/repo` start with `.github/workflows/`.

use crate::types::{GithubActionsDependency, GithubActionsParseResult, PinStyle};
use deps_core::lsp_helpers::{
    CharOffsets, LineOffsetTable, is_full_semver_shape, locate_value_span, warn_rejected_value,
};
use deps_core::parser::DependencySource;
use deps_core::{DepsError, Result};
use tower_lsp_server::ls_types::{Range, Uri};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Re-exported so existing `crate::parser::is_full_sha`/`is_tag_shaped` call sites
/// (`ecosystem.rs`, `formatter.rs`) keep working after the #472/GitLab-CI-plan §6.1
/// extraction of these into the shared, hardened `deps_core::lsp_helpers` scaffolding.
pub(crate) use deps_core::lsp_helpers::is_full_sha;
pub(crate) use deps_core::lsp_helpers::is_tag_shaped;

/// The first whitespace-delimited token after a whitespace-preceded `#` in
/// `rest_of_line` (the raw source text following a ref's end, up to end of line),
/// accepted as a comment tag only when it has the shape of a full `major.minor.patch`
/// version ([`is_full_semver_shape`], shared with the crate's `BareRequirementPolicy`
/// gate so the two mechanisms can't diverge — B2/B3/N1).
///
/// Returns `(tag_text, byte_offset_in_rest_of_line_where_the_token_ends)`. A `#` not
/// preceded by whitespace is not a YAML comment and is skipped (only the *first*
/// whitespace-preceded `#` is considered); a shape-rejected token (`# v4`, `# v4.2`) or
/// no `#` at all yields `None` — the ref degrades to a bare, commentless pin.
fn extract_comment_tag(rest_of_line: &str) -> Option<(&str, usize)> {
    let bytes = rest_of_line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b'#' {
            continue;
        }
        if i == 0 || !bytes[i - 1].is_ascii_whitespace() {
            continue;
        }
        let after_hash = &rest_of_line[i + 1..];
        let after_ws = after_hash.trim_start();
        let ws_len = after_hash.len() - after_ws.len();
        let token_len = after_ws.find(char::is_whitespace).unwrap_or(after_ws.len());
        let token = &after_ws[..token_len];
        return if is_full_semver_shape(token) {
            Some((token, i + 1 + ws_len + token_len))
        } else {
            None
        };
    }
    None
}

/// Outcome of classifying a raw `uses:` scalar value's `owner/repo[...]` prefix.
enum ParsedUses {
    /// `./local` or `.\local` — a local composite action.
    Path,
    /// `docker://image:tag` — a Docker Hub / registry image reference.
    Docker,
    /// A bare `owner/repo` with no `@ref` at all — nothing to version.
    NoAt { name: String },
    /// `owner/repo@ref`, or a truncated `owner/repo/.github/workflows/x.yml@ref`.
    Ref {
        name: String,
        is_reusable_workflow: bool,
        /// Byte length of the value's full pre-`@` path (`owner/repo[/sub/path]`), NOT
        /// `name.len()` — for a subdirectory action or reusable-workflow call, `name` is
        /// truncated at the second `/` while the `@` sits after the untruncated path.
        /// Using `name.len()` here would place `ref_text`'s range short by the truncated
        /// subpath's length (critic S1 in the implementation review).
        before_at_len: usize,
        ref_text: String,
    },
    /// Does not look like a GitHub identifier at all — skipped entirely (FR-015).
    Malformed,
}

/// Splits a raw `uses:` value into `owner/repo` (truncated at the second `/`) and its ref,
/// classifying the source shape. Does not resolve the ref against the tags API — that is
/// [`classify_ref`]'s job on the returned `ref_text`.
fn classify_uses_value(value: &str) -> ParsedUses {
    let value = value.trim();
    if value.is_empty() {
        return ParsedUses::Malformed;
    }
    if value.starts_with("./") || value.starts_with(".\\") {
        return ParsedUses::Path;
    }
    if value.starts_with("docker://") {
        return ParsedUses::Docker;
    }

    let (before_at, ref_text) = match value.split_once('@') {
        Some((b, r)) => (b, Some(r)),
        None => (value, None),
    };

    let mut segments = before_at.splitn(3, '/');
    let (Some(owner), Some(repo)) = (segments.next(), segments.next()) else {
        return ParsedUses::Malformed;
    };
    if owner.is_empty() || repo.is_empty() {
        return ParsedUses::Malformed;
    }
    let name = format!("{owner}/{repo}");
    if !crate::is_valid_github_identity(&name) {
        return ParsedUses::Malformed;
    }
    let is_reusable_workflow = segments
        .next()
        .is_some_and(|rest| rest.starts_with(".github/workflows/"));

    match ref_text {
        None => ParsedUses::NoAt { name },
        Some("") => ParsedUses::Malformed,
        Some(r) => ParsedUses::Ref {
            name,
            is_reusable_workflow,
            before_at_len: before_at.len(),
            ref_text: r.to_string(),
        },
    }
}

// --- Event-driven `uses:` scalar detection ---

#[derive(Clone, Copy)]
enum FrameKind {
    Mapping,
    Sequence,
}

/// Which special key (if any) a `Mapping` frame's `awaiting_key: false` state is
/// currently waiting on the value for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKey {
    /// Not awaiting a value (`awaiting_key: true`), or the pending key is neither
    /// `uses` nor `with`.
    None,
    Uses,
    With,
}

struct Frame {
    kind: FrameKind,
    is_with_ancestor: bool,
    awaiting_key: bool,
    pending_key: PendingKey,
}

/// One `uses:` scalar found by [`WorkflowReceiver`], not yet classified or range-mapped.
struct UsesCandidate {
    value: String,
    style: TScalarStyle,
    char_index: usize,
}

/// Collects every `uses:` value-scalar event, skipping any `uses` key that has a `with:`
/// ancestor (a step input literally named `uses`) — covers `jobs.*.steps[].uses` and
/// `jobs.<id>.uses` (reusable-workflow calls) with one rule, matching Renovate.
struct WorkflowReceiver {
    stack: Vec<Frame>,
    candidates: Vec<UsesCandidate>,
}

impl WorkflowReceiver {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            candidates: Vec::new(),
        }
    }

    fn child_is_with_ancestor(&self) -> bool {
        self.stack.last().is_some_and(|top| match top.kind {
            FrameKind::Mapping => top.is_with_ancestor || top.pending_key == PendingKey::With,
            FrameKind::Sequence => top.is_with_ancestor,
        })
    }

    fn consume_pending_value(&mut self) {
        if let Some(top) = self.stack.last_mut() {
            top.awaiting_key = true;
            top.pending_key = PendingKey::None;
        }
    }

    fn push_container(&mut self, kind: FrameKind) {
        let is_with_ancestor = self.child_is_with_ancestor();
        self.consume_pending_value();
        self.stack.push(Frame {
            kind,
            is_with_ancestor,
            awaiting_key: true,
            pending_key: PendingKey::None,
        });
    }
}

impl MarkedEventReceiver for WorkflowReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
                self.consume_pending_value();
            }
            Event::Scalar(value, style, _anchor, _tag) => {
                let is_key = self
                    .stack
                    .last()
                    .is_some_and(|top| matches!(top.kind, FrameKind::Mapping) && top.awaiting_key);
                if is_key {
                    if let Some(top) = self.stack.last_mut() {
                        top.pending_key = if value == "uses" && !top.is_with_ancestor {
                            PendingKey::Uses
                        } else if value == "with" {
                            PendingKey::With
                        } else {
                            PendingKey::None
                        };
                        top.awaiting_key = false;
                    }
                } else {
                    let is_uses_value = self.stack.last().is_some_and(|top| {
                        matches!(top.kind, FrameKind::Mapping)
                            && top.pending_key == PendingKey::Uses
                    });
                    if is_uses_value {
                        self.candidates.push(UsesCandidate {
                            value,
                            style,
                            char_index: marker.index(),
                        });
                    }
                    self.consume_pending_value();
                }
            }
            // A `uses: *anchor` alias value must still clear the pending `uses`/`with`
            // key slot, or the next mapping key/value pair desyncs (the following key
            // gets consumed as if it were this `uses`'s value) — critic M5. GitHub
            // itself does not support YAML anchors/aliases in workflow files, so this
            // is defense-in-depth rather than a reachable real-world case.
            Event::Alias(_) => self.consume_pending_value(),
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
    }
}

/// Builds a [`GithubActionsDependency`] for one `uses:` candidate, or `None` if its
/// `owner/repo` prefix does not look like a GitHub identifier (logged and skipped, FR-015).
fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    char_offsets: &CharOffsets,
    candidate: UsesCandidate,
) -> Option<GithubActionsDependency> {
    // Whether the *whole* `uses:` value scalar was written unquoted. For a quoted scalar,
    // any `Range` computed below sits inside the quotes — a SHA-pin code action (issue
    // #473) must not write `{sha} # {tag}` there, since the `#` would land inside the
    // string rather than starting a YAML comment (spec 031 FR-010). Read once here and
    // carried on every constructed dependency, mirroring the existing single-purpose
    // `TScalarStyle::Plain` gate below for the SHA-with-comment case.
    let is_plain_scalar = candidate.style == TScalarStyle::Plain;

    let value_start = char_offsets.byte_offset(candidate.char_index);
    let (raw_start, raw_end) = locate_value_span(content, value_start, &candidate.value)?;

    // `classify_uses_value` (and every offset computed below) works over the
    // *trimmed* value, but the span located above is the raw, untrimmed scalar
    // text. For a quoted `uses:` value with leading/trailing whitespace (e.g.
    // `" actions/checkout@v4"`), anchoring the downstream `name.len()`/
    // `before_at_len`-relative arithmetic to the untrimmed start desyncs every
    // computed offset by the trimmed byte count: on ordinary ASCII input this
    // silently points `version_range` at the wrong text (an accepted "update
    // version" code action then overwrites the wrong span), and on multi-byte
    // leading whitespace (e.g. an ideographic space, U+3000) it can split a UTF-8
    // sequence and panic on a raw `content[..]` slice downstream (security S-1).
    // Re-anchoring `span_start`/`span_end` to the trimmed text here — both still
    // guaranteed char-boundary-aligned in `content`, since `str::trim_start`/
    // `trim_end` only ever cut at `candidate.value`'s own char boundaries, and
    // that value is byte-identical to `content[raw_start..raw_end]` by
    // `locate_value_span`'s own contract — means every reference to them
    // downstream is already correct, with no further per-call adjustment needed.
    let leading_ws = candidate.value.len() - candidate.value.trim_start().len();
    let trailing_ws = candidate.value.len() - candidate.value.trim_end().len();
    let span_start = raw_start + leading_ws;
    let span_end = raw_end.saturating_sub(trailing_ws);
    let trimmed_value = candidate.value.trim().to_string();

    let make_range = |start: usize, end: usize| -> Range {
        Range::new(
            line_table.byte_offset_to_position(content, start),
            line_table.byte_offset_to_position(content, end),
        )
    };

    match classify_uses_value(&candidate.value) {
        ParsedUses::Path => Some(GithubActionsDependency {
            name: trimmed_value.clone().into(),
            name_range: make_range(span_start, span_end),
            version_req: None,
            version_range: None,
            version_literal: None,
            pin: None,
            source: DependencySource::Path {
                path: trimmed_value,
            },
            is_plain_scalar,
        }),
        ParsedUses::Docker => Some(GithubActionsDependency {
            name: trimmed_value.clone().into(),
            name_range: make_range(span_start, span_end),
            version_req: None,
            version_range: None,
            version_literal: None,
            pin: None,
            source: DependencySource::Url { url: trimmed_value },
            is_plain_scalar,
        }),
        ParsedUses::NoAt { name } => {
            let name_end = span_start + name.len();
            Some(GithubActionsDependency {
                name: name.into(),
                name_range: make_range(span_start, name_end),
                version_req: None,
                version_range: None,
                version_literal: None,
                pin: None,
                source: DependencySource::Registry,
                is_plain_scalar,
            })
        }
        ParsedUses::Ref {
            name,
            is_reusable_workflow,
            before_at_len,
            ref_text,
        } => {
            let name_end = span_start + name.len();
            // Not `name_end + 1`: `name` is truncated at the second `/` for a
            // subdirectory action or reusable-workflow call, but the `@` sits after the
            // full pre-`@` path (`before_at_len`) — using `name_end` would place every
            // ref offset short by the truncated subpath's length (critic S1).
            let ref_start = span_start + before_at_len + 1; // skip the '@'
            let ref_end = ref_start + ref_text.len();
            let name_range = make_range(span_start, name_end);

            if is_reusable_workflow {
                return Some(GithubActionsDependency {
                    name: name.clone().into(),
                    name_range,
                    version_req: None,
                    version_range: None,
                    version_literal: None,
                    pin: None,
                    source: DependencySource::Url {
                        url: format!("https://github.com/{name}"),
                    },
                    is_plain_scalar,
                });
            }

            if is_full_sha(&ref_text) {
                let rest_of_line = &content[ref_end..];
                let rest_of_line_end = rest_of_line.find('\n').unwrap_or(rest_of_line.len());
                let rest_of_line = &rest_of_line[..rest_of_line_end];

                let comment = is_plain_scalar
                    .then(|| extract_comment_tag(rest_of_line))
                    .flatten();

                return Some(match comment {
                    Some((tag, token_end)) => GithubActionsDependency {
                        name: name.into(),
                        name_range,
                        version_req: Some(tag.into()),
                        version_range: Some(make_range(ref_start, ref_end + token_end)),
                        version_literal: Some(content[ref_start..ref_end + token_end].to_string()),
                        pin: Some(PinStyle::Sha {
                            comment_tag: Some(tag.to_string()),
                        }),
                        source: DependencySource::Registry,
                        is_plain_scalar,
                    },
                    None => GithubActionsDependency {
                        name: name.into(),
                        name_range,
                        version_req: Some(ref_text.into()),
                        version_range: Some(make_range(ref_start, ref_end)),
                        version_literal: None,
                        pin: Some(PinStyle::Sha { comment_tag: None }),
                        source: DependencySource::Registry,
                        is_plain_scalar,
                    },
                });
            }

            let pin = if is_tag_shaped(&ref_text) {
                PinStyle::Tag
            } else {
                PinStyle::Branch
            };
            Some(GithubActionsDependency {
                name: name.into(),
                name_range,
                version_req: Some(ref_text.into()),
                version_range: Some(make_range(ref_start, ref_end)),
                version_literal: None,
                pin: Some(pin),
                source: DependencySource::Registry,
                is_plain_scalar,
            })
        }
        ParsedUses::Malformed => {
            // Logs only the value's length, not the raw attacker-controlled text
            // (security S-5) — matches every other rejection site in the workspace,
            // e.g. `deps_swift::registry::validate_owner_repo`.
            warn_rejected_value(
                "classify_uses_value",
                "workflow uses: value",
                &candidate.value,
            );
            None
        }
    }
}

/// Parses a `.github/workflows/*.yml`/`*.yaml` file and returns every `uses:` dependency
/// found, with LSP position tracking.
///
/// Gated first (as `deps-dart`'s pubspec.yaml parser) by
/// [`deps_core::check_yaml_nesting_depth`]/[`deps_core::check_yaml_expansion`], which return
/// a real [`DepsError::ParseError`]. A downstream YAML syntax error, by contrast, degrades to
/// an **empty** [`GithubActionsParseResult`] (logged at `debug`) rather than propagating —
/// workflows are numerous per repository, and one malformed file should not disable hover/
/// completion for every other open workflow.
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
/// use deps_github_actions::parse_workflow_yaml;
///
/// let content = "steps:\n  - uses: actions/checkout@v4\n";
/// let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
/// let result = parse_workflow_yaml(content, &uri).unwrap();
///
/// assert_eq!(result.dependencies.len(), 1);
/// assert_eq!(result.dependencies[0].name(), "actions/checkout");
/// ```
pub fn parse_workflow_yaml(content: &str, uri: &Uri) -> Result<GithubActionsParseResult> {
    if let Err(depth) =
        deps_core::check_yaml_nesting_depth(content, deps_core::MAX_YAML_NESTING_DEPTH)
    {
        return Err(DepsError::ParseError {
            file_type: "workflow.yml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML nesting depth {depth} exceeds maximum of {}",
                deps_core::MAX_YAML_NESTING_DEPTH
            ))),
        });
    }
    if let Err(bytes) = deps_core::check_yaml_expansion(content, deps_core::MAX_YAML_EXPANDED_BYTES)
    {
        return Err(DepsError::ParseError {
            file_type: "workflow.yml".into(),
            source: Box::new(std::io::Error::other(format!(
                "YAML expansion {bytes} bytes exceeds maximum of {} bytes",
                deps_core::MAX_YAML_EXPANDED_BYTES
            ))),
        });
    }

    let mut receiver = WorkflowReceiver::new();
    let mut parser = Parser::new_from_str(content);
    if let Err(e) = parser.load(&mut receiver, false) {
        tracing::debug!(error = %e, "failed to parse workflow YAML, treating as empty");
        return Ok(GithubActionsParseResult {
            dependencies: Vec::new(),
            uri: uri.clone(),
        });
    }

    let line_table = LineOffsetTable::new(content);
    let char_offsets = CharOffsets::new(content);
    let dependencies = receiver
        .candidates
        .into_iter()
        .filter_map(|candidate| build_dependency(content, &line_table, &char_offsets, candidate))
        .collect();

    Ok(GithubActionsParseResult {
        dependencies,
        uri: uri.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::Dependency;
    use std::assert_matches;

    fn test_uri() -> Uri {
        deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml")
    }

    /// Slices `content` over a single-line LSP `Range` (every fixture below is
    /// single-line ASCII, so character offsets equal byte offsets).
    fn slice(content: &str, range: Range) -> &str {
        assert_eq!(
            range.start.line, range.end.line,
            "fixture must be single-line"
        );
        let line = content.lines().nth(range.start.line as usize).unwrap();
        &line[range.start.character as usize..range.end.character as usize]
    }

    // --- R1: marker/range-derivation sanity, verified before anything else depends on it ---

    #[test]
    fn test_marker_positions_yield_correct_ranges_for_tag_pin() {
        let content = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(slice(content, dep.name_range), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }

    // --- Pin contract table ---

    #[test]
    fn test_tag_pin_major_only() {
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4")
        );
        assert_eq!(dep.version_literal(), None);
        assert_eq!(dep.pin, Some(PinStyle::Tag));
    }

    #[test]
    fn test_tag_pin_full_version_with_and_without_v() {
        for (uses, expected_req) in [
            ("actions/checkout@v4.2.0", "v4.2.0"),
            ("actions/checkout@4.2.0", "4.2.0"),
        ] {
            let content = format!("steps:\n  - uses: {uses}\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(
                dep.version_requirement().map(deps_core::VersionReq::as_str),
                Some(expected_req),
                "{uses}"
            );
            assert_eq!(dep.pin, Some(PinStyle::Tag));
        }
    }

    #[test]
    fn test_sha_with_comment_tag() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4.2.0")
        );
        assert_eq!(
            dep.version_literal(),
            Some(format!("{sha} # v4.2.0").as_str())
        );
        assert_eq!(
            slice(&content, dep.version_range().unwrap()),
            format!("{sha} # v4.2.0")
        );
        assert_eq!(
            dep.pin,
            Some(PinStyle::Sha {
                comment_tag: Some("v4.2.0".to_string())
            })
        );
    }

    #[test]
    fn test_sha_with_comment_and_trailing_annotation_keeps_range_at_tag_end() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content =
            format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0 — pinned, do not bump\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4.2.0")
        );
        // The range must stop at the tag token, not run to end of line — the
        // trailing annotation is never part of version_literal/version_range.
        assert_eq!(
            dep.version_literal(),
            Some(format!("{sha} # v4.2.0").as_str())
        );
    }

    #[test]
    fn test_sha_without_comment_is_bare_and_unresolved() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: actions/checkout@{sha}\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(sha)
        );
        assert_eq!(dep.version_literal(), None);
        assert_eq!(dep.pin, Some(PinStyle::Sha { comment_tag: None }));
    }

    #[test]
    fn test_sha_comment_partial_tag_rejected_stays_bare() {
        // `# v4` / `# v4.2` are deliberately rejected (B2/B3): a partial comment
        // tag would make the pin permanently "up to date" while the SHA rots.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        for suffix in ["v4", "v4.2"] {
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # {suffix}\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(
                dep.version_requirement().map(deps_core::VersionReq::as_str),
                Some(sha),
                "{suffix}"
            );
            assert_eq!(dep.pin, Some(PinStyle::Sha { comment_tag: None }));
        }
    }

    #[test]
    fn test_sha_comment_prerelease_tag_accepted() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0-beta.1\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4.2.0-beta.1")
        );
    }

    #[test]
    fn test_sha_comment_not_whitespace_preceded_is_not_a_comment() {
        // `#` glued directly to the ref (no preceding whitespace) is not a YAML
        // comment at all, so it stays part of the plain scalar's value.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: actions/checkout@{sha}#v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // The whole `{sha}#v4.2.0` is the ref text — not a valid 40-hex SHA (extra
        // trailing characters), so this falls through to the branch bucket instead
        // of ever being treated as a SHA-with-comment pin.
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(format!("{sha}#v4.2.0").as_str())
        );
        assert_eq!(dep.pin, Some(PinStyle::Branch));
    }

    #[test]
    fn test_quoted_sha_with_real_yaml_comment_outside_quotes_degrades_to_bare_sha() {
        // B3: the comment-tag rule applies only to plain (unquoted) scalars. Here the
        // quoted value is a clean 40-hex SHA, and `# v4.2.0` is a genuine YAML
        // comment sitting *outside* the quotes — but since the scalar itself is
        // quoted, no comment scan runs at all, and the pin degrades to a bare SHA.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: \"actions/checkout@{sha}\" # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(sha)
        );
        assert_eq!(dep.pin, Some(PinStyle::Sha { comment_tag: None }));
    }

    #[test]
    fn test_quoted_scalar_with_comment_like_text_is_not_a_valid_sha() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: \"actions/checkout@{sha} # v4.2.0\"\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // For a quoted scalar, `#` is part of the value — no comment scan runs, so
        // the ref text is `"{sha} # v4.2.0"` verbatim: not a valid 40-hex SHA (extra
        // trailing characters), so this falls through to the branch bucket, the
        // honest outcome for an unparseable ref shape.
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(format!("{sha} # v4.2.0").as_str())
        );
        assert_eq!(dep.pin, Some(PinStyle::Branch));
    }

    #[test]
    fn test_branch_pin() {
        let content = "steps:\n  - uses: dev/tool@main\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("main")
        );
        assert_eq!(dep.pin, Some(PinStyle::Branch));
    }

    #[test]
    fn test_local_path_action() {
        let content = "steps:\n  - uses: ./local-action\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(dep.version_range().is_none());
        assert!(dep.version_requirement().is_none());
        assert_matches!(dep.source(), DependencySource::Path { .. });
    }

    #[test]
    fn test_docker_image_ref() {
        let content = "steps:\n  - uses: docker://alpine:3.18\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(dep.version_range().is_none());
        assert_matches!(dep.source(), DependencySource::Url { .. });
    }

    #[test]
    fn test_bare_owner_repo_no_at() {
        let content = "steps:\n  - uses: actions/checkout\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert!(dep.version_range().is_none());
        assert!(dep.version_requirement().is_none());
    }

    #[test]
    fn test_subdirectory_action_truncates_and_stays_resolvable() {
        let content = "steps:\n  - uses: github/codeql-action/init@v3\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "github/codeql-action");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v3")
        );
        assert_matches!(dep.source(), DependencySource::Registry);
        // Critic S1 regression: `version_range` must span the ref (`v3`), not a
        // substring of the truncated subpath (`in`, from `codeql-action/**in**it@v3`)
        // — the bug the range assertion here is specifically for.
        assert_eq!(slice(content, dep.version_range().unwrap()), "v3");
        assert_eq!(slice(content, dep.name_range()), "github/codeql-action");
    }

    #[test]
    fn test_subdirectory_action_sha_with_comment_range_excludes_subpath() {
        // Critic S1: for the SHA-with-comment form, `version_range` must start right
        // after the full `owner/repo/sub@` prefix, not after the truncated `owner/repo@`.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: github/codeql-action/init@{sha} # v3.1.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "github/codeql-action");
        assert_eq!(
            slice(&content, dep.version_range().unwrap()),
            format!("{sha} # v3.1.0")
        );
    }

    #[test]
    fn test_reusable_workflow_call_is_recognized_but_non_resolvable() {
        let content = "jobs:\n  call:\n    uses: octo-org/repo/.github/workflows/x.yml@v1\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "octo-org/repo");
        assert!(dep.version_range().is_none());
        assert!(dep.version_requirement().is_none());
        assert_matches!(dep.source(), DependencySource::Url { .. });
    }

    #[test]
    fn test_malformed_uses_value_is_skipped_not_erroring() {
        let content = "steps:\n  - uses: not-a-valid-identifier\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    // --- Structural coverage ---

    #[test]
    fn test_duplicate_uses_lines_get_distinct_ranges() {
        let content = "steps:\n  - uses: actions/checkout@v3\n  - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        assert_ne!(
            result.dependencies[0].version_range(),
            result.dependencies[1].version_range()
        );
        assert_eq!(
            result.dependencies[0]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some("v3")
        );
        assert_eq!(
            result.dependencies[1]
                .version_requirement()
                .map(deps_core::VersionReq::as_str),
            Some("v4")
        );
    }

    #[test]
    fn test_quoted_scalar_uses_value_parses() {
        let content = "steps:\n  - uses: \"actions/checkout@v4\"\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4")
        );
        // Security audit finding (issue #473, spec 031 FR-010): a quoted `uses:` scalar
        // must be flagged so a SHA-pin code action never writes `{sha} # {tag}` inside
        // the quotes.
        assert!(!dep.is_plain_scalar);
    }

    #[test]
    fn test_is_plain_scalar_true_for_unquoted_uses_value() {
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert!(result.dependencies[0].is_plain_scalar);
    }

    #[test]
    fn test_is_plain_scalar_false_for_single_quoted_uses_value() {
        let content = "steps:\n  - uses: 'actions/checkout@v4'\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert!(!result.dependencies[0].is_plain_scalar);
    }

    #[test]
    fn test_with_block_uses_key_is_ignored() {
        // A step input literally named `uses` (inside `with:`) must not be treated
        // as an action reference.
        let content = "steps:\n  - uses: actions/github-script@v7\n    with:\n      uses: not-a-real-dependency\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "actions/github-script");
    }

    #[test]
    fn test_alias_value_does_not_desync_following_uses_key() {
        // Critic M5: an `Event::Alias` (YAML anchor reference) filling a `uses:` value
        // must still clear the pending-key slot, or the *next* key/value pair in the
        // same mapping desyncs. A single step normally has only one `uses:` key, so the
        // bug is invisible unless the alias-valued key is followed by another
        // key/value pair in the same mapping — demonstrated here with a (syntactically
        // valid, if unrealistic for a real workflow) duplicate `uses:` key: without the
        // fix, the second, literal `uses:` value is never recognized as a dependency at
        // all (it gets misread as a key with the alias's own value swallowing it).
        let content =
            "steps:\n  - uses: &a actions/checkout@v3\n  - uses: *a\n    uses: real/repo@v9\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let names: Vec<&str> = result
            .dependencies
            .iter()
            .map(|d| d.name().as_str())
            .collect();
        assert!(
            names.contains(&"real/repo"),
            "expected 'real/repo' among {names:?}"
        );
    }

    #[test]
    fn test_reusable_workflow_job_level_uses_with_with_block_still_recognized() {
        let content = "jobs:\n  call:\n    uses: owner/repo/.github/workflows/x.yml@v1\n    with:\n      config: default\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "owner/repo");
    }

    #[test]
    fn test_invalid_yaml_returns_empty_result_not_error() {
        let content = "steps:\n  - uses: [unterminated\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_empty_content() {
        let result = parse_workflow_yaml("", &test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    #[test]
    fn test_quoted_value_with_multibyte_leading_whitespace_does_not_panic() {
        // Security S-1: previously panicked ("byte index N is not a char boundary")
        // because `build_dependency` anchored its offset math on the *untrimmed*
        // value's start while `classify_uses_value`'s `name`/`ref_text` were derived
        // from the *trimmed* one — a multi-byte leading whitespace character (U+3000,
        // ideographic space, 3 bytes) inside a quoted scalar shifted every downstream
        // offset off a char boundary. Reproduced end-to-end against the real LSP
        // binary by the security audit; this is the minimal in-crate repro.
        let leading = "\u{3000}".repeat(15);
        let sha = "a".repeat(40);
        let content = format!("steps:\n  - uses: \"{leading}a/b@{sha}\"\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        // The malformed-looking owner/repo (leading ideographic spaces baked into the
        // quoted value) is expected to be classified sensibly; the requirement here is
        // solely that parsing completes without panicking.
        let _ = result.dependencies;
    }

    #[test]
    fn test_quoted_value_with_leading_space_reports_correct_ref_range() {
        // Security S-1's benign-input half: an ordinary, single-leading-space quoted
        // value (`" actions/checkout@v4"`, valid YAML, a common formatting choice) must
        // still resolve `version_range` to the real ref (`v4`), not a shifted
        // substring (`@v`) — the shift the desync bug produced would corrupt the file
        // when an "update version" code action wrote its edit at the wrong span.
        let content = "steps:\n  - uses: \" actions/checkout@v4\"\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }

    #[test]
    fn test_deeply_nested_yaml_rejected_as_parse_error() {
        // A dash-chain sequence: each `- ` nests one level deeper, mirroring
        // `deps_core::parser`'s own gate tests.
        let payload = format!("{}1", "- ".repeat(deps_core::MAX_YAML_NESTING_DEPTH + 1));
        let result = parse_workflow_yaml(&payload, &test_uri());
        assert_matches!(result, Err(DepsError::ParseError { .. }));
    }

    // --- classify_uses_value / ref classification unit coverage ---
    //
    // `is_full_sha`/`is_tag_shaped`/`locate_value_span`/`MAX_FALLBACK_SCAN_BYTES` moved to
    // `deps_core::lsp_helpers` (#472/GitLab-CI-plan §6.1) — their unit tests moved with
    // them, since they test the shared helper, not this crate's workflow parser.

    #[test]
    fn test_extract_comment_tag_multiple_hashes_uses_first() {
        assert_eq!(
            extract_comment_tag(" # v1.0.0 # v2.0.0"),
            Some(("v1.0.0", " # v1.0.0".len()))
        );
    }

    #[test]
    fn test_extract_comment_tag_no_hash_returns_none() {
        assert_eq!(extract_comment_tag(" no comment here"), None);
    }
}

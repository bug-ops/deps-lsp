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

use crate::types::{GithubActionsDependency, GithubActionsParseResult, PinStyle, ShaComment};
use deps_core::lsp_helpers::{
    CommitSha, LineOffsetTable, MarkedScalar, ShaPinTail, byte_span_to_range, read_sha_pin_tail,
    ref_is_last_on_line, warn_rejected_value,
};
use deps_core::parser::DependencySource;
use deps_core::yaml_walk::{FrameKind, FrameStack, ScalarPosition};
use deps_core::{Range, Result};
use url::Url;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

/// Re-exported so existing `crate::parser::is_full_sha`/`is_tag_shaped` call sites
/// (`ecosystem.rs`, `formatter.rs`) keep working after the #472/GitLab-CI-plan §6.1
/// extraction of these into the shared, hardened `deps_core::lsp_helpers` scaffolding.
pub(crate) use deps_core::lsp_helpers::is_full_sha;
pub(crate) use deps_core::lsp_helpers::is_tag_shaped;

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

/// Which special key (if any) a `Mapping` frame's `awaiting_key: false` state is
/// currently waiting on the value for.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum PendingKey {
    /// Not awaiting a value (`awaiting_key: true`), or the pending key is neither
    /// `uses` nor `with`.
    #[default]
    None,
    Uses,
    With,
}

/// The generic frame-stack mechanics ([`deps_core::yaml_walk::FrameStack`]) driven by
/// [`WorkflowReceiver`]. This crate has no role vocabulary of its own — every
/// structural distinction it needs collapses to whether a `with:` ancestor is in
/// scope, so the role type parameter is the unit type and that one fact is carried
/// directly as each frame's `payload`.
type Stack = FrameStack<(), PendingKey, bool>;

/// One `uses:` scalar found by [`WorkflowReceiver`], not yet classified or range-mapped —
/// see [`MarkedScalar`], whose `span()` resolves the value's byte offset only once
/// parsing completes, via a `line`/`col`-based lookup rather than `Marker::index()` (#879).
type UsesCandidate = MarkedScalar;

/// Collects every `uses:` value-scalar event, skipping any `uses` key that has a `with:`
/// ancestor (a step input literally named `uses`) — covers `jobs.*.steps[].uses` and
/// `jobs.<id>.uses` (reusable-workflow calls) with one rule, matching Renovate.
///
/// Also tracks [`Self::has_top_level_runs_key`] alongside `candidates`: both are derived
/// from the same single streaming pass over the document's YAML events, so recomputing
/// the `runs:` check separately (e.g. from the URI path instead) would mean a second,
/// redundant walk of the same event stream for one boolean.
struct WorkflowReceiver {
    stack: Stack,
    candidates: Vec<UsesCandidate>,
    /// Whether a `runs:` key was seen in the *document root* mapping (`stack.len() == 1`
    /// at the time its key scalar fired) — issue #706 review finding (security, LOW):
    /// `action.yml`/`action.yaml` is now routed by bare basename, matching any file with
    /// that name anywhere in an opened workspace, not just real GitHub Action manifests.
    /// GitHub requires every `action.yml`/`action.yaml` to declare a top-level `runs:`
    /// key; [`parse_workflow_yaml`] uses this flag (via [`is_action_manifest_filename`])
    /// to withhold every candidate for such a file when it's missing, cutting
    /// false-positive registry fetches and diagnostics on a coincidentally-named,
    /// unrelated file. Known limitation: a `runs:` key expressed only through a YAML
    /// merge key (`<<: *anchor`) is not detected — this flag only recognizes a literal
    /// `runs` scalar key, so such an action would be misclassified. Considered too
    /// obscure to warrant merge-key resolution here.
    has_top_level_runs_key: bool,
}

impl WorkflowReceiver {
    fn new() -> Self {
        Self {
            stack: Stack::new(),
            candidates: Vec::new(),
            has_top_level_runs_key: false,
        }
    }

    /// Whether a container about to be pushed inherits a `with:` ancestor from its
    /// parent — either the parent is itself already under one, or the parent is a
    /// `Mapping` currently holding a value for its own `with:` key.
    fn child_is_with_ancestor(&self) -> bool {
        self.stack.top().is_some_and(|top| match top.kind() {
            FrameKind::Mapping => top.payload || *top.pending_key() == PendingKey::With,
            FrameKind::Sequence => top.payload,
        })
    }

    fn push_container(&mut self, kind: FrameKind) {
        // Computed before `FrameStack::push` transitions state — must reflect the
        // parent's own with:-ancestor status, not the child's freshly pushed one.
        let is_with_ancestor = self.child_is_with_ancestor();
        self.stack.push(kind, (), is_with_ancestor);
    }
}

impl MarkedEventReceiver for WorkflowReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        match event {
            Event::MappingStart(..) => self.push_container(FrameKind::Mapping),
            Event::SequenceStart(..) => self.push_container(FrameKind::Sequence),
            Event::MappingEnd | Event::SequenceEnd => {
                self.stack.pop();
            }
            Event::Scalar(value, style, _anchor, _tag) => {
                if self.stack.scalar_position() == ScalarPosition::Key {
                    if self.stack.depth() == 1 && value == "runs" {
                        self.has_top_level_runs_key = true;
                    }
                    let is_with_ancestor = self.stack.top().is_some_and(|top| top.payload);
                    let key = if value == "uses" && !is_with_ancestor {
                        PendingKey::Uses
                    } else if value == "with" {
                        PendingKey::With
                    } else {
                        PendingKey::None
                    };
                    self.stack.observe_key(key);
                } else {
                    let is_uses_value = self.stack.top().is_some_and(|top| {
                        top.kind() == FrameKind::Mapping && *top.pending_key() == PendingKey::Uses
                    });
                    if is_uses_value {
                        self.candidates
                            .push(UsesCandidate::new(value, style, &marker));
                    }
                    self.stack.consume_value();
                }
            }
            // An alias value must still clear the pending key slot or the next pair
            // desyncs (critic M5) — defense-in-depth since GHA itself rejects anchors.
            Event::Alias(_) => self.stack.consume_value(),
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
// `ref_start`/`ref_end` build on `span_start`, which is char-boundary-aligned (see the trim
// re-anchoring comment below), plus whole-substring byte counts, so arithmetic never lands
// mid-character; `range_end` comes from `read_sha_pin_tail`, which clamps it to a char boundary.
#[allow(clippy::string_slice)]
fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    candidate: UsesCandidate,
) -> Option<GithubActionsDependency> {
    // Whether the whole `uses:` scalar was unquoted. For a quoted scalar, any Range below
    // sits inside the quotes, so a SHA-pin edit must not write `{sha} # {tag}` there (#473,
    // FR-010) — read once and carried on every constructed dependency.
    let is_plain_scalar = candidate.is_plain();

    let (raw_start, raw_end) = candidate.span(content, line_table)?;

    // `classify_uses_value` works over the trimmed value, but the span above is the raw,
    // untrimmed scalar text. Anchoring downstream offsets to the untrimmed start would
    // desync `version_range` by the trimmed byte count, and on multi-byte leading
    // whitespace (e.g. U+3000) can split a UTF-8 sequence and panic downstream (security
    // S-1). Re-anchoring `span_start`/`span_end` to the trimmed text here keeps them
    // char-boundary-aligned, since `trim_start`/`trim_end` only cut at existing boundaries.
    let leading_ws = candidate.text().len() - candidate.text().trim_start().len();
    let trailing_ws = candidate.text().len() - candidate.text().trim_end().len();
    let span_start = raw_start + leading_ws;
    let span_end = raw_end.saturating_sub(trailing_ws);
    let trimmed_value = candidate.text().trim().to_string();

    let make_range =
        |start: usize, end: usize| -> Range { byte_span_to_range(content, line_table, start, end) };

    match classify_uses_value(candidate.text()) {
        ParsedUses::Path => Some(GithubActionsDependency {
            name: trimmed_value.clone().into(),
            name_range: make_range(span_start, span_end),
            version_req: None,
            version_range: None,
            pin: None,
            source: DependencySource::Path {
                path: trimmed_value,
            },
            is_plain_scalar,
            is_last_on_line: true,
        }),
        ParsedUses::Docker => Some(GithubActionsDependency {
            name: trimmed_value.clone().into(),
            name_range: make_range(span_start, span_end),
            version_req: None,
            version_range: None,
            pin: None,
            source: DependencySource::Url { url: trimmed_value },
            is_plain_scalar,
            is_last_on_line: true,
        }),
        ParsedUses::NoAt { name } => {
            let name_end = span_start + name.len();
            Some(GithubActionsDependency {
                name: name.into(),
                name_range: make_range(span_start, name_end),
                version_req: None,
                version_range: None,
                pin: None,
                source: DependencySource::Registry,
                is_plain_scalar,
                is_last_on_line: true,
            })
        }
        ParsedUses::Ref {
            name,
            is_reusable_workflow,
            before_at_len,
            ref_text,
        } => {
            let name_end = span_start + name.len();
            // Not `name_end + 1`: `name` truncates at the second `/`, but `@` sits after
            // the full pre-`@` path — using `name_end` would shift every ref offset (critic S1).
            let ref_start = span_start + before_at_len + 1; // skip the '@'
            let ref_end = ref_start + ref_text.len();
            let name_range = make_range(span_start, name_end);

            if is_reusable_workflow {
                return Some(GithubActionsDependency {
                    name: name.clone().into(),
                    name_range,
                    version_req: None,
                    version_range: None,
                    pin: None,
                    source: DependencySource::Url {
                        url: format!("https://github.com/{name}"),
                    },
                    is_plain_scalar,
                    is_last_on_line: true,
                });
            }

            // Computed for every ref-pinned form, not just SHA-with-comment below, since
            // `sha_pin_text_edit_for` needs it for `PinStyle::Tag` too — a flow-style step
            // has real YAML content after the ref that a trailing `# <tag>` would swallow
            // (#633).
            let is_last_on_line =
                ref_is_last_on_line(content, line_table, ref_end, candidate.line());

            if let Some(sha) = CommitSha::parse(&ref_text) {
                let read = read_sha_pin_tail(
                    content,
                    line_table,
                    ref_end,
                    candidate.line(),
                    candidate.style(),
                    is_plain_scalar,
                );
                return Some(match read.tail {
                    ShaPinTail::Commented(pin_comment) => {
                        let tag = pin_comment.tag.as_str().to_string();
                        let comment_end = read.range_end;
                        let comment = ShaComment::new(
                            pin_comment,
                            make_range(comment_end - tag.len(), comment_end),
                            content[ref_start..comment_end].to_string(),
                        );
                        GithubActionsDependency {
                            name: name.into(),
                            name_range,
                            version_req: Some(tag.into()),
                            version_range: Some(make_range(ref_start, comment_end)),
                            pin: Some(PinStyle::Sha {
                                sha,
                                comment: Some(comment),
                            }),
                            source: DependencySource::Registry,
                            is_plain_scalar,
                            is_last_on_line,
                        }
                    }
                    ShaPinTail::Bare(_) => GithubActionsDependency {
                        name: name.into(),
                        name_range,
                        version_req: Some(ref_text.into()),
                        version_range: Some(make_range(ref_start, ref_end)),
                        pin: Some(PinStyle::Sha { sha, comment: None }),
                        source: DependencySource::Registry,
                        is_plain_scalar,
                        is_last_on_line,
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
                pin: Some(pin),
                source: DependencySource::Registry,
                is_plain_scalar,
                is_last_on_line,
            })
        }
        ParsedUses::Malformed => {
            // Logs only the value's length, not the raw attacker-controlled text
            // (security S-5) — matches every other rejection site in the workspace,
            // e.g. `deps_swift::registry::validate_owner_repo`.
            warn_rejected_value(
                "classify_uses_value",
                "workflow uses: value",
                candidate.text(),
            );
            None
        }
    }
}

/// Parses a `.github/workflows/*.yml`/`*.yaml` file and returns every `uses:` dependency
/// found, with LSP position tracking.
///
/// Gated first (as `deps-dart`'s pubspec.yaml parser) by [`deps_core::check_yaml_bounds`],
/// which returns a real [`deps_core::DepsError::ParseError`]. A downstream YAML syntax
/// error, by contrast, degrades to an **empty** [`GithubActionsParseResult`] (logged at
/// `debug`) rather than propagating — workflows are numerous per repository, and one
/// malformed file should not disable hover/completion for every other open workflow.
///
/// # Errors
///
/// Returns [`deps_core::DepsError::ParseError`] only when `content` exceeds the shared YAML
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
pub fn parse_workflow_yaml(content: &str, uri: &Url) -> Result<GithubActionsParseResult> {
    deps_core::check_yaml_bounds(content, "workflow.yml")?;

    let mut receiver = WorkflowReceiver::new();
    let mut parser = Parser::new_from_str(content);
    if let Err(e) = parser.load(&mut receiver, false) {
        tracing::debug!(error = %e, "failed to parse workflow YAML, treating as empty");
        return Ok(GithubActionsParseResult {
            dependencies: Vec::new(),
            uri: uri.clone(),
            dependency_truncation: None,
        });
    }

    // #706 (security, LOW): `action.yml`/`action.yaml` routes by bare basename, matching
    // anywhere in a workspace, not just real Action manifests — withhold every candidate
    // unless the file actually declares GitHub's required top-level `runs:` key.
    if is_action_manifest_filename(uri) && !receiver.has_top_level_runs_key {
        tracing::debug!(
            "action.yml/action.yaml with no top-level `runs:` key, treating as not a \
             GitHub Action manifest"
        );
        return Ok(GithubActionsParseResult {
            dependencies: Vec::new(),
            uri: uri.clone(),
            dependency_truncation: None,
        });
    }

    let line_table = LineOffsetTable::new(content);
    // #796: checked before `build_dependency` (the expensive step — SHA/tag resolution
    // setup, range computation) rather than after, so a `uses:` step beyond the ceiling
    // never reaches it.
    let mut budget = deps_core::DependencyBudget::new(deps_core::MAX_DEPENDENCIES_PER_DOCUMENT);
    let dependencies = receiver
        .candidates
        .into_iter()
        .filter(|_| budget.allow())
        .filter_map(|candidate| build_dependency(content, &line_table, candidate))
        .collect();

    Ok(GithubActionsParseResult {
        dependencies,
        uri: uri.clone(),
        dependency_truncation: budget.truncation(),
    })
}

/// Whether `uri`'s basename is exactly `action.yml` or `action.yaml` — the same
/// case-sensitive exact-name match [`crate::ecosystem::GithubActionsEcosystem::manifest_filenames`]
/// registers with [`deps_core::EcosystemRegistry`], recomputed here since routing itself
/// carries no signal into [`parse_workflow_yaml`] about *which* rule matched.
///
/// Deliberately does not special-case `.github/workflows/`: GitHub's own naming
/// convention makes a *workflow* actually named `action.yml` vanishingly unlikely (that
/// name specifically signals "this is an action manifest", not a workflow), so per the
/// project's MVP convention this stays a plain basename check rather than adding a
/// directory carve-out (and its own tests) for a near-hypothetical file. Should such a
/// workflow exist, [`parse_workflow_yaml`]'s "requires a top-level `runs:` key" guard
/// below would misclassify it and drop its `uses:` steps until renamed.
fn is_action_manifest_filename(uri: &Url) -> bool {
    let path = uri.path();
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename == "action.yml" || filename == "action.yaml"
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{Dependency, DepsError};
    use std::assert_matches;
    use yaml_rust2::scanner::TScalarStyle;

    /// Mirrors `deps_core`'s private rest-of-line window size.
    const REST_OF_LINE_WINDOW_BYTES: usize = 4096;

    fn test_uri() -> Url {
        deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml")
    }

    /// Slices `content` over a single-line LSP `Range` (every fixture below is
    /// single-line ASCII, so character offsets equal byte offsets).
    #[allow(clippy::string_slice)] // fixtures are single-line ASCII literals
    fn slice(content: &str, range: Range) -> &str {
        assert_eq!(
            range.start.line, range.end.line,
            "fixture must be single-line"
        );
        let line = content.lines().nth(range.start.line as usize).unwrap();
        &line[range.start.character as usize..range.end.character as usize]
    }

    fn comment_tag_of(dep: &GithubActionsDependency) -> Option<&str> {
        dep.sha_comment().map(ShaComment::tag)
    }

    fn is_commentless_sha(dep: &GithubActionsDependency) -> bool {
        matches!(dep.pin, Some(PinStyle::Sha { comment: None, .. }))
    }

    /// Text of a single-line `range`, addressed in UTF-16 columns like the LSP.
    fn utf16_slice(content: &str, range: Range) -> String {
        let line = content.lines().nth(range.start.line as usize).unwrap();
        let units: Vec<u16> = line.encode_utf16().collect();
        String::from_utf16(&units[range.start.character as usize..range.end.character as usize])
            .unwrap()
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
        assert_eq!(comment_tag_of(dep), Some("v4.2.0"));
    }

    #[test]
    fn test_sha_pin_carries_lowercase_commit_sha_and_parsed_comment() {
        let upper = "A1B2C3D4E5".repeat(4);
        let content = format!("steps:\n  - uses: actions/checkout@{upper} # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        let Some(PinStyle::Sha { sha, comment }) = &dep.pin else {
            panic!("expected a SHA pin, got {:?}", dep.pin);
        };
        assert_eq!(sha.as_str(), upper.to_ascii_lowercase());
        let comment = comment.as_ref().expect("commented SHA pin");
        assert_eq!(comment.tag(), "v4.2.0");
        assert_eq!(comment.literal(), format!("{upper} # v4.2.0"));
        assert_eq!(dep.version_literal(), Some(comment.literal()));
        assert_eq!(slice(&content, comment.tag_range()), "v4.2.0");
    }

    #[test]
    fn test_sha_comment_tag_range_covers_only_the_tag_token() {
        let sha = "a".repeat(40);
        for (uses, closers) in [
            (format!("actions/checkout@{sha}  # v4"), ""),
            (format!("actions/checkout@{sha}\t# v4.2.0-rc.1"), ""),
            (format!("\"actions/checkout@{sha}\" # v4"), "\""),
            (format!("{{uses: actions/checkout@{sha}}} # v4"), "}"),
        ] {
            let flow = uses.starts_with('{');
            let content = if flow {
                format!("steps:\n  - {uses}\n")
            } else {
                format!("steps:\n  - uses: {uses}\n")
            };
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            let comment = dep.sha_comment().unwrap_or_else(|| panic!("{uses}"));
            assert_eq!(
                slice(&content, comment.tag_range()),
                comment.tag(),
                "{uses}"
            );
            assert_eq!(comment.closing_delimiters().to_string(), closers, "{uses}");
        }
    }

    #[test]
    fn test_sha_comment_tag_range_is_utf16_correct_for_non_ascii_suffix() {
        let sha = "a".repeat(40);
        let content =
            format!("steps:\n  - {{name: \"日本\", uses: actions/checkout@{sha}}} # v4-β\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let comment = result.dependencies[0].sha_comment().expect("commented pin");
        assert_eq!(comment.tag(), "v4-β");
        assert_eq!(utf16_slice(&content, comment.tag_range()), "v4-β");
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
        assert!(is_commentless_sha(dep));
    }

    #[test]
    fn test_sha_comment_partial_tag_accepted() {
        // #907: `# v4`/`# v4.2` are the common real-world SHA-pin comment convention;
        // rejecting them degraded most real workflows to a bare, unresolvable SHA.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        for suffix in ["v4", "v4.2"] {
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # {suffix}\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(
                dep.version_requirement().map(deps_core::VersionReq::as_str),
                Some(suffix),
                "{suffix}"
            );
            assert_eq!(comment_tag_of(dep), Some(suffix), "{suffix}");
        }
    }

    #[test]
    fn test_sha_comment_non_version_text_rejected_stays_bare() {
        // #907 S1: a non-version comment (tool name, ticket number, date) must still
        // degrade to a bare SHA — `is_partial_semver_shaped` must not treat free text as
        // a version just because it starts with a digit.
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        for suffix in ["cargo-deny", "do-not-upgrade", "main", "1234", "20240501"] {
            let content = format!("steps:\n  - uses: taiki-e/install-action@{sha} # {suffix}\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(
                dep.version_requirement().map(deps_core::VersionReq::as_str),
                Some(sha),
                "{suffix}"
            );
            assert!(is_commentless_sha(dep), "{suffix}");
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
    fn test_quoted_sha_with_comment_outside_quotes_reads_tag_and_keeps_quote() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        for quote in ['"', '\''] {
            let content =
                format!("steps:\n  - uses: {quote}actions/checkout@{sha}{quote} # v4.2.0\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(comment_tag_of(dep), Some("v4.2.0"));
            assert_eq!(
                dep.version_literal(),
                Some(format!("{sha}{quote} # v4.2.0").as_str())
            );
            assert_eq!(
                slice(&content, dep.version_range().unwrap()),
                format!("{sha}{quote} # v4.2.0")
            );
            assert_eq!(
                dep.sha_comment().unwrap().closing_delimiters().to_string(),
                quote.to_string()
            );
            assert!(!dep.is_plain_scalar);
        }
    }

    #[test]
    fn test_flow_sha_with_comment_after_closing_brace_reads_tag() {
        let sha = "a".repeat(40);
        let cases = [
            (format!("{{uses: actions/checkout@{sha}}}"), "}"),
            (format!("{{uses: \"actions/checkout@{sha}\"}}"), "\"}"),
            (format!("{{uses: 'actions/checkout@{sha}'}}"), "'}"),
            (format!("{{ uses: actions/checkout@{sha} }}"), " }"),
            (format!("{{uses: actions/checkout@{sha}\t}}"), "\t}"),
            (format!("{{ uses: \"actions/checkout@{sha}\" }}"), "\" }"),
        ];
        for (flow, closers) in cases {
            let content = format!("steps:\n  - {flow} # v4\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert_eq!(comment_tag_of(dep), Some("v4"), "{flow}");
            assert_eq!(
                slice(&content, dep.version_range().unwrap()),
                format!("{sha}{closers} # v4"),
                "{flow}"
            );
            assert_eq!(
                dep.sha_comment().unwrap().closing_delimiters().to_string(),
                closers,
                "{flow}"
            );
        }
    }

    #[test]
    fn test_flow_sha_with_sibling_keys_or_outer_collection_stays_commentless() {
        let sha = "a".repeat(40);
        for flow in [
            format!("{{uses: actions/checkout@{sha}, name: x}}"),
            format!("{{uses: \"actions/checkout@{sha}\", name: x}}"),
            format!("{{a: {{uses: actions/checkout@{sha}}}}}"),
            format!("{{a: {{uses: \"actions/checkout@{sha}\"}}}}"),
            format!("[{{uses: actions/checkout@{sha}}}]"),
        ] {
            let content = format!("steps:\n  - {flow} # v4\n");
            let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
            let dep = &result.dependencies[0];
            assert!(is_commentless_sha(dep), "{flow}");
            assert_eq!(slice(&content, dep.version_range().unwrap()), sha);
        }
    }

    #[test]
    fn test_quoted_sha_comment_range_is_utf16_correct_after_multibyte_prefix() {
        let sha = "a".repeat(40);
        let content =
            format!("steps:\n  - {{name: \"日本\", uses: \"actions/checkout@{sha}\"}} # v4\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let range = result.dependencies[0].version_range().unwrap();
        let line = content.lines().nth(1).unwrap();
        let units: Vec<u16> = line.encode_utf16().collect();
        let literal = String::from_utf16(
            &units[range.start.character as usize..range.end.character as usize],
        )
        .unwrap();
        assert_eq!(literal, format!("{sha}\"}} # v4"));
    }

    #[test]
    fn test_quoted_scalar_with_comment_like_text_is_not_a_valid_sha() {
        let sha = "a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5";
        let content = format!("steps:\n  - uses: \"actions/checkout@{sha} # v4.2.0\"\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        // For a quoted scalar, `#` is part of the value, so the ref text is the literal
        // string verbatim: not a valid 40-hex SHA, so this falls through to the branch bucket.
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

    // --- deps-lsp#908: complex YAML key (`? <mapping>`/`? <sequence>`) no longer desyncs
    // the root mapping's key/value alternation (shared `FrameStack` walker fix).
    //
    // This crate's `uses:` detection never gates on a top-level key, so a root desync is
    // invisible to it — the one observable spot is `has_top_level_runs_key` (#706): the
    // old code left the root stuck "awaiting a key" after a complex key's subtree closed,
    // misreading the complex key's own value scalar as a literal top-level key.

    #[test]
    fn test_complex_key_value_is_not_misread_as_a_top_level_runs_key() {
        // `runs` here is the complex key's *value*, not a real top-level key. Pre-walker
        // this was misread as a literal `runs:` key, incorrectly waving the file through
        // as an action manifest.
        let uri = deps_core::test_util::test_uri("/repo/action.yml");
        let content =
            "? { a: 1 }\n: runs\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &uri).unwrap();
        assert!(
            result.dependencies.is_empty(),
            "a complex key's value scalar must never be misread as a literal top-level \
             `runs:` key: {:?}",
            result.dependencies
        );
    }

    #[test]
    fn test_complex_key_before_a_real_top_level_runs_key_does_not_lose_the_action_manifest() {
        // False-negative counterpart: an unrelated complex key appears *before* the
        // genuine top-level `runs:` key. Pre-walker this desynced the root mapping,
        // making `runs:` invisible and withholding a genuinely valid action manifest.
        let uri = deps_core::test_util::test_uri("/repo/action.yml");
        let content = "? { a: 1 }\n: unused\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &uri).unwrap();
        assert_eq!(
            result.dependencies.len(),
            1,
            "a complex key before a genuine top-level runs: key must not hide it from \
             has_top_level_runs_key: {:?}",
            result.dependencies
        );
        assert_eq!(result.dependencies[0].name(), "actions/checkout");
    }

    #[test]
    fn test_complex_mapping_key_does_not_crash_or_lose_sibling_keys() {
        // Basic complex-key coverage outside the `has_top_level_runs_key` gate: a workflow
        // file (not `action.yml`, so the gate above never applies) must still parse its
        // `uses:` steps normally after an unrelated complex key elsewhere in the document.
        let content = "? { a: 1 }\n: unused\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].name(), "actions/checkout");
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

    // --- issue #633 security audit finding: `is_last_on_line` / YAML flow-style guard ---

    /// Regression for the security audit's live reproduction: a `uses:` step written in
    /// YAML flow-mapping style has real content (`, with: {...}}`) after the ref on the
    /// same line — `is_last_on_line` must be `false` so a SHA-pin edit is withheld
    /// (`sha_pin_text_edit_for`'s guard) rather than commenting out the rest of the flow
    /// collection and producing invalid, unterminated YAML.
    #[test]
    fn test_flow_mapping_uses_step_is_not_last_on_line() {
        let content = "steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_matches!(dep.pin, Some(PinStyle::Tag));
        assert!(
            !dep.is_last_on_line,
            "a flow-mapping uses: step must not be considered safe for a trailing comment"
        );
    }

    /// Non-regression companion: a flow-*sequence* step (`steps: [{uses: ...}]`) has the
    /// same corruption risk and must be caught the same way.
    #[test]
    fn test_flow_sequence_uses_step_is_not_last_on_line() {
        let content = "steps: [{uses: actions/checkout@v4, with: {node: 20}}]\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert!(!result.dependencies[0].is_last_on_line);
    }

    /// Non-regression: an ordinary block-style step (the overwhelming common case) must
    /// keep `is_last_on_line: true` — the guard must not withhold the quickfix/bulk lens
    /// for every step, only the genuinely unsafe flow-style ones.
    #[test]
    fn test_block_style_uses_step_is_last_on_line() {
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert!(result.dependencies[0].is_last_on_line);
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
        // Critic M5: an alias filling a `uses:` value must still clear the pending-key
        // slot, or the next key/value pair in the same mapping desyncs — demonstrated here
        // with an unrealistic but syntactically valid duplicate `uses:` key.
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
        // because offset math anchored on the untrimmed value's start while
        // `classify_uses_value`'s output was derived from the trimmed one — multi-byte
        // leading whitespace (U+3000) inside a quoted scalar shifted every offset off a
        // char boundary. Minimal in-crate repro of the security audit's end-to-end finding.
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
        // Security S-1's benign-input half: an ordinary single-leading-space quoted value
        // must still resolve `version_range` to the real ref, not a shifted substring.
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

    #[test]
    fn test_expanded_yaml_rejected_as_parse_error() {
        // #1245: pins that the expansion bound is also wired through `check_yaml_bounds`.
        let mut payload = String::from("a0: &a0 [x, x]\n");
        for i in 1..=20 {
            payload.push_str(&format!("a{i}: &a{i} [*a{prev}, *a{prev}]\n", prev = i - 1));
        }
        let result = parse_workflow_yaml(&payload, &test_uri());
        let err = result.expect_err("expected the expansion budget to reject this");
        assert!(
            err.to_string().contains("YAML expansion"),
            "unexpected error message: {err}"
        );
    }

    // --- classify_uses_value / ref classification unit coverage ---
    //
    // `is_full_sha`/`is_tag_shaped`/`locate_value_span`/`MAX_FALLBACK_SCAN_BYTES` moved to
    // `deps_core::lsp_helpers` (#472/GitLab-CI-plan §6.1) — their unit tests moved with
    // them, since they test the shared helper, not this crate's workflow parser.

    // --- issue #885: O(1) line-end lookup past a ref-pinned dependency ---

    #[test]
    fn test_ref_near_end_of_document_without_trailing_newline_still_finds_comment_tag() {
        // Edge case for the line-end lookup: the file has no trailing newline at
        // all, so `line_table.line_start` for this line is `None` (falls back to
        // `content.len()`). Must still resolve the comment tag correctly.
        let sha = "a".repeat(40);
        let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4.2.0")
        );
    }

    #[test]
    fn test_flow_style_continuation_beyond_window_still_detected() {
        // Regression for a bounded-scan-window approach previously considered for #885
        // (impl-critic S1): a fixed lookahead would flip `is_last_on_line` to true once
        // enough padding separated the ref from the flow continuation, reopening #633.
        let sha = "a".repeat(40);
        let padding = " ".repeat(REST_OF_LINE_WINDOW_BYTES + 100);
        let content =
            format!("steps:\n  - {{uses: actions/checkout@{sha}{padding}, with: {{node: 20}}}}\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(
            !dep.is_last_on_line,
            "a flow-mapping continuation beyond the window must still be detected"
        );
    }

    #[test]
    fn test_sha_comment_tag_resolves_even_with_trailing_annotation_beyond_window() {
        // #885 (impl-critic point 4): a valid comment found within the window is
        // definitive regardless of trailing content beyond it — a naive
        // `!window_truncated && ...` gate would wrongly withhold the SHA-pin quickfix here.
        let sha = "a".repeat(40);
        let trailing_annotation = "-".repeat(REST_OF_LINE_WINDOW_BYTES + 100);
        let content =
            format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0 {trailing_annotation}\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("v4.2.0")
        );
        assert!(
            dep.is_last_on_line,
            "a resolved comment tag within the window must stay safe for block-style \
             lines regardless of trailing content beyond the window"
        );
    }

    #[test]
    fn test_comment_tag_truncated_at_window_boundary_is_rejected_not_shortened() {
        // Finding #1 on #885: a comment tag whose digits straddle the window boundary
        // must not be silently recorded as the truncated-but-still-semver-shaped prefix
        // (`v4.2.100` cut to `v4.2.10`, which still passes `is_partial_semver_shaped`).
        let sha = "a".repeat(40);
        let tag = "v4.2.100";
        // Window cuts after the 7th tag byte ("v4.2.10"), one byte short of the real tag.
        let padding_len = REST_OF_LINE_WINDOW_BYTES - "# ".len() - (tag.len() - 1);
        let padding = " ".repeat(padding_len);
        let filler = "z".repeat(REST_OF_LINE_WINDOW_BYTES);
        let content = format!("steps:\n  - uses: actions/checkout@{sha}{padding}# {tag}{filler}\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(
            dep.sha_comment().is_none(),
            "a comment tag straddling the window boundary must not be accepted at all, \
             truncated or otherwise; got {:?}",
            dep.pin
        );
    }

    #[test]
    fn test_comment_beyond_window_degrades_to_bare_sha_not_lost_within_window() {
        // Finding #2 on #885: a comment sitting entirely past the window degrades to a
        // bare SHA pin like "no comment", rather than panicking or misreading bytes.
        let sha = "a".repeat(40);
        let padding = " ".repeat(REST_OF_LINE_WINDOW_BYTES + 10);
        let content = format!("steps:\n  - uses: actions/checkout@{sha}{padding}# v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(is_commentless_sha(dep));
    }

    #[test]
    fn test_build_dependency_rest_of_line_lookup_is_not_quadratic() {
        // Direct regression test for the O(N^2) defect itself (#885), isolated from
        // `yaml-rust2`'s own O(document length) tokenizing cost, which an end-to-end
        // benchmark can't isolate from (an earlier version measured ~1s just tokenizing
        // an 8MB trailing comment with zero ref-pinned deps). Calls the private
        // `build_dependency` directly against one huge, newline-free "line" — the shape
        // the old unbounded `find('\n')` scanned to end-of-document on, once per call.
        let sha = "a".repeat(40);
        let filler = "x".repeat(8 * 1024 * 1024);
        let content = format!("uses: actions/checkout@{sha}{filler}");
        let line_table = LineOffsetTable::new(&content);
        let value = format!("actions/checkout@{sha}");

        // `Marker` has no public constructor, so a real one is captured once via a cheap
        // parse outside the loop; `Marker` is `Copy`, so it's reused for every iteration.
        let marker = {
            struct FirstScalarMarker(Option<Marker>);
            impl MarkedEventReceiver for FirstScalarMarker {
                fn on_event(&mut self, event: Event, marker: Marker) {
                    if matches!(&event, Event::Scalar(v, ..) if v == "actions/checkout@v4") {
                        self.0.get_or_insert(marker);
                    }
                }
            }
            let mut receiver = FirstScalarMarker(None);
            Parser::new_from_str("uses: actions/checkout@v4\n")
                .load(&mut receiver, false)
                .unwrap();
            receiver.0.expect("marker for the uses: value scalar")
        };

        // Iteration count halved from 2000 (finding #4) since `REST_OF_LINE_WINDOW_BYTES`
        // quadrupled, keeping wall-clock budget comparable while still swamping the old
        // code's per-call cost, which scanned the full 8MB tail regardless of iterations.
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let candidate = UsesCandidate::new(value.clone(), TScalarStyle::Plain, &marker);
            let dep = build_dependency(&content, &line_table, candidate);
            assert!(dep.is_some());
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "1000 build_dependency calls against an 8MB-tail line took {elapsed:?}; \
             expected the O(1) line-end lookup to make this independent of the trailing \
             content size instead of re-scanning ~8MB per call"
        );
    }

    // --- issue #898: comment-tag mis-attribution across sibling flow-mapping keys ---
    // `read_sha_pin_tail` can't tell this ref's own comment from an unrelated later
    // token on a flow-style line; gating on `is_last_on_line` (already computed for #633)
    // prevents a flow-style continuation from being misread as the comment.

    #[test]
    fn test_flow_style_sha_pin_trailing_comment_not_attributed_across_sibling_key() {
        // Exact issue repro: a flow-style step where `, with: {node: 20}}` sits between
        // the SHA ref and the line's only `#`. Before the fix, `version_range` swallowed
        // that whole span as a "trailing comment"; the fix must leave it un-attributed.
        let sha = "a".repeat(40);
        let content =
            format!("steps:\n  - {{uses: actions/checkout@{sha}, with: {{node: 20}}}} # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert!(!dep.is_last_on_line);
        assert!(is_commentless_sha(dep));
        assert_eq!(dep.version_literal(), None);
        assert_eq!(
            slice(&content, dep.version_range().unwrap()),
            sha,
            "version_range must span only the ref itself, never the sibling `with:` key"
        );
    }

    #[test]
    fn test_two_sha_pins_on_one_flow_style_line_get_distinct_non_overlapping_ranges() {
        // Issue #898 explicitly calls out this variant as worse: two SHA-pinned steps
        // sharing one flow-style line previously both got the line's single trailing
        // comment attributed, producing overlapping `version_range`s.
        let sha1 = "a".repeat(40);
        let sha2 = "b".repeat(40);
        let content = format!(
            "steps: [{{uses: actions/checkout@{sha1}}}, {{uses: actions/setup-node@{sha2}}}] # v4.2.0\n"
        );
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2);
        let dep0 = &result.dependencies[0];
        let dep1 = &result.dependencies[1];

        assert!(!dep0.is_last_on_line);
        assert!(!dep1.is_last_on_line);
        assert!(is_commentless_sha(dep0));
        assert!(is_commentless_sha(dep1));

        let range0 = dep0.version_range().unwrap();
        let range1 = dep1.version_range().unwrap();
        assert_eq!(slice(&content, range0), sha1);
        assert_eq!(slice(&content, range1), sha2);
        assert!(
            range0.end.character <= range1.start.character,
            "ranges must not overlap: {range0:?} vs {range1:?}"
        );
    }

    #[test]
    fn test_block_style_sha_pin_last_on_line_still_attributes_trailing_comment() {
        // Non-regression: an ordinary block-style SHA pin (the overwhelming common
        // case, and the whole reason `read_sha_pin_tail` exists) must keep resolving
        // its trailing `# vX.Y.Z` comment — the fix must not become overly conservative.
        let sha = "a".repeat(40);
        let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        let dep = &result.dependencies[0];
        assert!(dep.is_last_on_line);
        assert_eq!(comment_tag_of(dep), Some("v4.2.0"));
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
    }

    #[test]
    fn test_flow_style_sha_pin_version_range_excludes_sibling_key_text() {
        // End-to-end corruption check for #898: every code action scopes its `TextEdit`
        // exactly to `version_range`, so proving it never extends past the ref's own text
        // is sufficient to prove no edit could delete the sibling `with:` key's content.
        let sha = "a".repeat(40);
        let content =
            format!("steps:\n  - {{uses: actions/checkout@{sha}, with: {{node: 20}}}} # v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        let range = dep.version_range().unwrap();
        let spanned = slice(&content, range);
        assert_eq!(spanned, sha);
        assert!(!spanned.contains("with"));
        assert!(!spanned.contains('}'));
    }

    // --- issue #706: composite action.yml routing (parsing side) ---
    // `WorkflowReceiver` is key-driven, not path-driven: it recognizes any `uses:` scalar
    // not nested under `with:`, regardless of whether it sits under `jobs.*.steps` or
    // `runs.steps`. These tests confirm that; only routing (`ecosystem.rs`) needed a change.

    fn action_test_uri() -> Url {
        deps_core::test_util::test_uri("/repo/.github/actions/my-action/action.yml")
    }

    #[test]
    fn test_composite_action_uses_steps_are_parsed() {
        let content = "name: My Action\n\
             description: Does a thing\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20   - uses: actions/checkout@v4\n\
             \x20   - uses: actions/setup-node@v4.2.0\n\
             \x20     with:\n\
             \x20       node-version: 20\n";
        let result = parse_workflow_yaml(content, &action_test_uri()).unwrap();
        let names: Vec<&str> = result
            .dependencies
            .iter()
            .map(|d| d.name().as_str())
            .collect();
        assert_eq!(names, vec!["actions/checkout", "actions/setup-node"]);
    }

    /// A `docker`-`using:` composite action has no `runs.steps` at all — must parse to
    /// zero dependencies, not error, and (per `ecosystem.rs`'s routing change) must never
    /// surface a spurious "no dependencies" diagnostic since no such path exists in
    /// `deps-lsp`.
    #[test]
    fn test_docker_action_yields_no_dependencies() {
        let content = "name: My Docker Action\n\
             description: Runs in a container\n\
             runs:\n\
             \x20 using: docker\n\
             \x20 image: Dockerfile\n";
        let result = parse_workflow_yaml(content, &action_test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    /// A `node20`-`using:` composite action likewise has no `uses:` steps.
    #[test]
    fn test_node_action_yields_no_dependencies() {
        let content = "name: My JS Action\n\
             description: Runs on Node\n\
             runs:\n\
             \x20 using: node20\n\
             \x20 main: index.js\n";
        let result = parse_workflow_yaml(content, &action_test_uri()).unwrap();
        assert!(result.dependencies.is_empty());
    }

    /// Security audit finding (LOW, issue #706 review): `action.yml`/`action.yaml` is
    /// routed by bare basename anywhere in an opened workspace, not just real GitHub
    /// Action manifests. A file coincidentally named `action.yml` that happens to contain
    /// a `uses:`-shaped key but declares no top-level `runs:` (GitHub's own requirement
    /// for a real action manifest) must yield zero dependencies — no live registry fetch,
    /// no diagnostic — rather than being treated as a real action.
    #[test]
    fn test_action_yml_without_top_level_runs_key_yields_no_dependencies() {
        let content = "name: Not Actually a GitHub Action\n\
             uses: internal/base-template@stable\n";
        let result = parse_workflow_yaml(content, &action_test_uri()).unwrap();
        assert!(
            result.dependencies.is_empty(),
            "an action.yml/action.yaml with no top-level runs: key must not be treated \
             as a real GitHub Action manifest: {:?}",
            result.dependencies
        );
    }

    /// Companion to the guard above: a genuine root-level `action.yml` (no `.github/`
    /// ancestry at all) with a top-level `runs:` key must still be treated as a real
    /// action manifest and parse its `uses:` steps normally.
    #[test]
    fn test_root_level_action_yml_with_runs_key_is_parsed() {
        let uri = deps_core::test_util::test_uri("/repo/action.yml");
        let content = "name: My Action\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20   - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "actions/checkout");
    }

    /// Documents the accepted known limitation (review finding, item 1): `is_action_manifest_filename`
    /// is a plain basename check with no `.github/workflows` carve-out, so a workflow
    /// file unusually named `action.yml` (GitHub imposes no filename requirement on
    /// workflows, only the containing directory) is misclassified as a non-manifest and
    /// has its `uses:` steps dropped until renamed — accepted per the project's MVP
    /// convention since GitHub's own naming guidance makes this combination
    /// vanishingly unlikely in practice.
    #[test]
    fn test_workflow_file_named_action_yml_without_runs_key_loses_its_uses_steps() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/action.yml");
        let content = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &uri).unwrap();
        assert!(
            result.dependencies.is_empty(),
            "known limitation: a workflow file literally named action.yml with no \
             top-level runs: key is misclassified as a non-manifest: {:?}",
            result.dependencies
        );
    }

    /// Companion to the limitation above: the same workflow file is parsed normally once
    /// it happens to declare a top-level `runs:` key (an unlikely but not forbidden
    /// combination) — the guard only ever looks at content, never at directory.
    #[test]
    fn test_workflow_file_named_action_yml_with_runs_key_is_parsed() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/action.yml");
        let content = "on: push\n\
             runs: {}\n\
             jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &uri).unwrap();
        assert_eq!(result.dependencies.len(), 1);
        assert_eq!(result.dependencies[0].name(), "actions/checkout");
    }

    #[test]
    fn test_is_action_manifest_filename() {
        let cases = [
            ("/repo/action.yml", true),
            ("/repo/action.yaml", true),
            ("/repo/.github/actions/my-action/action.yml", true),
            ("/repo/.github/workflows/action.yml", true),
            ("/repo/.github/workflows/ci.yml", false),
            ("/repo/not-action.yml", false),
        ];
        for (path, expected) in cases {
            let uri = deps_core::test_util::test_uri(path);
            assert_eq!(is_action_manifest_filename(&uri), expected, "{path}");
        }
    }

    // --- issue #879: yaml-rust2 block-scalar byte-offset drift ---
    // Root cause: yaml-rust2 0.12.0's block-scalar scanner advances `Marker::index()` by
    // byte length, not char count, once its 16-char lookahead buffer refills mid-line —
    // any multi-byte char inside a block scalar permanently desyncs `index()` for the
    // rest of the document. Fixtures use lines long enough to force that refill, the
    // actual trigger, not merely "any non-ASCII char present".

    #[test]
    fn test_issue_879_literal_block_scalar_multibyte_then_uses_resolves() {
        let content = "on: push\njobs:\n  build:\n    steps:\n      - run: |\n          echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(slice(content, dep.name_range), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }

    #[test]
    fn test_issue_879_folded_block_scalar_multibyte_then_uses_resolves() {
        let content = "on: push\njobs:\n  build:\n    steps:\n      - run: >\n          echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }

    #[test]
    fn test_issue_879_multiple_block_scalars_drift_does_not_compound() {
        // Two prior block scalars each containing a multi-byte char must not accumulate
        // drift onto the second `uses:` step's resolved offset.
        let content = "on: push\njobs:\n  build:\n    steps:\n      - run: |\n          echo one \u{2014} first multibyte char here padded to be long enough for the scanner buffer refill\n      - uses: actions/checkout@v4\n      - run: |\n          echo two \u{2014} second multibyte char here also padded long enough for another scanner buffer refill\n      - uses: actions/setup-node@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 2, "{:?}", result.dependencies);
        assert_eq!(result.dependencies[0].name(), "actions/checkout");
        assert_eq!(
            slice(content, result.dependencies[0].version_range().unwrap()),
            "v4"
        );
        assert_eq!(result.dependencies[1].name(), "actions/setup-node");
        assert_eq!(
            slice(content, result.dependencies[1].version_range().unwrap()),
            "v4"
        );
    }

    #[test]
    fn test_issue_879_uses_before_multibyte_block_scalar_unaffected() {
        // Regression guard: a `uses:` step preceding the block scalar was never affected
        // by the drift (corruption only accumulates *after* the offending content line) —
        // must keep working exactly as before the fix.
        let content = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: |\n          echo hello \u{2014} world this line is long enough to force yaml-rust2's scanner buffer to refill mid-line\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }

    #[test]
    fn test_issue_879_multibyte_on_last_line_of_block_scalar_then_uses() {
        let content = "on: push\njobs:\n  build:\n    steps:\n      - run: |\n          first regular line long enough for buffer padding without any multibyte characters at all\n          echo hello \u{2014} world this final line of the block scalar is long enough too\n      - uses: actions/checkout@v4\n";
        let result = parse_workflow_yaml(content, &test_uri()).unwrap();
        assert_eq!(result.dependencies.len(), 1, "{:?}", result.dependencies);
        let dep = &result.dependencies[0];
        assert_eq!(dep.name(), "actions/checkout");
        assert_eq!(slice(content, dep.version_range().unwrap()), "v4");
    }
}

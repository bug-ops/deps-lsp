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
    LineOffsetTable, is_full_semver_shape, locate_value_span, marker_byte_offset,
    warn_rejected_value,
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

/// Upper bound, in bytes past a ref's end, on how far [`ref_is_last_token_on_line`] and
/// [`extract_comment_tag`] look ahead on the ref's physical line (issue #885 rework).
///
/// Deliberately a separate constant from `deps_core::lsp_helpers::MAX_FALLBACK_SCAN_BYTES`
/// (code-review finding #4 on the original #885 fix): that constant bounds a byte-offset
/// *correction* fallback with a completely different cost/correctness profile (a handful of
/// bytes in real manifests) — reusing it here coupled two unrelated tuning knobs, so that
/// crate's own consumers (including `deps-gitlab-ci`) would have silently inherited any
/// widening made for this file's rest-of-line comment/continuation lookahead.
///
/// Sized so realistic GitHub Actions inline comments/tags are essentially never truncated:
/// even a verbose annotation (`# pinned to v4.2.100, see PR #1234 for CVE-XXXX-XXXX`) is
/// well under a few hundred bytes, leaving an order of magnitude of headroom. Worst-case
/// cost is still bounded rather than reintroduced as O(document length): with
/// `deps_core::MAX_DEPENDENCIES_PER_DOCUMENT` (5000) ref-pinned dependencies packed onto
/// one adversarial physical line, each separated by a whitespace-only gap this large, the
/// two lookahead scans together visit at most `5000 * 2 * 4096` ≈ 40 MB total (each of the
/// ~20 MB of distinct gap content visited by both scans) — the distinct content alone is
/// already most of `deps_core::parser::MAX_YAML_EXPANDED_BYTES`'s 32 MiB document-size
/// ceiling, so this is close to the worst case such a document can express, not an
/// understatement of it. `test_build_dependency_rest_of_line_lookup_is_not_quadratic` below
/// demonstrates this stays a small, constant-per-call cost independent of how much content
/// follows on the line, unlike the unbounded `find('\n')` scan this issue was filed
/// against.
const REST_OF_LINE_WINDOW_BYTES: usize = 4096;

/// Whether [`build_dependency`]'s bounded rest-of-line window ([`REST_OF_LINE_WINDOW_BYTES`])
/// covers the ref's entire physical line, or was cut short before reaching the real
/// end-of-line content.
///
/// A plain `bool` here previously required the single call site to pass `!window_truncated`
/// — a negation that a future edit could silently drop or invert, flipping a
/// security-relevant conservative default to a permissive one with no type-level signal
/// (code-review finding #7). The two variants make the call site's intent explicit instead.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowCoverage {
    /// The window reached the line's real end — nothing on the line is unexamined.
    FullLine,
    /// The window was cut short by [`REST_OF_LINE_WINDOW_BYTES`]; real content may exist
    /// just past it that this scan never saw.
    Truncated,
}

/// Whether nothing unsafe to overwrite follows the ref on its source line: only
/// whitespace, or a whitespace-preceded YAML comment (the same comment-start rule
/// [`extract_comment_tag`] uses), all the way to end of line.
///
/// Security audit finding (pre-existing in the #473 quickfix, now shared by the bulk
/// pin-all-to-SHA aggregator, issue #633): a SHA-pin edit appends `# <tag>` right after
/// the ref, turning everything after it into a YAML comment. For a `uses:` step written
/// in **block** style that is safe — nothing meaningful follows on the line. For a step
/// written in YAML **flow** style (`{uses: actions/checkout@v4, with: {node: 20}}`), real
/// YAML content (`, with: {...}}`) follows the ref on the same line, and commenting it out
/// produces invalid YAML (an unterminated flow mapping) — silently breaking the workflow
/// rather than merely leaving it unpinned. This function has no notion of flow vs. block
/// context itself; it just checks "would writing a comment here swallow real content",
/// which is true in exactly the flow-style case and false for ordinary block-style lines.
///
/// `rest_of_line` may be a window bounded well short of the line's real end (issue #885
/// rework); `window` being [`WindowCoverage::FullLine`] is the answer to use only when the
/// *entire* window is whitespace with no `#`/real content found in it — a case this
/// function cannot resolve on its own, since real content might still exist just past a
/// truncated window. Finding a `#` comment or non-whitespace content within the window is
/// always a definitive answer regardless of `window` (impl-critic finding: gating a found
/// `#`/non-whitespace answer on "was the window truncated" discarded information the
/// window already proved, producing a false negative that withheld the SHA-pin quickfix on
/// a perfectly safe line whose comment tag resolved fine within the window).
// `bytes[i - 1]` is guarded by the `i > 0` conjunct immediately before it.
#[allow(clippy::indexing_slicing)]
fn ref_is_last_token_on_line(rest_of_line: &str, window: WindowCoverage) -> bool {
    let bytes = rest_of_line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            return true;
        }
        if !b.is_ascii_whitespace() {
            return false;
        }
    }
    window == WindowCoverage::FullLine
}

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
///
/// `window` reflects whether `rest_of_line` was cut short of the line's real end (issue
/// #885 rework). When the token runs all the way to the end of `rest_of_line` with no
/// terminating whitespace found *and* the window was [`WindowCoverage::Truncated`], the
/// token's true extent is unknown — real digits may continue just past the window edge
/// (e.g. a window boundary landing mid-digit turns `v4.2.100` into `v4.2.10`, which still
/// passes [`is_full_semver_shape`] and would otherwise be silently recorded as the real
/// version — code-review finding #1). Such an ambiguous token is rejected as `None` rather
/// than risking a truncated-but-plausible-looking version; a token that ends before the
/// window's edge (a terminating whitespace was actually observed) is unaffected regardless
/// of `window`, since its boundary was genuinely seen.
// `i` is a byte index holding ASCII `b'#'`; `token_len` from `find(char::is_whitespace)` or
// `.len()`. Both slice bounds are always char boundaries. `bytes[i - 1]` is short-circuited
// by the `i == 0 ||` conjunct, and `i` ranges `0..bytes.len()` from the loop.
#[allow(clippy::string_slice, clippy::indexing_slicing)]
fn extract_comment_tag(rest_of_line: &str, window: WindowCoverage) -> Option<(&str, usize)> {
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
        // A single `find` gives both "did a terminator turn up" and "where" — no need
        // for a separate `contains` pass over the same text first (impl-critic-2 nit).
        let terminator = after_ws.find(char::is_whitespace);
        if terminator.is_none() && window == WindowCoverage::Truncated {
            // The token has no observed end within the window, so its true text may
            // continue past the edge — accepting it here risks silently recording a
            // truncated-but-still-semver-shaped value (finding #1). Bail out rather than
            // guess; the ref degrades to a bare, commentless pin instead of a wrong one.
            return None;
        }
        let token_len = terminator.unwrap_or(after_ws.len());
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
    /// `yaml-rust2` marker line (1-indexed) and column (0-indexed char count) of the
    /// scalar — see [`marker_byte_offset`] for why these, not `Marker::index()`, are used
    /// to resolve the value's byte offset (#879).
    line: usize,
    col: usize,
}

/// Collects every `uses:` value-scalar event, skipping any `uses` key that has a `with:`
/// ancestor (a step input literally named `uses`) — covers `jobs.*.steps[].uses` and
/// `jobs.<id>.uses` (reusable-workflow calls) with one rule, matching Renovate.
///
/// Also tracks [`Self::has_top_level_runs_key`] alongside `candidates`: both are derived
/// from the same single streaming pass over the document's YAML events, so recomputing
/// the `runs:` check separately (e.g. from the URI path instead) would mean a second,
/// redundant walk of the same event stream for one boolean.
struct WorkflowReceiver {
    stack: Vec<Frame>,
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
            stack: Vec::new(),
            candidates: Vec::new(),
            has_top_level_runs_key: false,
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
                    if self.stack.len() == 1 && value == "runs" {
                        self.has_top_level_runs_key = true;
                    }
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
                            line: marker.line(),
                            col: marker.col(),
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
// `ref_start`/`ref_end` build on `span_start`, which is char-boundary-aligned in `content` via
// `marker_byte_offset` + `locate_value_span` and then re-anchored to the trimmed value
// (see the trim re-anchoring comment below) — plus `before_at_len`/`ref_text.len()`, both
// whole-substring byte counts, so the arithmetic never lands mid-character. `token_end` is
// relative to `content[ref_end..]`, windowed to at most `REST_OF_LINE_WINDOW_BYTES` past
// `ref_end` and to the line's own end (resolved via `line_table.line_start` in O(1)), rather
// than an unbounded `find('\n')` scan (issue #885).
#[allow(clippy::string_slice)]
fn build_dependency(
    content: &str,
    line_table: &LineOffsetTable,
    candidate: UsesCandidate,
) -> Option<GithubActionsDependency> {
    // Whether the *whole* `uses:` value scalar was written unquoted. For a quoted scalar,
    // any `Range` computed below sits inside the quotes — a SHA-pin code action (issue
    // #473) must not write `{sha} # {tag}` there, since the `#` would land inside the
    // string rather than starting a YAML comment (spec 031 FR-010). Read once here and
    // carried on every constructed dependency, mirroring the existing single-purpose
    // `TScalarStyle::Plain` gate below for the SHA-with-comment case.
    let is_plain_scalar = candidate.style == TScalarStyle::Plain;

    let value_start = marker_byte_offset(content, line_table, candidate.line, candidate.col);
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
            is_last_on_line: true,
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
            is_last_on_line: true,
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
                    is_last_on_line: true,
                });
            }

            // O(1) real line-end lookup via `line_table` instead of an unbounded
            // `find('\n')` scan (issue #885): the latter scanned to end-of-document
            // once per ref-pinned dependency, an O(N x remaining-document-length)
            // cost on a single-line manifest with N such deps. Mirrors
            // `marker_byte_offset`'s own use of `LineOffsetTable::line_start` — that
            // returns the byte offset right after this line's own '\n' (0-indexed
            // line `candidate.line`, so passing the 1-indexed `candidate.line` here
            // lands on the *next* line's start), or `content.len()` if this is the
            // last line with no trailing newline. `line_end` is always a `content`
            // char boundary (built from a `char_indices()` walk), and stepping back
            // one byte off it is too when that byte is the single-byte '\n' itself,
            // so no boundary clamp is needed for it specifically.
            let line_end = line_table
                .line_start(candidate.line)
                .unwrap_or(content.len());
            let line_end = match line_end.checked_sub(1) {
                Some(i) if content.as_bytes().get(i) == Some(&b'\n') => i,
                _ => line_end,
            };
            // Even a correctly-located line can itself be enormous — a
            // single-physical-line manifest with many ref-pinned dependencies and
            // no real newline anywhere is exactly #885's threat model, and neither
            // `ref_is_last_token_on_line` nor `extract_comment_tag` needs more than
            // a short window after the ref. Cap the window at
            // `REST_OF_LINE_WINDOW_BYTES` past `ref_end`; `floor_char_boundary`
            // clamps it back to a valid boundary since (unlike `line_end`) this
            // bound isn't guaranteed to land on one. `line_end < ref_end` is
            // defense-in-depth for a `line_table`/`ref_end` mismatch that shouldn't
            // occur in practice — logged distinctly below (code-review finding #8)
            // since it's a desync bug, not routine truncation, and without this
            // disjunct such a mismatch would silently look untruncated instead of
            // failing safe.
            let line_end_desynced = line_end < ref_end;
            if line_end_desynced {
                tracing::debug!(
                    ref_end,
                    line_end,
                    candidate_line = candidate.line,
                    "line_table line_end is before ref_end; this should not happen \
                     in practice — treating the rest-of-line window as truncated"
                );
            }
            let capped_end = ref_end
                .saturating_add(REST_OF_LINE_WINDOW_BYTES)
                .min(line_end);
            let window_truncated = line_end_desynced || capped_end < line_end;
            let window = if window_truncated {
                WindowCoverage::Truncated
            } else {
                WindowCoverage::FullLine
            };
            let capped_end = content.floor_char_boundary(capped_end);
            let rest_of_line = &content[ref_end..capped_end.max(ref_end)];
            // Security audit finding (issue #633): computed for every ref-pinned form,
            // not just the SHA-with-comment case below, since the mutable-tag SHA-pin
            // edit (`sha_pin_text_edit_for`) needs it for `PinStyle::Tag` too — a flow-
            // style step (`{uses: actions/checkout@v4, with: {...}}`) has real YAML
            // content after the ref that a trailing `# <tag>` comment would swallow.
            // `ref_is_last_token_on_line` gives a definitive answer whenever it finds
            // a `#` comment or real content within the (possibly truncated) window —
            // `window` only matters as the fallback when the window is all
            // whitespace with nothing conclusive in it, where we cannot safely assume
            // "nothing unsafe follows" (issue #885 rework, impl-critic S1: a naive
            // bounded window without this fallback flipped `is_last_on_line` from
            // false to true once enough padding separated the ref from a real
            // flow-style continuation, reopening the #633 corruption).
            let is_last_on_line = ref_is_last_token_on_line(rest_of_line, window);

            if is_full_sha(&ref_text) {
                let comment = is_plain_scalar
                    .then(|| extract_comment_tag(rest_of_line, window))
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
                        is_last_on_line,
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
                version_literal: None,
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
            dependency_truncation: None,
        });
    }

    // Issue #706 review finding (security, LOW): `action.yml`/`action.yaml` is routed by
    // bare basename (`Ecosystem::manifest_filenames`), which matches anywhere in an
    // opened workspace — not just real GitHub Action manifests. Withhold every candidate
    // for such a file unless it actually declares GitHub's own required top-level
    // `runs:` key, so a coincidentally-named, unrelated `action.yml` degrades to zero
    // dependencies instead of issuing live registry fetches and diagnostics.
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
fn is_action_manifest_filename(uri: &Uri) -> bool {
    let path = uri.path().as_str();
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename == "action.yml" || filename == "action.yaml"
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
    #[allow(clippy::string_slice)] // fixtures are single-line ASCII literals
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

    // --- issue #633 security audit finding: `is_last_on_line` / YAML flow-style guard ---

    #[test]
    fn test_ref_is_last_token_on_line_true_for_empty_and_whitespace_only() {
        assert!(ref_is_last_token_on_line("", WindowCoverage::FullLine));
        assert!(ref_is_last_token_on_line("   ", WindowCoverage::FullLine));
    }

    #[test]
    fn test_ref_is_last_token_on_line_false_for_empty_and_whitespace_only_when_window_truncated() {
        // #885 rework: an all-whitespace window gives no definitive answer on its own
        // when it was truncated before the line's real end — `WindowCoverage::Truncated`
        // must be honored as the fallback in that case.
        assert!(!ref_is_last_token_on_line("", WindowCoverage::Truncated));
        assert!(!ref_is_last_token_on_line("   ", WindowCoverage::Truncated));
    }

    #[test]
    fn test_ref_is_last_token_on_line_true_for_trailing_comment() {
        assert!(ref_is_last_token_on_line(
            " # my note",
            WindowCoverage::FullLine
        ));
    }

    #[test]
    fn test_ref_is_last_token_on_line_true_for_trailing_comment_even_when_window_truncated() {
        // #885 rework (impl-critic point 4): finding a `#` comment within the window
        // is a definitive answer regardless of `WindowCoverage` — the window
        // being truncated elsewhere in the line doesn't matter once the comment is
        // found here.
        assert!(ref_is_last_token_on_line(
            " # my note",
            WindowCoverage::Truncated
        ));
    }

    #[test]
    fn test_ref_is_last_token_on_line_false_for_flow_collection_continuation() {
        // The exact shape from the security audit's reproduction: `, with: {node: 20}}`
        // immediately follows a tag ref inside a YAML flow mapping.
        assert!(!ref_is_last_token_on_line(
            ", with: {node: 20}}",
            WindowCoverage::FullLine
        ));
        assert!(!ref_is_last_token_on_line("}", WindowCoverage::FullLine));
        assert!(!ref_is_last_token_on_line("]", WindowCoverage::FullLine));
    }

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
            extract_comment_tag(" # v1.0.0 # v2.0.0", WindowCoverage::FullLine),
            Some(("v1.0.0", " # v1.0.0".len()))
        );
    }

    #[test]
    fn test_extract_comment_tag_no_hash_returns_none() {
        assert_eq!(
            extract_comment_tag(" no comment here", WindowCoverage::FullLine),
            None
        );
    }

    #[test]
    fn test_extract_comment_tag_rejects_token_reaching_truncated_window_edge() {
        // Code-review finding #1: a token with no observed terminating whitespace
        // within a *truncated* window is ambiguous — it might continue past the
        // edge — and must be rejected rather than accepted as-is, even though it
        // otherwise has a valid semver shape.
        assert_eq!(
            extract_comment_tag(" # v4.2.10", WindowCoverage::Truncated),
            None
        );
    }

    #[test]
    fn test_extract_comment_tag_accepts_token_reaching_full_line_end() {
        // The same shape as above is fine when the window covers the real line end:
        // there is genuinely nothing more to see, so the token is complete.
        assert_eq!(
            extract_comment_tag(" # v4.2.10", WindowCoverage::FullLine),
            Some(("v4.2.10", " # v4.2.10".len()))
        );
    }

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
        // Regression for a bounded-scan-window approach previously considered for
        // #885 (impl-critic S1): a fixed lookahead window would flip
        // `is_last_on_line` from false to true once enough whitespace padding sat
        // between the ref and the flow-mapping's real continuation
        // (`, with: {...}}`), reopening the exact #633 corruption (a SHA-pin edit
        // commenting out real YAML). The O(1) `line_table`-bounded lookup covers
        // the whole physical line regardless of padding length, so this must stay
        // `false` no matter how far the continuation sits.
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
        // #885 rework (impl-critic point 4): a valid `# <tag>` comment found within
        // the bounded window is a definitive answer regardless of how much more text
        // follows on the line beyond the window — `is_last_on_line` must stay `true`
        // (block-style, nothing unsafe to overwrite) and the tag must still resolve.
        // A naive `!window_truncated && ...` gate would have incorrectly returned
        // `false` here purely because of the long trailing annotation, withholding
        // the SHA-pin quickfix on an otherwise perfectly safe line.
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
        // Code-review finding #1 on the #885 rework: a comment tag whose digits
        // straddle the window boundary must not be silently recorded as the
        // truncated-but-still-semver-shaped prefix (`v4.2.100` cut to `v4.2.10`,
        // which still passes `is_full_semver_shape`). Construct `rest_of_line` so
        // the window (`REST_OF_LINE_WINDOW_BYTES` bytes past `ref_end`) ends exactly
        // one byte into the last digit of `v4.2.100`, then confirm plenty of real
        // content continues past the window (so this isn't just routine end-of-line
        // truncation) and the tag is rejected as ambiguous rather than shortened.
        let sha = "a".repeat(40);
        let tag = "v4.2.100";
        // rest_of_line = padding + "# " + tag; window cuts after the 7th tag byte
        // ("v4.2.10"), one byte short of the real 8-byte tag.
        let padding_len = REST_OF_LINE_WINDOW_BYTES - "# ".len() - (tag.len() - 1);
        let padding = " ".repeat(padding_len);
        let filler = "z".repeat(REST_OF_LINE_WINDOW_BYTES);
        let content = format!("steps:\n  - uses: actions/checkout@{sha}{padding}# {tag}{filler}\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(
            !matches!(
                dep.pin,
                Some(PinStyle::Sha {
                    comment_tag: Some(_)
                })
            ),
            "a comment tag straddling the window boundary must not be accepted at all, \
             truncated or otherwise; got {:?}",
            dep.pin
        );
    }

    #[test]
    fn test_comment_beyond_window_degrades_to_bare_sha_not_lost_within_window() {
        // Code-review finding #2 on the #885 rework: sanity check that a `# <tag>`
        // comment sitting entirely past the window is treated the same as "no
        // comment" (degrades to a bare, commentless SHA pin) rather than panicking
        // or misreading nearby bytes — the window is a documented, intentional
        // limit (see `REST_OF_LINE_WINDOW_BYTES`'s doc comment), not a bug to patch
        // around per call site.
        let sha = "a".repeat(40);
        let padding = " ".repeat(REST_OF_LINE_WINDOW_BYTES + 10);
        let content = format!("steps:\n  - uses: actions/checkout@{sha}{padding}# v4.2.0\n");
        let result = parse_workflow_yaml(&content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];
        assert!(matches!(dep.pin, Some(PinStyle::Sha { comment_tag: None })));
    }

    #[test]
    fn test_build_dependency_rest_of_line_lookup_is_not_quadratic() {
        // Direct regression test for the O(N^2) defect itself (issue #885),
        // isolated from `yaml-rust2`'s own O(document length) tokenizing cost —
        // a full end-to-end `parse_workflow_yaml` benchmark can't isolate this
        // fix's effect from that unrelated, unavoidable baseline cost (an
        // earlier version of this test measured ~1s just tokenizing an 8MB
        // trailing YAML comment with *zero* ref-pinned dependencies present).
        // `build_dependency` is private to this module, so this calls it
        // directly with a synthetic candidate against one huge, newline-free
        // "line" — exactly the shape the old `content[ref_end..].find('\n')`
        // scanned to end-of-document on, once per call. The O(1)
        // `line_table.line_start` lookup makes each call's cost independent of
        // how much content follows on the line.
        let sha = "a".repeat(40);
        let filler = "x".repeat(8 * 1024 * 1024);
        let content = format!("uses: actions/checkout@{sha}{filler}");
        let line_table = LineOffsetTable::new(&content);
        let value = format!("actions/checkout@{sha}");

        // Iteration count halved from the original 2000 (finding #4/direction note):
        // `REST_OF_LINE_WINDOW_BYTES` quadrupled from the original 1024, so each call
        // now scans up to 4x as many bytes; keeping the wall-clock budget comparable
        // while still swamping the old code's cost (which scanned the full 8MB tail
        // per call, independent of iteration count) preserves a wide discrimination
        // margin without flirting with the assertion's headroom under CI load.
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let candidate = UsesCandidate {
                value: value.clone(),
                style: TScalarStyle::Plain,
                line: 1,
                col: "uses: ".len(),
            };
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

    // --- issue #706: composite action.yml routing (parsing side) ---
    //
    // `WorkflowReceiver` is key-driven, not path-driven — it recognizes any `uses:`
    // scalar not nested under `with:`, regardless of whether it sits under
    // `jobs.*.steps` (a workflow) or `runs.steps` (a composite action). These tests
    // confirm that already holds for `action.yml`'s own grammar; only routing
    // (`ecosystem.rs`) needed a change to reach this parser with such a file.

    fn action_test_uri() -> Uri {
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
    //
    // Root cause: yaml-rust2 0.12.0's `Scanner::scan_block_scalar_content_line` advances
    // `Marker::index()` by a content line's *byte* length, not its *char* count, once its
    // internal 16-char lookahead buffer refills mid-line — every multi-byte char inside a
    // block scalar (`|`/`>`) permanently desyncs `index()` for the rest of the document.
    // These fixtures use content lines long enough (well over 16 chars around the
    // multi-byte char) to force that refill — the actual trigger condition, not merely
    // "any non-ASCII char present".

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

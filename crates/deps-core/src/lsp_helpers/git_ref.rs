//! Shared git-tags-datasource parser scaffolding, extracted from
//! `deps-github-actions`'s originally crate-private `parser.rs`/`formatter.rs` helpers so a
//! second git-tags-shaped ecosystem (GitLab CI) can reuse the same hardened span/text
//! plumbing instead of forking it. `deps-github-actions` now imports these instead of
//! defining them locally.

use super::LineOffsetTable;
use crate::position::Range;
use yaml_rust2::parser::Tag;
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[cfg(feature = "lsp-responses")]
use super::{EcosystemFormatter, markdown_code_span, single_file_edit};
#[cfg(feature = "lsp-responses")]
use crate::{Dependency, ParseResult};
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, Position, TextEdit, WorkspaceEdit};

/// Length of a full, lowercase-or-not hex commit SHA (git's SHA-1 object id).
const SHA_LEN: usize = 40;

/// Whether `s` is a 40-character hex string — a git commit SHA shape, shared by every
/// ecosystem resolving refs against a git-tags-datasource API (GitHub, GitLab).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_full_sha;
///
/// assert!(is_full_sha(&"a".repeat(40)));
/// assert!(!is_full_sha(&"a".repeat(39)));
/// assert!(!is_full_sha("not-a-sha"));
/// ```
#[must_use]
pub fn is_full_sha(s: &str) -> bool {
    s.len() == SHA_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `s` has the shape of a tag ref: an optional leading `v`/`V` followed by a digit.
///
/// Anything else (that isn't an [`is_full_sha`] SHA) is treated as a branch name — the
/// "honest unknown" side, since a branch cannot be resolved to a concrete version without
/// registry access.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_tag_shaped;
///
/// assert!(is_tag_shaped("v4"));
/// assert!(is_tag_shaped("4.2.0"));
/// assert!(!is_tag_shaped("main"));
/// assert!(!is_tag_shaped(&"a".repeat(40)));
/// ```
#[must_use]
pub fn is_tag_shaped(s: &str) -> bool {
    if is_full_sha(s) {
        return false;
    }
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    stripped.starts_with(|c: char| c.is_ascii_digit())
}

/// Whether `s` has the shape of a version safe to trust from free-text context.
///
/// Unlike [`is_tag_shaped`] (safe for a constrained git-ref domain GitHub itself
/// resolves), this is meant for text a human wrote by hand — e.g. a YAML comment.
///
/// An optional leading `v`/`V`, 1-3 dot-separated all-digit components, and an optional
/// `-`/`+` prerelease/build suffix (accepted, not itself validated) — but, unlike
/// `is_tag_shaped`, a bare all-digit token with **no** `v`/`V` prefix and **no** dot
/// (`1234`, `20240501`, `0`) is rejected: nothing in the shape alone distinguishes an
/// unprefixed integer from an arbitrary numeric annotation a human might write in a
/// comment (a ticket number, a date), whereas `owner/repo@1234` as an actual git *ref* has
/// no such ambiguity — GitHub either has a ref named `1234` or it doesn't (issue #907
/// review finding S1: `deps-github-actions`'s SHA-pin trailing-comment parser had used
/// `is_tag_shaped` and silently treated a genuine non-version annotation as a version).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_partial_semver_shaped;
///
/// assert!(is_partial_semver_shaped("v4"));
/// assert!(is_partial_semver_shaped("v2.9"));
/// assert!(is_partial_semver_shaped("4.2.0"));
/// assert!(is_partial_semver_shaped("v4.2.0-beta.1"));
/// assert!(!is_partial_semver_shaped("1234"));
/// assert!(!is_partial_semver_shaped("20240501"));
/// assert!(!is_partial_semver_shaped("0"));
/// assert!(!is_partial_semver_shaped("2024-01-15"));
/// assert!(!is_partial_semver_shaped("main"));
/// ```
#[expect(
    clippy::string_slice,
    reason = "idx comes from str::find(['-', '+']), both ASCII bytes, so it is always a char \
              boundary; strip_prefix(['v', 'V']) likewise only ever removes a single ASCII byte"
)]
#[must_use]
pub fn is_partial_semver_shaped(s: &str) -> bool {
    let has_v_prefix = s.starts_with(['v', 'V']);
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let core = match stripped.find(['-', '+']) {
        Some(idx) => &stripped[..idx],
        None => stripped,
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 || (!has_v_prefix && parts.len() < 2) {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Rewrites `tag` to match `current`'s leading `v`/`V` prefix style (or lack of one).
///
/// A repository/project can change its tagging convention over time (`4.0.0` -> `v5.0.0`);
/// a formatted replacement should still read naturally against the user's existing pin
/// style rather than silently flipping it.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::match_v_prefix_style;
///
/// assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
/// assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
/// ```
#[expect(
    clippy::string_slice,
    reason = "tag[1..] only runs when tag_has_v (an ASCII 'v'/'V' prefix check), so index 1 \
              is always a char boundary"
)]
#[must_use]
pub fn match_v_prefix_style(current: &str, tag: &str) -> String {
    let current_has_v = current.starts_with(['v', 'V']);
    let tag_has_v = tag.starts_with(['v', 'V']);
    match (current_has_v, tag_has_v) {
        (true, false) => format!("v{tag}"),
        (false, true) => tag[1..].to_string(),
        _ => tag.to_string(),
    }
}

/// Whether a plain (unquoted) scalar's text denotes an absent value.
///
/// A completely empty plain scalar (`ref:` with nothing after the colon — the normal
/// mid-typing state in a live editor) is *always* absent, regardless of any tag: `!!str` on
/// no text still means no text was given, not the literal empty string (which needs an
/// actual quoted `""` to express — see the `style == Plain` guard below). For non-empty text
/// (`~`/`null`), an explicit tag matters: untagged or explicitly `tag:yaml.org,2002:null`
/// tagged text still resolves to absent, but any *other* explicit tag (e.g. `!!str`) forces
/// the scalar to that type instead — `!!str null` is the literal string `"null"`, not an
/// absent value.
///
/// The four spellings GitLab's Psych loader treats as null (verified against Ruby Psych
/// 5.3.1 — GitLab's own YAML loader and this function's binding oracle since
/// `deps-gitlab-ci`'s mapping-shaped container-anchor support (spec 058 FR-015) became this
/// function's second consumer): `~`, `null`, `Null`, `NULL`. This is a fixed enumeration, not
/// true case-insensitive matching — `nULL` or `nUll` do **not** match, mirroring Psych's own
/// behavior exactly. Gating on `"~" | "null"` alone (this function's original, `deps-dart`-only,
/// `yaml_rust2::YamlLoader`-mirroring behavior) let a merged-template `ref: NULL` resolve to
/// the literal version string `"NULL"` instead of absent — a plausible-looking wrong
/// version, worse than none (P0).
///
/// A *quoted* empty string (`ref: ""`) is a real, if unusual, explicit value and must not be
/// treated as absent — enforced by the `style == Plain` guard below, not by this list.
///
/// Promoted from `deps-dart/src/parser.rs` (originally private to that crate, and originally
/// scoped only to `yaml_rust2::YamlLoader`'s narrower `"" | "~" | "null"` rule) to
/// `deps-core` once `deps-gitlab-ci`'s mapping-shaped container-anchor support (spec 058
/// FR-015) became its second consumer; `deps-dart` now imports this shared version too,
/// rather than keeping its own duplicate.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_plain_null;
/// use yaml_rust2::scanner::TScalarStyle;
///
/// assert!(is_plain_null(TScalarStyle::Plain, None, ""));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "~"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "null"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "Null"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "NULL"));
/// assert!(!is_plain_null(TScalarStyle::DoubleQuoted, None, ""));
/// assert!(!is_plain_null(TScalarStyle::Plain, None, "v1.0.0"));
/// ```
#[must_use]
pub fn is_plain_null(style: TScalarStyle, tag: Option<&Tag>, value: &str) -> bool {
    if style != TScalarStyle::Plain {
        return false;
    }
    if value.is_empty() {
        return true;
    }
    match tag {
        None => matches!(value, "~" | "null" | "Null" | "NULL"),
        Some(tag) => is_null_tag(tag) && matches!(value, "~" | "null" | "Null" | "NULL"),
    }
}

/// Whether `tag` is YAML's `null` tag, in either form `yaml-rust2`'s scanner produces.
///
/// The `!!null` shorthand resolves to `Tag { handle: "tag:yaml.org,2002:", suffix: "null"
/// }`, but the equivalent verbatim form `!<tag:yaml.org,2002:null>` resolves to `Tag {
/// handle: "", suffix: "tag:yaml.org,2002:null" }` — the whole URI lands in `suffix` with an
/// empty `handle`, since verbatim tags bypass handle resolution entirely.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_null_tag;
/// use yaml_rust2::parser::Tag;
///
/// assert!(is_null_tag(&Tag {
///     handle: "tag:yaml.org,2002:".to_string(),
///     suffix: "null".to_string(),
/// }));
/// assert!(!is_null_tag(&Tag {
///     handle: "tag:yaml.org,2002:".to_string(),
///     suffix: "str".to_string(),
/// }));
/// ```
#[must_use]
pub fn is_null_tag(tag: &Tag) -> bool {
    (tag.handle == "tag:yaml.org,2002:" && tag.suffix == "null")
        || (tag.handle.is_empty() && tag.suffix == "tag:yaml.org,2002:null")
}

/// Resolves a `yaml-rust2` scanner marker's `(line, col)` position into a byte offset in
/// `content`, via a shared, once-per-document [`LineOffsetTable`].
///
/// Deliberately does **not** use `yaml_rust2::scanner::Marker::index()` — despite its own
/// doc comment claiming a byte count, `Scanner::scan_block_scalar_content_line`
/// (`yaml-rust2` 0.12.0's `scanner.rs:1778-1779`) advances `mark.index` by the **byte**
/// length of each block-scalar (`|`/`>`) content line, not its char count, once the
/// scanner's internal 16-char lookahead buffer empties mid-line — which happens on
/// essentially every real content line. Every multi-byte UTF-8 character consumed this way
/// desyncs `index` permanently for the rest of the document (#879). `Marker::line()`/
/// `Marker::col()` are unaffected: `col` resets to `0` on every line break
/// (`Scanner::skip_nl`), so the corruption from one block-scalar content line never carries
/// into a later scalar's own `col` — safe for every value this crate resolves spans for
/// (`uses:`, `ref:`, `project:`, `include:`), none of which are themselves inside a block
/// scalar's own content.
///
/// This `line`/`col`-based resolver is a workaround for an upstream `yaml-rust2` 0.12.0 bug
/// (tracked in #880, not yet reported upstream). Do not simplify this back to
/// `Marker::index()`-based resolution without first checking whether the upstream bug has
/// been fixed.
///
/// `line` is 1-indexed and `col` a 0-indexed **char** count within that line, matching
/// `yaml-rust2`'s own `Marker::line()`/`Marker::col()` *behavior* — note that
/// `yaml_rust2::scanner::Marker::col()`'s own doc comment claims 1-indexed while its `Display`
/// impl prints `col + 1`, i.e. the doc is wrong the same way `index()`'s was; do not "fix" the
/// `col.min(...)`/`.nth(col)` arithmetic below to match that prose. Returns `content.len()` if
/// `line` is past the end of `content`. `line` must be `>= 1` (see `debug_assert!` below) —
/// every marker `yaml-rust2` actually emits satisfies this.
///
/// # Line-ending assumption
///
/// Like every other [`LineOffsetTable`] lookup, this counts only `\n` as a line break. A
/// document using bare `\r` (no `\n`) line endings is out of scope: `yaml-rust2` still
/// advances `mark.line` across such a break (`Scanner::skip_nl`), but `LineOffsetTable::new`
/// never splits on a lone `\r`, so `line` can run past the table's line count for any content
/// after the first line — this function then falls back to `content.len()`, and the caller's
/// [`locate_value_span`] fails to find the value, dropping the candidate (logged at `debug`
/// — see its own doc comment) the same way as any other fallback-scan miss.
/// Bare-`\r` YAML is not a realistic manifest shape; LF and CRLF, which `yaml-rust2` and this
/// crate both handle throughout, are unaffected.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, marker_byte_offset};
///
/// let content = "a: b\nc: \u{2014}d\n";
/// let table = LineOffsetTable::new(content);
/// // Line 2 ("c: \u{2014}d"), char column 4 -> the 'd' right after the multi-byte em dash.
/// assert_eq!(marker_byte_offset(content, &table, 2, 4), content.find('d').unwrap());
/// ```
#[must_use]
pub fn marker_byte_offset(
    content: &str,
    table: &LineOffsetTable,
    line: usize,
    col: usize,
) -> usize {
    debug_assert!(line >= 1, "yaml-rust2 marker line is 1-indexed, got 0");
    let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
        return content.len();
    };
    let line_end = table.line_start(line).unwrap_or(content.len());
    let line_text = content.get(line_start..line_end).unwrap_or_default();
    // #742-style fast path: an ASCII line has 1 byte per char, so `col` is already a byte
    // offset — skip the `char_indices()` walk, which made this O(line length) per call.
    let byte_in_line = if table
        .line_is_ascii
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or(false)
    {
        col.min(line_text.len())
    } else {
        // #882: a naive char_indices().nth(col) walk per call is O(line length); the
        // cached per-line index makes repeat lookups on the same line O(1).
        table.non_ascii_char_byte_offset(line.saturating_sub(1), line_text, col)
    };
    line_start + byte_in_line
}

/// Upper bound, in bytes past `search_from`, on how far [`locate_value_span`]'s fallback
/// scan will search.
///
/// The fallback exists only to correct for `yaml-rust2`'s marker-vs-value quoting offset —
/// a handful of bytes at most for any real manifest value. Leaving the scan unbounded made
/// it an `O(line_length x value_length)` scan over the *rest of the line* regardless of how
/// far away the real match could possibly be: a several-megabyte single-line manifest
/// (comfortably under the crate's YAML expansion-size gate) could cost whole minutes of
/// single-core CPU per `didOpen`/`didChange` (security S-2). Capping the window bounds the
/// fallback's cost independent of line length; a value that genuinely cannot be located
/// within this window is treated the same as any other unlocatable value — the candidate is
/// silently skipped, not an error.
pub const MAX_FALLBACK_SCAN_BYTES: usize = 1024;

/// Finds the byte offset in `content` (searching only within the line starting at
/// `search_from`) where the literal bytes of `value` occur.
///
/// The scanner-reported marker usually points exactly at the value's start for a plain
/// scalar, but may point at the opening quote for a quoted one — rather than
/// reverse-engineering `yaml-rust2`'s exact escaping/quoting byte accounting, this verifies
/// the direct-offset guess first and falls back to a bounded same-line search (see
/// [`MAX_FALLBACK_SCAN_BYTES`]), which is exact for the unescaped ASCII text most manifest
/// values are.
///
/// `is_quoted` disambiguates the empty-value case (see below) — pass
/// [`MarkedScalar::is_quoted`], or the equivalent for a hand-rolled scanner receiver.
///
/// Returns `None` if `search_from` is past the end of `content` (checked first, before the
/// `value.is_empty()` short-circuit below — #673 M2) or `value` cannot be located within
/// the bounded fallback scan — logged at `debug` (value length only, never the value text
/// itself, matching the `warn_rejected_value` convention) so a future resolver miss (e.g.
/// #879's class of bug, or [`marker_byte_offset`]'s documented bare-`\r` gap) is diagnosable
/// instead of vanishing the candidate with zero trace.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::locate_value_span;
///
/// let content = "prefix xxxxx actions/checkout@v4 suffix";
/// let (start, end) = locate_value_span(content, 0, "actions/checkout@v4", false).unwrap();
/// assert_eq!(&content[start..end], "actions/checkout@v4");
/// ```
#[must_use]
pub fn locate_value_span(
    content: &str,
    search_from: usize,
    value: &str,
    is_quoted: bool,
) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    // #673: reject an out-of-bounds search_from before the value.is_empty() check below
    // (#673 M2: otherwise an empty value would return Some((search_from, search_from))).
    if search_from > bytes.len() {
        tracing::debug!(
            search_from,
            content_len = bytes.len(),
            "locate_value_span: search_from past end of content"
        );
        return None;
    }
    if value.is_empty() {
        // #1184: a quoted empty scalar (`""`/`''`) has no content bytes for a fallback
        // scan to anchor on, so the marker's own opening-quote-or-not shape is the only
        // signal available — advance past the quote when the raw marker lands on one.
        // Gated on `is_quoted` (a non-heuristic discriminator from the scanner's own
        // reported style — true only for `SingleQuoted`/`DoubleQuoted`, critic M2), not on
        // the marker byte alone and not on `!is_plain`: a `Plain` empty scalar's marker
        // points at the *next token*, not the value itself, and a `Literal`/`Folded`
        // block scalar's empty body is neither plain nor quoted — both cases have an
        // unrelated next token that can itself happen to be a quote byte, which
        // inferring "quoted" from `!is_plain` alone would incorrectly shift into.
        let corrected = if is_quoted {
            match bytes.get(search_from) {
                Some(b'"' | b'\'') => search_from + 1,
                _ => search_from,
            }
        } else {
            search_from
        };
        return Some((corrected, corrected));
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "every slice/index in this block is bounds-checked by the search_from <= \
                  bytes.len() guard above combined with each expression's own <=/.min(...) clamp"
    )]
    {
        if search_from + value.len() <= bytes.len()
            && &bytes[search_from..search_from + value.len()] == value.as_bytes()
        {
            return Some((search_from, search_from + value.len()));
        }
    }
    // #885: bound the window *before* searching for '\n', not after — searching the whole
    // remainder first reintroduces O(remaining-document-length) cost on one huge line even
    // though the resulting scan_end value is the same either way (min is order-independent).
    let window_end = bytes
        .len()
        .min(search_from.saturating_add(MAX_FALLBACK_SCAN_BYTES));
    #[expect(
        clippy::indexing_slicing,
        reason = "window_end = bytes.len().min(...), and search_from <= bytes.len() from the \
                  guard above, so bytes[search_from..window_end] is always in bounds"
    )]
    let scan_end = bytes[search_from..window_end]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(window_end, |p| search_from + p);
    #[expect(
        clippy::indexing_slicing,
        reason = "scan_end is derived from window_end or a position found within \
                  bytes[search_from..window_end], so it stays within [search_from, window_end]"
    )]
    let haystack = &bytes[search_from..scan_end];
    let needle = value.as_bytes();
    let found = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| (search_from + rel, search_from + rel + needle.len()));
    if found.is_none() {
        tracing::debug!(
            search_from,
            value_len = needle.len(),
            scan_bytes = scan_end - search_from,
            "locate_value_span: value not found within bounded fallback scan"
        );
    }
    found
}

/// Converts a byte span in `content` into an LSP [`Range`] via `table`.
///
/// `deps-gitlab-ci`'s `make_range` and `deps-github-actions`'s `make_range` closure each
/// defined this exact computation byte-for-byte identically before deps-lsp#908 extracted
/// it here. deps-lsp#927 later routed every other ecosystem crate's byte-span-to-`Range`
/// site through this same function: `deps-cargo`, `deps-pypi`, `deps-gradle`, and
/// `deps-nuget` each keep a thin local adapter for their own span shape (a
/// `toml_span::Span`, or a `(usize, usize)` tuple); `deps-swift` keeps its `make_range`
/// closure, which captures `content`/`line_table` to save two arguments across its ~15
/// call sites; `deps-bundler`, `deps-go`, `deps-maven`, `deps-deno`, and `deps-pypi`'s
/// `requirements.rs` call this directly at each bare inline site (`deps-deno` deleted its
/// own byte-identical `byte_range_to_lsp` rather than keep a pointless delegate); `deps-core`'s
/// own `json_ast` module calls it directly at two sites (`quoted_lsp_range`, plus
/// `dependency_position`'s `ObjectPropName::Word` arm). `deps-dart` is a full adopter as
/// well (see [`MarkedScalar::range`], added by deps-lsp#928) — it does not call this
/// function directly, but `MarkedScalar::range` does, on its behalf.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
///
/// let content = "uses: actions/checkout@v4\n";
/// let table = LineOffsetTable::new(content);
/// let range = byte_span_to_range(content, &table, 6, 26);
/// assert_eq!(range.start.line, 0);
/// assert_eq!(range.start.character, 6);
/// ```
#[must_use]
pub fn byte_span_to_range(
    content: &str,
    table: &LineOffsetTable,
    start: usize,
    end: usize,
) -> Range {
    Range::new(
        table.byte_offset_to_position(content, start),
        table.byte_offset_to_position(content, end),
    )
}

/// A YAML scalar captured directly from `yaml-rust2`'s event stream.
///
/// Holds the scalar's resolved text, its scalar style, and the scanner's own
/// marker — the shape all three `MarkedEventReceiver`-based ecosystem parsers
/// (`deps-dart`, `deps-github-actions`, `deps-gitlab-ci`) build from an
/// `Event::Scalar` payload before resolving a byte span for it.
///
/// Always built via [`MarkedScalar::new`] from a real `&Marker`, never hand-assembled
/// from raw numbers: `line` is 1-indexed and `col` a 0-indexed **char** count, matching
/// `yaml-rust2`'s own `Marker::line()`/`Marker::col()` (see [`marker_byte_offset`]'s
/// docs for why — #879/#882 both trace back to conflating this with a byte count).
///
/// The marker does not always come from the same event as the text/style: `deps-dart`'s
/// `on_alias` (key position) builds a `MarkedScalar` whose marker is the *alias*
/// occurrence's own site but whose text and style are the *anchor* definition's — this is
/// deliberate (the anchor's style is what `is_plain_null` already checked to accept the
/// value), and safe because [`MarkedScalar::span`]/[`MarkedScalar::range`] never read
/// `style`, only `text`/`line`/`col`.
#[derive(Debug, Clone)]
pub struct MarkedScalar {
    text: String,
    style: TScalarStyle,
    line: usize,
    col: usize,
}

impl MarkedScalar {
    /// Builds a `MarkedScalar` from an `Event::Scalar`'s resolved value/style and the
    /// scanner marker it fired at.
    ///
    /// `yaml-rust2`'s `Marker` has no public constructor — a real one is only ever
    /// obtained from a live `MarkedEventReceiver::on_event` callback, as shown here.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::MarkedScalar;
    /// use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
    /// use yaml_rust2::scanner::{Marker, TScalarStyle};
    ///
    /// struct Scalars(Vec<(String, TScalarStyle, Marker)>);
    /// impl MarkedEventReceiver for Scalars {
    ///     fn on_event(&mut self, event: Event, marker: Marker) {
    ///         if let Event::Scalar(value, style, ..) = event {
    ///             self.0.push((value, style, marker));
    ///         }
    ///     }
    /// }
    ///
    /// let mut receiver = Scalars(Vec::new());
    /// Parser::new_from_str("uses: v4\n")
    ///     .load(&mut receiver, false)
    ///     .unwrap();
    /// let (value, style, marker) = receiver.0[1].clone(); // the value scalar
    /// let scalar = MarkedScalar::new(value, style, &marker);
    /// assert_eq!(scalar.text(), "v4");
    /// assert!(scalar.is_plain());
    /// ```
    #[must_use]
    pub fn new(text: String, style: TScalarStyle, marker: &Marker) -> Self {
        Self {
            text,
            style,
            line: marker.line(),
            col: marker.col(),
        }
    }

    /// The scalar's resolved (dequoted) text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Consumes the scalar, returning its resolved text.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// The YAML scalar style (`Plain`, single/double-quoted, literal/folded block).
    #[must_use]
    pub const fn style(&self) -> TScalarStyle {
        self.style
    }

    /// Whether the scalar was written unquoted.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.style == TScalarStyle::Plain
    }

    /// Whether the scalar was written with an explicit quote style
    /// (`SingleQuoted`/`DoubleQuoted`).
    ///
    /// Deliberately not `!is_plain()` (critic M2 on #1184): a `Literal`/`Folded` block
    /// scalar (`ref: |`/`ref: >`) is neither plain nor quoted, and its marker has the
    /// same "points at the next token, not the value" shape as a `Plain` scalar's — so
    /// [`Self::span`]'s empty-value quote-correction must key on this method, not on the
    /// negation of [`Self::is_plain`].
    #[must_use]
    pub fn is_quoted(&self) -> bool {
        matches!(
            self.style,
            TScalarStyle::SingleQuoted | TScalarStyle::DoubleQuoted
        )
    }

    /// The scanner marker's 1-indexed line.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// The scanner marker's 0-indexed char column.
    #[must_use]
    pub const fn col(&self) -> usize {
        self.col
    }

    /// Resolves this scalar's **raw, untrimmed** byte span within `content`, via
    /// [`marker_byte_offset`] + [`locate_value_span`].
    ///
    /// This is the load-bearing primitive every caller needing a *sub*-span builds
    /// on: `deps-github-actions` needs `owner/repo@ref`'s ref sub-span
    /// (`span_start + before_at_len + 1`) and `deps-gitlab-ci` needs
    /// `component@version`'s name/version sub-spans (`raw_start + prefix.len()`), and
    /// both derive those from *this* span's start, never from a value this function
    /// re-trims itself.
    ///
    /// Deliberately does **not** trim leading/trailing whitespace off the located
    /// span — a caller with its own trim-aware offset arithmetic (`deps-github-actions`'s
    /// UTF-8-boundary guard for a quoted value with non-ASCII padding is the concrete
    /// case) depends on receiving the untrimmed span and re-anchoring its own
    /// downstream offsets to it; trimming here would silently desync that arithmetic.
    /// Returns `None` on the same misses [`locate_value_span`] does (e.g. a folded or
    /// multiline scalar it cannot locate within its bounded fallback scan).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{LineOffsetTable, MarkedScalar};
    /// use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
    /// use yaml_rust2::scanner::{Marker, TScalarStyle};
    ///
    /// struct Scalars(Vec<(String, TScalarStyle, Marker)>);
    /// impl MarkedEventReceiver for Scalars {
    ///     fn on_event(&mut self, event: Event, marker: Marker) {
    ///         if let Event::Scalar(value, style, ..) = event {
    ///             self.0.push((value, style, marker));
    ///         }
    ///     }
    /// }
    ///
    /// let content = "uses: actions/checkout@v4\n";
    /// let mut receiver = Scalars(Vec::new());
    /// Parser::new_from_str(content)
    ///     .load(&mut receiver, false)
    ///     .unwrap();
    /// let (value, style, marker) = receiver.0[1].clone(); // the value scalar
    /// let scalar = MarkedScalar::new(value, style, &marker);
    ///
    /// let table = LineOffsetTable::new(content);
    /// let (start, end) = scalar.span(content, &table).unwrap();
    /// assert_eq!(&content[start..end], "actions/checkout@v4");
    /// ```
    #[must_use]
    pub fn span(&self, content: &str, table: &LineOffsetTable) -> Option<(usize, usize)> {
        let start = marker_byte_offset(content, table, self.line, self.col);
        locate_value_span(content, start, &self.text, self.is_quoted())
    }

    /// Resolves this scalar's raw span (see [`MarkedScalar::span`]) into an LSP
    /// [`Range`] via [`byte_span_to_range`], or `None` on the same miss `span` can
    /// return.
    #[must_use]
    pub fn range(&self, content: &str, table: &LineOffsetTable) -> Option<Range> {
        self.span(content, table)
            .map(|(start, end)| byte_span_to_range(content, table, start, end))
    }
}

/// A successful static "pin to commit SHA" resolution: the dependency's display name, the
/// span of its current ref, and the commit-SHA replacement text for that span.
///
/// A named struct rather than a same-typed `(String, Range, String)` tuple (review finding
/// M3, #1138): `display_name` and `replacement` are both `String`, and a tuple return lets a
/// future [`ShaPinning`] implementor transpose them silently.
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedShaPin {
    /// The dependency's human-readable name, for the quickfix title ("Pin `{display_name}`
    /// to commit SHA").
    pub display_name: String,
    /// The span of the dependency's current ref — what the edit replaces.
    pub version_range: Range,
    /// The commit-SHA text (plus any ecosystem-specific trailing comment, e.g. GitHub
    /// Actions' `{sha} # {tag}`) to splice into `version_range`.
    pub replacement: String,
}

/// Resolves the *static* — warm-`TagIndex`-only, no live fetch — "pin a mutable ref to an
/// immutable commit SHA" quickfix shape.
///
/// Shared by every git-tags-datasource ecosystem (`deps-github-actions`'s `owner/repo@ref`,
/// `deps-gitlab-ci`'s `PinStyle::Tag` include) — see deps-lsp issue #1138. A resolution that
/// needs a live fetch instead of a warm tag index (e.g. GitLab's `component:`
/// `Latest`/`Partial` pin, resolved against a project's published releases) is out of this
/// trait's scope and stays ecosystem-specific.
#[cfg(feature = "lsp-responses")]
pub trait ShaPinning: Send + Sync {
    /// Attempts the static "pin to commit SHA" resolution for `dep`.
    ///
    /// Runs the eligibility check and `TagIndex` lookup in one step, since neither is
    /// meaningful without the other to this trait's callers.
    ///
    /// Returns a [`ResolvedShaPin`] on success. `None` if `dep` is not this ecosystem's own
    /// dependency type, is not a statically-pinnable occurrence (e.g. a mutable branch/SHA
    /// ref, or a non-editable alias token), has no ref span to anchor an edit on, or the
    /// `TagIndex` lookup misses (a registry fetch still in flight).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{ResolvedShaPin, ShaPinning};
    /// use deps_core::parser::DependencySource;
    /// use deps_core::position::Range;
    /// use deps_core::{Dependency, PackageName, VersionReq};
    /// use std::any::Any;
    ///
    /// struct MockDep {
    ///     name: PackageName,
    /// }
    ///
    /// impl Dependency for MockDep {
    ///     fn name(&self) -> &PackageName {
    ///         &self.name
    ///     }
    ///     fn name_range(&self) -> Range {
    ///         Range::default()
    ///     }
    ///     fn version_requirement(&self) -> Option<&VersionReq> {
    ///         None
    ///     }
    ///     fn version_range(&self) -> Option<Range> {
    ///         Some(Range::default())
    ///     }
    ///     fn source(&self) -> DependencySource {
    ///         DependencySource::Registry
    ///     }
    ///     fn as_any(&self) -> &dyn Any {
    ///         self
    ///     }
    /// }
    ///
    /// struct MockPinning;
    ///
    /// impl ShaPinning for MockPinning {
    ///     fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin> {
    ///         Some(ResolvedShaPin {
    ///             display_name: dep.name().as_str().to_string(),
    ///             version_range: dep.version_range()?,
    ///             replacement: "a".repeat(40),
    ///         })
    ///     }
    /// }
    ///
    /// let dep = MockDep { name: PackageName::new("owner/repo") };
    /// let resolved = MockPinning.resolve_static_sha_pin(&dep).unwrap();
    /// assert_eq!(resolved.display_name, "owner/repo");
    /// assert_eq!(resolved.replacement.len(), 40);
    /// ```
    fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin>;
}

/// Maximum character count of the dependency name interpolated into
/// [`build_sha_pin_action`]'s CodeAction title, before truncation with an ellipsis marker.
/// Mirrors `diagnostics::MAX_DIAGNOSTIC_NAME_CHARS`'s and each ecosystem's own
/// `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS`'s bound (#1252 critic follow-up C1): this is the
/// *primary* `PinStyle::Tag` quickfix title, shared by both `deps-github-actions` and
/// `deps-gitlab-ci`, so it needs the same cap as the diagnostic sinks it sits next to.
#[cfg(feature = "lsp-responses")]
const MAX_SHA_PIN_TITLE_NAME_CHARS: usize = 128;

/// Builds the "Pin `{name}` to commit SHA" [`CodeAction`] for the dependency at `position`.
///
/// The boilerplate `deps-github-actions`'s and `deps-gitlab-ci`'s own `build_sha_pin_action`
/// functions each re-derived byte-for-byte before deps-lsp#1138 moved it here: locate the
/// dependency at `position` through `formatter`'s shared
/// [`PackageRendering::is_position_on_dependency`](super::PackageRendering::is_position_on_dependency)
/// lookup, resolve it via [`ShaPinning::resolve_static_sha_pin`], and wrap the resulting edit
/// into a `WorkspaceEdit`-carrying quickfix tagged with `diagnostic_code` so a client can
/// later associate this action back to its diagnostic.
///
/// Takes a single `formatter: &F` bound by both [`EcosystemFormatter`] and [`ShaPinning`]
/// (review finding M4, #1138) rather than two separate parameters for the same value — every
/// real implementor is one type that implements both traits, and a two-parameter signature
/// let a caller pass mismatched formatters at the two call sites with no compile error.
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn build_sha_pin_action<F: EcosystemFormatter + ShaPinning>(
    parse_result: &dyn ParseResult,
    position: Position,
    uri: &url::Url,
    formatter: &F,
    diagnostic_code: &'static str,
) -> Option<CodeAction> {
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position.into()))?;
    let resolved = formatter.resolve_static_sha_pin(dep)?;
    let changes = single_file_edit(uri, resolved.version_range, resolved.replacement);
    let display_name = super::diagnostics::sanitize_and_truncate_for_diagnostic(
        &resolved.display_name,
        MAX_SHA_PIN_TITLE_NAME_CHARS,
    );
    Some(CodeAction {
        title: format!("Pin {display_name} to commit SHA"),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [diagnostic_code],
            "diagnostic_range": tower_lsp_server::ls_types::Range::from(resolved.version_range),
        })),
        ..Default::default()
    })
}

/// Builds the [`TextEdit`] for `dep` via [`ShaPinning::resolve_static_sha_pin`].
///
/// The single-dependency step `deps-github-actions`'s and `deps-gitlab-ci`'s own bulk "pin
/// all to SHA" collectors both build on, one dependency at a time, before their own
/// `dedup_overlapping_edits` pass.
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn sha_pin_text_edit(pinning: &impl ShaPinning, dep: &dyn Dependency) -> Option<TextEdit> {
    let resolved = pinning.resolve_static_sha_pin(dep)?;
    Some(TextEdit {
        range: resolved.version_range.into(),
        new_text: resolved.replacement,
    })
}

/// Inserts a `**Resolved**: `tag` (`sha…`)` line immediately after the shared hover's
/// `**Current**`/`**Requirement**` line (whichever is present), falling back to append.
///
/// Falls back to appending only if neither anchor is found — the byte-for-byte-identical
/// helper `deps-github-actions` and `deps-gitlab-ci` each defined locally, before
/// deps-lsp#1138 moved it here.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::splice_resolved_line;
///
/// let markdown = "**Current**: `v3`\n\nSome body.";
/// let sha = "a".repeat(40);
/// let out = splice_resolved_line(markdown, "v3.0.0", &sha);
/// assert!(out.contains("**Resolved**: `v3.0.0`"));
/// ```
// `pos`/`rel_end`/`insert_at` come from `find` of ASCII anchors (`"**Current**: "`,
// `"\n\n"`), so all are always char boundaries.
#[cfg(feature = "lsp-responses")]
#[expect(
    clippy::string_slice,
    reason = "sha.get(..7) already guards non-ASCII input; pos/rel_end/insert_at derive only \
              from find() of ASCII anchors, so every slice below is a char boundary"
)]
#[must_use]
pub fn splice_resolved_line(markdown: &str, resolved_tag: &str, sha: &str) -> String {
    let short_sha = sha.get(..7).unwrap_or(sha);
    let line = format!(
        "**Resolved**: {} ({})\n\n",
        markdown_code_span(resolved_tag),
        markdown_code_span(&format!("{short_sha}…"))
    );

    for anchor in ["**Current**: ", "**Requirement**: "] {
        if let Some(pos) = markdown.find(anchor)
            && let Some(rel_end) = markdown[pos..].find("\n\n")
        {
            let insert_at = pos + rel_end + 2;
            let mut out = String::with_capacity(markdown.len() + line.len());
            out.push_str(&markdown[..insert_at]);
            out.push_str(&line);
            out.push_str(&markdown[insert_at..]);
            return out;
        }
    }
    format!("{markdown}{line}")
}

#[cfg(test)]
#[expect(
    clippy::string_slice,
    reason = "fixtures are single-line ASCII literals with hand-computed byte offsets"
)]
mod tests {
    use super::*;

    #[test]
    fn test_is_full_sha_accepts_and_rejects() {
        assert!(is_full_sha(&"a".repeat(40)));
        assert!(!is_full_sha(&"a".repeat(39)));
        assert!(!is_full_sha(&"g".repeat(40)));
    }

    #[test]
    fn test_is_tag_shaped() {
        assert!(is_tag_shaped("v4"));
        assert!(is_tag_shaped("4.2.0"));
        assert!(!is_tag_shaped("main"));
        assert!(!is_tag_shaped(&"a".repeat(40)));
    }

    #[test]
    fn test_is_partial_semver_shaped_accepts_v_prefixed_at_any_precision() {
        assert!(is_partial_semver_shaped("v4"));
        assert!(is_partial_semver_shaped("v2.9"));
        assert!(is_partial_semver_shaped("v4.2.0"));
        assert!(is_partial_semver_shaped("v4.2.0-beta.1"));
        assert!(is_partial_semver_shaped("v4.2.0+build.5"));
        assert!(is_partial_semver_shaped("V4"));
    }

    #[test]
    fn test_is_partial_semver_shaped_accepts_dotted_without_v_prefix() {
        assert!(is_partial_semver_shaped("2.9"));
        assert!(is_partial_semver_shaped("4.2.0"));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_bare_unprefixed_integer() {
        // #907 review S1: a bare all-digit token (ticket number, date) is indistinguishable
        // from a version, so it must be rejected here unlike `is_tag_shaped`.
        assert!(!is_partial_semver_shaped("1234"));
        assert!(!is_partial_semver_shaped("20240501"));
        assert!(!is_partial_semver_shaped("0"));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_dash_separated_date_and_branch_names() {
        assert!(!is_partial_semver_shaped("2024-01-15"));
        assert!(!is_partial_semver_shaped("main"));
        assert!(!is_partial_semver_shaped(&"a".repeat(40)));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_too_many_components() {
        assert!(!is_partial_semver_shaped("v1.2.3.4"));
    }

    #[test]
    fn test_match_v_prefix_style() {
        assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
        assert_eq!(match_v_prefix_style("v4", "v5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "5.0.0"), "5.0.0");
    }

    #[test]
    fn test_locate_value_span_finds_value_within_fallback_bound() {
        let content = "prefix xxxxx actions/checkout@v4 suffix";
        let value = "actions/checkout@v4";
        let (start, end) = locate_value_span(content, 0, value, false).unwrap();
        assert_eq!(&content[start..end], value);
    }

    #[test]
    fn test_locate_value_span_out_of_bounds_search_from_rejected_even_with_empty_value() {
        // #673 M2: the `search_from > bytes.len()` guard must run before the
        // `value.is_empty()` early return, or this returned `Some((usize::MAX, usize::MAX))`.
        let content = "short";
        assert_eq!(locate_value_span(content, usize::MAX, "", false), None);
        assert_eq!(
            locate_value_span(content, content.len() + 1, "", false),
            None
        );
    }

    #[test]
    fn test_locate_value_span_empty_value_corrects_past_opening_double_quote() {
        // #1180: the raw marker for `pkg: ""` lands on the opening `"`, one byte before the
        // actual (empty) value slot between the quotes.
        let content = r#"pkg: """#;
        let quote_offset = content.find('"').unwrap();
        let (start, end) = locate_value_span(content, quote_offset, "", true).unwrap();
        assert_eq!(start, quote_offset + 1);
        assert_eq!(end, quote_offset + 1);
    }

    #[test]
    fn test_locate_value_span_empty_value_corrects_past_opening_single_quote() {
        let content = "ref: ''";
        let quote_offset = content.find('\'').unwrap();
        let (start, end) = locate_value_span(content, quote_offset, "", true).unwrap();
        assert_eq!(start, quote_offset + 1);
        assert_eq!(end, quote_offset + 1);
    }

    #[test]
    fn test_locate_value_span_empty_value_at_non_quote_position_is_unchanged() {
        // A plain (unquoted) empty value has no opening quote to correct past — the marker
        // already points at the right (empty) slot, e.g. `ref:` with nothing after it.
        let content = "ref: ";
        let end_offset = content.len();
        let (start, end) = locate_value_span(content, end_offset, "", false).unwrap();
        assert_eq!(start, end_offset);
        assert_eq!(end, end_offset);
    }

    #[test]
    fn test_locate_value_span_plain_empty_value_never_shifts_past_a_next_token_quote() {
        // #1184 Gap 1: for a Plain empty scalar the marker points at the *next token*,
        // not the value itself — if that next token happens to start with a quote byte,
        // `is_quoted: false` must still suppress the quote-correction, unlike the quoted
        // case above where the byte-at-marker really is the value's own opening quote.
        let content = "ref: \n\"next-token\"";
        let marker_offset = content.find('\n').unwrap() + 1;
        assert_eq!(content.as_bytes()[marker_offset], b'"');
        let (start, end) = locate_value_span(content, marker_offset, "", false).unwrap();
        assert_eq!(start, marker_offset);
        assert_eq!(end, marker_offset);
    }

    #[test]
    fn test_locate_value_span_literal_style_empty_value_never_shifts_past_a_next_token_quote() {
        // #1184 critic M2: a `Literal`/`Folded` block scalar's empty body is neither
        // `Plain` nor quoted — the old `!is_plain` gate would have wrongly performed the
        // quote-correction here (`is_plain()` is `false` for `Literal` too). `is_quoted`
        // must be keyed on the actual quote styles, not the negation of `is_plain`.
        let content = "ref: |\n\"next-token\"";
        let marker_offset = content.find('\n').unwrap() + 1;
        assert_eq!(content.as_bytes()[marker_offset], b'"');
        let (start, end) = locate_value_span(content, marker_offset, "", false).unwrap();
        assert_eq!(start, marker_offset);
        assert_eq!(end, marker_offset);
    }

    #[test]
    fn test_marked_scalar_span_quoted_empty_value_anchors_after_opening_quote() {
        // End-to-end regression for #1180: `MarkedScalar::span` (via `locate_value_span`)
        // must anchor a quoted empty scalar's span at the actual value slot, not the
        // opening quote one column early — reproduces deps-dart's `pkg: ""` and
        // deps-gitlab-ci's `ref: ""`.
        use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};

        struct Scalars(Vec<(String, TScalarStyle, Marker)>);
        impl MarkedEventReceiver for Scalars {
            fn on_event(&mut self, event: Event, marker: Marker) {
                if let Event::Scalar(value, style, ..) = event {
                    self.0.push((value, style, marker));
                }
            }
        }

        let content = "pkg: \"\"\n";
        let mut receiver = Scalars(Vec::new());
        Parser::new_from_str(content)
            .load(&mut receiver, false)
            .unwrap();
        // receiver.0[0] is the key scalar ("pkg"), receiver.0[1] is the value.
        let (value, style, marker) = receiver.0[1].clone();
        assert_eq!(value, "");
        let scalar = MarkedScalar::new(value, style, &marker);
        let table = LineOffsetTable::new(content);
        let (start, end) = scalar.span(content, &table).unwrap();
        let quote_offset = content.find("\"\"").unwrap();
        assert_eq!(
            (start, end),
            (quote_offset + 1, quote_offset + 1),
            "expected the empty value's span to anchor between the quotes, not on the \
             opening quote"
        );
    }

    #[test]
    fn test_marked_scalar_is_quoted_distinguishes_literal_from_plain_and_quoted() {
        // #1184 critic M2: `is_quoted()` must be `false` for `Literal`/`Folded`, same as
        // `Plain` — not the negation of `is_plain()`, which was `true` for `Literal` too.
        use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};

        struct Scalars(Vec<(String, TScalarStyle, Marker)>);
        impl MarkedEventReceiver for Scalars {
            fn on_event(&mut self, event: Event, marker: Marker) {
                if let Event::Scalar(value, style, ..) = event {
                    self.0.push((value, style, marker));
                }
            }
        }

        let content = "ref: |\n";
        let mut receiver = Scalars(Vec::new());
        Parser::new_from_str(content)
            .load(&mut receiver, false)
            .unwrap();
        let (value, style, marker) = receiver.0[1].clone();
        assert_eq!(style, TScalarStyle::Literal);
        let scalar = MarkedScalar::new(value, style, &marker);
        assert!(!scalar.is_plain());
        assert!(
            !scalar.is_quoted(),
            "a Literal block scalar is neither plain nor quoted"
        );
    }

    #[test]
    fn test_locate_value_span_gives_up_beyond_fallback_bound_instead_of_hanging() {
        let filler = "x".repeat(MAX_FALLBACK_SCAN_BYTES + 100);
        let value = "actions/checkout@v4";
        let content = format!("{filler}{value}");
        assert_eq!(locate_value_span(&content, 0, value, false), None);
    }

    #[test]
    fn test_locate_value_span_bounded_scan_stays_fast_on_a_huge_line() {
        // Regression guard (security S-2): a several-megabyte single-line haystack must
        // resolve in milliseconds, not minutes, once the scan is bounded.
        let filler = "y".repeat(6 * 1024 * 1024);
        let value = "not-present-in-filler@v4";
        let content = format!("{filler}\n");
        let start = std::time::Instant::now();
        let result = locate_value_span(&content, 0, value, false);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "locate_value_span took {:?}, expected a bounded scan to finish in well under 1s",
            start.elapsed()
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_locate_value_span_many_fallback_scans_on_one_huge_line_stay_bounded() {
        // Regression for #885 (S2): each fallback-triggering call on one huge physical line
        // used to cost O(remaining-document-length) despite the cap. Simulates many
        // fallback-forcing lookups on one multi-megabyte single-line manifest.
        let filler_segment = "z".repeat(64);
        let mut content = String::new();
        let mut offsets = Vec::new();
        for _ in 0..2000 {
            offsets.push(content.len());
            content.push_str(&filler_segment);
        }
        content.push_str(&"w".repeat(8 * 1024 * 1024));
        let value = "actions/checkout@v4";

        let start = std::time::Instant::now();
        for &offset in &offsets {
            let _ = locate_value_span(&content, offset, value, false);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "{} locate_value_span fallback calls against an 8MB-tail single line took \
             {elapsed:?}; expected the pre-bound window to make each call's cost \
             independent of the trailing content size",
            offsets.len()
        );
    }

    #[test]
    fn test_marker_byte_offset_ascii() {
        let content = "hello\nworld";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 1, 0), 0);
        assert_eq!(marker_byte_offset(content, &table, 2, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_multibyte() {
        let content = "\u{3000}a\nb";
        let table = LineOffsetTable::new(content);
        // U+3000 is 3 bytes; the second char ('a') on line 1 starts at byte 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 1), 3);
        // Line 2 ('b') starts right after the '\n'.
        assert_eq!(marker_byte_offset(content, &table, 2, 0), 5);
    }

    #[test]
    fn test_marker_byte_offset_block_scalar_drift_regression() {
        // #879: a non-ASCII char inside a `|` block scalar must not desync the byte offset
        // resolved for a later scalar — reproduces the yaml-rust2 Marker::index() drift.
        let content = "run: |\n  echo \u{2014} hi\nuses: actions/checkout@v4\n";
        let table = LineOffsetTable::new(content);
        // Line 3, col 6 is where "actions/checkout@v4" starts (after "uses: ").
        let expected = content.find("actions/checkout@v4").unwrap();
        assert_eq!(marker_byte_offset(content, &table, 3, 6), expected);
    }

    #[test]
    fn test_marker_byte_offset_line_past_end_returns_content_len() {
        let content = "hello";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 5, 0), content.len());
    }

    #[test]
    fn test_marker_byte_offset_multiple_multibyte_chars_before_target_col() {
        // Each multi-byte char before the target col must count as one *char*, not its byte
        // length, when walking to `col` (#879's failure mode, direct on the resolver).
        let content = "\u{2014}\u{2014}\u{3000}target";
        let table = LineOffsetTable::new(content);
        // 3 leading multi-byte chars (3 + 3 + 3 = 9 bytes), then "target" starts at char
        // column 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_col_past_end_of_line_clamps_to_line_end() {
        let content = "ab\ncd";
        let table = LineOffsetTable::new(content);
        // Line 1 ("ab") has only 2 chars; a col past that clamps to the line span's byte
        // end (`table.line_start(1)`, i.e. right after the '\n', where the next line
        // starts), rather than panicking or reading past that into line 2's content.
        assert_eq!(marker_byte_offset(content, &table, 1, 100), 3);
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_matches_char_indices_result() {
        // Differential test: the `line_is_ascii` fast path must agree with the pre-S1
        // general `char_indices().nth(col)` walk (reimplemented here) for every column on
        // an ASCII line, including overshoot — the desync class S1's fix could introduce.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "uses: actions/checkout@v4\nref: v1.0.0\n";
        let table = LineOffsetTable::new(content);
        for col in 0..=35 {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "ascii fast path desynced from the general char_indices() walk at col {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_stays_linear_on_a_huge_single_line() {
        // Regression guard (S1, impl-critic, #879 follow-up): without `line_is_ascii`,
        // this was O(line length) per call, reintroducing the O(n^2) shape.
        let filler = "x".repeat(6 * 1024 * 1024);
        let table = LineOffsetTable::new(&filler);
        let start = std::time::Instant::now();
        for col in (0..filler.len()).step_by(filler.len() / 5000) {
            assert_eq!(marker_byte_offset(&filler, &table, 1, col), col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge ASCII line, expected well \
             under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_cache_stays_fast_on_a_huge_single_line() {
        // Regression guard for #882: without the per-line char-boundary cache, N lookups on
        // the same non-ASCII line cost O(N x line length) — ~500ms for 5000 lookups on a
        // several-hundred-KB line in a release build.
        let filler = "x".repeat(200 * 1024);
        let content = format!("{filler}\u{2014}{filler}");
        let table = LineOffsetTable::new(&content);
        let char_count = content.chars().count();
        let start = std::time::Instant::now();
        for col in (0..char_count).step_by((char_count / 5000).max(1)) {
            let _ = marker_byte_offset(&content, &table, 1, col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge non-ASCII line, expected \
             well under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_cache_matches_char_indices_result() {
        // Differential test: the cached char-boundary path must agree with a plain
        // reimplemented `char_indices().nth(col)` walk for every column on a non-ASCII line —
        // the exact class of desync a caching bug could silently introduce.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "\u{1f680}rocket \u{2014} emoji then em dash \u{3000} and more";
        let table = LineOffsetTable::new(content);
        for col in 0..=(content.chars().count() + 5) {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "cached non-ASCII path desynced from the general char_indices() walk at col \
                 {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_multiple_non_ascii_lines_cache_isolation() {
        // Coverage gap flagged by #882 review: the per-line cache must resolve two or more
        // non-ASCII lines independently regardless of query order, with no cross-line leak.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "ascii only\n\u{2014}em dash line\n\u{1f680}rocket \u{3000}ideographic line\nascii again";
        let table = LineOffsetTable::new(content);

        // Query line 3 first, then line 2, then re-query line 3 and line 2 — deliberately out
        // of line order and with a repeat, to catch any cross-line contamination.
        let cases: &[(usize, usize)] = &[(3, 5), (2, 2), (3, 0), (2, 5), (3, 8), (2, 0)];
        for &(line, col) in cases {
            assert_eq!(
                marker_byte_offset(content, &table, line, col),
                slow_path(content, &table, line, col),
                "line {line} col {col} desynced after interleaved multi-line lookups"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_still_correct_without_fast_path() {
        // The fast path must only trigger for a genuinely ASCII line; a non-ASCII line still
        // takes the O(line) `char_indices()` walk, unchanged from before S1.
        let content = "\u{1f680}rocket \u{2014} emoji then em dash";
        let table = LineOffsetTable::new(content);
        let expected = content.char_indices().nth(3).unwrap().0;
        assert_eq!(marker_byte_offset(content, &table, 1, 3), expected);
    }

    #[test]
    fn test_marker_byte_offset_lone_cr_document_documented_limitation() {
        // S2 (impl-critic, #879 follow-up): a bare-`\r` document is out of scope per the
        // "Line-ending assumption" doc section, so this falls back to `content.len()`.
        // Locks in the documented behavior, not asserting it is desirable.
        let content = "on: push\rjobs:\r  build:\r    steps:\r      - uses: actions/checkout@v4\r";
        let table = LineOffsetTable::new(content);
        // yaml-rust2 would report line 5 for the `uses:` value here; only line 1 exists in
        // the table since it never splits on a lone `\r`.
        assert_eq!(marker_byte_offset(content, &table, 5, 14), content.len());
    }

    // --- #1138 review M5: direct coverage for `build_sha_pin_action`/`sha_pin_text_edit`,
    // which previously had only indirect coverage via ecosystem-crate wrapper tests.

    #[cfg(feature = "lsp-responses")]
    use crate::lsp_helpers::test_support::MockFormatter;
    #[cfg(feature = "lsp-responses")]
    use crate::position::Position as CorePosition;
    #[cfg(feature = "lsp-responses")]
    use crate::{PackageName, VersionReq};

    /// Resolves a dependency named `"resolvable"` to a fixed SHA; declines everything else
    /// — the minimal [`ShaPinning`] fixture these tests need, layered onto the shared
    /// [`MockFormatter`] fixture (already implements every [`EcosystemFormatter`] sub-trait)
    /// rather than hand-rolling a second formatter mock.
    #[cfg(feature = "lsp-responses")]
    impl ShaPinning for MockFormatter {
        fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin> {
            if dep.name().as_str() != "resolvable" {
                return None;
            }
            Some(ResolvedShaPin {
                display_name: dep.name().as_str().to_string(),
                version_range: dep.version_range()?,
                replacement: "a".repeat(40),
            })
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "fixed short ASCII test-fixture names never approach u32::MAX"
    )]
    fn sha_pin_test_dep(name: &str) -> crate::lsp_helpers::test_support::MockDep {
        let range = Range::new(
            CorePosition::new(0, 6),
            CorePosition::new(0, 6 + name.len() as u32),
        );
        crate::lsp_helpers::test_support::MockDep {
            name: PackageName::new(name),
            version_req: VersionReq::new("v1"),
            version_range: range,
            name_range: range,
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_sha_pin_action_resolves_at_position() {
        let dep = sha_pin_test_dep("resolvable");
        let uri = crate::test_util::test_uri("/repo/manifest.yml");
        let parse_result = crate::lsp_helpers::test_support::MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };
        let position = Position {
            line: 0,
            character: 7,
        };

        let action = build_sha_pin_action(
            &parse_result,
            position,
            &uri,
            &MockFormatter,
            "TEST_DIAGNOSTIC_CODE",
        )
        .expect("resolvable dependency at position must produce a quickfix");

        assert_eq!(action.title, "Pin resolvable to commit SHA");
        let edits = action
            .edit
            .expect("quickfix must carry a WorkspaceEdit")
            .changes
            .expect("WorkspaceEdit must carry changes");
        let text_edits = edits.values().next().expect("one file's edits");
        assert_eq!(text_edits.len(), 1);
        assert_eq!(text_edits[0].new_text, "a".repeat(40));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_sha_pin_action_none_when_pinning_declines() {
        let dep = sha_pin_test_dep("not-resolvable");
        let uri = crate::test_util::test_uri("/repo/manifest.yml");
        let parse_result = crate::lsp_helpers::test_support::MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };
        let position = Position {
            line: 0,
            character: 7,
        };

        assert!(
            build_sha_pin_action(
                &parse_result,
                position,
                &uri,
                &MockFormatter,
                "TEST_DIAGNOSTIC_CODE",
            )
            .is_none()
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_sha_pin_action_none_when_position_off_dependency() {
        let dep = sha_pin_test_dep("resolvable");
        let uri = crate::test_util::test_uri("/repo/manifest.yml");
        let parse_result = crate::lsp_helpers::test_support::MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };
        let position = Position {
            line: 5,
            character: 0,
        };

        assert!(
            build_sha_pin_action(
                &parse_result,
                position,
                &uri,
                &MockFormatter,
                "TEST_DIAGNOSTIC_CODE",
            )
            .is_none()
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_sha_pin_text_edit_resolves() {
        let dep = sha_pin_test_dep("resolvable");
        let edit =
            sha_pin_text_edit(&MockFormatter, &dep).expect("resolvable dependency must resolve");
        assert_eq!(edit.new_text, "a".repeat(40));
        assert_eq!(edit.range, dep.version_range.into());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_sha_pin_text_edit_none_when_pinning_declines() {
        let dep = sha_pin_test_dep("not-resolvable");
        assert!(sha_pin_text_edit(&MockFormatter, &dep).is_none());
    }
}

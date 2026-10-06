//! Trailing `# tag` comments on full-SHA pins, shared by every git-tags-datasource ecosystem
//! (GitHub Actions, GitLab CI).
//!
//! A SHA pin conventionally carries the tag it was cut from (`uses: a/b@<sha> # v4.2.0`).
//! This module owns the whole lifecycle of that comment so the ecosystems cannot diverge on
//! it: reading it from the source line ([`read_sha_pin_tail`]), checking it against the
//! repository's [`TagIndex`] ([`CommentCheck`]), rewriting the pin on update
//! ([`sha_pin_rewrite`]) and reporting a mismatch ([`sha_comment_mismatch_diagnostic`]).

use std::fmt;

use yaml_rust2::scanner::TScalarStyle;

use super::git_ref::SHA_LEN;
use super::{
    CommitSha, LineOffsetTable, MAX_DIAGNOSTIC_VALUE_CHARS, PinResolution, TagIndex,
    byte_span_to_range, extends_tag, is_partial_semver_shaped, markdown_code_span,
    position_in_range, redact_name_for_diagnostic, sanitize_and_truncate_for_diagnostic, short_sha,
};
use crate::diagnostic::{Diagnostic, Severity};
use crate::github::normalize_tag;
use crate::position::{Position, Range};
use crate::{ConcreteVersion, PackageName};

#[cfg(feature = "lsp-responses")]
use super::single_file_edit;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, WorkspaceEdit};

/// Stable [`Diagnostic::code`] of the SHA-comment-mismatch diagnostic (issue #1722), shared
/// by every ecosystem that emits it.
///
/// Flags a SHA-pinned ref whose trailing `# vX.Y.Z` comment names a tag that is provably not
/// the pinned commit's tag, a supply-chain signal distinct from the outdated check.
pub const SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE: &str = "sha-comment-mismatch";

/// Upper bound, in bytes past a ref's end, on how far the tail scan looks ahead on the ref's
/// physical line (issue #885).
///
/// Separate from [`super::MAX_FALLBACK_SCAN_BYTES`]: that bounds a byte-offset correction
/// with a different cost profile. Sized so realistic inline comments are never truncated
/// while one adversarial line stays a constant cost per ref.
const REST_OF_LINE_WINDOW_BYTES: usize = 4096;

/// A validated version-shaped token a human wrote after the `#` of a SHA pin comment.
///
/// Accepts [`is_partial_semver_shaped`] text (`v4`, `v4.2`, `v4.2.0`) without whitespace,
/// control characters or `#`. Text read from a manifest may carry a non-ASCII suffix
/// (`v4-β`); [`sha_pin_rewrite`] only writes a tag that is printable ASCII.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::CommentTag;
///
/// assert_eq!(CommentTag::parse("v4.2.0").unwrap().as_str(), "v4.2.0");
/// assert!(CommentTag::parse("stable").is_none());
/// assert!(CommentTag::parse("1234").is_none());
/// assert!(CommentTag::parse("v1-a\nb").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentTag(String);

impl CommentTag {
    /// Parses `text` as a comment tag, `None` when it is not version-shaped or contains
    /// whitespace, control characters or `#`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let safe = !text
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '#');
        (safe && is_partial_semver_shaped(text)).then(|| Self(text.to_string()))
    }

    /// Whether the tag is a full `major.minor.patch` version (`v4.2.0`, `4.2.0-rc.1`), as
    /// opposed to a moving alias such as `v4` or `v4.2`.
    ///
    /// Only a full version is a claim about one commit; an alias legitimately drifts, so it can
    /// never be contradicted by the tag index. The index matches such a comment by version, so
    /// `# 4.3.1` is checked against the tag `v4.3.1` (a listed tag is required; a version the
    /// index does not list stays unverifiable).
    #[must_use]
    pub(crate) fn is_full_version(&self) -> bool {
        semver::Version::parse(normalize_tag(&self.0)).is_ok()
    }

    fn is_printable_ascii(&self) -> bool {
        self.0.chars().all(|c| c.is_ascii_graphic())
    }

    /// The tag text, verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommentTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delimiter {
    DoubleQuote,
    SingleQuote,
    Space,
    Tab,
    CloseBrace,
}

impl Delimiter {
    const fn as_char(self) -> char {
        match self {
            Self::DoubleQuote => '"',
            Self::SingleQuote => '\'',
            Self::Space => ' ',
            Self::Tab => '\t',
            Self::CloseBrace => '}',
        }
    }

    const fn blank(c: char) -> Option<Self> {
        match c {
            ' ' => Some(Self::Space),
            '\t' => Some(Self::Tab),
            _ => None,
        }
    }
}

/// The closing quote and flow-mapping `}` between a full-SHA ref and its `# tag` comment.
///
/// For instance the closing `"` of `uses: "a/b@<sha>" # v4`, or the `}` of
/// `{uses: a/b@<sha>} # v4`. Blanks before the `}` (`{ uses: a/b@<sha> } # v4`) are kept.
///
/// Non-empty only for a pin whose comment was read past those delimiters; every SHA-comment
/// rewrite re-emits them verbatim so the surrounding quote or flow mapping stays balanced.
/// At most one `}` is accepted: further closers end an outer collection, where a trailing
/// comment cannot be attributed to this ref. Restricted by construction to ASCII characters,
/// so its byte length equals its column width.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::ClosingDelimiters;
///
/// let none = ClosingDelimiters::default();
/// assert!(none.is_empty());
/// assert_eq!(none.byte_len(), 0);
/// assert_eq!(none.to_string(), "");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosingDelimiters(Vec<Delimiter>);

impl ClosingDelimiters {
    /// Parses the delimiters at the start of `tail` (the source text after the ref).
    ///
    /// A quoted scalar requires its own closing quote first; then blanks followed by one
    /// flow-mapping `}` may follow. Blanks not followed by `}` are not consumed, and block
    /// scalars or any other tail shape yield an empty value.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::ClosingDelimiters;
    /// use yaml_rust2::scanner::TScalarStyle;
    ///
    /// let closers = ClosingDelimiters::parse("\" # v4", TScalarStyle::DoubleQuoted);
    /// assert_eq!(closers.to_string(), "\"");
    /// assert!(ClosingDelimiters::parse(" # v4", TScalarStyle::Plain).is_empty());
    /// ```
    #[must_use]
    pub fn parse(tail: &str, style: TScalarStyle) -> Self {
        let opening = match style {
            TScalarStyle::Plain => None,
            TScalarStyle::SingleQuoted => Some(Delimiter::SingleQuote),
            TScalarStyle::DoubleQuoted => Some(Delimiter::DoubleQuote),
            TScalarStyle::Literal | TScalarStyle::Folded => return Self::default(),
        };
        let mut chars = tail.chars();
        let mut delimiters = Vec::new();
        if let Some(quote) = opening {
            if chars.next() != Some(quote.as_char()) {
                return Self::default();
            }
            delimiters.push(quote);
        }
        let rest = chars.as_str();
        let blanks: Vec<Delimiter> = rest.chars().map_while(Delimiter::blank).collect();
        if rest.chars().nth(blanks.len()) == Some(Delimiter::CloseBrace.as_char()) {
            delimiters.extend(blanks);
            delimiters.push(Delimiter::CloseBrace);
        }
        Self(delimiters)
    }

    /// Whether no delimiter sits between the ref and its comment.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length in bytes (equal to the column width, all delimiters being ASCII).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for ClosingDelimiters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|d| fmt::Write::write_char(f, d.as_char()))
    }
}

/// What follows a SHA pin comment's tag token on its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentRemainder {
    /// Nothing but whitespace, seen through the end of the line.
    Empty,
    /// More comment text (`# v1.0.0 pinned for CVE`), or an unexamined line tail.
    Text,
}

/// A SHA pin's trailing comment: the tag it names and the closers read past to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShaPinComment {
    /// The tag the comment names.
    pub tag: CommentTag,
    /// LSP range of the tag token alone, excluding the `#` and surrounding blanks.
    pub tag_range: Range,
    /// The closing quote/flow `}` between the SHA and the `#`.
    pub closing: ClosingDelimiters,
    /// What follows the tag token; the pin's range ends at the token, so a rewrite that
    /// removes the `#` must know whether comment words would be left outside it.
    pub remainder: CommentRemainder,
}

impl ShaPinComment {
    /// A comment naming `tag` at `tag_range` after `closing`, assumed to be followed by more
    /// text (the conservative choice, see [`CommentRemainder::Text`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{ClosingDelimiters, CommentTag, ShaPinComment};
    /// use deps_core::position::{Position, Range};
    ///
    /// let range = Range::new(Position::new(0, 47), Position::new(0, 53));
    /// let comment = ShaPinComment::new(
    ///     CommentTag::parse("v4.2.0").unwrap(),
    ///     ClosingDelimiters::default(),
    ///     range,
    /// );
    /// assert_eq!(comment.tag_range, range);
    /// ```
    #[must_use]
    pub const fn new(tag: CommentTag, closing: ClosingDelimiters, tag_range: Range) -> Self {
        Self {
            tag,
            tag_range,
            closing,
            remainder: CommentRemainder::Text,
        }
    }

    /// Replaces the recorded [`CommentRemainder`].
    #[must_use]
    pub const fn with_remainder(mut self, remainder: CommentRemainder) -> Self {
        self.remainder = remainder;
        self
    }
}

/// Whether a SHA pin without a comment may gain one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentSlot {
    /// A `# tag` can be appended right after the SHA: a plain scalar with nothing but
    /// whitespace or a YAML comment after it on the line.
    Appendable,
    /// Appending would corrupt the document: the SHA is quoted (`#` would land inside the
    /// string, #473), shares its line with flow content a comment would swallow (#633/#898),
    /// or sits in a form that never carries a comment (an alias).
    Unavailable,
}

/// What follows a full SHA on its source line, as far as a rewrite is concerned.
///
/// Replaces a loose `comment_tag` + `closing_delimiters` + "plain and last on line" triple
/// with the only combinations that can occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaPinTail {
    /// A trailing comment names a tag.
    Commented(ShaPinComment),
    /// No comment; `CommentSlot` says whether one may be added.
    Bare(CommentSlot),
}

impl ShaPinTail {
    /// The trailing comment, if any.
    #[must_use]
    pub const fn comment(&self) -> Option<&ShaPinComment> {
        match self {
            Self::Commented(comment) => Some(comment),
            Self::Bare(_) => None,
        }
    }
}

/// A [`ShaPinTail`] together with where the pin's text ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShaPinTailRead {
    /// What follows the SHA.
    pub tail: ShaPinTail,
    /// Byte offset where the pin's text ends: the end of the comment token for a
    /// [`ShaPinTail::Commented`] tail, the end of the SHA otherwise.
    pub range_end: usize,
}

/// Whether the bounded rest-of-line window covers the ref's entire physical line or was cut
/// short before reaching the real end-of-line content.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowCoverage {
    FullLine,
    Truncated,
}

/// The source text after `ref_end` on its line, capped at [`REST_OF_LINE_WINDOW_BYTES`].
///
/// `line` is 1-indexed. O(1) line-end lookup through `line_table` instead of an unbounded
/// `find('\n')` scan (issue #885).
fn rest_of_line<'a>(
    content: &'a str,
    line_table: &LineOffsetTable,
    ref_end: usize,
    line: usize,
) -> (&'a str, WindowCoverage) {
    let next_line_start = line_table.line_start(line).unwrap_or(content.len());
    let line_end = match next_line_start.checked_sub(1) {
        Some(i) if content.as_bytes().get(i) == Some(&b'\n') => i,
        _ => next_line_start,
    };
    let desynced = line_end < ref_end;
    if desynced {
        tracing::debug!(
            ref_end,
            line_end,
            line,
            "line_table line_end is before ref_end; treating the rest-of-line window as truncated"
        );
    }
    let capped_end = ref_end
        .saturating_add(REST_OF_LINE_WINDOW_BYTES)
        .min(line_end);
    let coverage = if desynced || capped_end < line_end {
        WindowCoverage::Truncated
    } else {
        WindowCoverage::FullLine
    };
    let capped_end = content.floor_char_boundary(capped_end).max(ref_end);
    let rest = content.get(ref_end..capped_end).unwrap_or_default();
    (rest, coverage)
}

/// Whether nothing unsafe to overwrite follows on the line: only whitespace, or a
/// whitespace-preceded YAML comment, all the way to the end.
///
/// A found `#` or non-whitespace byte is a definitive answer whatever `window` says; an
/// all-whitespace window proves the line is clear only when it is [`WindowCoverage::FullLine`].
fn is_last_token_on_line(rest: &str, window: WindowCoverage) -> bool {
    let mut previous_is_blank = false;
    for b in rest.bytes() {
        if b == b'#' && previous_is_blank {
            return true;
        }
        if !b.is_ascii_whitespace() {
            return false;
        }
        previous_is_blank = true;
    }
    window == WindowCoverage::FullLine
}

/// The first whitespace-delimited token after a whitespace-preceded `#` in `rest`, as a
/// [`CommentTag`], with the byte offset in `rest` where the token ends.
///
/// A token that runs to the end of a [`WindowCoverage::Truncated`] window has an unknown
/// true extent (`v4.2.100` cut to `v4.2.10` still looks valid) and is rejected.
fn extract_comment_tag(rest: &str, window: WindowCoverage) -> Option<(CommentTag, usize)> {
    let mut previous_is_blank = false;
    let hash = rest.bytes().position(|b| {
        let found = b == b'#' && previous_is_blank;
        previous_is_blank = b.is_ascii_whitespace();
        found
    })?;
    let after_hash = rest.get(hash + 1..)?;
    let after_ws = after_hash.trim_start();
    let ws_len = after_hash.len() - after_ws.len();
    let terminator = after_ws.find(char::is_whitespace);
    if terminator.is_none() && window == WindowCoverage::Truncated {
        return None;
    }
    let token_len = terminator.unwrap_or(after_ws.len());
    let tag = CommentTag::parse(after_ws.get(..token_len)?)?;
    Some((tag, hash + 1 + ws_len + token_len))
}

/// Whether nothing but whitespace or a YAML comment follows the ref at `ref_end` on its
/// 1-indexed `line`.
///
/// A step written in YAML flow style (`{uses: a/b@v4, with: {x: 1}}`) has real content after
/// the ref that a trailing `# tag` would swallow, so an edit that appends a comment must
/// check this first (#633).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, ref_is_last_on_line};
///
/// let content = "ref: abc # note\n";
/// let table = LineOffsetTable::new(content);
/// assert!(ref_is_last_on_line(content, &table, 8, 1));
/// let flow = "{ref: abc, x: 1}\n";
/// assert!(!ref_is_last_on_line(flow, &LineOffsetTable::new(flow), 9, 1));
/// ```
#[must_use]
pub fn ref_is_last_on_line(
    content: &str,
    line_table: &LineOffsetTable,
    ref_end: usize,
    line: usize,
) -> bool {
    let (rest, window) = rest_of_line(content, line_table, ref_end, line);
    is_last_token_on_line(rest, window)
}

fn comment_remainder(rest: &str, token_end: usize, window: WindowCoverage) -> CommentRemainder {
    let blank = rest
        .get(token_end..)
        .is_some_and(|after| after.chars().all(char::is_whitespace));
    if blank && window == WindowCoverage::FullLine {
        CommentRemainder::Empty
    } else {
        CommentRemainder::Text
    }
}

fn comment_slot(is_plain_scalar: bool, is_last_on_line: bool) -> CommentSlot {
    if is_plain_scalar && is_last_on_line {
        CommentSlot::Appendable
    } else {
        CommentSlot::Unavailable
    }
}

/// Whether a `# tag` comment may be appended after a ref ending at `ref_end` on its
/// 1-indexed `line`: [`CommentSlot::Appendable`] only for a plain scalar that is last on its
/// line.
///
/// The same rule [`read_sha_pin_tail`] applies to a SHA pin without a comment, exposed for a
/// ref that is not yet a SHA (a tag a quickfix is about to convert to one).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommentSlot, LineOffsetTable, comment_slot_after};
///
/// let content = "ref: v4\n";
/// let table = LineOffsetTable::new(content);
/// assert_eq!(comment_slot_after(content, &table, 7, 1, true), CommentSlot::Appendable);
/// assert_eq!(comment_slot_after(content, &table, 7, 1, false), CommentSlot::Unavailable);
/// let flow = "{ref: v4, x: 1}\n";
/// let table = LineOffsetTable::new(flow);
/// assert_eq!(comment_slot_after(flow, &table, 8, 1, true), CommentSlot::Unavailable);
/// ```
#[must_use]
pub fn comment_slot_after(
    content: &str,
    line_table: &LineOffsetTable,
    ref_end: usize,
    line: usize,
    is_plain_scalar: bool,
) -> CommentSlot {
    comment_slot(
        is_plain_scalar,
        ref_is_last_on_line(content, line_table, ref_end, line),
    )
}

/// Reads what follows a full SHA ending at `ref_end` on its 1-indexed `line`.
///
/// A comment is read only when nothing but closing delimiters sits between the SHA and the
/// `#` and nothing else follows on the line, because the comment of a ref cannot be told
/// from an unrelated later token on a flow-style line (#898). Without a comment the tail is
/// [`CommentSlot::Appendable`] only for a plain scalar that is last on its line.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, ShaPinTail, read_sha_pin_tail};
/// use yaml_rust2::scanner::TScalarStyle;
///
/// let sha = "a".repeat(40);
/// let content = format!("ref: {sha} # v4.2.0\n");
/// let table = LineOffsetTable::new(&content);
/// let read = read_sha_pin_tail(&content, &table, 5 + 40, 1, TScalarStyle::Plain, true);
/// assert_eq!(read.tail.comment().unwrap().tag.as_str(), "v4.2.0");
/// assert_eq!(read.range_end, content.trim_end().len());
/// ```
#[must_use]
pub fn read_sha_pin_tail(
    content: &str,
    line_table: &LineOffsetTable,
    ref_end: usize,
    line: usize,
    style: TScalarStyle,
    is_plain_scalar: bool,
) -> ShaPinTailRead {
    let (rest, window) = rest_of_line(content, line_table, ref_end, line);
    let is_last = is_last_token_on_line(rest, window);
    let closing = ClosingDelimiters::parse(rest, style);
    let closer_len = closing.byte_len();
    let comment = if closing.is_empty() {
        (is_plain_scalar && is_last)
            .then(|| extract_comment_tag(rest, window))
            .flatten()
    } else {
        rest.get(closer_len..).and_then(|tail| {
            is_last_token_on_line(tail, window)
                .then(|| extract_comment_tag(tail, window))
                .flatten()
                .map(|(tag, end)| (tag, closer_len + end))
        })
    };
    match comment {
        Some((tag, token_end)) => {
            let end = ref_end + token_end;
            let tag_range = byte_span_to_range(content, line_table, end - tag.as_str().len(), end);
            ShaPinTailRead {
                tail: ShaPinTail::Commented(
                    ShaPinComment::new(tag, closing, tag_range)
                        .with_remainder(comment_remainder(rest, token_end, window)),
                ),
                range_end: end,
            }
        }
        None => ShaPinTailRead {
            tail: ShaPinTail::Bare(comment_slot(is_plain_scalar, is_last)),
            range_end: ref_end,
        },
    }
}

/// The text that replaces a SHA pin's range (SHA plus any comment) when the pin moves to
/// `sha`, the commit of release `target`.
///
/// The one rewrite rule for every ecosystem:
/// - [`ShaPinTail::Commented`]: `{sha}{closers} # {target}`, the closing quote/`}` re-emitted;
/// - [`CommentSlot::Appendable`]: `{sha} # {target}`;
/// - [`CommentSlot::Unavailable`]: the bare `{sha}`.
///
/// A comment is written only when `target` is a [`CommentTag`]. A release name that is not
/// version-shaped (`stable`) would otherwise be written as a comment the next parse cannot
/// read back, so the comments would pile up on every later update; a stale comment is
/// dropped instead and the closers kept. When more comment text follows the stale tag
/// ([`CommentRemainder::Text`]) the bare `#` is kept so those words stay inside the comment.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::{CommentSlot, CommitSha, ShaPinTail, sha_pin_rewrite};
///
/// let sha = CommitSha::parse(&"b".repeat(40)).unwrap();
/// let target = ConcreteVersion::new("v4.3.0");
/// let appendable = ShaPinTail::Bare(CommentSlot::Appendable);
/// assert_eq!(
///     sha_pin_rewrite(&appendable, &sha, &target),
///     format!("{} # v4.3.0", sha.as_str())
/// );
/// let unavailable = ShaPinTail::Bare(CommentSlot::Unavailable);
/// assert_eq!(sha_pin_rewrite(&unavailable, &sha, &target), sha.as_str());
/// ```
#[must_use]
pub fn sha_pin_rewrite(tail: &ShaPinTail, sha: &CommitSha, target: &ConcreteVersion) -> String {
    let comment = CommentTag::parse(target.as_str()).filter(CommentTag::is_printable_ascii);
    match (tail, comment) {
        (ShaPinTail::Commented(existing), Some(tag)) => {
            format!("{sha}{} # {tag}", existing.closing)
        }
        (ShaPinTail::Commented(existing), None) => match existing.remainder {
            CommentRemainder::Empty => format!("{sha}{}", existing.closing),
            CommentRemainder::Text => format!("{sha}{} #", existing.closing),
        },
        (ShaPinTail::Bare(CommentSlot::Appendable), Some(tag)) => format!("{sha} # {tag}"),
        (ShaPinTail::Bare(CommentSlot::Appendable | CommentSlot::Unavailable), _) => {
            sha.to_string()
        }
    }
}

/// Verdict on whether a SHA pin's trailing `# tag` comment matches the pinned commit (#1722).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentCheck {
    /// The pin has no version comment to check.
    NoComment,
    /// The index cannot vouch either way (cold cache, or the SHA is absent from a truncated
    /// index).
    Unverifiable,
    /// The comment names the pinned commit's tag.
    Confirmed,
    /// The comment provably does not name the pinned commit's tag.
    Mismatch(CommentMismatch),
}

/// Why a SHA pin's comment does not match its commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentMismatch {
    /// No release tag of the repository points at the SHA.
    ShaNotInIndex,
    /// A different tag names the SHA.
    ShaIsOtherTag {
        /// The tag that does point at the SHA.
        actual: ConcreteVersion,
    },
    /// The index is truncated and lacks the SHA, but maps the comment's full-version tag to a
    /// different commit.
    CommentNamesOtherCommit,
}

/// Whether a `# comment` names `actual`: equal ignoring the `v`/`V` prefix, or a shorter
/// prefix of a release tag (`# v4` over `v4.3.1`). A prerelease tag (`v4.3.1-rc.1`) is only
/// named by a comment that itself carries the prerelease part.
fn comment_names_tag(comment: &str, actual: &str) -> bool {
    let is_prerelease = |tag: &str| normalize_tag(tag).contains(['-', '+']);
    normalize_tag(comment) == normalize_tag(actual)
        || (extends_tag(actual, comment) && (!is_prerelease(actual) || is_prerelease(comment)))
}

impl CommentCheck {
    /// Checks `comment` against `index` for a pin at `sha`.
    ///
    /// Partial-precision comments (`# v4` over `v4.3.1`) agree when the SHA's most specific
    /// tag extends the comment; `tag_to_sha["v4"]` is not compared for that case since moving
    /// majors legitimately drift. A cold or empty index, or a SHA absent from a truncated
    /// one ([`PinResolution::Unlisted`]), is [`Self::Unverifiable`] rather than a mismatch, unless the truncated index maps
    /// a full-version comment to another commit ([`CommentMismatch::CommentNamesOtherCommit`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{
    ///     CommentCheck, CommentTag, ClosingDelimiters, CommitSha, ShaPinComment, TagIndex,
    /// };
    /// use deps_core::position::Range;
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v4.2.0", &sha)]);
    /// let comment = |tag| {
    ///     ShaPinComment::new(
    ///         CommentTag::parse(tag).unwrap(),
    ///         ClosingDelimiters::default(),
    ///         Range::default(),
    ///     )
    /// };
    /// assert_eq!(
    ///     CommentCheck::evaluate(Some(&index), &sha, Some(&comment("v4"))),
    ///     CommentCheck::Confirmed
    /// );
    /// assert!(matches!(
    ///     CommentCheck::evaluate(Some(&index), &sha, Some(&comment("v5.0.0"))),
    ///     CommentCheck::Mismatch(_)
    /// ));
    /// assert_eq!(CommentCheck::evaluate(None, &sha, None), CommentCheck::NoComment);
    /// ```
    #[must_use]
    pub fn evaluate(
        index: Option<&TagIndex>,
        sha: &CommitSha,
        comment: Option<&ShaPinComment>,
    ) -> Self {
        let Some(comment) = comment else {
            return Self::NoComment;
        };
        let Some(index) = index.filter(|index| !index.is_empty()) else {
            return Self::Unverifiable;
        };
        let commented = comment.tag.as_str();
        if index
            .tag_to_sha
            .get(commented)
            .is_some_and(|commit| commit == sha)
        {
            return Self::Confirmed;
        }
        match index.pin_resolution(sha, Some(&comment.tag)) {
            PinResolution::Resolved { pin, .. }
                if comment_names_tag(commented, pin.version().as_str()) =>
            {
                Self::Confirmed
            }
            PinResolution::Resolved { pin, .. } => Self::Mismatch(CommentMismatch::ShaIsOtherTag {
                actual: pin.version().clone(),
            }),
            PinResolution::Untagged => Self::Mismatch(CommentMismatch::ShaNotInIndex),
            PinResolution::CommentContradicted => {
                Self::Mismatch(CommentMismatch::CommentNamesOtherCommit)
            }
            PinResolution::Unresolved | PinResolution::Unlisted => Self::Unverifiable,
        }
    }
}

fn sanitize_for_message(value: &str) -> String {
    sanitize_and_truncate_for_diagnostic(value, MAX_DIAGNOSTIC_VALUE_CHARS)
}

/// Builds the SHA-comment-mismatch [`Diagnostic`] (#1722) for a pin at `range` whose
/// `comment` provably does not name the commit `sha`.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_core::diagnostic::Severity;
/// use deps_core::lsp_helpers::{
///     CommentMismatch, CommentTag, CommitSha, SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE,
///     sha_comment_mismatch_diagnostic,
/// };
/// use deps_core::position::{Position, Range};
///
/// let range = Range::new(Position::new(0, 0), Position::new(0, 60));
/// let diagnostic = sha_comment_mismatch_diagnostic(
///     range,
///     &PackageName::new("a/b"),
///     &CommitSha::parse(&"a".repeat(40)).unwrap(),
///     &CommentTag::parse("v4").unwrap(),
///     &CommentMismatch::ShaNotInIndex,
///     Severity::Warning,
/// );
/// assert_eq!(diagnostic.code(), Some(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE));
/// ```
#[must_use]
pub fn sha_comment_mismatch_diagnostic(
    range: Range,
    name: &PackageName,
    sha: &CommitSha,
    comment: &CommentTag,
    mismatch: &CommentMismatch,
    severity: Severity,
) -> Diagnostic {
    let name = redact_name_for_diagnostic(name);
    let sha = short_sha(sha.as_str());
    let comment = sanitize_for_message(comment.as_str());
    let message = match mismatch {
        CommentMismatch::ShaIsOtherTag { actual } => format!(
            "{name}: SHA {sha} is not the commit of `{comment}` named in the comment \
             (it is `{}`)",
            sanitize_for_message(actual.as_str())
        ),
        CommentMismatch::ShaNotInIndex => format!(
            "{name}: SHA {sha} is not the commit of any release tag; the comment \
             names `{comment}`"
        ),
        CommentMismatch::CommentNamesOtherCommit => {
            format!("{name}: SHA {sha} is not the commit of `{comment}` named in the comment")
        }
    };
    Diagnostic::new(range, message)
        .with_severity(severity)
        .with_code(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE)
}

/// The hover warning line for a SHA-comment mismatch (#1722).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommentMismatch, CommentTag, CommitSha, sha_comment_mismatch_hover_line};
///
/// let line = sha_comment_mismatch_hover_line(
///     &CommitSha::parse(&"a".repeat(40)).unwrap(),
///     &CommentTag::parse("v4").unwrap(),
///     &CommentMismatch::ShaNotInIndex,
/// );
/// assert!(line.starts_with("**Warning**"));
/// ```
#[must_use]
pub fn sha_comment_mismatch_hover_line(
    sha: &CommitSha,
    comment: &CommentTag,
    mismatch: &CommentMismatch,
) -> String {
    let sha = markdown_code_span(&format!("{}…", short_sha(sha.as_str())));
    let comment = markdown_code_span(&sanitize_for_message(comment.as_str()));
    match mismatch {
        CommentMismatch::ShaIsOtherTag { actual } => format!(
            "**Warning**: comment says {comment}, but SHA {sha} is {}",
            markdown_code_span(&sanitize_for_message(actual.as_str()))
        ),
        CommentMismatch::ShaNotInIndex => format!(
            "**Warning**: SHA {sha} is not the commit of any release tag; comment says {comment}"
        ),
        CommentMismatch::CommentNamesOtherCommit => {
            format!("**Warning**: SHA {sha} is not the commit of {comment} named in the comment")
        }
    }
}

/// Builds the "Correct version comment" quickfix (#1734) for the SHA pin spanning
/// `version_range` whose trailing `# tag` comment names a different tag than the one the
/// pinned commit carries.
///
/// The edit replaces only the comment's tag token with the registry-confirmed tag, so the
/// written SHA casing, closing delimiters, and spacing are untouched. `None` unless `mismatch`
/// is [`CommentMismatch::ShaIsOtherTag`]: [`CommentMismatch::ShaNotInIndex`] and
/// [`CommentMismatch::CommentNamesOtherCommit`] name no tag to offer.
///
/// The tag text comes from the registry's tag list, so it is offered only when the parser would
/// read it back as a comment tag and sanitization leaves it unchanged (no invisible or bidi
/// characters, within the length cap). A comment token with trailing punctuation (`v4-beta,`)
/// is left alone: the corrected token would no longer parse as a comment tag, hiding the
/// warning without confirming the pin.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::{
///     ClosingDelimiters, CommentMismatch, CommentTag, ShaPinComment, build_sha_comment_fix_action,
/// };
/// use deps_core::position::{Position, Range};
///
/// let uri = url::Url::parse("file:///repo/ci.yml").unwrap();
/// let tag_range = Range::new(Position::new(0, 47), Position::new(0, 49));
/// let comment = ShaPinComment::new(
///     CommentTag::parse("v3").unwrap(),
///     ClosingDelimiters::default(),
///     tag_range,
/// );
/// let range = Range::new(Position::new(0, 6), Position::new(0, 49));
/// let mismatch = CommentMismatch::ShaIsOtherTag { actual: ConcreteVersion::new("v4.2.0") };
/// let action = build_sha_comment_fix_action(&uri, range, &comment, &mismatch).unwrap();
/// assert_eq!(action.title, "Correct version comment to `v4.2.0`");
/// assert!(build_sha_comment_fix_action(&uri, range, &comment, &CommentMismatch::ShaNotInIndex).is_none());
/// ```
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn build_sha_comment_fix_action(
    uri: &url::Url,
    version_range: Range,
    comment: &ShaPinComment,
    mismatch: &CommentMismatch,
) -> Option<CodeAction> {
    let CommentMismatch::ShaIsOtherTag { actual } = mismatch else {
        return None;
    };
    let actual = actual.as_str();
    if !is_partial_semver_shaped(actual)
        || sanitize_for_message(actual) != actual
        || comment
            .tag
            .as_str()
            .ends_with(|c: char| c.is_ascii_punctuation())
    {
        return None;
    }
    let changes = single_file_edit(uri, comment.tag_range, actual.to_string());
    Some(CodeAction {
        title: format!("Correct version comment to `{actual}`"),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE],
            "diagnostic_range": tower_lsp_server::ls_types::Range::from(version_range),
        })),
        ..Default::default()
    })
}

/// Whether `position` lies inside a SHA pin's `range` but past the end of the SHA itself.
///
/// A pin with a trailing comment has a range that extends through the comment; completion
/// must not offer tag or version items while the cursor is in that comment. A cursor exactly
/// at the SHA's end (still typing it) is not past it. A range that starts at the SHA, with
/// its start column plus the SHA length as the boundary, is assumed.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::position_past_sha;
/// use deps_core::position::{Position, Range};
///
/// let range = Range::new(Position::new(2, 10), Position::new(2, 60));
/// assert!(position_past_sha(range, Position::new(2, 55)));
/// assert!(!position_past_sha(range, Position::new(2, 50)));
/// assert!(!position_past_sha(range, Position::new(3, 55)));
/// ```
#[must_use]
pub fn position_past_sha(range: Range, position: Position) -> bool {
    let Ok(sha_len) = u32::try_from(SHA_LEN) else {
        return false;
    };
    position_in_range(position, range)
        && position.character > range.start.character.saturating_add(sha_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pagination::ListCoverage;
    use std::assert_matches;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn read(content: &str, style: TScalarStyle, plain: bool, ref_end: usize) -> ShaPinTailRead {
        let table = LineOffsetTable::new(content);
        read_sha_pin_tail(content, &table, ref_end, 1, style, plain)
    }

    fn comment(tag: &str, closing: &str, style: TScalarStyle) -> ShaPinComment {
        ShaPinComment::new(
            CommentTag::parse(tag).unwrap(),
            ClosingDelimiters::parse(closing, style),
            Range::default(),
        )
        .with_remainder(CommentRemainder::Empty)
    }

    #[test]
    fn test_comment_tag_parse_table() {
        for ok in [
            "v4",
            "V4",
            "v4.2",
            "v4.2.0",
            "4.2.0",
            "v4.2.0-rc.1",
            "v1+build",
        ] {
            assert_eq!(CommentTag::parse(ok).unwrap().as_str(), ok, "{ok}");
        }
        for bad in [
            "", "stable", "main", "1234", "20240501", "v1 2", "v1\tx", "v1-a\nb", "v1-#x",
            "v1.2.3.4",
        ] {
            assert!(CommentTag::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn test_comment_tag_is_full_version() {
        for full in ["v4.2.0", "V4.2.0", "4.2.0", "v4.2.0-rc.1", "v1.0.0+build"] {
            assert!(CommentTag::parse(full).unwrap().is_full_version(), "{full}");
        }
        for alias in ["v4", "v4.2", "v4-beta", "v2.1-rc"] {
            assert!(
                !CommentTag::parse(alias).unwrap().is_full_version(),
                "{alias}"
            );
        }
    }

    fn truncated_index_1762() -> TagIndex {
        TagIndex::from_tags([("v4.2.0", &sha('b'))]).with_coverage(ListCoverage::Truncated)
    }

    #[test]
    fn test_comment_check_truncated_index_contradicted_comment_is_mismatch() {
        let index = truncated_index_1762();
        let check = |tag: &str| {
            CommentCheck::evaluate(
                Some(&index),
                &sha('a'),
                Some(&comment(tag, "", TScalarStyle::Plain)),
            )
        };
        assert_eq!(
            check("v4.2.0"),
            CommentCheck::Mismatch(CommentMismatch::CommentNamesOtherCommit)
        );
        for variant in ["4.2.0", "V4.2.0", "v4.2.0+build"] {
            assert_eq!(
                check(variant),
                CommentCheck::Mismatch(CommentMismatch::CommentNamesOtherCommit),
                "{variant}"
            );
        }
        for benign in ["v4", "v9.9.9"] {
            assert_eq!(check(benign), CommentCheck::Unverifiable, "{benign}");
        }
        assert_eq!(
            CommentCheck::evaluate(
                Some(&index),
                &sha('b'),
                Some(&comment("v4.2.0", "", TScalarStyle::Plain))
            ),
            CommentCheck::Confirmed
        );
    }

    #[test]
    fn test_comment_names_other_commit_message_and_hover() {
        let name = PackageName::new("a/b");
        let tag = CommentTag::parse("v4.2.0").unwrap();
        let diagnostic = sha_comment_mismatch_diagnostic(
            Range::default(),
            &name,
            &sha('a'),
            &tag,
            &CommentMismatch::CommentNamesOtherCommit,
            Severity::Warning,
        );
        assert_eq!(
            diagnostic.code(),
            Some(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE)
        );
        assert!(diagnostic.message().contains("`v4.2.0`"));
        assert!(
            diagnostic
                .message()
                .contains("is not the commit of `v4.2.0`")
        );
        let hover = sha_comment_mismatch_hover_line(
            &sha('a'),
            &tag,
            &CommentMismatch::CommentNamesOtherCommit,
        );
        assert!(hover.starts_with("**Warning**"));
        assert!(hover.contains("v4.2.0"));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_sha_comment_fix_action_offers_only_a_clean_other_tag() {
        let uri = url::Url::parse("file:///repo/ci.yml").unwrap();
        let range = Range::new(Position::new(0, 6), Position::new(0, 60));
        let other = |tag: &str| CommentMismatch::ShaIsOtherTag {
            actual: ConcreteVersion::new(tag),
        };
        let stale = comment("v3", "", TScalarStyle::Plain);
        let action = build_sha_comment_fix_action(&uri, range, &stale, &other("v4.2.0")).unwrap();
        assert_eq!(action.title, "Correct version comment to `v4.2.0`");
        for refused in [
            CommentMismatch::ShaNotInIndex,
            CommentMismatch::CommentNamesOtherCommit,
            other("stable"),
            other("v4\u{202e}"),
        ] {
            assert!(
                build_sha_comment_fix_action(&uri, range, &stale, &refused).is_none(),
                "{refused:?}"
            );
        }
        let punctuated = ShaPinComment::new(
            CommentTag::parse("v4-beta,").unwrap(),
            ClosingDelimiters::default(),
            Range::default(),
        );
        assert!(build_sha_comment_fix_action(&uri, range, &punctuated, &other("v4.2.0")).is_none());
    }

    #[test]
    fn test_closing_delimiters_parse() {
        use TScalarStyle::{DoubleQuoted, Folded, Literal, Plain, SingleQuoted};
        let cases = [
            (" # v4", Plain, ""),
            ("\" # v4", DoubleQuoted, "\""),
            ("' # v4", SingleQuoted, "'"),
            ("} # v4", Plain, "}"),
            (" \t} # v4", Plain, " \t}"),
            ("\"} # v4", DoubleQuoted, "\"}"),
            ("\" } # v4", DoubleQuoted, "\" }"),
            ("\"}} # v4", DoubleQuoted, "\"}"),
            (" , x: 1}", Plain, ""),
            ("# v4", Literal, ""),
            ("# v4", Folded, ""),
            (" # v4", DoubleQuoted, ""),
            ("' # v4", DoubleQuoted, ""),
        ];
        for (tail, style, expected) in cases {
            let parsed = ClosingDelimiters::parse(tail, style);
            assert_eq!(parsed.to_string(), expected, "{tail:?} {style:?}");
            assert_eq!(parsed.byte_len(), expected.len());
            assert_eq!(parsed.is_empty(), expected.is_empty());
        }
    }

    #[test]
    fn test_read_tail_plain_comment() {
        let s = "a".repeat(40);
        let content = format!("ref: {s} # v4.2.0\n");
        let read = read(&content, TScalarStyle::Plain, true, 5 + 40);
        assert_eq!(
            read.tail,
            ShaPinTail::Commented(ShaPinComment {
                tag_range: Range::new(Position::new(0, 48), Position::new(0, 54)),
                ..comment("v4.2.0", "", TScalarStyle::Plain)
            })
        );
        assert_eq!(
            content.get(5..read.range_end).unwrap(),
            format!("{s} # v4.2.0")
        );
    }

    #[test]
    fn test_read_tail_tag_range_counts_utf16_units() {
        let s = "a".repeat(40);
        let content = format!("😀: {s} # v4.2.0\n");
        let read = read(&content, TScalarStyle::Plain, true, 4 + 2 + 40);
        assert_eq!(
            read.tail.comment().unwrap().tag_range,
            Range::new(Position::new(0, 47), Position::new(0, 53))
        );
    }

    #[test]
    fn test_comment_slot_after_matches_read_tail_slot() {
        let s = "a".repeat(40);
        for (content, style, plain, ref_end) in [
            (format!("ref: {s}\n"), TScalarStyle::Plain, true, 45),
            (
                format!("ref: \"{s}\"\n"),
                TScalarStyle::DoubleQuoted,
                false,
                46,
            ),
            (
                format!("{{ref: {s}, x: 1}}\n"),
                TScalarStyle::Plain,
                true,
                46,
            ),
        ] {
            let table = LineOffsetTable::new(&content);
            assert_eq!(
                ShaPinTail::Bare(comment_slot_after(&content, &table, ref_end, 1, plain)),
                read(&content, style, plain, ref_end).tail,
                "{content:?}"
            );
        }
    }

    #[test]
    fn test_read_tail_partial_precision_comments() {
        let s = "a".repeat(40);
        for tag in ["v4", "v4.2", "4.2.0"] {
            let content = format!("ref: {s} # {tag}");
            let read = read(&content, TScalarStyle::Plain, true, 45);
            assert_eq!(read.tail.comment().unwrap().tag.as_str(), tag);
            assert_eq!(read.range_end, content.len());
        }
    }

    #[test]
    fn test_read_tail_quoted_and_flow_closers() {
        let s = "a".repeat(40);
        let double = format!("ref: \"{s}\" # v4\n");
        let read_double = read(&double, TScalarStyle::DoubleQuoted, false, 6 + 40);
        assert_eq!(
            read_double.tail,
            ShaPinTail::Commented(ShaPinComment {
                tag_range: Range::new(Position::new(0, 50), Position::new(0, 52)),
                ..comment("v4", "\"", TScalarStyle::DoubleQuoted)
            })
        );
        assert_eq!(
            double.get(6..read_double.range_end).unwrap(),
            format!("{s}\" # v4")
        );

        let single = format!("ref: '{s}' # v4");
        let read_single = read(&single, TScalarStyle::SingleQuoted, false, 6 + 40);
        assert_eq!(read_single.tail.comment().unwrap().closing.to_string(), "'");

        let flow = format!("{{ref: {s} }} # v4");
        let read_flow = read(&flow, TScalarStyle::Plain, true, 6 + 40);
        assert_eq!(read_flow.tail.comment().unwrap().closing.to_string(), " }");

        let flow_tight = format!("{{ref: {s}}} # v4");
        let read_tight = read(&flow_tight, TScalarStyle::Plain, true, 6 + 40);
        assert_eq!(read_tight.tail.comment().unwrap().closing.to_string(), "}");
    }

    #[test]
    fn test_read_tail_bare_slots() {
        let s = "a".repeat(40);
        let plain = format!("ref: {s}\n");
        assert_eq!(
            read(&plain, TScalarStyle::Plain, true, 45).tail,
            ShaPinTail::Bare(CommentSlot::Appendable)
        );
        let plain_note = format!("ref: {s} # why\n");
        assert_eq!(
            read(&plain_note, TScalarStyle::Plain, true, 45).tail,
            ShaPinTail::Bare(CommentSlot::Appendable)
        );
        let quoted = format!("ref: \"{s}\"\n");
        assert_eq!(
            read(&quoted, TScalarStyle::DoubleQuoted, false, 46).tail,
            ShaPinTail::Bare(CommentSlot::Unavailable)
        );
        let flow = format!("{{ref: {s}, x: 1}}\n");
        assert_eq!(
            read(&flow, TScalarStyle::Plain, true, 46).tail,
            ShaPinTail::Bare(CommentSlot::Unavailable)
        );
        let block = format!("ref: {s}\n");
        assert_eq!(
            read(&block, TScalarStyle::Literal, false, 45).tail,
            ShaPinTail::Bare(CommentSlot::Unavailable)
        );
    }

    #[test]
    fn test_read_tail_range_end_is_sha_end_without_comment() {
        let s = "a".repeat(40);
        let content = format!("ref: {s}   \n");
        assert_eq!(read(&content, TScalarStyle::Plain, true, 45).range_end, 45);
    }

    #[test]
    fn test_read_tail_hash_not_preceded_by_blank_is_not_a_comment() {
        let s = "a".repeat(40);
        let content = format!("ref: {s}#v4\n");
        let read = read(&content, TScalarStyle::Plain, true, 45);
        assert_eq!(read.tail, ShaPinTail::Bare(CommentSlot::Unavailable));
    }

    #[test]
    fn test_read_tail_later_flow_token_comment_is_not_attributed() {
        let s = "a".repeat(40);
        let content = format!("{{ref: {s}, x: 1}} # v4\n");
        let read = read(&content, TScalarStyle::Plain, true, 46);
        assert_eq!(read.tail, ShaPinTail::Bare(CommentSlot::Unavailable));
    }

    #[test]
    fn test_read_tail_non_version_comment_is_bare() {
        let s = "a".repeat(40);
        for note in ["cargo-deny", "main", "20240501", "1234"] {
            let content = format!("ref: {s} # {note}\n");
            let read = read(&content, TScalarStyle::Plain, true, 45);
            assert_eq!(
                read.tail,
                ShaPinTail::Bare(CommentSlot::Appendable),
                "{note}"
            );
        }
    }

    #[test]
    fn test_read_tail_truncated_window_rejects_token_of_unknown_extent() {
        let s = "a".repeat(40);
        let padding = " ".repeat(REST_OF_LINE_WINDOW_BYTES - 8);
        let content = format!("ref: {s}{padding}# v4.2.100 more\n");
        let read = read(&content, TScalarStyle::Plain, true, 45);
        assert_eq!(read.tail, ShaPinTail::Bare(CommentSlot::Appendable));

        let fits = format!("ref: {s} # v4.2.100 more\n");
        let read = read_tail_ok(&fits);
        assert_eq!(read.tail.comment().unwrap().tag.as_str(), "v4.2.100");
    }

    fn read_tail_ok(content: &str) -> ShaPinTailRead {
        read(content, TScalarStyle::Plain, true, 45)
    }

    #[test]
    fn test_read_tail_truncated_all_blank_window_is_not_last_on_line() {
        let s = "a".repeat(40);
        let padding = " ".repeat(REST_OF_LINE_WINDOW_BYTES + 16);
        let content = format!("{{ref: {s}{padding}, x: 1}}\n");
        let read = read(&content, TScalarStyle::Plain, true, 46);
        assert_eq!(read.tail, ShaPinTail::Bare(CommentSlot::Unavailable));
    }

    #[test]
    fn test_read_tail_comment_found_within_truncated_window_is_definitive() {
        let s = "a".repeat(40);
        let tail = "x".repeat(REST_OF_LINE_WINDOW_BYTES * 2);
        let content = format!("ref: {s} # v4 {tail}\n");
        let read = read(&content, TScalarStyle::Plain, true, 45);
        assert_eq!(read.tail.comment().unwrap().tag.as_str(), "v4");
    }

    #[test]
    fn test_read_tail_multibyte_after_ref_does_not_panic() {
        let s = "a".repeat(40);
        let content = format!("ref: {s} # v4 {}\n", "é".repeat(REST_OF_LINE_WINDOW_BYTES));
        let read = read(&content, TScalarStyle::Plain, true, 45);
        assert_eq!(read.tail.comment().unwrap().tag.as_str(), "v4");
    }

    #[test]
    fn test_read_tail_second_line_and_crlf() {
        let s = "a".repeat(40);
        let content = format!("x: 1\r\nref: {s} # v4\r\ny: 2\r\n");
        let table = LineOffsetTable::new(&content);
        let ref_end = 6 + 5 + 40;
        let read = read_sha_pin_tail(&content, &table, ref_end, 2, TScalarStyle::Plain, true);
        assert_eq!(read.tail.comment().unwrap().tag.as_str(), "v4");
        assert_eq!(read.range_end, ref_end + " # v4".len());
    }

    #[test]
    fn test_read_tail_ref_end_past_line_does_not_panic() {
        let content = "ref: x\n";
        let table = LineOffsetTable::new(content);
        let read = read_sha_pin_tail(content, &table, 100, 1, TScalarStyle::Plain, true);
        assert_eq!(read.range_end, 100);
        assert_matches!(read.tail, ShaPinTail::Bare(_));
    }

    #[test]
    fn test_ref_is_last_on_line() {
        let cases = [
            ("ref: abc\n", 8, true),
            ("ref: abc   \n", 8, true),
            ("ref: abc # note\n", 8, true),
            ("ref: abc#x\n", 8, false),
            ("{ref: abc, x: 1}\n", 9, false),
            ("{ref: abc}\n", 9, false),
            ("ref: abc", 8, true),
        ];
        for (content, ref_end, expected) in cases {
            let table = LineOffsetTable::new(content);
            assert_eq!(
                ref_is_last_on_line(content, &table, ref_end, 1),
                expected,
                "{content:?}"
            );
        }
    }

    #[test]
    fn test_sha_pin_rewrite_table() {
        use TScalarStyle::{DoubleQuoted, Plain, SingleQuoted};
        let new = sha('b');
        let n = new.as_str();
        let target = ConcreteVersion::new("v4.3.0");
        let cases = [
            (
                ShaPinTail::Commented(comment("v4.2.0", "", Plain)),
                format!("{n} # v4.3.0"),
            ),
            (
                ShaPinTail::Commented(comment("v4", "\"", DoubleQuoted)),
                format!("{n}\" # v4.3.0"),
            ),
            (
                ShaPinTail::Commented(comment("v4", "'", SingleQuoted)),
                format!("{n}' # v4.3.0"),
            ),
            (
                ShaPinTail::Commented(comment("v4", " }", Plain)),
                format!("{n} }} # v4.3.0"),
            ),
            (
                ShaPinTail::Bare(CommentSlot::Appendable),
                format!("{n} # v4.3.0"),
            ),
            (ShaPinTail::Bare(CommentSlot::Unavailable), n.to_string()),
        ];
        for (tail, expected) in cases {
            assert_eq!(sha_pin_rewrite(&tail, &new, &target), expected, "{tail:?}");
        }
    }

    #[test]
    fn test_sha_pin_rewrite_non_version_target_never_writes_a_comment() {
        let new = sha('b');
        let n = new.as_str();
        for name in [
            "stable",
            "main",
            "1234",
            "v1 x",
            "v1\n# x",
            "v1-\u{202e}x",
            "v4-\u{3b2}",
        ] {
            let target = ConcreteVersion::new(name);
            assert_eq!(
                sha_pin_rewrite(&ShaPinTail::Bare(CommentSlot::Appendable), &new, &target),
                n,
                "{name:?}"
            );
            assert_eq!(
                sha_pin_rewrite(
                    &ShaPinTail::Commented(
                        comment("v4", "\"", TScalarStyle::DoubleQuoted)
                            .with_remainder(CommentRemainder::Empty)
                    ),
                    &new,
                    &target
                ),
                format!("{n}\""),
                "{name:?}"
            );
        }
    }

    /// Reads the pin in `content` (starting after `prefix`), rewrites it to a non-tag target
    /// and splices the result back, returning the new line.
    fn rewrite_line(prefix: &str, quote: &str, comment_text: &str) -> String {
        let old = "a".repeat(40);
        let new = sha('b');
        let style = if quote.is_empty() {
            TScalarStyle::Plain
        } else {
            TScalarStyle::DoubleQuoted
        };
        let head = format!("{prefix}{quote}");
        let content = format!("{head}{old}{quote}{comment_text}\n");
        let start = head.len();
        let table = LineOffsetTable::new(&content);
        let read = read_sha_pin_tail(&content, &table, start + 40, 1, style, quote.is_empty());
        let rewritten = sha_pin_rewrite(&read.tail, &new, &ConcreteVersion::new("stable"));
        format!(
            "{}{}{}",
            content.get(..start).unwrap(),
            rewritten,
            content.get(read.range_end..).unwrap()
        )
    }

    #[test]
    fn test_sha_pin_rewrite_non_tag_target_keeps_trailing_comment_words_inside_comment() {
        let n = "b".repeat(40);
        let cases = [
            (
                "c: x@",
                "",
                " # 1.0.0 pinned for CVE",
                format!("c: x@{n} # pinned for CVE\n"),
            ),
            (
                "ref: ",
                "\"",
                " # v1.0.0 pinned",
                format!("ref: \"{n}\" # pinned\n"),
            ),
            ("ref: ", "", " # v1.0.0 \t", format!("ref: {n} \t\n")),
            ("ref: ", "", " # v1.0.0", format!("ref: {n}\n")),
            ("ref: ", "\"", " # v1.0.0", format!("ref: \"{n}\"\n")),
        ];
        for (prefix, quote, text, expected) in cases {
            assert_eq!(rewrite_line(prefix, quote, text), expected, "{text:?}");
        }
    }

    #[test]
    fn test_read_tail_records_comment_remainder() {
        let s = "a".repeat(40);
        let remainder = |text: &str| {
            let content = format!("ref: {s}{text}\n");
            read(&content, TScalarStyle::Plain, true, 45)
                .tail
                .comment()
                .unwrap()
                .remainder
        };
        assert_eq!(remainder(" # v4"), CommentRemainder::Empty);
        assert_eq!(remainder(" # v4   "), CommentRemainder::Empty);
        assert_eq!(remainder(" # v4 words"), CommentRemainder::Text);
    }

    #[test]
    fn test_sha_pin_rewrite_is_idempotent_through_reparse() {
        let s = sha('a');
        let new = sha('b');
        let target = ConcreteVersion::new("v4.3.0");
        for (style, plain, quote) in [
            (TScalarStyle::Plain, true, ""),
            (TScalarStyle::DoubleQuoted, false, "\""),
        ] {
            let content = format!("ref: {quote}{} # v4.2.0\n", s.as_str());
            let first = read(&content, style, plain, 5 + quote.len() + 40);
            let rewritten = sha_pin_rewrite(&first.tail, &new, &target);
            let updated = format!("ref: {quote}{rewritten}\n");
            let second = read(&updated, style, plain, 5 + quote.len() + 40);
            assert_eq!(
                sha_pin_rewrite(&second.tail, &new, &target),
                rewritten,
                "{style:?}"
            );
            assert_eq!(second.range_end, updated.trim_end().len());
        }
    }

    fn check(index: Option<&TagIndex>, pin: &CommitSha, tag: Option<&str>) -> CommentCheck {
        let comment = tag.map(|t| comment(t, "", TScalarStyle::Plain));
        CommentCheck::evaluate(index, pin, comment.as_ref())
    }

    #[test]
    fn test_comment_check_no_comment_and_unverifiable() {
        let a = sha('a');
        let index = TagIndex::from_tags([("v1.0.0", &a)]);
        assert_eq!(check(Some(&index), &a, None), CommentCheck::NoComment);
        assert_eq!(check(None, &a, None), CommentCheck::NoComment);
        assert_eq!(check(None, &a, Some("v1.0.0")), CommentCheck::Unverifiable);
        assert_eq!(
            check(Some(&TagIndex::default()), &a, Some("v1.0.0")),
            CommentCheck::Unverifiable
        );
    }

    #[test]
    fn test_comment_check_confirmed_forms() {
        let a = sha('a');
        let index = TagIndex::from_tags([("v4.3.1", &a), ("v4", &a)]);
        for tag in ["v4.3.1", "4.3.1", "v4", "v4.3"] {
            assert_eq!(
                check(Some(&index), &a, Some(tag)),
                CommentCheck::Confirmed,
                "{tag}"
            );
        }
        let upper = CommitSha::parse(&"A".repeat(40)).unwrap();
        assert_eq!(
            check(Some(&index), &upper, Some("v4")),
            CommentCheck::Confirmed
        );
    }

    #[test]
    fn test_comment_check_mismatch_forms() {
        let a = sha('a');
        let b = sha('b');
        let index = TagIndex::from_tags([("v1.0.0", &a), ("v2.0.0", &b)]);
        assert_eq!(
            check(Some(&index), &a, Some("v2.0.0")),
            CommentCheck::Mismatch(CommentMismatch::ShaIsOtherTag {
                actual: ConcreteVersion::new("v1.0.0")
            })
        );
        assert_eq!(
            check(Some(&index), &sha('c'), Some("v2.0.0")),
            CommentCheck::Mismatch(CommentMismatch::ShaNotInIndex)
        );
        let truncated =
            TagIndex::from_tags([("v1.0.0", &a)]).with_coverage(ListCoverage::Truncated);
        assert_eq!(
            check(Some(&truncated), &sha('c'), Some("v2.0.0")),
            CommentCheck::Unverifiable
        );
    }

    #[test]
    fn test_comment_check_prerelease_commit_is_named_only_by_prerelease_comment() {
        let a = sha('a');
        let index = TagIndex::from_tags([("v4.3.1-rc.1", &a)]);
        assert_matches!(
            check(Some(&index), &a, Some("v4")),
            CommentCheck::Mismatch(_)
        );
        assert_eq!(
            check(Some(&index), &a, Some("v4.3.1-rc.1")),
            CommentCheck::Confirmed
        );
    }

    #[test]
    fn test_mismatch_diagnostic_text_and_code() {
        let range = Range::new(Position::new(1, 2), Position::new(1, 50));
        let name = PackageName::new("a/b");
        let a = sha('a');
        let tag = CommentTag::parse("v2.0.0").unwrap();
        let other = sha_comment_mismatch_diagnostic(
            range,
            &name,
            &a,
            &tag,
            &CommentMismatch::ShaIsOtherTag {
                actual: ConcreteVersion::new("v1.0.0"),
            },
            Severity::Warning,
        );
        assert_eq!(
            other.message(),
            "a/b: SHA aaaaaaa is not the commit of `v2.0.0` named in the comment (it is `v1.0.0`)"
        );
        assert_eq!(other.code(), Some(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE));
        let missing = sha_comment_mismatch_diagnostic(
            range,
            &name,
            &a,
            &tag,
            &CommentMismatch::ShaNotInIndex,
            Severity::Warning,
        );
        assert_eq!(
            missing.message(),
            "a/b: SHA aaaaaaa is not the commit of any release tag; the comment names `v2.0.0`"
        );
    }

    #[test]
    fn test_mismatch_hover_line_text() {
        let a = sha('a');
        let tag = CommentTag::parse("v2.0.0").unwrap();
        assert_eq!(
            sha_comment_mismatch_hover_line(
                &a,
                &tag,
                &CommentMismatch::ShaIsOtherTag {
                    actual: ConcreteVersion::new("v1.0.0")
                }
            ),
            "**Warning**: comment says `v2.0.0`, but SHA `aaaaaaa…` is `v1.0.0`"
        );
        assert_eq!(
            sha_comment_mismatch_hover_line(&a, &tag, &CommentMismatch::ShaNotInIndex),
            "**Warning**: SHA `aaaaaaa…` is not the commit of any release tag; comment says `v2.0.0`"
        );
    }

    #[test]
    fn test_position_past_sha_boundaries() {
        let range = Range::new(Position::new(2, 10), Position::new(2, 60));
        assert!(position_past_sha(range, Position::new(2, 51)));
        assert!(!position_past_sha(range, Position::new(2, 50)));
        assert!(!position_past_sha(range, Position::new(2, 9)));
        assert!(!position_past_sha(range, Position::new(2, 61)));
        assert!(!position_past_sha(range, Position::new(1, 55)));
    }
}

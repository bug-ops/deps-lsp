//! Shared escape-aware string-literal and comment scanning for manifest raw-text parsers.
//!
//! Three ecosystem parsers scan manifest source text byte-by-byte, skipping over string
//! literals and comments to find or classify code: `deps-bundler`'s Gemfile option
//! extraction, `deps-swift`'s Package.swift comment stripping, and `deps-pypi`'s TOML
//! comment stripping. Before this module each did so with its own hand-rolled scanner —
//! one of which (`deps-pypi`'s) did not track backslash escapes at all, truncating a
//! quoted value early at an escaped `"`. This module centralizes that skip-scan behind a
//! `syntax`-parameterized surface ([`crate::quote_scan::ScanSyntax`]), implemented as a
//! single skip loop that advances past whichever comes first: a string literal (read via
//! [`crate::quote_scan::read_string_literal`]) or a comment.
//!
//! The skip-scan delegates all escape-aware closing-quote search to
//! [`crate::fallback_completion::find_closing_quote`] rather than re-implementing it, so
//! there is exactly one escape rule in the workspace. **Use `find_closing_quote` directly**
//! when a string is already known to be open and only its closing quote is needed (e.g.
//! completing inside a string the cursor sits in). **Use this module** when comments are
//! also in play, or when the string's start position is not already known and must be
//! found by scanning.

use crate::fallback_completion::find_closing_quote;
use std::ops::Range;

/// Which manifest syntax family a scan should follow: which characters open a string
/// literal, whether that literal's contents are backslash-escaped, and which characters
/// start a comment.
///
/// One variant per syntax family, not per quote-style/comment-style combination — a
/// `ScanSyntax` value fully determines both, so a new manifest family adds one variant
/// here (and an exhaustive `match` on it forces every scan function to handle it) instead
/// of a cross product of independent style flags.
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, strip_line_comment};
///
/// assert_eq!(
///     strip_line_comment(r#"gem "x", source: "https://h" # comment"#, ScanSyntax::Ruby),
///     r#"gem "x", source: "https://h" "#,
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSyntax {
    /// Ruby (Gemfile) syntax: `"` and `'` string literals, both backslash-escaped;
    /// `#` starts a line comment.
    Ruby,
    /// Swift (Package.swift) syntax: `"` string literals, backslash-escaped; `//` starts
    /// a line comment and `/* ... */` a block comment.
    Swift,
    /// TOML syntax: `"` string literals are backslash-escaped; `'` literal strings are
    /// not escaped at all (a `\` inside one is just a literal backslash). `#` starts a
    /// line comment.
    Toml,
}

/// A string literal read from source text: its raw content span, the position just past
/// its closing delimiter, and which character delimited it.
///
/// `content` excludes both delimiters and is the **raw** source span — escape sequences
/// inside it (e.g. `\'` in `o\'brien`) are left intact, not unescaped. Byte offsets in
/// `content` are absolute within the `text` passed to [`read_string_literal`], so callers
/// can feed them directly to LSP byte-to-position conversion; unescaping, where a caller
/// needs it, is ecosystem-specific and out of scope here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteral {
    /// Byte range of the literal's content, excluding both delimiters.
    pub content: Range<usize>,
    /// Byte offset just past the closing delimiter.
    pub end: usize,
    /// The delimiter character (`"` or `'`) that opened, and must close, this literal.
    pub quote: char,
}

/// Byte-range classification produced by the internal skip-scan.
#[derive(Debug, Clone, Copy)]
enum SpanKind {
    /// Plain source text, outside any string literal or comment.
    Code,
    /// A string literal, delimiters included.
    Str,
    /// A `#`/`//`-style line comment, excluding a trailing newline, if any.
    LineComment,
    /// A Swift `/* ... */` block comment, delimiters included.
    BlockComment,
}

/// One classified byte range produced by [`scan_spans`], in source order and covering
/// `text` without gaps or overlaps.
struct Span {
    range: Range<usize>,
    kind: SpanKind,
}

/// The next syntactically significant marker found in `text` at or after `from`.
enum Marker {
    /// A string-literal delimiter (`"` or `'`); the delimiter itself is recovered from
    /// `text` by [`read_string_literal`], so it is not carried here.
    Delim,
    /// The start of a line comment (`#` or `//`, per [`ScanSyntax`]).
    LineComment,
    /// The start of a Swift `/*` block comment.
    BlockComment,
}

/// Whether `ch` opens a string literal under `syntax`.
fn is_delimiter(ch: char, syntax: ScanSyntax) -> bool {
    match syntax {
        ScanSyntax::Ruby | ScanSyntax::Toml => ch == '"' || ch == '\'',
        ScanSyntax::Swift => ch == '"',
    }
}

/// Whether a literal delimited by `quote` under `syntax` is backslash-escaped — false
/// only for TOML's literal `'...'` strings, which read every byte up to the next `'`
/// verbatim.
fn is_escaped(syntax: ScanSyntax, quote: char) -> bool {
    match syntax {
        ScanSyntax::Ruby | ScanSyntax::Swift => true,
        ScanSyntax::Toml => quote == '"',
    }
}

/// Finds the first delimiter or comment-start marker in `text` at or after `from`.
fn find_next_marker(text: &str, from: usize, syntax: ScanSyntax) -> Option<(usize, Marker)> {
    let rest = text.get(from..)?;
    for (offset, ch) in rest.char_indices() {
        if is_delimiter(ch, syntax) {
            return Some((from + offset, Marker::Delim));
        }
        match syntax {
            ScanSyntax::Ruby | ScanSyntax::Toml => {
                if ch == '#' {
                    return Some((from + offset, Marker::LineComment));
                }
            }
            ScanSyntax::Swift => {
                if ch == '/' {
                    match rest.as_bytes().get(offset + 1) {
                        Some(b'/') => return Some((from + offset, Marker::LineComment)),
                        Some(b'*') => return Some((from + offset, Marker::BlockComment)),
                        _ => {}
                    }
                }
            }
        }
    }
    None
}

/// Byte offset just past a Swift block comment's closing `*/`, given the opening `/*`'s
/// start `at` — `text.len()` if unterminated, mirroring [`ScanSyntax::Swift`]'s existing
/// "runs to end of input" behavior for an unterminated block comment.
fn block_comment_end(text: &str, at: usize) -> usize {
    text.get(at + 2..)
        .and_then(|rest| rest.find("*/"))
        .map_or(text.len(), |offset| at + 2 + offset + 2)
}

/// Byte offset of a line comment's end: the position of the next `\n`, or `text.len()` if
/// the comment runs to the end of `text`. Excludes the newline itself, so
/// [`SpanKind::LineComment`] never swallows it — matching [`ScanSyntax::Swift`]'s existing
/// line-comment behavior, which both [`blank_comments`] and [`strip_line_comment`] now
/// share across all three syntaxes.
fn line_comment_end(text: &str, at: usize) -> usize {
    text.get(at..)
        .and_then(|rest| rest.find('\n'))
        .map_or(text.len(), |offset| at + offset)
}

/// The core skip-scan: classifies every byte of `text` under `syntax` as code, a string
/// literal, a line comment, or a block comment, in source order.
///
/// Semantics an unterminated construct leaves for callers:
/// - An unterminated string literal (its delimiter never closes) absorbs every remaining
///   byte of `text` into one [`SpanKind::Str`] span — nothing after it can be a comment,
///   since Ruby/TOML/Swift would not parse past an unterminated literal either.
/// - An unterminated Swift block comment absorbs every remaining byte into one
///   [`SpanKind::BlockComment`] span.
fn scan_spans(text: &str, syntax: ScanSyntax) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let Some((marker_at, marker)) = find_next_marker(text, i, syntax) else {
            spans.push(Span {
                range: i..text.len(),
                kind: SpanKind::Code,
            });
            break;
        };
        if marker_at > i {
            spans.push(Span {
                range: i..marker_at,
                kind: SpanKind::Code,
            });
        }
        let (end, kind) = match marker {
            Marker::Delim => (
                read_string_literal(text, marker_at, syntax)
                    .map_or(text.len(), |literal| literal.end),
                SpanKind::Str,
            ),
            Marker::LineComment => (line_comment_end(text, marker_at), SpanKind::LineComment),
            Marker::BlockComment => (block_comment_end(text, marker_at), SpanKind::BlockComment),
        };
        spans.push(Span {
            range: marker_at..end,
            kind,
        });
        i = end;
    }
    spans
}

/// Reads the string literal starting at `text[at]`, per `syntax`'s quoting rules.
///
/// `text[at]` must be a delimiter character for `syntax` — a precondition, not validated
/// here; callers only reach this from a position already known to be an opening quote
/// (a caller-known-open-quote position, or a delimiter [`is_code_byte`]/`scan_spans` found
/// by scanning). Returns `None` if the literal never closes before `text` ends.
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, read_string_literal};
///
/// let text = r#"path: 'vendor/git: "cache"', git: "https://real.example/r""#;
/// let literal = read_string_literal(text, 6, ScanSyntax::Ruby).unwrap();
/// assert_eq!(&text[literal.content], r#"vendor/git: "cache""#);
/// ```
#[must_use]
pub fn read_string_literal(text: &str, at: usize, syntax: ScanSyntax) -> Option<StringLiteral> {
    let quote = text.get(at..)?.chars().next()?;
    let content_start = at + quote.len_utf8();
    let rest = text.get(content_start..)?;
    let content_len = if is_escaped(syntax, quote) {
        find_closing_quote(rest, quote)?
    } else {
        rest.find(quote)?
    };
    let content_end = content_start + content_len;
    Some(StringLiteral {
        content: content_start..content_end,
        end: content_end + quote.len_utf8(),
        quote,
    })
}

/// Returns `line` with its trailing comment (per `syntax`) removed, stopping the search
/// inside any string literal so a comment marker inside a quoted value is never mistaken
/// for a real comment.
///
/// Returns `line` unchanged if no comment is found on it — including when a string
/// literal on the line never closes, since an unterminated literal's `SpanKind::Str` span
/// (see `scan_spans`) absorbs the rest of the line, leaving nothing that could still be
/// classified as a comment.
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, strip_line_comment};
///
/// assert_eq!(
///     strip_line_comment(r#"source: "a#b" # real comment"#, ScanSyntax::Ruby),
///     r#"source: "a#b" "#,
/// );
/// assert_eq!(strip_line_comment("no comment here", ScanSyntax::Ruby), "no comment here");
/// ```
// `span.range.start` is always a char boundary: every span built by `scan_spans` starts
// either at 0, at a `char_indices()` offset from `find_next_marker`, or just past a prior
// span's end (itself always a char boundary by the same argument).
#[allow(clippy::string_slice)]
#[must_use]
pub fn strip_line_comment(line: &str, syntax: ScanSyntax) -> &str {
    scan_spans(line, syntax)
        .into_iter()
        .find(|span| matches!(span.kind, SpanKind::LineComment | SpanKind::BlockComment))
        .map_or(line, |span| &line[..span.range.start])
}

/// Replaces every comment (per `syntax`) in `content` with spaces.
///
/// Preserves both byte length and every `\n` inside a comment — so downstream byte-offset
/// math (LSP position tracking) stays valid whether or not a comment was present, and
/// multi-line block comments do not collapse the lines after them.
///
/// Always returns a full-length buffer, even when `content` has no comments at all —
/// never the untouched original, so callers must not rely on pointer or allocation
/// identity to detect "no comments found".
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, blank_comments};
///
/// let blanked = blank_comments("let x = 1 // comment\nlet y = 2", ScanSyntax::Swift);
/// assert_eq!(blanked, "let x = 1           \nlet y = 2");
/// ```
// Every `span.range` returned by `scan_spans` is a sub-range of `0..content.len()`, so
// indexing `bytes` (the same length as `content.as_bytes()`) with it never panics.
#[allow(clippy::indexing_slicing)]
#[must_use]
pub fn blank_comments(content: &str, syntax: ScanSyntax) -> String {
    let mut bytes = content.as_bytes().to_vec();
    for span in scan_spans(content, syntax) {
        if !matches!(span.kind, SpanKind::LineComment | SpanKind::BlockComment) {
            continue;
        }
        for byte in &mut bytes[span.range] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    // Every replaced byte becomes an ASCII space at its original offset, so a
    // multi-byte UTF-8 sequence inside a comment is never left half-blanked into an
    // invalid encoding — `from_utf8` always succeeds; the fallback is defensive only.
    String::from_utf8(bytes).unwrap_or_else(|_| content.to_string())
}

/// True iff the skip-scan (per `syntax`) visits `byte_idx` as source code — outside every
/// string literal's content and closing delimiter, and outside every comment.
///
/// A string literal's *opening* delimiter counts as code; its content and closing
/// delimiter do not. So a decoy option-like key sitting inside an already-open string
/// (e.g. `git:` inside `path: 'vendor/git: "cache"'`) is correctly reported as non-code,
/// while the same key outside any string is code — this is what lets a caller take the
/// first *code-positioned* regex match on a line instead of rejecting the line outright
/// whenever a decoy match exists anywhere on it.
///
/// Returns `false` for `byte_idx` out of range or not on a char boundary (unreachable
/// from the ASCII key regexes that call this).
///
/// Recomputes `text`'s full classification on every call — checking *one* candidate
/// position on `text` is the right tool. A caller checking many candidate positions on
/// the *same* `text` (e.g. every regex match on one manifest line) should build one
/// [`CodeSpans`] instead: repeatedly rebuilding this classification from scratch, once per
/// candidate, turns an O(text length) scan into O(candidates × text length) — quadratic
/// against adversarial input packed with decoy substrings (#1022 impl-critic C1).
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, is_code_byte};
///
/// let line = r#"gem "x", path: 'vendor/git: "cache"', git: "https://real.example/r""#;
/// let decoy = line.find("git:").unwrap();
/// let real = line.rfind("git:").unwrap();
/// assert_ne!(decoy, real);
/// assert!(!is_code_byte(line, decoy, ScanSyntax::Ruby));
/// assert!(is_code_byte(line, real, ScanSyntax::Ruby));
/// ```
#[must_use]
pub fn is_code_byte(text: &str, byte_idx: usize, syntax: ScanSyntax) -> bool {
    CodeSpans::new(text, syntax).is_code_byte(byte_idx)
}

/// A `text`'s code/string/comment classification (per `syntax`), built once and queried
/// many times.
///
/// The amortized alternative to [`is_code_byte`] for a caller that checks several
/// candidate positions on the *same* `text` — e.g. every regex match a `find_iter`/
/// `captures_iter` pass produces on one manifest line. Build one `CodeSpans` per `text` and
/// call [`CodeSpans::is_code_byte`] for each candidate: the underlying scan runs once
/// (O(text length)) instead of once per candidate, and each query is a binary search
/// (O(log spans)) rather than a full rescan — turning what was an O(candidates × text
/// length) — quadratic under adversarial input — into O(text length + candidates ×
/// log(spans)) (#1022 impl-critic C1).
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{CodeSpans, ScanSyntax};
///
/// let line = r#"gem "x", path: 'vendor/git: "cache"', git: "https://real.example/r""#;
/// let code = CodeSpans::new(line, ScanSyntax::Ruby);
/// let decoy = line.find("git:").unwrap();
/// let real = line.rfind("git:").unwrap();
/// assert!(!code.is_code_byte(decoy));
/// assert!(code.is_code_byte(real));
/// ```
pub struct CodeSpans<'a> {
    text: &'a str,
    spans: Vec<Span>,
}

impl<'a> CodeSpans<'a> {
    /// Classifies all of `text` (per `syntax`) once, up front.
    #[must_use]
    pub fn new(text: &'a str, syntax: ScanSyntax) -> Self {
        Self {
            text,
            spans: scan_spans(text, syntax),
        }
    }

    /// Same contract as [`is_code_byte`], answered against the classification
    /// [`CodeSpans::new`] already built instead of recomputing it.
    ///
    /// `self.spans` covers `0..self.text.len()` contiguously and in order (by
    /// construction in `scan_spans`), so the span containing `byte_idx`, if any, is found
    /// by binary search rather than a linear scan.
    #[must_use]
    pub fn is_code_byte(&self, byte_idx: usize) -> bool {
        if byte_idx >= self.text.len() || !self.text.is_char_boundary(byte_idx) {
            return false;
        }
        let idx = self
            .spans
            .partition_point(|span| span.range.end <= byte_idx);
        self.spans.get(idx).is_some_and(|span| match span.kind {
            SpanKind::Code => true,
            SpanKind::Str => byte_idx == span.range.start,
            SpanKind::LineComment | SpanKind::BlockComment => false,
        })
    }
}

#[cfg(test)]
// Every `literal.content` indexed below comes from `read_string_literal`, whose bounds
// are always char boundaries (see `strip_line_comment`'s justification above).
#[allow(clippy::string_slice)]
mod tests {
    use super::*;

    #[test]
    fn read_string_literal_ruby_double_quoted() {
        let text = r#"source: "https://gems.corp""#;
        let literal = read_string_literal(text, 8, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], "https://gems.corp");
        assert_eq!(literal.end, text.len());
        assert_eq!(literal.quote, '"');
    }

    #[test]
    fn read_string_literal_ruby_single_quoted_ignores_double_quotes_inside() {
        let text = r#"'vendor/git: "cache"'"#;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"vendor/git: "cache""#);
        assert_eq!(literal.end, text.len());
    }

    #[test]
    fn read_string_literal_unterminated_is_none() {
        assert!(read_string_literal(r#""no closing quote"#, 0, ScanSyntax::Ruby).is_none());
    }

    #[test]
    fn read_string_literal_ruby_backslash_escaped_quote() {
        let text = r#""https://o\'brien.example""#;
        // Ruby double-quoted strings only need `"` escaped, but the shared scanner
        // tracks `\` generically, so an escaped `'` inside a `"`-delimited literal is
        // just inert content, not a delimiter at all (Ruby never treats `'` specially
        // inside `"..."`).
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"https://o\'brien.example");
    }

    #[test]
    fn read_string_literal_toml_literal_string_has_no_escapes() {
        let text = r"'C:\Users\x'";
        let literal = read_string_literal(text, 0, ScanSyntax::Toml).unwrap();
        assert_eq!(&text[literal.content], r"C:\Users\x");
    }

    #[test]
    fn strip_line_comment_mismatched_delimiters_falls_through_unchanged() {
        // `read_string_literal` never closes a `"` with a `'` (or vice versa) — an
        // unterminated literal absorbs the rest of the line, so a trailing `#` inside
        // what looks like a comment position is not treated as a comment start.
        let line = r#"source: "foo' # not a comment"#;
        assert_eq!(strip_line_comment(line, ScanSyntax::Ruby), line);
    }

    #[test]
    fn strip_line_comment_toml_escape_aware() {
        // The bug `strip_trailing_toml_comment` had before this migration: a naive,
        // non-escape-aware scan closed the string at the escaped `\"`, then truncated
        // at the `#` that followed inside the still-open literal.
        let line = "description = \"a\\\"# x\"";
        assert_eq!(strip_line_comment(line, ScanSyntax::Toml), line);
    }

    #[test]
    fn blank_comments_preserves_byte_length_for_non_ascii_comment() {
        let content = "value = 1 # héllo wörld 日本語\nvalue2 = 2";
        let blanked = blank_comments(content, ScanSyntax::Toml);
        assert_eq!(blanked.len(), content.len());
        assert!(blanked.starts_with("value = 1 "));
        assert!(blanked.contains("\nvalue2 = 2"));
    }

    #[test]
    fn blank_comments_preserves_newline_inside_block_comment() {
        let content = "let x = 1 /* multi\nline */ let y = 2";
        let blanked = blank_comments(content, ScanSyntax::Swift);
        assert_eq!(blanked.len(), content.len());
        assert!(blanked.contains('\n'));
        assert!(blanked.contains("let y = 2"));
        assert!(!blanked.contains("multi"));
    }

    #[test]
    fn blank_comments_no_comment_returns_full_length_copy() {
        let content = "no comments here";
        assert_eq!(blank_comments(content, ScanSyntax::Ruby), content);
    }

    #[test]
    fn is_code_byte_out_of_range_and_non_boundary_are_false() {
        let text = "hé";
        assert!(!is_code_byte(text, text.len(), ScanSyntax::Ruby));
        assert!(!is_code_byte(text, text.len() + 5, ScanSyntax::Ruby));
        // Byte 2 sits inside the 2-byte UTF-8 encoding of 'é' (which starts at byte 1),
        // not on a char boundary.
        assert!(!is_code_byte(text, 2, ScanSyntax::Ruby));
    }

    #[test]
    fn is_code_byte_true_for_plain_code() {
        assert!(is_code_byte("gem \"x\"", 0, ScanSyntax::Ruby));
    }

    #[test]
    fn is_code_byte_false_inside_comment() {
        let line = "gem \"x\" # comment";
        let hash = line.find('#').unwrap();
        assert!(!is_code_byte(line, hash, ScanSyntax::Ruby));
    }

    #[test]
    fn code_spans_agrees_with_is_code_byte_at_every_byte() {
        // #1022 impl-critic C1: `CodeSpans` is an amortized reimplementation of the same
        // classification `is_code_byte` computes from scratch — every byte position must
        // agree between the two, including span boundaries (the char right after a string
        // literal's opening delimiter, and the char right after a comment/literal ends).
        let line = r#"gem "x", path: 'vendor/git: "cache"', git: "https://real.example/r" # c"#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        for idx in 0..=line.len() {
            assert_eq!(
                code.is_code_byte(idx),
                is_code_byte(line, idx, ScanSyntax::Ruby),
                "byte {idx} disagreed"
            );
        }
    }

    #[test]
    fn code_spans_out_of_range_and_non_boundary_are_false() {
        let text = "hé";
        let code = CodeSpans::new(text, ScanSyntax::Ruby);
        assert!(!code.is_code_byte(text.len()));
        assert!(!code.is_code_byte(text.len() + 5));
        assert!(!code.is_code_byte(2));
    }
}

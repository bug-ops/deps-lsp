//! Shared escape-aware string-literal and comment scanning for manifest raw-text parsers.
//!
//! Four ecosystem parsers scan manifest source text byte-by-byte, skipping over string
//! literals and comments to find or classify code: `deps-bundler`'s Gemfile option
//! extraction, `deps-swift`'s Package.swift comment stripping, `deps-pypi`'s TOML comment
//! stripping, and `deps-gradle`'s DSL/version-catalog completion-context detection. Before
//! this module each did so with its own hand-rolled scanner — one of which (`deps-pypi`'s)
//! did not track backslash escapes at all, truncating a quoted value early at an escaped
//! `"`. This module centralizes that skip-scan behind a `syntax`-parameterized surface
//! ([`crate::quote_scan::ScanSyntax`]), implemented as a single skip loop that advances past
//! whichever comes first: a string literal (read via
//! [`crate::quote_scan::read_string_literal`]) or a comment.
//!
//! The skip-scan delegates all escape-aware closing-quote search to
//! [`crate::fallback_completion::find_closing_quote`] rather than re-implementing it, so
//! there is exactly one escape rule in the workspace, with two exceptions. First, a
//! [`crate::quote_scan::ScanSyntax::Ruby`] `"..."` literal is scanned via a dedicated `#{...}`
//! interpolation-aware helper instead, since Ruby interpolation can nest a string literal using
//! the same quote type as the outer literal — see [`crate::quote_scan::read_string_literal`]'s
//! doc for the full contract and [`crate::quote_scan::ScanSyntax::Ruby`]'s doc for which
//! literals this applies to. Second,
//! [`crate::quote_scan::find_closing_quote_before_comment`] inlines its own copy of the same
//! `backslash_run`/parity check rather than delegating to `find_closing_quote`, since it needs
//! to interleave escape-tracking with comment-marker detection in a single forward pass —
//! a structural requirement `find_closing_quote` itself has no comment awareness to serve, not
//! an accidental duplication. **Use `find_closing_quote` directly** when a string is already
//! known to be open and only its closing quote is needed (e.g. completing inside a string the
//! cursor sits in). **Use this module** when comments are also in play, or when the string's
//! start position is not already known and must be found by scanning — including via
//! [`crate::quote_scan::last_string_literal`], which finds the *last* literal in a text (open
//! or closed) rather than reading one from an already-known position, and
//! [`crate::quote_scan::find_closing_quote_before_comment`], a comment-aware variant of
//! `find_closing_quote` for scanning a partially-typed line.

use crate::fallback_completion::{count_real_quotes_with, find_closing_quote};
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
    /// Ruby (Gemfile) syntax: `"` and `'` string literals, both backslash-escaped; `#` starts
    /// a line comment. Only `"..."` literals interpolate (`#{...}`, tracked by
    /// [`read_string_literal`] via a dedicated helper) — Ruby's `'...'` literals never
    /// interpolate, so `#{` inside one is just literal text, scanned like any other
    /// backslash-escaped content.
    Ruby,
    /// Swift (Package.swift) syntax: `"` string literals, backslash-escaped; `//` starts
    /// a line comment and `/* ... */` a block comment.
    Swift,
    /// TOML syntax: `"` string literals are backslash-escaped; `'` literal strings are
    /// not escaped at all (a `\` inside one is just a literal backslash). `#` starts a
    /// line comment.
    Toml,
    /// Groovy/Kotlin DSL syntax (Gradle build scripts): `"` and `'` string literals, both
    /// backslash-escaped ([`ScanSyntax::Ruby`]'s quote handling); `//` starts a line comment
    /// and `/* ... */` a block comment ([`ScanSyntax::Swift`]'s comment handling). Unlike
    /// Ruby, `?"`/`?'` is not a distinct token, so the `?`-predecessor char-literal check is
    /// never consulted for this variant.
    ///
    /// Known, documented approximations (all pre-existing in this crate's Gradle-specific
    /// scanners this variant replaces, not new regressions):
    /// - Groovy GString interpolation (`"${...}"`) nesting a same-type quote
    ///   (`"${p.get("x")}"`) is not tracked — the Groovy analogue of the Ruby `#{}` problem
    ///   [`read_string_literal`]'s interpolation-aware path solves; a literal reads as
    ///   closing at the inner `"` instead.
    /// - Triple-quoted strings (`'''...'''`, `"""..."""`) are not tokenized; each `'`/`"`
    ///   inside one is read as an ordinary delimiter.
    /// - A Kotlin `'a'` `Char` literal is scanned as a one-character string literal, which is
    ///   harmless for skip-scanning (the content is opaque either way).
    /// - Known, intentional divergence from the crate-local scanner this variant replaces
    ///   (#1174 impl-critic C2): the old scanner tracked one `backslash_run` across the
    ///   *entire* input, so a stray `\` in code position (outside any string) suppressed
    ///   the very next quote as a delimiter (e.g. `impl \"a:b:1.0` read as no open string at
    ///   all); this scanner's escape tracking is scoped to inside a literal, so the same
    ///   input opens a `"` literal there instead. Unreachable from valid Groovy/Kotlin
    ///   syntax (a bare `\` is not valid outside a string literal), and the new answer is
    ///   arguably the more correct one, so this is not treated as a regression.
    Groovy,
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

/// The *last* string literal found while scanning `text` left to right, open or closed —
/// the result of [`last_string_literal`].
///
/// Unlike [`StringLiteral`] (returned by [`read_string_literal`] for a literal whose
/// opening position is already known), this describes a literal found by scanning `text`
/// from its start, and distinguishes a literal that is still open at the end of `text`
/// (`close: None`) from one that closed exactly at `text`'s end (`close: Some(text.len())`)
/// — the distinction a completion handler needs to tell "cursor is inside an unterminated
/// literal" from "cursor sits right after a literal that just closed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannedLiteral {
    /// The delimiter character (`"` or `'`) that opened this literal.
    pub quote: char,
    /// Byte offset of the opening delimiter.
    pub open: usize,
    /// Byte offset just past the closing delimiter, or `None` if the literal runs
    /// unterminated to the end of the scanned text.
    pub close: Option<usize>,
}

/// Scans `text` left to right (per `syntax`) and returns its last string literal, open or
/// closed.
///
/// This is the one a cursor at the end of `text` would be inside, if any, or (when `text`
/// ends outside any string) the last one that closed.
///
/// A quote of the *other* style encountered while inside an open literal is content, not a
/// delimiter — toggling between `'`/`"` as independent alternatives rather than assuming one
/// quote style for the whole text, so a line mixing both styles doesn't have an unrelated
/// quote desync which delimiter actually closes the literal a cursor sits in. A comment (per
/// `syntax`) outside any open literal is skipped, not scanned, so a quote character inside
/// comment text is never mistaken for a literal opener.
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, last_string_literal};
///
/// // Still open at the end of `text` — the cursor sits inside it.
/// let open = last_string_literal(r#"implementation("a:b:1.0"); implementation("c:d:2"#, ScanSyntax::Groovy).unwrap();
/// assert!(open.close.is_none());
///
/// // Closed exactly at `text`'s end.
/// let closed = last_string_literal(r#"version = "1.0""#, ScanSyntax::Toml).unwrap();
/// assert_eq!(closed.close, Some(r#"version = "1.0""#.len()));
/// ```
#[must_use]
pub fn last_string_literal(text: &str, syntax: ScanSyntax) -> Option<ScannedLiteral> {
    scan_spans(text, syntax)
        .into_iter()
        .rev()
        .find_map(|span| match span.kind {
            SpanKind::Str { quote, terminated } => Some(ScannedLiteral {
                quote,
                open: span.range.start,
                close: terminated.then_some(span.range.end),
            }),
            _ => None,
        })
}

/// Forward search for the byte offset of `rest`'s real closing `quote` character.
///
/// Follows `syntax`'s escaping rule, bailing out (returning `None`, same as "no closing
/// quote on this line") as soon as a comment marker (per `syntax`: `//`/`/* */` for
/// [`ScanSyntax::Groovy`]/[`ScanSyntax::Swift`], `#` for [`ScanSyntax::Ruby`] or
/// [`ScanSyntax::Toml`] with `quote == '"'`) is reached, and skipping over a *closed* block
/// comment rather than scanning its content for a coincidental match. A `#` is deliberately
/// **not** a bail marker for [`ScanSyntax::Toml`] with `quote == '\''`: a TOML `'...'`
/// literal string has no escaping at all and permits `#` as ordinary content (unlike a
/// `"..."` basic string, where this heuristic still applies), so bailing there would
/// truncate a legitimately `#`-containing value like `version = '1.0-build#5'`.
///
/// `rest` is the tail of a **partially typed** line already known to sit inside an open
/// literal delimited by `quote` (e.g. from [`last_string_literal`] filtered to `close.is_none()`).
/// A comment marker found there is a hard stop because the trailing text is mid-edit — not
/// because a comment can legitimately appear inside a string (it cannot; a real comment
/// marker inside a closed string is just string content, already handled by
/// [`read_string_literal`]/[`last_string_literal`], which this function is not used for).
/// Callers must only use this where the value being completed cannot legitimately contain
/// the comment marker itself under the bail rule above — a Maven coordinate segment or a
/// double-quoted TOML catalog version literal contains neither `//` nor `#`; a single-quoted
/// TOML literal string is exempted from the `#` rule for the reason above instead of being
/// excluded from this function's use entirely.
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, find_closing_quote_before_comment};
///
/// assert_eq!(
///     find_closing_quote_before_comment(r#"1.0" // trailing"#, '"', ScanSyntax::Groovy),
///     Some(3),
/// );
/// assert_eq!(
///     find_closing_quote_before_comment(r#"1.0 // still typing"#, '"', ScanSyntax::Groovy),
///     None,
/// );
/// ```
#[must_use]
pub fn find_closing_quote_before_comment(
    rest: &str,
    quote: char,
    syntax: ScanSyntax,
) -> Option<usize> {
    let escaped = is_escaped(syntax, quote);
    let mut backslash_run = 0usize;
    let mut chars = rest.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '\\' if escaped => backslash_run += 1,
            '#' if syntax == ScanSyntax::Ruby || (syntax == ScanSyntax::Toml && quote != '\'') => {
                return None;
            }
            '/' if matches!(syntax, ScanSyntax::Groovy | ScanSyntax::Swift) => {
                match chars.peek().copied() {
                    Some((_, '/')) => return None,
                    Some((star_idx, '*')) => {
                        chars.next();
                        // `?`-bail distinguishes "closed" from "unterminated" (the latter
                        // must return `None`, same as any other unresolved comment marker);
                        // `block_comment_end` alone can't make that distinction, so it's
                        // only called below, once a close is already confirmed, to compute
                        // the resume offset instead of re-deriving the same arithmetic here.
                        rest.get(star_idx + 1..).and_then(|s| s.find("*/"))?;
                        let resume_at = block_comment_end(rest, idx);
                        while chars.peek().is_some_and(|&(i, _)| i < resume_at) {
                            chars.next();
                        }
                        backslash_run = 0;
                    }
                    _ => backslash_run = 0,
                }
            }
            _ if ch == quote => {
                let is_real = !escaped || backslash_run.is_multiple_of(2);
                backslash_run = 0;
                if is_real {
                    return Some(idx);
                }
            }
            _ => backslash_run = 0,
        }
    }
    None
}

/// Byte-range classification produced by the internal skip-scan.
#[derive(Debug, Clone, Copy)]
enum SpanKind {
    /// Plain source text, outside any string literal or comment.
    Code,
    /// A string literal, delimiters included.
    Str {
        /// The delimiter character (`"` or `'`) that opened this literal.
        quote: char,
        /// Whether the literal closed before `text` ended — `false` when it runs
        /// unterminated to the end of the scanned text.
        terminated: bool,
    },
    /// A `#`/`//`-style line comment, excluding a trailing newline, if any.
    LineComment,
    /// A Swift/Groovy `/* ... */` block comment, delimiters included.
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
        ScanSyntax::Ruby | ScanSyntax::Toml | ScanSyntax::Groovy => ch == '"' || ch == '\'',
        ScanSyntax::Swift => ch == '"',
    }
}

/// Whether a literal delimited by `quote` under `syntax` is backslash-escaped — false
/// only for TOML's literal `'...'` strings, which read every byte up to the next `'`
/// verbatim.
fn is_escaped(syntax: ScanSyntax, quote: char) -> bool {
    match syntax {
        ScanSyntax::Ruby | ScanSyntax::Swift | ScanSyntax::Groovy => true,
        ScanSyntax::Toml => quote == '"',
    }
}

/// True when the `"`/`'` at `text[at]` is actually Ruby's `?"`/`?'` one-character literal — a
/// self-contained token, not a string-opening delimiter — e.g. the `?"` in `a: ?"` (bug-ops/
/// deps-lsp#1039: a naive quote-toggling scan misreads `?"` as *opening* a string, desyncing
/// quote state for everything after and hiding real brackets/option keys from bracket-depth
/// tracking that assumes it can trust that state).
///
/// Heuristic, matching Ruby's real "expression expected" lexer state closely enough for manifest
/// scanning without a full Ruby lexer: fires only when `?` is immediately followed (no space) by
/// the quote character, **and** the last non-whitespace character before `?` — skipping over any
/// run of plain spaces/tabs, so a space right before `?` never hides what actually precedes it —
/// is one that unambiguously starts a fresh Ruby expression (`,` `(` `[` `{` `=` `>` `<` `|` `&`
/// `~` `+` `-` `*` `/` `%` `^` `:` `;` `\n`, or nothing at all — start of text). Any other
/// preceding token means a *value* already sits there, putting `?` in ternary-operator position
/// instead (`cond ? "a" : "b"`, the unspaced `cond?"a":"b"`, or a ternary whose condition is
/// itself a string literal like `"a" ? "b" : "c"`), where the following quote is a genuine string
/// delimiter, not a character literal.
///
/// Allowlist-based, not a blocklist (#1039 critic finding C4): an earlier blocklist version
/// (reject only when preceded by an identifier char or a closing `)`/`]`/`}`) missed that a
/// *closing quote* or a bare space can also immediately precede `?` in genuine ternary position
/// — `"a"?"..."` (condition is a string literal, no space at all before `?`) and `1 ?"..."`
/// (space before `?`, but the real predecessor past that space is the value `1`) both slipped
/// through the blocklist and had their real string's opening quote misread as a character
/// literal, silently exposing the string's contents as "code" — reopening the exact quote-desync
/// leak class this function exists to close, in the opposite direction. An allowlist cannot make
/// that mistake: it only fires where a value provably cannot already be sitting.
///
/// **`!` is deliberately excluded** (#1039, defense-in-depth — see the round-7 correctness-gate
/// doc correction below; this is *not* fixing a demonstrated false positive against valid Ruby).
/// An earlier version of this doc justified the exclusion by claiming a bang-suffixed value like
/// `save!` puts a following `?` in ternary-operator position, not char-literal position — that
/// claim is factually wrong. Verified with `ruby -c`: both `x.save!?"a"` and `x.save! ?"a"`
/// produce a syntax error ("unexpected character literal"), meaning Ruby's own lexer treats `!`
/// exactly like the other allowlisted punctuation here — it puts `?"`/`?'` in char-literal
/// (expression-begin) position, not ternary — and simply rejects the *result* as invalid in that
/// argument position. So `!` in the allowlist was never a reachable false positive against
/// genuinely valid Ruby; the shape that originally motivated removing it was itself not valid
/// Ruby to begin with.
///
/// `!` stays excluded anyway, but as a conservative simplification rather than a correctness fix:
/// relying on "Ruby will always reject this shape anyway" to justify recognizing a `?"`/`?'` right
/// after `!` as a char literal is fragile — it ties this heuristic's correctness to an assumption
/// about what surrounding Ruby *rejects*, not just what a `?"`/`?'` itself means, which is a
/// larger and more easily invalidated assumption than the other allowlisted characters need. The
/// cost is narrow: a genuine `!?"..."` (logical-NOT applied to a character literal, e.g. `x =
/// !?"a"`) is now a false negative — the quote falls back to being read as a real string
/// delimiter — rather than a demonstrated regression on any currently-valid Ruby input.
///
/// **Scope of the fix — a narrow set of unambiguous punctuation predecessors only.** This closes
/// the `?"`/`?'` desync class when the character before `?` is one of the allowlisted punctuation
/// characters above. A Ruby *keyword* predecessor (`and`, `or`, `not`, `then`, `return`, `when`,
/// `else`, etc. — e.g. `return ?"` or `x = flag ? ?a : ?b`, where `?"`/`?a` right after
/// `return`/`?`/`:` still legitimately opens a character literal) is not in the allowlist and so
/// is not recognized, meaning a genuine char-literal position right after one of those keywords
/// still desyncs quote state today. Ruby's real `?X` disambiguation is a lexer-state decision
/// (`EXPR_BEG`/`EXPR_ARG` vs `EXPR_END`) plus a spacing rule — no character-class test of a single
/// preceding byte can fully decide it, keyword or punctuation; closing the keyword-predecessor
/// case (along with `%q`/`%w` percent-literals, regex literals, and heredocs — the other Ruby
/// literal forms [`ScanSyntax::Ruby`] does not tokenize) needs real token-level lexing, not
/// another allowlist entry. Tracked as a known, documented gap rather than attempted here — see
/// bug-ops/deps-lsp#1039's follow-up discussion; every such vector still requires the Gemfile to
/// already contain unusual/invalid-for-this-scanner Ruby, so it grants no capability beyond what
/// a plain, valid `source: "evil"` already would.
///
/// Only ever called for [`ScanSyntax::Ruby`] — `?"` is not a distinct token in Swift or TOML.
fn is_char_literal_quote(text: &str, at: usize) -> bool {
    let Some('?') = text.get(..at).and_then(|s| s.chars().next_back()) else {
        return false;
    };
    let question_at = at - '?'.len_utf8();
    let before = text.get(..question_at).unwrap_or_default();
    let trimmed = before.trim_end_matches([' ', '\t']);
    trimmed.is_empty()
        || trimmed.ends_with([
            ',', '(', '[', '{', '=', '>', '<', '|', '&', '~', '+', '-', '*', '/', '%', '^', ':',
            ';', '\n',
        ])
}

/// Finds the first delimiter or comment-start marker in `text` at or after `from`.
fn find_next_marker(text: &str, from: usize, syntax: ScanSyntax) -> Option<(usize, Marker)> {
    let rest = text.get(from..)?;
    for (offset, ch) in rest.char_indices() {
        if is_delimiter(ch, syntax) {
            if syntax == ScanSyntax::Ruby && is_char_literal_quote(text, from + offset) {
                continue;
            }
            return Some((from + offset, Marker::Delim));
        }
        match syntax {
            ScanSyntax::Ruby | ScanSyntax::Toml => {
                if ch == '#' {
                    return Some((from + offset, Marker::LineComment));
                }
            }
            ScanSyntax::Swift | ScanSyntax::Groovy => {
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
            Marker::Delim => {
                let literal = read_string_literal(text, marker_at, syntax);
                let terminated = literal.is_some();
                // `literal.quote` is reused on the closed path; the unterminated path (no
                // `StringLiteral` to read it from) falls back to the same lookup directly.
                let quote = literal.as_ref().map_or_else(
                    || {
                        text.get(marker_at..)
                            .and_then(|s| s.chars().next())
                            .unwrap_or('"')
                    },
                    |l| l.quote,
                );
                let end = literal.map_or(text.len(), |literal| literal.end);
                (end, SpanKind::Str { quote, terminated })
            }
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

/// Finds the byte length of a Ruby string literal's content, given `rest` (the text
/// immediately after the opening `quote`) — interpolation-aware, unlike the generic
/// [`find_closing_quote`], since Ruby's `#{...}` interpolation can embed a nested string
/// literal using the *same* quote type as the outer literal (`"https://#{ENV["CREDS"]}@..."`
/// — closing on the first same-type quote, as a naive scan would, truncates the value right
/// there (#1041)).
///
/// Three-tier chain: [`find_ruby_closing_quote_primary`], then
/// [`find_ruby_closing_quote_fallback`] when the primary pass can't resolve a close, then
/// [`find_ruby_closing_quote_naive`] as a final, quote-blind resort that never fails on input
/// the pre-#1047 baseline could resolve — see each function's doc for what it covers and why
/// the next is needed.
fn find_ruby_closing_quote(rest: &str, quote: char) -> Option<usize> {
    find_ruby_closing_quote_primary(rest, quote)
        .or_else(|| find_ruby_closing_quote_fallback(rest, quote))
        .or_else(|| find_ruby_closing_quote_naive(rest, quote))
}

/// Primary pass behind [`find_ruby_closing_quote`]: tracks `#{` … `}` interpolation-depth (as
/// a counter, so nested interpolation like `#{a["b#{c}"]}` closes correctly) and suspends the
/// outer-quote check for its extent. While inside an interpolation span, a `'`/`"` opens a
/// *nested* string whose own `{`/`}` are then content, not depth markers (`#{ENV["A}B"]}`) —
/// otherwise the nested string's `}` would drop `interpolation_depth` early and its own
/// closing quote would be misread as the outer literal's terminator (the same #1041 leak class
/// via a different construct).
///
/// Security regression (critic finding S2, #1041 follow-up): a cross-type nested "string"
/// (`nested_quote` holding the *other* quote character from `quote`) that is actually a regex
/// or character literal's lone quote-shaped byte (`/'/`, `?'`) does not reliably fail to close
/// — if a *later, unrelated* occurrence of that same character happens to appear further down
/// `rest` (e.g. inside a completely different option's value on the same line), the latch
/// closes there instead, silently absorbing everything in between (including a real `}` that
/// should have ended the interpolation) as swallowed "nested string content". The result was a
/// `Some` too far past the literal's true end rather than a clean scan failure, so the
/// `find_ruby_closing_quote` fallback (triggered only by `None`) never engaged. Guarded here by
/// aborting — returning `None` so [`find_ruby_closing_quote_fallback`] takes over — the moment
/// `quote` itself (the *outer* literal's own delimiter) is seen while a *cross-type* nested
/// quote is still open: a well-formed cross-type nested string (`ENV['X']` inside a `"..."`
/// literal) has no structural reason to contain the outer literal's own quote character before
/// its own close, so seeing one there is treated as proof the nested-quote assumption doesn't
/// hold here — even though it may still hold in general (the fallback pass resolves those
/// cases, see its doc). This can never misfire for a *same-type* nested string (`nq == quote`):
/// there, any occurrence of `quote` always satisfies the `ch == nq` arm first and closes the
/// nested span normally instead of reaching this check.
fn find_ruby_closing_quote_primary(rest: &str, quote: char) -> Option<usize> {
    let mut chars = rest.char_indices().peekable();
    let mut interpolation_depth: u32 = 0;
    let mut nested_quote: Option<char> = None;
    while let Some((idx, ch)) = chars.next() {
        if interpolation_depth > 0 {
            if let Some(nq) = nested_quote {
                if ch == '\\' {
                    chars.next();
                } else if ch == nq {
                    nested_quote = None;
                } else if ch == quote {
                    return None;
                }
                continue;
            }
            if ch == '\'' || ch == '"' {
                nested_quote = Some(ch);
                continue;
            }
            match ch {
                '{' => interpolation_depth += 1,
                '}' => interpolation_depth -= 1,
                _ => {}
            }
            continue;
        }
        if ch == '\\' {
            chars.next();
            continue;
        }
        if ch == '#' && chars.peek().is_some_and(|&(_, next)| next == '{') {
            chars.next();
            interpolation_depth = 1;
            continue;
        }
        if ch == quote {
            return Some(idx);
        }
    }
    None
}

/// Looks ahead from `start` (just past a candidate nested-quote opener `nq`, met while
/// [`find_ruby_closing_quote_fallback`] is inside an open interpolation and already cleared by
/// its lexical `/`/`?`-predecessor gate) for `nq`'s escape-aware matching close via
/// [`find_closing_quote`], and decides whether to trust the span in between as genuine
/// nested-string content (so its `{`/`}` are skipped as content, not counted as depth markers).
///
/// This is a *second* gate, not the sole trust signal (#1047 follow-up round 2: neither
/// direction of this parity check is a proof on its own — see the caller's doc for the lexical
/// gate that runs first). The signal here is the parity of how many *real* (non-escaped, via
/// [`count_real_quotes_with`] — matching [`find_closing_quote`]'s own escape rule) times the
/// *outer* literal's own `quote` character appears inside the candidate span: an odd count
/// (including exactly one) is what genuine nested content containing the outer delimiter
/// verbatim looks like (`'}a"b'` inside a `"..."` literal — the outer `"` appears once, as
/// plain content, #1047); an even count means a complete `"..."`/`'...'` literal fully opened
/// and closed inside the supposed span — one signature (among others the lexical gate catches
/// instead) of `nq` being a stray non-string quote whose "close" is really some later,
/// unrelated value's own delimiter (the #1041-follow-up S2 latch bug the primary pass's abort
/// exists to dodge). Returns `None` — untrusted — when no close is found at all, or the parity
/// check fails.
///
/// Parity alone is not infallible in *either* direction: a stray quote's candidate span can
/// land on odd parity by chance and get wrongly trusted (#1047 follow-up round 2), or on even
/// parity and get wrongly rejected when genuine (#1047 follow-up round 1, caught by
/// [`find_ruby_closing_quote_naive`]).
///
/// The wrongly-trusted (odd-parity) direction is caught by the caller for a stray quote
/// shaped like a regex or character literal (`/'/`, `?'`) via its lexical gate, and — since
/// #1060 — for one embedded in a `%`-literal (`%r|'|`, `%w[a'b]`) or a `#` line comment via a
/// span-skip that never lets `nested_span_len` see that quote at all.
/// [`find_ruby_closing_quote_naive`] can't help with any of these, since a wrongly-trusted
/// span can still resolve to a `Some`, not just a `None`. Three residual gaps remain, all
/// documented rather than fixed because closing them costs more (in leaked, over-long spans)
/// than the truncation they prevent — see [`find_ruby_closing_quote_fallback`]'s doc for the
/// `%`/`#` gate this reasoning applies to:
/// - Ruby heredocs, a literal form this scanner does not tokenize at all.
/// - String content that happens to look like a `#` comment once this function has already
///   rejected it as a nested string (`ENV["c#d"]` inside `#{...}`) — the `#` there is
///   unconditionally treated as a real comment (#1060 follow-up round 2, critic finding S3).
/// - `%`-literal recognition is predecessor-approximated (an `after_value` heuristic, not real
///   EXPR_BEG/EXPR_ARG lexer state), so a `%` in an ambiguous position can still be mis-skipped
///   (#1060 follow-up round 2, critic finding M3).
fn nested_span_len(rest: &str, start: usize, nq: char, quote: char) -> Option<usize> {
    let close_len = find_closing_quote(rest.get(start..)?, nq)?;
    let content = rest.get(start..start + close_len)?;
    let (quote_count, _) = count_real_quotes_with(content, quote);
    (!quote_count.is_multiple_of(2)).then_some(close_len + nq.len_utf8())
}

/// Maps a Ruby `%`-literal's opening delimiter to its closing delimiter: the four
/// bracket-pair openers nest (`%w[a[b]c]`'s inner `[`/`]` don't close the literal early);
/// every other delimiter (including `%r|...|`'s `|`) closes on its own next unescaped
/// occurrence.
fn percent_literal_closing_delim(open: char) -> char {
    match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        other => other,
    }
}

/// Byte offset in `rest` just past a Ruby `%`-literal's closing delimiter, given
/// `rest[at] == '%'` — `None` when `at` is not actually a `%`-literal opener, so the caller
/// falls through to treating `%` as ordinary content (e.g. the modulo operator in `a % b`).
///
/// Recognizes an optional one-letter literal type — Ruby's full set, `%q`/`%Q` (string),
/// `%w`/`%W` (word array), `%i`/`%I` (symbol array), `%r` (regex), `%s` (symbol), `%x`
/// (command) — immediately followed by a delimiter, or a bare `%<delim>` (`%(...)`, `%{...}`,
/// ...).
/// Requires the delimiter to sit immediately after `%` (or the type letter) with no space —
/// `a % b`'s `%` is followed by a space, which is neither a type letter nor a punctuation
/// delimiter, so it is correctly rejected here. The delimiter itself must be neither
/// alphanumeric nor whitespace, which also rules out `%` inside an identifier.
///
/// An unterminated `%`-literal (its delimiter never closes) absorbs the rest of `rest`,
/// mirroring how an unterminated string literal is handled elsewhere in this module. Ruby
/// heredocs are a distinct literal form this scanner does not tokenize and remain out of
/// scope (see [`find_ruby_closing_quote_fallback`]'s doc).
fn percent_literal_end(rest: &str, at: usize) -> Option<usize> {
    let after_percent = at + '%'.len_utf8();
    let mut chars = rest.get(after_percent..)?.char_indices();
    let (_, first) = chars.next()?;
    let (open_offset, open) =
        if matches!(first, 'r' | 'q' | 'Q' | 'w' | 'W' | 'i' | 'I' | 's' | 'x') {
            chars.next()?
        } else {
            (0, first)
        };
    if open.is_alphanumeric() || open.is_whitespace() {
        return None;
    }
    let close = percent_literal_closing_delim(open);
    let body_start = after_percent + open_offset + open.len_utf8();
    let mut depth = 1u32;
    let mut body_chars = rest.get(body_start..)?.char_indices();
    while let Some((idx, ch)) = body_chars.next() {
        // Delimiter recognition runs before escape-consumption, so a delimiter that happens
        // to be `\` itself (Ruby permits any non-alphanumeric, non-whitespace delimiter) still
        // closes the literal instead of always being swallowed as an escape.
        if close != open && ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(body_start + idx + close.len_utf8());
            }
        } else if ch == '\\' {
            body_chars.next();
        }
    }
    Some(rest.len())
}

/// Middle tier behind [`find_ruby_closing_quote`], engaged once
/// [`find_ruby_closing_quote_primary`] has already aborted (returned `None`) rather than risk
/// a wrong answer.
///
/// Tracks `#{` … `}` interpolation-depth like the primary pass, but resolves each candidate
/// nested-quote span via two gates instead of the primary pass's char-by-char latch that never
/// finds a close and must abort to get here in the first place (#1047: without this, a `}`
/// inside a genuine nested string — same-type-as-outer or cross-type — was misread as closing
/// the interpolation early, leaking or truncating whatever followed depending on which quote
/// the mis-termination landed on):
///
/// 1. **Lexical gate** (#1047 follow-up round 2): a `'`/`"` immediately preceded by `?` (a
///    Ruby character literal, e.g. `?'`) is never a string opener — an absolute grammar fact.
///    Preceded by `/` it is *usually* a regex literal, not always (`/` is also division), but
///    treating it as never a string opener is still safe here: it only ever widens which
///    candidates fall through to plain brace counting instead of being parity-checked, which
///    the pre-#1047 baseline already did unconditionally for every quote — so this can only
///    recover cases that baseline got right, never regress below it. Either way the quote is
///    never passed to [`nested_span_len`] at all and always falls through to plain brace
///    counting for that character. Without this, a stray regex/char-literal quote whose
///    candidate span happened
///    to land on odd parity (see below) was wrongly trusted, silently swallowing everything up
///    to and past the interpolation's true close as far as some later, unrelated same-type
///    quote — a `Some` too far, which (unlike the `None` failure mode round 1 covers) the
///    [`find_ruby_closing_quote_naive`] tier chained after this one is structurally unable to
///    catch, since `.or_else` only fires on `None`.
/// 2. **Parity gate** ([`nested_span_len`]) for whatever the lexical gate doesn't already rule
///    out.
///
/// The previous character is tracked in `prev` as the byte-by-byte scan proceeds — no extra
/// pass or allocation.
///
/// A backslash at interpolation top level (not yet inside a trusted nested-quote span) is
/// consumed together with the character it escapes, *before* that character is ever considered
/// as a candidate quote opener — both because an escaped quote character is not a real
/// delimiter, and because without this a long run of escaped quotes (`\'\'\'...`) would each
/// independently trigger [`nested_span_len`]'s `O(n)` lookahead, an `O(n²)` blowup on
/// attacker-controlled document text with no size cap (#1047 follow-up C2). The primary pass
/// does not do this at interpolation top level (only inside an already-open nested quote) —
/// harmless in practice (verified on `#{ x.gsub(/\}/, '') }"`), but an intentional divergence
/// between the two passes' otherwise-matching depth tracking.
///
/// Even with both gates, this tier is not proven infallible, so it can still fail to find a
/// close that [`find_ruby_closing_quote_naive`] — chained after it — would have found; unlike
/// that final tier, this one is allowed to return `None`.
///
/// A third mechanism, added for #1060, runs *before* either gate: a `%`-literal
/// (`%r|'|`, `%w[a'b]`, ...) or a `#` line comment met while `interpolation_depth > 0` is
/// skipped as a whole span via [`percent_literal_end`] / [`line_comment_end`] before any
/// quote-shaped byte inside it is ever considered a candidate at all — unlike the lexical
/// gate, which only ever looks at the single character immediately preceding a candidate
/// quote, these two constructs can put a stray apostrophe arbitrarily far past their own
/// opener (`%w[a'b]`'s `'` is preceded by `a`, not `%`/`w`/`[`), so a predecessor-only check
/// cannot catch them; span-skipping sidesteps the candidate check entirely instead of trying
/// to extend it. The `%` half of this skip is additionally gated on `prev` not being a value
/// token (`x%=2` is modulo, not a `%`-literal); the `#` half is deliberately left ungated —
/// see the `after_value` comment at this function's `%`/`#` branches for why the two are not
/// symmetric, verified against a Ruby/Prism oracle (#1060 follow-up round 2). Ruby heredocs
/// are a distinct literal form this scanner does not tokenize and remain out of scope, per
/// this module's top-level doc.
fn find_ruby_closing_quote_fallback(rest: &str, quote: char) -> Option<usize> {
    let mut interpolation_depth: u32 = 0;
    let mut i = 0;
    let mut prev: Option<char> = None;
    while i < rest.len() {
        let ch = rest.get(i..)?.chars().next()?;
        let ch_len = ch.len_utf8();
        if interpolation_depth > 0 {
            if ch == '\\' {
                let escaped = rest.get(i + ch_len..)?.chars().next();
                i += ch_len + escaped.map_or(0, char::len_utf8);
                prev = escaped.or(Some(ch));
                continue;
            }
            // After a value token, `%` is always modulo, never a %-literal opener (critic S1,
            // #1060): gate on `prev` or `x%=2` misreads as a %-literal and swallows text to a
            // later `=`.
            //
            // `#` is deliberately NOT gated the same way (critic S3, #1060 round 2 — corrects
            // this function's earlier doc): Ruby always starts a comment after any predecessor,
            // so gating would wrongly re-admit an apostrophe inside a real comment as a quote
            // candidate. Oracle-verified over 86k Ruby cases: ungated `#` only ever truncates
            // early (safer — see `..._hash_in_rejected_nested_string_is_a_documented_residual_gap`),
            // while gating it leaks text past the literal's true end (credential-retention path,
            // S1/S2 handoff).
            let after_value = matches!(
                prev,
                Some(c) if c.is_alphanumeric() || matches!(c, '_' | ')' | ']' | '}' | '\'' | '"')
            );
            if ch == '#' {
                // `prev = None` is safe here: `line_comment_end` always stops at (never past)
                // `\n`, so the next iteration reprocesses it and sets `prev` correctly before
                // `after_value` is read again; with no trailing `\n`, the loop ends first.
                i = line_comment_end(rest, i);
                prev = None;
                continue;
            }
            if ch == '%'
                && !after_value
                && let Some(end) = percent_literal_end(rest, i)
            {
                i = end;
                // A %-literal always produces a value, so `prev = Some(')')` marks it as such
                // for the next `after_value` check (code-review finding: `prev = None` here let
                // a %-literal's own close be misread as a fresh EXPR_BEG, re-admitting
                // `%w[a]%=2`'s trailing `%` as a literal opener again — reopening S1's leak via
                // a new trigger).
                prev = Some(')');
                continue;
            }
            // Deliberately not `is_char_literal_quote` (#1062): that helper also treats a
            // genuine ternary (`flag?'a'`) as non-opening, which would narrow this gate and
            // re-admit the quote to `nested_span_len`, reopening the wrong-trust direction
            // #1047 round 2 closed. Treating every unspaced `?`-predecessor as non-opening is
            // strictly conservative instead — it only ever widens fallthrough to plain brace
            // counting.
            let is_regex_or_char_literal_quote = matches!(prev, Some('/' | '?'));
            if (ch == '\'' || ch == '"')
                && !is_regex_or_char_literal_quote
                && let Some(span_len) = nested_span_len(rest, i + ch_len, ch, quote)
            {
                i += ch_len + span_len;
                prev = Some(ch);
                continue;
            }
            match ch {
                '{' => interpolation_depth += 1,
                '}' => interpolation_depth -= 1,
                _ => {}
            }
            i += ch_len;
            prev = Some(ch);
            continue;
        }
        if ch == '\\' {
            i += ch_len
                + rest
                    .get(i + ch_len..)?
                    .chars()
                    .next()
                    .map_or(0, char::len_utf8);
            continue;
        }
        if ch == '#' && rest.get(i + ch_len..).is_some_and(|r| r.starts_with('{')) {
            i += ch_len + 1;
            interpolation_depth = 1;
            prev = None;
            continue;
        }
        if ch == quote {
            return Some(i);
        }
        i += ch_len;
    }
    None
}

/// Last-resort tier behind [`find_ruby_closing_quote`]: plain `#{` … `}` brace-depth counting
/// with no quote-awareness at all, byte-for-byte the same scan this module used as its only
/// fallback before #1047's [`nested_span_len`]/[`find_ruby_closing_quote_fallback`] heuristic
/// was added.
///
/// Chained last specifically *because* that heuristic can trust a wrong span (a stray
/// regex/char-literal quote whose candidate span happens to land on odd parity by chance) and
/// then run off the end of `rest` without `interpolation_depth` ever returning to 0 — this tier
/// guarantees [`find_ruby_closing_quote`] never regresses below this module's pre-#1047
/// baseline: for any input that baseline could resolve, this tier resolves it the same way
/// (#1047 follow-up C1).
fn find_ruby_closing_quote_naive(rest: &str, quote: char) -> Option<usize> {
    let mut chars = rest.char_indices().peekable();
    let mut interpolation_depth: u32 = 0;
    while let Some((idx, ch)) = chars.next() {
        if interpolation_depth > 0 {
            match ch {
                '{' => interpolation_depth += 1,
                '}' => interpolation_depth -= 1,
                _ => {}
            }
            continue;
        }
        if ch == '\\' {
            chars.next();
            continue;
        }
        if ch == '#' && chars.peek().is_some_and(|&(_, next)| next == '{') {
            chars.next();
            interpolation_depth = 1;
            continue;
        }
        if ch == quote {
            return Some(idx);
        }
    }
    None
}

/// Reads the string literal starting at `text[at]`, per `syntax`'s quoting rules.
///
/// `text[at]` must be a delimiter character for `syntax` — a precondition, not validated
/// here; callers only reach this from a position already known to be an opening quote
/// (a caller-known-open-quote position, or a delimiter [`is_code_byte`]/`scan_spans` found
/// by scanning). Returns `None` if the literal never closes before `text` ends.
///
/// A `ScanSyntax::Ruby` literal is scanned via a dedicated interpolation-aware helper only
/// when `quote == '"'` — Ruby's `'...'` literals never interpolate (`'#{x}'` is the literal
/// four-character-plus text `#{x}`, not an expression), so treating `#{` specially inside one
/// would misparse valid Ruby (critic finding S1, #1041 follow-up): an unbalanced `#{` in a
/// single-quoted value (e.g. `require: '#{'`) has no matching `}` to close on, so the
/// interpolation-aware scan never finds the literal's real (very next) closing `'`, and the
/// resulting "unterminated literal" absorbs the rest of the line — including any later
/// `source:` option — into one string span, the same public-registry-leak direction #1041
/// itself fixes, via a different construct. Single-quoted Ruby literals, and Swift/TOML (which
/// have no interpolation syntax at all), keep the plain escape-aware (Swift, Ruby's `'...'`,
/// and TOML's `"..."`) or verbatim (TOML's `'...'`) scan via the generic [`find_closing_quote`].
///
/// # Examples
///
/// ```
/// use deps_core::quote_scan::{ScanSyntax, read_string_literal};
///
/// let text = r#"path: 'vendor/git: "cache"', git: "https://real.example/r""#;
/// let literal = read_string_literal(text, 6, ScanSyntax::Ruby).unwrap();
/// assert_eq!(&text[literal.content], r#"vendor/git: "cache""#);
///
/// // Ruby interpolation nesting the outer literal's own quote type (#1041).
/// let text = r#"source: "https://#{ENV["TOKEN"]}@gems.corp/""#;
/// let literal = read_string_literal(text, 8, ScanSyntax::Ruby).unwrap();
/// assert_eq!(&text[literal.content], r#"https://#{ENV["TOKEN"]}@gems.corp/"#);
/// ```
#[must_use]
pub fn read_string_literal(text: &str, at: usize, syntax: ScanSyntax) -> Option<StringLiteral> {
    let quote = text.get(at..)?.chars().next()?;
    let content_start = at + quote.len_utf8();
    let rest = text.get(content_start..)?;
    let content_len = match syntax {
        ScanSyntax::Ruby if quote == '"' => find_ruby_closing_quote(rest, quote)?,
        _ if is_escaped(syntax, quote) => find_closing_quote(rest, quote)?,
        _ => rest.find(quote)?,
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
#[expect(
    clippy::string_slice,
    reason = "span.range.start is always a char boundary: every span built by scan_spans \
              starts either at 0, at a char_indices() offset from find_next_marker, or just \
              past a prior span's end (itself always a char boundary by the same argument)"
)]
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
#[expect(
    clippy::indexing_slicing,
    reason = "every span.range returned by scan_spans is a sub-range of 0..content.len(), so \
              indexing bytes (the same length as content.as_bytes()) with it never panics"
)]
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
            SpanKind::Str { .. } => byte_idx == span.range.start,
            SpanKind::LineComment | SpanKind::BlockComment => false,
        })
    }
}

#[cfg(test)]
#[expect(
    clippy::string_slice,
    reason = "every literal.content indexed below comes from read_string_literal, whose \
              bounds are always char boundaries (see strip_line_comment's justification above)"
)]
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
    fn read_string_literal_ruby_interpolation_same_type_nested_quote_not_truncated() {
        // #1041: a naive scan closes on the first same-type quote it meets, which sits
        // inside the `#{...}` interpolation span here, truncating the value.
        let text = r#""https://#{ENV["TOKEN"]}@gems.corp/""#;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(
            &text[literal.content],
            r#"https://#{ENV["TOKEN"]}@gems.corp/"#
        );
    }

    #[test]
    fn read_string_literal_ruby_nested_interpolation_closes_correctly() {
        // #1041 repro 2: interpolation-depth must be a counter, not a boolean, so a nested
        // `#{c}` inside the outer `#{a["b#{c}"]}` doesn't close the span one `}` early.
        let text = r##""#{a["b#{c}"]}""##;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"#{a["b#{c}"]}"#);
    }

    #[test]
    fn read_string_literal_ruby_interpolation_regex_apostrophe_falls_back_correctly() {
        // A `'` inside `#{...}` that isn't a string delimiter (here, a regex literal) must not
        // latch the nested-quote tracker open forever — the fallback rescan recovers this.
        let text = r##""#{x =~ /'/}""##;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    /// Security regression (critic finding S1, #1041 follow-up): a regex/char-literal quote
    /// stranded inside `#{...}` can also close the nested-quote latch on a *later, unrelated*
    /// occurrence of the same character further down the text (here, another double-quoted
    /// value's own delimiter), rather than failing to close at all — in which case the
    /// nested-quote-aware pass returns a `Some` that reaches (and swallows) past the literal's
    /// true end, instead of the clean `None` the `.or_else` fallback in
    /// [`find_ruby_closing_quote`] is triggered by. Guarded in
    /// `find_ruby_closing_quote_primary` by aborting the moment the *outer* delimiter is seen
    /// while a *cross-type* nested quote is still open.
    #[test]
    fn read_string_literal_ruby_interpolation_regex_apostrophe_does_not_swallow_later_value() {
        let text = r##""#{x =~ /'/}", "https://a'b}c""##;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    /// #1047 (leak direction, as reported): with the outer `"` escaped (`\"`) inside the
    /// nested `'}a\"b'`, the primary pass's own backslash handling inside its nested-quote
    /// latch consumes that escaped quote before ever reaching its cross-type abort check, so
    /// this exact repro resolves on the primary pass alone — pinned here as a regression, but
    /// it does not exercise the fallback (see
    /// `read_string_literal_ruby_fallback_nested_brace_in_cross_type_quote_not_truncated` for
    /// the un-escaped variant that does).
    #[test]
    fn read_string_literal_ruby_leak_repro_with_escaped_outer_quote_resolves_via_primary() {
        let text = r##"gem "p", require: "#{ ENV['}a\"b']}", source: "https://gems.corp/""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_some());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"#{ ENV['}a\"b']}"#);
    }

    /// #1047 (leak direction): the fallback pass must be nested-quote-aware, not just
    /// brace-depth-aware — the `}` inside the cross-type nested `'}a"b'` (no escaping this
    /// time, so the primary pass genuinely aborts and the fallback must resolve it) must not be
    /// misread as closing the interpolation, which would truncate the `require:` value and
    /// leave `source:` misparsed (falling through to the public registry instead of resolving
    /// to `https://gems.corp/`).
    #[test]
    fn read_string_literal_ruby_fallback_nested_brace_in_cross_type_quote_not_truncated() {
        let text = r##"gem "p", require: "#{ ENV['}a"b']}", source: "https://gems.corp/""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"#{ ENV['}a"b']}"#);
    }

    /// #1047 (truncation direction): same root cause as the leak-direction repro above, but
    /// the mis-termination lands on the outer literal's own quote character instead — the
    /// nested `'}a"b'` string's `}` closes the interpolation early, and the very next `"a`
    /// content is then misread as the outer literal's closing quote.
    #[test]
    fn read_string_literal_ruby_fallback_nested_brace_in_same_type_quote_not_truncated() {
        let text = r#"source "https://#{ENV['}a"b']}@gems.corp/" do"#;
        let quote_pos = text.find('"').unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(
            &text[literal.content],
            r#"https://#{ENV['}a"b']}@gems.corp/"#
        );
    }

    /// Direct unit coverage of the fallback pass itself (rather than only through
    /// `read_string_literal`'s `.or_else`), pinning that it resolves the #1047 nested-brace
    /// case correctly even when reached in isolation.
    #[test]
    fn find_ruby_closing_quote_fallback_skips_brace_inside_nested_quote() {
        let rest = r#"https://#{ENV['}a"b']}@gems.corp/" do"#;
        let len = find_ruby_closing_quote_fallback(rest, '"').unwrap();
        assert_eq!(&rest[..len], r#"https://#{ENV['}a"b']}@gems.corp/"#);
    }

    /// The fallback pass must still reject a stray regex/char-literal quote instead of
    /// latching onto a later, unrelated occurrence of the same character (the #1041-follow-up
    /// S2 bug `nested_span_len`'s parity check exists to avoid re-introducing). Must include
    /// the `#{` opener so the scan actually enters `interpolation_depth > 0` and reaches the
    /// parity check (#1047 follow-up S1: a prior version of this test omitted it and passed
    /// vacuously, exercising nothing).
    #[test]
    fn find_ruby_closing_quote_fallback_rejects_unpaired_quote_far_match() {
        let rest = r#"#{x =~ /'/}", "https://a'b}c""#;
        let len = find_ruby_closing_quote_fallback(rest, '"').unwrap();
        assert_eq!(&rest[..len], r"#{x =~ /'/}");
    }

    /// #1047 follow-up C1 (round 1): before the lexical `/`/`?`-predecessor gate was added
    /// (round 2), the fallback pass's parity heuristic alone could land on *odd* parity by
    /// chance for a stray regex-literal apostrophe (one real quote inside `ENV['GEM_HOST']`'s
    /// own value) and wrongly trust it, jumping past the true interpolation close so
    /// `interpolation_depth` never returned to 0 — reintroducing #1047's own leak class one
    /// level up (an apparently-unterminated `require:` swallowing `source:`). The lexical gate
    /// now rules this quote out before parity is ever consulted (the apostrophe is directly
    /// preceded by `/`), so this now resolves within the fallback tier itself; kept as a
    /// regression pin for the original round-1 shape, and the naive tier remains in place as a
    /// backstop for whatever the two gates together still miss.
    #[test]
    fn read_string_literal_ruby_fallback_regex_apostrophe_before_later_odd_parity_value() {
        let text = r##"gem "p", require: "#{x =~ /'/}", source: ENV['GEM_HOST']"##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    /// #1047 follow-up C1 (round 1), second reproducer from the critic: same shape, this time
    /// landing on 3 real quotes (also odd) inside a later `git:` option's single-quoted value —
    /// also now resolved within the fallback tier by the lexical gate.
    #[test]
    fn read_string_literal_ruby_fallback_regex_apostrophe_before_later_odd_parity_value_git_option()
    {
        let text = r##"gem "p", require: "#{x =~ /'/}", source: "https://gems.corp/", git: 'https://git.corp/p.git'"##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    /// #1047 follow-up round 2 (W1-W4): the parity heuristic also fails in the *opposite*
    /// direction from round 1 — a wrongly-trusted span can resolve to a too-long `Some` instead
    /// of `None` whenever *any* later `}` in the rest of the literal brings
    /// `interpolation_depth` back to 0 before the damage is undone. Unlike round 1's `None`
    /// failure, `.or_else` never triggers the naive tier for a wrong `Some`, so these are
    /// structurally invisible to the three-tier chain without the lexical gate. All four are
    /// real Bundler/Ruby syntax with a stray regex/char-literal quote ahead of a later `}`.
    #[test]
    fn read_string_literal_ruby_lexical_gate_w1_install_if_lambda() {
        let text = r##"gem "p", require: "#{x =~ /'/}", install_if: -> { ENV['CI'] }, source: "https://gems.corp/""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    #[test]
    fn read_string_literal_ruby_lexical_gate_w2_hash_literal_option() {
        let text = r##"gem "p", require: "#{x =~ /'/}", git: { url: ENV['U'] }, source: "https://gems.corp/""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    #[test]
    fn read_string_literal_ruby_lexical_gate_w3_brace_in_later_value() {
        let text = r##"gem "p", require: "#{x =~ /'/}", source: ENV['A}B'], x: "q""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ /'/}");
    }

    #[test]
    fn read_string_literal_ruby_lexical_gate_w4_char_literal() {
        let text = r##"gem "p", require: "#{x == ?'}",  install_if: -> { ENV['CI'] }, source: "https://gems.corp/""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x == ?'}");
    }

    /// #1060 repro 1: a `%r|'|` percent-literal regex inside `#{...}` contains an apostrophe
    /// that is not a string-opening quote at all — the fallback's span-skip gate must consume
    /// the whole `%r|...|` construct so this apostrophe never reaches the nested-quote parity
    /// check, rather than only inspecting the single character before it.
    #[test]
    fn read_string_literal_ruby_percent_literal_regex_apostrophe_not_swallowed() {
        let text = r##"gem "p", require: "#{x =~ %r|'| }", install_if: -> { ENV['CI'] }, x: "q""##;
        let quote_pos = text.find("\"#{").unwrap();
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ %r|'| }");
    }

    /// #1060 repro 2: a `%w[a'b]` word-array percent literal, whose apostrophe sits inside the
    /// bracket delimiter body rather than right after the `%w` opener — the span-skip gate
    /// must still find and consume the whole construct.
    #[test]
    fn read_string_literal_ruby_percent_literal_word_array_apostrophe_not_swallowed() {
        let text = r##"gem "p", require: "#{ %w[a'b] }", install_if: -> { ENV['CI'] }, x: "q""##;
        let quote_pos = text.find("\"#{").unwrap();
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{ %w[a'b] }");
    }

    /// #1060 repro 3: a `#` line comment inside `#{...}` containing an apostrophe must be
    /// skipped up to the next newline, never scanned for a quote.
    #[test]
    fn read_string_literal_ruby_hash_comment_apostrophe_not_swallowed() {
        let text =
            "gem \"p\", require: \"#{ # don't\n x }\", install_if: -> { ENV['CI'] }, x: \"q\"";
        let quote_pos = text.find("\"#{").unwrap();
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], "#{ # don't\n x }");
    }

    /// #1060 non-regression: `a % b` (spaced modulo) inside `#{...}` must not be misread as a
    /// `%`-literal opener — the space right after `%` is neither a literal-type letter nor a
    /// punctuation delimiter, so `percent_literal_end` must reject it.
    #[test]
    fn read_string_literal_ruby_percent_modulo_not_misread_as_literal() {
        let text = r##""#{a % b}""##;
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], "#{a % b}");
    }

    /// impl-critic S1 (#1060 follow-up): `%` immediately after a value token (the identifier
    /// `x`, here at EXPR_END) is always the modulo/format operator, never a `%`-literal opener
    /// — `%=` in particular is Ruby's modulo-assign operator, never a literal delimiter.
    /// Without the `after_value` gate, `percent_literal_end` read any non-alphanumeric byte
    /// after a bare `%` as a delimiter, so `x%=2` was misread as a `%`-literal delimited by
    /// `=` and swallowed everything up to the next unrelated `=` — reopening #1060's own
    /// over-long-span leak via a different trigger. `ENV['a"b']` forces the primary tier to
    /// abort so this exercises the fallback tier specifically.
    #[test]
    fn read_string_literal_ruby_fallback_percent_after_value_is_modulo_not_over_long_leak() {
        let text = r##"gem "a", source: "#{ ENV['a"b'] + x%=2 }", install_if: -> { ENV['CI'] == "1" }, git: "https://TOKEN@evil""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"#{ ENV['a"b'] + x%=2 }"#);
    }

    /// Code-review finding (#1060 follow-up, code-review round): a `%`-literal's own close was
    /// resetting `prev` to `None` instead of a value marker, so a `%` immediately following it
    /// (`%w[a]%=2`) was wrongly re-admitted to `percent_literal_end` as a fresh opener,
    /// reopening S1's leak via a new trigger — `%w[a]` produces a value just as much as an
    /// identifier does, so the `%` right after it must also resolve as modulo.
    #[test]
    fn read_string_literal_ruby_fallback_percent_after_percent_literal_close_is_modulo() {
        let text = r##"gem "a", source: "#{ ENV['a"b'] + %w[a]%=2 }", install_if: -> { ENV['CI'] == "1" }, git: "https://TOKEN@evil""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r#"#{ ENV['a"b'] + %w[a]%=2 }"#);
    }

    /// Direct unit coverage of the `after_value` gate itself: `%` right after an identifier
    /// character, with no space at all, must resolve as modulo rather than opening a
    /// `%`-literal delimited by `y`.
    #[test]
    fn find_ruby_closing_quote_fallback_percent_immediately_after_identifier_is_modulo() {
        let rest = "#{x%y}\" tail";
        let len = find_ruby_closing_quote_fallback(rest, '"').unwrap();
        assert_eq!(&rest[..len], "#{x%y}");
    }

    /// impl-critic S2/S3 (#1060 follow-up, second round): pinned known-gap test, not a
    /// regression check — a `#` reached only because the parity gate already rejected the
    /// nested string `ENV["c#d"]` is string CONTENT, not a comment, but this scanner cannot
    /// tell code from string content at this point (no predecessor test separates `x# comment`
    /// from `ENV["c#d"]`, since both have a value predecessor). Verified against a Ruby/Prism
    /// oracle: gating `#` on `after_value` to fix this one case costs ~2193 new over-long
    /// (leak-direction) errors elsewhere across 86k valid-Ruby cases, against only 406 residual
    /// if `#` stays ungated — so `#` is deliberately left ungated, and this construct
    /// truncates the literal early (the safer failure direction) instead. See the `%`/`#`
    /// branch comment in `find_ruby_closing_quote_fallback` and this module's residual-gap doc
    /// on `nested_span_len`, which lists this beside heredocs.
    #[test]
    fn read_string_literal_ruby_fallback_hash_in_rejected_nested_string_is_a_documented_residual_gap()
     {
        let text = r##"gem "a", source: "#{ ENV['a"b'] + ENV["c#d"].map { |v|
  v } + "z" }", git: "ok""##;
        let quote_pos = text.find("\"#{").unwrap();
        assert!(find_ruby_closing_quote_primary(&text[quote_pos + 1..], '"').is_none());
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        let full_value = r#"#{ ENV['a"b'] + ENV["c#d"].map { |v|
  v } + "z" }"#;
        let resolved = &text[literal.content];
        // Truncates before the true end (the safer, non-leaking direction) rather than
        // resolving the full interpolation.
        assert!(resolved.len() < full_value.len());
        assert!(full_value.starts_with(resolved));
    }

    /// impl-critic M1 (#1060 follow-up): `%s` (symbol literal) is Ruby's own type-letter set
    /// but was missing from the allowlist — exact mirror of repro 1's `%r` case.
    #[test]
    fn read_string_literal_ruby_percent_literal_symbol_apostrophe_not_swallowed() {
        let text = r##"gem "p", require: "#{x =~ %s|'| }", install_if: -> { ENV['CI'] }, x: "q""##;
        let quote_pos = text.find("\"#{").unwrap();
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ %s|'| }");
    }

    /// impl-critic M1 (#1060 follow-up): `%x` (command literal) was also missing from the
    /// allowlist — exact mirror of repro 1's `%r` case.
    #[test]
    fn read_string_literal_ruby_percent_literal_command_apostrophe_not_swallowed() {
        let text = r##"gem "p", require: "#{x =~ %x|'| }", install_if: -> { ENV['CI'] }, x: "q""##;
        let quote_pos = text.find("\"#{").unwrap();
        let literal = read_string_literal(text, quote_pos, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], r"#{x =~ %x|'| }");
    }

    /// Direct unit coverage of [`percent_literal_end`]: a bracket-delimited `%`-literal nests
    /// its own delimiter type, so an inner `[`/`]` pair does not close the literal early.
    #[test]
    fn percent_literal_end_handles_nested_brackets() {
        let rest = "%w[a[b]c] tail";
        let end = percent_literal_end(rest, 0).unwrap();
        assert_eq!(&rest[..end], "%w[a[b]c]");
    }

    /// Direct unit coverage of [`percent_literal_end`]: a bare `%<delim>` literal with no
    /// type-letter prefix is still recognized.
    #[test]
    fn percent_literal_end_bare_delimiter_without_type_letter() {
        let rest = "%(hello world) tail";
        let end = percent_literal_end(rest, 0).unwrap();
        assert_eq!(&rest[..end], "%(hello world)");
    }

    /// Code-review finding, low severity (#1060 follow-up, code-review round): a `\`-delimited
    /// `%`-literal (`%\...\`, rare/unidiomatic but syntactically permitted — Ruby allows any
    /// non-alphanumeric, non-whitespace delimiter) must still close on its own delimiter rather
    /// than always having it consumed as an escape.
    #[test]
    fn percent_literal_end_backslash_delimiter_closes() {
        let rest = r"%\a\ tail";
        let end = percent_literal_end(rest, 0).unwrap();
        assert_eq!(&rest[..end], r"%\a\");
    }

    /// Direct unit coverage of [`percent_literal_end`]'s modulo-operator guard.
    #[test]
    fn percent_literal_end_rejects_spaced_percent() {
        assert!(percent_literal_end("% b", 0).is_none());
    }

    /// Direct unit coverage of the naive last-resort tier: pins that it resolves the same,
    /// quote-blind brace-counted close this module always used before #1047's nested-quote
    /// lookahead was added — kept as a backstop the fallback tier's two gates can still fall
    /// through to.
    #[test]
    fn find_ruby_closing_quote_naive_ignores_nested_quotes() {
        let rest = r#"#{ENV["A"]}", source: "https://gems.corp/""#;
        let len = find_ruby_closing_quote_naive(rest, '"').unwrap();
        assert_eq!(&rest[..len], r#"#{ENV["A"]}"#);
    }

    /// #1047 follow-up C2: a long run of escaped quotes inside an interpolation must not
    /// trigger a separate `O(n)` [`nested_span_len`] lookahead per occurrence — each `\'` is
    /// consumed as one escaped unit before ever being considered a candidate quote opener. This
    /// does not assert on timing (flaky in CI); it pins the *correctness* of that escape
    /// handling, which is what makes the `O(n)` behavior possible.
    #[test]
    fn find_ruby_closing_quote_fallback_handles_long_escaped_quote_run_without_misparsing() {
        let escaped_run = r"\'".repeat(2000);
        let rest = format!("#{{ x.gsub(/{escaped_run}/, '') }}\"");
        let len = find_ruby_closing_quote_fallback(&rest, '"').unwrap();
        assert_eq!(&rest[..len], format!("#{{ x.gsub(/{escaped_run}/, '') }}"));
    }

    /// Security regression (critic finding S1, #1041 follow-up): Ruby's `'...'` literals never
    /// interpolate (`'#{x}'` is the literal text `#{x}`, not an expression), so an unbalanced
    /// `#{` inside a single-quoted value (which has no matching `}` to close on) must not be
    /// treated as opening an interpolation span — that misreads the literal's own very next `'`
    /// as still being inside an unclosed interpolation, making the whole literal look
    /// unterminated.
    #[test]
    fn read_string_literal_ruby_single_quoted_never_interpolates() {
        let text = r"'#{'";
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], "#{");
    }

    /// Regression (critic finding M3, #1041 follow-up): a single-quoted Ruby literal containing
    /// a same-type nested quote is not itself a case interpolation-awareness applies to (there
    /// is no interpolation to nest inside), so it must keep resolving via the plain
    /// escape-aware path exactly as before this fix.
    #[test]
    fn read_string_literal_ruby_single_quoted_ignores_hash_brace_content() {
        let text = r"'a #{ b'";
        let literal = read_string_literal(text, 0, ScanSyntax::Ruby).unwrap();
        assert_eq!(&text[literal.content], "a #{ b");
    }

    /// Known limitation, pinned (critic finding M1, #1041 follow-up): an unterminated `#{`
    /// interpolation (invalid Ruby — `ruby -c` rejects it) has no matching `}`, so the
    /// interpolation-aware scan never finds a close and `read_string_literal` reports the
    /// literal as unterminated. Acceptable since the input isn't valid Ruby to begin with; pinned
    /// here so a future change to this area doesn't silently alter the (documented) behavior for
    /// malformed input.
    #[test]
    fn read_string_literal_ruby_unterminated_interpolation_is_none() {
        let text = r##""#{""##;
        assert!(read_string_literal(text, 0, ScanSyntax::Ruby).is_none());
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

    /// Regression (bug-ops/deps-lsp#1039, vector 1): Ruby's `?"` one-character literal must not
    /// be misread as opening a string — the exact critic PoC, confirmed with `ruby -c` and a stub
    /// `gem` method dumping parsed kwargs to show Ruby itself treats `source:` as nested inside
    /// `install_if`'s hash, not a top-level argument.
    #[test]
    fn char_literal_quote_does_not_open_a_string() {
        let line = r#"a: ?", install_if: { b: ?", source: "https://evil.example.com", c: ?" }"#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let brace = line.find('{').unwrap();
        let source_key = line.find("source:").unwrap();
        // The `{` must be seen as code (not swallowed into a bogus string opened by `?"`).
        assert!(code.is_code_byte(brace));
        // `source:` sits inside the (correctly recognized) `install_if` hash, not in a string.
        assert!(code.is_code_byte(source_key));
        // The genuine string value is still read correctly.
        let quote = line[source_key..].find('"').unwrap() + source_key;
        let literal = read_string_literal(line, quote, ScanSyntax::Ruby).unwrap();
        assert_eq!(&line[literal.content], "https://evil.example.com");
    }

    #[test]
    fn char_literal_quote_single_quote_variant_also_recognized() {
        let line = "a: ?', b: 1";
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let b_key = line.find('b').unwrap();
        assert!(code.is_code_byte(b_key));
    }

    #[test]
    fn ternary_with_space_still_opens_a_real_string() {
        // `cond ? "a" : "b"` — a space between `?` and `"` means this is the ternary operator
        // followed by a genuine string literal, not a character literal.
        let line = r#"cond ? "a" : "b""#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let quote = line.find('"').unwrap();
        assert!(code.is_code_byte(quote));
        let literal = read_string_literal(line, quote, ScanSyntax::Ruby).unwrap();
        assert_eq!(&line[literal.content], "a");
    }

    #[test]
    fn unspaced_ternary_after_value_still_opens_a_real_string() {
        // `flag?"a":"b"` — `?` directly follows an identifier (a value), so this is still
        // ternary-operator position, not a character literal, even with no space.
        let line = r#"flag?"a":"b""#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let quote = line.find('"').unwrap();
        assert!(code.is_code_byte(quote));
    }

    /// Regression (#1039 critic finding C4): a ternary whose *condition* is itself a string
    /// literal (`"a"?"..."`, no space at all between the condition's closing quote and `?`) must
    /// not be misread as a character literal — the closing quote right before `?` proves a value
    /// already sits there.
    #[test]
    fn ternary_with_string_condition_and_no_space_still_opens_a_real_string() {
        let line = r#""a"?"b":"c""#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let quote_after_question_mark = line.find('?').unwrap() + 1;
        assert!(code.is_code_byte(quote_after_question_mark));
        let literal =
            read_string_literal(line, quote_after_question_mark, ScanSyntax::Ruby).unwrap();
        assert_eq!(&line[literal.content], "b");
    }

    /// Regression (#1039 critic finding C4): a space before `?` does not by itself mean
    /// character-literal position — `1 ?"..."` is still a ternary (condition `1`), since the
    /// real predecessor past the space is a value, not a fresh-expression punctuation character.
    #[test]
    fn ternary_with_space_but_value_before_it_still_opens_a_real_string() {
        let line = r#"1 ?"b":"c""#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let quote = line.find('"').unwrap();
        assert!(code.is_code_byte(quote));
        let literal = read_string_literal(line, quote, ScanSyntax::Ruby).unwrap();
        assert_eq!(&line[literal.content], "b");
    }

    /// Regression (#1039 critic finding C4): a char literal right after an assignment `=` must
    /// still be recognized (part of the allowlist's operator set), distinct from the ternary
    /// cases above.
    #[test]
    fn char_literal_quote_after_assignment_operator_still_recognized() {
        let line = r#"x = ?", y = 1"#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let y_pos = line.find('y').unwrap();
        assert!(code.is_code_byte(y_pos));
    }

    /// Regression (#1039, `!` excluded from `is_char_literal_quote`'s allowlist — see its doc for
    /// why this is defense-in-depth, not a fix for a reachable false positive on valid Ruby).
    /// Asserting `is_code_byte` on the *first* quote alone does not discriminate this: that
    /// position reads as code either way (an unrecognized-as-delimiter quote is still ordinary
    /// code, and a delimiter's own opening position also counts as code — see [`CodeSpans`]'s
    /// doc), so a prior version of this test passed unchanged whether `!` was allowlisted or not
    /// (tester finding, round-6 re-validation). The real discriminator is whether the SECOND
    /// string (`source:`'s value) is still correctly recognized as string content: if `!` were
    /// wrongly allowlisted, the first quote (right after `!?`) would be skipped as a non-delimiter,
    /// so the *next* quote (`"a"`'s closer) opens a bogus string that swallows `, source: ` and
    /// closes on the quote just before `https:`, leaving the real URL sitting in plain code —
    /// exactly the "content misread as code" failure this whole function exists to prevent.
    #[test]
    fn bang_before_question_mark_does_not_swallow_source_option_into_bogus_string() {
        let line = r#"save!?"a", source: "https://evil.example.com""#;
        let code = CodeSpans::new(line, ScanSyntax::Ruby);
        let url_start = line.find("https").unwrap();
        assert!(
            !code.is_code_byte(url_start),
            "the source: value must stay recognized as string content, not be exposed as code by a bogus string span opened when '!' was (wrongly, defensively excluded now) treated as license for a char literal"
        );
        let url_quote = url_start - 1;
        let literal = read_string_literal(line, url_quote, ScanSyntax::Ruby).unwrap();
        assert_eq!(&line[literal.content], "https://evil.example.com");
    }

    // #1174: `ScanSyntax::Groovy` and `last_string_literal`/`find_closing_quote_before_comment`.

    #[test]
    fn last_string_literal_closed_at_text_end() {
        let text = r#"version = "1.0""#;
        let literal = last_string_literal(text, ScanSyntax::Toml).unwrap();
        assert_eq!(literal.quote, '"');
        assert_eq!(literal.close, Some(text.len()));
    }

    #[test]
    fn last_string_literal_unterminated_is_open() {
        let text = r#"version = "1.0"#;
        let literal = last_string_literal(text, ScanSyntax::Toml).unwrap();
        assert_eq!(literal.quote, '"');
        assert_eq!(literal.open, text.find('"').unwrap());
        assert_eq!(literal.close, None);
    }

    #[test]
    fn last_string_literal_groovy_single_quote_open() {
        let text = "implementation 'com.example:lib:1.0";
        let literal = last_string_literal(text, ScanSyntax::Groovy).unwrap();
        assert_eq!(literal.quote, '\'');
        assert_eq!(literal.close, None);
    }

    #[test]
    fn last_string_literal_groovy_double_quote_open() {
        let text = r#"implementation "com.example:lib:1.0"#;
        let literal = last_string_literal(text, ScanSyntax::Groovy).unwrap();
        assert_eq!(literal.quote, '"');
        assert_eq!(literal.close, None);
    }

    #[test]
    fn last_string_literal_toml_single_quote_no_escape() {
        let text = r"version = 'C:\Users\x";
        let literal = last_string_literal(text, ScanSyntax::Toml).unwrap();
        assert_eq!(literal.quote, '\'');
        assert_eq!(literal.close, None);
    }

    #[test]
    fn last_string_literal_escaped_closing_quote_stays_open() {
        let text = r#"description = "a\""#;
        let literal = last_string_literal(text, ScanSyntax::Toml).unwrap();
        assert_eq!(literal.close, None);
    }

    #[test]
    fn last_string_literal_quote_inside_comment_is_not_a_phantom_literal() {
        // The `'` inside the Groovy `//` comment must not be read as opening a literal.
        let text = "implementation(\"a:b:1.0\") // don't bump";
        let literal = last_string_literal(text, ScanSyntax::Groovy).unwrap();
        assert_eq!(literal.quote, '"');
        assert_eq!(literal.close, Some(text.find(')').unwrap()));
    }

    #[test]
    fn last_string_literal_toml_hash_comment_not_a_phantom_literal() {
        let text = "version = \"1.0\" # a 'note'";
        let literal = last_string_literal(text, ScanSyntax::Toml).unwrap();
        assert_eq!(literal.quote, '"');
        assert_eq!(literal.close, Some(text.find(" #").unwrap()));
    }

    #[test]
    fn last_string_literal_closed_block_comment_is_skipped() {
        let text = r#"implementation("a" /* "x" */ + "b"#;
        let literal = last_string_literal(text, ScanSyntax::Groovy).unwrap();
        assert_eq!(literal.close, None);
        assert_eq!(literal.open, text.rfind('"').unwrap());
    }

    #[test]
    fn last_string_literal_unterminated_block_comment_ends_scan() {
        // An unterminated `/*` absorbs the rest of the text; no literal after it is found.
        let text = r#""a" /* unterminated"#;
        let literal = last_string_literal(text, ScanSyntax::Groovy).unwrap();
        assert_eq!(literal.close, Some(3));
    }

    #[test]
    fn last_string_literal_empty_text_is_none() {
        assert!(last_string_literal("", ScanSyntax::Groovy).is_none());
    }

    #[test]
    fn last_string_literal_no_literal_is_none() {
        assert!(last_string_literal("no strings here", ScanSyntax::Groovy).is_none());
    }

    #[test]
    fn groovy_hash_is_not_a_comment() {
        // `#` has no comment meaning in Groovy — must stay code, unlike Ruby/TOML.
        let line = "implementation(\"a:b:1.0\") # not a comment";
        let code = CodeSpans::new(line, ScanSyntax::Groovy);
        let hash = line.find('#').unwrap();
        assert!(code.is_code_byte(hash));
    }

    #[test]
    fn groovy_double_slash_inside_string_is_not_a_comment() {
        let line = r#"implementation("http://example.com:1.0")"#;
        let code = CodeSpans::new(line, ScanSyntax::Groovy);
        let slash = line.find("//").unwrap();
        // Inside the open string, so it stays non-code content, not a comment start.
        assert!(!code.is_code_byte(slash));
        assert_eq!(strip_line_comment(line, ScanSyntax::Groovy), line);
    }

    #[test]
    fn groovy_line_comment_stripped() {
        let line = r#"implementation("a:b:1.0") // don't bump"#;
        assert_eq!(
            strip_line_comment(line, ScanSyntax::Groovy),
            r#"implementation("a:b:1.0") "#,
        );
    }

    #[test]
    fn groovy_block_comment_blanked() {
        let content = "val x = 1 /* multi\nline */ val y = 2";
        let blanked = blank_comments(content, ScanSyntax::Groovy);
        assert_eq!(blanked.len(), content.len());
        assert!(blanked.contains('\n'));
        assert!(!blanked.contains("multi"));
    }

    #[test]
    fn groovy_both_quote_styles_open_a_literal() {
        let single = last_string_literal("val a = 'x", ScanSyntax::Groovy).unwrap();
        assert_eq!(single.quote, '\'');
        let double = last_string_literal("val a = \"x", ScanSyntax::Groovy).unwrap();
        assert_eq!(double.quote, '"');
    }

    #[test]
    fn find_closing_quote_before_comment_found() {
        assert_eq!(
            find_closing_quote_before_comment(r#"1.0" tail"#, '"', ScanSyntax::Groovy),
            Some(3),
        );
    }

    #[test]
    fn find_closing_quote_before_comment_line_comment_bails() {
        assert_eq!(
            find_closing_quote_before_comment("1.0 // still typing", '"', ScanSyntax::Groovy),
            None,
        );
    }

    #[test]
    fn find_closing_quote_before_comment_hash_bails_under_toml() {
        assert_eq!(
            find_closing_quote_before_comment("1.0 # still typing", '"', ScanSyntax::Toml),
            None,
        );
    }

    #[test]
    fn find_closing_quote_before_comment_hash_is_not_a_comment_under_groovy() {
        // `#` has no comment meaning in Groovy, so it doesn't bail — it's just content, and the
        // scan continues past it to the real closing quote.
        assert_eq!(
            find_closing_quote_before_comment(
                "1.0 # not-a-comment\" tail",
                '"',
                ScanSyntax::Groovy
            ),
            Some(19),
        );
    }

    #[test]
    fn find_closing_quote_before_comment_closed_block_comment_skipped() {
        let rest = r#"1.0" /* "x" */"#;
        assert_eq!(
            find_closing_quote_before_comment(rest, '"', ScanSyntax::Groovy),
            Some(3),
        );
    }

    #[test]
    fn find_closing_quote_before_comment_unterminated_block_comment_bails() {
        assert_eq!(
            find_closing_quote_before_comment("1.0 /* unterminated", '"', ScanSyntax::Groovy),
            None,
        );
    }

    #[test]
    fn find_closing_quote_before_comment_escaped_quote_not_taken() {
        let rest = r#"a\" real" tail"#;
        assert_eq!(
            find_closing_quote_before_comment(rest, '"', ScanSyntax::Groovy),
            Some(8),
        );
    }

    #[test]
    fn find_closing_quote_before_comment_toml_literal_string_has_no_escapes() {
        let rest = r"C:\Users' tail";
        assert_eq!(
            find_closing_quote_before_comment(rest, '\'', ScanSyntax::Toml),
            Some(8),
        );
    }

    /// Code-review finding (#1174/#1175 review round): a TOML `'...'` literal string has no
    /// escaping at all and permits `#` as ordinary content — unlike a `"..."` basic string,
    /// where `#` still bails as a mid-edit comment marker — so a legitimately `#`-containing
    /// single-quoted catalog value (e.g. a build-metadata suffix) must not be truncated.
    #[test]
    fn find_closing_quote_before_comment_toml_single_quoted_hash_is_content_not_comment() {
        let rest = r"1.0-build#5' tail";
        assert_eq!(
            find_closing_quote_before_comment(rest, '\'', ScanSyntax::Toml),
            Some(11),
        );
    }
}

//! Gradle ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Position, Range};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};
use deps_maven::MavenCentralRegistry;

use crate::formatter::GradleFormatter;

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: the three range delimiters
/// `formatter::gradle_version_matches` accepts — `[`/`(` plus Gradle's own reversed-bracket
/// exclusive notation `]1.2,1.5]` (`deps_core::interval::BracketStyle::AllowReversed`,
/// unlike Maven's `Standard`). The trailing dynamic suffix (`1.+`) has no leading operator
/// to strip. Originally left empty, which meant a completion prefix like `"[2.2"` was never
/// stripped down to `"2.2"` and so never prefix-matched any real version (#1137 critic S1).
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &['[', '(', ']'];

/// Which manifest position a Gradle completion request resolved to, or none.
///
/// A crate-local, non-`&'static str` replacement for the hand-rolled context-type return of
/// [`GradleEcosystem::detect_completion_context`] and its `detect_catalog_context`/
/// `detect_dsl_context` helpers (issue #819, same bug class as #793/#118): the dispatch
/// match in [`Ecosystem::generate_completions`]'s override for this crate must be
/// exhaustive over this enum, so adding a new completable position forces a compile error
/// at the match instead of silently falling through a `_ => vec![]` wildcard. `Package` and
/// `Version` do map conceptually to
/// [`deps_core::completion::CompletionContext::PackageName`]/`Version` — the reason this
/// crate keeps its own full override rather than the shared dispatch isn't a missing
/// concept, it's the detection *source*: `detect_completion_context` scans the manifest's
/// raw text (DSL coordinate strings or version-catalog TOML) directly, independent of
/// `parse_result.dependencies()` (deliberately dependency-blind, see
/// `test_generate_completions_version_context_no_dependency_at_position_returns_empty`
/// below), whereas [`deps_core::completion::detect_completion_context`] derives its context
/// from parsed-AST dependency ranges (see that method's default-impl doc).
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GradleCompletionContext {
    /// Cursor is inside a dependency coordinate's version segment.
    Version,
    /// Cursor is inside a dependency coordinate's package/module segment.
    Package,
    /// Cursor is not inside any completable position.
    None,
}

/// [`Ecosystem`] implementation for Gradle (`build.gradle`/`build.gradle.kts`), reusing
/// Maven Central resolution via [`MavenCentralRegistry`].
pub struct GradleEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: GradleFormatter,
    /// Kept alongside `registry` (which owns its own clone, internal to
    /// `MavenCentralRegistry`) for [`Self::fetch_license`]'s independent POM fetch
    /// (issue #660) — that fetch targets a different Maven Central endpoint
    /// (`{coord}/{version}/{artifact}-{version}.pom`) than any `MavenCentralRegistry`
    /// method exposes, so it goes through `crate::license` directly rather than
    /// growing `MavenCentralRegistry`'s own (differently-scoped, `deps-maven`-owned)
    /// public API.
    http_cache: Arc<deps_core::HttpCache>,
}

impl GradleEcosystem {
    /// Creates a Gradle ecosystem instance backed by the given shared HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(Arc::clone(&cache))),
            formatter: GradleFormatter,
            http_cache: cache,
        }
    }

    #[cfg(feature = "lsp-responses")]
    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    // Trait-completeness path for `complete_version` (unreachable from the real `Version`-arm
    // dispatch below, which calls `complete_versions_generic_from` directly with `dep.source()`).
    #[cfg(feature = "lsp-responses")]
    async fn complete_versions(
        &self,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic_from(
            self.registry.as_ref(),
            &self.formatter,
            package_name,
            &deps_core::parser::DependencySource::Registry,
            prefix,
            VERSION_OPERATOR_CHARS,
            freshness,
        )
        .await
    }

    /// Detects completion context for Gradle files at the given position.
    ///
    /// Returns `(context_type, value, range)` where `context_type` is a
    /// [`GradleCompletionContext`]; `value` is the already-typed prefix up to the cursor;
    /// `range` spans the entire existing value being completed, not just up to the
    /// cursor — the whole package coordinate (module/`group:artifact`) for
    /// [`GradleCompletionContext::Package`], or the whole version literal for
    /// [`GradleCompletionContext::Version`] (the latter is also consumed by
    /// [`deps_core::lsp_helpers::dependency_version_range_is_literal`] at the
    /// `Version`-arm call site in [`Ecosystem::generate_completions`]) — and is meaningless
    /// only when `context_type` is [`GradleCompletionContext::None`].
    ///
    /// `position.character` is a UTF-16 code unit offset (LSP spec) and is converted to a
    /// byte offset once via [`deps_core::completion::utf16_to_byte_offset`] before any
    /// slicing, avoiding panics on multi-byte content preceding the cursor (e.g. an accented
    /// character in a `groupId`); the returned `range`'s `character` fields are converted
    /// back to UTF-16 units via [`deps_core::completion::byte_to_utf16_offset`].
    // `col_idx` comes from `utf16_to_byte_offset` (char_indices-based), always a char boundary.
    #[cfg(feature = "lsp-responses")]
    #[allow(clippy::string_slice)]
    fn detect_completion_context<'a>(
        content: &'a str,
        position: Position,
        uri: &Url,
    ) -> (GradleCompletionContext, &'a str, Range) {
        let path = uri.path().to_string();
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        let Some(&line) = lines.get(line_idx) else {
            return (GradleCompletionContext::None, "", Range::default());
        };
        let col_idx = deps_core::completion::utf16_to_byte_offset(line, position.character)
            .unwrap_or(line.len());
        let before_cursor = &line[..col_idx];

        if path.ends_with("libs.versions.toml") {
            detect_catalog_context(before_cursor, line, col_idx, position.line)
        } else if path.ends_with(".gradle.kts") || path.ends_with(".gradle") {
            detect_dsl_context(before_cursor, line, col_idx, position.line)
        } else {
            (GradleCompletionContext::None, "", Range::default())
        }
    }
}

/// Builds an LSP [`Range`] on `line_idx` from a pair of byte offsets into `line`,
/// converting each to a UTF-16 code unit offset via
/// [`deps_core::completion::byte_to_utf16_offset`].
#[cfg(feature = "lsp-responses")]
fn byte_range(line: &str, line_idx: u32, start_byte: usize, end_byte: usize) -> Range {
    Range::new(
        Position::new(
            line_idx,
            deps_core::completion::byte_to_utf16_offset(line, start_byte),
        ),
        Position::new(
            line_idx,
            deps_core::completion::byte_to_utf16_offset(line, end_byte),
        ),
    )
}

/// Finds the byte offset (relative to `before_cursor`) where the current inline-table
/// field starts — right after the last comma that is *not* inside a quoted string.
///
/// An inline-table catalog entry like `lib = { module = "...", version = "..." }` puts
/// multiple `key = "value"` fields on one line; without this, an unscoped `rfind` for
/// "version"/"module" (and the quote-parity check alongside it) can walk back past a
/// comma into an *earlier* field and misidentify which field the cursor is actually in
/// (e.g. treating a cursor inside `module`'s still-open value as "version" context,
/// because "version" appears earlier on the line and the combined quote count happens
/// to be odd).
// Own escape-aware loop, not the shared count_real_quotes/find_closing_quote helpers: needs an
// in_string toggle interleaved with comma-boundary tracking in one forward pass, which those
// whole-segment helpers don't expose mid-scan. Mirrors their backslash-run escape rule (#738
// follow-up) — keep in sync if that rule ever changes.
#[cfg(feature = "lsp-responses")]
fn current_field_start(before_cursor: &str) -> usize {
    let mut in_string = false;
    let mut backslash_run = 0usize;
    let mut field_start = 0;
    for (i, c) in before_cursor.char_indices() {
        match c {
            '\\' => backslash_run += 1,
            '"' => {
                if backslash_run.is_multiple_of(2) {
                    in_string = !in_string;
                }
                backslash_run = 0;
            }
            ',' if !in_string => {
                field_start = i + 1;
                backslash_run = 0;
            }
            _ => backslash_run = 0,
        }
    }
    field_start
}

/// Detects completion context in version catalog files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
// Every offset below derives from `char_indices()` or `find`/`rfind` of an ASCII token, so every
// slice bound is always a char boundary.
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn detect_catalog_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (GradleCompletionContext, &'a str, Range) {
    let cursor = col_idx.min(line.len());
    // Scoped to the current inline-table field so an earlier field on the same line isn't
    // mistaken for the one the cursor is in (see `current_field_start`'s doc).
    let field_start = current_field_start(before_cursor);
    let field = &before_cursor[field_start..];

    // version = "..." or version.ref = "..."
    if let Some(rel_eq_pos) = field.rfind("version")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        // Odd escape-aware quote count means the cursor is inside an unclosed string opened by
        // the last real quote; even means it's past this `version = "..."` entirely.
        && let (quote_count, Some(quote_start)) =
            deps_core::fallback_completion::count_real_quotes(after)
        && !quote_count.is_multiple_of(2)
    {
        // `version.ref = "alias"` names a `[versions]` table alias, not a registry version
        // literal — computing a real range for it would let `dependency_version_range_is_literal`
        // wrongly ACCEPT if the alias name equals its own resolved value (critic follow-up to
        // #931), so this keeps the pre-#931 placeholder range instead, which the guard always
        // rejects. `trim_start()` before the dot check because TOML allows whitespace around `.`
        // (`version . ref = ...`); a bare `starts_with` would miss that and fall into the
        // real-range branch, reintroducing the wrong-direction-accept bug.
        let is_version_ref = after
            .get("version".len()..)
            .is_some_and(|rest| rest.trim_start().starts_with('.'));
        let value_start = field_start + rel_eq_pos + quote_start + 1;
        if value_start <= cursor {
            let range = if is_version_ref {
                Range::default()
            } else {
                // Bound by the cursor, not end-of-line, so an unterminated value doesn't swallow
                // trailing line content (#931 fix; this arm previously always returned
                // `Range::default()`, rejecting every completion here).
                let value_end =
                    deps_core::fallback_completion::find_closing_quote(&line[value_start..], '"')
                        .map_or(cursor, |rel| value_start + rel)
                        .max(cursor);
                byte_range(line, line_idx, value_start, value_end)
            };
            return (
                GradleCompletionContext::Version,
                &line[value_start..cursor],
                range,
            );
        }
    }

    // module = "..."
    if let Some(rel_eq_pos) = field.rfind("module")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        && let (quote_count, Some(quote_start)) =
            deps_core::fallback_completion::count_real_quotes(after)
        && !quote_count.is_multiple_of(2)
    {
        let value_start = field_start + rel_eq_pos + quote_start + 1;
        if value_start <= cursor {
            // Fall back to the cursor, not end-of-line, when unterminated (mirrors
            // `MavenEcosystem::detect_xml_context`'s no-closing-tag fallback).
            let value_end =
                deps_core::fallback_completion::find_closing_quote(&line[value_start..], '"')
                    .map_or(cursor, |rel| value_start + rel)
                    .max(cursor);
            let range = byte_range(line, line_idx, value_start, value_end);
            return (
                GradleCompletionContext::Package,
                &line[value_start..cursor],
                range,
            );
        }
    }

    (GradleCompletionContext::None, "", Range::default())
}

/// One Groovy/Kotlin `'...'`/`"..."` string literal found while scanning left to right,
/// toggling between the two quote characters as independent delimiters instead of
/// assuming one quote style for the whole text (#1168) — so a line mixing both styles
/// (`"a:b:1.0"; implementation 'c:d:2.0`) doesn't have an unrelated `"` earlier on the
/// line desync which character actually closes the `'...'` the cursor is in.
///
/// `close` is the byte offset just past the closing delimiter, or `None` when `text` ends
/// inside this literal (i.e. it's still open at the cursor).
#[cfg(feature = "lsp-responses")]
struct QuoteLiteral {
    quote: char,
    open: usize,
    close: Option<usize>,
}

/// Scans `text` and returns its *last* string literal, open or closed — the one whose
/// delimiter the cursor (at the end of `text`) would be inside, if any, or (when `text`
/// ends outside any string) the last one that closed.
///
/// Escape-aware per [`deps_core::fallback_completion::count_real_quotes_with`]'s rule: an
/// odd run of `\` immediately before a quote escapes it. A quote of the *other* style
/// encountered while inside an open literal is just content, not a delimiter — mirrors
/// how a single-quote-char scan already treats the other quote character as content.
///
/// A `//` or `/* ... */` comment outside any open literal is skipped rather than scanned:
/// otherwise a quote character inside comment text (e.g. an apostrophe in `// don't bump`)
/// is misread as opening a phantom literal (critic finding S1 on #1168's PR — `"` picked
/// line-wide happened to make this parity-even and harmless before that fix; scoping the
/// scan per-literal removed that accident). A `/`/`*` inside an *open* literal is just
/// content (the `open.is_none()` guard below), matching e.g. `"http://example.com"`. An
/// unterminated block comment (no closing `*/` before the end of `text`) is treated like a
/// line comment — nothing after it can be code.
#[cfg(feature = "lsp-responses")]
fn last_quote_literal(text: &str) -> Option<QuoteLiteral> {
    let mut open: Option<(char, usize)> = None;
    let mut last = None;
    let mut backslash_run = 0usize;
    let mut chars = text.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '\\' => backslash_run += 1,
            '/' if open.is_none() => match chars.peek().copied() {
                Some((_, '/')) => break,
                Some((star_idx, '*')) => {
                    chars.next();
                    let Some(body_len) = text.get(star_idx + 1..).and_then(|s| s.find("*/")) else {
                        break;
                    };
                    let resume_at = star_idx + 1 + body_len + "*/".len();
                    while chars.peek().is_some_and(|&(i, _)| i < resume_at) {
                        chars.next();
                    }
                }
                _ => backslash_run = 0,
            },
            '\'' | '"' => {
                let is_real = backslash_run.is_multiple_of(2);
                backslash_run = 0;
                if !is_real {
                    continue;
                }
                match open {
                    Some((q, start)) if q == ch => {
                        last = Some(QuoteLiteral {
                            quote: q,
                            open: start,
                            close: Some(idx + ch.len_utf8()),
                        });
                        open = None;
                    }
                    Some(_) => {}
                    None => open = Some((ch, idx)),
                }
            }
            _ => backslash_run = 0,
        }
    }
    if let Some((quote, start)) = open {
        last = Some(QuoteLiteral {
            quote,
            open: start,
            close: None,
        });
    }
    last
}

/// Forward search for the byte offset of `rest`'s real closing `quote` character, bailing
/// out (returning `None`, same as "no closing quote on this line") as soon as a `//` line
/// comment or an unterminated `/*` block comment is reached, and skipping over a *closed*
/// `/* ... */` block comment rather than scanning its content for a coincidental match.
///
/// `rest` is the tail of the current line starting inside an already-open literal (from
/// [`detect_dsl_context`]'s `open_pos`/`version_start`), and it can extend past the cursor
/// into not-yet-confirmed content — including a trailing comment the user already typed
/// while still mid-editing the coordinate. Without this guard, a quote character inside
/// that comment (e.g. the apostrophe in `// don't forget`, or a quote inside `/* "x" */`)
/// is indistinguishable from the literal's real closing delimiter to a plain
/// escape-aware scan, corrupting the completion range and risking deletion of real
/// comment text on accept (#1168 code review).
///
/// Unlike [`last_quote_literal`]'s backward scan — which must still let `/` stand as
/// ordinary content inside some *other*, unrelated open string (e.g. `"http://..."`) —
/// this function always treats `//`/`/*` as comment syntax, without an `open.is_none()`
/// gate: a Maven coordinate segment (group/artifact/version) never legitimately contains
/// `//`, so there is no real string content this could misclassify here.
#[cfg(feature = "lsp-responses")]
fn find_closing_quote_skip_comments(rest: &str, quote: char) -> Option<usize> {
    let mut backslash_run = 0usize;
    let mut chars = rest.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        match ch {
            '\\' => backslash_run += 1,
            '/' => match chars.peek().copied() {
                Some((_, '/')) => return None,
                Some((star_idx, '*')) => {
                    chars.next();
                    let body_len = rest.get(star_idx + 1..).and_then(|s| s.find("*/"))?;
                    let resume_at = star_idx + 1 + body_len + "*/".len();
                    while chars.peek().is_some_and(|&(i, _)| i < resume_at) {
                        chars.next();
                    }
                    backslash_run = 0;
                }
                _ => backslash_run = 0,
            },
            _ if ch == quote => {
                let is_real = backslash_run.is_multiple_of(2);
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

/// Whether `before_colon` (the text up to, but excluding, a trailing `:` immediately
/// before the cursor's open literal) ends in a *quoted* map key (`'version'`) rather than
/// a ternary/Elvis operand's already-closed string (`"a:b:1.0" :` / `value ?:`, #1160
/// review) — both shapes end in a closing quote, so the distinguishing signal is what
/// sits right before that quoted token's own *opening* delimiter.
///
/// Allowlist, not a blocklist (critic finding S2 on #1168's PR, same rationale as
/// [`deps_core::quote_scan`]'s `is_ruby_char_literal` doc on #1039 finding C4): fires only
/// when that character is `,`/`(`/`[`/`{` (a named-arg separator or list opener), an
/// identifier character (a bare command-style call name immediately preceding the first
/// key, e.g. `implementation 'group': ...`), or nothing at all (the key is the first
/// token on a wrapped continuation line). Any operator character (`?`, `+`, `)`, ...)
/// means a value already sits there — e.g. a ternary's true branch (`cond ? "a" : "b"`) or
/// an arithmetic expression (`c ? p + "a" : "b"`) — so those fall through and are NOT
/// treated as a map key. A blocklist that only excluded `?` missed the latter shape.
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn quoted_key_precedes_colon(before_colon: &str) -> bool {
    let Some(span) = last_quote_literal(before_colon) else {
        return false;
    };
    if span.close != Some(before_colon.len()) {
        return false;
    }
    let before_key = before_colon[..span.open].trim_end();
    before_key.is_empty()
        || before_key
            .ends_with(|c: char| c.is_alphanumeric() || matches!(c, '_' | ',' | '(' | '[' | '{'))
}

/// Detects completion context in Kotlin/Groovy DSL files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
// Every offset below (`open_pos`, `end_rel`, `version_start`) derives from `rfind`/`find` of
// an ASCII `'"'`/`'\''`/`':'` token or `char_indices()`, so every slice bound is always a
// char boundary.
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn detect_dsl_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (GradleCompletionContext, &'a str, Range) {
    let cursor = col_idx.min(line.len());
    // Scoped per-literal (#1168), not line-wide: `quote_char` is whatever delimiter opens
    // the string containing the cursor, found by scanning forward and toggling between
    // `'`/`"` as independent delimiters, rather than picking one quote character for the
    // whole line and checking its parity.
    let Some(open) = last_quote_literal(before_cursor).filter(|span| span.close.is_none()) else {
        return (GradleCompletionContext::None, "", Range::default());
    };
    let quote_char = open.quote;
    let open_pos = open.open;

    // Groovy's named-argument ("map notation") dependency form
    // (`group: 'x', name: 'y', version: 'z'`) puts each field's value in its own standalone
    // quoted literal, with the field name and colon OUTSIDE the quotes — a shape
    // `crate::parser::groovy` doesn't parse into a `Dependency` at all, so its colon-free field
    // values must not be misread as a Package/Version segment of a compact coordinate.
    // Requires the colon to be immediately preceded (after whitespace) by an identifier
    // character or a quoted key (`'version':`, #1168), not just any trailing `:` — a Groovy
    // ternary's or Elvis operator's colon (`cond ? "a:b:1.0" : "c:d:2.0`, `value ?: "a:b:1.0"`)
    // also leaves a trailing `:` before a legitimate compact-coordinate string, but is preceded
    // by a ternary branch or `?`, never a map key (see `quoted_key_precedes_colon`).
    if let Some(before_colon) = before_cursor[..open_pos].trim_end().strip_suffix(':') {
        let before_colon = before_colon.trim_end();
        let is_map_key = before_colon.ends_with(|c: char| c.is_alphanumeric() || c == '_')
            || quoted_key_precedes_colon(before_colon);
        if is_map_key {
            return (GradleCompletionContext::None, "", Range::default());
        }
    }

    // Scoped to the currently open string literal (from `open_pos` to the cursor), not the
    // whole line: a semicolon- or space-joined multi-dependency statement
    // (`implementation("a:b:1.0"); implementation("c:d:2.0")`) would otherwise let an earlier,
    // already-closed dependency's colons leak into this one's colon count and `version_start`
    // computation, causing both a wrong context (Package vs Version) and, in the Version arm,
    // a `value_range` that overspans back into the earlier dependency's text (#1160).
    let in_string_before_cursor = &before_cursor[open_pos + 1..];
    let colon_count = in_string_before_cursor
        .chars()
        .filter(|&c| c == ':')
        .count();

    match colon_count {
        0 | 1 => {
            // Package range covers "group" or "group:artifact", up to a second colon (an
            // already-typed version) if any, else the closing quote; bounded by the cursor when
            // unterminated (mirrors `MavenEcosystem::detect_xml_context`'s fallback).
            let rest = &line[open_pos + 1..];
            let closing_quote_rel = find_closing_quote_skip_comments(rest, quote_char);
            let scan_limit_rel = closing_quote_rel.unwrap_or(cursor - (open_pos + 1));
            let end_rel = rest[..scan_limit_rel]
                .char_indices()
                .filter(|&(_, c)| c == ':')
                .nth(1)
                .map_or(scan_limit_rel, |(i, _)| i);
            let value_end = (open_pos + 1 + end_rel).max(cursor);
            let range = byte_range(line, line_idx, open_pos + 1, value_end);
            (
                GradleCompletionContext::Package,
                &line[open_pos + 1..cursor],
                range,
            )
        }
        _ => {
            let version_start = in_string_before_cursor
                .char_indices()
                .filter(|(_, c)| *c == ':')
                .nth(1)
                .map(|(i, _)| open_pos + 1 + i + 1)
                .unwrap_or(before_cursor.len());
            // Same unterminated-string fallback as the `colon_count 0 | 1` arm above (#931 —
            // this arm previously returned `Range::default()`, rejecting every compact-coordinate
            // completion here).
            let rest = &line[version_start..];
            let closing_quote_rel = find_closing_quote_skip_comments(rest, quote_char);
            let value_end = closing_quote_rel
                .map_or(cursor, |rel| version_start + rel)
                .max(cursor);
            let range = byte_range(line, line_idx, version_start, value_end);
            (
                GradleCompletionContext::Version,
                &line[version_start..cursor],
                range,
            )
        }
    }
}

impl deps_core::ecosystem::private::Sealed for GradleEcosystem {}

impl Ecosystem for GradleEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Gradle
    }

    fn display_name(&self) -> &'static str {
        "Gradle (JVM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &[
            "libs.versions.toml",
            "build.gradle.kts",
            "build.gradle",
            "settings.gradle.kts",
            "settings.gradle",
        ]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Url,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_gradle(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    /// This is a full override, not the shared [`Ecosystem::generate_completions`] default
    /// dispatch: Gradle routes on its own `GradleCompletionContext` DSL/catalog context
    /// (`Self::detect_completion_context`), detected from raw manifest text rather than
    /// [`deps_core::completion::detect_completion_context`]'s parsed-AST dependency ranges
    /// (see `GradleCompletionContext`'s doc for why that source difference — not a missing
    /// concept — is the actual reason this crate can't reuse the shared dispatch). Opting
    /// out of it means this ecosystem takes on #793's wildcard-match obligation itself; see
    /// `deps_core::Ecosystem::generate_completions`'s doc.
    #[cfg(feature = "lsp-responses")]
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            let uri = parse_result.uri();
            let (ctx_type, value, range) = Self::detect_completion_context(content, position, uri);

            // Exhaustive on purpose (#819, same bug class as #793): no wildcard arm.
            match ctx_type {
                GradleCompletionContext::Version => {
                    // #1134: finds+literal-checks the dependency; #1136: complete_versions_generic_from's own gate rejects a non-registry `dep.source()`.
                    match deps_core::completion::literal_version_dependency(
                        parse_result,
                        position,
                        content,
                        range,
                    ) {
                        Some(dep) => {
                            deps_core::completion::complete_versions_generic_from(
                                self.registry.as_ref(),
                                &self.formatter,
                                dep.name(),
                                &dep.source(),
                                value,
                                VERSION_OPERATOR_CHARS,
                                freshness,
                            )
                            .await
                        }
                        None => vec![],
                    }
                }
                GradleCompletionContext::Package => self.complete_package_names(value, range).await,
                GradleCompletionContext::None => vec![],
            }
            .into()
        })
    }

    /// Required by [`Ecosystem`]; called only from this crate's own
    /// [`Self::generate_completions`] override (Gradle does not use the shared default
    /// dispatch — see that method's doc), for the `GradleCompletionContext::Version`
    /// DSL/catalog context.
    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        request: deps_core::completion::CompletionRequest<'a>,
        package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            self.complete_versions(&package_name, &prefix, request.freshness)
                .await
                .into()
        })
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("implementation(\"{name}:{latest}\")"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s (`"group:artifact"`) license at `version` from Maven Central,
    /// following one or more `<parent>` POM hops when the leaf POM declares no
    /// `<licenses>` block of its own (issue #660/#688/#692). See
    /// `crate::license::fetch_license`.
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        Box::pin(crate::license::fetch_license(
            &self.http_cache,
            name,
            version,
        ))
    }

    /// Gradle's Maven Central POM `<licenses><license><name>` is free text, not an SPDX
    /// identifier — see [`deps_core::LicenseSource::PomFreeText`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::PomFreeText
    }
}

#[cfg(test)]
// Fixtures are single-line ASCII (or explicitly UTF-16-tested) literals with hand-computed byte offsets.
#[allow(clippy::string_slice)]
mod tests {
    use super::*;

    fn make_cache() -> Arc<deps_core::HttpCache> {
        Arc::new(deps_core::HttpCache::new())
    }

    // #758: exact-value `Ecosystem` conformance, replacing the individual hand-written tests.
    // `no_lockfile_support: true;` (#782 gap 2) covers Gradle having no lock file format.
    deps_core::ecosystem_conformance! {
        mod gradle_ecosystem_conformance;
        build: GradleEcosystem::new(make_cache());
        ty: GradleEcosystem;
        id: "gradle";
        display_name: "Gradle (JVM)";
        manifest_filenames: &[
            "libs.versions.toml",
            "build.gradle.kts",
            "build.gradle",
            "settings.gradle.kts",
            "settings.gradle",
        ];
        no_lockfile_support: true;
    }

    // #784: `build_arc:` against the real `Ecosystem::registry()` wiring, not a `build:` fixture
    // constructing `MavenCentralRegistry` directly — that would only duplicate deps-maven's own
    // test and prove nothing gradle-specific. `req: "*"` exercises the wildcard branch the real
    // LSP fetch call sites actually take.
    deps_core::registry_conformance! {
        mod gradle_registry_conformance;
        build_arc: GradleEcosystem::new(make_cache()).registry();
        select_latest_matching: {
            versions: vec![
                Box::new(deps_maven::MavenVersion::new("3.2.0".into())),
                Box::new(deps_maven::MavenVersion::new("3.1.0".into())),
            ];
            req: "*";
            expected_index: 0;
        };
    }

    // #758: shared completion-prefix-length guard conformance, also closing the missing
    // max-length case deps-gradle previously lacked.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_guard_conformance! {
        mod gradle_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + '_>,
        > {
            Box::pin(async move {
                deps_core::completion::complete_package_names_generic(
                    registry,
                    &prefix,
                    20,
                    Range::default(),
                )
                .await
            })
        };
    }

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
    // own doc comment (`formatter::gradle_version_matches`'s range-delimiter set, including
    // the reversed-bracket `]` form), so an edit to one without the other fails loudly
    // instead of silently degrading completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod gradle_operator_chars_conformance;
        ecosystem: "gradle";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &['[', '(', ']'];
    }

    #[tokio::test]
    async fn test_parse_manifest_kts() {
        // Held per `fs_probe::snapshot_guard`'s doc: `parse_manifest` transitively touches
        // fs_probe (via `load_gradle_properties`), and every such test in this file must hold it.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"junit:junit:4.13.2\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_cursor_at_start() {
        // version = "|1.0.0"
        let line = r#"version = "1.0.0""#;
        // before_cursor = `version = "`, cursor at 11 (right after '"')
        let col = 11;
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "");
        // #931: range must span the whole literal value ("1.0.0"), not Range::default().
        assert_eq!(
            range,
            Range::new(Position::new(0, 11), Position::new(0, 16))
        );
        assert_eq!(&line[11..16], "1.0.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_cursor_mid() {
        // version = "1.0|.0"
        let line = r#"version = "1.0.0""#;
        // value_start = 11, "1.0" = 3 chars, cursor at 14
        let col = 14;
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
        // #931: the range covers the whole literal value regardless of cursor position.
        assert_eq!(
            range,
            Range::new(Position::new(0, 11), Position::new(0, 16))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_cursor_at_end() {
        // version = "1.0.0|"
        let line = r#"version = "1.0.0""#;
        // value_start = 11, "1.0.0" = 5 chars, cursor at 16
        let col = 16;
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0.0");
        assert_eq!(
            range,
            Range::new(Position::new(0, 11), Position::new(0, 16))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_module_prefix() {
        // module = "com.ex|ample:lib"
        let line = r#"module = "com.example:lib""#;
        // value_start = 9 + 1 = 10 (after `module = "`), "com.ex" = 6 chars, cursor at 16
        let col = 16;
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.ex");
        // range replaces the whole quoted value ("com.example:lib"), not just "com.ex"
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, 25))
        );
        assert_eq!(&line[10..25], "com.example:lib");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_closed_value_with_escaped_quote_stays_closed() {
        // version = "a\"b" | — cursor past a properly closed value that contains an
        // escaped quote. A naive raw `"` count sees 3 quote characters (odd, "still
        // open") and wrongly reports a "version" context whose value is the trailing
        // space; the escape-aware count correctly sees 2 real quotes (even, closed) and
        // reports no completion context at all (#738 follow-up).
        let line = "version = \"a\\\"b\" ";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_module_escaped_quote_does_not_close_string() {
        // module = "com.example\"extra:lib — an escaped quote inside the still-open
        // value must not be miscounted as closing the string (#738): a naive raw `"`
        // count sees 2 quote characters (even, "closed") while the escape-aware count
        // correctly sees 1 real quote (odd, still open).
        let line = "module = \"com.example\\\"extra:lib";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        let value_start = line.find('"').unwrap() + 1;
        assert_eq!(v, &line[value_start..col]);
        assert_eq!(
            range,
            Range::new(
                Position::new(0, value_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_package_cursor_mid() {
        // implementation("junit|:junit:4.13.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // open_pos=15 ('"'), "junit" = 5 chars, cursor at 21 (after 5 chars)
        // before_cursor = `implementation("junit`
        let col = 21;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "junit");
        // range replaces the whole "group:artifact" coordinate ("junit:junit"),
        // stopping before the version separator, not just the already-typed "junit"
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 27))
        );
        assert_eq!(&line[16..27], "junit:junit");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_package_no_version_yet() {
        // implementation("junit|") — no colon typed yet, string not closed by a version
        let line = r#"implementation("junit")"#;
        let col = 21; // right after "junit"
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "junit");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 21))
        );
        assert_eq!(&line[16..21], "junit");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_escaped_quote_in_earlier_group_does_not_block_completion() {
        // implementation "a\"b", "com.foo:ba — the escaped quote inside the first,
        // already-closed string argument must not desync the quote-parity check and
        // suppress completion on the second, still-open string (#738). A naive raw `"`
        // count sees 4 quote characters total (even, "no open string") and reports no
        // completion context at all.
        let line = "implementation \"a\\\"b\", \"com.foo:ba";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.foo:ba");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_apostrophe_inside_double_quoted_package_name() {
        // implementation "com.o'reilly:li — an apostrophe inside a double-quoted
        // string must not be mistaken for a single-quote delimiter (#738).
        let line = r#"implementation "com.o'reilly:li"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.o'reilly:li");
    }

    // #1168: a completed double-quoted string earlier on the line must not stop
    // completion inside a still-open single-quoted string later on the same line — the
    // scanner now toggles between both quote styles per-literal instead of picking one
    // quote character for the whole line (previously the even `"` count from the closed
    // `"x"` returned "no completion context" here, even though the cursor sits in an
    // unrelated, still-open `'...'`).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_mixed_quote_types_on_one_line_resolves_open_literal() {
        // exclude module: "x"; implementation 'com.baz:qu|
        let line = r#"exclude module: "x"; implementation 'com.baz:qu"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.baz:qu");
    }

    // #1168 Gap 1: the same fix must also apply when the SECOND (not just the last)
    // literal on the line is closed with the other quote style, and the cursor sits in a
    // third, still-open literal further right — proving the scan isn't limited to a
    // two-literal line.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_mixed_quote_styles_joined_line_scopes_version_to_last_dependency() {
        // implementation "a:b:1.0"; implementation 'c:d:2.0|
        let line = r#"implementation "a:b:1.0"; implementation 'c:d:2.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "2.0");
        let expected_start = line.rfind("2.0").unwrap();
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1168 Gap 2: a QUOTED map key (`'version': '1.0'`) must be withheld the same way
    // the unquoted form (`version: '1.0'`) already is — the map-notation guard's
    // alphanumeric/underscore check alone misses this, since a quoted key's character
    // before the colon is `'`, not an identifier character.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_quoted_map_notation_version_value_withholds_completion() {
        // implementation 'group': 'com.example', 'version': '1.0|
        let line = r"implementation 'group': 'com.example', 'version': '1.0";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1168 Gap 2 follow-up: the quoted-key guard must not misfire on a quoted key mixed
    // with an unquoted one on the same map-notation line.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_quoted_map_notation_group_value_withholds_completion() {
        // implementation 'group': 'com.exam|
        let line = "implementation 'group': 'com.exam";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1168 critic finding S1 (significant regression): an apostrophe inside a trailing
    // `//` comment must not be read as opening a phantom literal. Nothing strips comments
    // before `detect_dsl_context` runs, so the per-literal scan has to skip them itself.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_apostrophe_in_trailing_line_comment_no_phantom_literal() {
        // implementation "a:b:1.0" // don't bump|
        let line = r#"implementation "a:b:1.0" // don't bump"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1168 critic finding S1 follow-up: the same class pre-dates this fix for a
    // single-quoted line too (an unrelated accident of even quote parity previously hid
    // it there) — the comment guard must close it for both quote styles.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_apostrophe_in_trailing_line_comment_single_quoted_line() {
        // implementation 'a:b:1.0' // don't bump|
        let line = "implementation 'a:b:1.0' // don't bump";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1168 critic finding S1 follow-up: a `/* ... */` block comment containing a quote
    // character must be skipped the same way, and — unlike a line comment — code after its
    // closing `*/` on the same line must still be scanned normally.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_apostrophe_in_block_comment_no_phantom_literal_and_resumes_after() {
        // implementation /* don't */ "com.exam|
        let line = "implementation /* don't */ \"com.exam";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.exam");
    }

    // #1168 critic finding S2 (minor regression): a ternary true-branch that ends in a
    // literal but is preceded by an operator (not just `?`) must still resolve normally —
    // `quoted_key_precedes_colon` was a blocklist that only excluded `?`, so an operand
    // like `p + "a"` was misclassified as a quoted map key.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_ternary_branch_after_operator_still_resolves_version() {
        // implementation(x = c ? p + "a" : "g:a:1.0|
        let line = r#"implementation(x = c ? p + "a" : "g:a:1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    // #1168 code review: `find_closing_quote`'s forward scan (past the cursor, looking for
    // the literal's real closing delimiter) had no comment awareness — a genuinely
    // unterminated coordinate followed by a trailing `//` comment that happens to contain a
    // quote character (e.g. inside `"notes"`) had that quote mistaken for the real closer,
    // corrupting the Version range into comment text.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_forward_scan_stops_at_trailing_line_comment() {
        // implementation("com.example:foo:1.0| // see "notes" here
        let line = r#"implementation("com.example:foo:1.0 // see "notes" here"#;
        let expected_start = line.find("1.0").unwrap();
        let col = expected_start + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1168 code review follow-up: the same forward-scan comment guard applies to the
    // Package arm (`rest` there also scans past the cursor to the end of the line).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_package_forward_scan_stops_at_trailing_line_comment() {
        // implementation("com.example:fo| // see "notes" here
        let line = r#"implementation("com.example:fo // see "notes" here"#;
        let expected_start = line.find('"').unwrap() + 1;
        let col = line.find(":fo").unwrap() + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.example:fo");
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1168 code review follow-up: a `/* ... */` block comment containing a quote character
    // (e.g. inside `"hi"`) must be skipped wholesale, not scanned for a coincidental match —
    // with nothing legitimate following it here, the search still correctly reports "no
    // closing quote found" rather than grabbing the quote inside the comment.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_forward_scan_skips_block_comment_with_quote_inside() {
        // implementation("com.example:foo:1.0| /* say "hi" */ trailing
        let line = r#"implementation("com.example:foo:1.0 /* say "hi" */ trailing"#;
        let expected_start = line.find("1.0").unwrap();
        let col = expected_start + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1168 code review follow-up: the team-lead's exact repro — a single-quoted literal
    // (not just double-quoted) whose trailing `//` comment contains an apostrophe matching
    // its OWN delimiter character (`developer's`), proving the comment guard isn't
    // accidentally specific to the double-quote case already covered above.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_forward_scan_stops_at_apostrophe_in_own_delimiter_style_comment()
     {
        // implementation 'com.example:artifact:1.0| // developer's note
        let line = "implementation 'com.example:artifact:1.0 // developer's note";
        let expected_start = line.find("1.0").unwrap();
        let col = expected_start + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1160 S2 (critic follow-up): Groovy's named-argument ("map notation") dependency form
    // is not parsed by `crate::parser::groovy` into a `Dependency` at all, and scoping
    // colon-count to the open string literal (#1160's own fix) now sees zero colons inside
    // the version value's own quoted text and misreads it as a Package-name prefix instead
    // of correctly withholding completion — regression this test pins closed.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_groovy_map_notation_version_value_withholds_completion() {
        // implementation group: 'com.example', name: 'foo', version: '1.0|
        let line = r"implementation group: 'com.example', name: 'foo', version: '1.0";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1160 S2 follow-up: the same map-notation shape must also withhold completion for the
    // `group`/`name` fields, not just `version`, confirming the fix isn't accidentally
    // keyed to the word "version".
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_groovy_map_notation_group_value_withholds_completion() {
        // implementation group: 'com.exam|
        let line = "implementation group: 'com.exam";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1160 S2 code-review follow-up: a Groovy ternary's second colon
    // (`cond ? "a:b:1.0" : "c:d:2.0`) leaves the same trailing `:` before an open quote as
    // map-notation's `version: '...'`, but the character immediately before it (after
    // whitespace) is `"` — a closing quote, not an identifier — so this must still resolve
    // to Version, not be withheld.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_ternary_colon_before_string_still_resolves_version() {
        // implementation(cond ? "a:b:1.0" : "c:d:2.0|
        let line = r#"implementation(cond ? "a:b:1.0" : "c:d:2.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "2.0");
        let expected_start = line.rfind("2.0").unwrap();
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, col as u32)
            )
        );
    }

    // #1160 S2 code-review follow-up: the same ternary shape, cursor in the second string's
    // still-untyped package segment, must resolve to Package.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_ternary_colon_before_string_still_resolves_package() {
        // implementation(cond ? "a:b:1.0" : "com.exam|
        let line = r#"implementation(cond ? "a:b:1.0" : "com.exam"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.exam");
    }

    // #1160 S2 code-review follow-up: an Elvis operator (`value ?: "a:b:1.0"`) leaves a
    // trailing `?:` before the open quote — the character immediately before the colon is
    // `?`, never an identifier, so this must not be withheld either.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_elvis_operator_colon_before_string_still_resolves_version() {
        // implementation(value ?: "com.example:foo:1.0|
        let line = r#"implementation(value ?: "com.example:foo:1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_catalog_multibyte_module_value() {
        // module = "café:lib" — 'é' is 2 bytes in UTF-8 but 1 UTF-16 code unit, so byte
        // and UTF-16 offsets diverge from this point on in the line. Exercises the
        // top-level UTF-16-to-byte conversion and the byte-to-UTF-16 conversion on the
        // returned range (regression test for the #232 follow-up: byte offsets were
        // previously emitted directly as UTF-16 character positions).
        let content = "module = \"café:lib\"\n";
        let uri = deps_core::test_util::test_uri("/test/libs.versions.toml");
        let position = Position::new(0, 14); // cursor right after "café" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "café");
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, 18))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_catalog_inline_table_multibyte_does_not_consume_closing_quote()
     {
        // Live repro from code review: `lib = { module = "com.exämple:lib", version = "1.0" }`
        // with the cursor right after the fully-typed module value (byte offset 34, right
        // before the closing quote). Before the UTF-16 fix, the byte offset (34) was
        // returned directly as the range's end *character* — but "com.exämple:lib" is only
        // 15 UTF-16 units (ä is 2 bytes / 1 UTF-16 unit), so the correct end is 33, not 34.
        // A range ending at 34 would extend one UTF-16 unit past the value, consuming the
        // closing quote itself when the client applies the edit — corrupting the TOML.
        let content = r#"lib = { module = "com.exämple:lib", version = "1.0" }"#;
        assert_eq!(&content[18..34], "com.exämple:lib");
        assert_eq!(content.as_bytes()[34], b'"');
        let uri = deps_core::test_util::test_uri("/test/libs.versions.toml");
        let position = Position::new(0, 33); // cursor right after "lib" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.exämple:lib");
        // Range must end at UTF-16 33 (right before the closing quote), not 34 (which
        // would swallow it).
        assert_eq!(
            range,
            Range::new(Position::new(0, 18), Position::new(0, 33))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_dsl_multibyte_package_value() {
        // implementation("café:junit") — same multi-byte concern as above, in the
        // Kotlin/Groovy DSL path.
        let content = "implementation(\"café:junit\")\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let position = Position::new(0, 20); // cursor right after "café" (UTF-16 units)

        let (t, v, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "café");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 26))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_cursor_past_closing_quote_not_matched() {
        // module = "com.example:lib"|  — cursor placed after the closing quote (e.g. in
        // trailing content on the same line) must not be treated as still inside the
        // quoted value.
        let line = r#"module = "com.example:lib" # trailing"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_module_unterminated_falls_back_to_cursor() {
        // module = "com.example:lib   (no closing quote on the line) — the range must
        // stop at the cursor, not swallow the rest of the line.
        let line = r#"module = "com.example:li"#;
        let col = line.len(); // cursor at end of line, right after "li"
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.example:li");
        assert_eq!(
            range,
            Range::new(Position::new(0, 10), Position::new(0, col as u32))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_inline_table_does_not_leak_across_fields() {
        // lib = { version = "1.0", module = "com.exa|  — cursor is inside the *module*
        // field's still-open value. An earlier field ("version") appearing before it on
        // the same line must not be mistaken for the current context: without scoping to
        // the current inline-table field, `rfind("version")` would walk back past the
        // comma, and the combined quote count across both fields happens to be odd,
        // producing a bogus "version" context instead of "package".
        let line = r#"lib = { version = "1.0", module = "com.exa"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.exa");
        assert_eq!(
            range,
            Range::new(Position::new(0, 35), Position::new(0, col as u32))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_inline_table_version_field_after_module() {
        // lib = { module = "com.example:lib", version = "1.0|  — the reverse ordering:
        // cursor inside the *version* field, with a completed "module" field earlier on
        // the same line. Confirms the field-scoping fix doesn't over-correct and still
        // matches "version" correctly here.
        let line = r#"lib = { module = "com.example:lib", version = "1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
        // #931 (tester follow-up): this exercises the fixed Version arm in a
        // multi-field-per-line scenario — unterminated value, so the range is bounded by
        // the cursor rather than end-of-line.
        assert_eq!(
            range,
            Range::new(Position::new(0, 47), Position::new(0, col as u32))
        );
        assert_eq!(&line[47..col], "1.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_ref_keeps_placeholder_range() {
        // lib = { module = "com.example:lib", version.ref = "guavaVersion|" — `version.ref`
        // refers to a `[versions]` table alias name, not a registry version literal
        // directly. Critic follow-up to #931: computing a real range here (as for plain
        // `version = "..."`) would let `dependency_version_range_is_literal` wrongly
        // ACCEPT whenever the alias name happens to equal its own resolved value, which is
        // a newly introduced wrong-direction accept versus the pre-#931 code's blanket
        // (always-wrong-but-safe) rejection. This must keep returning `Range::default()`.
        let line = r#"lib = { module = "com.example:lib", version.ref = "guavaVersion" }"#;
        let col = line.len() - 3; // cursor inside "guavaVersion", right before the closing quote
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "guavaVersion");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_ref_with_toml_whitespace_keeps_placeholder_range() {
        // lib = { module = "com.example:lib", version . ref = "guavaVersion|" — TOML's
        // dotted-key syntax allows whitespace around the `.` (`version . ref = ...` is
        // legal TOML), so a bare `starts_with('.')` check (without `trim_start()`) would
        // miss this spacing, fall through to the real-range branch, and reintroduce the
        // wrong-direction-accept bug the `is_version_ref` check exists to prevent
        // (follow-up to the critic's M2 finding on #931).
        let line = r#"lib = { module = "com.example:lib", version . ref = "guavaVersion" }"#;
        let col = line.len() - 3; // cursor inside "guavaVersion", right before the closing quote
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "guavaVersion");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_unterminated_falls_back_to_cursor() {
        // implementation("junit:junit   (no closing quote/paren on the line) — the range
        // must stop at the cursor, not swallow the rest of the line.
        let line = r#"implementation("junit:junit"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "junit:junit");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, col as u32))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_cursor_mid() {
        // implementation("junit:junit:4.1|3.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // second ':' at index 27; version_start=28, "4.1"=3 chars, cursor at 31
        let col = 31;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "4.1");
        // #931: range must span the whole literal version segment ("4.13.2"), not
        // Range::default() — otherwise `dependency_version_range_is_literal`'s content
        // slice never matches the declared version and completion is rejected outright.
        assert_eq!(
            range,
            Range::new(Position::new(0, 28), Position::new(0, 34))
        );
        assert_eq!(&line[28..34], "4.13.2");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_cursor_at_start() {
        // implementation("junit:junit:|4.13.2")
        let line = r#"implementation("junit:junit:4.13.2")"#;
        // second ':' at index 27, cursor at 28 (right after it)
        let col = 28;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "");
        assert_eq!(
            range,
            Range::new(Position::new(0, 28), Position::new(0, 34))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_version_unterminated_falls_back_to_cursor() {
        // implementation("junit:junit:4.13.2 — no closing quote/paren on the line; the
        // range must stop at the cursor, not swallow the rest of the line (#931).
        let line = r#"implementation("junit:junit:4.13.2"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "4.13.2");
        assert_eq!(
            range,
            Range::new(Position::new(0, 28), Position::new(0, col as u32))
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_groovy() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation 'junit:junit:4.13.2'\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    /// Gradle spans five manifest formats (TOML version catalog, Groovy DSL, Kotlin
    /// DSL) with no raw-text section marker shared across all of them — no override,
    /// unreachable in practice.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_default_none() {
        let eco = GradleEcosystem::new(make_cache());
        assert!(
            eco.fallback_completion_prefix("anything at all\n", Position::new(0, 0).into())
                .is_none()
        );
    }

    #[test]
    fn test_completion_insert_text() {
        let eco = GradleEcosystem::new(make_cache());
        struct MockMetadata {
            name: deps_core::PackageName,
            latest_version: deps_core::ConcreteVersion,
        }
        impl deps_core::Metadata for MockMetadata {
            fn name(&self) -> &deps_core::PackageName {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                None
            }
            fn repository(&self) -> Option<&str> {
                None
            }
            fn documentation(&self) -> Option<&str> {
                None
            }
            fn latest_version(&self) -> &deps_core::ConcreteVersion {
                &self.latest_version
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("implementation(\"org.apache.commons:commons-lang3:3.14.0\")".to_string())
        );
    }

    // --- #793 characterization: `GradleEcosystem::generate_completions` keeps its own
    // full override (crate-local `GradleCompletionContext`-typed DSL/catalog context, out of
    // #793's scope — see the plan), but the "version" arm's body moves into the new required
    // `complete_version` hook. This pins the arm's observable output before that move.

    /// Deterministic, CI-enforced counterpart to the network-gated test below:
    /// `detect_completion_context` (the raw-text DSL scanner) recognizes a
    /// [`GradleCompletionContext::Version`] context from the coordinate string's shape
    /// alone, independent of the surrounding `dependencies { }` block the parser requires —
    /// so a coordinate outside that block still resolves `ctx_type ==
    /// GradleCompletionContext::Version` while `parse_result.dependencies()` stays empty,
    /// and the arm must fail closed to `Completions::default()` without ever calling the
    /// registry.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_no_dependency_at_position_returns_empty() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "implementation(\"junit:junit:4.13.2\")\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        assert!(parse_result.dependencies().is_empty());

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(0, 31),
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #819 characterization: a cursor with no open quoted string on its line resolves to
    /// [`GradleCompletionContext::None`], which is now a named, non-wildcard match arm in
    /// `generate_completions` rather than a catch-all `_ => vec![]` — this exercises that
    /// arm end-to-end through the public `generate_completions` entry point, not just the
    /// lower-level `detect_dsl_context`/`detect_catalog_context` unit tests above. Note
    /// this pins the arm's *observable output* (identical before and after #819 —
    /// `Completions::default()` either way); the actual #819 guarantee is compile-time (a
    /// new `GradleCompletionContext` variant is a compile error at the match in
    /// `generate_completions`), which no runtime test can exercise.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_none_context_returns_empty() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "// no dependency coordinate on this line\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let (ctx, _, _) =
            GradleEcosystem::detect_completion_context(content, Position::new(0, 5), &uri);
        assert_eq!(ctx, GradleCompletionContext::None);

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(0, 5),
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #919 C1 (critic follow-up): an *unresolved* `$var` reference — no matching
    /// `gradle.properties` entry, since `snapshot_guard_async` isolates this test from any
    /// real file on disk — must withhold version completion entirely, deterministically and
    /// without touching the registry. This is the exact scenario #919 was filed over:
    /// `detect_completion_context`'s raw-text DSL scanner only checks the coordinate's
    /// shape, so without the literal-span guard this would previously offer the full
    /// version list and, on accept, splice a version string into `$libVersion`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_withheld_for_unresolved_variable() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"com.example:lib:$libVersion\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("$libVersion"),
            "fixture no longer exercises the unresolved-variable shape: {content}"
        );
        let position: Position = dep.version_range().unwrap().start.into();
        let freshness = deps_core::FreshnessSettings::default();

        // M4 (critic follow-up): `Completions::default()` below is also what the
        // *unguarded* path would produce offline (`complete_versions_generic_from` returns
        // `vec![]` on a registry fetch error, network-free or not) — non-discriminating on
        // its own. Assert the guard's own decision directly against the real parsed `dep`
        // first, so this test fails loudly if the guard regresses rather than passing
        // vacuously either way.
        assert!(
            !deps_core::lsp_helpers::dependency_version_range_is_literal(
                *dep,
                content,
                dep.version_range().unwrap(),
            )
        );

        let result = eco
            .generate_completions(parse_result.as_ref(), position, content, freshness)
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #931 regression: a plain literal compact-coordinate version must be admitted by the
    /// #922 guard now that `detect_dsl_context`'s `colon_count >= 2` arm returns the real
    /// span of the version segment instead of `Range::default()` — the guard's content
    /// slice previously never matched the declared version, rejecting every such
    /// completion.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_dsl_context_range_admits_plain_literal_compact_coordinate() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation 'com.google.guava:guava:32.0.1-jre'\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();

        let (ctx, _, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(ctx, GradleCompletionContext::Version);
        assert!(deps_core::lsp_helpers::dependency_version_range_is_literal(
            *dep,
            content,
            range.into(),
        ));
    }

    /// #931 regression: a plain literal `version = "..."` catalog value must be admitted
    /// by the #922 guard now that `detect_catalog_context`'s `version` arm returns the
    /// real span of the value instead of `Range::default()`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_catalog_context_range_admits_plain_literal_version() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "[libraries]\ncommons-lang = { module = \"org.apache.commons:commons-lang3\", version = \"3.12.0\" }\n";
        let uri = deps_core::test_util::test_uri("/project/libs.versions.toml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();

        let (ctx, _, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(ctx, GradleCompletionContext::Version);
        assert!(deps_core::lsp_helpers::dependency_version_range_is_literal(
            *dep,
            content,
            range.into(),
        ));
    }

    // Critic follow-up (C1) to #1161: end-to-end pin, through the real parser and
    // `generate_completions` dispatch, of the exact #931 worst case — an alias whose
    // resolved value is textually identical to its own name — proving
    // `dependency_version_range_is_literal`'s empty-slice relaxation for #1161 did not
    // invert `detect_catalog_context`'s deliberate `Range::default()` always-reject
    // sentinel into an always-accept.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_ref_alias_withheld_even_when_resolved_value_matches_alias_name()
     {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "[versions]\nguavaVersion = \"guavaVersion\"\n\n[libraries]\nguava = { module = \"com.google.guava:guava\", version.ref = \"guavaVersion\" }\n";
        let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("guavaVersion"),
            "fixture must resolve the alias to a value textually identical to its own name: {content}"
        );
        let position: Position = dep.version_range().unwrap().start.into();

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(
            result,
            Completions::default(),
            "a version.ref alias must never be offered completions, even when its \
             resolved value happens to equal its own alias name"
        );
    }

    // Critic follow-up (C1, second round) to #1161: the ORDINARY interactive state while
    // typing a `version.ref` alias — every prefix short of the real key, so
    // `version_requirement()` is `None` on every keystroke, not just for a permanently
    // dangling reference — must never fall through to the unfiltered full version list.
    // Exercises several partial-typing states end-to-end through the real parser + dispatch.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_ref_alias_withheld_while_still_being_typed() {
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        for partial in ["g", "gu", "gua", "guavaVersio"] {
            let content = format!(
                "[versions]\nguavaVersion = \"32.0.1\"\n\n[libraries]\nguava = {{ module = \"com.google.guava:guava\", version.ref = \"{partial}\" }}\n"
            );
            let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let dep = &parse_result.dependencies()[0];
            assert!(
                dep.version_requirement().is_none(),
                "{partial:?} must not resolve against \"guavaVersion\": {content}"
            );
            let position: Position = dep.version_range().unwrap().start.into();

            let result = eco
                .generate_completions(
                    parse_result.as_ref(),
                    position,
                    &content,
                    deps_core::FreshnessSettings::default(),
                )
                .await;
            assert_eq!(
                result,
                Completions::default(),
                "partial alias {partial:?} must not offer the unfiltered version list: {content}"
            );
        }
    }

    // `complete_versions` has no offline guard for an already-well-formed package name, so
    // the "happy path" needs live Maven Central access, mirroring `deps_maven`'s equivalent
    // characterization test.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_generate_completions_version_arm_dispatches_by_position() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"junit:junit:4.13.2\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();
        let freshness = deps_core::FreshnessSettings::default();

        let direct = eco.complete_versions(dep.name(), "", freshness).await;
        let via_dispatch = eco
            .generate_completions(parse_result.as_ref(), position, content, freshness)
            .await;
        assert_eq!(via_dispatch.items, direct);
    }

    // #1160: `detect_dsl_context`'s colon-counting/`version_start` must be scoped to the
    // current dependency call, not the whole line, so a semicolon-joined second dependency's
    // version resolves to its own literal text instead of overspanning back into the first
    // dependency's already-closed coordinate.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_semicolon_joined_line_scopes_version_to_second_dependency() {
        // implementation("com.example:foo:1.0.0"); implementation("com.example:bar:2.0|.0")
        let line =
            r#"implementation("com.example:foo:1.0.0"); implementation("com.example:bar:2.0.0")"#;
        let col = line.find("2.0").unwrap() + 3; // cursor right after "2.0" in the second dep
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "2.0");
        let expected_start = line.rfind("2.0.0").unwrap();
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, (expected_start + "2.0.0".len()) as u32)
            )
        );
    }

    // #1160 M2 (tester follow-up): the same scoping fix must also generalize to a
    // space-joined (not just semicolon-joined) pair of dependencies, since `detect_dsl_context`
    // doesn't special-case the joining delimiter — only `open_pos` (the last odd-parity quote)
    // matters.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_space_joined_line_scopes_version_to_second_dependency() {
        // implementation("com.example:foo:1.0.0") implementation("com.example:bar:2.0|.0")
        let line =
            r#"implementation("com.example:foo:1.0.0") implementation("com.example:bar:2.0.0")"#;
        let col = line.find("2.0").unwrap() + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "2.0");
        let expected_start = line.rfind("2.0.0").unwrap();
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, (expected_start + "2.0.0".len()) as u32)
            )
        );
    }

    // #1160 M2 (tester follow-up): a 3-dependency-per-line statement must scope correctly to
    // the LAST dependency, proving the fix isn't a special case for exactly two dependencies.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_three_dependencies_semicolon_joined_scopes_to_third() {
        // implementation("a:b:1.0"); implementation("c:d:2.0"); implementation("e:f:3.0|.0")
        let line =
            r#"implementation("a:b:1.0"); implementation("c:d:2.0"); implementation("e:f:3.0.0")"#;
        let col = line.find("3.0").unwrap() + 3;
        let before = &line[..col];
        let (t, v, range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "3.0");
        let expected_start = line.rfind("3.0.0").unwrap();
        assert_eq!(
            range,
            Range::new(
                Position::new(0, expected_start as u32),
                Position::new(0, (expected_start + "3.0.0".len()) as u32)
            )
        );
    }

    // #1160 follow-up: the same unscoped colon-count bug also misclassified a second,
    // not-yet-colon-typed dependency's package name as a Version context, since the first
    // dependency's own two colons were counted against it.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_semicolon_joined_line_scopes_package_to_second_dependency() {
        // implementation("com.example:foo:1.0.0"); implementation("ba|
        let line = r#"implementation("com.example:foo:1.0.0"); implementation("ba"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "ba");
    }

    // #1160: end-to-end through `generate_completions`'s real parser + dispatch, on the exact
    // semicolon-joined fixture from the issue, proving completion is no longer withheld for
    // the second dependency's version.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_dsl_context_semicolon_joined_line_admits_second_dependency_version() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"com.example:foo:1.0.0\"); implementation(\"com.example:bar:2.0.0\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let deps = parse_result.dependencies();
        assert_eq!(
            deps.len(),
            2,
            "fixture must parse both dependencies: {content}"
        );
        let dep_two = deps[1];
        let position: Position = dep_two.version_range().unwrap().start.into();

        let (ctx, _, range) = GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(ctx, GradleCompletionContext::Version);
        assert!(
            deps_core::lsp_helpers::dependency_version_range_is_literal(
                dep_two,
                content,
                range.into(),
            ),
            "second dependency's version must be admitted as a literal, editable span"
        );
    }

    // #1146: cursor just before dep-two's version_range on a real two-dep line resolves dep-two via pass 2, not dep-one.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_resolves_second_dependency_from_real_parser_output() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies {\n    implementation(\"com.example:foo:1.0.0\"); implementation(\"com.example:bar:2.0.0\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let deps = parse_result.dependencies();
        assert_eq!(
            deps.len(),
            2,
            "fixture must parse both same-line dependencies: {content}"
        );
        let dep_one_name = deps[0].name().clone();
        let dep_two = deps[1];
        let dep_two_version_range: Range = dep_two.version_range().unwrap().into();
        let position = Position {
            line: dep_two_version_range.start.line,
            character: dep_two_version_range.start.character - 1,
        };

        let resolved = deps_core::completion::literal_version_dependency(
            parse_result.as_ref(),
            position,
            content,
            dep_two_version_range,
        )
        .expect("dep-two's own version_range must resolve it");

        assert_eq!(
            resolved.name(),
            dep_two.name(),
            "must resolve the second dependency, not the first"
        );
        assert_ne!(resolved.name().as_str(), dep_one_name.as_str());
    }

    // #1146 review follow-up: `version` written before `module` in a catalog entry must still resolve via the fallback.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_resolves_catalog_entry_with_version_before_module() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content =
            "[libraries]\nfoo-bar = { version = \"1.0.0\", module = \"com.example:foo\" }\n";
        let uri = deps_core::test_util::test_uri("/project/gradle/libs.versions.toml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let deps = parse_result.dependencies();
        assert_eq!(
            deps.len(),
            1,
            "fixture must parse one dependency: {content}"
        );
        let dep = deps[0];
        let version_range: Range = dep.version_range().unwrap().into();
        assert!(
            dep.name_range().start.character > version_range.start.character,
            "fixture must keep `version` before `module` in source order: {content}"
        );
        let position = Position {
            line: version_range.start.line,
            character: version_range.start.character - 1,
        };

        let resolved = deps_core::completion::literal_version_dependency(
            parse_result.as_ref(),
            position,
            content,
            version_range,
        )
        .expect("must resolve despite name_range starting after version_range");

        assert_eq!(resolved.name(), dep.name());
    }
}

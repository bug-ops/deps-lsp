//! LSP-only completion support for Gradle (issues #819/#1137/#1191/#1447): raw-text DSL/
//! version-catalog completion-context detection.
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use tower_lsp_server::ls_types::{Position, Range};

use deps_core::quote_scan::{self, CodeSpans, ScanSyntax};

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: the three range delimiters
/// `formatter::gradle_version_matches` accepts — `[`/`(` plus Gradle's own reversed-bracket
/// exclusive notation `]1.2,1.5]` (`deps_core::interval::BracketStyle::AllowReversed`,
/// unlike Maven's `Standard`). The trailing dynamic suffix (`1.+`) has no leading operator
/// to strip. Originally left empty, which meant a completion prefix like `"[2.2"` was never
/// stripped down to `"2.2"` and so never prefix-matched any real version (#1137 critic S1).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['[', '(', ']'];

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GradleCompletionContext {
    /// Cursor is inside a dependency coordinate's version segment.
    Version,
    /// Cursor is inside a dependency coordinate's package/module segment.
    Package,
    /// Cursor is not inside any completable position.
    None,
}

/// Builds an LSP [`Range`] on `line_idx` from a pair of byte offsets into `line`,
/// converting each to a UTF-16 code unit offset via
/// [`deps_core::completion::byte_to_utf16_offset`].
pub(super) fn byte_range(line: &str, line_idx: u32, start_byte: usize, end_byte: usize) -> Range {
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

/// Restricts [`detect_dsl_context`]'s `Version`-arm same-line pass-2 fallback (see
/// [`deps_core::completion::literal_version_dependency_in_scope`]'s doc) to this literal's own
/// declaration, using [`resolve_call_word`]'s shared call-shape walk (issue #1191, generalized
/// for #1447).
///
/// Deliberately does **not** share its own classification with the `Package` arm's gate
/// ([`package_completion_gate`]) despite sharing that walk — the two arms have different
/// failure costs (a missed `Package` denial only costs a stray registry search on text the user
/// typed; wrongly admitting a `Version` pass-2 candidate silently offers a *different*
/// package's versions, issue #1191's misattribution class), so `Version`'s own scope check
/// stays strict (default-deny on anything not positively recognized) while `Package`'s gate is
/// default-allow (see [`PackageGate`]'s doc).
///
/// Returns [`DeclarationScope::Outside`] when the resolved word is empty or not
/// [`crate::parser::is_dependency_configuration`] — e.g. `println("...")` or an unrecognized
/// call — or when [`resolve_call_word`] finds a bare assignment with no call word at all.
/// Otherwise returns [`DeclarationScope::Within`] spanning from `open_pos` (the current
/// literal's own start, **not** the configuration word's start — impl-critic S2 on #1447: a
/// span starting at the word extends across any earlier, already-closed vararg sibling this
/// literal shares a call with, e.g. `implementation "a:b:1.0", "c:d:<cursor>` — so pass 2's
/// `position_in_range(anchor, span)` check would wrongly admit the sibling `a:b`'s own anchor,
/// fetching the wrong package's versions) to `value_end` (the same end-of-literal-or-cursor
/// bound the `Version` arm of [`detect_dsl_context`] already computes). Every real anchor for
/// *this* literal's own declaration (its `version_range`/`name_range` start) necessarily falls
/// after `open_pos`, so narrowing the span start this way never rejects a legitimate rescue.
///
/// The word scan is ASCII-only (`[A-Za-z0-9_]`), unlike the parsers' Unicode `\w+`: a
/// non-ASCII custom source-set name (e.g. `kaptDébug`) degrades to pre-#1191 behavior for
/// that one call — `Outside` instead of `Within` — losing the pass-2 rescue but never
/// misattributing to an unrelated dependency.
#[allow(clippy::string_slice)]
pub(super) fn dsl_declaration_scope(
    line: &str,
    line_idx: u32,
    open_pos: usize,
    value_end: usize,
) -> deps_core::completion::DeclarationScope {
    use deps_core::completion::DeclarationScope;

    let blanked = quote_scan::blank_comments(&line[..open_pos], ScanSyntax::Groovy);
    let code = CodeSpans::new(&blanked, ScanSyntax::Groovy);

    let word = match resolve_call_word(&blanked, &code) {
        CallWordResolution::Word(word) => word,
        CallWordResolution::Assignment => "",
    };

    if word.is_empty() || !crate::parser::is_dependency_configuration(word) {
        return DeclarationScope::Outside;
    }

    DeclarationScope::Within(byte_range(line, line_idx, open_pos, value_end).into())
}

/// Finds the byte offset of the `(` in `text` that has no matching `)` between it and `text`'s
/// end — the paren directly enclosing whatever expression sits at the end of `text` — by
/// scanning backward and tracking paren balance, skipping any `(`/`)` that `code` (built over
/// the same `text`) marks as sitting inside a string literal.
///
/// Returns `None` when every paren in `text` is already balanced: either there is no call at
/// all (a paren-less call), or the nearest call's parens are already fully closed before
/// `text`'s end (e.g. `id("x") version ` — `id(...)` is a separate, already-closed call, not an
/// enclosing one).
pub(super) fn enclosing_open_paren(text: &str, code: &CodeSpans<'_>) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, c) in text.char_indices().rev() {
        if !code.is_code_byte(i) {
            continue;
        }
        match c {
            ')' => depth += 1,
            '(' if depth == 0 => return Some(i),
            '(' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Extracts the identifier word immediately before `paren_pos` in `blanked` — the call name
/// governing whatever sits inside that paren — after stripping one optional
/// `platform`/`enforcedPlatform` wrapper keyword and its own enclosing `(`, covering
/// `implementation(platform("g:a:v"))`.
#[allow(clippy::string_slice)]
pub(super) fn call_word_before_paren(blanked: &str, paren_pos: usize) -> &str {
    let mut rest = blanked[..paren_pos].trim_end();
    if let Some(stripped) = rest
        .strip_suffix("platform")
        .or_else(|| rest.strip_suffix("enforcedPlatform"))
    {
        rest = stripped.trim_end();
        if let Some(stripped) = rest.strip_suffix('(') {
            rest = stripped.trim_end();
        }
    }
    word_before(rest)
}

/// Extracts the trailing ASCII `[A-Za-z0-9_]+` identifier word `rest` ends with (empty if
/// `rest` doesn't end in one).
#[allow(clippy::string_slice)]
pub(super) fn word_before(rest: &str) -> &str {
    let word_start = rest
        .char_indices()
        .rev()
        .find(|&(_, c)| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |(i, c)| i + c.len_utf8());
    &rest[word_start..]
}

/// Upper bound on the sibling arguments [`skip_vararg_siblings`] walks over in one call.
///
/// Each accepted sibling costs a fresh [`quote_scan::last_string_literal`] scan of the
/// remaining text, so an uncapped walk on a crafted line with an unrealistic sibling count is
/// `O(line length²)` (issue #1447 impl-critic S3 — live-reproduced as a completion-handler hang
/// on a single ~100 KB line with ~20k comma-separated arguments). Capping bounds total work to
/// `O(MAX_VARARG_SIBLINGS * line length)` regardless of how many siblings a crafted line
/// claims; no real Gradle dependency declaration has anywhere near this many comma-separated
/// coordinates in one call.
pub(super) const MAX_VARARG_SIBLINGS: usize = 32;

/// Walks `rest` backward over up to [`MAX_VARARG_SIBLINGS`] already-closed, comma-separated
/// sibling arguments — Gradle Groovy's vararg form of a dependency-configuration call,
/// `implementation "a:b:1.0", "c:d:2.0<cursor>` — returning what remains before the first
/// non-sibling boundary, and whether at least one `,` was actually consumed.
#[allow(clippy::string_slice)]
pub(super) fn skip_vararg_siblings(mut rest: &str) -> (&str, bool) {
    let mut consumed = false;
    for _ in 0..MAX_VARARG_SIBLINGS {
        let Some(stripped) = rest.strip_suffix(',') else {
            break;
        };
        consumed = true;
        rest = stripped.trim_end();
        let Some(sibling) = quote_scan::last_string_literal(rest, ScanSyntax::Groovy) else {
            break;
        };
        if sibling.close != Some(rest.len()) {
            break;
        }
        rest = rest[..sibling.open].trim_end();
    }
    (rest, consumed)
}

/// What [`resolve_call_word`] found governing an open string literal: either an identifier
/// word (checked by each caller against its own criteria — [`crate::parser::is_dependency_configuration`]
/// for [`dsl_declaration_scope`], [`NON_DEPENDENCY_CALL_WORDS`] for [`package_completion_gate`]),
/// or a bare assignment with no call word at all.
pub(super) enum CallWordResolution<'a> {
    /// An identifier word (possibly empty, meaning nothing identifier-shaped precedes the
    /// resolved call/position at all — e.g. Kotlin's string-invoke syntax
    /// `"implementation"(...)`, or a multi-line call whose `(` sits on an earlier line, outside
    /// `blanked`'s single-line scope) sits immediately before the resolved call.
    Word(&'a str),
    /// No call word to check at all: a trailing `=` with nothing but whitespace before it (a
    /// project-metadata assignment, e.g. `group = "<cursor>`) — only reachable when there's no
    /// enclosing paren.
    Assignment,
}

/// Resolves what call, if any, governs the string literal opening at `open_pos` on `line` —
/// finding its nearest enclosing, syntactically unmatched `(` (issue #1191, generalized for
/// #1447) if any, else a Groovy without-parens call's own configuration word (including its
/// vararg form).
///
/// Shared by both [`dsl_declaration_scope`] (the `Version` arm's pass-2 restrictor) and
/// [`package_completion_gate`] (the `Package` arm's gate) — the two differ only in how they
/// classify this walk's result (see each caller's own doc), not in how the result is found;
/// issue #1447 exists specifically because a shared-logic gap let the two arms drift apart
/// before, so this one walk is the single place either arm's call-shape detection can change.
///
/// [`enclosing_open_paren`] finds the call's own `(` by paren balance alone, so it doesn't need
/// to understand what sits between it and the literal — a ternary (`cond ? "a" : "b"`), an
/// Elvis operator (`value ?: "b"`), or any other expression nested inside the same argument
/// list all resolve identically, unlike a purely left-to-right token walk that would have to
/// special-case each such operator. Once found, the word immediately before that `(` is
/// checked directly, after stripping one optional `platform`/`enforcedPlatform` wrapper keyword
/// and its own `(` — covering `implementation(platform("g:a:v"))`. A literal with **no**
/// enclosing `(` at all falls back to [`skip_vararg_siblings`] plus a word scan instead, for
/// Groovy's without-parens call syntax (`implementation "g:a:v"`, including its vararg form),
/// or [`CallWordResolution::Assignment`] when that fallback text ends in a bare `=`. Comments
/// preceding the literal (e.g. `implementation /* … */ "g:a:v"`) are blanked via
/// [`quote_scan::blank_comments`] first, so a `(`/`)` inside one is never mistaken for real
/// call syntax and a trailing `*/` is never mistaken for the end of a bare word.
pub(super) fn resolve_call_word<'a>(
    blanked: &'a str,
    code: &CodeSpans<'a>,
) -> CallWordResolution<'a> {
    if let Some(paren_pos) = enclosing_open_paren(blanked, code) {
        return CallWordResolution::Word(call_word_before_paren(blanked, paren_pos));
    }
    let trimmed = blanked.trim_end();
    if trimmed.ends_with('=') {
        return CallWordResolution::Assignment;
    }
    let (rest, _consumed) = skip_vararg_siblings(trimmed);
    CallWordResolution::Word(word_before(rest))
}

/// Outcome of [`detect_dsl_context`]'s `Package` arm gate (issue #1447): whether an open string
/// literal's colon-shaped position (0 or 1 colons typed so far) is still allowed to trigger a
/// Package-name registry search.
///
/// Default-**allow**, unlike [`dsl_declaration_scope`]'s default-deny: a wrongly-withheld
/// `Package` completion silently breaks a real, working feature (impl-critic S1 —
/// live-verified regressions on `library(...)` in `settings.gradle.kts`, a multi-line
/// `implementation(\n    "g:a:v"\n)` call, Kotlin's string-invoke syntax
/// `"implementation"("g:a:v")`, and custom/plugin-registered configurations this crate's
/// [`crate::parser::is_dependency_configuration`] doesn't know about), whereas a
/// wrongly-*granted* one only issues an extra Maven Central search against text the user
/// already typed — issue #1447 asks to suppress specific, positively-identified false-positive
/// shapes ([`NON_DEPENDENCY_CALL_WORDS`]), not every literal this heuristic can't positively
/// recognize as a real dependency call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PackageGate {
    /// Not positively excluded — [`crate::parser::is_dependency_configuration`] matched, or
    /// nothing conclusive was found at all (an unrecognized/custom configuration word, a
    /// helper call, Kotlin's string-invoke syntax, or a literal whose enclosing call isn't
    /// visible on this single line — see [`CallWordResolution::Word`]'s doc).
    Allowed,
    /// Positively recognized as something that is never a dependency coordinate — see
    /// [`NON_DEPENDENCY_CALL_WORDS`] and [`CallWordResolution::Assignment`].
    Excluded,
}

/// Call/assignment words that, immediately before an open paren (or, for a bare `=`, with no
/// paren at all), positively identify a Gradle DSL position that is never a dependency
/// coordinate: a plugin id (`id(...)`), a Kotlin-DSL plugin shorthand (`kotlin(...)`), a
/// repository URL builder (`uri(...)`), a plugin version literal/call
/// (`version`/`version(...)`), a project reference/file-collection helper
/// (`project(...)`/`files(...)`), `settings.gradle(.kts)` project inclusion
/// (`include`/`includeBuild` — the highest-traffic false-positive shape, present in essentially
/// every settings file), Android Gradle Plugin project metadata (`namespace`/`applicationId`),
/// a repository declaration (`url`/`maven`), or a same-class false positive to #1191's
/// `println("a:b:1.0")` example (`println`).
///
/// **Not an allowlist**: any word not in this set (and not
/// [`crate::parser::is_dependency_configuration`]) is [`PackageGate::Allowed`], not denied —
/// see that variant's and [`PackageGate`]'s own doc for why a positive-exclusion list, however
/// extended (issue #1447 impl-critic M1 follow-up added `include`/`includeBuild`/`namespace`/
/// `applicationId`/`url`/`maven`/`println` to the four issue-reported words), can never be
/// exhaustive by design.
pub(super) const NON_DEPENDENCY_CALL_WORDS: &[&str] = &[
    "id",
    "kotlin",
    "uri",
    "version",
    "project",
    "files",
    "include",
    "includeBuild",
    "namespace",
    "applicationId",
    "url",
    "maven",
    "println",
];

pub(super) fn classify_word(word: &str) -> PackageGate {
    if !word.is_empty()
        && !crate::parser::is_dependency_configuration(word)
        && NON_DEPENDENCY_CALL_WORDS.contains(&word)
    {
        PackageGate::Excluded
    } else {
        PackageGate::Allowed
    }
}

/// Classifies the call/position governing the string literal opening at `open_pos` on `line`,
/// for [`detect_dsl_context`]'s `Package` arm gate (issue #1447), via [`resolve_call_word`]'s
/// shared call-shape walk. See [`PackageGate`]'s doc for the default-allow-unless-positively-
/// excluded policy this implements.
// `open_pos` is always the byte offset of a literal's opening quote, from
// `quote_scan::last_string_literal` — always a char boundary (same guarantee
// `detect_dsl_context` and `dsl_declaration_scope` rely on for identical slicing).
#[allow(clippy::string_slice)]
pub(super) fn package_completion_gate(line: &str, open_pos: usize) -> PackageGate {
    let blanked = quote_scan::blank_comments(&line[..open_pos], ScanSyntax::Groovy);
    let code = CodeSpans::new(&blanked, ScanSyntax::Groovy);

    match resolve_call_word(&blanked, &code) {
        // A project-metadata assignment (`group = "<cursor>`) is positively excluded, not just
        // an unrecognized word, since it never has a call word to check at all.
        CallWordResolution::Assignment => PackageGate::Excluded,
        CallWordResolution::Word(word) => classify_word(word),
    }
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
///
/// Built on [`deps_core::quote_scan::CodeSpans`] under [`ScanSyntax::Toml`] (#1175), which
/// tracks `'...'` and `"..."` as independent delimiters instead of assuming one quote style
/// for the whole `before_cursor` — the earlier per-`"`-only toggle mis-split a mixed-style
/// entry like `{ module = "a:b", version = '[1.0,2.0` at the comma inside `version`'s
/// still-open single-quoted range value, since the old toggle never opened a string for
/// that `'` at all — and, as a side effect, correctly ignores a comma inside a `#` comment.
pub(super) fn current_field_start(before_cursor: &str) -> usize {
    let code = CodeSpans::new(before_cursor, ScanSyntax::Toml);
    before_cursor
        .char_indices()
        .rfind(|&(i, c)| c == ',' && code.is_code_byte(i))
        .map_or(0, |(i, _)| i + 1)
}

/// Detects completion context in version catalog files.
///
/// `col_idx`/`before_cursor` are byte offsets (see
/// `GradleEcosystem::detect_completion_context`'s doc comment); the returned `Range`'s
/// character fields are UTF-16 code unit offsets.
// Every offset below derives from `char_indices()` or `find`/`rfind` of an ASCII token, so every
// slice bound is always a char boundary.
#[allow(clippy::string_slice)]
pub(super) fn detect_catalog_context<'a>(
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

    // version = "..." or version.ref = "..." — also '...' (#1175): a single-`"`-parity check
    // disagrees with itself once both quote styles are legal on the same line (`version =
    // "1.0-o'brien` has both an odd `'` count and an odd `"` count), so this scans left to
    // right toggling between the two styles as alternatives instead of picking one.
    if let Some(rel_eq_pos) = field.rfind("version")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        && let Some(literal) =
            quote_scan::last_string_literal(after, ScanSyntax::Toml).filter(|l| l.close.is_none())
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
        let value_start = field_start + rel_eq_pos + literal.open + 1;
        if value_start <= cursor {
            let range = if is_version_ref {
                Range::default()
            } else {
                // Bound by the cursor, not end-of-line, so an unterminated value doesn't swallow
                // trailing line content (#931 fix; this arm previously always returned
                // `Range::default()`, rejecting every completion here). Comment-aware (#1175,
                // same defect class #1168 fixed on the DSL side): `version = "1.0   # a "quoted"
                // note` must not overspan the completion range into the trailing comment.
                let value_end = quote_scan::find_closing_quote_before_comment(
                    &line[value_start..],
                    literal.quote,
                    ScanSyntax::Toml,
                )
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

    // module = "..." or '...' (#1175, same fix as the version arm above)
    if let Some(rel_eq_pos) = field.rfind("module")
        && let after = &field[rel_eq_pos..]
        && after.contains('=')
        && let Some(literal) =
            quote_scan::last_string_literal(after, ScanSyntax::Toml).filter(|l| l.close.is_none())
    {
        let value_start = field_start + rel_eq_pos + literal.open + 1;
        if value_start <= cursor {
            // Fall back to the cursor, not end-of-line, when unterminated (mirrors
            // `MavenEcosystem::detect_xml_context`'s no-closing-tag fallback).
            let value_end = quote_scan::find_closing_quote_before_comment(
                &line[value_start..],
                literal.quote,
                ScanSyntax::Toml,
            )
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
#[allow(clippy::string_slice)]
pub(super) fn quoted_key_precedes_colon(before_colon: &str) -> bool {
    let Some(literal) = quote_scan::last_string_literal(before_colon, ScanSyntax::Groovy) else {
        return false;
    };
    if literal.close != Some(before_colon.len()) {
        return false;
    }
    let before_key = before_colon[..literal.open].trim_end();
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
#[allow(clippy::string_slice)]
pub(super) fn detect_dsl_context<'a>(
    before_cursor: &str,
    line: &'a str,
    col_idx: usize,
    line_idx: u32,
) -> (
    GradleCompletionContext,
    &'a str,
    Range,
    deps_core::completion::DeclarationScope,
) {
    let cursor = col_idx.min(line.len());
    // Scoped per-literal (#1168), not line-wide: `quote_char` is whatever delimiter opens
    // the string containing the cursor, found by scanning forward and toggling between
    // `'`/`"` as independent delimiters, rather than picking one quote character for the
    // whole line and checking its parity.
    let Some(open) = quote_scan::last_string_literal(before_cursor, ScanSyntax::Groovy)
        .filter(|span| span.close.is_none())
    else {
        return (
            GradleCompletionContext::None,
            "",
            Range::default(),
            deps_core::completion::DeclarationScope::Unchecked,
        );
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
            return (
                GradleCompletionContext::None,
                "",
                Range::default(),
                deps_core::completion::DeclarationScope::Unchecked,
            );
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
            let closing_quote_rel =
                quote_scan::find_closing_quote_before_comment(rest, quote_char, ScanSyntax::Groovy);
            let scan_limit_rel = closing_quote_rel.unwrap_or(cursor - (open_pos + 1));
            let end_rel = rest[..scan_limit_rel]
                .char_indices()
                .filter(|&(_, c)| c == ':')
                .nth(1)
                .map_or(scan_limit_rel, |(i, _)| i);
            let value_end = (open_pos + 1 + end_rel).max(cursor);

            // A colon count of 0 or 1 alone can't distinguish a partial dependency coordinate
            // from any other open string literal (a plugin id/shorthand argument, a project
            // metadata assignment, a URL) — gated on `package_completion_gate`'s
            // default-allow-unless-positively-excluded classification (issue #1447; see its
            // doc, and `PackageGate`'s, for why this differs from `dsl_declaration_scope`'s
            // stricter default-deny). Matched exhaustively, not compared with `==`, so a future
            // `PackageGate` variant forces this call site to be revisited at compile time.
            match package_completion_gate(line, open_pos) {
                PackageGate::Excluded => {
                    return (
                        GradleCompletionContext::None,
                        "",
                        Range::default(),
                        deps_core::completion::DeclarationScope::Unchecked,
                    );
                }
                PackageGate::Allowed => {}
            }

            let range = byte_range(line, line_idx, open_pos + 1, value_end);
            (
                GradleCompletionContext::Package,
                &line[open_pos + 1..cursor],
                range,
                deps_core::completion::DeclarationScope::Unchecked,
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
            let closing_quote_rel =
                quote_scan::find_closing_quote_before_comment(rest, quote_char, ScanSyntax::Groovy);
            let value_end = closing_quote_rel
                .map_or(cursor, |rel| version_start + rel)
                .max(cursor);
            let range = byte_range(line, line_idx, version_start, value_end);
            let scope = dsl_declaration_scope(line, line_idx, open_pos, value_end);
            (
                GradleCompletionContext::Version,
                &line[version_start..cursor],
                range,
                scope,
            )
        }
    }
}

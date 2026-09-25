//! Gradle ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Position, Range};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
#[cfg(feature = "lsp-responses")]
use deps_core::quote_scan::{self, CodeSpans, ScanSyntax};
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
            &deps_core::SelectionContext::none(),
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
    ) -> (
        GradleCompletionContext,
        &'a str,
        Range,
        deps_core::completion::DeclarationScope,
    ) {
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        let Some(&line) = lines.get(line_idx) else {
            return (
                GradleCompletionContext::None,
                "",
                Range::default(),
                deps_core::completion::DeclarationScope::Unchecked,
            );
        };
        let col_idx = deps_core::completion::utf16_to_byte_offset(line, position.character)
            .unwrap_or(line.len());
        let before_cursor = &line[..col_idx];

        match crate::parser::GradleManifestKind::from_uri(uri) {
            crate::parser::GradleManifestKind::Catalog => {
                let (ctx, value, range) =
                    detect_catalog_context(before_cursor, line, col_idx, position.line);
                (
                    ctx,
                    value,
                    range,
                    deps_core::completion::DeclarationScope::Unchecked,
                )
            }
            // `settings.gradle(.kts)`/`build.gradle(.kts)` also declare plugins
            // (`id(...) version "..."`); a plugin id or version literal has no colon and, before
            // issue #1447's fix, was misdetected as a `Package` context, issuing a registry
            // *search* on the typed text (issues #1436/#1441/#1446). `detect_dsl_context`'s
            // `Package` arm now gates on a call-shape check for every manifest kind that reaches
            // it — `id`/`kotlin`/`version` are positively-excluded call words (see
            // `NON_DEPENDENCY_CALL_WORDS`), so that gate alone withholds completion here; no
            // Settings/Build-specific suppression is needed on top of it (previously
            // `is_plugin_version_literal_position`, removed as redundant).
            crate::parser::GradleManifestKind::KotlinBuild
            | crate::parser::GradleManifestKind::GroovyBuild
            | crate::parser::GradleManifestKind::Settings => {
                detect_dsl_context(before_cursor, line, col_idx, position.line)
            }
            crate::parser::GradleManifestKind::Other => (
                GradleCompletionContext::None,
                "",
                Range::default(),
                deps_core::completion::DeclarationScope::Unchecked,
            ),
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn dsl_declaration_scope(
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
#[cfg(feature = "lsp-responses")]
fn enclosing_open_paren(text: &str, code: &CodeSpans<'_>) -> Option<usize> {
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn call_word_before_paren(blanked: &str, paren_pos: usize) -> &str {
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn word_before(rest: &str) -> &str {
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
#[cfg(feature = "lsp-responses")]
const MAX_VARARG_SIBLINGS: usize = 32;

/// Walks `rest` backward over up to [`MAX_VARARG_SIBLINGS`] already-closed, comma-separated
/// sibling arguments — Gradle Groovy's vararg form of a dependency-configuration call,
/// `implementation "a:b:1.0", "c:d:2.0<cursor>` — returning what remains before the first
/// non-sibling boundary, and whether at least one `,` was actually consumed.
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn skip_vararg_siblings(mut rest: &str) -> (&str, bool) {
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
#[cfg(feature = "lsp-responses")]
enum CallWordResolution<'a> {
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
#[cfg(feature = "lsp-responses")]
fn resolve_call_word<'a>(blanked: &'a str, code: &CodeSpans<'a>) -> CallWordResolution<'a> {
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
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageGate {
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
#[cfg(feature = "lsp-responses")]
const NON_DEPENDENCY_CALL_WORDS: &[&str] = &[
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

#[cfg(feature = "lsp-responses")]
fn classify_word(word: &str) -> PackageGate {
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn package_completion_gate(line: &str, open_pos: usize) -> PackageGate {
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
#[cfg(feature = "lsp-responses")]
fn current_field_start(before_cursor: &str) -> usize {
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn quoted_key_precedes_colon(before_colon: &str) -> bool {
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
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn detect_dsl_context<'a>(
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
            let (ctx_type, value, range, scope) =
                Self::detect_completion_context(content, position, uri);

            // Exhaustive on purpose (#819/#793); each arm also picks the CompletionOrigin it maps to (#1195).
            let (items, origin) = match ctx_type {
                GradleCompletionContext::Version => {
                    // #1134: finds+literal-checks the dependency; #1136: complete_versions_generic_from's own gate rejects a non-registry `dep.source()`; #1191: `scope` restricts the same-line fallback to this literal's own declaration.
                    let items = match deps_core::completion::literal_version_dependency_in_scope(
                        parse_result,
                        position,
                        content,
                        range,
                        scope,
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
                                &parse_result.selection_context(),
                            )
                            .await
                        }
                        None => vec![],
                    };
                    (items, deps_core::completion::CompletionOrigin::Version)
                }
                GradleCompletionContext::Package => {
                    let items = self.complete_package_names(value, range).await;
                    (items, deps_core::completion::CompletionOrigin::PackageName)
                }
                GradleCompletionContext::None => {
                    (vec![], deps_core::completion::CompletionOrigin::Unresolved)
                }
            };
            Completions::from(items).with_origin(origin)
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
        Some(format!("implementation(\"{}:{latest}\")", name.as_str()))
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
        // #1212: closes the follow-up noted in the previous `no_non_registry_fixture` reason —
        // Gradle 6+'s `content { includeGroup(...) }` restriction is a real static per-group
        // binding (see `parser::parse_repository_content_restrictions`), unlike the general
        // `repositories { }` DSL (still unclassifiable without real Groovy/Kotlin evaluation).
        non_registry_fixture: "build.gradle.kts" => r#"
repositories {
    maven {
        url = "https://repo.acme.internal/maven"
        content {
            includeGroup("com.acme")
        }
    }
}
dependencies {
    implementation("com.acme:secretlib:1.0.0")
}
"#;
    }

    // #1370/#1372/#1391: Gradle's parser preserves an unresolved `$var`/`${var}` reference
    // (and a malformed bracket range with one embedded, e.g. `[1.0,$hi`) as
    // `Some(version_requirement)` — it reaches `deps_core::edit::plan_vulnerability_fix`
    // directly, so `GradleFormatter::requirement_is_placeholder`'s central gate must actually
    // hold (`GradleFormatter` no longer has its own `format_version_replacing` guard; the
    // shared `edit::replacement_text` gate covers it).
    deps_core::unresolved_requirement_conformance! {
        mod gradle_unresolved_requirement_conformance;
        build: GradleEcosystem::new(make_cache());
        reachable: true;
        // #1370 critic M3: `${v}` (braced form) and `[$lo,` (variable in the lower-bound
        // position, distinct from `[1.0,$hi`'s upper-bound position) alongside the original
        // bare `$someVersion` and `[1.0,$hi` — the deleted hand-written tests covered both
        // range positions, so this fixture restores that coverage.
        fixture: "build.gradle.kts" =>
            "dependencies {\n    implementation(\"com.example:some-lib:$someVersion\")\n    implementation(\"com.example:braced-var:${v}\")\n    implementation(\"com.example:malformed-range:[1.0,$hi\")\n    implementation(\"com.example:malformed-range-lower:[$lo,2.0]\")\n}\n";
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    // #1447: the `Package` arm's colon-count heuristic (0 or 1 colons) alone can't
    // distinguish a partial dependency coordinate from any other open string literal — these
    // four are the exact false-positive shapes reported on the issue, none of which is a
    // partial `group`/`group:artifact` coordinate. All must now resolve to `None` rather than
    // issuing a stray Maven Central search on the typed text.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_plugin_id_argument_is_not_package() {
        // id("com.exa|
        let line = r#"id("com.exa"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_kotlin_dsl_shorthand_argument_is_not_package() {
        // kotlin("jv|
        let line = r#"kotlin("jv"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_project_metadata_assignment_is_not_package() {
        // group = "|
        let line = r#"group = ""#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_repository_url_argument_is_not_package() {
        // url = uri("https:|
        let line = r#"url = uri("https:"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// impl-critic S1/M1 follow-up: `include(":ap<cursor>")` — the highest-traffic
    /// false-positive shape, present in essentially every `settings.gradle(.kts)` — must not
    /// issue a registry search on the typed project-path prefix.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_settings_include_argument_is_not_package() {
        let content = r#"include(":ap"#;
        let uri = deps_core::test_util::test_uri("/project/settings.gradle.kts");
        let position = Position::new(0, u32::try_from(content.len()).unwrap());

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    // #1447: a compact coordinate wrapped in real parens must still resolve, not just the
    // paren-less form already covered by
    // `test_detect_dsl_context_escaped_quote_in_earlier_group_does_not_block_completion` —
    // proves `enclosing_open_paren` finds the call's own `(` directly, without needing the
    // comma-walk fallback at all.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_parenthesized_vararg_second_argument_is_package() {
        // implementation("a:b:1.0", "c|
        let line = r#"implementation("a:b:1.0", "c"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "c");
    }

    // Regressions for impl-critic S1 on #1447: the `Package` gate is default-allow, so these
    // shapes — none of which is a positively-excluded call word — must resolve to `Package`,
    // not be silently withheld just because this heuristic can't positively recognize them.

    /// The enclosing `(` sits on an earlier line; `detect_completion_context` only scans the
    /// cursor's own line, so neither `enclosing_open_paren` nor a call word is visible here at
    /// all — must classify as `Indeterminate` (allow), not `Excluded` (deny).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_multiline_call_package_is_allowed() {
        // implementation(
        //     "com.google.guava:gua|
        let content =
            "dependencies {\n    implementation(\n        \"com.google.guava:gua\n    )\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let line = content.lines().nth(2).expect("line 2 exists");
        let position = Position::new(2, u32::try_from(line.len()).unwrap());

        let (t, v, _range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::Package,
            "a multi-line call's literal must still get Package completion"
        );
        assert_eq!(v, "com.google.guava:gua");
    }

    /// `library(...)` (a Settings-kind version-catalog-builder call) is not a recognized
    /// dependency-configuration word, but it's not positively excluded either — documented on
    /// main (#1436) as "verified live, still completable".
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_settings_library_call_package_is_allowed() {
        // library("guava", "com.google.guava:gua|
        let content = r#"library("guava", "com.google.guava:gua"#;
        let uri = deps_core::test_util::test_uri("/project/settings.gradle.kts");
        let position = Position::new(0, u32::try_from(content.len()).unwrap());

        let (t, v, _range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.google.guava:gua");
    }

    /// Kotlin's string-invoke call syntax (`"implementation"(...)`, the standard
    /// `subprojects {}`/`allprojects {}` pattern) has a closing quote, not an identifier
    /// character, immediately before its `(` — the word scan finds nothing, not a real word.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_kotlin_string_invoke_package_is_allowed() {
        // "implementation"("com.google.guava:gua|
        let line = r#""implementation"("com.google.guava:gua"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.google.guava:gua");
    }

    /// A plugin-registered configuration this crate's `is_dependency_configuration` doesn't
    /// know about (e.g. the Android Gradle Plugin's `coreLibraryDesugaring`) must still get
    /// Package completion.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_custom_configuration_package_is_allowed() {
        // coreLibraryDesugaring("com.android.tools:de|
        let line = r#"coreLibraryDesugaring("com.android.tools:de"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.android.tools:de");
    }

    /// impl-critic S1 addendum: the `io.spring.dependency-management` plugin's own DSL
    /// (`dependencyManagement { dependencies { dependency '...' } }`) uses the paren-less,
    /// singular `dependency` call — not a recognized `is_dependency_configuration` word, and
    /// not positively excluded either.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_spring_dependency_management_package_is_allowed() {
        // dependency 'org.springframework:spring-co|
        let line = r"dependency 'org.springframework:spring-co";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "org.springframework:spring-co");
    }

    /// Regression for impl-critic S2 on #1447: `dsl_declaration_scope`'s `Within` span used to
    /// start at the configuration word, extending across an earlier, already-closed vararg
    /// sibling — pass 2's anchor-containment check then wrongly admitted that sibling. The
    /// parser's own DSL regexes require an identifier word directly before the quote, so they
    /// only ever capture the FIRST comma-separated argument as a real `GradleDependency`; the
    /// second sibling here is deliberately never parsed, forcing pass 1 to miss and pass 2 to
    /// be what's under test. Same-family libraries sharing a version prefix
    /// (`io.ktor:ktor-client-core` / `-cio`) make the misattribution realistic.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_vararg_sibling_not_misattributed() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies { implementation \"io.ktor:ktor-client-core:2.3.0\", \"io.ktor:ktor-client-cio:2.3.0\" }\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "only the first vararg argument parses as a real dependency: {content}"
        );
        assert_eq!(
            parse_result.dependencies()[0].name().as_str(),
            "io.ktor:ktor-client-core"
        );

        let line = content.lines().next().unwrap();
        let col = line.rfind("2.3.0").unwrap() + 3; // mid-version, inside the unparsed sibling
        let before = &line[..col];
        let (ctx, _, range, scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(ctx, GradleCompletionContext::Version);

        let position = Position::new(0, u32::try_from(col).unwrap());
        let resolved = deps_core::completion::literal_version_dependency_in_scope(
            parse_result.as_ref(),
            position,
            content,
            range,
            scope,
        );
        assert!(
            resolved.is_none(),
            "must not misattribute the unparsed vararg sibling to the earlier, already-parsed \
             ktor-client-core dependency: got {:?}",
            resolved.map(|d| d.name().as_str().to_string())
        );
    }

    /// Regression for impl-critic S3 on #1447: an uncapped comma-walk re-scans the whole
    /// remaining text per sibling (`O(line length^2)`), live-reproduced as a completion-handler
    /// hang on a crafted ~100 KB line with ~20k siblings. `skip_vararg_siblings` bounds this to
    /// `MAX_VARARG_SIBLINGS` iterations, so it must both complete quickly and correctly decline
    /// to walk all the way back to the call word when the sibling count exceeds the cap.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_skip_vararg_siblings_bounded_for_crafted_input() {
        let mut rest = String::from("implementation ");
        for _ in 0..5_000 {
            rest.push_str("\"a\", ");
        }
        let rest = rest.trim_end();

        let start = std::time::Instant::now();
        let (remaining, consumed) = skip_vararg_siblings(rest);
        let elapsed = start.elapsed();

        assert!(consumed, "at least one sibling comma must be consumed");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "must not hang on a crafted line with an unrealistic sibling count: took {elapsed:?}"
        );
        assert_ne!(
            remaining, "implementation",
            "capped at MAX_VARARG_SIBLINGS, so 5000 siblings must not all be walked over"
        );
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

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
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

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
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

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "café");
        assert_eq!(
            range,
            Range::new(Position::new(0, 16), Position::new(0, 26))
        );
    }

    /// Regression test for the live-verified bug fixed alongside issue #1436: a cursor inside
    /// a `settings.gradle.kts` plugin's version literal (`id("x") version "1.<cursor>"`) has
    /// no colon, so before this fix `detect_dsl_context` (shared with `build.gradle(.kts)`)
    /// misdetected it as a `Package` context and completion issued a stray registry search on
    /// the typed version text. Must now resolve to `None` — not silently regress back to
    /// `Package`.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_settings_plugin_version_literal_is_none() {
        let content = "pluginManagement {\n    plugins {\n        id(\"com.example.plugin\") version \"1.2.3\"\n    }\n}\n";
        let uri = deps_core::test_util::test_uri("/project/settings.gradle.kts");
        let line = content.lines().nth(2).expect("line 2 exists");
        // Cursor inside "1.2.3", right after "1.2" (UTF-16 units == byte offset, ASCII line).
        let col =
            u32::try_from(line.find("1.2.3\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(2, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// Companion to the regression test above (issue #1436 Q1): the Settings-kind suppression
    /// must be scoped to the plugin-version-literal shape specifically, not every completion in
    /// a `settings.gradle.kts` file — a compact `group:artifact:version` coordinate elsewhere on
    /// the same kind of file (e.g. inside `versionCatalogs { create("libs") { library(...) } }`)
    /// still reaches the same DSL detection every `build.gradle(.kts)` position uses.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_settings_compact_coordinate_still_detected() {
        let content = "library(\"guava\", \"com.google.guava:guava:31.1\")\n";
        let uri = deps_core::test_util::test_uri("/project/settings.gradle.kts");
        let col =
            u32::try_from(content.find("31.1\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(0, col);

        let (t, v, _range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::Version,
            "a real compact coordinate's version segment must still be detected in a Settings-kind file"
        );
        assert_eq!(v, "31.");
    }

    /// Regression test for issue #1441: the same plugin-version-literal misdetection fixed for
    /// `settings.gradle.kts` in #1436 also applies to `build.gradle.kts`'s top-level
    /// `plugins { id(...) version "..." }` block, which went through the unmodified
    /// `detect_dsl_context` and issued the same stray registry search.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_kotlin_build_plugin_version_literal_is_none() {
        let content = "plugins {\n    id(\"com.example.plugin\") version \"1.2.3\"\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col =
            u32::try_from(line.find("1.2.3\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// Groovy-DSL companion of the Kotlin-DSL regression test above (issue #1441): the same
    /// `plugins { id "..." version "..." }` shape in `build.gradle` (Groovy) must not be
    /// misdetected either — cross-DSL parity for this project's Gradle support.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_groovy_build_plugin_version_literal_is_none() {
        let content = "plugins {\n    id \"com.example.plugin\" version \"1.2.3\"\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col =
            u32::try_from(line.find("1.2.3\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// Companion to the two regression tests above (issue #1441): the suppression must be
    /// scoped to the plugin-version-literal shape specifically, not every completion in a
    /// `build.gradle(.kts)` file — a regular dependency coordinate's version segment elsewhere
    /// in the same file must still be detected.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_kotlin_build_compact_coordinate_still_detected() {
        let content = "implementation(\"com.google.guava:guava:31.1\")\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let col =
            u32::try_from(content.find("31.1\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(0, col);

        let (t, v, _range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::Version,
            "a real dependency coordinate's version segment must still be detected in a build.gradle.kts file"
        );
        assert_eq!(v, "31.");
    }

    /// Regression test for impl-critic finding M1 (issue #1441 review): the method-call form
    /// `id("x").version("1.2<cursor>")` — a trailing `(` between `version` and the quote —
    /// must also be suppressed, not just the infix `version "1.2<cursor>"` form.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_kotlin_build_plugin_version_method_call_literal_is_none() {
        let content = "plugins {\n    id(\"com.example.plugin\").version(\"1.2.3\")\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col =
            u32::try_from(line.find("1.2.3\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "method-call-form plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// Groovy companion of the method-call regression test above (impl-critic M1): the
    /// `version(...)` call form (no dot, Groovy's optional-parens style) must also be
    /// suppressed.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_groovy_build_plugin_version_call_literal_is_none() {
        let content = "plugins {\n    id 'com.example.plugin' version('1.2.3')\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col = u32::try_from(line.find("1.2.3'").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "version(...) call-form plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// impl-critic M3: `kotlin("jvm") version "..."` — the Kotlin-DSL shorthand for
    /// first-party plugins — must be suppressed the same as the generic `id(...)` form.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_kotlin_build_plugin_shorthand_version_literal_is_none() {
        let content = "plugins {\n    kotlin(\"jvm\") version \"1.9.0\"\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col =
            u32::try_from(line.find("1.9.0\"").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "kotlin(...) shorthand plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    /// impl-critic M3: the single-quoted Groovy infix form `id 'x' version '1.2'` must be
    /// suppressed the same as the double-quoted form already covered above.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_completion_context_groovy_build_plugin_single_quoted_version_literal_is_none() {
        let content = "plugins {\n    id 'com.example.plugin' version '1.2.3'\n}\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let line = content.lines().nth(1).expect("line 1 exists");
        let col = u32::try_from(line.find("1.2.3'").expect("version literal present")).unwrap() + 3;
        let position = Position::new(1, col);

        let (t, v, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
        assert_eq!(
            t,
            GradleCompletionContext::None,
            "single-quoted plugin version literal must not be misdetected as Package"
        );
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
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

    // #1175: single-quote catalog values, cross-quote-style non-desync, and the
    // inline-table comma-split fix.

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_single_quoted() {
        let line = "version = '1.0";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_module_single_quoted() {
        let line = "module = 'com.a:b";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "com.a:b");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_ref_single_quoted_keeps_placeholder_range() {
        let line = "version.ref = 'junit";
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "junit");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_double_quoted_apostrophe_content_no_desync() {
        // Both the `'` count and the `"` count in `after` are odd here — a per-quote-char
        // parity check cannot disambiguate which delimiter is actually open (#1175). The
        // shared left-to-right scan resolves it: the open literal is delimited by `"`.
        let line = "version = \"1.0-o'brien";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0-o'brien");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_module_single_quoted_double_quote_content_no_desync() {
        let line = "module = 'a\"b";
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Package);
        assert_eq!(v, "a\"b");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_inline_table_module_single_version_double_no_comma_desync() {
        // module = 'a,b', version = "1.0| — the comma inside `module`'s single-quoted value
        // must not be mistaken for the inline-table field separator. Positive coverage, not
        // a regression discriminator: impl-critic C1 found the pre-#1175 `"`-only
        // `in_string` toggle also lands on the correct field here (a later real
        // `"`-delimited comma overwrites `field_start` to the same position regardless), so
        // this input alone does not distinguish old from new behavior — see
        // `test_detect_catalog_context_inline_table_comma_split_regression_c1` below for an
        // input that does.
        let line = r#"{ module = 'a,b', version = "1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_inline_table_module_double_version_single_no_quote_style_desync()
    {
        // module = "a,b", version = '1.0| — this variant fails under the pre-#1175 code, but
        // (impl-critic C1) because of the `"`-only quote-parity gate #1175 replaces, not
        // because of a comma-split bug; it overlaps with the dedicated quote-style coverage
        // in `test_detect_catalog_context_version_double_quoted_apostrophe_content_no_desync`/
        // `test_detect_catalog_context_module_single_quoted_double_quote_content_no_desync`.
        let line = r#"{ module = "a,b", version = '1.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "1.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_inline_table_comma_split_regression_c1() {
        // Genuinely discriminating comma-split input (impl-critic C1): `version`'s value is
        // a single-quoted TOML range literal containing a comma, which the pre-#1175
        // `"`-only `in_string` toggle never recognized as an open string, misreading the
        // comma as the inline-table field separator and desyncing `current_field_start`.
        let line = r#"{ module = "a:b", version = '[1.0,2.0"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, _range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::Version);
        assert_eq!(v, "[1.0,2.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_catalog_context_version_trailing_comment_cursor_at_line_end_is_none() {
        let line = r#"version = "1.0" # don't bump"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range) = detect_catalog_context(before, line, col, 0);
        assert_eq!(t, GradleCompletionContext::None);
        assert_eq!(v, "");
        assert_eq!(range, Range::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_current_field_start_regression_c1_discriminates_old_scanner_bug_version_range() {
        // impl-critic C1: `{ module = 'a,b', version = "1.0` does NOT discriminate the old
        // `"`-only `in_string` toggle from the new scan — the old scanner also lands on the
        // real comma here (a later real `"`-delimited comma would just overwrite
        // `field_start` to the same position either way), so a test on that input alone
        // passes unedited against the pre-#1175 code and guards nothing. This input does
        // discriminate: `version`'s value is a single-quoted TOML range literal, which the
        // old `"`-only toggle never recognized as an open string at all, so its comma was
        // misread as a field separator there.
        let before_cursor = "{ module = \"a:b\", version = '[1.0,2.0";
        let field_start = current_field_start(before_cursor);
        assert_eq!(&before_cursor[field_start..], " version = '[1.0,2.0");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_current_field_start_regression_c1_discriminates_old_scanner_bug_single_quoted_only() {
        // Second discriminating input (impl-critic C1): a bare single-quoted field with a
        // comma inside it. The old `"`-only toggle never opened a string for the `'`, so it
        // read the comma inside `'a,b` as a field separator; the new `CodeSpans`-based scan
        // correctly keeps it inside the still-open literal.
        let before_cursor = "{ module = 'a,b";
        let field_start = current_field_start(before_cursor);
        assert_eq!(field_start, 0);
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_current_field_start_comma_inside_comment_is_not_a_field_boundary() {
        let before_cursor = "module = \"a\", version = \"1.0\" # a, b";
        let field_start = current_field_start(before_cursor);
        assert_eq!(&before_cursor[field_start..], " version = \"1.0\" # a, b");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_dsl_context_unterminated_falls_back_to_cursor() {
        // implementation("junit:junit   (no closing quote/paren on the line) — the range
        // must stop at the cursor, not swallow the rest of the line.
        let line = r#"implementation("junit:junit"#;
        let col = line.len();
        let before = &line[..col];
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        assert_eq!(
            result,
            Completions::default().with_origin(deps_core::completion::CompletionOrigin::Version)
        );
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

        let (ctx, _, _, _) =
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
        assert_eq!(
            result.origin,
            deps_core::completion::CompletionOrigin::Unresolved
        );
    }

    /// #1195 supplementary coverage: the `GradleCompletionContext::Package` arm must stamp
    /// `CompletionOrigin::PackageName` end-to-end through `generate_completions`, not just
    /// resolve the context — a swapped origin literal in the hand-written match would
    /// otherwise have no test catching it.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_package_context_stamps_package_name_origin() {
        // See the comment in `test_parse_manifest_kts` on why this guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let eco = GradleEcosystem::new(make_cache());
        let content = r#"implementation("junit:junit:4.13.2")"#;
        let uri = deps_core::test_util::test_uri("/project/build.gradle.kts");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        // Only "j" typed: too short for `complete_package_names_generic` to search the
        // registry, so this stays network-free while still exercising the `Package` arm.
        let (ctx, value, _, _) =
            GradleEcosystem::detect_completion_context(content, Position::new(0, 17), &uri);
        assert_eq!(ctx, GradleCompletionContext::Package);
        assert_eq!(value, "j");

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(0, 17),
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(
            result,
            Completions::default()
                .with_origin(deps_core::completion::CompletionOrigin::PackageName)
        );
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
        assert_eq!(
            result,
            Completions::default().with_origin(deps_core::completion::CompletionOrigin::Version)
        );
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

        let (ctx, _, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
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

        let (ctx, _, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
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
            Completions::default().with_origin(deps_core::completion::CompletionOrigin::Version),
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
                Completions::default()
                    .with_origin(deps_core::completion::CompletionOrigin::Version),
                "partial alias {partial:?} must not offer the unfiltered version list: {content}"
            );
        }
    }

    // `complete_versions` has no offline guard for an already-well-formed package name, so
    // the "happy path" needs live Maven Central access, mirroring `deps_maven`'s equivalent
    // characterization test.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore = "requires network access"]
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, range, _scope) = detect_dsl_context(before, line, col, 0);
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
        let (t, v, _range, _scope) = detect_dsl_context(before, line, col, 0);
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

        let (ctx, _, range, _scope) =
            GradleEcosystem::detect_completion_context(content, position, &uri);
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

    /// #1191: a same-line, non-dependency literal that happens to look version-shaped
    /// (`println("a:b:1.0.0")` beside a real `com.example:foo:1.0.0` dependency) must not be
    /// misattributed to that dependency. Pins exactly what `dsl_declaration_scope` prevents:
    /// under the real computed scope (`Outside`, since `println` is not a recognized
    /// configuration) the result is `None`, but under `DeclarationScope::Unchecked` — the
    /// pre-#1191 behavior — the same-line fallback wrongly resolves `foo`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_minified_dsl_non_dependency_literal_is_not_attributed()
    {
        let eco = GradleEcosystem::new(make_cache());
        let content =
            "dependencies { implementation(\"com.example:foo:1.0.0\"); println(\"a:b:1.0.0\") }\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "println(...) must not parse as a dependency: {content}"
        );

        let line = content.lines().next().unwrap();
        let literal_start = line.find("\"a:b:1.0.0\"").unwrap() + 1;
        let col = literal_start + "a:b:1.0.0".len();
        let before = &line[..col];
        let (ctx, _, range, scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(ctx, GradleCompletionContext::Version);
        assert_eq!(scope, deps_core::completion::DeclarationScope::Outside);

        let position = Position::new(0, col as u32);

        assert!(
            deps_core::completion::literal_version_dependency_in_scope(
                parse_result.as_ref(),
                position,
                content,
                range,
                scope,
            )
            .is_none(),
            "the real computed scope must reject println's non-dependency literal"
        );
        assert_eq!(
            deps_core::completion::literal_version_dependency_in_scope(
                parse_result.as_ref(),
                position,
                content,
                range,
                deps_core::completion::DeclarationScope::Unchecked,
            )
            .map(|d| d.name().as_str().to_string()),
            Some("com.example:foo".to_string()),
            "Unchecked pins exactly what the scope prevents: same-line misattribution to foo"
        );
    }

    /// #1191: a still-unparsed second declaration mid-typing on the same line as a real
    /// dependency (`implementation("org.other:bar:1.0.0`, no closing quote/paren yet — so
    /// `crate::parser::groovy` never captures it as a `Dependency`) must not be misattributed
    /// to the first, already-parsed dependency, even when its typed-so-far text happens to
    /// coincide with the first dependency's own version (the scenario `Unchecked`'s same-line
    /// fallback would wrongly resolve).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_minified_dsl_unparsed_second_declaration_is_not_attributed()
     {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies { implementation(\"com.example:foo:1.0.0\"); implementation(\"org.other:bar:1.0.0";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "the unterminated second declaration must not parse: {content}"
        );

        let line = content.lines().next().unwrap();
        let col = line.len();
        let before = &line[..col];
        let (ctx, _, range, scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(ctx, GradleCompletionContext::Version);

        let position = Position::new(0, col as u32);

        assert_eq!(
            deps_core::completion::literal_version_dependency_in_scope(
                parse_result.as_ref(),
                position,
                content,
                range,
                deps_core::completion::DeclarationScope::Unchecked,
            )
            .map(|d| d.name().as_str().to_string()),
            Some("com.example:foo".to_string()),
            "Unchecked pins the misattribution this test's real scope must prevent"
        );
        assert!(
            deps_core::completion::literal_version_dependency_in_scope(
                parse_result.as_ref(),
                position,
                content,
                range,
                scope,
            )
            .is_none(),
            "the real computed scope must not misattribute to the first dependency"
        );
    }

    /// #1191: a raw-text scanner's own detected version span can diverge from the AST's
    /// `version_range` by exactly one character (here, a space after the colon —
    /// `find_version_range`, `crates/deps-gradle/src/parser/mod.rs`, finds the *trimmed*
    /// version text and so skips the space, while `detect_dsl_context`'s own colon-counted
    /// `version_start` does not) — pass 1 must miss at that boundary, and pass 2's same-line
    /// fallback, restricted to this dependency's own `Within` scope, must still rescue it.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_literal_version_dependency_same_line_boundary_rescue_still_resolves() {
        let eco = GradleEcosystem::new(make_cache());
        let content = "dependencies { implementation(\"com.example:foo: 1.0.0\") }\n";
        let uri = deps_core::test_util::test_uri("/project/build.gradle");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let deps = parse_result.dependencies();
        assert_eq!(
            deps.len(),
            1,
            "fixture must parse one dependency: {content}"
        );
        let dep = deps[0];
        let version_range: Range = dep.version_range().unwrap().into();

        let line = content.lines().next().unwrap();
        let col = line.find("foo:").unwrap() + "foo:".len();
        let before = &line[..col];
        let (ctx, _, range, scope) = detect_dsl_context(before, line, col, 0);
        assert_eq!(ctx, GradleCompletionContext::Version);

        let position = Position::new(0, col as u32);
        assert!(
            position.character < version_range.start.character,
            "cursor must sit outside the AST's own version_range, so pass 1 misses and pass 2 \
             is what resolves this: {version_range:?} vs cursor {position:?}"
        );

        let resolved = deps_core::completion::literal_version_dependency_in_scope(
            parse_result.as_ref(),
            position,
            content,
            range,
            scope,
        )
        .expect("pass 2, restricted to this dependency's own Within scope, must rescue it");
        assert_eq!(resolved.name(), dep.name());
    }

    /// #1191: [`dsl_declaration_scope`] must recognize every call shape
    /// `crate::parser::groovy`/`crate::parser::kotlin`'s own regexes accept (direct,
    /// with/without parens, platform-wrapped, prefix-convention configurations like `kapt*`)
    /// as `Within`, and reject an unrecognized call or a literal with nothing call-shaped
    /// before it as `Outside`. Each fixture ends in the literal's opening quote, so
    /// `open_pos` is always its last byte.
    #[test]
    fn test_dsl_declaration_scope_recognizes_configuration_calls() {
        let within_cases: &[&str] = &[
            "implementation(\"",
            "implementation (\"",
            "implementation '",
            "implementation(platform(\"",
            "compile platform('",
            "kaptTest '",
        ];
        for line in within_cases {
            let open_pos = line.len() - 1;
            let scope = dsl_declaration_scope(line, 0, open_pos, line.len());
            assert!(
                matches!(scope, deps_core::completion::DeclarationScope::Within(_)),
                "{line:?} must resolve to Within, got {scope:?}"
            );
        }

        let outside_cases: &[&str] = &["println(\"", "unknown '", "    \""];
        for line in outside_cases {
            let open_pos = line.len() - 1;
            let scope = dsl_declaration_scope(line, 0, open_pos, line.len());
            assert_eq!(
                scope,
                deps_core::completion::DeclarationScope::Outside,
                "{line:?} must resolve to Outside"
            );
        }
    }
}

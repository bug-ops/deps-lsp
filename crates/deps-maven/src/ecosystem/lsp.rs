//! LSP-only completion support for Maven (issues #819/#1137/#1181/#1195/#1282): raw-text XML
//! completion-context detection for `pom.xml`.
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use quick_xml::Reader;
use quick_xml::events::Event;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionTextEdit, Position, Range as LspRange, TextEdit,
};

use deps_core::completion::VersionReplacement;
use deps_core::{
    ParseResult as ParseResultTrait, Registry, is_safe_maven_coordinate_segment,
    lsp_helpers::warn_rejected_value,
};

use crate::types::ArtifactInfo;

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: the two range delimiters `crate::range::is_range` accepts
/// (`[1.0,2.0)`, `(,2.0]`) — `deps_core::interval::BracketStyle::Standard`, unlike Gradle's
/// `AllowReversed`, has no reversed-bracket leading `]` form. A bare `<version>` (no leading
/// bracket) is a "soft" recommended version, not a range, and has no operator to strip.
/// Originally left empty, which meant a completion prefix like `"[2.2"` was never stripped
/// down to `"2.2"` and so never prefix-matched any real version (#1137 critic S1).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &['[', '('];

/// Which half of a Maven `groupId:artifactId` coordinate a completion should insert.
///
/// A pom.xml `<groupId>`/`<artifactId>` tag only ever holds one half of the coordinate,
/// so the completion inserted into it must not be the full "group:artifact" search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MavenNameField {
    GroupId,
    ArtifactId,
}

/// Which manifest position a Maven completion request resolved to, or none.
///
/// A crate-local, non-`&'static str` replacement for the hand-rolled tag-name return of
/// [`super::MavenEcosystem::detect_xml_context`] (issue #819, same bug class as #793/#118): the
/// dispatch match in [`deps_core::Ecosystem::generate_completions`]'s override for this crate
/// must be exhaustive over this enum, so adding a new completable tag forces a compile error at
/// the match instead of silently falling through a `_ => vec![]` wildcard. `Version` does map
/// conceptually to [`deps_core::completion::CompletionContext::Version`] — the reason this
/// crate keeps its own full override rather than the shared dispatch isn't a missing
/// concept, it's the detection *source*: `detect_xml_context` scans the manifest's raw text
/// for `<version>`/`<artifactId>`/`<groupId>` tags directly, independent of
/// `parse_result.dependencies()` (deliberately blind to the *parsed* dependency list — see
/// `test_generate_completions_version_context_no_dependency_at_position_returns_empty`
/// below), whereas [`deps_core::completion::detect_completion_context`] derives its context
/// from parsed-AST dependency ranges. A matched `<version>` is, since #1181, still checked
/// against the raw-text XML *structure* around it (is it actually nested inside a
/// `<dependency>`/`<plugin>` element, not just textually nearest) — this is a raw-text
/// ancestry check, not a lookup into `parse_result.dependencies()`, so the "dependency-blind"
/// characterization above still holds for the parsed list, just not for XML nesting anymore.
/// `ArtifactId`/`GroupId` genuinely have no counterpart —
/// a pom.xml coordinate splits `groupId`/`artifactId` across two separate tags, unlike
/// `CompletionContext::PackageName`'s single combined name (see that method's default-impl
/// doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MavenXmlContext {
    /// Cursor is inside a `<version>` tag's value.
    Version,
    /// Cursor is inside an `<artifactId>` tag's value.
    ArtifactId,
    /// Cursor is inside a `<groupId>` tag's value.
    GroupId,
    /// Cursor is inside or immediately around a self-closing `<version/>` (or
    /// `<version />`) tag, which has no value slot at all — `tag_span` is the whole tag's
    /// range, replaced wholesale with `<version>` + version + `</version>` instead of an
    /// insert at the cursor (see [`deps_core::completion::VersionReplacement`]'s doc for
    /// why a cursor-insert can never land correctly here).
    SelfClosingVersion {
        /// The full `<version/>` token's range, UTF-16 units.
        tag_span: LspRange,
    },
    /// Cursor is not inside any completable tag.
    None,
}

/// The token a self-closing `<version/>` tag starts with — shared by
/// [`find_self_closing_version_tag`] and [`VERSION_OPEN_TAG_UTF16_LEN`] so the two never
/// drift out of sync.
pub(super) const VERSION_OPEN_TAG: &str = "<version";

/// UTF-16 code unit length of [`VERSION_OPEN_TAG`] — it is pure ASCII, so byte length,
/// `char` count, and UTF-16 length all coincide.
pub(super) const VERSION_OPEN_TAG_UTF16_LEN: u32 = 8;

/// Finds the byte range `[tag_start, tag_end)` of the self-closing `<version/>` (or
/// `<version />`, `<version  />`) tag on `line` whose span contains `cursor_byte`, if any.
///
/// Rejects a longer tag name sharing the same prefix (e.g. `<versionRange/>`) by requiring
/// the character right after [`VERSION_OPEN_TAG`] to be ASCII whitespace or `/`. When several
/// self-closing `<version/>` tags appear on one line, only the occurrence whose
/// `[tag_start, tag_end]` contains `cursor_byte` — inclusive, so the returned span provably
/// contains the completion position per LSP 3.17 — is returned; when the cursor sits exactly
/// on the shared boundary between two adjacent tags (e.g. `<version/><version/>`, cursor right
/// between them), the earlier tag wins, since it is checked first and its inclusive `tag_end`
/// already contains that column.
///
/// Like `detect_xml_context`'s own `<tag>...</tag>` loop, this scanner itself has no
/// XML-comment or element-ancestry awareness and would match `<!-- <version/> -->` on its
/// own — but `detect_xml_context` now runs the same [`innermost_open_element`] ancestry
/// check on every match this function returns (#1181 follow-up): a `<version/>` inside a
/// comment with no real `<dependency>`/`<plugin>` ancestor of its own is correctly rejected.
/// See [`innermost_open_element`]'s own doc for the one case this does not cover — a comment
/// nested *inside* a real `<dependency>`/`<plugin>` — which applies equally to this arm and
/// the `<version>...</version>` arm below, not something introduced here.
// Every bound is an ASCII-token-length offset from an already-valid boundary, same invariant as `detect_xml_context`'s own `#[allow(clippy::string_slice)]`.
#[allow(clippy::string_slice)]
pub(super) fn find_self_closing_version_tag(
    line: &str,
    cursor_byte: usize,
) -> Option<(usize, usize)> {
    let mut search_from = 0;
    while let Some(rel) = line[search_from..].find(VERSION_OPEN_TAG) {
        let tag_start = search_from + rel;
        let after_open = tag_start + VERSION_OPEN_TAG.len();
        let Some(next_char) = line[after_open..].chars().next() else {
            break;
        };
        if next_char != '/' && !next_char.is_ascii_whitespace() {
            // e.g. "<versionRange" — not a bare `<version` tag.
            search_from = after_open;
            continue;
        }
        let after_ws = line[after_open..]
            .find(|c: char| !c.is_ascii_whitespace())
            .map_or(line.len(), |rel_ws| after_open + rel_ws);
        if line[after_ws..].starts_with("/>") {
            let tag_end = after_ws + 2;
            if cursor_byte >= tag_start && cursor_byte <= tag_end {
                return Some((tag_start, tag_end));
            }
            search_from = tag_end;
        } else {
            search_from = after_open;
        }
    }
    None
}

/// Zero-width probe position just past `<version` in `tag_span` — NOT `tag_span` itself,
/// since `dependency_version_range_is_literal`'s `None`-requirement branch would slice the
/// non-empty `"<version/>"` and always return `false`, silently disabling the whole feature.
pub(super) fn self_closing_version_probe_range(tag_span: LspRange) -> LspRange {
    let character = tag_span.start.character + VERSION_OPEN_TAG_UTF16_LEN;
    LspRange {
        start: Position {
            line: tag_span.start.line,
            character,
        },
        end: Position {
            line: tag_span.start.line,
            character,
        },
    }
}

/// Completes the value of a self-closing `<version/>` tag by replacing the whole `tag_span`
/// with `<version>` + version + `</version>` (see [`VersionReplacement`]'s doc for why a
/// cursor-insert can never land correctly here).
///
/// Takes `registry`/`formatter` as trait objects rather than reading `self.registry`/
/// `self.formatter` directly, so this — the arm's entire logic — can run against a test
/// double instead of requiring live network access.
#[allow(
    clippy::too_many_arguments,
    reason = "each parameter is independently meaningful and this is the whole arm's inputs \
              extracted verbatim for testability; wrapping them in a request struct now would \
              have exactly one caller and one test"
)]
pub(super) async fn complete_self_closing_version(
    registry: &dyn Registry,
    formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
    parse_result: &dyn ParseResultTrait,
    position: Position,
    content: &str,
    tag_span: LspRange,
    value: &str,
    freshness: deps_core::FreshnessSettings,
) -> Vec<CompletionItem> {
    let probe_range = self_closing_version_probe_range(tag_span);
    match deps_core::completion::literal_version_dependency(
        parse_result,
        position,
        content,
        probe_range,
    ) {
        Some(dep) => {
            let replacement = VersionReplacement {
                range: tag_span,
                lead: "<version>".to_string(),
                trail: "</version>".to_string(),
                replaced_text: value.to_string(),
            };
            deps_core::completion::complete_versions_generic_replacing(
                registry,
                formatter,
                dep.name(),
                &dep.source(),
                "",
                &[],
                freshness,
                Some(&replacement),
                &parse_result.selection_context(),
            )
            .await
        }
        None => vec![],
    }
}

/// Builds a completion item for one field of a Maven coordinate.
///
/// Reuses [`deps_core::completion::build_package_completion_fields`] for documentation/detail
/// formatting, then overrides the insertable text to just the requested field so it fits
/// the single `<groupId>` or `<artifactId>` tag the cursor is inside. `replace_range` must
/// span the entire existing tag value, not just the already-typed prefix (see
/// [`super::MavenEcosystem::detect_xml_context`]) — the base builder supplies no `insert_text`/
/// `text_edit` at all, so this override is required, not a correction of a placeholder
/// range.
///
/// Returns `None` when the requested field's value doesn't pass
/// [`is_safe_maven_coordinate_segment`], or when the base builder itself rejects the
/// combined `groupId:artifactId` name — a malicious/compromised search result must not
/// reach the manifest as an unsanitized `TextEdit`, so the item is dropped rather than
/// built with unsafe text. A known, benign edge case: two maximal-length segments
/// (128 bytes each, [`is_safe_maven_coordinate_segment`]'s own cap) joined by `:` is
/// 257 bytes, one over [`deps_core::is_safe_package_name`]'s 256-byte cap — an
/// implausibly long but fully legitimate coordinate would be dropped here too,
/// failing closed rather than insecurely.
pub(super) fn build_field_completion(
    artifact: &ArtifactInfo,
    field: MavenNameField,
    replace_range: LspRange,
    index: usize,
    prefix: &str,
) -> Option<CompletionItem> {
    let value = match field {
        MavenNameField::GroupId => artifact.group_id.clone(),
        MavenNameField::ArtifactId => artifact.artifact_id.clone(),
    };

    if !is_safe_maven_coordinate_segment(&value) {
        warn_rejected_value(
            "is_safe_maven_coordinate_segment",
            "maven coordinate field completion",
            &value,
        );
        return None;
    }

    let mut item = deps_core::completion::build_package_completion_fields(artifact, index, prefix)?;

    item.insert_text = Some(value.clone());
    item.filter_text = Some(value.clone());
    // `build_package_completion_fields`'s own `sort_text` ties `prefix` to `artifact.name()`
    // (the full `group:artifact` coordinate), which is the wrong candidate for a bare
    // `artifactId` field completion — recompute it against `value` instead (#1282 S2).
    // This discards the sort_text `build_package_completion_fields` already computed above;
    // not worth restructuring that function's signature to avoid one extra string format on
    // a result list capped at 20-50 items.
    item.sort_text = Some(deps_core::completion::build_completion_sort_text(
        index, prefix, &value,
    ));
    item.text_edit = Some(CompletionTextEdit::Edit(TextEdit {
        range: replace_range,
        new_text: value,
    }));

    Some(item)
}

/// Builds completion items for one field of a Maven coordinate, deduped by that field's value.
///
/// Several search results can share the same `groupId` (or, more rarely, `artifactId`) —
/// collapsed here to one item per distinct value, since they would otherwise insert
/// identical text into the tag and only clutter the list. Keeps the first (highest-relevance,
/// per the registry's own ranking) match for each value.
pub(super) fn build_deduped_field_completions(
    results: &[ArtifactInfo],
    field: MavenNameField,
    replace_range: LspRange,
    prefix: &str,
) -> Vec<CompletionItem> {
    let mut seen = std::collections::HashSet::new();
    results
        .iter()
        .filter(|artifact| {
            let value = match field {
                MavenNameField::GroupId => &artifact.group_id,
                MavenNameField::ArtifactId => &artifact.artifact_id,
            };
            seen.insert(value.clone())
        })
        .enumerate()
        .filter_map(|(index, artifact)| {
            build_field_completion(artifact, field, replace_range, index, prefix)
        })
        .collect()
}

/// Tag name of the innermost XML element open at `offset` (an absolute byte offset into
/// `content`), found via a single forward scan from the document start that pushes on
/// every opening tag and pops on every closing one, stopping once `offset` is reached —
/// used by [`super::MavenEcosystem::detect_xml_context`]'s `Version` arm (#1181) and its
/// self-closing `<version/>` arm (#1181 follow-up) alike, to verify a matched `<version>`
/// (open/close or self-closing) is actually nested inside a `<dependency>`/`<plugin>`, not
/// just nearest on the cursor's physical line.
///
/// Comments (`<!--...-->`), CDATA sections (`<![CDATA[...]]>`), processing instructions
/// (`<?...?>`) and other `<!...>` declarations (including a DOCTYPE's internal subset) are
/// all skipped by `quick_xml`'s own tokenizer, so a commented-out `<dependency>` block can't
/// be mistaken for a live one and an unescaped `>` inside a quoted attribute value never
/// desyncs the scan. This only ever runs against content that
/// `deps-maven::parser::parse_pom_xml` has already accepted as well-formed XML (completion is
/// only reachable with a successfully parsed `ParseResult`), so tags close in strict LIFO
/// order and a plain pop-without-name-check on every close tag is sound. Should that
/// precondition ever stop holding, a `quick_xml` parse error mid-scan truncates the ancestry
/// to whatever was pushed before the error, rather than degrading gracefully like the old
/// hand-rolled scanner did.
///
/// Being opaque cuts both ways: a comment is never *entered*, so `offset` values that fall
/// *inside* one are never distinguished from each other — if the comment itself sits inside a
/// real `<dependency>`/`<plugin>`, every `offset` inside it (including one from a `<version>`
/// or `<version/>` match a caller's raw-text scanner found on the commented-out text) still
/// resolves to that real ancestor, e.g. `<dependency><!-- <version/> --></dependency>` reports
/// `Some("dependency")` for an `offset` inside the comment, same as if the comment weren't
/// there at all. This narrows the #1181 misattribution class without closing every instance of
/// it; a comment with no real ancestor of its own is still correctly rejected (see
/// `test_detect_xml_context_failed_version_ancestry_does_not_suppress_artifact_id`), only a
/// comment nested inside one is not.
///
/// Proving `<version>` sits inside *a* `<dependency>`/`<plugin>` narrows the #1181
/// misattribution class, it does not close it: [`deps_core::completion::literal_version_dependency`]'s
/// pass-2 same-line fallback still ranks purely by same-line distance among *parsed*
/// `Dependency`s, so a `<version>` whose own element never became a `Dependency` (e.g. a
/// `<dependency>` still missing `<groupId>` mid-typing, dropped by `finalize_dep`; or a
/// `<plugin>` whose accumulator got overwritten by a nested `<dependencies>` block it
/// declares) can still resolve to a minified-line neighbor. Out of scope here — same
/// territory as #1147 — do not read this function as a complete fix for the fallback's
/// same-line ranking.
pub(super) fn innermost_open_element(content: &str, offset: usize) -> Option<&str> {
    let mut reader = Reader::from_str(content);
    let mut stack: Vec<&str> = Vec::new();
    // quick-xml's `remove_utf8_bom` drops a leading BOM from its input slice without advancing
    // `buffer_position()`, so every position it reports on BOM'd content is short by the BOM's
    // byte length while `offset` (derived from `content` itself) still counts it — add it back.
    let base = if content.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };

    while let Ok(pos) = usize::try_from(reader.buffer_position()) {
        let pos = pos + base;
        if pos >= offset {
            break;
        }

        match reader.read_event() {
            Ok(Event::Start(e)) => {
                // Strip a namespace prefix (`m:dependency` -> `dependency`) so a
                // namespace-prefixed pom.xml compares the same way `parse_pom_xml` already
                // does via quick-xml's `local_name()` (`parser.rs`) — without this, a
                // prefixed document would keep parsing into real `Dependency`s (hover/
                // diagnostics/code actions unaffected) while completion alone silently
                // stopped triggering, since the qualified name never equals
                // `"dependency"`/`"plugin"` (#1181 critic S1).
                let qname = content
                    .get(pos + 1..pos + 1 + e.name().as_ref().len())
                    .unwrap_or_default();
                stack.push(qname.rsplit(':').next().unwrap_or(qname));
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            Ok(_) => {}
        }
    }

    stack.last().copied()
}

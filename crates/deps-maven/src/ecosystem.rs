//! Maven ecosystem implementation for deps-lsp.

#[cfg(feature = "lsp-responses")]
use quick_xml::Reader;
#[cfg(feature = "lsp-responses")]
use quick_xml::events::Event;
use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionTextEdit, Position, Range as LspRange, TextEdit,
};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::{Completions, VersionReplacement};
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, is_safe_maven_coordinate_segment,
    lsp_helpers::{EcosystemFormatter, warn_rejected_value},
};

use crate::formatter::MavenFormatter;
use crate::registry::MavenCentralRegistry;
#[cfg(feature = "lsp-responses")]
use crate::types::ArtifactInfo;

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: the two range delimiters `crate::range::is_range` accepts
/// (`[1.0,2.0)`, `(,2.0]`) — `deps_core::interval::BracketStyle::Standard`, unlike Gradle's
/// `AllowReversed`, has no reversed-bracket leading `]` form. A bare `<version>` (no leading
/// bracket) is a "soft" recommended version, not a range, and has no operator to strip.
/// Originally left empty, which meant a completion prefix like `"[2.2"` was never stripped
/// down to `"2.2"` and so never prefix-matched any real version (#1137 critic S1).
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &['[', '('];

/// [`Ecosystem`] implementation for Maven (`pom.xml`).
pub struct MavenEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: MavenFormatter,
}

/// Which half of a Maven `groupId:artifactId` coordinate a completion should insert.
///
/// A pom.xml `<groupId>`/`<artifactId>` tag only ever holds one half of the coordinate,
/// so the completion inserted into it must not be the full "group:artifact" search result.
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MavenNameField {
    GroupId,
    ArtifactId,
}

/// Which manifest position a Maven completion request resolved to, or none.
///
/// A crate-local, non-`&'static str` replacement for the hand-rolled tag-name return of
/// [`MavenEcosystem::detect_xml_context`] (issue #819, same bug class as #793/#118): the
/// dispatch match in [`Ecosystem::generate_completions`]'s override for this crate must be
/// exhaustive over this enum, so adding a new completable tag forces a compile error at the
/// match instead of silently falling through a `_ => vec![]` wildcard. `Version` does map
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
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MavenXmlContext {
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
#[cfg(feature = "lsp-responses")]
const VERSION_OPEN_TAG: &str = "<version";

/// UTF-16 code unit length of [`VERSION_OPEN_TAG`] — it is pure ASCII, so byte length,
/// `char` count, and UTF-16 length all coincide.
#[cfg(feature = "lsp-responses")]
const VERSION_OPEN_TAG_UTF16_LEN: u32 = 8;

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
/// Like [`detect_xml_context`]'s own `<tag>...</tag>` loop, this scanner itself has no
/// XML-comment or element-ancestry awareness and would match `<!-- <version/> -->` on its
/// own — but [`detect_xml_context`] now runs the same [`innermost_open_element`] ancestry
/// check on every match this function returns (#1181 follow-up): a `<version/>` inside a
/// comment with no real `<dependency>`/`<plugin>` ancestor of its own is correctly rejected.
/// See [`innermost_open_element`]'s own doc for the one case this does not cover — a comment
/// nested *inside* a real `<dependency>`/`<plugin>` — which applies equally to this arm and
/// the `<version>...</version>` arm below, not something introduced here.
// Every bound is an ASCII-token-length offset from an already-valid boundary, same invariant as `detect_xml_context`'s own `#[allow(clippy::string_slice)]`.
#[cfg(feature = "lsp-responses")]
#[allow(clippy::string_slice)]
fn find_self_closing_version_tag(line: &str, cursor_byte: usize) -> Option<(usize, usize)> {
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
#[cfg(feature = "lsp-responses")]
fn self_closing_version_probe_range(tag_span: LspRange) -> LspRange {
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
#[cfg(feature = "lsp-responses")]
#[allow(
    clippy::too_many_arguments,
    reason = "each parameter is independently meaningful and this is the whole arm's inputs \
              extracted verbatim for testability; wrapping them in a request struct now would \
              have exactly one caller and one test"
)]
async fn complete_self_closing_version(
    registry: &dyn Registry,
    formatter: &dyn deps_core::lsp_helpers::SourcePolicy,
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
/// [`MavenEcosystem::detect_xml_context`]) — the base builder supplies no `insert_text`/
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
#[cfg(feature = "lsp-responses")]
fn build_field_completion(
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
#[cfg(feature = "lsp-responses")]
fn build_deduped_field_completions(
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

impl MavenEcosystem {
    /// Creates a Maven ecosystem instance backed by the given shared HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(cache)),
            formatter: MavenFormatter,
        }
    }

    #[cfg(feature = "lsp-responses")]
    async fn complete_package_names_for_field(
        &self,
        prefix: &str,
        field: MavenNameField,
        replace_range: LspRange,
    ) -> Vec<CompletionItem> {
        if !deps_core::completion::is_valid_completion_prefix_len(prefix) {
            return vec![];
        }
        // #1206 S1: this bespoke path doesn't route through `complete_package_names_generic`, so it needs its own gate.
        if let Some(rejected) = deps_core::completion::reject_credential_bearing_value(
            prefix,
            "maven package-name completion",
        ) {
            return rejected;
        }

        let results = match self.registry.search(prefix, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "Maven registry search failed for '{}': {}",
                    deps_core::net_policy::url_for_tracing(prefix),
                    e
                );
                return vec![];
            }
        };

        build_deduped_field_completions(&results, field, replace_range, prefix)
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

    /// Detects Maven XML completion context at the given position.
    ///
    /// Returns `(context_type, value, value_range)` where `context_type` is a
    /// [`MavenXmlContext`]; `value` is the already-typed prefix up to the cursor, used as
    /// the search query; `value_range` spans the *entire* existing tag value (opening tag
    /// to closing tag, not just up to the cursor) and is the range a completion's
    /// `text_edit` must replace so the whole value is overwritten instead of leaving
    /// trailing characters behind — it is meaningless when `context_type` is
    /// [`MavenXmlContext::None`]. For [`MavenXmlContext::SelfClosingVersion`], `value` and
    /// `value_range` both carry the whole self-closing tag's own raw text/span (there is no
    /// separate "typed prefix" for a tag with no value slot), identical to that variant's
    /// own `tag_span` field.
    ///
    /// `position.character` is a UTF-16 code unit offset (LSP spec) and is converted to a
    /// byte offset once via [`deps_core::completion::utf16_to_byte_offset`] before any
    /// slicing; the returned `value_range`'s `character` fields are converted back to UTF-16
    /// units via [`deps_core::completion::byte_to_utf16_offset`]. This avoids panics on
    /// multi-byte tag content (e.g. accented characters) and keeps the returned range valid
    /// for LSP clients.
    // `col_idx` comes from `utf16_to_byte_offset` (char_indices-based); tag offsets come from
    // `rfind`/`find` of ASCII `<tag>`/`</` tokens. Every slice bound is always a char boundary.
    #[cfg(feature = "lsp-responses")]
    #[allow(clippy::string_slice)]
    fn detect_xml_context<'a>(
        content: &'a str,
        position: Position,
        parse_result: &dyn ParseResultTrait,
    ) -> (MavenXmlContext, &'a str, LspRange) {
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        let Some(&line) = lines.get(line_idx) else {
            return (MavenXmlContext::None, "", LspRange::default());
        };
        let col_idx = deps_core::completion::utf16_to_byte_offset(line, position.character)
            .unwrap_or(line.len());

        let before_cursor = &line[..col_idx];

        // Self-closing `<version/>` has no cursor-insert position that lands inside the
        // element (#1167) — checked before the `<tag>...</tag>` loop below since it matches
        // a structurally different shape (no literal "<version>" open substring for the
        // loop to find anyway). `generate_completions` replaces the whole `tag_span`
        // wholesale via `VersionReplacement` rather than inserting at the cursor.
        if let Some((tag_start, tag_end)) = find_self_closing_version_tag(line, col_idx) {
            // #1181 follow-up: the same ancestry requirement as the `<version>...</version>`
            // arm below — a self-closing `<version/>` must also be nested inside
            // `<dependency>`/`<plugin>`, or a minified pom.xml's `<project>`/`<parent>` own
            // `<version/>` can misattribute to a nearby `<dependency>` via
            // `literal_version_dependency`'s same-line fallback, the same bug class as #1181
            // just for the self-closing tag shape. A self-closing tag never contains the
            // literal `<version>` substring the loop below searches for (it has `/>`, not
            // `>`, right after the tag name), so there is no *`Version`* candidate to fall
            // through to for this cursor position. There CAN still be an unrelated
            // `artifactId`/`groupId` open-tag match at this same cursor position (e.g.
            // `<groupId>org.foo<version/></groupId>`, cursor inside the self-closing tag) —
            // `return`ing `None` directly discards that too, unlike the loop's own `continue`
            // below, which only disqualifies the `Version` candidate and still lets a later
            // iteration try `artifactId`/`groupId` independently. Pre-existing gap, not a
            // regression: before #1189 a self-closing tag always resolved to `None` outright,
            // so no candidate — `Version` or otherwise — was ever reachable there; `None` is
            // still the safer of the two choices, so left as-is here.
            let tag_offset = content.substr_range(line).map(|r| r.start + tag_start);
            if !matches!(
                tag_offset.and_then(|offset| innermost_open_element(content, offset)),
                Some("dependency" | "plugin")
            ) {
                return (MavenXmlContext::None, "", LspRange::default());
            }

            let tag_span = LspRange {
                start: Position {
                    line: position.line,
                    character: deps_core::completion::byte_to_utf16_offset(line, tag_start),
                },
                end: Position {
                    line: position.line,
                    character: deps_core::completion::byte_to_utf16_offset(line, tag_end),
                },
            };
            return (
                MavenXmlContext::SelfClosingVersion { tag_span },
                &line[tag_start..tag_end],
                tag_span,
            );
        }

        for (tag, ctx) in [
            ("version", MavenXmlContext::Version),
            ("artifactId", MavenXmlContext::ArtifactId),
            ("groupId", MavenXmlContext::GroupId),
        ] {
            let open = format!("<{tag}>");
            if let Some(start) = before_cursor.rfind(&open) {
                let value_start = start + open.len();
                let between = &before_cursor[value_start..];
                if !between.contains("</") {
                    // Check if cursor is on a dependency line (use parse_result for context)
                    let _ = parse_result;

                    // #1181: a `<version>` match is only a real completion trigger when it is
                    // structurally nested inside `<dependency>`/`<plugin>` — not merely the
                    // nearest `<version>` tag on the cursor's line. Without this, a minified
                    // pom.xml where `<project>`'s own top-level `<version>` shares a physical
                    // line with unrelated dependency coordinates lets
                    // `literal_version_dependency`'s same-line fallback (#1146) misattribute
                    // the project's own version to a nearby dependency, and an accepted
                    // completion would then edit the wrong element. `artifactId`/`groupId`
                    // don't need this: they complete in place from the tag's own text with no
                    // cross-element attribution step, so there is nothing to misattribute.
                    // `line` is a subslice of `content` from `content.lines()`, so
                    // `substr_range` recovers its absolute offset without re-scanning
                    // `content` for it.
                    let tag_offset = content.substr_range(line).map(|r| r.start + start);
                    if ctx == MavenXmlContext::Version
                        && !matches!(
                            tag_offset.and_then(|offset| innermost_open_element(content, offset)),
                            Some("dependency" | "plugin")
                        )
                    {
                        // `continue`, not `return`: this only disqualifies THIS `<version>`
                        // match (e.g. one found inside a comment on a minified line) — a
                        // later iteration's `artifactId`/`groupId` pattern can still validly
                        // match the same `before_cursor` independently, and must still get
                        // the chance to.
                        continue;
                    }

                    let value = &line[value_start..col_idx];
                    let value_end = line[value_start..]
                        .find("</")
                        .map_or(col_idx, |rel| value_start + rel)
                        .max(col_idx);
                    let value_range = LspRange {
                        start: Position {
                            line: position.line,
                            character: deps_core::completion::byte_to_utf16_offset(
                                line,
                                value_start,
                            ),
                        },
                        end: Position {
                            line: position.line,
                            character: deps_core::completion::byte_to_utf16_offset(line, value_end),
                        },
                    };
                    return (ctx, value, value_range);
                }
            }
        }

        (MavenXmlContext::None, "", LspRange::default())
    }
}

/// Tag name of the innermost XML element open at `offset` (an absolute byte offset into
/// `content`), found via a single forward scan from the document start that pushes on
/// every opening tag and pops on every closing one, stopping once `offset` is reached —
/// used by [`MavenEcosystem::detect_xml_context`]'s `Version` arm (#1181) and its
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
#[cfg(feature = "lsp-responses")]
fn innermost_open_element(content: &str, offset: usize) -> Option<&str> {
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

impl deps_core::ecosystem::private::Sealed for MavenEcosystem {}

impl Ecosystem for MavenEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Maven
    }

    fn display_name(&self) -> &'static str {
        "Maven (JVM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["pom.xml"]
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
            let result = crate::parser::parse_pom_xml(content, uri)?;
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
    /// dispatch: Maven routes on its own `MavenXmlContext` (`Self::detect_xml_context`),
    /// detected from raw manifest text rather than
    /// [`deps_core::completion::detect_completion_context`]'s parsed-AST dependency ranges
    /// (see `MavenXmlContext`'s doc for why that source difference, plus `groupId`/
    /// `artifactId` having no counterpart at all, is why this crate can't reuse the shared
    /// dispatch). Opting out of it means this ecosystem takes on #793's wildcard-match
    /// obligation itself; see `deps_core::Ecosystem::generate_completions`'s doc.
    #[cfg(feature = "lsp-responses")]
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            let (ctx_type, value, value_range) =
                Self::detect_xml_context(content, position, parse_result);

            // Exhaustive on purpose (#819/#793); each arm also picks the CompletionOrigin it maps to (#1195).
            let (items, origin) = match ctx_type {
                MavenXmlContext::Version => {
                    // #1134: finds+literal-checks the dependency; #1136: complete_versions_generic_from's own gate rejects a non-registry `dep.source()`.
                    let items = match deps_core::completion::literal_version_dependency(
                        parse_result,
                        position,
                        content,
                        value_range,
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
                    };
                    (items, deps_core::completion::CompletionOrigin::Version)
                }
                MavenXmlContext::ArtifactId => {
                    let items = self
                        .complete_package_names_for_field(
                            value,
                            MavenNameField::ArtifactId,
                            value_range,
                        )
                        .await;
                    (items, deps_core::completion::CompletionOrigin::PackageName)
                }
                MavenXmlContext::GroupId => {
                    let items = self
                        .complete_package_names_for_field(
                            value,
                            MavenNameField::GroupId,
                            value_range,
                        )
                        .await;
                    (items, deps_core::completion::CompletionOrigin::PackageName)
                }
                MavenXmlContext::SelfClosingVersion { tag_span } => {
                    let items = complete_self_closing_version(
                        self.registry.as_ref(),
                        &self.formatter,
                        parse_result,
                        position,
                        content,
                        tag_span,
                        value,
                        freshness,
                    )
                    .await;
                    (items, deps_core::completion::CompletionOrigin::Version)
                }
                MavenXmlContext::None => {
                    (vec![], deps_core::completion::CompletionOrigin::Unresolved)
                }
            };
            Completions::from(items).with_origin(origin)
        })
    }

    /// Required by [`Ecosystem`]; called only from this crate's own
    /// [`Self::generate_completions`] override (Maven does not use the shared default
    /// dispatch — see that method's doc), for the `"version"` XML context.
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

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: deps_core::position::Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        let (prefix, tag) = extract_prefix(line, position.character);
        // The cursor sits inside some *other* already-open Maven tag (`groupId`,
        // `version`, or an unrecognized element) — this raw-text fallback has no safe
        // text to offer at that position (a `groupId` completion is a different search
        // than the combined `group:artifact` query this prefix feeds), and the full
        // snippet `completion_insert_text` builds would be exactly as wrong-context as
        // inserting the bare artifact id would be (#724/#728). `None` here suppresses
        // the completion item entirely and, since the caller treats "no prefix" as
        // "nothing completable," also skips the registry search.
        if matches!(tag, Some(name) if name != "artifactId") {
            return None;
        }
        Some(prefix)
    }

    fn fallback_completion_is_bare(
        &self,
        content: &str,
        position: deps_core::position::Position,
    ) -> bool {
        let Some(line) = deps_core::fallback_completion::line_at(content, position) else {
            return false;
        };
        extract_prefix(line, position.character).1 == Some("artifactId")
    }

    fn fallback_bare_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        // Cursor is already inside an open `<artifactId>gua` tag's content (see
        // `fallback_completion_is_bare`): only the bare artifact id belongs at that
        // position, matching the primary AST-anchored path's bare artifact-id
        // `textEdit` (`MavenEcosystem::detect_xml_context`) — inserting the full
        // `<groupId>...<artifactId>...<version>...` snippet here would nest it inside
        // the tag already open around the cursor (#724).
        let artifact_id = metadata
            .name()
            .as_str()
            .split_once(':')
            .map_or(metadata.name().as_str(), |(_, artifact_id)| artifact_id);
        if !is_safe_maven_coordinate_segment(artifact_id) {
            warn_rejected_value(
                "is_safe_maven_coordinate_segment",
                "maven package name completion item",
                artifact_id,
            );
            return None;
        }
        Some(artifact_id.to_string())
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // The predicate rejects `:` by design, so it must validate each half of the
        // coordinate after splitting, never the joined `name`.
        let (group_id, artifact_id) = match name.as_str().split_once(':') {
            Some((group_id, artifact_id)) => (Some(group_id), artifact_id),
            None => (None, name.as_str()),
        };
        if !is_safe_maven_coordinate_segment(artifact_id) {
            warn_rejected_value(
                "is_safe_maven_coordinate_segment",
                "maven package name completion item",
                artifact_id,
            );
            return None;
        }
        if let Some(g) = group_id
            && !is_safe_maven_coordinate_segment(g)
        {
            warn_rejected_value(
                "is_safe_maven_coordinate_segment",
                "maven package name completion item",
                g,
            );
            return None;
        }
        Some(group_id.map_or_else(
            || format!("<artifactId>{artifact_id}</artifactId><version>{latest}</version>"),
            |group_id| {
                format!(
                    "<groupId>{group_id}</groupId><artifactId>{artifact_id}</artifactId><version>{latest}</version>"
                )
            },
        ))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Checks if `line_number` of `content` is inside pom.xml's `<dependencies>` element,
/// for `deps-lsp`'s raw-text fallback completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    deps_core::fallback_completion::is_in_xml_tag_section(content, line_number, "dependencies")
}

/// Extracts the fallback-completion prefix on `line` up to `character`, stripping the
/// surrounding XML tag (`<artifactId>gua` -> `gua`) so the extracted text matches what
/// [`MavenEcosystem::detect_xml_context`] would search for at the same cursor position,
/// together with the name of the tag whose content the cursor sits inside, when there
/// is one — used by [`MavenEcosystem::fallback_completion_is_bare`] and
/// [`MavenEcosystem::fallback_completion_prefix`]'s suppression check (#724/#728).
fn extract_prefix(line: &str, character: u32) -> (&str, Option<&str>) {
    deps_core::fallback_completion::strip_leading_xml_tag(
        deps_core::fallback_completion::raw_prefix(line, character),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_manifest_filenames/test_as_any
    // family. Maven has no lock file format, so `lockfile_filenames` is omitted here;
    // `no_lockfile_support: true;` (#782 gap 2) replaces the hand-copied
    // test_lockfile_filenames/test_lockfile_provider_none pair below.
    deps_core::ecosystem_conformance! {
        mod maven_ecosystem_conformance;
        build: MavenEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: MavenEcosystem;
        id: "maven";
        display_name: "Maven (JVM)";
        manifest_filenames: &["pom.xml"];
        no_lockfile_support: true;
        non_registry_fixture: "pom.xml" => "<project><dependencies><dependency><groupId>com.acme</groupId><artifactId>internal-jar</artifactId><version>1.0.0</version><scope>system</scope><systemPath>/opt/lib/internal-jar-1.0.0.jar</systemPath></dependency></dependencies></project>";
    }

    // #1370/#1372/#1384/#1391: Maven's parser preserves an unexpanded `${property}`
    // placeholder, a malformed range with one embedded (e.g. `[1.0,${hi}`), and an unexpanded
    // `@property@` resource-filtering placeholder (e.g. `@project.version@`) as
    // `Some(version_requirement)` — all three reach `deps_core::edit::plan_vulnerability_fix`
    // directly, so `RequirementResolution::requirement_is_placeholder`'s central gate
    // (`MavenFormatter` has no override; the shared default's own `is_unresolved`-equivalent
    // detector covers both grammars) must actually hold for both placeholder grammars.
    deps_core::unresolved_requirement_conformance! {
        mod maven_unresolved_requirement_conformance;
        build: MavenEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        reachable: true;
        fixture: "pom.xml" =>
            "<project><dependencies><dependency><groupId>com.example</groupId><artifactId>some-lib</artifactId><version>${ver}</version></dependency><dependency><groupId>com.example</groupId><artifactId>malformed-range</artifactId><version>[1.0,${hi}</version></dependency><dependency><groupId>com.example</groupId><artifactId>at-placeholder</artifactId><version>@project.version@</version></dependency><dependency><groupId>com.example</groupId><artifactId>dollar-paren-placeholder</artifactId><version>$(MAKEFILE_VERSION)</version></dependency></dependencies></project>";
    }

    // #794: `complete_package_names_for_field` (defined above in `impl MavenEcosystem`)
    // guards on the exact same `is_valid_completion_prefix_len` predicate
    // `complete_package_names_generic` uses internally, before calling
    // `registry.search` — this proves that shared guard predicate behaves correctly,
    // mirroring every other ecosystem's `completion_guard_conformance!` invocation (see
    // that macro's doc for why the substitute closure calls `complete_package_names_generic`
    // directly rather than through Maven's own field-completion wiring).
    //
    // Wiring the substitute closure through the real `complete_package_names_for_field`
    // instead (#794 impl-critic minor) is not feasible without a production change: that
    // method is `&self`-based over `self.registry: Arc<MavenCentralRegistry>` (a concrete
    // type, calling its inherent `search`, not the `Registry` trait's `search`), while
    // this macro's `complete:` closure only ever receives a substituted `&dyn Registry` — the
    // fixture registry can't be threaded into `self.registry`'s concrete type without
    // widening that field to `Arc<dyn Registry>`, out of scope for this test-only change.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_guard_conformance! {
        mod maven_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<CompletionItem>> + Send + '_>,
        > {
            Box::pin(async move {
                deps_core::completion::complete_package_names_generic(
                    registry,
                    &prefix,
                    20,
                    tower_lsp_server::ls_types::Range::default(),
                )
                .await
            })
        };
    }

    /// #1206 S1: `complete_package_names_for_field` doesn't route through
    /// `complete_package_names_generic` (see the conformance block above for why), so it needs
    /// its own direct test that a credential-shaped prefix is rejected — no mock/network setup
    /// needed: if the gate works, `self.registry.search` is never called at all.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_for_field_rejects_credential_bearing_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let prefix = "deploy:AUDITSENTINEL0000@git.internal.corp/team/x";

        let items = eco
            .complete_package_names_for_field(
                prefix,
                MavenNameField::ArtifactId,
                tower_lsp_server::ls_types::Range::default(),
            )
            .await;

        assert!(items.is_empty());
    }

    // #1137: regression guard — `required` mirrors `VERSION_OPERATOR_CHARS`'s own doc
    // comment (`[`/`(`, `crate::range::is_range`'s leading delimiters), so an edit to one
    // without the other fails loudly instead of silently degrading completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod maven_operator_chars_conformance;
        ecosystem: "maven";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &['[', '('];
    }

    #[cfg(feature = "lsp-responses")]
    struct NoopParseResult;
    #[cfg(feature = "lsp-responses")]
    impl deps_core::ParseResult for NoopParseResult {
        fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
            vec![]
        }
        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }
        fn uri(&self) -> &url::Url {
            unimplemented!()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[cfg(feature = "lsp-responses")]
    fn make_position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    #[cfg(feature = "lsp-responses")]
    fn xml_context(line_content: &str, col: u32) -> (MavenXmlContext, String) {
        let (t, v, _range) = xml_context_with_range(line_content, col);
        (t, v)
    }

    #[cfg(feature = "lsp-responses")]
    fn xml_context_with_range(line_content: &str, col: u32) -> (MavenXmlContext, String, LspRange) {
        let content = format!("    {line_content}\n");
        let col_in_content = col + 4; // 4 spaces indent
        let (t, v, range) = MavenEcosystem::detect_xml_context(
            &content,
            make_position(0, col_in_content),
            &NoopParseResult,
        );
        (t, v.to_owned(), range)
    }

    /// Same fixture shape as [`xml_context_with_range`], but `line_content` sits on line 1
    /// of a `<dependency>...</dependency>`-wrapped document instead of standing alone on
    /// line 0 — required for a `<version>` match to satisfy #1181's ancestry check (a bare
    /// `<version>` with no enclosing `<dependency>`/`<plugin>` now correctly yields
    /// `MavenXmlContext::None`, see `test_detect_xml_context_version_without_dependency_
    /// ancestor_yields_no_context`). The 4-space indent and column math are unchanged from
    /// `xml_context_with_range`; only the line index shifts from 0 to 1.
    #[cfg(feature = "lsp-responses")]
    fn xml_context_with_range_in_dependency(
        line_content: &str,
        col: u32,
    ) -> (MavenXmlContext, String, LspRange) {
        let content = format!("<dependency>\n    {line_content}\n</dependency>\n");
        let col_in_content = col + 4; // 4 spaces indent
        let (t, v, range) = MavenEcosystem::detect_xml_context(
            &content,
            make_position(1, col_in_content),
            &NoopParseResult,
        );
        (t, v.to_owned(), range)
    }

    #[cfg(feature = "lsp-responses")]
    fn xml_context_in_dependency(line_content: &str, col: u32) -> (MavenXmlContext, String) {
        let (t, v, _range) = xml_context_with_range_in_dependency(line_content, col);
        (t, v)
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_cursor_at_start() {
        // <version>|4.13.2</version> — cursor right after '>'
        let line = "<version>4.13.2</version>";
        // col 0..8 is "<version", col 9 is '4'
        let (t, v) = xml_context_in_dependency(line, 9); // col at value_start
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_cursor_mid() {
        // <version>4.1|3.2</version>
        let line = "<version>4.13.2</version>";
        let (t, v) = xml_context_in_dependency(line, 12); // "4.1" = 3 chars after value_start (9)
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "4.1");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_cursor_at_end() {
        // <version>4.13.2|</version>
        let line = "<version>4.13.2</version>";
        let (t, v) = xml_context_in_dependency(line, 15); // value_start=9, end=15
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "4.13.2");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_empty_value() {
        // <version>|</version>
        let line = "<version></version>";
        let (t, v) = xml_context_in_dependency(line, 9);
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "");
    }

    // #1167: self-closing `<version/>` (and its whitespace variants) has no cursor-insert
    // position that lands inside the element at all — a prior fix (#1161 round 2) tried
    // anchoring completion right after `/>`, matching the parser's own `Event::Empty`
    // capture, but `complete_versions_generic_from` relies on cursor-position insert with no
    // `text_edit`, so accepting a completion there inserted text AFTER the self-closed tag
    // (`<version/>1.2.3`), corrupting the pom.xml. This is fixed by detecting the whole tag
    // span and replacing it wholesale via `VersionReplacement` (`MavenXmlContext::
    // SelfClosingVersion`) instead of relying on a bare cursor-insert.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_version_tag_is_a_completion_trigger() {
        for line in ["<version/>", "<version />", "<version  />"] {
            let cursor = u32::try_from(line.len()).unwrap();
            let (t, v, range) = xml_context_with_range_in_dependency(line, cursor);
            let expected_span = LspRange {
                start: Position::new(1, 4),
                end: Position::new(1, 4 + cursor),
            };
            assert_eq!(
                t,
                MavenXmlContext::SelfClosingVersion {
                    tag_span: expected_span
                },
                "must trigger for {line:?}"
            );
            assert_eq!(v, line);
            assert_eq!(range, expected_span);
        }
    }

    /// #1181: a `<version>` tag with no enclosing `<dependency>`/`<plugin>` at all (e.g. a
    /// standalone fixture, or the project's own top-level `<version>`) must not trigger
    /// completion, even though the raw-text scanner alone would still find an open
    /// `<version>` tag with the cursor inside it.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_without_dependency_ancestor_yields_no_context() {
        let line = "<version>4.13.2</version>";
        let (t, v, range) = xml_context_with_range(line, 9);
        assert_eq!(t, MavenXmlContext::None);
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    /// LSP 3.17 requires `textEdit.range` to contain the completion position — proven here
    /// for the tag-start, mid-tag, and tag-end cursor positions inside a single
    /// self-closing `<version/>` tag.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_version_tag_triggers_at_any_cursor_inside() {
        let line = "<version/>";
        let tag_len = u32::try_from(line.len()).unwrap();
        for cursor in [0, tag_len / 2, tag_len] {
            let (t, _v, range) = xml_context_with_range_in_dependency(line, cursor);
            let MavenXmlContext::SelfClosingVersion { tag_span } = t else {
                panic!("must trigger at cursor {cursor} for {line:?}, got {t:?}");
            };
            let indented_cursor = Position::new(1, cursor + 4);
            assert!(
                range.start <= indented_cursor && indented_cursor <= range.end,
                "range {range:?} must contain cursor {indented_cursor:?}"
            );
            assert_eq!(tag_span, range);
        }
    }

    /// Rejects a longer tag name sharing the `<version` prefix.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_range_self_closing_tag_is_not_a_trigger() {
        let line = "<versionRange/>";
        let (t, v, range) =
            xml_context_with_range_in_dependency(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, MavenXmlContext::None, "must not trigger for {line:?}");
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    /// #1181: `<plugin>` is as valid an ancestor as `<dependency>` — the ancestry check
    /// must not narrow the trigger to `<dependency>` alone.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_inside_plugin_is_a_completion_trigger() {
        let content = "<plugin>\n    <version>1.0.0</version>\n</plugin>\n";
        let position = Position::new(1, 4 + "<version>".len() as u32);
        let (t, v, _range) =
            MavenEcosystem::detect_xml_context(content, position, &NoopParseResult);
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "");
    }

    /// #1181: a `<parent>` block's `<version>` (the parent POM reference, not a regular
    /// dependency) must not trigger completion either — `<parent>` is neither `<dependency>`
    /// nor `<plugin>`, and `deps-maven::parser::parse_pom_xml` never turns it into a
    /// `Dependency`, so a completion there would have nothing valid to resolve against.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_version_inside_parent_yields_no_context() {
        let content = "<parent>\n    <version>1.0.0</version>\n</parent>\n";
        let position = Position::new(1, 4 + "<version>".len() as u32);
        let (t, v, range) = MavenEcosystem::detect_xml_context(content, position, &NoopParseResult);
        assert_eq!(t, MavenXmlContext::None);
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_optional_self_closing_tag_is_not_a_trigger() {
        let line = "<optional/>";
        let (t, v, range) =
            xml_context_with_range_in_dependency(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, MavenXmlContext::None, "must not trigger for {line:?}");
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    /// #1181 follow-up: the same ancestry gap as
    /// `test_detect_xml_context_version_without_dependency_ancestor_yields_no_context`, but
    /// for the self-closing tag shape — a minified pom.xml where `<project>`'s own
    /// self-closing `<version/>` shares physical structure with a real `<dependency>` must
    /// not trigger completion via the self-closing path either.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_version_without_dependency_ancestor_yields_no_context()
    {
        let content =
            "<project><version/><dependency><artifactId>foo</artifactId></dependency></project>\n";
        let cursor = u32::try_from(content.find("<version/>").unwrap() + 4).unwrap();
        let (t, v, range) =
            MavenEcosystem::detect_xml_context(content, Position::new(0, cursor), &NoopParseResult);
        assert_eq!(t, MavenXmlContext::None);
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    /// Positive counterpart: a self-closing `<version/>` correctly nested inside
    /// `<dependency>` still triggers `SelfClosingVersion` after the #1181 follow-up ancestry
    /// check — proves the fix withholds completion only for the misattributed case, not for
    /// every self-closing tag.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_version_inside_dependency_is_a_completion_trigger() {
        let content = "<dependency><version/></dependency>\n";
        let cursor = u32::try_from(content.find("<version/>").unwrap() + 4).unwrap();
        let (t, v, _range) =
            MavenEcosystem::detect_xml_context(content, Position::new(0, cursor), &NoopParseResult);
        assert!(
            matches!(t, MavenXmlContext::SelfClosingVersion { .. }),
            "expected SelfClosingVersion, got {t:?}"
        );
        assert_eq!(v, "<version/>");
    }

    /// #1181: a commented-out `<dependency>` block must not be mistaken for a live one by
    /// `innermost_open_element`'s ancestry scan — the `<version>` right after the comment
    /// closes must resolve to the real, uncommented enclosing element, not "dependency"
    /// leaked from inside the comment text.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_skips_commented_out_dependency() {
        let content = "<project><!-- <dependency><version>0.0.0</version></dependency> \
                        --><parent><version>1.0.0</version></parent></project>";
        let offset = content.rfind("<version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("parent"));
    }

    /// #1181 critic S1 (regression): `innermost_open_element` must compare on the XML local
    /// name, stripping a `prefix:` the same way `parse_pom_xml`'s quick-xml reader already
    /// does via `local_name()` — otherwise a namespace-prefixed `<m:dependency>` never
    /// equals `"dependency"`, and a document that `parse_pom_xml` parses into real
    /// dependencies just fine would silently lose version completion while hover/
    /// diagnostics/code-actions kept working.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_strips_namespace_prefix() {
        let content = "<m:project><m:dependencies><m:dependency><m:version>1.0.0</m:version>\
                        </m:dependency></m:dependencies></m:project>";
        let offset = content.rfind("<m:version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("dependency"));
    }

    /// #1192 regression: the old hand-rolled `find('>')` scanner stops inside the quoted
    /// attribute value `"a/>b"`, misreads the truncated `<exclusions ...` as self-closing, and
    /// never pushes it — so its real `</exclusions>` then pops the genuine `<dependency>` off
    /// the stack, leaving `<version>` misattributed to `project` instead of `dependency`.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_handles_unescaped_gt_in_attribute_value() {
        let content = r#"<project><dependency><exclusions d="a/>b"></exclusions><version>1</version></dependency></project>"#;
        let offset = content.rfind("<version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("dependency"));
    }

    /// #1192 regression: same desync class as above, reached through an arbitrary
    /// `<plugin><configuration>` subtree rather than `<exclusions>` — not purely theoretical
    /// since plugin configuration is free-form user XML.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_handles_unescaped_gt_in_plugin_configuration() {
        let content = r#"<project><plugin><configuration><f p="x/>y"></f></configuration><version>1</version></plugin></project>"#;
        let offset = content.rfind("<version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("plugin"));
    }

    /// #1192: a DOCTYPE with an internal subset is now handled by `quick_xml`'s own DTD state
    /// machine instead of the old generic `<!...>` span (which stopped at the first `>`, inside
    /// the subset). Not user-visible before this fix — the DOCTYPE sits in the prolog where the
    /// ancestor stack is empty — but locks the fix in for any future caller that scans earlier
    /// in the document.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_handles_doctype_internal_subset() {
        let content = concat!(
            r#"<!DOCTYPE project [<!ENTITY x "><parent>">]>"#,
            "<project><dependency><version>1</version></dependency></project>"
        );
        let offset = content.rfind("<version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("dependency"));
    }

    /// #1192 critic S1 (blocking): `quick_xml`'s `remove_utf8_bom` strips a leading UTF-8 BOM
    /// from its input slice without advancing `buffer_position()`, so every reported position on
    /// BOM'd content is 3 bytes short of `offset` (which is derived from `content` itself and
    /// does count the BOM) — without correcting for it, this returns garbage ancestry and
    /// silently disables version completion for the whole file.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_innermost_open_element_handles_utf8_bom() {
        let content = "\u{feff}<project><dependency><version>1</version></dependency></project>";
        let offset = content.rfind("<version>").unwrap();
        assert_eq!(innermost_open_element(content, offset), Some("dependency"));
    }

    /// #1181 critic S1: the same fix through the real parser + `detect_xml_context`. The
    /// `<version>` tag itself is deliberately left unprefixed (`detect_xml_context`'s raw-text
    /// search for the literal token `<version>` is a separate, pre-existing limitation that
    /// does not understand namespace prefixes at all — out of scope here) while its
    /// `<m:dependency>` ancestor is prefixed, isolating exactly the ancestry-comparison bug
    /// this fix addresses: `parse_pom_xml` already parses this into a real `Dependency` via
    /// quick-xml's `local_name()`, so completion must trigger too.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_namespaced_dependency_still_triggers() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = r"<m:project xmlns:m='http://maven.apache.org/POM/4.0.0'>
  <m:dependencies>
    <m:dependency>
      <m:groupId>com.example</m:groupId>
      <m:artifactId>foo</m:artifactId>
      <version>1.0.0</version>
    </m:dependency>
  </m:dependencies>
</m:project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();

        let (ctx, _, _) = MavenEcosystem::detect_xml_context(xml, position, parse_result.as_ref());
        assert_eq!(
            ctx,
            MavenXmlContext::Version,
            "a <version> nested inside a namespace-prefixed <m:dependency> must still trigger \
             completion"
        );
    }

    /// #1181 critic M1: a failed ancestry check must only withhold the `Version` context,
    /// not bail out of the whole tag-detection loop — an unrelated `<artifactId>` match at
    /// the same cursor position must still resolve independently.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_failed_version_ancestry_does_not_suppress_artifact_id() {
        // A `<version>` substring inside a comment (no real `<dependency>`/`<plugin>`
        // ancestor) precedes a genuinely open `<artifactId>` tag on the same line — the
        // version match must be rejected without aborting the loop before it can find the
        // artifactId match that follows.
        let line = "<!-- <version>x --><artifactId>jun";
        let (t, v) = xml_context(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "jun");
    }

    /// M2 (impl-critic follow-up): unlike the tag-loop's `continue` above, a failed ancestry
    /// check on the self-closing arm returns `None` directly and so DOES suppress an unrelated
    /// `groupId`/`artifactId` candidate at the same cursor position — pinning the current,
    /// intentionally-not-fixed behavior (see the `return (MavenXmlContext::None, ...)` comment
    /// in `detect_xml_context`'s self-closing arm) rather than leaving it undocumented.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_failed_version_ancestry_suppresses_group_id() {
        let content = "<dependency><groupId>org.foo<version/></groupId></dependency>\n";
        let cursor = u32::try_from(content.find("<version/>").unwrap() + 4).unwrap();
        let (t, v, range) =
            MavenEcosystem::detect_xml_context(content, Position::new(0, cursor), &NoopParseResult);
        assert_eq!(
            t,
            MavenXmlContext::None,
            "the self-closing arm's ancestry rejection (innermost element is groupId, not \
             dependency/plugin) returns None directly, discarding the groupId match the loop \
             below would otherwise have found"
        );
        assert_eq!(v, "");
        assert_eq!(range, LspRange::default());
    }

    /// Two self-closing `<version/>` tags share one line — only the occurrence whose span
    /// contains the cursor is returned, not always the first.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_two_self_closing_version_tags_picks_containing_one() {
        let line = "<version/><version/>";
        let second_tag_start = u32::try_from(line.rfind("<version/>").unwrap()).unwrap();
        let cursor = second_tag_start + 3; // inside the second tag
        let (t, v, range) = xml_context_with_range_in_dependency(line, cursor);
        let MavenXmlContext::SelfClosingVersion { tag_span } = t else {
            panic!("must trigger, got {t:?}");
        };
        assert_eq!(v, "<version/>");
        assert_eq!(tag_span, range);
        assert_eq!(range.start, Position::new(1, second_tag_start + 4)); // +4 for indent
    }

    /// M2 (critic follow-up): when the cursor sits exactly on the shared boundary between two
    /// adjacent self-closing tags, the earlier one wins — the previous test only probes a
    /// column inside the second tag, never the boundary itself.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_two_self_closing_version_tags_boundary_picks_first() {
        let line = "<version/><version/>";
        let boundary = u32::try_from("<version/>".len()).unwrap(); // end of tag 1 == start of tag 2
        let (t, v, range) = xml_context_with_range_in_dependency(line, boundary);
        let MavenXmlContext::SelfClosingVersion { tag_span } = t else {
            panic!("must trigger, got {t:?}");
        };
        assert_eq!(v, "<version/>");
        assert_eq!(tag_span, range);
        assert_eq!(
            range.start,
            Position::new(1, 4),
            "the first tag must win the tie"
        );
        assert_eq!(range.end, Position::new(1, 4 + boundary));
    }

    /// Architect's test plan item (not covered by `test_detect_xml_context_multibyte_value_
    /// no_panic`, which exercises a different tag branch): a multi-byte character before the
    /// self-closing tag must not desync the UTF-16/byte round-trip. Expected offsets are
    /// derived via the same conversion helper the scanner uses, not hand-computed, so the
    /// test can't silently encode the same arithmetic mistake it's meant to catch.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_version_tag_after_multibyte_prefix_no_panic() {
        let line = "café <version/>";
        let tag_byte_start = line.find("<version/>").unwrap();
        let cursor_byte = tag_byte_start + 1; // one byte into the tag
        let cursor_char = deps_core::completion::byte_to_utf16_offset(line, cursor_byte);

        let content = format!("<dependency>\n{line}\n</dependency>\n");
        let (ctx, value, range) = MavenEcosystem::detect_xml_context(
            &content,
            Position::new(1, cursor_char),
            &NoopParseResult,
        );

        let MavenXmlContext::SelfClosingVersion { tag_span } = ctx else {
            panic!("expected SelfClosingVersion, got {ctx:?}");
        };
        assert_eq!(value, "<version/>");
        assert_eq!(tag_span, range);
        assert_eq!(
            tag_span.start.character,
            deps_core::completion::byte_to_utf16_offset(line, tag_byte_start)
        );
        assert_eq!(
            tag_span.end.character,
            deps_core::completion::byte_to_utf16_offset(line, tag_byte_start + "<version/>".len())
        );
    }

    /// Proves the emitted `TextEdit` actually produces valid XML when applied — not just
    /// that its fields look right. Covers the whitespace variants and both the `lead`/`trail`
    /// wrapping and `filter_text` reasoning from `VersionReplacement`'s own doc.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_self_closing_version_replacement_applies_to_produce_valid_xml() {
        struct MockVersion(deps_core::ConcreteVersion);
        impl deps_core::Version for MockVersion {
            fn version_string(&self) -> &deps_core::ConcreteVersion {
                &self.0
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        for (tag, indent) in [
            ("<version/>", "      "),
            ("<version />", "  "),
            ("<version  />", ""),
        ] {
            let source = format!("{indent}{tag}\n");
            let tag_start = source.find(tag).unwrap();
            let tag_end = tag_start + tag.len();
            let tag_span = LspRange {
                start: Position::new(0, u32::try_from(tag_start).unwrap()),
                end: Position::new(0, u32::try_from(tag_end).unwrap()),
            };
            let replacement = VersionReplacement {
                range: tag_span,
                lead: "<version>".to_string(),
                trail: "</version>".to_string(),
                replaced_text: tag.to_string(),
            };

            let version = MockVersion("1.2.3".into());
            let display_item = deps_core::completion::VersionDisplayItem::new(
                &version,
                &deps_core::PackageName::new("com.example:foo"),
                0,
                true,
            );
            let item = deps_core::completion::build_version_completion(
                &display_item,
                Some(&replacement),
                deps_core::PublishTime::now(),
                true,
            );

            let Some(CompletionTextEdit::Edit(edit)) = item.text_edit else {
                panic!("expected a textEdit::Edit for {tag:?}");
            };
            assert_eq!(edit.new_text, "<version>1.2.3</version>");
            assert_eq!(item.filter_text, Some(tag.to_string()));

            // Decode `edit.range` itself back to byte offsets (M4, critic follow-up) rather
            // than reusing the locally-computed `tag_start`/`tag_end` — this proves the
            // UTF-16 round-trip the emitted range actually carries, not just `new_text`.
            let line = source.lines().next().unwrap();
            let edit_start =
                deps_core::completion::utf16_to_byte_offset(line, edit.range.start.character)
                    .unwrap();
            let edit_end =
                deps_core::completion::utf16_to_byte_offset(line, edit.range.end.character)
                    .unwrap();
            assert_eq!((edit_start, edit_end), (tag_start, tag_end));

            let mut result = source.clone();
            result.replace_range(edit_start..edit_end, &edit.new_text);
            assert_eq!(
                result,
                format!("{indent}<version>1.2.3</version>\n"),
                "applying the edit to {source:?} must yield valid, indentation-preserving XML"
            );
        }
    }

    /// Acceptance criterion #3 (architect's test plan): sibling `<groupId>`/`<artifactId>`/
    /// `<scope>` lines must be byte-identical after the edit is applied. Deterministic and
    /// network-free — the only multi-line integration test is `#[ignore]`d for network, and
    /// it never asserted the untouched sibling lines either (tester/impl-critic finding).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_self_closing_version_replacement_leaves_sibling_lines_byte_identical() {
        struct MockVersion(deps_core::ConcreteVersion);
        impl deps_core::Version for MockVersion {
            fn version_string(&self) -> &deps_core::ConcreteVersion {
                &self.0
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let source = "<project>\n  <dependencies>\n    <dependency>\n      \
                       <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      \
                       <scope>test</scope>\n      <version/>\n    </dependency>\n  \
                       </dependencies>\n</project>\n";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = crate::parser::parse_pom_xml(source, &uri).unwrap();

        let line_idx = 6u32; // "      <version/>"
        let line = source.lines().nth(6).unwrap();
        let cursor_col = u32::try_from(line.find("<version").unwrap() + "<version".len()).unwrap();
        let (ctx, value, tag_span) = MavenEcosystem::detect_xml_context(
            source,
            Position::new(line_idx, cursor_col),
            &parse_result,
        );
        assert!(
            matches!(ctx, MavenXmlContext::SelfClosingVersion { .. }),
            "expected SelfClosingVersion, got {ctx:?}"
        );

        let replacement = VersionReplacement {
            range: tag_span,
            lead: "<version>".to_string(),
            trail: "</version>".to_string(),
            replaced_text: value.to_string(),
        };
        let version = MockVersion("1.2.3".into());
        let display_item = deps_core::completion::VersionDisplayItem::new(
            &version,
            &deps_core::PackageName::new("com.example:foo"),
            0,
            true,
        );
        let item = deps_core::completion::build_version_completion(
            &display_item,
            Some(&replacement),
            deps_core::PublishTime::now(),
            true,
        );
        let Some(CompletionTextEdit::Edit(edit)) = item.text_edit else {
            panic!("expected a textEdit::Edit");
        };

        let mut lines: Vec<String> = source.lines().map(str::to_string).collect();
        let target_idx = edit.range.start.line as usize;
        let target_line = lines[target_idx].clone();
        let start =
            deps_core::completion::utf16_to_byte_offset(&target_line, edit.range.start.character)
                .unwrap();
        let end =
            deps_core::completion::utf16_to_byte_offset(&target_line, edit.range.end.character)
                .unwrap();
        let mut new_line = target_line;
        new_line.replace_range(start..end, &edit.new_text);
        lines[target_idx] = new_line;
        let result = lines.join("\n") + "\n";

        let expected = "<project>\n  <dependencies>\n    <dependency>\n      \
                         <groupId>com.example</groupId>\n      <artifactId>foo</artifactId>\n      \
                         <scope>test</scope>\n      <version>1.2.3</version>\n    \
                         </dependency>\n  </dependencies>\n</project>\n";
        assert_eq!(
            result, expected,
            "sibling lines must be byte-identical, only the <version/> line changes"
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_artifact_id_prefix() {
        // <artifactId>jun|it</artifactId>
        let line = "<artifactId>junit</artifactId>";
        let (t, v) = xml_context(line, 15); // value_start=12, cursor at 15 = "jun"
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "jun");
    }

    /// #282 S1 (second critic round) parity guard: `deps-lsp`'s `completion.rs`
    /// (`extract_prefix`/`strip_leading_xml_tag`) must extract the identical query
    /// string for the identical cursor position, since it's a raw-text approximation of
    /// this function's own tag-aware extraction, and both feed the same registry
    /// dedup/cache-key mechanism (`MavenCentralRegistry::search`). This line and
    /// cursor position are kept intentionally identical to `deps-lsp`'s
    /// `test_fallback_completion_maven_query_matches_tag_value` — if either extractor's
    /// logic changes, update both tests and confirm they still agree.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_compact_multi_tag_line_matches_completion_extractor() {
        // <dependency><groupId>com.google.guava</groupId><artifactId>gua| — cursor
        // right after "gua", with an earlier `<groupId>...</groupId>` on the same line.
        let line = "<dependency><groupId>com.google.guava</groupId><artifactId>gua";
        let (t, v) = xml_context(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "gua");
    }

    /// #282 S1 (second critic round) parity guard: cursor right after a fully closed
    /// tag (`<artifactId>guava</artifactId>|`) yields no completion context at all —
    /// `between.contains("</")` rejects it. `deps-lsp`'s `strip_leading_xml_tag` must
    /// agree by yielding an empty string for the same position (which `fallback_completion`'s
    /// existing empty-prefix guard then rejects), not a markup-polluted search query.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_after_closed_tag_yields_no_context() {
        let line = "<artifactId>guava</artifactId>";
        let (t, v) = xml_context(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, MavenXmlContext::None);
        assert_eq!(v, "");
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_artifact_id_range_spans_full_value() {
        // <artifactId>jun|it</artifactId> — indented by 4 spaces in xml_context_with_range
        // The range must span the FULL existing value ("junit"), not just up to the
        // cursor, so a completion replaces the whole tag content instead of leaving
        // trailing characters behind (issue #218a).
        let line = "<artifactId>junit</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "jun");
        // value_start = 4 (indent) + 12 ("<artifactId>") = 16; value_end = 16 + "junit".len() = 21
        assert_eq!(range.start, Position::new(0, 16));
        assert_eq!(range.end, Position::new(0, 21));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_group_id_range_spans_full_value() {
        // <groupId>org.apache.comm|ons</groupId>
        let line = "<groupId>org.apache.commons</groupId>";
        let (t, v, range) = xml_context_with_range(line, 24);
        assert_eq!(t, MavenXmlContext::GroupId);
        assert_eq!(v, "org.apache.comm");
        // value_start = 4 (indent) + 9 ("<groupId>") = 13; value_end = 13 + "org.apache.commons".len() = 31
        assert_eq!(range.start, Position::new(0, 13));
        assert_eq!(range.end, Position::new(0, 31));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_surrogate_pair_value_no_panic() {
        // <artifactId>🎉|lib</artifactId> — 🎉 (U+1F389) is 4 UTF-8 bytes but a UTF-16
        // surrogate pair (2 code units); cursor placed right after it via UTF-16 units.
        let line = "<artifactId>🎉lib</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 14); // value_start=12 + 2 (🎉)
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "🎉");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 21)); // 16 + "🎉lib".len() in UTF-16 units (2+3)
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_value_end_fallback_no_closing_tag_on_line() {
        // <artifactId>jun|it — no closing tag anywhere on the line. After the S1 fix the
        // range falls back to the cursor position (insert-mode) rather than swallowing the
        // rest of the line, since there is no proof of where the value actually ends.
        let line = "<artifactId>junit";
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "jun");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 19)); // falls back to cursor: 4 + 15
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_no_closing_tag_range_excludes_trailing_comment() {
        // <artifactId>ju|    <!-- todo --> — regression for S1: the old `line.len()`
        // fallback swallowed the trailing comment into the replace range. The range must
        // stop at the cursor, not extend into unrelated trailing content.
        let line = "<artifactId>ju    <!-- todo -->";
        let (t, v, range) = xml_context_with_range(line, 14);
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "ju");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 18)); // 4 + 14 — does not reach the comment
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_range_always_contains_cursor() {
        // <artifactId>ju|</artifactId> — cursor sits between '<' and '/' of the closing
        // tag, so `find("</")` locates a match *before* the cursor. Regression for S2:
        // per LSP 3.17, `textEdit.range` must contain the request position, so `range.end`
        // must never fall before the cursor.
        let line = "<artifactId>ju</artifactId>";
        let cursor_col = 15u32; // indented cursor position
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "ju<");
        let cursor = Position::new(0, cursor_col + 4);
        assert!(
            range.end >= cursor,
            "range {range:?} must contain cursor {cursor:?}"
        );
        assert_eq!(range.end, Position::new(0, 19));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_empty_value_zero_width_range() {
        // <version>|</version> — empty existing value produces a zero-width range at the
        // value's start.
        let line = "<version></version>";
        let (t, v, range) = xml_context_with_range_in_dependency(line, 9);
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "");
        assert_eq!(range.start, range.end);
        assert_eq!(range.start, Position::new(1, 13)); // 4 (indent) + "<version>".len()
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_cursor_at_value_start_full_replace_range() {
        // <version>|4.13.2</version> — range must span the full existing value even
        // though the typed prefix is empty.
        let line = "<version>4.13.2</version>";
        let (t, v, range) = xml_context_with_range_in_dependency(line, 9);
        assert_eq!(t, MavenXmlContext::Version);
        assert_eq!(v, "");
        assert_eq!(range.start, Position::new(1, 13)); // 4 (indent) + "<version>".len()
        assert_eq!(range.end, Position::new(1, 19)); // 13 + "4.13.2".len()
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_multibyte_value_no_panic() {
        // <artifactId>café|-lib</artifactId> — cursor positioned via UTF-16 units right
        // after the multi-byte 'é' (col 16 = value_start 12 + 4 UTF-16 units into "café"),
        // reflecting how a real LSP client reports the position (issue #217 regression:
        // this used to panic on the byte/UTF-16 mismatch).
        let line = "<artifactId>café-lib</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 16);
        assert_eq!(t, MavenXmlContext::ArtifactId);
        assert_eq!(v, "café");

        // value_start (UTF-16 units) = 4 (indent) + "<artifactId>".len() = 16
        assert_eq!(range.start, Position::new(0, 16));
        // full value "café-lib" is 8 UTF-16 units long -> end = 16 + 8 = 24
        assert_eq!(range.end, Position::new(0, 24));
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_for_field_min_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let range = LspRange::default();
        assert!(
            eco.complete_package_names_for_field("a", MavenNameField::ArtifactId, range)
                .await
                .is_empty()
        );
        assert!(
            eco.complete_package_names_for_field("", MavenNameField::GroupId, range)
                .await
                .is_empty()
        );
    }

    #[cfg(feature = "lsp-responses")]
    fn test_artifact() -> ArtifactInfo {
        ArtifactInfo {
            group_id: "org.apache.commons".to_string(),
            artifact_id: "commons-lang3".to_string(),
            name: "org.apache.commons:commons-lang3".to_string().into(),
            description: Some("Apache Commons Lang".to_string()),
            latest_version: "3.14.0".into(),
            repository: None,
        }
    }

    #[cfg(feature = "lsp-responses")]
    fn test_range() -> LspRange {
        LspRange {
            start: Position::new(3, 12),
            end: Position::new(3, 15),
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_artifact_id() {
        let artifact = test_artifact();
        let range = test_range();
        let item =
            build_field_completion(&artifact, MavenNameField::ArtifactId, range, 0, "").unwrap();

        assert_eq!(item.insert_text, Some("commons-lang3".to_string()));
        assert_eq!(item.filter_text, Some("commons-lang3".to_string()));
        assert_eq!(item.label, "org.apache.commons:commons-lang3");
        // text_edit must replace exactly the caller-supplied range (the already-typed value
        // text), not the base builder's placeholder (0,0)-(0,0) range.
        assert_eq!(
            item.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: "commons-lang3".to_string(),
            }))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_group_id() {
        let artifact = test_artifact();
        let range = test_range();
        let item =
            build_field_completion(&artifact, MavenNameField::GroupId, range, 0, "").unwrap();

        assert_eq!(item.insert_text, Some("org.apache.commons".to_string()));
        assert_eq!(item.filter_text, Some("org.apache.commons".to_string()));
        assert_eq!(item.label, "org.apache.commons:commons-lang3");
        assert_eq!(
            item.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: "org.apache.commons".to_string(),
            }))
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_sort_text_uses_field_value_not_full_coordinate() {
        // #1282 S2: `build_package_completion`'s own `sort_text` ties `prefix` to
        // `artifact.name()` (`"group:artifact"`), which never starts with a bare
        // `artifactId` fragment like "commons" — `build_field_completion` must recompute
        // the tier against `value` (the field's own text) instead, or the exact-prefix
        // boost is inert for every `ArtifactId` completion.
        let artifact = test_artifact();
        let range = test_range();

        let artifact_id_item =
            build_field_completion(&artifact, MavenNameField::ArtifactId, range, 2, "commons")
                .unwrap();
        assert_eq!(artifact_id_item.sort_text, Some("00000000002".to_string()));

        let group_id_item =
            build_field_completion(&artifact, MavenNameField::GroupId, range, 2, "org.apache")
                .unwrap();
        assert_eq!(group_id_item.sort_text, Some("00000000002".to_string()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_rejects_xml_breakout_artifact_id() {
        let mut artifact = test_artifact();
        artifact.artifact_id = "commons</artifactId><parent><groupId>evil".to_string();
        let range = test_range();

        assert!(
            build_field_completion(&artifact, MavenNameField::ArtifactId, range, 0, "").is_none()
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_rejects_control_character_group_id() {
        let mut artifact = test_artifact();
        artifact.group_id = "org.apache\ncommons".to_string();
        let range = test_range();

        assert!(build_field_completion(&artifact, MavenNameField::GroupId, range, 0, "").is_none());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_field_completion_rejects_when_base_builder_rejects_name() {
        // `build_field_completion` only validates the *requested* field via
        // `is_safe_maven_coordinate_segment` — the other half of the coordinate is
        // left unvalidated by that check alone. Here `group_id` (the requested
        // field) is safe on its own, but `artifact_id` contains a space, which is
        // outside `is_safe_package_name`'s allowlist (though it would also fail
        // `is_safe_maven_coordinate_segment`, that check never runs against the
        // non-requested field). Realistically the registry always sets `name` to
        // the joined `group_id:artifact_id` (see `crates/deps-maven/src/registry.rs`),
        // so the base builder's `is_safe_package_name` gate on the combined name is
        // what closes this — and that rejection must propagate through
        // `build_field_completion`'s `?`, poisoning `label` otherwise (never
        // overridden by this function).
        let mut artifact = test_artifact();
        artifact.artifact_id = "commons lang3".to_string();
        artifact.name = format!("{}:{}", artifact.group_id, artifact.artifact_id).into();
        let range = test_range();

        assert!(is_safe_maven_coordinate_segment(&artifact.group_id));
        assert!(build_field_completion(&artifact, MavenNameField::GroupId, range, 0, "").is_none());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_deduped_field_completions_drops_unsafe_results() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-lang3".to_string(),
                name: "org.apache.commons:commons-lang3".to_string().into(),
                description: None,
                latest_version: "3.14.0".into(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.evil</groupId><parent>".to_string(),
                artifact_id: "payload".to_string(),
                name: "org.evil:payload".to_string().into(),
                description: None,
                latest_version: "1.0.0".into(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::GroupId, test_range(), "");

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, Some("org.apache.commons".to_string()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_deduped_field_completions_dedupes_shared_group_id() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-lang3".to_string(),
                name: "org.apache.commons:commons-lang3".to_string().into(),
                description: None,
                latest_version: "3.14.0".into(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-io".to_string(),
                name: "org.apache.commons:commons-io".to_string().into(),
                description: None,
                latest_version: "2.16.1".into(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-collections4".to_string(),
                name: "org.apache.commons:commons-collections4".to_string().into(),
                description: None,
                latest_version: "4.4".into(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::GroupId, test_range(), "");

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, Some("org.apache.commons".to_string()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_deduped_field_completions_keeps_distinct_group_ids() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-lang3".to_string(),
                name: "org.apache.commons:commons-lang3".to_string().into(),
                description: None,
                latest_version: "3.14.0".into(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "com.google.guava".to_string(),
                artifact_id: "guava".to_string(),
                name: "com.google.guava:guava".to_string().into(),
                description: None,
                latest_version: "33.2.1-jre".into(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::GroupId, test_range(), "");

        assert_eq!(items.len(), 2);
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_build_deduped_field_completions_dedupes_shared_artifact_id() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.foo".to_string(),
                artifact_id: "commons".to_string(),
                name: "org.foo:commons".to_string().into(),
                description: None,
                latest_version: "1.0.0".into(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.bar".to_string(),
                artifact_id: "commons".to_string(),
                name: "org.bar:commons".to_string().into(),
                description: None,
                latest_version: "2.0.0".into(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::ArtifactId, test_range(), "");

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, Some("commons".to_string()));
    }

    #[tokio::test]
    async fn test_parse_manifest() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);

        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>";

        #[cfg(windows)]
        let path = "C:/test/pom.xml";
        #[cfg(not(windows))]
        let path = "/test/pom.xml";
        let uri = Url::from_file_path(path).unwrap();

        let result = eco.parse_manifest(xml, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    /// Composition regression guard (#390/#282 bug class, mirrors the deleted
    /// `deps-lsp` end-to-end test `test_fallback_completion_maven_query_matches_tag_value`):
    /// proves `line_at` + `is_in_xml_tag_section` + `strip_leading_xml_tag` compose
    /// correctly through the real trait method on realistic multi-line pom.xml
    /// content.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let content = "<dependencies>\n  <dependency>\n    <artifactId>gua";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            Some("gua")
        );
    }

    /// #724/#728: an open `<groupId>org.apa` tag (not `artifactId`) must suppress the
    /// completion entirely — neither the bare artifact id nor the full snippet is a
    /// safe insert at that position — which this trait method achieves by returning
    /// `None`, the same value it returns for "no completable position at all" (the
    /// caller's registry search is skipped either way).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_other_open_tag_is_suppressed() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let content = "<dependencies>\n  <dependency>\n    <groupId>org.apa";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            None
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_inside_open_artifact_id_tag() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let content = "<dependencies>\n  <dependency>\n    <artifactId>gua";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(eco.fallback_completion_is_bare(content, position.into()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_no_open_tag() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let content = "<dependencies>\n  <dependency>\n    gua";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    #[test]
    fn test_fallback_bare_insert_text_inserts_artifact_id_only() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert_eq!(
            eco.fallback_bare_insert_text(&meta),
            Some("commons-lang3".to_string())
        );
    }

    #[test]
    fn test_fallback_bare_insert_text_rejects_xml_breakout_artifact_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new(
                "org.apache.commons:commons</artifactId><parent><groupId>evil",
            ),
            latest_version: "3.14.0".into(),
        };
        assert!(eco.fallback_bare_insert_text(&meta).is_none());
    }

    #[test]
    fn test_is_in_dependencies_section_basic() {
        let content = "\n<project>\n  <dependencies>\n    <dependency></dependency>\n  </dependencies>\n</project>\n";
        assert!(is_in_dependencies_section(content, 3));
        assert!(!is_in_dependencies_section(content, 1));
    }

    #[test]
    fn test_is_in_dependencies_section_no_false_positive_on_longer_tag_name() {
        let content = "\n<project>\n  <dependencyManagement>\n    <dependencies>\n      <dependency></dependency>\n    </dependencies>\n  </dependencyManagement>\n</project>\n";
        // Line 2 opens `<dependencyManagement>`, not `<dependencies>` — must not match.
        assert!(!is_in_dependencies_section(content, 2));
        // Line 4 is genuinely inside the nested `<dependencies>` block.
        assert!(is_in_dependencies_section(content, 4));
    }

    #[test]
    fn test_extract_prefix_strips_leading_xml_tag() {
        // Cursor right after "gua" in `<artifactId>gua`.
        assert_eq!(
            extract_prefix("  <artifactId>gua", 17),
            ("gua", Some("artifactId"))
        );
    }

    /// Diverges from a first-`>`-based strip whenever more than one tag precedes the
    /// cursor on a line — mirrored by `test_detect_xml_context_compact_multi_tag_line_
    /// matches_completion_extractor` using the identical line/cursor position.
    #[test]
    fn test_extract_prefix_strips_last_tag_not_first() {
        let line = "    <dependency><groupId>com.google.guava</groupId><artifactId>gua";
        assert_eq!(extract_prefix(line, 66), ("gua", Some("artifactId")));
    }

    /// Cursor right after a fully closed tag must yield an empty prefix, matching
    /// `detect_xml_context`'s own "no context" outcome for the same position —
    /// mirrored by `test_detect_xml_context_after_closed_tag_yields_no_context` using
    /// the identical line/cursor position.
    #[test]
    fn test_extract_prefix_after_closed_tag_is_empty() {
        let line = "    <artifactId>guava</artifactId>";
        assert_eq!(extract_prefix(line, 34), ("", None));
    }

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

    #[test]
    fn test_completion_insert_text_group_artifact() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.apache.commons:commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some(
                "<groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId>\
                 <version>3.14.0</version>"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_completion_insert_text_no_colon() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("<artifactId>commons-lang3</artifactId><version>3.14.0</version>".to_string())
        );
    }

    /// S1: the identical breakout `build_field_completion` guards against must also be
    /// rejected on this fallback-search path, not just the primary XML-context path.
    #[test]
    fn test_completion_insert_text_rejects_xml_breakout_artifact_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new(
                "org.apache.commons:commons</artifactId><parent><groupId>evil",
            ),
            latest_version: "3.14.0".into(),
        };
        assert!(eco.completion_insert_text(&meta).is_none());
    }

    #[test]
    fn test_completion_insert_text_rejects_xml_breakout_group_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("org.evil</groupId><parent>:commons-lang3"),
            latest_version: "3.14.0".into(),
        };
        assert!(eco.completion_insert_text(&meta).is_none());
    }

    #[test]
    fn test_completion_insert_text_no_colon_rejects_xml_breakout() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("commons</artifactId><parent>"),
            latest_version: "3.14.0".into(),
        };
        assert!(eco.completion_insert_text(&meta).is_none());
    }

    // --- #793 characterization: `MavenEcosystem::generate_completions` keeps its own
    // full override (crate-local `MavenXmlContext`-typed XML context, out of #793's scope —
    // see the plan), but the "version" arm's body moves into the new required
    // `complete_version` hook. This pins the arm's observable output before that move.

    /// Deterministic, CI-enforced counterpart to the network-gated test below: a
    /// `<version>` tag with no enclosing `<dependency>`/`<plugin>` — the project's own
    /// top-level `<version>` here — is rejected by `detect_xml_context`'s own ancestry
    /// check (#1181) *before* `MavenXmlContext::Version` is ever returned, so
    /// `generate_completions`'s `None` arm fires without ever calling
    /// `literal_version_dependency` or the registry. Before #1181, `detect_xml_context`
    /// returned `Version` unconditionally for any open `<version>` tag (`detect_xml_context`
    /// remains blind to the *parsed* dependency list — `parse_result.dependencies()` is
    /// still unused by it — but is no longer blind to the raw-text XML structure around the
    /// tag) and this exact scenario was instead rejected one layer up, by
    /// `literal_version_dependency` finding no dependency whose range covers the position.
    /// This test pins the ancestry check's own `ctx` boundary directly, not just the final
    /// `Completions::default()` output it happens to still produce either way — so a future
    /// regression that makes `detect_xml_context` wrongly permissive again (while
    /// `literal_version_dependency` still happens to fail closed) would be caught here
    /// instead of passing silently.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_no_dependency_at_position_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = "<project>\n  <version>1.0.0</version>\n</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        assert!(parse_result.dependencies().is_empty());

        let (ctx, _, _) =
            MavenEcosystem::detect_xml_context(xml, Position::new(1, 13), parse_result.as_ref());
        assert_eq!(
            ctx,
            MavenXmlContext::None,
            "detect_xml_context's own ancestry check must reject this before \
             literal_version_dependency is ever reached"
        );

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(1, 13),
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #819 characterization: a cursor outside every completable tag resolves to
    /// [`MavenXmlContext::None`], which is now a named, non-wildcard match arm in
    /// `generate_completions` rather than a catch-all `_ => vec![]` — this exercises that
    /// arm end-to-end through the public `generate_completions` entry point, not just the
    /// lower-level `detect_xml_context` unit tests above. Note this pins the arm's
    /// *observable output* (identical before and after #819 — `Completions::default()`
    /// either way); the actual #819 guarantee is compile-time (a new `MavenXmlContext`
    /// variant is a compile error at the match in `generate_completions`), which no
    /// runtime test can exercise.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_none_context_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = "<project>\n  <name>demo</name>\n</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();

        // Cursor sits inside `<name>`, a tag `detect_xml_context` does not recognize.
        let (ctx, _, _) =
            MavenEcosystem::detect_xml_context(xml, Position::new(1, 8), parse_result.as_ref());
        assert_eq!(ctx, MavenXmlContext::None);

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(1, 8),
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
        assert_eq!(
            result.origin,
            deps_core::completion::CompletionOrigin::Unresolved
        );
    }

    /// #1195 supplementary coverage: the `MavenXmlContext::ArtifactId` arm must stamp
    /// `CompletionOrigin::PackageName` end-to-end through `generate_completions`, not just
    /// resolve the context — a swapped origin literal in the hand-written match would
    /// otherwise have no test catching it.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_artifact_id_context_stamps_package_name_origin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = "<project>\n  <artifactId>junit</artifactId>\n</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();

        // Only "j" typed: too short for `complete_package_names_for_field` to search the
        // registry, so this stays network-free while still exercising the `ArtifactId` arm.
        let (ctx, value, _) =
            MavenEcosystem::detect_xml_context(xml, Position::new(1, 15), parse_result.as_ref());
        assert_eq!(ctx, MavenXmlContext::ArtifactId);
        assert_eq!(value, "j");

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(1, 15),
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(
            result,
            Completions::default()
                .with_origin(deps_core::completion::CompletionOrigin::PackageName)
        );
    }

    /// #1195 supplementary coverage: the `MavenXmlContext::GroupId` arm must stamp
    /// `CompletionOrigin::PackageName` end-to-end through `generate_completions`, not just
    /// resolve the context — a swapped origin literal in the hand-written match would
    /// otherwise have no test catching it.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_group_id_context_stamps_package_name_origin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = "<project>\n  <groupId>org.example</groupId>\n</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();

        // Only "o" typed: too short for `complete_package_names_for_field` to search the
        // registry, so this stays network-free while still exercising the `GroupId` arm.
        let (ctx, value, _) =
            MavenEcosystem::detect_xml_context(xml, Position::new(1, 12), parse_result.as_ref());
        assert_eq!(ctx, MavenXmlContext::GroupId);
        assert_eq!(value, "o");

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(1, 12),
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(
            result,
            Completions::default()
                .with_origin(deps_core::completion::CompletionOrigin::PackageName)
        );
    }

    /// #919 C1 (critic follow-up): an *unresolved* `${property}` reference — no
    /// `<properties>` entry to resolve it against, the dominant real-world shape for a
    /// version inherited from a parent/BOM POM this crate cannot resolve — must withhold
    /// version completion entirely, deterministically and without touching the registry.
    /// This is the exact scenario #919 was filed over: `detect_xml_context` only checks
    /// that the cursor sits inside a `<version>` tag, so without the literal-span guard
    /// this would previously offer the full version list and, on accept, splice a version
    /// string into `${slf4j.version}`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_withheld_for_unresolved_property() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("${slf4j.version}"),
            "fixture no longer exercises the unresolved-property shape: {xml}"
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
                xml,
                dep.version_range().unwrap(),
            )
        );

        let result = eco
            .generate_completions(parse_result.as_ref(), position, xml, freshness)
            .await;
        assert_eq!(
            result,
            Completions::default().with_origin(deps_core::completion::CompletionOrigin::Version)
        );
    }

    // `complete_versions` has no offline guard for an already-well-formed package name, so
    // the "happy path" needs live Maven Central access, mirroring this codebase's existing
    // convention for such tests (e.g. `deps_maven::registry::tests`'s own `#[ignore]`d
    // network tests).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_generate_completions_version_arm_dispatches_by_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();
        let freshness = deps_core::FreshnessSettings::default();

        let direct = eco.complete_versions(dep.name(), "", freshness).await;
        let via_dispatch = eco
            .generate_completions(parse_result.as_ref(), position, xml, freshness)
            .await;
        assert_eq!(via_dispatch.items, direct);
    }

    // #1161: an empty `<version></version>` tag on its own line (a different line from
    // `<artifactId>`) must still resolve completion end-to-end through the real parser +
    // dispatch. Before the parser fix, this shape was unresolvable by either of
    // `literal_version_dependency`'s passes: pass 1 requires a real `version_range` (there was
    // none), and pass 2's same-line fallback requires `name_range`'s line to equal the
    // cursor's line, which it doesn't here. After the fix, the parser's now-real (zero-width)
    // `version_range` makes pass 1 match directly via its inclusive `position_in_range` check
    // — this test exercises pass 1, not the same-line fallback (critic re-check follow-up:
    // this comment previously described the pre-fix, now-inapplicable failure mode).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_admits_empty_version_tag_on_separate_line() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>foo</artifactId>
      <version></version>
    </dependency>
  </dependencies>
</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let version_range = dep
            .version_range()
            .expect("empty <version></version> must still yield a trackable range");
        assert_eq!(
            version_range.start, version_range.end,
            "empty tag content must be zero-width"
        );
        assert_ne!(
            version_range.start.line,
            dep.name_range().start.line,
            "fixture must keep <version> on a different line from <artifactId>: {xml}"
        );
        let position: Position = version_range.start.into();

        let (ctx, value, value_range) =
            MavenEcosystem::detect_xml_context(xml, position, parse_result.as_ref());
        assert_eq!(ctx, MavenXmlContext::Version);
        assert_eq!(value, "");

        let resolved = deps_core::completion::literal_version_dependency(
            parse_result.as_ref(),
            position,
            xml,
            value_range,
        );
        assert!(
            resolved.is_some(),
            "must resolve the dependency despite version_range being empty and on a \
             different line from name_range"
        );
        assert_eq!(resolved.unwrap().name(), dep.name());
    }

    /// CI-run counterpart to the network-`#[ignore]`d test below: without this, a wiring
    /// regression in `complete_self_closing_version` (e.g. swapping `probe_range`/`tag_span`,
    /// or dropping `Some(&replacement)`) would pass CI undetected, since `cargo nextest run`
    /// never executes `#[ignore]`d tests. Exercises the exact function the `generate_completions`
    /// arm calls, substituting a mock registry for the real network-backed one.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_self_closing_version_threads_replacement_through_mock_registry() {
        struct MockVersion(deps_core::ConcreteVersion);
        impl deps_core::Version for MockVersion {
            fn version_string(&self) -> &deps_core::ConcreteVersion {
                &self.0
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockRegistry;
        impl deps_core::Registry for MockRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>>
            {
                let versions: Vec<Box<dyn deps_core::Version>> =
                    vec![Box::new(MockVersion("1.2.3".into()))];
                Box::pin(async move { Ok(versions) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version/>
    </dependency>
  </dependencies>
</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = crate::parser::parse_pom_xml(xml, &uri).unwrap();
        let dep = &parse_result.dependencies()[0];
        let position: Position = dep.version_range().unwrap().start.into();

        let (ctx, value, _) = MavenEcosystem::detect_xml_context(xml, position, &parse_result);
        let MavenXmlContext::SelfClosingVersion { tag_span } = ctx else {
            panic!("expected SelfClosingVersion, got {ctx:?}");
        };

        let items = complete_self_closing_version(
            &MockRegistry,
            &MavenFormatter,
            &parse_result,
            position,
            xml,
            tag_span,
            value,
            deps_core::FreshnessSettings::default(),
        )
        .await;

        assert!(
            !items.is_empty(),
            "must offer a completion via the mock registry"
        );
        let Some(CompletionTextEdit::Edit(edit)) = &items[0].text_edit else {
            panic!("expected a textEdit::Edit");
        };
        assert_eq!(edit.range, tag_span);
        assert_eq!(edit.new_text, "<version>1.2.3</version>");
        assert_eq!(items[0].filter_text, Some("<version/>".to_string()));
    }

    /// #1195 regression: a self-closing `<version/>` with no matching dependency at this
    /// position resolves to `MavenXmlContext::SelfClosingVersion` (purely text-based, see
    /// `find_self_closing_version_tag`) but `literal_version_dependency` finds nothing —
    /// `complete_self_closing_version` returns empty without ever touching the registry
    /// (deterministic, CI-safe, no network needed), and `generate_completions` must still
    /// stamp `CompletionOrigin::Version` on that empty result, not
    /// `Completions::default()`'s `CompletionOrigin::Unresolved`, which would let
    /// `deps-lsp`'s fallback re-enter a raw-text package-name search.
    ///
    /// The cursor sits at an *interior* column of `<version/>` (immediately after
    /// `<version`, before the `/`), not past the closing `>`:
    /// `MavenEcosystem::fallback_completion_prefix`'s own `strip_leading_xml_tag`-derived
    /// suppression only fires once a `>` has been typed, so a test whose cursor sits past
    /// the tag would pass vacuously (the length guard already rejects the resulting empty
    /// prefix) without exercising the actual leak this closes — confirmed here by asserting
    /// `fallback_completion_prefix` still returns a prefix at this exact position, i.e. the
    /// raw-text path really would have run without the `CompletionOrigin`-based gate.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_self_closing_version_empty_result_stamps_version_origin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        // `<version/>` is nested inside a `<dependency>` element (satisfying #1181's ancestry
        // check, so ctx still resolves to `SelfClosingVersion`), but that `<dependency>` has
        // no `<groupId>`/`<artifactId>` — `finalize_dep` drops it, so no parsed dependency
        // matches this position, keeping `complete_self_closing_version` registry-free.
        let xml = "<project>\n  <dependencies>\n    <dependency>\n      <version/>\n    </dependency>\n  </dependencies>\n</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        assert!(
            parse_result.dependencies().is_empty(),
            "fixture must not parse a <dependency>: {xml}"
        );

        let line = "      <version/>";
        let interior_col =
            u32::try_from(line.find("<version").unwrap() + "<version".len()).unwrap();
        let position = Position::new(3, interior_col);

        let (ctx, _, _) = MavenEcosystem::detect_xml_context(xml, position, parse_result.as_ref());
        assert!(
            matches!(ctx, MavenXmlContext::SelfClosingVersion { .. }),
            "expected SelfClosingVersion, got {ctx:?}"
        );
        assert!(
            deps_core::completion::literal_version_dependency(
                parse_result.as_ref(),
                position,
                xml,
                LspRange::default(),
            )
            .is_none(),
            "fixture must have no matching dependency, to keep the registry unreachable"
        );

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                position,
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(result.items.is_empty());
        assert_eq!(
            result.origin,
            deps_core::completion::CompletionOrigin::Version,
            "empty SelfClosingVersion result must still block the raw-text fallback"
        );

        assert!(
            eco.fallback_completion_prefix(xml, position.into())
                .is_some(),
            "the raw-text fallback prefix must still be reachable at this interior position — \
             proving CompletionOrigin::Version, not the prefix guard itself, is what closes #1195"
        );
    }

    // #1167: a self-closing `<version/>` must still get a trackable `version_range` from the
    // parser (round 1's S1 fix, kept — every other consumer, hover/diagnostics/code-actions/
    // code-lenses, correctly no-ops on it), and `generate_completions` now offers a real
    // completion there too, replacing the whole tag via `VersionReplacement` instead of
    // withholding it (round 2's reverted trigger, fixed properly this time).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_generate_completions_offers_completion_for_self_closing_version_tag() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = r"<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version/>
    </dependency>
  </dependencies>
</project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let version_range = dep
            .version_range()
            .expect("self-closing <version/> must still yield a trackable range for non-completion consumers");
        assert_eq!(
            version_range.start, version_range.end,
            "self-closing tag content must be zero-width"
        );
        let position: Position = version_range.start.into();

        let (ctx, _, _) = MavenEcosystem::detect_xml_context(xml, position, parse_result.as_ref());
        let MavenXmlContext::SelfClosingVersion { tag_span } = ctx else {
            panic!("self-closing <version/> must be a completion trigger, got {ctx:?}");
        };

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                position,
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(
            !result.items.is_empty(),
            "must offer real version completions"
        );
        let Some(CompletionTextEdit::Edit(edit)) = &result.items[0].text_edit else {
            panic!("expected a textEdit::Edit");
        };
        assert_eq!(edit.range, tag_span);
        assert!(edit.new_text.starts_with("<version>"));
        assert!(edit.new_text.ends_with("</version>"));
    }

    /// #1181 follow-up: on a minified pom.xml, `<project>`'s own top-level self-closing
    /// `<version/>` can share a physical line with an unrelated `<dependency>`'s coordinates.
    /// Before this fix, a self-closing `<version/>` had no ancestry check at all, so
    /// `literal_version_dependency`'s same-line fallback (#1146) misattributed the project's
    /// own version tag to the nearby dependency — the same #1181 misattribution class the
    /// `<version>...</version>` arm was already closed for. The extended ancestry check in
    /// `detect_xml_context` must now suppress the trigger before `literal_version_dependency`
    /// is ever reached, mirroring
    /// `test_generate_completions_withholds_completion_for_project_own_version_on_minified_line`.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_detect_xml_context_self_closing_project_version_on_minified_line_yields_no_context() {
        let xml = "<project><version/><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>foo</artifactId><version/></dependency>\
</dependencies></project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let result = crate::parser::parse_pom_xml(xml, &uri).unwrap();
        let deps = result.dependencies();
        assert_eq!(deps.len(), 1, "fixture must parse one dependency: {xml}");

        // Cursor inside the project's OWN self-closing `<version/>` (not the dependency's).
        let project_version_col = u32::try_from(xml.find("<version/>").unwrap() + 5).unwrap();
        let position = Position::new(0, project_version_col);

        let (ctx, _, _) = MavenEcosystem::detect_xml_context(xml, position, &result);
        assert_eq!(
            ctx,
            MavenXmlContext::None,
            "a self-closing <version/> with no enclosing <dependency>/<plugin> must not trigger \
             completion, even when a real dependency's version shares the same minified line"
        );
    }

    /// #1181: on a minified pom.xml, `<project>`'s own top-level `<version>` can share a
    /// physical line with an unrelated `<dependency>`'s coordinates. Before the ancestry
    /// check, `literal_version_dependency`'s same-line fallback (#1146) would resolve the
    /// cursor position — sitting inside the project's own version — to the nearby real
    /// dependency instead, so an accepted completion would have edited `foo`'s version, not
    /// the project's own. The ancestry check in `detect_xml_context` must suppress the
    /// trigger before `literal_version_dependency` is ever reached.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_withholds_completion_for_project_own_version_on_minified_line()
     {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        let xml = "<project><version>9.9.9</version><dependencies><dependency>\
                    <groupId>com.example</groupId><artifactId>foo</artifactId>\
                    <version>1.0.0</version></dependency></dependencies></project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let parse_result = eco.parse_manifest(xml, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "fixture must parse exactly the real dependency, not the project's own version: {xml}"
        );

        // Cursor inside the project's own <version>9.9.9</version>, not the dependency's.
        let project_version_value_start = xml.find("<version>9.9.9").unwrap() + "<version>".len();
        let position = Position::new(0, u32::try_from(project_version_value_start + 2).unwrap());

        let (ctx, _, _) = MavenEcosystem::detect_xml_context(xml, position, parse_result.as_ref());
        assert_eq!(
            ctx,
            MavenXmlContext::None,
            "a <version> with no enclosing <dependency>/<plugin> must not trigger completion, \
             even when a real dependency's version shares the same minified line"
        );

        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                position,
                xml,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    // #1146: cursor just before dep-two's version_range on a real two-dep-per-line pom.xml resolves dep-two via pass 2, not dep-one.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_literal_version_dependency_resolves_second_dependency_from_real_parser_output() {
        let xml = "<project><dependencies>\
<dependency><groupId>com.example</groupId><artifactId>foo</artifactId><version>1.0.0</version></dependency>\
<dependency><groupId>com.example</groupId><artifactId>bar</artifactId><version>2.0.0</version></dependency>\
</dependencies></project>";
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let result = crate::parser::parse_pom_xml(xml, &uri).unwrap();
        let deps = result.dependencies();
        assert_eq!(
            deps.len(),
            2,
            "fixture must parse both same-line dependencies: {xml}"
        );
        let dep_one_name = deps[0].name().clone();
        let dep_two = deps[1];
        let dep_two_version_range: LspRange = dep_two.version_range().unwrap().into();
        let position = Position {
            line: dep_two_version_range.start.line,
            character: dep_two_version_range.start.character - 1,
        };

        let resolved = deps_core::completion::literal_version_dependency(
            &result,
            position,
            xml,
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
}

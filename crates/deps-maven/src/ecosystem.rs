//! Maven ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionTextEdit, Position, Range as LspRange, TextEdit, Uri,
};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
    position_in_range,
};

use crate::formatter::MavenFormatter;
use crate::registry::MavenCentralRegistry;
use crate::types::ArtifactInfo;

pub struct MavenEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: MavenFormatter,
}

/// Which half of a Maven `groupId:artifactId` coordinate a completion should insert.
///
/// A pom.xml `<groupId>`/`<artifactId>` tag only ever holds one half of the coordinate,
/// so the completion inserted into it must not be the full "group:artifact" search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MavenNameField {
    GroupId,
    ArtifactId,
}

/// Builds a completion item for one field of a Maven coordinate.
///
/// Reuses [`deps_core::completion::build_package_completion`] for documentation/detail
/// formatting, then overrides the insertable text to just the requested field so it fits
/// the single `<groupId>` or `<artifactId>` tag the cursor is inside. `replace_range` must
/// span the entire existing tag value, not just the already-typed prefix (see
/// [`MavenEcosystem::detect_xml_context`]) — the base builder's own range is a placeholder
/// `(0,0)-(0,0)` that does not contain the real cursor position and would corrupt the
/// document if used as-is.
fn build_field_completion(
    artifact: &ArtifactInfo,
    field: MavenNameField,
    replace_range: LspRange,
) -> CompletionItem {
    let mut item = deps_core::completion::build_package_completion(artifact, LspRange::default());

    let value = match field {
        MavenNameField::GroupId => artifact.group_id.clone(),
        MavenNameField::ArtifactId => artifact.artifact_id.clone(),
    };

    item.insert_text = Some(value.clone());
    item.filter_text = Some(value.clone());
    item.sort_text = Some(value.clone());
    item.text_edit = Some(CompletionTextEdit::Edit(TextEdit {
        range: replace_range,
        new_text: value,
    }));

    item
}

/// Builds completion items for one field of a Maven coordinate, deduped by that field's value.
///
/// Several search results can share the same `groupId` (or, more rarely, `artifactId`) —
/// collapsed here to one item per distinct value, since they would otherwise insert
/// identical text into the tag and only clutter the list. Keeps the first (highest-relevance,
/// per the registry's own ranking) match for each value.
fn build_deduped_field_completions(
    results: &[ArtifactInfo],
    field: MavenNameField,
    replace_range: LspRange,
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
        .map(|artifact| build_field_completion(artifact, field, replace_range))
        .collect()
}

impl MavenEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(cache)),
            formatter: MavenFormatter,
        }
    }

    async fn complete_package_names_for_field(
        &self,
        prefix: &str,
        field: MavenNameField,
        replace_range: LspRange,
    ) -> Vec<CompletionItem> {
        if !deps_core::completion::is_valid_completion_prefix_len(prefix) {
            return vec![];
        }

        let results = match self.registry.search_typed(prefix, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Maven registry search failed for '{}': {}", prefix, e);
                return vec![];
            }
        };

        build_deduped_field_completions(&results, field, replace_range)
    }

    async fn complete_versions(
        &self,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
            freshness,
        )
        .await
    }

    /// Detects Maven XML completion context at the given position.
    ///
    /// Returns `(context_type, value, value_range)` where `context_type` is "version",
    /// "artifactId", "groupId", or empty string for no completion; `value` is the
    /// already-typed prefix up to the cursor, used as the search query; `value_range` spans
    /// the *entire* existing tag value (opening tag to closing tag, not just up to the
    /// cursor) and is the range a completion's `text_edit` must replace so the whole value
    /// is overwritten instead of leaving trailing characters behind — it is meaningless when
    /// `context_type` is empty.
    ///
    /// `position.character` is a UTF-16 code unit offset (LSP spec) and is converted to a
    /// byte offset once via [`deps_core::completion::utf16_to_byte_offset`] before any
    /// slicing; the returned `value_range`'s `character` fields are converted back to UTF-16
    /// units via [`deps_core::completion::byte_to_utf16_offset`]. This avoids panics on
    /// multi-byte tag content (e.g. accented characters) and keeps the returned range valid
    /// for LSP clients.
    fn detect_xml_context<'a>(
        content: &'a str,
        position: Position,
        parse_result: &dyn ParseResultTrait,
    ) -> (&'static str, &'a str, LspRange) {
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;

        if line_idx >= lines.len() {
            return ("", "", LspRange::default());
        }

        let line = lines[line_idx];
        let col_idx = deps_core::completion::utf16_to_byte_offset(line, position.character)
            .unwrap_or(line.len());

        // Find if cursor is inside a tag value: <tag>|value|</tag>
        // Walk back from cursor to find opening tag
        let before_cursor = &line[..col_idx];

        // Check if we're inside a known element by looking for the most recent opening tag
        for tag in &["version", "artifactId", "groupId"] {
            let open = format!("<{tag}>");
            if let Some(start) = before_cursor.rfind(&open) {
                let value_start = start + open.len();
                // Make sure there's no closing tag before cursor
                let between = &before_cursor[value_start..];
                if !between.contains("</") {
                    // Check if cursor is on a dependency line (use parse_result for context)
                    let _ = parse_result;
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
                    return (tag, value, value_range);
                }
            }
        }

        ("", "", LspRange::default())
    }
}

impl deps_core::ecosystem::private::Sealed for MavenEcosystem {}

impl Ecosystem for MavenEcosystem {
    fn id(&self) -> &'static str {
        "maven"
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
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result =
                crate::parser::parse_pom_xml(content, uri).map_err(deps_core::DepsError::from)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move {
            let (ctx_type, value, value_range) =
                Self::detect_xml_context(content, position, parse_result);

            match ctx_type {
                "version" => {
                    let dep = parse_result.dependencies().into_iter().find(|d| {
                        d.version_range()
                            .is_some_and(|r| position_in_range(position, r))
                            || d.name_range().start.line == position.line
                    });
                    if let Some(dep) = dep {
                        self.complete_versions(dep.name(), value, freshness).await
                    } else {
                        vec![]
                    }
                }
                "artifactId" => {
                    self.complete_package_names_for_field(
                        value,
                        MavenNameField::ArtifactId,
                        value_range,
                    )
                    .await
                }
                "groupId" => {
                    self.complete_package_names_for_field(
                        value,
                        MavenNameField::GroupId,
                        value_range,
                    )
                    .await
                }
                _ => vec![],
            }
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert_eq!(eco.id(), "maven");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert_eq!(eco.display_name(), "Maven (JVM)");
    }

    #[test]
    fn test_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &["pom.xml"]);
    }

    #[test]
    fn test_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert!(eco.lockfile_filenames().is_empty());
    }

    #[test]
    fn test_lockfile_provider_none() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_none());
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert!(eco.as_any().is::<MavenEcosystem>());
    }

    struct NoopParseResult;
    impl deps_core::ParseResult for NoopParseResult {
        fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
            vec![]
        }
        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }
        fn uri(&self) -> &tower_lsp_server::ls_types::Uri {
            unimplemented!()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn make_position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    fn xml_context(line_content: &str, col: u32) -> (&'static str, String) {
        let (t, v, _range) = xml_context_with_range(line_content, col);
        (t, v)
    }

    fn xml_context_with_range(line_content: &str, col: u32) -> (&'static str, String, LspRange) {
        let content = format!("    {line_content}\n");
        let col_in_content = col + 4; // 4 spaces indent
        let (t, v, range) = MavenEcosystem::detect_xml_context(
            &content,
            make_position(0, col_in_content),
            &NoopParseResult,
        );
        (t, v.to_owned(), range)
    }

    #[test]
    fn test_detect_xml_context_version_cursor_at_start() {
        // <version>|4.13.2</version> — cursor right after '>'
        let line = "<version>4.13.2</version>";
        // col 0..8 is "<version", col 9 is '4'
        let (t, v) = xml_context(line, 9); // col at value_start
        assert_eq!(t, "version");
        assert_eq!(v, "");
    }

    #[test]
    fn test_detect_xml_context_version_cursor_mid() {
        // <version>4.1|3.2</version>
        let line = "<version>4.13.2</version>";
        let (t, v) = xml_context(line, 12); // "4.1" = 3 chars after value_start (9)
        assert_eq!(t, "version");
        assert_eq!(v, "4.1");
    }

    #[test]
    fn test_detect_xml_context_version_cursor_at_end() {
        // <version>4.13.2|</version>
        let line = "<version>4.13.2</version>";
        let (t, v) = xml_context(line, 15); // value_start=9, end=15
        assert_eq!(t, "version");
        assert_eq!(v, "4.13.2");
    }

    #[test]
    fn test_detect_xml_context_version_empty_value() {
        // <version>|</version>
        let line = "<version></version>";
        let (t, v) = xml_context(line, 9);
        assert_eq!(t, "version");
        assert_eq!(v, "");
    }

    #[test]
    fn test_detect_xml_context_artifact_id_prefix() {
        // <artifactId>jun|it</artifactId>
        let line = "<artifactId>junit</artifactId>";
        let (t, v) = xml_context(line, 15); // value_start=12, cursor at 15 = "jun"
        assert_eq!(t, "artifactId");
        assert_eq!(v, "jun");
    }

    /// #282 S1 (second critic round) parity guard: `deps-lsp`'s `completion.rs`
    /// (`extract_prefix`/`strip_leading_xml_tag`) must extract the identical query
    /// string for the identical cursor position, since it's a raw-text approximation of
    /// this function's own tag-aware extraction, and both feed the same registry
    /// dedup/cache-key mechanism (`MavenCentralRegistry::search_typed`). This line and
    /// cursor position are kept intentionally identical to `deps-lsp`'s
    /// `test_fallback_completion_maven_query_matches_tag_value` — if either extractor's
    /// logic changes, update both tests and confirm they still agree.
    #[test]
    fn test_detect_xml_context_compact_multi_tag_line_matches_completion_extractor() {
        // <dependency><groupId>com.google.guava</groupId><artifactId>gua| — cursor
        // right after "gua", with an earlier `<groupId>...</groupId>` on the same line.
        let line = "<dependency><groupId>com.google.guava</groupId><artifactId>gua";
        let (t, v) = xml_context(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, "artifactId");
        assert_eq!(v, "gua");
    }

    /// #282 S1 (second critic round) parity guard: cursor right after a fully closed
    /// tag (`<artifactId>guava</artifactId>|`) yields no completion context at all —
    /// `between.contains("</")` rejects it. `deps-lsp`'s `strip_leading_xml_tag` must
    /// agree by yielding an empty string for the same position (which `fallback_completion`'s
    /// existing empty-prefix guard then rejects), not a markup-polluted search query.
    #[test]
    fn test_detect_xml_context_after_closed_tag_yields_no_context() {
        let line = "<artifactId>guava</artifactId>";
        let (t, v) = xml_context(line, u32::try_from(line.len()).unwrap());
        assert_eq!(t, "");
        assert_eq!(v, "");
    }

    #[test]
    fn test_detect_xml_context_artifact_id_range_spans_full_value() {
        // <artifactId>jun|it</artifactId> — indented by 4 spaces in xml_context_with_range
        // The range must span the FULL existing value ("junit"), not just up to the
        // cursor, so a completion replaces the whole tag content instead of leaving
        // trailing characters behind (issue #218a).
        let line = "<artifactId>junit</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, "artifactId");
        assert_eq!(v, "jun");
        // value_start = 4 (indent) + 12 ("<artifactId>") = 16; value_end = 16 + "junit".len() = 21
        assert_eq!(range.start, Position::new(0, 16));
        assert_eq!(range.end, Position::new(0, 21));
    }

    #[test]
    fn test_detect_xml_context_group_id_range_spans_full_value() {
        // <groupId>org.apache.comm|ons</groupId>
        let line = "<groupId>org.apache.commons</groupId>";
        let (t, v, range) = xml_context_with_range(line, 24);
        assert_eq!(t, "groupId");
        assert_eq!(v, "org.apache.comm");
        // value_start = 4 (indent) + 9 ("<groupId>") = 13; value_end = 13 + "org.apache.commons".len() = 31
        assert_eq!(range.start, Position::new(0, 13));
        assert_eq!(range.end, Position::new(0, 31));
    }

    #[test]
    fn test_detect_xml_context_surrogate_pair_value_no_panic() {
        // <artifactId>🎉|lib</artifactId> — 🎉 (U+1F389) is 4 UTF-8 bytes but a UTF-16
        // surrogate pair (2 code units); cursor placed right after it via UTF-16 units.
        let line = "<artifactId>🎉lib</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 14); // value_start=12 + 2 (🎉)
        assert_eq!(t, "artifactId");
        assert_eq!(v, "🎉");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 21)); // 16 + "🎉lib".len() in UTF-16 units (2+3)
    }

    #[test]
    fn test_detect_xml_context_value_end_fallback_no_closing_tag_on_line() {
        // <artifactId>jun|it — no closing tag anywhere on the line. After the S1 fix the
        // range falls back to the cursor position (insert-mode) rather than swallowing the
        // rest of the line, since there is no proof of where the value actually ends.
        let line = "<artifactId>junit";
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, "artifactId");
        assert_eq!(v, "jun");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 19)); // falls back to cursor: 4 + 15
    }

    #[test]
    fn test_detect_xml_context_no_closing_tag_range_excludes_trailing_comment() {
        // <artifactId>ju|    <!-- todo --> — regression for S1: the old `line.len()`
        // fallback swallowed the trailing comment into the replace range. The range must
        // stop at the cursor, not extend into unrelated trailing content.
        let line = "<artifactId>ju    <!-- todo -->";
        let (t, v, range) = xml_context_with_range(line, 14);
        assert_eq!(t, "artifactId");
        assert_eq!(v, "ju");
        assert_eq!(range.start, Position::new(0, 16)); // 4 (indent) + 12
        assert_eq!(range.end, Position::new(0, 18)); // 4 + 14 — does not reach the comment
    }

    #[test]
    fn test_detect_xml_context_range_always_contains_cursor() {
        // <artifactId>ju|</artifactId> — cursor sits between '<' and '/' of the closing
        // tag, so `find("</")` locates a match *before* the cursor. Regression for S2:
        // per LSP 3.17, `textEdit.range` must contain the request position, so `range.end`
        // must never fall before the cursor.
        let line = "<artifactId>ju</artifactId>";
        let cursor_col = 15u32; // indented cursor position
        let (t, v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, "artifactId");
        assert_eq!(v, "ju<");
        let cursor = Position::new(0, cursor_col + 4);
        assert!(
            range.end >= cursor,
            "range {range:?} must contain cursor {cursor:?}"
        );
        assert_eq!(range.end, Position::new(0, 19));
    }

    #[test]
    fn test_detect_xml_context_empty_value_zero_width_range() {
        // <version>|</version> — empty existing value produces a zero-width range at the
        // value's start.
        let line = "<version></version>";
        let (t, v, range) = xml_context_with_range(line, 9);
        assert_eq!(t, "version");
        assert_eq!(v, "");
        assert_eq!(range.start, range.end);
        assert_eq!(range.start, Position::new(0, 13)); // 4 (indent) + "<version>".len()
    }

    #[test]
    fn test_detect_xml_context_cursor_at_value_start_full_replace_range() {
        // <version>|4.13.2</version> — range must span the full existing value even
        // though the typed prefix is empty.
        let line = "<version>4.13.2</version>";
        let (t, v, range) = xml_context_with_range(line, 9);
        assert_eq!(t, "version");
        assert_eq!(v, "");
        assert_eq!(range.start, Position::new(0, 13)); // 4 (indent) + "<version>".len()
        assert_eq!(range.end, Position::new(0, 19)); // 13 + "4.13.2".len()
    }

    #[test]
    fn test_detect_xml_context_multibyte_value_no_panic() {
        // <artifactId>café|-lib</artifactId> — cursor positioned via UTF-16 units right
        // after the multi-byte 'é' (col 16 = value_start 12 + 4 UTF-16 units into "café"),
        // reflecting how a real LSP client reports the position (issue #217 regression:
        // this used to panic on the byte/UTF-16 mismatch).
        let line = "<artifactId>café-lib</artifactId>";
        let (t, v, range) = xml_context_with_range(line, 16);
        assert_eq!(t, "artifactId");
        assert_eq!(v, "café");

        // value_start (UTF-16 units) = 4 (indent) + "<artifactId>".len() = 16
        assert_eq!(range.start, Position::new(0, 16));
        // full value "café-lib" is 8 UTF-16 units long -> end = 16 + 8 = 24
        assert_eq!(range.end, Position::new(0, 24));
    }

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

    fn test_artifact() -> ArtifactInfo {
        ArtifactInfo {
            group_id: "org.apache.commons".to_string(),
            artifact_id: "commons-lang3".to_string(),
            name: "org.apache.commons:commons-lang3".to_string().into(),
            description: Some("Apache Commons Lang".to_string()),
            latest_version: "3.14.0".to_string(),
            repository: None,
        }
    }

    fn test_range() -> LspRange {
        LspRange {
            start: Position::new(3, 12),
            end: Position::new(3, 15),
        }
    }

    #[test]
    fn test_build_field_completion_artifact_id() {
        let artifact = test_artifact();
        let range = test_range();
        let item = build_field_completion(&artifact, MavenNameField::ArtifactId, range);

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

    #[test]
    fn test_build_field_completion_group_id() {
        let artifact = test_artifact();
        let range = test_range();
        let item = build_field_completion(&artifact, MavenNameField::GroupId, range);

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

    #[test]
    fn test_build_deduped_field_completions_dedupes_shared_group_id() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-lang3".to_string(),
                name: "org.apache.commons:commons-lang3".to_string().into(),
                description: None,
                latest_version: "3.14.0".to_string(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-io".to_string(),
                name: "org.apache.commons:commons-io".to_string().into(),
                description: None,
                latest_version: "2.16.1".to_string(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-collections4".to_string(),
                name: "org.apache.commons:commons-collections4".to_string().into(),
                description: None,
                latest_version: "4.4".to_string(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::GroupId, test_range());

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, Some("org.apache.commons".to_string()));
    }

    #[test]
    fn test_build_deduped_field_completions_keeps_distinct_group_ids() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.apache.commons".to_string(),
                artifact_id: "commons-lang3".to_string(),
                name: "org.apache.commons:commons-lang3".to_string().into(),
                description: None,
                latest_version: "3.14.0".to_string(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "com.google.guava".to_string(),
                artifact_id: "guava".to_string(),
                name: "com.google.guava:guava".to_string().into(),
                description: None,
                latest_version: "33.2.1-jre".to_string(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::GroupId, test_range());

        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_build_deduped_field_completions_dedupes_shared_artifact_id() {
        let results = vec![
            ArtifactInfo {
                group_id: "org.foo".to_string(),
                artifact_id: "commons".to_string(),
                name: "org.foo:commons".to_string().into(),
                description: None,
                latest_version: "1.0.0".to_string(),
                repository: None,
            },
            ArtifactInfo {
                group_id: "org.bar".to_string(),
                artifact_id: "commons".to_string(),
                name: "org.bar:commons".to_string().into(),
                description: None,
                latest_version: "2.0.0".to_string(),
                repository: None,
            },
        ];

        let items =
            build_deduped_field_completions(&results, MavenNameField::ArtifactId, test_range());

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
        let uri = Uri::from_file_path(path).unwrap();

        let result = eco.parse_manifest(xml, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }
}

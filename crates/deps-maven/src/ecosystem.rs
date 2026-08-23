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
/// span exactly the already-typed value text (see [`MavenEcosystem::detect_xml_context`]) —
/// the base builder's own range is a placeholder `(0,0)-(0,0)` that does not contain the
/// real cursor position and would corrupt the document if used as-is.
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
        if prefix.len() < 2 || prefix.len() > 200 {
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
    /// "artifactId", "groupId", or empty string for no completion; `value_range` spans the
    /// already-typed value text (from the opening tag to the cursor) and is the range a
    /// completion's `text_edit` must replace — it is meaningless when `context_type` is empty.
    ///
    /// Note: `position.character` is a UTF-16 code unit offset (LSP spec). The slicing
    /// `&line[..col_idx]` uses byte indexing. For typical pom.xml content (ASCII groupId,
    /// artifactId, version values) these are equivalent. Files with multi-byte characters
    /// in XML tag content near dependency fields may produce incorrect context detection.
    fn detect_xml_context<'a>(
        content: &'a str,
        position: Position,
        parse_result: &dyn ParseResultTrait,
    ) -> (&'static str, &'a str, LspRange) {
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;
        let col_idx = position.character as usize;

        if line_idx >= lines.len() {
            return ("", "", LspRange::default());
        }

        let line = lines[line_idx];

        // Find if cursor is inside a tag value: <tag>|value|</tag>
        // Walk back from cursor to find opening tag
        let before_cursor = if col_idx <= line.len() {
            &line[..col_idx]
        } else {
            line
        };

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
                    let clamped_col = col_idx.min(line.len());
                    let value = &line[value_start..clamped_col];
                    let value_range = LspRange {
                        start: Position {
                            line: position.line,
                            character: value_start as u32,
                        },
                        end: Position {
                            line: position.line,
                            character: clamped_col as u32,
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

    #[test]
    fn test_detect_xml_context_artifact_id_range_spans_typed_value() {
        // <artifactId>jun|it</artifactId> — indented by 4 spaces in xml_context_with_range
        let line = "<artifactId>junit</artifactId>";
        let (t, _v, range) = xml_context_with_range(line, 15);
        assert_eq!(t, "artifactId");
        // value_start = 4 (indent) + 12 ("<artifactId>") = 16; cursor col = 4 + 15 = 19
        assert_eq!(range.start, Position::new(0, 16));
        assert_eq!(range.end, Position::new(0, 19));
    }

    #[test]
    fn test_detect_xml_context_group_id_range_spans_typed_value() {
        // <groupId>org.apache.comm|ons</groupId>
        let line = "<groupId>org.apache.commons</groupId>";
        let (t, v, range) = xml_context_with_range(line, 24);
        assert_eq!(t, "groupId");
        assert_eq!(v, "org.apache.comm");
        // value_start = 4 (indent) + 9 ("<groupId>") = 13; cursor col = 4 + 24 = 28
        assert_eq!(range.start, Position::new(0, 13));
        assert_eq!(range.end, Position::new(0, 28));
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

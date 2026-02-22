//! Maven ecosystem implementation for deps-lsp.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers,
    position_in_range,
};

use crate::formatter::MavenFormatter;
use crate::registry::MavenCentralRegistry;

pub struct MavenEcosystem {
    registry: Arc<MavenCentralRegistry>,
    formatter: MavenFormatter,
}

impl MavenEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(MavenCentralRegistry::new(cache)),
            formatter: MavenFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(self.registry.as_ref(), prefix, 20)
            .await
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
        )
        .await
    }

    /// Detects Maven XML completion context at the given position.
    ///
    /// Returns (context_type, value) where context_type is "version", "artifactId", "groupId",
    /// or empty string for no completion.
    ///
    /// Note: `position.character` is a UTF-16 code unit offset (LSP spec). The slicing
    /// `&line[..col_idx]` uses byte indexing. For typical pom.xml content (ASCII groupId,
    /// artifactId, version values) these are equivalent. Files with multi-byte characters
    /// in XML tag content near dependency fields may produce incorrect context detection.
    fn detect_xml_context<'a>(
        content: &'a str,
        position: Position,
        parse_result: &dyn ParseResultTrait,
    ) -> (&'static str, &'a str) {
        let lines: Vec<&str> = content.lines().collect();
        let line_idx = position.line as usize;
        let col_idx = position.character as usize;

        if line_idx >= lines.len() {
            return ("", "");
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
                    let full_value_end = line[value_start..]
                        .find("</")
                        .map_or(line.len(), |i| value_start + i);
                    let value = &line[value_start..full_value_end];
                    return (tag, value);
                }
            }
        }

        ("", "")
    }
}

#[async_trait]
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

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResultTrait>> {
        let result =
            crate::parser::parse_pom_xml(content, uri).map_err(deps_core::DepsError::from)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        None
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        loading_state: deps_core::LoadingState,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        lsp_helpers::generate_inlay_hints(
            parse_result,
            cached_versions,
            resolved_versions,
            loading_state,
            config,
            &self.formatter,
        )
    }

    async fn generate_hover(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
    ) -> Option<Hover> {
        lsp_helpers::generate_hover(
            parse_result,
            position,
            cached_versions,
            resolved_versions,
            self.registry.as_ref(),
            &self.formatter,
        )
        .await
    }

    async fn generate_code_actions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        _cached_versions: &HashMap<String, String>,
        uri: &Uri,
    ) -> Vec<CodeAction> {
        lsp_helpers::generate_code_actions(
            parse_result,
            position,
            uri,
            self.registry.as_ref(),
            &self.formatter,
        )
        .await
    }

    async fn generate_diagnostics(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        _uri: &Uri,
    ) -> Vec<Diagnostic> {
        lsp_helpers::generate_diagnostics_from_cache(
            parse_result,
            cached_versions,
            resolved_versions,
            &self.formatter,
        )
    }

    async fn generate_completions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        content: &str,
    ) -> Vec<CompletionItem> {
        let (ctx_type, value) = Self::detect_xml_context(content, position, parse_result);

        match ctx_type {
            "version" => {
                // Find package name from parse_result at this position
                let dep = parse_result.dependencies().into_iter().find(|d| {
                    d.version_range()
                        .is_some_and(|r| position_in_range(position, r))
                        || d.name_range().start.line == position.line
                });
                if let Some(dep) = dep {
                    self.complete_versions(dep.name(), value).await
                } else {
                    vec![]
                }
            }
            "artifactId" | "groupId" => self.complete_package_names(value).await,
            _ => vec![],
        }
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

    #[tokio::test]
    async fn test_complete_package_names_min_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = MavenEcosystem::new(cache);
        assert!(eco.complete_package_names("a").await.is_empty());
        assert!(eco.complete_package_names("").await.is_empty());
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

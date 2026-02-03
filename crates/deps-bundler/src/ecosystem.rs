//! Bundler ecosystem implementation for deps-lsp.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers,
};

use crate::formatter::BundlerFormatter;
use crate::registry::RubyGemsRegistry;

/// Bundler ecosystem implementation.
///
/// Provides LSP functionality for Gemfile files, including:
/// - Dependency parsing with position tracking
/// - Version information from rubygems.org
/// - Inlay hints for latest versions
/// - Hover tooltips with gem metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/yanked gems
pub struct BundlerEcosystem {
    registry: Arc<RubyGemsRegistry>,
    formatter: BundlerFormatter,
}

impl BundlerEcosystem {
    /// Creates a new Bundler ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(RubyGemsRegistry::new(cache)),
            formatter: BundlerFormatter,
        }
    }

    /// Completes gem names by searching rubygems.org.
    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        use deps_core::completion::build_package_completion;

        // Require at least 2 characters, max 100 for security
        if prefix.len() < 2 || prefix.len() > 100 {
            return vec![];
        }

        let results = match self.registry.search(prefix, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Gem search failed for '{}': {}", prefix, e);
                return vec![];
            }
        };

        let insert_range = tower_lsp_server::ls_types::Range::default();

        results
            .into_iter()
            .map(|metadata| {
                let boxed: Box<dyn deps_core::Metadata> = Box::new(metadata);
                build_package_completion(boxed.as_ref(), insert_range)
            })
            .collect()
    }

    async fn complete_versions(&self, package_name: &str, prefix: &str) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &['~', '>', '<', '=', '!'],
        )
        .await
    }
}

#[async_trait]
impl Ecosystem for BundlerEcosystem {
    fn id(&self) -> &'static str {
        "bundler"
    }

    fn display_name(&self) -> &'static str {
        "Bundler (Ruby)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Gemfile"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["Gemfile.lock"]
    }

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_gemfile(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::GemfileLockParser))
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
        use deps_core::completion::{CompletionContext, detect_completion_context};

        let context = detect_completion_context(parse_result, position, content);

        match context {
            CompletionContext::PackageName { prefix } => self.complete_package_names(&prefix).await,
            CompletionContext::Version {
                package_name,
                prefix,
            } => self.complete_versions(&package_name, &prefix).await,
            CompletionContext::Feature { .. } | CompletionContext::None => vec![],
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
        let ecosystem = BundlerEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "bundler");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "Bundler (Ruby)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["Gemfile"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["Gemfile.lock"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        let any = ecosystem.as_any();
        assert!(any.is::<BundlerEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem.complete_package_names("r").await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);

        // Prefix longer than 100 chars should return empty
        let long_prefix = "a".repeat(101);
        let results = ecosystem.complete_package_names(&long_prefix).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_lockfile_provider() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        assert!(ecosystem.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);

        let gemfile = r#"source 'https://rubygems.org'
gem 'rails', '~> 7.0'"#;

        #[cfg(windows)]
        let path = "C:/test/Gemfile";
        #[cfg(not(windows))]
        let path = "/test/Gemfile";
        let uri = Uri::from_file_path(path).unwrap();

        let result = ecosystem.parse_manifest(gemfile, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }
}

//! Composer ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for PHP/Composer projects,
//! providing LSP functionality for `composer.json` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::ComposerFormatter;
use crate::registry::PackagistRegistry;

/// Composer ecosystem implementation.
///
/// Provides LSP functionality for composer.json files, including:
/// - Dependency parsing with position tracking
/// - Version information from Packagist registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/abandoned packages
pub struct ComposerEcosystem {
    registry: Arc<PackagistRegistry>,
    formatter: ComposerFormatter,
}

impl ComposerEcosystem {
    /// Creates a new Composer ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PackagistRegistry::new(cache)),
            formatter: ComposerFormatter,
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
            &['^', '~', '=', '<', '>', '*'],
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for ComposerEcosystem {}

impl Ecosystem for ComposerEcosystem {
    fn id(&self) -> &'static str {
        "composer"
    }

    fn display_name(&self) -> &'static str {
        "Composer (PHP)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["composer.json"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["composer.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_composer_json(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::ComposerLockParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix } => {
                    self.complete_package_names(&prefix).await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => self.complete_versions(&package_name, &prefix).await,
                CompletionContext::Feature { .. } => vec![],
                CompletionContext::None => vec![],
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
    use deps_core::EcosystemConfig;
    use std::collections::HashMap;

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "composer");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["composer.json"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["composer.lock"]);
    }

    #[test]
    fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        assert!(ecosystem.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/composer.json").unwrap();

        let content = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert_eq!(parse_result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/composer.json").unwrap();

        let result = ecosystem.parse_manifest("{invalid json}", &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_complete_package_names_short_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);

        let results = ecosystem.complete_package_names("s").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/composer.json").unwrap();

        let content = r#"{"require": {}}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                &HashMap::new(),
                &HashMap::new(),
                deps_core::LoadingState::Loaded,
                &EcosystemConfig::default(),
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/composer.json").unwrap();

        let content = r#"{"name": "test/project"}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };

        let completions = ecosystem
            .generate_completions(parse_result.as_ref(), position, content)
            .await;
        assert!(completions.is_empty());
    }
}

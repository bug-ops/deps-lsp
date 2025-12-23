//! npm ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for npm/JavaScript projects,
//! providing LSP functionality for `package.json` files.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Url,
};

use deps_core::{
    Ecosystem, EcosystemConfig, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers,
};

use crate::formatter::NpmFormatter;
use crate::registry::NpmRegistry;

/// npm ecosystem implementation.
///
/// Provides LSP functionality for package.json files, including:
/// - Dependency parsing with position tracking
/// - Version information from npm registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/deprecated packages
pub struct NpmEcosystem {
    registry: Arc<NpmRegistry>,
    formatter: NpmFormatter,
}

impl NpmEcosystem {
    /// Creates a new npm ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(NpmRegistry::new(cache)),
            formatter: NpmFormatter,
        }
    }
}

#[async_trait]
impl Ecosystem for NpmEcosystem {
    fn id(&self) -> &'static str {
        "npm"
    }

    fn display_name(&self) -> &'static str {
        "npm (JavaScript)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["package.json"]
    }

    async fn parse_manifest(&self, content: &str, uri: &Url) -> Result<Box<dyn ParseResultTrait>> {
        let result = crate::parser::parse_package_json(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::NpmLockParser))
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        resolved_versions: &HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        lsp_helpers::generate_inlay_hints(
            parse_result,
            cached_versions,
            resolved_versions,
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
        uri: &Url,
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
        _cached_versions: &HashMap<String, String>,
        _uri: &Url,
    ) -> Vec<Diagnostic> {
        lsp_helpers::generate_diagnostics(parse_result, self.registry.as_ref(), &self.formatter)
            .await
    }

    async fn generate_completions(
        &self,
        _parse_result: &dyn ParseResultTrait,
        _position: Position,
        _content: &str,
    ) -> Vec<CompletionItem> {
        vec![]
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
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "npm");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "npm (JavaScript)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["package.json"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<NpmEcosystem>());
    }
}

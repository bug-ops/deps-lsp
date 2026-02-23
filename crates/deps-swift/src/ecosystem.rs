//! Swift ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::SwiftFormatter;
use crate::lockfile::SwiftLockParser;
use crate::registry::SwiftRegistry;

/// Swift/SPM ecosystem implementation.
///
/// Provides LSP functionality for Package.swift files, including:
/// - Dependency parsing with position tracking
/// - Version information from GitHub tags
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown packages
pub struct SwiftEcosystem {
    registry: Arc<SwiftRegistry>,
    formatter: SwiftFormatter,
    lockfile_provider: Arc<SwiftLockParser>,
}

impl SwiftEcosystem {
    /// Creates a new Swift ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(SwiftRegistry::new(cache)),
            formatter: SwiftFormatter,
            lockfile_provider: Arc::new(SwiftLockParser),
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
}

impl deps_core::ecosystem::private::Sealed for SwiftEcosystem {}

impl Ecosystem for SwiftEcosystem {
    fn id(&self) -> &'static str {
        "swift"
    }

    fn display_name(&self) -> &'static str {
        "Swift (SPM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Package.swift"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["Package.resolved"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_package_swift(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(self.lockfile_provider.clone() as Arc<dyn deps_core::lockfile::LockFileProvider>)
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
                    // Strip "https://github.com/" prefix for search query
                    let query = prefix
                        .strip_prefix("https://github.com/")
                        .or_else(|| prefix.strip_prefix("https://github.com"))
                        .unwrap_or(&prefix);
                    if query.len() < 2 {
                        return vec![];
                    }
                    self.complete_package_names(query).await
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

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.id(), "swift");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.display_name(), "Swift (SPM)");
    }

    #[test]
    fn test_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &["Package.swift"]);
        assert_eq!(eco.lockfile_filenames(), &["Package.resolved"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert!(eco.as_any().is::<SwiftEcosystem>());
    }

    #[test]
    fn test_lockfile_provider_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/Package.swift").unwrap();
        let content = r#".package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0")"#;
        let result = eco.parse_manifest(content, &uri).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let uri = Uri::from_file_path("/test/Package.swift").unwrap();
        let result = eco.parse_manifest("// empty file", &uri).await;
        assert!(result.is_ok());
        assert!(result.unwrap().dependencies().is_empty());
    }
}

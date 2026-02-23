//! Dart ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::DartFormatter;
use crate::registry::PubDevRegistry;

pub struct DartEcosystem {
    registry: Arc<PubDevRegistry>,
    formatter: DartFormatter,
}

impl DartEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PubDevRegistry::new(cache)),
            formatter: DartFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str) -> Vec<CompletionItem> {
        use deps_core::completion::build_package_completion;

        if prefix.len() < 2 || prefix.len() > 100 {
            return vec![];
        }

        let results = match self.registry.search(prefix, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Pub.dev search failed for '{}': {}", prefix, e);
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
            &['^', '>', '<', '='],
        )
        .await
    }
}

impl Ecosystem for DartEcosystem {
    fn id(&self) -> &'static str {
        "dart"
    }

    fn display_name(&self) -> &'static str {
        "Dart (Pub)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["pubspec.yaml"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["pubspec.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_pubspec_yaml(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::PubspecLockParser))
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
                CompletionContext::Feature { .. } | CompletionContext::None => vec![],
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
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.id(), "dart");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.display_name(), "Dart (Pub)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &["pubspec.yaml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.lockfile_filenames(), &["pubspec.lock"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(eco.as_any().is::<DartEcosystem>());
    }

    #[tokio::test]
    async fn test_complete_package_names_min_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(eco.complete_package_names("h").await.is_empty());
        assert!(eco.complete_package_names("").await.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let long = "a".repeat(101);
        assert!(eco.complete_package_names(&long).await.is_empty());
    }

    #[tokio::test]
    async fn test_lockfile_provider() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);

        let yaml = "name: app\ndependencies:\n  http: ^1.0.0\n";
        #[cfg(windows)]
        let path = "C:/test/pubspec.yaml";
        #[cfg(not(windows))]
        let path = "/test/pubspec.yaml";
        let uri = Uri::from_file_path(path).unwrap();

        let result = eco.parse_manifest(yaml, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }
}

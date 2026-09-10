//! Bundler ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
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

    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
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
            &['~', '>', '<', '=', '!'],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for BundlerEcosystem {}

impl Ecosystem for BundlerEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Bundler
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

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_gemfile(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::GemfileLockParser))
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
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix, range } => {
                    self.complete_package_names(&prefix, range).await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => {
                    self.complete_versions(&package_name, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature { .. } | CompletionContext::None | _ => vec![],
            }
            .into()
        })
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("gem \"{name}\", \"~> {latest}\""))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_ecosystem_manifest_filenames/
    // test_ecosystem_lockfile_filenames/test_as_any family.
    deps_core::ecosystem_conformance! {
        mod bundler_ecosystem_conformance;
        build: BundlerEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: BundlerEcosystem;
        id: "bundler";
        display_name: "Bundler (Ruby)";
        manifest_filenames: &["Gemfile"];
        lockfile_filenames: &["Gemfile.lock"];
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_minimum_prefix/test_complete_package_names_max_length.
    deps_core::completion_guard_conformance! {
        mod bundler_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<tower_lsp_server::ls_types::CompletionItem>> + Send + '_>,
        > {
            Box::pin(async move {
                deps_core::completion::complete_package_names_generic(
                    registry,
                    &prefix,
                    20,
                    Range::default(),
                )
                .await
            })
        };
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        let content = "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'";
        let uri = deps_core::test_util::test_uri("/test/Gemfile");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(1, 7); // cursor after "ra" in "rails"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "ra");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(1, 5), Position::new(1, 10)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
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

        let gemfile = r"source 'https://rubygems.org'
gem 'rails', '~> 7.0'";

        #[cfg(windows)]
        let path = "C:/test/Gemfile";
        #[cfg(not(windows))]
        let path = "/test/Gemfile";
        let uri = Uri::from_file_path(path).unwrap();

        let result = ecosystem.parse_manifest(gemfile, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    /// A Gemfile has no delimited dependencies section — `gem "name"` calls are valid
    /// anywhere — so there is no raw-text boundary to detect: no override.
    #[test]
    fn test_fallback_completion_prefix_default_none() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
        assert!(
            ecosystem
                .fallback_completion_prefix("anything at all\n", Position::new(0, 0))
                .is_none()
        );
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = BundlerEcosystem::new(cache);
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
        let meta = MockMetadata {
            name: deps_core::PackageName::new("rails"),
            latest_version: "7.1.3".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("gem \"rails\", \"~> 7.1.3\"".to_string())
        );
    }
}

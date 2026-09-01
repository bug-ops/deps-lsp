//! Deno ecosystem implementation for deps-lsp (D1).
//!
//! Provides LSP functionality for `deno.json`/`deno.jsonc` files: dependency parsing with
//! position tracking, `jsr:`/`npm:` version lookups via [`crate::registry::DenoRegistry`],
//! inlay hints, hover, code actions, and diagnostics — all via `deps-core`'s generic
//! handlers, with no Deno-specific handler code (FR-010).

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::DenoFormatter;
use crate::registry::DenoRegistry;
use deps_npm::NpmRegistry;

/// Deno ecosystem implementation.
///
/// Provides LSP functionality for `deno.json`/`deno.jsonc` files, including:
/// - Dependency parsing with position tracking (`imports` map only, D8)
/// - Version information from the JSR and npm registries, dispatched by
///   [`DenoRegistry`] (D3)
/// - Inlay hints, hover, code actions, and diagnostics via the shared `deps-core`
///   handlers
///
/// No lock file support in the MVP (D9): `deno.lock` resolved-version parsing is a
/// follow-up increment.
pub struct DenoEcosystem {
    registry: Arc<DenoRegistry>,
    formatter: DenoFormatter,
}

impl DenoEcosystem {
    /// Creates a new Deno ecosystem with the given HTTP cache.
    ///
    /// The same cache backs both halves of the registry facade (M1), deduping plain
    /// cached GETs between `package.json` and `deno.json` for the same npm package. This
    /// does not extend to npm's separate freshness-path packument fetch, which bypasses
    /// `HttpCache` and is memoized per `NpmRegistry` instance — see
    /// [`DenoRegistry::new`](crate::registry::DenoRegistry::new)'s docs for the full
    /// caveat (N4). Use [`Self::with_npm`] to avoid it.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(DenoRegistry::new(cache)),
            formatter: DenoFormatter,
        }
    }

    /// Creates a new Deno ecosystem sharing an existing [`NpmRegistry`] instance for its
    /// `npm:`-scheme half, instead of building a private one (N4/#312).
    ///
    /// `deps-lsp`'s ecosystem registration uses this when both the `npm` and `deno`
    /// features are enabled, so a package appearing in both `package.json` and
    /// `deno.json` shares one freshness-path publish-time cache. See
    /// [`DenoRegistry::with_npm`](crate::registry::DenoRegistry::with_npm) for what this
    /// dedupes.
    #[must_use]
    pub fn with_npm(cache: Arc<deps_core::HttpCache>, npm: NpmRegistry) -> Self {
        Self {
            registry: Arc::new(DenoRegistry::with_npm(cache, npm)),
            formatter: DenoFormatter,
        }
    }

    /// Completes package names by searching whichever registry the typed scheme prefix
    /// (`jsr:`/`npm:`) selects.
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
            &['^', '~', '=', '<', '>', '*'],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for DenoEcosystem {}

impl Ecosystem for DenoEcosystem {
    fn id(&self) -> &'static str {
        "deno"
    }

    fn display_name(&self) -> &'static str {
        "Deno (JSR/npm)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["deno.json", "deno.jsonc"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_deno_json(content, uri)?;
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
                CompletionContext::Feature { .. } => vec![],
                CompletionContext::None => vec![],
            }
            .into()
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
        let ecosystem = DenoEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "deno");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "Deno (JSR/npm)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["deno.json", "deno.jsonc"]);
    }

    #[test]
    fn test_ecosystem_no_lockfile_support() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        assert!(ecosystem.lockfile_filenames().is_empty());
        assert!(ecosystem.lockfile_provider().is_none());
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        assert!(ecosystem.as_any().is::<DenoEcosystem>());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/deno.json");

        let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0"}}"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/deno.json");

        let result = ecosystem.parse_manifest("{ not valid !!", &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_registry_returns_arc() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let registry = ecosystem.registry();
        assert!(Arc::strong_count(&registry) >= 1);
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/deno.json");

        let content = r#"{"name": "test"}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(0, 0);

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(completions.items.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);

        let results = ecosystem
            .complete_package_names("j", Range::default())
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &deps_core::PackageName::new("jsr:@this-scope/does-not-exist-12345"),
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }
}

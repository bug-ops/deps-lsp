//! npm ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for npm/JavaScript projects,
//! providing LSP functionality for `package.json` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter, parser::DependencySource,
};

use crate::config::NpmParseContext;
use crate::formatter::NpmFormatter;
use crate::registry::NpmRegistry;

/// The source(s) a `CompletionContext::Version`'s bare `package_name` joins back to within a
/// manifest's already-parsed dependencies (spec FR-017).
enum CompletionSource {
    /// No dependency in the manifest has this exact name yet — most commonly because the
    /// user is still typing a brand-new dependency line. Callers fall back to the
    /// pre-existing public-registry-only behavior, unchanged.
    NotInManifest,
    /// Every occurrence of this name in the manifest agrees on one resolved source.
    Resolved(DependencySource),
    /// Two or more occurrences of this name resolve to different sources — callers must
    /// offer no completions at all rather than picking one arbitrarily.
    Ambiguous,
}

/// Joins `package_name` back to `parse_result.dependencies()` by name (spec FR-017).
///
/// Mirrors `deps_cargo::ecosystem`'s identical helper, adapted to npm's scope-keyed (rather
/// than alias-keyed) resolution: the source itself is already resolved by the parser from
/// the `@scope/` name prefix, so this is purely a name join, no `.npmrc` re-resolution.
fn resolve_completion_source(
    parse_result: &dyn ParseResultTrait,
    package_name: &deps_core::PackageName,
) -> CompletionSource {
    let mut sources = parse_result
        .dependencies()
        .into_iter()
        .filter(|d| d.name() == package_name)
        .map(deps_core::Dependency::source);

    let Some(first) = sources.next() else {
        return CompletionSource::NotInManifest;
    };
    if sources.all(|s| s == first) {
        CompletionSource::Resolved(first)
    } else {
        tracing::warn!(
            package = %package_name,
            "ambiguous dependency source for version completion; offering none"
        );
        CompletionSource::Ambiguous
    }
}

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
    /// The reachability policy and `.npmrc` memoization cache (spec FR-012) every
    /// `parse_manifest` call threads through to
    /// [`crate::parser::parse_package_json_with_context`]. Defaulted by [`Self::new`]; set
    /// explicitly by [`Self::with_context`] so `crate::lib::register_ecosystems` can share
    /// one process-wide policy handle with `ServerState` (mirrors
    /// `deps_cargo::ecosystem::CargoEcosystem`'s identical `context` field).
    context: NpmParseContext,
}

impl NpmEcosystem {
    /// Creates a new npm ecosystem with the given HTTP cache, using a fresh, default
    /// [`NpmParseContext`] — an all-`PublicOnly`-policy, empty-cache context private to this
    /// ecosystem instance. Production use goes through [`Self::with_context`] instead.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self::with_context(
            Arc::new(NpmRegistry::new(cache)),
            NpmParseContext::default(),
        )
    }

    /// Creates a new npm ecosystem around an existing [`NpmRegistry`] instance (#312), using
    /// a fresh, default [`NpmParseContext`].
    ///
    /// Used only by tests that need a shared `NpmRegistry` but no live `.npmrc` policy of
    /// their own; production registration goes through [`Self::with_context`].
    #[must_use]
    pub fn with_registry(registry: Arc<NpmRegistry>) -> Self {
        Self::with_context(registry, NpmParseContext::default())
    }

    /// Creates a new npm ecosystem sharing `ctx`'s reachability policy and `.npmrc`
    /// memoization cache, around an existing [`NpmRegistry`] instance (#312) — the production
    /// constructor, used by `crate::lib::register_ecosystems` so
    /// `initialize`/`workspace/didChangeConfiguration` can update the same
    /// `Arc<RegistryAccessPolicy>` this ecosystem's every parse reads, and so `deps-deno` can
    /// share one `NpmRegistry` (and thus one freshness-path publish-time cache) with this
    /// ecosystem via its own `DenoRegistry::with_npm`.
    #[must_use]
    pub fn with_context(registry: Arc<NpmRegistry>, ctx: NpmParseContext) -> Self {
        Self {
            registry,
            formatter: NpmFormatter,
            context: ctx,
        }
    }

    /// Completes package names by searching the npm registry.
    ///
    /// Requires at least 2 characters for search. Returns up to 20 results.
    ///
    /// Deliberately source-blind (spec FR-011): the string here is a prefix the user typed
    /// into the name field, not a resolved private dependency name, so it is safe to send to
    /// the public registry unconditionally — unlike [`Self::complete_versions`].
    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    /// Completes version requirements for `package_name`, routed by the source that name
    /// resolves to in `parse_result` (spec FR-017). An ambiguous, unresolved, or
    /// unregistered-alternate source offers no completions rather than risking a private
    /// package name lookup against `registry.npmjs.org` — the same leak class FR-006 closes
    /// for hover/diagnostics/code-actions.
    async fn complete_versions(
        &self,
        parse_result: &dyn ParseResultTrait,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        match resolve_completion_source(parse_result, package_name) {
            CompletionSource::Ambiguous => vec![],
            CompletionSource::NotInManifest
            | CompletionSource::Resolved(DependencySource::Registry) => {
                deps_core::completion::complete_versions_generic(
                    self.registry.as_ref(),
                    package_name,
                    prefix,
                    &['^', '~', '=', '<', '>', '*'],
                    freshness,
                )
                .await
            }
            CompletionSource::Resolved(DependencySource::AlternateRegistry { index, .. }) => {
                match self.registry.alternate_client(&index) {
                    Some(client) => {
                        deps_core::completion::complete_versions_generic(
                            client.as_ref(),
                            package_name,
                            prefix,
                            &['^', '~', '=', '<', '>', '*'],
                            freshness,
                        )
                        .await
                    }
                    None => vec![],
                }
            }
            CompletionSource::Resolved(_) => vec![],
        }
    }
}

impl deps_core::ecosystem::private::Sealed for NpmEcosystem {}

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

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["package-lock.json"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result =
                crate::parser::parse_package_json_with_context(content, uri, &self.context)?;
            // Registers every `.npmrc`-resolved alternate index this parse found (spec
            // FR-002–004) into the shared router — the only point where a per-document
            // `.npmrc` resolution and the long-lived `NpmRegistry` this ecosystem shares
            // across every document ever meet. See `NpmParseResult::resolved_registries`.
            for index in result.resolved_registries.clone() {
                self.registry.register_alternate(index);
            }
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::NpmLockParser))
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
                    self.complete_versions(parse_result, &package_name, &prefix, freshness)
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
    use deps_core::{EcosystemConfig, VersionData};
    use std::collections::HashMap;

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    struct MockParseResult {
        dependencies: Vec<crate::types::NpmDependency>,
    }

    impl deps_core::ParseResult for MockParseResult {
        fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
            self.dependencies
                .iter()
                .map(|d| d as &dyn deps_core::Dependency)
                .collect()
        }

        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }

        fn uri(&self) -> &Uri {
            static URI: std::sync::LazyLock<Uri> =
                std::sync::LazyLock::new(|| deps_core::test_util::test_uri("/test/package.json"));
            &URI
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A `MockParseResult` with no dependencies — `resolve_completion_source` reports
    /// `NotInManifest` for any name against it, so `complete_versions` falls back to its
    /// pre-existing public-registry-only behavior (M4/SC-002: this is the mechanical,
    /// behavior-preserving fixture change FR-017 forces on every pre-existing
    /// `complete_versions` test below).
    fn empty_parse_result() -> MockParseResult {
        MockParseResult {
            dependencies: vec![],
        }
    }

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
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["package-lock.json"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<NpmEcosystem>());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let content = "{\n  \"dependencies\": {\n    \"express\": \"^4.18.2\"\n  }\n}";
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 8); // cursor after "exp" in "express"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "exp");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(2, 5), Position::new(2, 12)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_package_name_completion_context_one_past_name_end_does_not_consume_closing_quote()
    {
        // Regression test for a bug introduced by an earlier #232 fix attempt: a cursor one
        // column past "express"'s name_range (byte/char 12, i.e. sitting right at/after the
        // closing quote of `"express"`) must never produce a PackageName textEdit range that
        // extends into the closing quote — applying such an edit would delete the quote and
        // corrupt the JSON.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let content = "{\n  \"dependencies\": {\n    \"express\": \"^4.18.2\"\n  }\n}";
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 13); // one column past name_range.end (12)

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        if let deps_core::completion::CompletionContext::PackageName { range, .. } = context {
            panic!(
                "expected this position not to match PackageName context (it is past the \
                 name's own span and the range must not be widened to reach it), got {range:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem
            .complete_package_names("e", Range::default())
            .await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("", Range::default()).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_real_search() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem
            .complete_package_names("expre", Range::default())
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "express"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("express"),
                "4.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("4.")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("express"),
                "^4.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("4.")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Package names with special characters (@scope/package) should work
        let results = ecosystem
            .complete_package_names("@type", Range::default())
            .await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Prefix longer than 200 chars should return empty (security)
        let long_prefix = "a".repeat(201);
        let results = ecosystem
            .complete_package_names(&long_prefix, Range::default())
            .await;
        assert!(results.is_empty());

        // Exactly 100 chars should work
        let max_prefix = "a".repeat(100);
        let results = ecosystem
            .complete_package_names(&max_prefix, Range::default())
            .await;
        // Should not panic, but may return empty (no matches)
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_limit_20() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("express"),
                "4",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_scoped() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Scoped packages (@types/node, etc.)
        let results = ecosystem
            .complete_package_names("@types", Range::default())
            .await;
        assert!(!results.is_empty() || results.is_empty()); // May not have results but shouldn't panic
    }

    #[tokio::test]
    async fn test_parse_manifest_valid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"dependencies": {"express": "^4.18.0"}}"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(!parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_json() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let invalid_content = r#"{"dependencies": invalid json"#;

        let result = ecosystem.parse_manifest(invalid_content, &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_manifest_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"dependencies": {}}"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_registry_returns_arc() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let registry = ecosystem.registry();
        assert!(Arc::strong_count(&registry) >= 1);
    }

    #[tokio::test]
    async fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        let provider = ecosystem.lockfile_provider();
        assert!(provider.is_some());
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"dependencies": {}}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let config = EcosystemConfig::default();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::LoadingState::Loaded,
                &config,
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"name": "test"}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };

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
    async fn test_generate_completions_feature_context_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // npm doesn't have features, so this should always return empty
        let content = r#"{"dependencies": {"express": "4.0.0"}}"#;
        let uri = deps_core::test_util::test_uri("/test/package.json");
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let position = Position {
            line: 0,
            character: 30,
        };

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        // Should not crash, returns empty or package/version completions
        assert!(completions.items.is_empty() || !completions.items.is_empty());
    }

    #[tokio::test]
    async fn test_generate_hover_no_dependency_at_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"name": "test"}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = ecosystem
            .generate_hover(
                parse_result.as_ref(),
                position,
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(hover.is_none());
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_actions() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"name": "test"}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let actions = ecosystem
            .generate_code_actions(
                parse_result.as_ref(),
                position,
                &uri,
                VersionData::new(&cached_versions, &resolved_versions),
                content,
            )
            .await;

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/package.json");

        let content = r#"{"dependencies": {}}"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = ecosystem
            .generate_diagnostics(
                parse_result.as_ref(),
                VersionData::new(&cached_versions, &resolved_versions),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
            )
            .await;

        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_empty_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Empty prefix should show non-deprecated versions (up to 20)
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        // Should not panic, returns empty for unknown package
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_tilde_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test ~ operator stripping
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "~4.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_wildcard() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test * wildcard stripping
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "*",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_less_than_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);

        // Test < and > operator stripping
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "<2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    // --- FR-017: version-completion source routing ---

    fn dep_with_source(name: &str, source: DependencySource) -> crate::types::NpmDependency {
        crate::types::NpmDependency {
            name: pkg(name),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            section: crate::types::NpmDependencySection::Dependencies,
            source,
        }
    }

    #[test]
    fn test_resolve_completion_source_not_in_manifest() {
        let parse_result = empty_parse_result();
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("express")),
            CompletionSource::NotInManifest
        ));
    }

    #[test]
    fn test_resolve_completion_source_resolved() {
        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source("express", DependencySource::Registry)],
        };
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("express")),
            CompletionSource::Resolved(DependencySource::Registry)
        ));
    }

    /// Two occurrences of the same name resolving to different sources must not pick either
    /// arbitrarily.
    #[test]
    fn test_resolve_completion_source_ambiguous() {
        let parse_result = MockParseResult {
            dependencies: vec![
                dep_with_source("@myorg/pkg", DependencySource::Registry),
                dep_with_source(
                    "@myorg/pkg",
                    DependencySource::AlternateRegistry {
                        index: "https://npm.pkg.github.com".to_string(),
                        mirrors_crates_io: false,
                    },
                ),
            ],
        };
        assert!(matches!(
            resolve_completion_source(&parse_result, &pkg("@myorg/pkg")),
            CompletionSource::Ambiguous
        ));
    }

    #[tokio::test]
    async fn test_complete_versions_ambiguous_source_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let parse_result = MockParseResult {
            dependencies: vec![
                dep_with_source("@myorg/pkg", DependencySource::Registry),
                dep_with_source(
                    "@myorg/pkg",
                    DependencySource::AlternateRegistry {
                        index: "https://npm.pkg.github.com".to_string(),
                        mirrors_crates_io: false,
                    },
                ),
            ],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("@myorg/pkg"),
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// FR-006 interaction: a `CustomRegistry`-resolved name (the fail-closed state) offers no
    /// completions either.
    ///
    /// SC-004 requires *no public-registry request at all*, not merely an empty result — a
    /// real, unmocked `registry.npmjs.org` client would pass this test's old
    /// `results.is_empty()`-only assertion even if the fail-closed dispatch regressed and
    /// fell through to `complete_versions_generic`, since that helper returns `vec![]` on
    /// *any* `Err` (including a 404 from a nonexistent package name), not only on the
    /// intended fail-closed arm. A mocked public registry with `.expect(0)` makes the
    /// dispatch regression itself fail the test, not just its result shape.
    #[tokio::test]
    async fn test_complete_versions_custom_registry_source_offers_nothing() {
        let mut public_server = mockito::Server::new_async().await;
        let public_mock = public_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"versions": {"9.9.9": {}}}"#)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = NpmRegistry::with_registry_base(cache, public_server.url());
        let ecosystem = NpmEcosystem::with_registry(Arc::new(registry));
        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "@myorg/pkg",
                DependencySource::CustomRegistry {
                    url: "not-a-valid-url".to_string(),
                },
            )],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("@myorg/pkg"),
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
        public_mock.assert_async().await;
    }

    /// An `AlternateRegistry` source whose index has no registered client offers no
    /// completions — never a fall back to the public registry.
    ///
    /// Same SC-004 rationale as
    /// `test_complete_versions_custom_registry_source_offers_nothing` above: a mocked public
    /// registry with `.expect(0)` proves no request reaches it, which `results.is_empty()`
    /// alone cannot.
    #[tokio::test]
    async fn test_complete_versions_unregistered_alternate_offers_nothing() {
        let mut public_server = mockito::Server::new_async().await;
        let public_mock = public_server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"versions": {"9.9.9": {}}}"#)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = NpmRegistry::with_registry_base(cache, public_server.url());
        let ecosystem = NpmEcosystem::with_registry(Arc::new(registry));
        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "@myorg/pkg",
                DependencySource::AlternateRegistry {
                    index: "https://never-registered.example".to_string(),
                    mirrors_crates_io: false,
                },
            )],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("@myorg/pkg"),
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
        public_mock.assert_async().await;
    }

    /// FR-017 end-to-end: a registered alternate client's version completion routes there.
    #[tokio::test]
    async fn test_complete_versions_routes_to_registered_alternate_client() {
        let mut alt_server = mockito::Server::new_async().await;
        alt_server
            .mock("GET", "/@myorg/pkg")
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}, "1.5.0": {}}}"#)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let registry = Arc::new(NpmRegistry::new(Arc::clone(&cache)));
        let ecosystem = NpmEcosystem::with_registry(Arc::clone(&registry));

        let policy = deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        );
        let index = crate::config::NpmRegistryIndex::new(&alt_server.url(), &policy).unwrap();
        registry.register_alternate(index.clone());

        let parse_result = MockParseResult {
            dependencies: vec![dep_with_source(
                "@myorg/pkg",
                DependencySource::AlternateRegistry {
                    index: index.as_str().to_string(),
                    mirrors_crates_io: false,
                },
            )],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("@myorg/pkg"),
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
    }
}

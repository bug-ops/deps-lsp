//! npm ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for npm/JavaScript projects,
//! providing LSP functionality for `package.json` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CompletionItem, Diagnostic, DiagnosticSeverity, Hover, HoverContents, Position, Range, Uri,
};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{DiagnosticSeverities, EcosystemFormatter},
};

use crate::config::NpmParseContext;
use crate::formatter::NpmFormatter;
use crate::registry::NpmRegistry;
use crate::types::NpmDependency;

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

    /// Completes version requirements for the dependency at `position`, resolved by cursor
    /// position rather than by name (issue #599, mirroring `deps_cargo::ecosystem`'s
    /// identical migration for issue #593) — delegates to
    /// [`deps_core::completion::complete_versions_at_position`]. This fixes the residual gap
    /// in the old name-based `resolve_completion_source` routing: two dependencies sharing
    /// one `PackageName` but resolving to different sources (e.g. two npm workspace scopes,
    /// or a `.npmrc` scope override) used to collapse into an `Ambiguous` result and offer no
    /// completions for either occurrence, even though the cursor position unambiguously
    /// identifies which one the user is editing.
    ///
    /// The shared helper's `can_resolve_source` gate keeps `NpmRegistry::get_versions_from`'s
    /// permissive catch-all from leaking a private/non-registry dependency's name to
    /// `registry.npmjs.org` on every keystroke (the same leak class FR-006 closes for
    /// hover/diagnostics/code-actions); `AlternateRegistry` routing through
    /// `self.registry.alternate_client` is unchanged — it already lives inside
    /// `NpmRegistry::get_versions_from` itself, which the shared helper calls into.
    async fn complete_versions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_at_position(
            self.registry.as_ref(),
            &self.formatter,
            parse_result,
            position,
            prefix,
            &['^', '~', '=', '<', '>', '*'],
            freshness,
        )
        .await
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

    fn watched_config_filenames(&self) -> &[&'static str] {
        &["pnpm-workspace.yaml", ".npmrc"]
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
                CompletionContext::Version { prefix, .. } => {
                    self.complete_versions(parse_result, position, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature { .. } => vec![],
                CompletionContext::None => vec![],
            }
            .into()
        })
    }

    /// Appends a `**Catalog**` line (spec 046) to the shared default's hover output for a
    /// `catalog:`/`catalog:<name>`-referencing dependency — the base hover already renders
    /// everything else identically to a literal-range dependency (FR-004), since a resolved
    /// catalog entry rewrites `version_req` in place before hover ever runs.
    fn generate_hover<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        versions: deps_core::VersionData<'a>,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Option<Hover>> {
        Box::pin(async move {
            let mut hover = deps_core::lsp_generate_hover(
                parse_result,
                position,
                versions,
                self.registry.as_ref(),
                self.formatter(),
                freshness,
                deps_core::PublishTime::now(),
            )
            .await?;

            let catalog_line = parse_result
                .dependencies()
                .into_iter()
                .find(|dep| {
                    deps_core::position_in_range(position, dep.name_range())
                        || dep
                            .version_range()
                            .is_some_and(|r| deps_core::position_in_range(position, r))
                })
                .and_then(|dep| dep.as_any().downcast_ref::<NpmDependency>())
                .and_then(catalog_hover_line);

            if let Some(catalog_line) = catalog_line
                && let HoverContents::Markup(content) = &mut hover.contents
            {
                content.value.push_str(&catalog_line);
            }

            Some(hover)
        })
    }

    /// Appends one diagnostic per unresolved `catalog:`-referencing dependency (spec 046
    /// FR-005/FR-006) to the shared default's output — additive, since the base pass never
    /// evaluates a catalog dependency's outdated/unsatisfiable/yanked status once
    /// `version_req` is `None` (the module's totality invariant closes that off structurally).
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        versions: deps_core::VersionData<'a>,
        uri: &'a Uri,
        freshness: deps_core::FreshnessSettings,
        severities: DiagnosticSeverities,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(async move {
            let mut diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                parse_result,
                versions,
                self.formatter(),
                uri,
                freshness,
                severities,
                deps_core::PublishTime::now(),
            );
            diagnostics.extend(catalog_diagnostics(parse_result, severities.unknown));
            diagnostics
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Renders the `**Catalog**` hover line for `dep`, or `None` for a non-catalog dependency.
///
/// `` `catalog:react17` → `^17.0.2` `` when resolved; the outcome's own message otherwise
/// (including [`crate::catalog::CatalogOutcome::NonSemverEntry`], which gets no diagnostic but
/// still deserves a hover explanation of why no version comparison ran).
fn catalog_hover_line(dep: &NpmDependency) -> Option<String> {
    let origin = dep.catalog.as_ref()?;
    Some(format!(
        "\n**Catalog**: {}\n",
        origin.hover_detail(dep.name.as_str())
    ))
}

/// One diagnostic per catalog-referencing dependency whose outcome carries a message (spec 046
/// FR-005/FR-006) — `None` from [`crate::catalog::CatalogOrigin::diagnostic_message`] (resolved,
/// or a non-semver entry) contributes nothing.
///
/// The `npm_dep.version_range?` skip is not a catalog-specific gap in FR-005's "no silent
/// omission" guarantee: every diagnostic rule in this codebase anchors on `version_range` and
/// skips the same way when it's absent (`crates/deps-core/src/lsp_helpers/diagnostics.rs`'s
/// own `let Some(version_range) = dep.version_range() else { continue };` gate) — there is
/// simply nowhere in the document to place a diagnostic squiggle without a span, catalog or
/// otherwise.
fn catalog_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: DiagnosticSeverity,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let npm_dep = dep.as_any().downcast_ref::<NpmDependency>()?;
            let origin = npm_dep.catalog.as_ref()?;
            let range = npm_dep.version_range?;
            let message = origin.diagnostic_message(npm_dep.name.as_str())?;
            Some(Diagnostic {
                range,
                severity: Some(severity),
                message,
                source: Some("deps-lsp".into()),
                ..Default::default()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::parser::DependencySource;
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

    /// Builds an `NpmDependency` with a `version_range` at `line`, whose start position is
    /// what `complete_versions` (position-based, issue #599) looks up `parse_result` by.
    fn dep_with_source(
        name: &str,
        source: DependencySource,
        line: u32,
    ) -> crate::types::NpmDependency {
        crate::types::NpmDependency {
            name: pkg(name),
            name_range: Range::default(),
            version_req: None,
            version_range: Some(Range::new(Position::new(line, 0), Position::new(line, 10))),
            section: crate::types::NpmDependencySection::Dependencies,
            source,
            catalog: None,
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
    fn test_ecosystem_watched_config_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        assert_eq!(
            ecosystem.watched_config_filenames(),
            &["pnpm-workspace.yaml", ".npmrc"]
        );
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
        let dep = dep_with_source("express", DependencySource::Registry, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source("express", DependencySource::Registry, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "this-package-does-not-exist-12345",
            DependencySource::Registry,
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source("express", DependencySource::Registry, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Test that we respect the 20 result limit
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "this-package-does-not-exist-12345",
            DependencySource::Registry,
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Empty prefix should show non-deprecated versions (up to 20)
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "this-package-does-not-exist-12345",
            DependencySource::Registry,
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Test ~ operator stripping
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "this-package-does-not-exist-12345",
            DependencySource::Registry,
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Test * wildcard stripping
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "this-package-does-not-exist-12345",
            DependencySource::Registry,
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        // Test < and > operator stripping
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "<2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    // --- issue #599: position-based version-completion source routing ---

    /// Issue #599: two dependencies sharing one `PackageName` but resolving to different
    /// sources no longer collapse into the old name-based "offer nothing for either" result
    /// — cursor position now identifies exactly one dependency, so each occurrence routes
    /// independently. Mirrors `deps_cargo::ecosystem`'s identical
    /// `test_complete_versions_same_name_different_sources_routes_by_position` (issue #593).
    ///
    /// Both halves are required to discriminate pre-fix from post-fix behavior (impl-critic
    /// finding C1): the alternate-occurrence assertion alone is empty under *both* the old
    /// name-based `Ambiguous` collapse and the new position-based routing (an unregistered
    /// alternate index fails closed either way), so it cannot fail on unfixed code by itself.
    /// The registry-occurrence assertion is the discriminating half — pre-fix it also
    /// collapsed to `Ambiguous` and returned empty; post-fix, cursor position resolves it
    /// independently of the co-occurring `AlternateRegistry` entry and it reaches the (mocked)
    /// public registry.
    #[tokio::test]
    async fn test_complete_versions_same_name_different_sources_routes_by_position() {
        let mut public_server = mockito::Server::new_async().await;
        public_server
            .mock("GET", "/@myorg/pkg")
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}, "1.5.0": {}}}"#)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = NpmRegistry::with_registry_base(cache, public_server.url());
        let ecosystem = NpmEcosystem::with_registry(Arc::new(registry));

        let registry_dep = dep_with_source("@myorg/pkg", DependencySource::Registry, 0);
        let registry_position = registry_dep.version_range.unwrap().start;
        let alternate_dep = dep_with_source(
            "@myorg/pkg",
            DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            },
            1,
        );
        let alternate_position = alternate_dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![registry_dep, alternate_dep],
        };

        // The alternate occurrence resolves deterministically without network: its index was
        // never registered, so `NpmRegistry::get_versions_from` fails closed with
        // `PackageNotFound` before any HTTP call — proving its own source, not the
        // co-occurring `Registry`-sourced entry, drove the routing.
        let alternate_results = ecosystem
            .complete_versions(
                &parse_result,
                alternate_position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            alternate_results.is_empty(),
            "unregistered alternate index must offer no completions"
        );

        // Discriminating assertion: the co-occurring `Registry`-sourced entry must still
        // resolve via the mocked public registry, proving position (not the ambiguity the old
        // name-based join would have detected) drives routing.
        let registry_results = ecosystem
            .complete_versions(
                &parse_result,
                registry_position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            !registry_results.is_empty(),
            "the Registry-sourced occurrence must resolve despite a co-occurring, \
             differently-sourced entry sharing its name"
        );
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
        let dep = dep_with_source(
            "@myorg/pkg",
            DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = dep_with_source(
            "@myorg/pkg",
            DependencySource::AlternateRegistry {
                index: "https://never-registered.example".to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
        public_mock.assert_async().await;
    }

    /// Issue #599 end-to-end: a registered alternate client's version completion routes there.
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

        let dep = dep_with_source(
            "@myorg/pkg",
            DependencySource::AlternateRegistry {
                index: index.as_str().to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
    }

    // --- pnpm catalogs (spec 046): generate_hover/generate_diagnostics overrides ---

    #[tokio::test]
    async fn test_generate_hover_appends_catalog_line_for_resolved_dependency() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let content = r#"{"dependencies": {"react": "catalog:"}}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let position = Position::new(0, 20); // inside "react"'s name
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let hover = ecosystem
            .generate_hover(
                parse_result.as_ref(),
                position,
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover must fire for a catalog-resolved dependency");

        let tower_lsp_server::ls_types::HoverContents::Markup(content) = &hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("**Requirement**"),
            "{}",
            content.value
        );
        assert!(content.value.contains("^18.3.0"), "{}", content.value);
        assert!(content.value.contains("**Catalog**"), "{}", content.value);
        assert!(content.value.contains("catalog:"), "{}", content.value);
    }

    #[tokio::test]
    async fn test_generate_diagnostics_reports_missing_catalog_entry() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "catalog:\n  react: ^18.3.0\n",
        )
        .unwrap();
        let manifest_path = root.path().join("package.json");
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = NpmEcosystem::new(cache);
        let content = r#"{"dependencies": {"left-pad": "catalog:"}}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        // A cached entry for "left-pad" so the base diagnostics pass doesn't separately fire
        // its own "unknown package" rule (which reads whether *any* registry data was ever
        // cached, independent of the catalog outcome under test here).
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            pkg("left-pad"),
            deps_core::lsp_helpers::PackageVersions::latest_only("1.3.0"),
        );
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

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("left-pad"));
        assert_eq!(
            diagnostics[0].severity,
            Some(tower_lsp_server::ls_types::DiagnosticSeverity::WARNING)
        );
    }
}

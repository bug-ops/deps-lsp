//! Cargo ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Cargo/Rust projects,
//! providing LSP functionality for `Cargo.toml` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::parser::DependencySource;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, Version, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::CargoFormatter;
use crate::registry::CargoRegistry;

/// Cargo ecosystem implementation.
///
/// Provides LSP functionality for Cargo.toml files, including:
/// - Dependency parsing with position tracking
/// - Version information from crates.io
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/yanked packages
pub struct CargoEcosystem {
    registry: Arc<CargoRegistry>,
    formatter: CargoFormatter,
}

/// The source(s) a `CompletionContext::Version`/`Feature`'s bare `package_name` joins back
/// to within a manifest's already-parsed dependencies (spec FR-012).
enum CompletionSource {
    /// No dependency in the manifest has this exact name yet — most commonly because the
    /// user is still typing a brand-new dependency line, with `registry`/`registry-index`
    /// not yet present for the parser to classify. Callers fall back to the pre-existing
    /// crates.io-only behavior, unchanged.
    NotInManifest,
    /// Every occurrence of this name in the manifest agrees on one resolved source.
    Resolved(DependencySource),
    /// Two or more occurrences of this name resolve to different sources (the same
    /// ambiguity FR-011 covers for the background fetch) — callers must offer no
    /// completions at all rather than picking one arbitrarily.
    Ambiguous,
}

/// Joins `package_name` back to `parse_result.dependencies()` by name (spec FR-012).
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
            "ambiguous dependency source for version/feature completion; offering none"
        );
        CompletionSource::Ambiguous
    }
}

impl CargoEcosystem {
    /// Creates a new Cargo ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(CargoRegistry::new(cache)),
            formatter: CargoFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        // Package-name search is crates.io-only unconditionally (spec Out of Scope: the
        // sparse index protocol has no search endpoint), so this never needs source
        // awareness — `self.registry`'s source-blind `Registry::search` already means
        // crates.io by construction (`CargoRegistry::search`).
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    /// Completes version requirements for `package_name`, routed by the source that name
    /// resolves to in `parse_result` (spec FR-012). An ambiguous or otherwise
    /// non-crates.io/non-alternate source offers no completions rather than risking a
    /// private-crate-name lookup against crates.io (the same leak class FR-001 closes for
    /// hover/diagnostics/code-actions).
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
                    &['^', '~', '=', '<', '>'],
                    freshness,
                )
                .await
            }
            CompletionSource::Resolved(DependencySource::AlternateRegistry { index }) => {
                match self.registry.alternate_client(&index) {
                    Some(client) => {
                        deps_core::completion::complete_versions_generic(
                            client.as_ref(),
                            package_name,
                            prefix,
                            &['^', '~', '=', '<', '>'],
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

    /// Completes feature flags for a specific package.
    ///
    /// Fetches features from the latest stable version, routed by the source `package_name`
    /// resolves to in `parse_result` (spec FR-012) — same routing/ambiguity policy as
    /// [`Self::complete_versions`].
    async fn complete_features(
        &self,
        parse_result: &dyn ParseResultTrait,
        package_name: &deps_core::PackageName,
        prefix: &str,
    ) -> Vec<CompletionItem> {
        use deps_core::completion::build_feature_completion;

        let versions_result: Result<Vec<Box<dyn Version>>> =
            match resolve_completion_source(parse_result, package_name) {
                CompletionSource::Ambiguous => return vec![],
                CompletionSource::NotInManifest
                | CompletionSource::Resolved(DependencySource::Registry) => {
                    Registry::get_versions(self.registry.as_ref(), package_name).await
                }
                CompletionSource::Resolved(DependencySource::AlternateRegistry { index }) => {
                    match self.registry.alternate_client(&index) {
                        Some(client) => Registry::get_versions(client.as_ref(), package_name).await,
                        None => return vec![],
                    }
                }
                CompletionSource::Resolved(_) => return vec![],
            };

        let versions = match versions_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to fetch versions for '{}': {}", package_name, e);
                return vec![];
            }
        };

        let latest = match versions.iter().find(|v| v.is_stable()) {
            Some(v) => v,
            None => {
                tracing::warn!("No stable version found for '{}'", package_name);
                return vec![];
            }
        };

        // Get features and filter by prefix
        let features = latest.features();
        features
            .into_iter()
            .filter(|f| f.starts_with(prefix))
            .map(|feature| build_feature_completion(&feature, package_name, None))
            .collect()
    }
}

impl deps_core::ecosystem::private::Sealed for CargoEcosystem {}

impl Ecosystem for CargoEcosystem {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn display_name(&self) -> &'static str {
        "Cargo (Rust)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Cargo.toml"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["Cargo.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_cargo_toml(content, uri)?;
            // Registers every alternate index this parse resolved (spec FR-002) into the
            // shared router, including its credential (if any) — the only point in the
            // whole pipeline where a `.cargo/config.toml`/`$CARGO_HOME` resolution and the
            // long-lived `CargoRegistry` this ecosystem shares across every document ever
            // meet. See `crate::parser::ParseResult::resolved_registries`'s docs.
            for (index, auth) in result.resolved_registries.clone() {
                self.registry.register_alternate(index, auth);
            }
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::CargoLockParser))
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
                CompletionContext::Feature {
                    package_name,
                    prefix,
                } => {
                    self.complete_features(parse_result, &package_name, &prefix)
                        .await
                }
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
    use crate::types::{DependencySection, DependencySource, ParsedDependency};
    use deps_core::{EcosystemConfig, PackageVersions, VersionData};
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{InlayHintLabel, Position, Range};

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    /// Mock dependency for testing
    fn mock_dependency(
        name: &str,
        version: Option<&str>,
        name_line: u32,
        version_line: u32,
    ) -> ParsedDependency {
        ParsedDependency {
            name: name.into(),
            name_range: Range::new(
                Position::new(name_line, 0),
                Position::new(name_line, name.len() as u32),
            ),
            version_req: version.map(Into::into),
            version_range: version.map(|_| {
                Range::new(
                    Position::new(version_line, 0),
                    Position::new(version_line, 10),
                )
            }),
            features: vec![],
            features_range: None,
            source: DependencySource::Registry,
            section: DependencySection::Dependencies,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<ParsedDependency>,
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
                std::sync::LazyLock::new(|| deps_core::test_util::test_uri("/test/Cargo.toml"));
            &URI
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// A `MockParseResult` with no dependencies — `resolve_completion_source` reports
    /// `NotInManifest` for any name against it, so `complete_versions`/`complete_features`
    /// fall back to their pre-existing crates.io-only behavior. Used by every test below
    /// that predates FR-012's source-aware routing and isn't itself testing that routing.
    fn empty_parse_result() -> MockParseResult {
        MockParseResult {
            dependencies: vec![],
        }
    }

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "cargo");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "Cargo (Rust)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["Cargo.toml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["Cargo.lock"]);
    }

    #[test]
    fn test_generate_inlay_hints_up_to_date_exact_match() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.214"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.0.214".into());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_up_to_date_caret_version() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("^1.0"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.0.214".into());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "✅ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_needs_update() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.100"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "❌ 1.0.214"),
            _ => panic!("Expected String label"),
        }
    }

    #[test]
    fn test_generate_inlay_hints_hide_up_to_date() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("serde", Some("1.0.214"), 5, 5)],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: false,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Lock file has the latest version - but show_up_to_date_hints is false
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), "1.0.214".into());
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 0);
    }

    #[test]
    fn test_generate_inlay_hints_no_version_range() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let mut dep = mock_dependency("serde", Some("1.0.214"), 5, 5);
        dep.version_range = None;

        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 0);
    }

    #[test]
    fn test_generate_inlay_hints_caret_edge_case() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Edge case: version_req is just "^" without version number
        let dep = mock_dependency("serde", Some("^"), 5, 5);

        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        // Should not panic, should return update hint
        let resolved_versions = HashMap::new();
        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loaded,
            &config,
        ));

        assert_eq!(hints.len(), 1);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Verify we can downcast
        let any = ecosystem.as_any();
        assert!(any.is::<CargoEcosystem>());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        let content = "[dependencies]\nserd = \"1.0\"\n";
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(1, 3); // cursor after "ser" in "serd"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "ser");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(1, 0), Position::new(1, 4)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem
            .complete_package_names("s", Range::default())
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
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem
            .complete_package_names("serd", Range::default())
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "serde"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("serde"),
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("1.0")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("serde"),
                "^1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("1.0")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem
            .complete_features(&empty_parse_result(), &pkg("serde"), "")
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "derive"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_with_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let results = ecosystem
            .complete_features(&empty_parse_result(), &pkg("serde"), "der")
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("der")));
    }

    /// FR-012's `CompletionSource::Ambiguous` branch (review finding #6): two occurrences
    /// of the same name resolving to two different sources must offer no version
    /// completions at all, not silently pick one arm's registry.
    #[tokio::test]
    async fn test_complete_versions_ambiguous_source_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let mut registry_dep = mock_dependency("shared-name", Some("1.0"), 0, 0);
        registry_dep.source = DependencySource::Registry;
        let mut alternate_dep = mock_dependency("shared-name", Some("1.0"), 1, 1);
        alternate_dep.source = DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev".into(),
        };
        let parse_result = MockParseResult {
            dependencies: vec![registry_dep, alternate_dep],
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("shared-name"),
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "an ambiguous source must offer no version completions"
        );
    }

    /// Same ambiguity, exercised through `complete_features` — mirrors
    /// `test_complete_versions_ambiguous_source_offers_nothing`'s routing policy.
    #[tokio::test]
    async fn test_complete_features_ambiguous_source_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let mut registry_dep = mock_dependency("shared-name", Some("1.0"), 0, 0);
        registry_dep.source = DependencySource::Registry;
        let mut alternate_dep = mock_dependency("shared-name", Some("1.0"), 1, 1);
        alternate_dep.source = DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev".into(),
        };
        let parse_result = MockParseResult {
            dependencies: vec![registry_dep, alternate_dep],
        };

        let results = ecosystem
            .complete_features(&parse_result, &pkg("shared-name"), "")
            .await;
        assert!(
            results.is_empty(),
            "an ambiguous source must offer no feature completions"
        );
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

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
    async fn test_complete_features_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_features(
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "",
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Package names with hyphens and underscores should work
        let results = ecosystem
            .complete_package_names("tokio-ut", Range::default())
            .await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

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
        let ecosystem = CargoEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
                &pkg("serde"),
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_features_empty_list() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Some packages have no features - should handle gracefully
        // (Using a package that likely has no features, or empty prefix on a small package)
        let results = ecosystem
            .complete_features(&empty_parse_result(), &pkg("anyhow"), "nonexistent")
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_special_chars_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Real packages with special characters
        let results = ecosystem
            .complete_package_names("tokio-ut", Range::default())
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label.contains('-')));
    }

    #[test]
    fn test_generate_inlay_hints_loading_state() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let parse_result = MockParseResult {
            dependencies: vec![mock_dependency("tokio", Some("1.0"), 5, 5)],
        };

        // Empty caches - simulating loading state
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let config = EcosystemConfig {
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        };

        let hints = tokio_test::block_on(ecosystem.generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            deps_core::LoadingState::Loading,
            &config,
        ));

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(s) => assert_eq!(s, "⏳", "Expected loading indicator"),
            _ => panic!("Expected String label"),
        }

        if let Some(tower_lsp_server::ls_types::InlayHintTooltip::String(tooltip)) =
            &hints[0].tooltip
        {
            assert_eq!(tooltip, "Fetching latest version...");
        } else {
            panic!("Expected tooltip for loading state");
        }
    }
}

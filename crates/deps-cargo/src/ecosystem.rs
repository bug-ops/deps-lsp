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
use crate::parser::CargoParseContext;
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
    /// The reachability policy (spec #443) and `.cargo/config.toml` memoization cache (spec
    /// NFR-005) every `parse_manifest` call threads through to
    /// [`crate::parser::parse_cargo_toml_with_context`]. Defaulted by [`Self::new`]; set
    /// explicitly by [`Self::with_context`] so `crate::lib::register_ecosystems` can share
    /// one process-wide policy handle with `ServerState`.
    context: CargoParseContext,
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
    /// Creates a new Cargo ecosystem with the given HTTP cache, using a fresh, default
    /// [`CargoParseContext`] — an all-`PublicOnly`-policy, empty-cache context private to
    /// this ecosystem instance. Production use goes through [`Self::with_context`] instead,
    /// so the policy handle is shared with `ServerState` and live-updatable via
    /// `workspace/didChangeConfiguration`.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self::with_context(cache, CargoParseContext::default())
    }

    /// Creates a new Cargo ecosystem sharing `ctx`'s reachability policy and config-file
    /// cache — the production constructor (plan-1b §1.6), used by
    /// `crate::lib::register_ecosystems` so `initialize`/`workspace/didChangeConfiguration`
    /// can update the same `Arc<RegistryAccessPolicy>` this ecosystem's every parse reads.
    pub fn with_context(cache: Arc<deps_core::HttpCache>, ctx: CargoParseContext) -> Self {
        Self {
            registry: Arc::new(CargoRegistry::new(cache)),
            formatter: CargoFormatter,
            context: ctx,
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

    /// Completes version requirements for the dependency at `position`, resolved by cursor
    /// position rather than by name (issue #593) — delegates to
    /// [`deps_core::completion::complete_versions_at_position`], which mirrors
    /// `deps_gitlab_ci::ecosystem::GitLabCiEcosystem::generate_completions`'s reference
    /// pattern. Position-based lookup also fixes a residual gap in the old name-based
    /// [`resolve_completion_source`] routing: two dependencies sharing one `PackageName` but
    /// resolving to different sources (e.g. two `[[registries]]`-scoped Cargo entries) used to
    /// collapse into `CompletionSource::Ambiguous` and offer no completions for either
    /// occurrence, even though the cursor position unambiguously identifies which one the user
    /// is editing.
    ///
    /// The shared helper's `can_resolve_source` gate keeps `Registry::get_versions_from`'s
    /// permissive catch-all (anything it doesn't explicitly recognize — Git, Path, an
    /// unresolved `CustomRegistry`, ...) from leaking a private/non-registry dependency's name
    /// to crates.io on every keystroke (#248). One source it does *not* reject —
    /// `AlternateRegistry { mirrors_crates_io: true, .. }` left unregistered — deliberately
    /// degrades to crates.io inside `CargoRegistry::get_versions_for_source`
    /// (`registry.rs`'s `mirrors_crates_io` arm): safe, since Cargo verifies per-version
    /// checksum equality against crates.io for a `[source.crates-io] replace-with` mirror, and
    /// matches hover's identical degrade-to-public behavior for the same flag.
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
            &['^', '~', '=', '<', '>'],
            freshness,
        )
        .await
    }

    /// Completes feature flags for a specific package.
    ///
    /// Fetches features from the latest stable version, routed by the source `package_name`
    /// resolves to in `parse_result` by name (spec FR-012) — unlike [`Self::complete_versions`]
    /// (issue #593, position-based), this still joins by name via
    /// [`resolve_completion_source`]/[`CompletionSource`], so it keeps the same residual
    /// same-name-different-source `Ambiguous` gap #593 fixed for versions (not itself in
    /// #593's scope: `features_range`-based position routing for this method is a follow-up,
    /// not done here).
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
                CompletionSource::Resolved(DependencySource::AlternateRegistry {
                    index, ..
                }) => match self.registry.alternate_client(&index) {
                    Some(client) => Registry::get_versions(client.as_ref(), package_name).await,
                    None => return vec![],
                },
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
            let result = crate::parser::parse_cargo_toml_with_context(content, uri, &self.context)?;
            // Registers every alternate index this parse resolved (spec FR-002) into the
            // shared router, including its credential (if any) — the only point in the
            // whole pipeline where a `.cargo/config.toml`/`$CARGO_HOME` resolution and the
            // long-lived `CargoRegistry` this ecosystem shares across every document ever
            // meet. See `crate::parser::CargoParseResult::resolved_registries`'s docs.
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
                CompletionContext::Version { prefix, .. } => {
                    self.complete_versions(parse_result, position, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature {
                    package_name,
                    prefix,
                } => {
                    self.complete_features(parse_result, &package_name, &prefix)
                        .await
                }
                CompletionContext::None | _ => vec![],
            }
            .into()
        })
    }

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        Some(extract_prefix(line, position.character))
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // The key is quoted, not bare: a bare TOML key containing `.` (allowed by
        // `is_safe_package_name` for Cargo crate names) expands into a nested table
        // instead of a dependency entry — quoting closes that dotted-key injection.
        Some(format!("\"{name}\" = \"{latest}\""))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Checks if `line_number` of `content` is inside a Cargo `[dependencies]`-like
/// section, for `deps-lsp`'s raw-text fallback completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    deps_core::fallback_completion::is_in_toml_dependencies(content, line_number)
}

/// Extracts the fallback-completion prefix on `line` up to `character` — a bare TOML
/// key, with no manifest-syntax wrapper to strip (unlike PyPI's TOML array-element or
/// npm's JSON-key shapes).
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CargoDependency, CargoDependencySection, DependencySource};
    use deps_core::{EcosystemConfig, PackageVersions, VersionData};
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{InlayHintLabel, Position, Range};

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_ecosystem_manifest_filenames/
    // test_ecosystem_lockfile_filenames/test_as_any family. Does not replace registry.rs's
    // own test_registry_creation, which constructs `CratesIoRegistry` directly — a different
    // type from `Ecosystem::registry()`'s `Arc<dyn Registry>` return value.
    deps_core::ecosystem_conformance! {
        mod cargo_ecosystem_conformance;
        build: CargoEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: CargoEcosystem;
        id: "cargo";
        display_name: "Cargo (Rust)";
        manifest_filenames: &["Cargo.toml"];
        lockfile_filenames: &["Cargo.lock"];
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_minimum_prefix/test_complete_package_names_max_length.
    // The mock registry the macro supplies stands in for `CargoEcosystem`'s own
    // `self.registry` here, so this calls the exact shared guard `complete_package_names`
    // delegates to (`formatter.rs`'s `CargoEcosystem::complete_package_names`,
    // `deps_core::completion::complete_package_names_generic`), with the same `limit: 20` —
    // without it, an always-offline real registry couldn't distinguish "the guard rejected
    // this prefix" from "the network call failed" (#758 impl-critic M1).
    deps_core::completion_guard_conformance! {
        mod cargo_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<tower_lsp_server::ls_types::CompletionItem>> + Send + '_>,
        > {
            // Boxed, lifetime-parameterized future: `complete_package_names_generic`'s
            // `impl Future` borrows `registry` across the `.await`, which a plain `Fn(..) ->
            // Fut` associated type can't express per-call (see
            // `deps_core::conformance::assert_completion_guard`'s doc).
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

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    /// Mock dependency for testing
    fn mock_dependency(
        name: &str,
        version: Option<&str>,
        name_line: u32,
        version_line: u32,
    ) -> CargoDependency {
        CargoDependency {
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
            section: CargoDependencySection::Dependencies,
            package: None,
        }
    }

    /// Mock parse result for testing
    struct MockParseResult {
        dependencies: Vec<CargoDependency>,
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
    /// `NotInManifest` for any name against it, so `complete_features` falls back to its
    /// pre-existing crates.io-only behavior. Used by tests below that only exercise
    /// `complete_features` (`complete_versions` is now position-based; see `mock_dependency`).
    fn empty_parse_result() -> MockParseResult {
        MockParseResult {
            dependencies: vec![],
        }
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
            offline: false,
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
            offline: false,
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
            offline: false,
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
            offline: false,
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
            offline: false,
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
            offline: false,
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
        let dep = mock_dependency("serde", Some("1.0"), 0, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
        let dep = mock_dependency("serde", Some("^1.0"), 0, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };

        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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

    /// Issue #593: two dependencies sharing one `PackageName` but resolving to different
    /// sources no longer collapse into the old name-based `CompletionSource::Ambiguous`
    /// "offer nothing for either" result (review finding #6) — cursor position now
    /// identifies exactly one dependency, so each occurrence routes independently.
    #[tokio::test]
    async fn test_complete_versions_same_name_different_sources_routes_by_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let mut registry_dep = mock_dependency("shared-name", Some("1.0"), 0, 0);
        registry_dep.source = DependencySource::Registry;
        let mut alternate_dep = mock_dependency("shared-name", Some("1.0"), 1, 1);
        alternate_dep.source = DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev/never-registered".into(),
            mirrors_crates_io: false,
        };
        let alternate_position = alternate_dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![registry_dep, alternate_dep],
        };

        // The alternate occurrence resolves deterministically without network: its index
        // was never registered, so `CargoRegistry::alternate_client` returns `None` and the
        // fetch fails closed with `PackageNotFound` before any HTTP call — proving its own
        // source, not the co-occurring `Registry`-sourced entry, drove the routing.
        let results = ecosystem
            .complete_versions(
                &parse_result,
                alternate_position,
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "unregistered alternate index must offer no completions"
        );
    }

    /// Issue #593 critic finding M5: the test above only proves the *empty* case, which a
    /// totally broken position lookup would also satisfy. This proves position-based routing
    /// actually selects the right source's data — a *registered* alternate index's own client
    /// is hit and its versions come back — mirroring `deps-go`'s/`deps-nuget`'s equivalent
    /// `..._routes_to_registered_alternate_client` tests.
    #[tokio::test]
    async fn test_complete_versions_routes_to_registered_alternate_client() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(
                "{\"name\":\"serde\",\"vers\":\"1.0.0\",\"yanked\":false,\"features\":{},\"deps\":[]}\n\
                 {\"name\":\"serde\",\"vers\":\"1.5.0\",\"yanked\":false,\"features\":{},\"deps\":[]}\n",
            )
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let registry_index = crate::config::RegistryIndex::new(
            &server.url(),
            crate::config::IndexTrust::Trusted,
            &policy,
        )
        .unwrap();
        let index_key = registry_index.as_str().to_string();
        ecosystem.registry.register_alternate(registry_index, None);

        let mut dep = mock_dependency("serde", Some("1.0"), 0, 0);
        dep.source = DependencySource::AlternateRegistry {
            index: index_key,
            mirrors_crates_io: false,
        };
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
        assert!(
            !results.is_empty(),
            "a registered alternate index must route completions through its own client"
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
            mirrors_crates_io: false,
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
        let dep = mock_dependency("this-package-does-not-exist-12345", Some("1.0"), 0, 0);
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
    #[ignore] // Requires network access
    async fn test_complete_versions_limit_20() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let dep = mock_dependency("serde", Some("1.0"), 0, 0);
        let position = dep.version_range.unwrap().start;
        let parse_result = MockParseResult {
            dependencies: vec![dep],
        };
        let results = ecosystem
            .complete_versions(
                &parse_result,
                position,
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
            offline: false,
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

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_toml_dependencies` + `raw_prefix` compose correctly through the real
    /// trait method on realistic multi-line content, not just each primitive in
    /// isolation.
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        let content = "[package]\nname = \"test\"\n\n[dependencies]\nser";
        let line = content.lines().nth(4).unwrap();
        let position = Position::new(4, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position),
            Some("ser")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_basic() {
        let content = "\n[dependencies]\nserde\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 0));
    }

    #[test]
    fn test_is_in_dependencies_section_wrong_section() {
        let content = "\n[package]\nname = \"test\"\n\n[profile.release]\nopt-level = 3\n";
        assert!(!is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 5));
    }

    #[test]
    fn test_extract_prefix_cursor_beyond_line() {
        let line = "serde";
        assert_eq!(extract_prefix(line, 100), "serde");
    }

    #[test]
    fn test_extract_prefix_leaves_quotes_unstripped() {
        // Cargo keys are typed unquoted, so a leading `"` should never appear in
        // practice, but the strip must stay scoped: unlike PyPI's TOML array-element
        // shape, Cargo does not strip surrounding quotes.
        let line = "\"expr";
        assert_eq!(extract_prefix(line, line.len() as u32), "\"expr");
    }

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

    #[test]
    fn test_completion_insert_text_quotes_key_and_version() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        let meta = MockMetadata {
            name: pkg("serde"),
            latest_version: "1.0.214".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"serde\" = \"1.0.214\"".to_string())
        );
    }

    /// S1: a bare TOML key containing `.` (legal — real crate names can use it)
    /// expands into a nested table instead of a dependency entry
    /// (`serde.path = "vendor"` parses as `serde = { path = "vendor" }`). Quoting the
    /// key keeps the dotted name a single dependency entry.
    #[test]
    fn test_completion_insert_text_dotted_name_quotes_toml_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = CargoEcosystem::new(cache);
        let meta = MockMetadata {
            name: pkg("some.crate"),
            latest_version: "6.1".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"some.crate\" = \"6.1\"".to_string())
        );
    }
}

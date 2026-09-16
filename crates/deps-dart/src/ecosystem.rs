//! Dart ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Position, Range};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::DartFormatter;
use crate::registry::PubDevRegistry;

/// [`Ecosystem`] implementation for Dart/Pub (`pubspec.yaml`).
pub struct DartEcosystem {
    registry: Arc<PubDevRegistry>,
    formatter: DartFormatter,
}

impl DartEcosystem {
    /// Creates a Dart ecosystem instance backed by the given shared HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PubDevRegistry::new(cache)),
            formatter: DartFormatter,
        }
    }

    /// Test-only: wraps an already-constructed [`PubDevRegistry`] (e.g. one built via
    /// [`PubDevRegistry::with_base`](crate::registry::PubDevRegistry::with_base) pointed at a
    /// mock server) instead of building a live-registry one (#1038).
    #[cfg(test)]
    #[cfg(feature = "lsp-responses")]
    #[must_use]
    pub(crate) fn with_registry_for_test(registry: PubDevRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            formatter: DartFormatter,
        }
    }

    #[cfg(feature = "lsp-responses")]
    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    // Position-based, gated: see complete_versions_at_position's own doc (#593, #1136).
    #[cfg(feature = "lsp-responses")]
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
            &['^', '>', '<', '='],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for DartEcosystem {}

impl Ecosystem for DartEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Dart
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
        uri: &'a Url,
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

    #[cfg(feature = "lsp-responses")]
    fn complete_package_name<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        prefix: String,
        range: Range,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move { self.complete_package_names(&prefix, range).await.into() })
    }

    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        request: deps_core::completion::CompletionRequest<'a>,
        _package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            self.complete_versions(
                request.parse_result,
                request.position,
                &prefix,
                request.freshness,
            )
            .await
            .into()
        })
    }

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: deps_core::position::Position,
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
        // The key is quoted: an unquoted YAML plain scalar can't start with `@`
        // (allowed by `is_safe_package_name` for npm/Deno-shaped names), which would
        // otherwise emit invalid YAML instead of a dependency entry.
        Some(format!("\"{name}\": ^{latest}"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s best-effort detected license (issue #660/#688) — `version` is
    /// unused, since pub.dev's `/score` endpoint is per-*package*, not per-version. See
    /// [`crate::registry::PubDevRegistry::get_license`] for the source and its
    /// "detected, not declared" caveat.
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        _version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        Box::pin(self.registry.get_license(name))
    }

    /// pub.dev's `/score` endpoint is pana's own license-detection heuristic, not an
    /// author-declared registry field — see [`deps_core::LicenseSource::DetectedSpdx`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::DetectedSpdx
    }
}

/// pubspec.yaml's top-level (unindented) dependency-like keys.
const SECTION_KEYS: &[&str] = &[
    "dependencies:",
    "dev_dependencies:",
    "dependency_overrides:",
];

/// Checks if `line_number` of `content` is inside a pubspec.yaml dependency section.
///
/// Dart's `dependencies`, `dev_dependencies`, and `dependency_overrides` keys are
/// top-level (unindented) YAML mappings; their entries stay part of the section until
/// the next unindented key starts a new one. For `deps-lsp`'s raw-text fallback
/// completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    let mut in_dependencies = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Top-level (unindented) key: starts a new section, or leaves the current one.
        if trimmed.len() == line.len() {
            in_dependencies = SECTION_KEYS.iter().any(|key| trimmed.starts_with(key));
        }
    }

    in_dependencies
}

/// Extracts the fallback-completion prefix on `line` up to `character` — a bare YAML
/// key, with no manifest-syntax wrapper to strip.
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

#[cfg(test)]
mod tests {
    use super::*;

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_ecosystem_manifest_filenames/
    // test_ecosystem_lockfile_filenames/test_as_any family.
    deps_core::ecosystem_conformance! {
        mod dart_ecosystem_conformance;
        build: DartEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: DartEcosystem;
        id: "dart";
        display_name: "Dart (Pub)";
        manifest_filenames: &["pubspec.yaml"];
        lockfile_filenames: &["pubspec.lock"];
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_min_prefix/test_complete_package_names_max_length.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_guard_conformance! {
        mod dart_completion_guard_conformance;
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

    // #1136: a `hosted:` package pointing at a custom (unresolved) registry must yield zero
    // version completions and never reach pub.dev.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_source_gate_conformance! {
        mod dart_completion_source_gate_conformance;
        build: async {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", mockito::Matcher::Any)
                .expect(0)
                .create_async()
                .await;
            let cache = Arc::new(deps_core::HttpCache::new());
            let registry = PubDevRegistry::with_base(Arc::clone(&cache), server.url());
            let eco = DartEcosystem::with_registry_for_test(registry);
            (eco, mock, server)
        };
        manifest: "pubspec.yaml" => "name: my_app\ndependencies:\n  custom_pkg:\n    hosted: https://custom-registry.example.com\n    version: ^1.0.0\n";
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 4); // cursor after "ht" in "http"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "ht");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(2, 2), Position::new(2, 6)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
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
        let uri = Url::from_file_path(path).unwrap();

        let result = eco.parse_manifest(yaml, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_dependencies_section`'s top-level-key scan compose correctly through
    /// the real trait method on realistic multi-line `pubspec.yaml` content.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: myapp\ndependencies:\n  pa";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            Some("pa")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_basic() {
        let content =
            "name: myapp\ndependencies:\n  http: ^1.0.0\nenvironment:\n  sdk: '>=3.0.0'\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 4));
    }

    /// A column-0 `#` comment inside a section must not read as a new top-level key
    /// and reset `in_dependencies` to false.
    #[test]
    fn test_is_in_dependencies_section_column_zero_comment() {
        let content = "name: myapp\ndependencies:\n# a comment\n  http: ^1.0.0\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(is_in_dependencies_section(content, 3));
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
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
            name: deps_core::PackageName::new("path"),
            latest_version: "1.9.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("\"path\": ^1.9.0".to_string())
        );
    }

    // --- #793 characterization: `generate_completions` dispatch, pinned before the
    // wildcard-match refactor.

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_package_name_context_below_length_guard_is_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: my_app\ndependencies:\n  h: ^1.0.0\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 3); // cursor right after "h"
        let freshness = deps_core::FreshnessSettings::default();

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );
        let deps_core::completion::CompletionContext::PackageName { prefix, range } = context
        else {
            panic!("expected PackageName context, got {context:?}");
        };
        let direct = eco.complete_package_names(&prefix, range).await;
        let via_dispatch = eco
            .generate_completions(parse_result.as_ref(), position, content, freshness)
            .await;
        assert_eq!(via_dispatch.items, direct);
        assert!(direct.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_none_context_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: my_app\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let result = eco
            .generate_completions(
                parse_result.as_ref(),
                Position::new(0, 0),
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// CI-enforced (not `#[ignore]`d) counterpart to the happy-path test below: exercises the
    /// same dispatch path (`package_name`/`prefix` threaded from the resolved `Version`
    /// context to `complete_versions`) the ignored test below leaves uncovered in an ordinary
    /// CI run, but against a mocked 404 rather than the live `pub.dev` (#1038) — a regression
    /// that makes zero requests (and so also produces an empty result) can no longer pass
    /// vacuously, since `mock.assert_async()` requires the request to actually have been made.
    ///
    /// `.expect(2)`, not `.expect_at_least(1)`: this test calls both `complete_versions`
    /// directly and `generate_completions` (which must dispatch to the same
    /// `complete_versions`), and `HttpCache` never caches a non-2xx response (a 404 becomes
    /// `DepsError::HttpStatus`, never stored) — so exactly 2 requests reach the mock on the
    /// unregressed path. A regression that dropped the `generate_completions` dispatch would
    /// leave the mock at 1 hit, which `.expect_at_least(1)` alone would not catch.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_version_context_unknown_package_is_empty() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/packages/this_package_does_not_exist_12345")
            .with_status(404)
            .expect(2)
            .create_async()
            .await;
        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = PubDevRegistry::with_base(Arc::clone(&cache), server.url());
        let eco = DartEcosystem::with_registry_for_test(registry);
        let content = "name: my_app\ndependencies:\n  this_package_does_not_exist_12345: ^1.0.0\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position: Position = parse_result.dependencies()[0]
            .version_range()
            .unwrap()
            .start
            .into();
        let freshness = deps_core::FreshnessSettings::default();

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );
        let deps_core::completion::CompletionContext::Version { prefix, .. } = context else {
            panic!("expected Version context, got {context:?}");
        };
        let direct = eco
            .complete_versions(parse_result.as_ref(), position, &prefix, freshness)
            .await;
        let via_dispatch = eco
            .generate_completions(parse_result.as_ref(), position, content, freshness)
            .await;
        mock.assert_async().await;
        assert_eq!(via_dispatch.items, direct);
        assert!(direct.is_empty());
    }

    /// #793 S1: pins that a `Version` context threads `package_name`/`prefix` through to
    /// `complete_versions` — requires live network for a real, non-empty result (pub.dev has
    /// no offline test seam here), mirroring this codebase's existing convention for
    /// completion tests that need a genuine registry round-trip.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_generate_completions_version_context_dispatches_to_registry() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position: Position = parse_result.dependencies()[0]
            .version_range()
            .unwrap()
            .start
            .into();
        let freshness = deps_core::FreshnessSettings::default();

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );
        let deps_core::completion::CompletionContext::Version { prefix, .. } = context else {
            panic!("expected Version context, got {context:?}");
        };
        let direct = eco
            .complete_versions(parse_result.as_ref(), position, &prefix, freshness)
            .await;
        let via_dispatch = eco
            .generate_completions(parse_result.as_ref(), position, content, freshness)
            .await;
        assert_eq!(via_dispatch.items, direct);
        assert!(!direct.is_empty());
    }
}

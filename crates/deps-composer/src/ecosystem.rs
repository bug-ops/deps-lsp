//! Composer ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for PHP/Composer projects,
//! providing LSP functionality for `composer.json` files.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::ComposerFormatter;
use crate::registry::PackagistRegistry;

/// Composer ecosystem implementation.
///
/// Provides LSP functionality for composer.json files, including:
/// - Dependency parsing with position tracking
/// - Version information from Packagist registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/abandoned packages
pub struct ComposerEcosystem {
    registry: Arc<PackagistRegistry>,
    formatter: ComposerFormatter,
}

impl ComposerEcosystem {
    /// Creates a new Composer ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PackagistRegistry::new(cache)),
            formatter: ComposerFormatter,
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
            &['^', '~', '=', '<', '>', '*'],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for ComposerEcosystem {}

impl Ecosystem for ComposerEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Composer
    }

    fn display_name(&self) -> &'static str {
        "Composer (PHP)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["composer.json"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["composer.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_composer_json(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::ComposerLockParser))
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
        let (prefix, _) = extract_prefix(line, position.character);
        // A closed key or an open value string (see `extract_prefix`) both come back
        // as an empty prefix — there is no safe text to offer at that position, so
        // this suppresses the completion entirely (`None`, same as "no completable
        // position at all") rather than relying on the caller's own `prefix.is_empty()`
        // guard (#729).
        if prefix.is_empty() {
            return None;
        }
        Some(prefix)
    }

    fn fallback_completion_is_bare(&self, content: &str, position: Position) -> bool {
        let Some(line) = deps_core::fallback_completion::line_at(content, position) else {
            return false;
        };
        extract_prefix(line, position.character).1
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("\"{name}\": \"^{latest}\""))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Composer's `composer.json` dependency-like section keys.
const DEPENDENCY_KEYS: &[&str] = &["require", "require-dev"];

/// Checks if `line_number` of `content` is inside one of Composer's dependency-like
/// sections, for `deps-lsp`'s raw-text fallback completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    deps_core::fallback_completion::is_in_json_dependencies(content, line_number, DEPENDENCY_KEYS)
}

/// Extracts the fallback-completion prefix on `line` up to `character`, together with
/// whether the cursor sits inside a genuinely still-open key string (see
/// [`deps_core::fallback_completion::strip_open_json_key`]) — used by both
/// [`ComposerEcosystem::fallback_completion_prefix`] and
/// [`ComposerEcosystem::fallback_completion_is_bare`].
///
/// A surviving `"` proves the key's own quotes are already open around the cursor —
/// the same shape as NuGet's open-attribute case — so
/// [`ComposerEcosystem::completion_insert_text`]'s full `"{name}": "^{latest}"` pair
/// would duplicate that quote and produce invalid JSON if inserted there.
/// `strip_open_json_key` only reports an open key when quote parity (escape-aware)
/// proves the string is genuinely still open and precedes a key position, not a closed
/// key or an open value; the closed/ambiguous/value cases return an empty prefix,
/// which `deps-lsp`'s fallback-completion caller's `prefix.is_empty()` guard rejects
/// before any registry search fires — suppressing rather than guessing, matching
/// Maven's non-`artifactId`-tag discipline (#729).
fn extract_prefix(line: &str, character: u32) -> (&str, bool) {
    deps_core::fallback_completion::strip_open_json_key(deps_core::fallback_completion::raw_prefix(
        line, character,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{EcosystemConfig, VersionData};
    use std::collections::HashMap;

    // #758: exact-value `Ecosystem` conformance, replacing test_ecosystem_id,
    // test_ecosystem_manifest_filenames, and test_ecosystem_lockfile_filenames. Also closes
    // a real gap: this crate had no `test_as_any`/registry-smoke-test equivalent before.
    deps_core::ecosystem_conformance! {
        mod composer_ecosystem_conformance;
        build: ComposerEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: ComposerEcosystem;
        id: "composer";
        display_name: "Composer (PHP)";
        manifest_filenames: &["composer.json"];
        lockfile_filenames: &["composer.lock"];
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_short_prefix — also closes the missing max-length case.
    deps_core::completion_guard_conformance! {
        mod composer_completion_guard_conformance;
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

    #[test]
    fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        assert!(ecosystem.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/composer.json");

        let content = r#"{"require": {"symfony/console": "^6.0"}}"#;
        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert_eq!(parse_result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/composer.json");

        let result = ecosystem.parse_manifest("{invalid json}", &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"symfony/console\": \"^6.0\"\n  }\n}";
        let uri = deps_core::test_util::test_uri("/test/composer.json");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 9); // cursor after "symf" in "symfony/console"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "symf");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(2, 5), Position::new(2, 20)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/composer.json");

        let content = r#"{"require": {}}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                VersionData::new(&HashMap::new(), &HashMap::new()),
                deps_core::LoadingState::Loaded,
                &EcosystemConfig::default(),
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/composer.json");

        let content = r#"{"name": "test/project"}"#;
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

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_json_dependencies` + quote-stripping compose correctly through the real
    /// trait method on realistic multi-line content.
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/mono";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position),
            Some("monolog/mono")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_basic() {
        let content = "{\n  \"require\": {\n    \"monolog/monolog\": \"^2.0\"\n  },\n  \"scripts\": {\n    \"test\": \"phpunit\"\n  }\n}";
        assert!(is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 5));
    }

    #[test]
    fn test_extract_prefix_strips_quotes() {
        let line = "    \"monolog/mono";
        assert_eq!(
            extract_prefix(line, line.len() as u32),
            ("monolog/mono", true)
        );
    }

    #[test]
    fn test_extract_prefix_closed_key_is_suppressed_not_reopened() {
        // #729 critic S1: cursor right after an already fully-closed key (quote
        // parity even) is NOT an open string — bare-inserting there would duplicate
        // the closed key's quote. Suppressed instead of guessed.
        let line = "    \"monolog/monolog\"";
        assert_eq!(extract_prefix(line, line.len() as u32), ("", false));
    }

    /// #729: a closed key (`"monolog/monolog"`, cursor past both quotes) must
    /// suppress the completion entirely — the same "no safe text to offer" outcome as
    /// Maven's non-`artifactId` open tag — which this trait method achieves by
    /// returning `None`, same as "no completable position at all".
    #[test]
    fn test_fallback_completion_prefix_closed_key_is_suppressed() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/monolog\"";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(eco.fallback_completion_prefix(content, position), None);
    }

    #[test]
    fn test_fallback_completion_is_bare_inside_open_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/mono";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(eco.fallback_completion_is_bare(content, position));
    }

    #[test]
    fn test_fallback_completion_is_bare_false_with_no_open_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    monolog";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position));
    }

    /// #729: `ComposerEcosystem` has no `fallback_bare_insert_text` override — the
    /// default (bare `metadata.name()`) is exactly right here.
    #[test]
    fn test_fallback_bare_insert_text_default_is_bare_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("monolog/monolog"),
            latest_version: "3.5.0".into(),
        };
        assert_eq!(
            eco.fallback_bare_insert_text(&meta),
            Some("monolog/monolog".to_string())
        );
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
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("monolog/monolog"),
            latest_version: "3.5.0".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"monolog/monolog\": \"^3.5.0\"".to_string())
        );
    }
}

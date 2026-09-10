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
        // No quote strip, unlike npm/Composer: the completable text at a
        // package-name position in `deno.json` is the JSON *value* (the
        // `jsr:`/`npm:` specifier string), not the *key* (the import alias) — the
        // raw line-start-to-cursor text is always preceded by the alias key, colon
        // and opening quote in real JSON (`"@std/fs": "jsr:@std/f`), so this can
        // never coincide with a bare `jsr:`/`npm:` prefix; `DenoRegistry::search`
        // always takes its scheme-less `None => Ok(vec![])` arm for this path, so
        // the fallback query is effectively a no-op here rather than a source of
        // garbage results — the primary `detect_completion_context`-based path
        // does the real work.
        Some(extract_prefix(line, position.character))
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // D11: the alias key is conventionally the bare name (scheme stripped); the
        // value is the full scheme-qualified specifier.
        let bare = name
            .as_str()
            .split_once(':')
            .map_or(name.as_str(), |(_, rest)| rest);
        // N5: an empty `latest` (a JSR search hit with no `latestVersion`) must not
        // insert a dangling `@^` with nothing after it.
        if latest.is_empty() {
            Some(format!("\"{bare}\": \"{name}\""))
        } else {
            Some(format!("\"{bare}\": \"{name}@^{latest}\""))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s (already scheme-qualified, e.g. `"jsr:@std/fs"`) license at
    /// `version` (issue #660/#688) from the JSR per-version API. See
    /// [`crate::registry::DenoRegistry::get_license`].
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        // Wrapped in an explicit `async move` block (rather than boxing the inner async
        // fn's future directly, as the other three tier-3 ecosystems' `fetch_license` do)
        // because `PackageName::new(name)` is a temporary: borrowing it outside an async
        // block that also performs the `.await` would only live to the end of this
        // statement, not for the lifetime of the returned, not-yet-polled future.
        Box::pin(async move {
            self.registry
                .get_license(&deps_core::PackageName::new(name), version)
                .await
        })
    }

    /// JSR's package-metadata endpoint returns an author-declared SPDX identifier, but
    /// via a dedicated fetch separate from the hot-path registry response — see
    /// [`deps_core::LicenseSource::FetchedDeclaredSpdx`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::FetchedDeclaredSpdx
    }
}

/// Checks if `line_number` of `content` is inside deno.json's `imports` mapping, for
/// `deps-lsp`'s raw-text fallback completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    deps_core::fallback_completion::is_in_json_dependencies(content, line_number, &["imports"])
}

/// Extracts the fallback-completion prefix on `line` up to `character` — no quote
/// strip (see [`DenoEcosystem::fallback_completion_prefix`]'s doc for why).
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

#[cfg(test)]
mod tests {
    use super::*;

    // #758: exact-value `Ecosystem` conformance, replacing test_ecosystem_id/
    // test_ecosystem_display_name/test_ecosystem_manifest_filenames/test_as_any.
    // `lockfile_filenames` is omitted — deno.lock resolved-version parsing is a documented
    // MVP gap (D9), not yet a `LockFileProvider` impl in this crate; `no_lockfile_support:
    // true;` (#782 gap 2) replaces the hand-written test_ecosystem_no_lockfile_support that
    // used to cover that absence-of-both-halves invariant.
    deps_core::ecosystem_conformance! {
        mod deno_ecosystem_conformance;
        build: DenoEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: DenoEcosystem;
        id: "deno";
        display_name: "Deno (JSR/npm)";
        manifest_filenames: &["deno.json", "deno.jsonc"];
        no_lockfile_support: true;
    }

    // #758: the shared completion-prefix-length guard, replacing
    // test_complete_package_names_minimum_prefix (which only checked a 1-character prefix).
    deps_core::completion_guard_conformance! {
        mod deno_completion_guard_conformance;
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

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_json_dependencies` compose correctly through the real trait method on
    /// realistic multi-line content — no quote strip, unlike npm/Composer (see
    /// `DenoEcosystem::fallback_completion_prefix`'s doc for why).
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let content = "{\n  \"name\": \"test\",\n  \"imports\": {\n    \"@std/fs\": \"jsr:@std/f";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position),
            Some("\"@std/fs\": \"jsr:@std/f")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_imports() {
        let content = "{\n  \"name\": \"test\",\n  \"imports\": {\n    \"@std/fs\": \"jsr:@std/fs@^1.0\"\n  }\n}";
        assert!(is_in_dependencies_section(content, 3));
        assert!(!is_in_dependencies_section(content, 1));
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
    fn test_completion_insert_text_strips_scheme_for_alias_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("jsr:@std/fs"),
            latest_version: "1.0.24".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"@std/fs\": \"jsr:@std/fs@^1.0.24\"".to_string())
        );
    }

    #[test]
    fn test_completion_insert_text_npm_scheme() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("npm:react"),
            latest_version: "18.3.1".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"react\": \"npm:react@^18.3.1\"".to_string())
        );
    }

    /// N5: a JSR search hit lacking `latestVersion` must not insert a dangling `@^`.
    #[test]
    fn test_completion_insert_text_empty_latest_omits_version_clause() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("jsr:@std/fs"),
            latest_version: "".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"@std/fs\": \"jsr:@std/fs\"".to_string())
        );
    }
}

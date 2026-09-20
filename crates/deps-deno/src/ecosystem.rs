//! Deno ecosystem implementation for deps-lsp (D1).
//!
//! Provides LSP functionality for `deno.json`/`deno.jsonc` files: dependency parsing with
//! position tracking, `jsr:`/`npm:` version lookups via [`crate::registry::DenoRegistry`],
//! inlay hints, hover, code actions, and diagnostics — all via `deps-core`'s generic
//! handlers, with no Deno-specific handler code (FR-010).

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Position, Range};

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::DenoFormatter;
use crate::registry::DenoRegistry;
use deps_npm::NpmRegistry;

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: `node-semver`'s caret, tilde, comparison, and wildcard
/// operators — both JSR and npm specifiers resolve through this grammar (#1137).
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &['^', '~', '=', '<', '>', '*'];

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
    /// The `.npmrc` reachability policy and memoization cache (#1212) every `parse_manifest`
    /// call threads through to [`crate::parser::parse_deno_json_with_context`]. Defaulted by
    /// [`Self::new`]/[`Self::with_npm`]; set explicitly by [`Self::with_context`] so
    /// `deps_engine::setup::register_ecosystems` can share the same handles it hands
    /// `NpmEcosystem` (mirrors `deps_npm::ecosystem::NpmEcosystem`'s identical `context`
    /// field).
    context: crate::parser::DenoParseContext,
}

impl DenoEcosystem {
    /// Creates a new Deno ecosystem with the given HTTP cache, using a fresh, default
    /// [`crate::parser::DenoParseContext`] — an all-`PublicOnly`-policy, empty-cache context
    /// private to this ecosystem instance. Production use goes through [`Self::with_context`]
    /// instead.
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
            context: crate::parser::DenoParseContext::default(),
        }
    }

    /// Creates a new Deno ecosystem sharing an existing [`NpmRegistry`] instance for its
    /// `npm:`-scheme half, instead of building a private one (N4/#312), using a fresh,
    /// default [`crate::parser::DenoParseContext`].
    ///
    /// Used by tests and by `deps-lsp`'s registration when only the `deno` feature (not
    /// `npm`) is enabled; production registration with both features goes through
    /// [`Self::with_context`] instead. See [`DenoRegistry::with_npm`](crate::registry::DenoRegistry::with_npm)
    /// for what sharing the registry itself dedupes.
    #[must_use]
    pub fn with_npm(cache: Arc<deps_core::HttpCache>, npm: NpmRegistry) -> Self {
        Self {
            registry: Arc::new(DenoRegistry::with_npm(cache, npm)),
            formatter: DenoFormatter,
            context: crate::parser::DenoParseContext::default(),
        }
    }

    /// Creates a new Deno ecosystem sharing an existing [`NpmRegistry`] instance and `ctx`'s
    /// `.npmrc` reachability policy and memoization cache (#1212) — the production
    /// constructor, used by `deps_engine::setup::register_ecosystems` so a `.npmrc` file
    /// ancestor-walked once for this workspace is cached and reused across every reparse,
    /// and shared with `NpmEcosystem`'s own identical handles rather than re-read from disk
    /// independently per ecosystem.
    #[must_use]
    pub fn with_context(
        cache: Arc<deps_core::HttpCache>,
        npm: NpmRegistry,
        ctx: crate::parser::DenoParseContext,
    ) -> Self {
        Self {
            registry: Arc::new(DenoRegistry::with_npm(cache, npm)),
            formatter: DenoFormatter,
            context: ctx,
        }
    }

    /// Creates a new Deno ecosystem with `ctx`'s `.npmrc` reachability policy and memoization
    /// cache, building its own private [`NpmRegistry`] from `cache` instead of taking one
    /// (impl-critic #1 follow-up to #1212's S5 fix).
    ///
    /// For a caller that needs to thread a live context through but cannot construct an
    /// [`NpmRegistry`] value itself — `deps_engine::setup::register_ecosystems`'s
    /// deno-without-npm build configuration (`#[cfg(all(feature = "deno", not(feature =
    /// "npm")))]`), whose own `deps-npm` dependency is optional and gated behind its *own*
    /// `npm` feature (off in that configuration), so `deps_npm::NpmRegistry` is not nameable
    /// from that crate at all in that build. `deps-deno` itself always depends on `deps-npm`
    /// unconditionally, so this constructor can build the registry internally where the type
    /// is always nameable (mirrors [`Self::new`]'s identical "build our own" pattern).
    #[must_use]
    pub fn with_context_standalone(
        cache: Arc<deps_core::HttpCache>,
        ctx: crate::parser::DenoParseContext,
    ) -> Self {
        Self {
            registry: Arc::new(DenoRegistry::new(cache)),
            formatter: DenoFormatter,
            context: ctx,
        }
    }

    /// Test-only: wraps an already-constructed [`DenoRegistry`] (e.g. one built via
    /// [`DenoRegistry::with_bases_for_test`](crate::registry::DenoRegistry::with_bases_for_test)
    /// pointed at a mock server) instead of building a live-registry one (#1038).
    #[cfg(test)]
    #[cfg(feature = "lsp-responses")]
    #[must_use]
    pub(crate) fn with_registry_for_test(registry: DenoRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            formatter: DenoFormatter,
            context: crate::parser::DenoParseContext::default(),
        }
    }

    /// Completes package names by searching whichever registry the typed scheme prefix
    /// (`jsr:`/`npm:`) selects.
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

    // Position-based, gated (#593, #1136) via `SourcePolicy::can_resolve_source` — an
    // `npm:`-scheme import classified non-`Registry` (#1212, see `parser::classify_npm_imports`)
    // now correctly yields zero completions here.
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
            VERSION_OPERATOR_CHARS,
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for DenoEcosystem {}

impl Ecosystem for DenoEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Deno
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
        uri: &'a url::Url,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_deno_json_with_context(content, uri, &self.context)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
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
        // No quote strip, unlike npm/Composer: the completable text here is the JSON
        // *value* (the specifier), never the alias key, so this can't coincide with a
        // bare `jsr:`/`npm:` prefix — `DenoRegistry::search` no-ops on it harmlessly,
        // and the real work happens via `detect_completion_context` instead.
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
        no_non_registry_fixture: "Deno's non-Registry classification (parser::classify_npm_imports) only fires once a real .npmrc file resolves from disk for an npm: import's scope — the shared macro's fixture has no filesystem backing to supply one. Covered instead by parser::tests::test_npm_scoped_import_resolves_via_npmrc, which builds a real tempfile::tempdir() with a .npmrc and asserts the same gate properties end-to-end.";
    }

    // #758: the shared completion-prefix-length guard, replacing
    // test_complete_package_names_minimum_prefix (which only checked a 1-character prefix).
    #[cfg(feature = "lsp-responses")]
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

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
    // own doc comment (`node-semver`'s operator set), so an edit to one without the other
    // fails loudly instead of silently degrading completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod deno_operator_chars_conformance;
        ecosystem: "deno";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &['^', '~', '=', '<', '>', '*'];
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

    #[cfg(feature = "lsp-responses")]
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

    /// #1038: uses a mockito 404 instead of the live `jsr.io`, so a regression that makes
    /// zero requests (and so also produces an empty result) can no longer pass vacuously —
    /// `mock.assert_async()` requires the request to actually have been made.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/@this-scope/does-not-exist-12345/meta.json")
            .with_status(404)
            .create_async()
            .await;
        // A `jsr:`-scheme package must never fall through to the `npm:` half (#1038 M3):
        // a separate mock server with `.expect(0)` pins that, rather than the previous
        // unexplained `http://127.0.0.1:1` sentinel, which would have silently turned a
        // jsr->npm-fallback regression into a connect-refused error instead of a test failure.
        let mut npm_server = mockito::Server::new_async().await;
        let npm_mock = npm_server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let cache = Arc::new(deps_core::HttpCache::new());
        let npm = NpmRegistry::with_public_base_for_test(Arc::clone(&cache), npm_server.url());
        let registry =
            DenoRegistry::with_bases_for_test(Arc::clone(&cache), npm, server.url(), server.url());
        let ecosystem = DenoEcosystem::with_registry_for_test(registry);

        // Exercises `DenoRegistry`'s own jsr/npm scheme routing directly through the public
        // `complete_versions_generic_from` entry point, rather than through
        // `DenoEcosystem::complete_versions` (position-based since #1136, needing a real
        // manifest fixture this test has no other reason to build).
        let results = deps_core::completion::complete_versions_generic_from(
            ecosystem.registry.as_ref(),
            &DenoFormatter,
            &deps_core::PackageName::new("jsr:@this-scope/does-not-exist-12345"),
            &deps_core::parser::DependencySource::Registry,
            "1.0",
            VERSION_OPERATOR_CHARS,
            deps_core::FreshnessSettings::default(),
        )
        .await;
        mock.assert_async().await;
        npm_mock.assert_async().await;
        assert!(results.is_empty());
    }

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_json_dependencies` compose correctly through the real trait method on
    /// realistic multi-line content — no quote strip, unlike npm/Composer (see
    /// `DenoEcosystem::fallback_completion_prefix`'s doc for why).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = DenoEcosystem::new(cache);
        let content = "{\n  \"name\": \"test\",\n  \"imports\": {\n    \"@std/fs\": \"jsr:@std/f";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position.into()),
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

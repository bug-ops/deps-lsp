//! Composer ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for PHP/Composer projects,
//! providing LSP functionality for `composer.json` files.

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, Range};

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::ComposerFormatter;
use crate::registry::PackagistRegistry;

/// Leading version-constraint operators stripped from a completion prefix before
/// matching it against registry versions: caret `^`, tilde `~`, the comparison set
/// `>=`/`<=`/`>`/`<`/`=`, and `!=` — `formatter::ComposerFormatter::
/// version_satisfies_requirement` accepts all of these, including `!=`, which was
/// missing here (#1137). `*` covers the bare wildcard requirement; the trailing-wildcard
/// form (`"1.0.*"`) has no leading operator to strip.
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &['^', '~', '=', '<', '>', '*', '!'];

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
    /// `composer.lock` memoization cache (#1212 impl-critic follow-up) every `parse_manifest`
    /// call threads through to [`crate::parser::parse_composer_json_with_lockfile`]. Defaulted
    /// by [`Self::new`] to a private instance; set explicitly by [`Self::with_context`] so
    /// `deps_engine::setup::register_ecosystems` can share the same handle `deps-lsp`'s own
    /// in-use-version resolution reads, instead of each parsing `composer.lock` independently.
    lockfile_cache: Arc<deps_core::lockfile::LockFileCache>,
}

impl ComposerEcosystem {
    /// Creates a new Composer ecosystem with the given HTTP cache, using a fresh, private
    /// `composer.lock` memoization cache. Production use goes through [`Self::with_context`]
    /// instead.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PackagistRegistry::new(cache)),
            formatter: ComposerFormatter,
            lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        }
    }

    /// Creates a new Composer ecosystem sharing `lockfile_cache` (#1212 impl-critic follow-up)
    /// — the production constructor, used by `deps_engine::setup::register_ecosystems` so a
    /// `composer.lock` read for classification and a `composer.lock` read for in-use-version
    /// resolution hit the same mtime-keyed cache instance instead of each parsing it
    /// independently on every reparse.
    #[must_use]
    pub fn with_context(
        cache: Arc<deps_core::HttpCache>,
        lockfile_cache: Arc<deps_core::lockfile::LockFileCache>,
    ) -> Self {
        Self {
            registry: Arc::new(PackagistRegistry::new(cache)),
            formatter: ComposerFormatter,
            lockfile_cache,
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
        uri: &'a url::Url,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_composer_json_with_lockfile(
                content,
                uri,
                &self.lockfile_cache,
            )
            .await?;
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
    fn version_operator_chars(&self) -> &'static [char] {
        VERSION_OPERATOR_CHARS
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
        let (prefix, _) = extract_prefix(line, position.character);
        // A closed key or open value string both yield an empty prefix (#729) — suppress
        // explicitly rather than relying on the caller's own `prefix.is_empty()` guard.
        if prefix.is_empty() {
            return None;
        }
        Some(prefix)
    }

    fn fallback_completion_is_bare(
        &self,
        content: &str,
        position: deps_core::position::Position,
    ) -> bool {
        let Some(line) = deps_core::fallback_completion::line_at(content, position) else {
            return false;
        };
        extract_prefix(line, position.character).1
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        Some(format!("\"{}\": \"^{latest}\"", name.as_str()))
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
    #[cfg(feature = "lsp-responses")]
    use deps_core::{EcosystemConfig, VersionData};
    #[cfg(feature = "lsp-responses")]
    use std::collections::HashMap;
    #[cfg(feature = "lsp-responses")]
    use tower_lsp_server::ls_types::Position;

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
        non_registry_fixture: "composer.json" => r#"{"repositories": [{"type": "vcs", "url": "ssh://git@git.acme.internal/private.git", "only": ["acme/secretpkg"]}], "require": {"acme/secretpkg": "^1.0"}}"#;
    }

    // #1373/#1374: `composer.json`'s version-constraint grammar has no placeholder/
    // environment-variable interpolation syntax of its own, but a manifest can still carry
    // three non-rewritable forms deps-lsp must never overwrite with a literal registry
    // version — two Composer-native (`self.version`, an inline alias
    // `<branch-or-constraint> as <alias-version>`) and one from external templating
    // (`${VAR}`/`$VAR` left unexpanded, #1374 impl-critic M2) — see `ComposerFormatter`'s
    // `requirement_is_composer_unresolved` guard.
    // impl-critic M3 (#1379 follow-up): fixtures now also cover the four template forms the
    // shared `requirement_contains_template_placeholder` predicate gained for #1379 — Composer
    // inherits them for free via `requirement_is_composer_unresolved`'s delegation, but had no
    // fixture pinning that (the doc comment describing this was also stale, fixed alongside).
    deps_core::unresolved_requirement_conformance! {
        mod composer_unresolved_requirement_conformance;
        build: ComposerEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        reachable: true;
        fixture: "composer.json" =>
            r#"{"require":{
                "monolog/monolog":"self.version",
                "symfony/console":"dev-main as 1.0.0",
                "psr/log":"${PSR_LOG}",
                "guzzlehttp/guzzle":"{{ GUZZLE_VERSION }}",
                "phpunit/phpunit":"@PHPUNIT_VERSION@",
                "doctrine/orm":"%ORM_VERSION%",
                "twig/twig":"<%= TWIG_VERSION %>"
            }}"#;
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_short_prefix — also closes the missing max-length case.
    #[cfg(feature = "lsp-responses")]
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

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
    // own doc comment (`ComposerFormatter::version_satisfies_requirement`'s operator set),
    // so an edit to one without the other fails loudly instead of silently degrading
    // completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod composer_operator_chars_conformance;
        ecosystem: "composer";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &['^', '~', '=', '<', '>', '*', '!'];
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    /// #1171: end-to-end counterpart of `deps_core::completion`'s
    /// `test_complete_versions_generic_operator_stripping_composer_not_equal` — that test
    /// proves the shared helper strips a `!=` prefix against a hard-coded *copy* of
    /// Composer's operator array (`deps-core` cannot depend on `deps-composer` to reference
    /// the real one). This drives the same scenario through the real
    /// `ComposerEcosystem::generate_completions` against a mocked Packagist response,
    /// proving the actual shipped `VERSION_OPERATOR_CHARS` constant above.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_strips_not_equal_operator_against_real_registry() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        server
            .mock("GET", "/p2/monolog/monolog.json")
            .with_status(200)
            .with_body(
                r#"{"packages": {"monolog/monolog": [
                    {"version": "2.0.0", "version_normalized": "2.0.0.0", "abandoned": null},
                    {"version": "1.0.0", "version_normalized": "1.0.0.0"}
                ]}}"#,
                // "1.0.0" doesn't match the "!=2.0"-stripped "2.0" prefix — its presence
                // proves the assertion below reflects filtering, not just an unfiltered list.
            )
            .create_async()
            .await;

        let ecosystem = ComposerEcosystem {
            registry: Arc::new(PackagistRegistry::with_base(
                Arc::new(deps_core::HttpCache::new()),
                base,
            )),
            formatter: ComposerFormatter,
            lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        };
        let uri = deps_core::test_util::test_uri("/test/composer.json");
        let content = r#"{"require": {"monolog/monolog": "!=2.0"}}"#;
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let dep = &parse_result.dependencies()[0];
        let position = dep.version_range().unwrap().end.into();

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert_eq!(completions.items.len(), 1);
        assert_eq!(completions.items[0].label, "2.0.0 (latest)");
    }

    /// #1433: hover, completion, and code actions must all agree with diagnostics about
    /// what "latest" means for the same dependency once the manifest sets
    /// `minimum-stability: alpha` — reproduces the issue's live repro (Packagist's newest
    /// tag is a `v`-prefixed alpha, the newest *stable* release is older).
    #[cfg(feature = "lsp-responses")]
    mod minimum_stability_selection_context_tests {
        use super::*;
        use deps_core::VersionData;

        async fn composer_ecosystem_with_alpha_and_stable(
            server: &mut mockito::ServerGuard,
        ) -> ComposerEcosystem {
            server
                .mock("GET", "/p2/twig/twig.json")
                .with_status(200)
                .with_body(
                    r#"{"packages": {"twig/twig": [
                        {"version": "v4.0.0-alpha1", "version_normalized": "4.0.0.0-alpha1", "abandoned": null},
                        {"version": "v3.29.0", "version_normalized": "3.29.0.0"}
                    ]}}"#,
                )
                .create_async()
                .await;

            ComposerEcosystem {
                registry: Arc::new(PackagistRegistry::with_base(
                    Arc::new(deps_core::HttpCache::new()),
                    server.url(),
                )),
                formatter: ComposerFormatter,
                lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
            }
        }

        const MANIFEST: &str = r#"{
  "minimum-stability": "alpha",
  "require": {
    "twig/twig": "3.28.0"
  }
}"#;

        /// #1433: hover's `**Latest**` line must report the alpha version, matching
        /// diagnostics/inlay-hints' own `minimum-stability`-aware pick.
        #[tokio::test]
        async fn test_generate_hover_respects_manifest_minimum_stability() {
            let mut server = mockito::Server::new_async().await;
            let ecosystem = composer_ecosystem_with_alpha_and_stable(&mut server).await;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = ecosystem.parse_manifest(MANIFEST, &uri).await.unwrap();
            let dep = &parse_result.dependencies()[0];
            let position = dep.version_range().unwrap().start.into();

            let hover = ecosystem
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    VersionData::new(&HashMap::new(), &HashMap::new()),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover must fire on the version token");

            assert!(
                hover.markdown().contains("4.0.0-alpha1"),
                "hover must report the alpha version as latest under minimum-stability: \
                 alpha, got: {}",
                hover.markdown()
            );
        }

        /// #1433: completion's "(latest)" tag must land on the alpha version. #1435: the
        /// item's insert text must stay unprefixed (matching the requirement already typed,
        /// `"3.28.0"`) even though the label legitimately shows Packagist's real, `v`-prefixed
        /// tag text — `label` is informational, `insert_text` is what gets spliced in.
        #[tokio::test]
        async fn test_generate_completions_respects_manifest_minimum_stability() {
            let mut server = mockito::Server::new_async().await;
            let ecosystem = composer_ecosystem_with_alpha_and_stable(&mut server).await;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = ecosystem.parse_manifest(MANIFEST, &uri).await.unwrap();
            let dep = &parse_result.dependencies()[0];
            let position = dep.version_range().unwrap().end.into();

            let completions = ecosystem
                .generate_completions(
                    parse_result.as_ref(),
                    position,
                    MANIFEST,
                    deps_core::FreshnessSettings::default(),
                )
                .await;

            let latest_item = completions
                .items
                .iter()
                .find(|item| item.label == "v4.0.0-alpha1 (latest)")
                .unwrap_or_else(|| {
                    panic!(
                        "completion must tag the alpha version as latest under \
                         minimum-stability: alpha, got: {:?}",
                        completions
                            .items
                            .iter()
                            .map(|i| &i.label)
                            .collect::<Vec<_>>()
                    )
                });
            assert_eq!(
                latest_item.insert_text.as_deref(),
                Some("4.0.0-alpha1"),
                "insert text must stay unprefixed, matching the already-typed requirement, \
                 not Packagist's raw v-tagged text (#1435)"
            );
        }

        /// #1433: the "update to latest" code action must target the alpha version.
        #[tokio::test]
        async fn test_generate_code_actions_respects_manifest_minimum_stability() {
            let mut server = mockito::Server::new_async().await;
            let ecosystem = composer_ecosystem_with_alpha_and_stable(&mut server).await;
            let uri = deps_core::test_util::test_uri("/test/composer.json");
            let parse_result = ecosystem.parse_manifest(MANIFEST, &uri).await.unwrap();
            let dep = &parse_result.dependencies()[0];
            let position = dep.version_range().unwrap().start.into();

            let actions = ecosystem
                .generate_code_actions(
                    parse_result.as_ref(),
                    position,
                    &uri,
                    VersionData::new(&HashMap::new(), &HashMap::new()),
                    MANIFEST,
                )
                .await;

            // Exact match, not `.contains` (impl-critic M1): the manifest's own requirement
            // ("3.28.0") is unprefixed, so this also end-to-end-proves #1435's fix through
            // `generate_code_actions` — a `.contains("4.0.0-alpha1")` check would pass just
            // as well for the unfixed, `v`-prefixed `"v4.0.0-alpha1"`.
            let latest_action_targets_alpha = actions.iter().any(|action| {
                action
                    .edit
                    .as_ref()
                    .and_then(|edit| edit.changes.as_ref())
                    .into_iter()
                    .flat_map(|changes| changes.values())
                    .flatten()
                    .any(|edit| edit.new_text == "4.0.0-alpha1")
            });
            assert!(
                latest_action_targets_alpha,
                "an update-version code action must target the unprefixed alpha version \
                 under minimum-stability: alpha, got: {actions:?}"
            );
        }
    }

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_json_dependencies` + quote-stripping compose correctly through the real
    /// trait method on realistic multi-line content.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/mono";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            ecosystem.fallback_completion_prefix(content, position.into()),
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
        // #729 critic S1: a fully-closed key (quote parity even) is NOT an open string —
        // bare-inserting there would duplicate the closed key's quote.
        let line = "    \"monolog/monolog\"";
        assert_eq!(extract_prefix(line, line.len() as u32), ("", false));
    }

    /// #729: a closed key (`"monolog/monolog"`, cursor past both quotes) must
    /// suppress the completion entirely — the same "no safe text to offer" outcome as
    /// Maven's non-`artifactId` open tag — which this trait method achieves by
    /// returning `None`, same as "no completable position at all".
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_closed_key_is_suppressed() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/monolog\"";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            None
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_inside_open_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    \"monolog/mono";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(eco.fallback_completion_is_bare(content, position.into()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_no_open_key() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = ComposerEcosystem::new(cache);
        let content = "{\n  \"require\": {\n    monolog";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
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

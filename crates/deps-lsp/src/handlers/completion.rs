//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::EcosystemId;
use deps_core::completion::{COMPLETION_SEARCH_TIMEOUT, is_valid_completion_prefix_len};
use deps_core::{is_safe_package_name, is_safe_version_string, lsp_helpers::warn_rejected_value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionList, CompletionParams, CompletionResponse,
    InsertTextFormat,
};

// Completion is keystroke-driven and must stay responsive, so registry-backed
// completion work gets its own short timeout instead of sharing the 30s HTTP client
// timeout used elsewhere ([`COMPLETION_SEARCH_TIMEOUT`]).
//
// Shared with `deps_core::completion` (rather than kept local) because
// registry-backed completion paths that retry internally on failure (e.g.
// `deps-maven`'s `search_typed`, #274) must size their own retry budget against
// this same value — see `deps_core::completion::COMPLETION_SEARCH_TIMEOUT`'s doc.

/// Handles completion requests.
///
/// Delegates to the appropriate ecosystem implementation based on the document type.
/// Falls back to text-based completion when TOML parsing fails (user is still typing).
pub async fn handle_completion(
    state: Arc<ServerState>,
    params: CompletionParams,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Option<CompletionResponse> {
    let uri = &params.text_document_position.text_document.uri;
    let position = params.text_document_position.position;

    tracing::info!(
        "completion request: uri={:?}, line={}, character={}",
        uri,
        position.line,
        position.character
    );

    // Snapshot before any document lookup, matching hover.rs/diagnostics.rs's ordering —
    // this acquires the config RwLock before the DashMap shard guard, never the reverse.
    let freshness = { config.read().await.freshness.to_settings() };

    // Resolved once, from the URI alone via `get_for_uri` (the same routing
    // `handle_document_open` uses), rather than from the loaded document's
    // `ecosystem_id` — that would only be available *after* the document-load and
    // document-lookup early returns below. `is_some_and` (not `?`) so an
    // unrecognized URI falls through to `false` (matching every ecosystem's
    // default) rather than short-circuiting this function.
    let package_search_is_incomplete = state
        .ecosystem_registry
        .get_for_uri(uri)
        .is_some_and(|e| e.package_search_is_incomplete());

    // Shared by the document-load and document-lookup early returns below, so
    // both report `isIncomplete` consistently for an ecosystem whose package-name
    // search (the only kind of completion either path could otherwise have
    // produced, via `fallback_completion`) may be a truncated view of a larger
    // candidate set (#419 S1) — `None` would serialize as LSP `null`, which
    // carries no `isIncomplete` and leaves the client with nothing to invalidate
    // on the next keystroke.
    let context_less_response = || {
        if package_search_is_incomplete {
            Some(CompletionResponse::List(CompletionList {
                is_incomplete: true,
                items: vec![],
            }))
        } else {
            None
        }
    };

    // Check if document is loaded, if not try to load with short timeout
    // Completion is latency-critical, so we use a 200ms timeout
    if state.get_document(uri).is_none() {
        tracing::info!("completion: document not loaded, loading from disk");

        // Try to load with short timeout (200ms)
        let load_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            ensure_document_loaded(uri, Arc::clone(&state), client.clone(), Arc::clone(&config)),
        )
        .await;

        match load_result {
            Ok(true) => {
                // Document loaded successfully, continue with completion
                tracing::debug!("completion: document loaded successfully");
            }
            Ok(false) | Err(_) => {
                // Load failed or timed out, return empty completions
                tracing::warn!("completion: document load failed or timed out");
                return context_less_response();
            }
        }
    }

    // Own everything needed from the document in a single shard acquisition, then
    // release the `Ref` immediately: two separate acquisitions (one for `content`, a
    // later one for `parse_result`) would let a concurrent `didChange` land in
    // between, pairing a `parse_result` with `content` from a different document
    // revision — `generate_completions` correlates the two (e.g. `extract_prefix`
    // slicing `content` at a range taken from `parse_result`), so a torn pair risks
    // wrong or out-of-bounds-guarded-empty completions (#319 review).
    // `with_document` makes releasing the guard structural rather than a convention
    // to remember (#333).
    let Some((ecosystem_id, ecosystem_kind, content, parse_result)) =
        state.with_document(uri, |doc| {
            (
                doc.ecosystem_id(),
                doc.ecosystem,
                doc.content.clone(),
                doc.parse_result_arc(),
            )
        })
    else {
        tracing::warn!("completion: document not found: {:?}", uri);
        return context_less_response();
    };

    tracing::info!(
        "completion: ecosystem={}, has_parse_result={}",
        ecosystem_id,
        parse_result.is_some()
    );

    // Try parse_result first, fallback to text-based detection. `is_incomplete` is
    // the per-call signal `generate_completions` computed for the actual completion
    // context it served (#427). Whenever `fallback_completion` actually runs — the
    // primary result was empty, or there was no `parse_result` to call
    // `generate_completions` with at all — it is OR'd with
    // `ecosystem.package_search_is_incomplete()`: `fallback_completion` always
    // performs a raw package-name search via `Registry::search` regardless of the
    // primary context, so it inherits the primary's `is_incomplete` only by
    // coincidence, not because the two searches share a completeness signal.
    let (items, is_incomplete) = if let Some(parse_result) = parse_result {
        match state.ecosystem_registry.get(ecosystem_id) {
            Some(ecosystem) => {
                // The DashMap shard `Ref` was already dropped above, before this
                // timeout-bound await: the search can run for up to
                // `COMPLETION_SEARCH_TIMEOUT`, and holding the guard that long would
                // block a concurrent `documents.get_mut` on the same shard for the
                // duration (#319).
                let completion_result = tokio::time::timeout(
                    COMPLETION_SEARCH_TIMEOUT,
                    ecosystem.generate_completions(
                        parse_result.as_ref(),
                        position,
                        &content,
                        freshness,
                    ),
                )
                .await;

                match completion_result {
                    // Ecosystem returned no completions: try fallback, since this
                    // handles the case where the user is typing a NEW package name.
                    Ok(completions) if completions.items.is_empty() => {
                        tracing::info!("completion: ecosystem returned empty, trying fallback");
                        let fallback_items =
                            fallback_completion(&state, ecosystem_kind, position, &content).await;
                        (
                            fallback_items,
                            completions.is_incomplete || ecosystem.package_search_is_incomplete(),
                        )
                    }
                    Ok(completions) => (completions.items, completions.is_incomplete),
                    // Timed out, not genuinely empty: the registry is slow right now,
                    // so a fallback search against the same registry would likely
                    // time out too. Skip it instead of doubling the worst-case
                    // latency.
                    Err(_) => {
                        tracing::warn!(
                            "completion: generate_completions timed out after \
                             {}s, skipping fallback search",
                            COMPLETION_SEARCH_TIMEOUT.as_secs()
                        );
                        (vec![], false)
                    }
                }
            }
            None => {
                tracing::warn!("completion: ecosystem not found for id: {ecosystem_id}");
                (vec![], false)
            }
        }
    } else {
        // Fallback: detect context from raw text. No `parse_result` means
        // `generate_completions` was never called, so `package_search_is_incomplete`
        // (already resolved for this URI's ecosystem above) is the only signal
        // available — matches the every-`didChange`-with-a-parse-failure case
        // (`document/lifecycle.rs`'s `new_without_parse_result`), exactly the
        // mid-typing state for a new package name.
        (
            fallback_completion(&state, ecosystem_kind, position, &content).await,
            package_search_is_incomplete,
        )
    };

    tracing::info!("completion: returning {} items", items.len());

    if is_incomplete {
        // Must still be a `List` when `items` is empty: `None` serializes as LSP
        // `null`, which carries no `isIncomplete` and leaves the client with
        // nothing to invalidate on the next keystroke (#419 C1) — this is the
        // cold-start-returns-empty case PyPI's search index relies on.
        Some(CompletionResponse::List(CompletionList {
            is_incomplete: true,
            items,
        }))
    } else if items.is_empty() {
        None
    } else {
        Some(CompletionResponse::Array(items))
    }
}

/// Fallback completion when document parsing fails.
///
/// Delegates the raw-text section/prefix detection entirely to the resolved
/// ecosystem's [`deps_core::Ecosystem::fallback_completion_prefix`] (issue #722) — the
/// per-ecosystem section-boundary and manifest-syntax-stripping heuristics that used to
/// live here now live with each ecosystem crate. This function only owns the two
/// ecosystem-agnostic pieces: resolving the ecosystem, and the length (2-200 chars,
/// [`is_valid_completion_prefix_len`])/no-`=` guard on whatever prefix comes back.
///
/// The ecosystem lookup now happens *before* the section/prefix check (previously
/// after) — same return value either way (empty vec), only log ordering changes.
async fn fallback_completion(
    state: &ServerState,
    ecosystem_kind: EcosystemId,
    position: tower_lsp_server::ls_types::Position,
    content: &str,
) -> Vec<CompletionItem> {
    tracing::info!(
        "fallback_completion: starting for ecosystem={}",
        ecosystem_kind
    );

    let Some(ecosystem) = state.ecosystem_registry.get(ecosystem_kind.id()) else {
        tracing::warn!(
            "fallback_completion: ecosystem not found for id: {}",
            ecosystem_kind
        );
        return vec![];
    };

    // Collapses this file's former separate "line not found" / "not in dependencies
    // section" log lines into one — both are now internal to the ecosystem's own
    // `fallback_completion_prefix`, which has no completable position to report either
    // way.
    let Some(prefix) = ecosystem.fallback_completion_prefix(content, position) else {
        tracing::info!("fallback_completion: no completable prefix at this position");
        return vec![];
    };

    // Shares the same 2-200 char guard every primary (parsed-AST) completion path
    // uses (`is_valid_completion_prefix_len`), rather than hand-rolling only the
    // lower half of it: an unbounded prefix here would flow straight into the
    // tracing logs below and into `registry.search`'s outbound request/cache key
    // (#739).
    if prefix.contains('=') || !is_valid_completion_prefix_len(prefix) {
        tracing::info!("fallback_completion: prefix rejected (contains =, or invalid length)");
        return vec![];
    }

    // Whether the cursor sits inside manifest markup that's already open (an XML
    // tag or attribute value) and can only safely hold the bare candidate text,
    // rather than `completion_insert_text`'s normal full snippet — inserting the
    // full snippet there would nest a duplicate copy of the markup already open
    // around the cursor (#724/#728). Decided once per call, from the same
    // `content`/`position` `fallback_completion_prefix` used, and applied to every
    // result.
    let bare = ecosystem.fallback_completion_is_bare(content, position);

    tracing::info!(
        "fallback_completion: prefix = {:?}, bare = {}",
        deps_core::lsp_helpers::truncate_for_diagnostic(prefix, 64),
        bare
    );

    search_packages(ecosystem.as_ref(), prefix, bare).await
}

/// Searches for packages and returns completion items.
///
/// Bounded by [`deps_core::completion::COMPLETION_SEARCH_TIMEOUT`] as a direct, in-place timeout (not a
/// detached `tokio::spawn`): this keeps the search cancellable by the LSP server's own
/// `$/cancelRequest` handling, which wraps the whole request future and aborts it on
/// cancellation — a detached task would sit outside that abort and keep the request's
/// registry connection open regardless.
async fn search_packages(
    ecosystem: &dyn deps_core::Ecosystem,
    query: &str,
    bare: bool,
) -> Vec<CompletionItem> {
    tracing::info!(
        "search_packages: query={:?}, ecosystem={}",
        deps_core::lsp_helpers::truncate_for_diagnostic(query, 64),
        ecosystem.id()
    );

    let registry = ecosystem.registry();
    let results =
        match tokio::time::timeout(COMPLETION_SEARCH_TIMEOUT, registry.search(query, 50)).await {
            Ok(Ok(r)) => {
                tracing::info!("search_packages: found {} results", r.len());
                r
            }
            Ok(Err(e)) => {
                tracing::warn!("search_packages: search failed: {}", e);
                return vec![];
            }
            Err(_) => {
                tracing::warn!(
                    "search_packages: timed out after {}s",
                    COMPLETION_SEARCH_TIMEOUT.as_secs()
                );
                return vec![];
            }
        };

    // Convert search results to completion items
    results
        .iter()
        .filter_map(|metadata| create_package_completion_item(metadata.as_ref(), ecosystem, bare))
        .collect()
}

/// Creates a completion item for a package.
///
/// The insert text mirrors the ecosystem's own manifest syntax, via
/// [`deps_core::Ecosystem::completion_insert_text`] — required, no default, so a new
/// ecosystem must supply its own snippet instead of silently inheriting another
/// ecosystem's syntax (see issue #118).
///
/// Returns `None` when `latest` (whenever non-empty) fails
/// [`is_safe_version_string`], `name` fails [`is_safe_package_name`], or the
/// ecosystem's own `completion_insert_text`/`fallback_bare_insert_text` rejects the
/// metadata for an ecosystem-specific reason (a Maven `groupId`/`artifactId`
/// breakout, an unsafe Swift repository URL, GitHub Actions' `owner/repo` shape).
/// `metadata` comes straight from a registry search response, so a
/// malicious/compromised registry must not be able to write structural characters
/// into the manifest this text is inserted into. The two upfront gates run here,
/// once, rather than being re-implemented by every `completion_insert_text`/
/// `fallback_bare_insert_text` override — see those methods' docs.
///
/// `bare` (from `fallback_completion`'s `Ecosystem::fallback_completion_is_bare`
/// call) selects which of the two ecosystem hooks builds `insert_text`: `true`
/// routes to `Ecosystem::fallback_bare_insert_text` (the cursor already sits inside
/// open manifest markup that can only safely hold the bare candidate text — #724/
/// #728), `false` to `Ecosystem::completion_insert_text` (the normal full snippet).
fn create_package_completion_item(
    metadata: &dyn deps_core::Metadata,
    ecosystem: &dyn deps_core::Ecosystem,
    bare: bool,
) -> Option<CompletionItem> {
    let name = metadata.name();
    let latest = metadata.latest_version().as_str();
    let description = metadata.description();

    if !is_safe_package_name(name.as_str()) {
        warn_rejected_value(
            "is_safe_package_name",
            "package name completion item",
            name.as_str(),
        );
        return None;
    }

    if !latest.is_empty() && !is_safe_version_string(latest) {
        warn_rejected_value(
            "is_safe_version_string",
            "package name completion item",
            latest,
        );
        return None;
    }

    let insert_text = if bare {
        ecosystem.fallback_bare_insert_text(metadata)?
    } else {
        ecosystem.completion_insert_text(metadata)?
    };

    // Build detail text
    let detail = if latest.is_empty() {
        None
    } else {
        Some(format!("Latest: {latest}"))
    };

    Some(CompletionItem {
        label: name.to_string(),
        kind: Some(CompletionItemKind::MODULE),
        detail,
        documentation: description
            .map(|d| tower_lsp_server::ls_types::Documentation::String(d.into())),
        insert_text: Some(insert_text),
        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{
        Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    struct MockFormatter;
    impl deps_core::PackageNaming for MockFormatter {}

    impl deps_core::PackageRendering for MockFormatter {
        fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &deps_core::PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    impl deps_core::RequirementResolution for MockFormatter {}
    impl deps_core::DiagnosticMessages for MockFormatter {}
    impl deps_core::DiagnosticPolicy for MockFormatter {}
    impl deps_core::SourcePolicy for MockFormatter {}
    impl deps_core::OsvNaming for MockFormatter {}

    /// Generic test double for [`deps_core::Ecosystem`], configurable per test so
    /// `fallback_completion`/`search_packages` tests can observe (or forbid) a
    /// registry search, and control the resulting completion item's insert text,
    /// without hitting the network or depending on any real ecosystem's raw-text
    /// syntax — per-ecosystem section/prefix/insert-text syntax is now covered
    /// directly in each owning ecosystem crate (issue #722).
    struct MockEcosystem {
        id: &'static str,
        registry: Arc<dyn deps_core::Registry>,
        /// Canned return value for `fallback_completion_prefix`, ignoring
        /// `content`/`position` entirely.
        fallback_prefix: Option<&'static str>,
        insert_text: fn(&dyn deps_core::Metadata) -> Option<String>,
        /// Canned return value for `fallback_completion_is_bare`, ignoring
        /// `content`/`position` entirely.
        is_bare: bool,
        bare_insert_text: fn(&dyn deps_core::Metadata) -> Option<String>,
    }
    impl deps_core::ecosystem::private::Sealed for MockEcosystem {}
    impl deps_core::Ecosystem for MockEcosystem {
        fn id(&self) -> &'static str {
            self.id
        }
        fn display_name(&self) -> &'static str {
            self.id
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &["Cargo.toml"]
        }
        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a tower_lsp_server::ls_types::Uri,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>>
        {
            Box::pin(async move { unimplemented!() })
        }
        fn registry(&self) -> Arc<dyn deps_core::Registry> {
            Arc::clone(&self.registry)
        }
        fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter {
            &MockFormatter
        }
        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn deps_core::ParseResult,
            _position: tower_lsp_server::ls_types::Position,
            _content: &'a str,
            _freshness: deps_core::FreshnessSettings,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions> {
            Box::pin(async move { unimplemented!() })
        }
        fn fallback_completion_prefix<'a>(
            &self,
            _content: &'a str,
            _position: tower_lsp_server::ls_types::Position,
        ) -> Option<&'a str> {
            self.fallback_prefix
        }
        fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
            (self.insert_text)(metadata)
        }
        fn fallback_completion_is_bare(
            &self,
            _content: &str,
            _position: tower_lsp_server::ls_types::Position,
        ) -> bool {
            self.is_bare
        }
        fn fallback_bare_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
            (self.bare_insert_text)(metadata)
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// Default `completion_insert_text`/`fallback_bare_insert_text` for
    /// [`MockEcosystem`]: the bare package name, sufficient whenever a test only
    /// asserts on the completion item's `label` or on whether a search happened at
    /// all, not on the inserted snippet's syntax.
    fn default_insert_text(metadata: &dyn deps_core::Metadata) -> Option<String> {
        Some(metadata.name().to_string())
    }

    /// Builds a [`MockEcosystem`] with `id`, routing registry search through
    /// `registry`, using [`default_insert_text`].
    fn mock_ecosystem(
        id: &'static str,
        registry: Arc<dyn deps_core::Registry>,
    ) -> Arc<dyn deps_core::Ecosystem> {
        Arc::new(MockEcosystem {
            id,
            registry,
            fallback_prefix: None,
            insert_text: default_insert_text,
            is_bare: false,
            bare_insert_text: default_insert_text,
        })
    }

    /// Builds a `ServerState` whose `"cargo"` ecosystem entry is a [`MockEcosystem`]
    /// routing registry search through `registry` and returning `fallback_prefix`
    /// (verbatim) from `fallback_completion_prefix`.
    fn mock_cargo_state(
        registry: Arc<dyn deps_core::Registry>,
        fallback_prefix: Option<&'static str>,
    ) -> ServerState {
        let state = ServerState::new();
        state.ecosystem_registry.register(Arc::new(MockEcosystem {
            id: "cargo",
            registry,
            fallback_prefix,
            insert_text: default_insert_text,
            is_bare: false,
            bare_insert_text: default_insert_text,
        }));
        state
    }

    #[tokio::test]
    async fn test_completion_returns_empty_for_missing_document() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // With cold start support, missing documents trigger background load and
        // return empty completions for the first request, collapsing to `None`.
        assert!(result.is_none());
    }

    /// #419 S1 regression, still required after #427: the document-not-loaded/
    /// load-failed early return never reaches `generate_completions` — there is no
    /// completion context yet to compute a precise per-call `is_incomplete` from
    /// (see [`Completions`](deps_core::completion::Completions)) — but it must still
    /// report `isIncomplete: true` for an ecosystem whose package-name search (the
    /// only kind `fallback_completion` could otherwise have produced) is truncated,
    /// via [`Ecosystem::package_search_is_incomplete`]. `None` serializes as LSP
    /// `null`, which carries no `isIncomplete` and would leave the client with
    /// nothing to invalidate on the next keystroke.
    #[tokio::test]
    async fn test_completion_missing_document_reports_incomplete_for_flagged_ecosystem() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter, Metadata,
            OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::Uri;

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for `PypiEcosystem`: overrides `package_search_is_incomplete`
        /// the same way, and `generate_completions` is deliberately `unimplemented!()`
        /// since this test never lets it run.
        struct IncompleteEcosystem;
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn package_search_is_incomplete(&self) -> bool {
                true
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                Box::pin(async move { unimplemented!() })
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        state
            .ecosystem_registry
            .register(Arc::new(IncompleteEcosystem));
        // Deliberately never inserted into `state.documents` — the document-load
        // path below must time out/fail against a nonexistent file, exactly the
        // `test_completion_returns_empty_for_missing_document` shape.
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        match result {
            Some(CompletionResponse::List(list)) => {
                assert!(list.is_incomplete);
                assert!(list.items.is_empty());
            }
            other => panic!("expected List{{is_incomplete:true, items:[]}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let content = "[dependencies]\nserde = \"1.0\"".to_string();

        // Parse the manifest to get a proper parse result
        let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();

        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 9),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should return Some or None based on ecosystem implementation
        // We don't test the actual completions here as that's ecosystem-specific
        let (client, config) = create_test_client_and_config();
        let _result = handle_completion(state, params, client, config).await;
        // Just verify it doesn't panic - actual completion logic is in ecosystem
    }

    /// #319 liveness regression: `handle_completion` must release the DashMap shard
    /// `Ref` on the document *before* entering the `COMPLETION_SEARCH_TIMEOUT`-bounded
    /// await, so a concurrent `documents.get_mut` on the same URI (e.g. a `didChange`)
    /// is never blocked behind an in-flight (or stuck) registry-backed search.
    ///
    /// `BlockingEcosystem::generate_completions` waits on a `Barrier` before blocking
    /// forever (`std::future::pending`), standing in for a registry call that never
    /// returns — the worst case for a shard `Ref` held across the search. The test
    /// only proceeds to race the writer once that future has demonstrably started
    /// executing (via the barrier), which — pre-fix — would still be *after* the old
    /// code's `let doc = state.get_document(uri)?;` acquisition but *before* its
    /// `drop(doc)`, since that drop ran only once the whole timeout resolved. A
    /// concurrent write racing here would previously deadlock against the `parking_lot`
    /// shard guard for the life of the (never-resolving) search; post-fix it must
    /// complete almost immediately, since the `Ref` was already dropped before the
    /// search was ever awaited.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_document_write_not_blocked_by_in_flight_completion_search() {
        use crate::test_utils::blocking_ecosystem::{
            BlockingEcosystem, BlockingHook, MockParseResult,
        };
        use deps_core::ParseResult;
        use tokio::sync::Barrier;

        let state = Arc::new(ServerState::new());
        let started = Arc::new(Barrier::new(2));
        state
            .ecosystem_registry
            .register(Arc::new(BlockingEcosystem {
                started: Arc::clone(&started),
                hook: BlockingHook::Completions,
            }));

        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let (client, config) = create_test_client_and_config();

        let completion_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                let params = CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri },
                        position: Position::new(1, 9),
                    },
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                    context: None,
                };
                handle_completion(state, params, client, config).await
            }
        });

        // Block until `generate_completions` has actually started executing — i.e.
        // `handle_completion` has reached (and is now inside) the
        // `COMPLETION_SEARCH_TIMEOUT`-bounded await — before racing the writer below.
        started.wait().await;

        // Spawned onto its own task (rather than awaited inline) deliberately:
        // `DashMap::get_mut` blocks the OS thread synchronously on a `parking_lot`
        // lock, with no `.await` point of its own. Wrapping that blocking call
        // directly in `tokio::time::timeout` would not work — a `Future::poll` that
        // never returns can't be preempted by a sibling timer that only fires between
        // polls. Spawning it gives the *join* a real async yield point, so the
        // `timeout` below can race against it and fire even while the spawned task
        // sits blocked on the shard lock.
        let write_task = tokio::spawn({
            let state = Arc::clone(&state);
            let uri = uri.clone();
            async move {
                state.documents.get_mut(&uri).unwrap().set_loading();
            }
        });
        let write_result =
            tokio::time::timeout(std::time::Duration::from_millis(500), write_task).await;

        completion_task.abort();

        assert!(
            write_result.is_ok(),
            "#319 regression: a concurrent documents.get_mut on the same URI must not \
             block on an in-flight completion search — the DashMap shard Ref must be \
             dropped before the COMPLETION_SEARCH_TIMEOUT-bounded await, not after it"
        );
    }

    /// Issue #227 tester gap: `build_version_completion`'s `label_details`
    /// present/absent-when-`freshness.enabled`-toggles behavior is already unit-tested
    /// directly in `deps_core::completion` — this test covers the piece that isn't: that
    /// `handle_completion` (`completion.rs:47`) re-reads `config.freshness` on *every*
    /// call, so a `workspace/didChangeConfiguration`-driven config update (simulated here
    /// by writing directly to the shared `Arc<RwLock<DepsConfig>>`, exactly what
    /// `Backend::did_change_configuration` does) changes completion's age-suffix presence
    /// on the very next request, with no server restart and no re-opening the document.
    #[tokio::test]
    async fn test_completion_freshness_enabled_live_reload_changes_label_details_on_next_request() {
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            Metadata, OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use std::path::Path;
        use tower_lsp_server::ls_types::{CompletionItemLabelDetails, Uri};

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for a real ecosystem's `generate_completions`, echoing whatever
        /// `freshness.enabled` it was called with into `label_details` — exactly the
        /// signal real ecosystems derive from `build_version_completion`, without
        /// needing a real registry fetch or parsed manifest.
        struct FreshnessEchoEcosystem;
        impl Sealed for FreshnessEchoEcosystem {}
        impl Ecosystem for FreshnessEchoEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move {
                    vec![CompletionItem {
                        label: "1.0.0".to_string(),
                        kind: Some(CompletionItemKind::VALUE),
                        label_details: freshness.enabled.then(|| CompletionItemLabelDetails {
                            detail: Some("  1 hour ago".to_string()),
                            description: None,
                        }),
                        ..Default::default()
                    }]
                    .into()
                })
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        // Overwrites the real Cargo ecosystem for this state instance only.
        state
            .ecosystem_registry
            .register(Arc::new(FreshnessEchoEcosystem));
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = || CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position::new(0, 0),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        assert!(
            config.read().await.freshness.enabled,
            "default config ships freshness enabled"
        );

        let before = handle_completion(
            Arc::clone(&state),
            params(),
            client.clone(),
            Arc::clone(&config),
        )
        .await
        .expect("completion response");
        let CompletionResponse::Array(items) = before else {
            panic!("expected an array response");
        };
        assert!(
            items[0].label_details.is_some(),
            "freshness enabled by default: label_details must be present"
        );

        // Exactly what `Backend::did_change_configuration` does to the stored config —
        // no document reload, no server restart.
        config.write().await.freshness.enabled = false;

        let after = handle_completion(state, params(), client, config)
            .await
            .expect("completion response");
        let CompletionResponse::Array(items) = after else {
            panic!("expected an array response");
        };
        assert!(
            items[0].label_details.is_none(),
            "freshness disabled via live-reload: label_details must disappear on the very \
             next completion request"
        );
    }

    #[tokio::test]
    async fn test_fallback_triggered_when_parse_fails() {
        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        // Malformed content that will fail to parse
        let content = r"[dependencies]
ser"
        .to_string();

        // Create document without parse result (simulating parse failure)
        let doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content.clone());
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 3), // After "ser"
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        // Should use fallback completion (won't panic, may return empty if search fails)
        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
        // Just verify it doesn't panic - actual results depend on registry availability
        // In a real scenario with mocked registry, we'd verify it returns search results
        drop(result);
    }

    /// A single CJK character is 3 bytes, so a byte-length guard `prefix.len() < 2`
    /// would wrongly let it reach the registry; `search` panics here so the test fails
    /// loudly if the char-count guard regresses instead of silently returning empty
    /// either way.
    #[tokio::test]
    async fn test_fallback_completion_rejects_single_cjk_char_prefix() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct PanicsIfSearchedRegistry;
        impl Registry for PanicsIfSearchedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                panic!("guard must short-circuit before reaching registry search");
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = mock_cargo_state(Arc::new(PanicsIfSearchedRegistry), Some("日"));
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(1, 1), "unused").await;
        assert!(items.is_empty());
    }

    /// #739 regression: the fallback path used to hand-roll only the lower half of
    /// [`is_valid_completion_prefix_len`]'s guard (`< 2 chars`), dropping its 200-char
    /// upper bound entirely — an unbounded prefix (e.g. from one huge malformed
    /// manifest line) would then flow into logging and into `registry.search`'s
    /// outbound request/cache key. `search` panics here so the test fails loudly if
    /// the upper bound regresses.
    #[tokio::test]
    async fn test_fallback_completion_rejects_prefix_over_200_chars() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct PanicsIfSearchedRegistry;
        impl Registry for PanicsIfSearchedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                panic!("guard must short-circuit before reaching registry search");
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let long_prefix: &'static str = Box::leak("a".repeat(201).into_boxed_str());
        let state = mock_cargo_state(Arc::new(PanicsIfSearchedRegistry), Some(long_prefix));
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(0, 0), "unused").await;
        assert!(items.is_empty());
    }

    /// M2 (critic, #739 follow-up): the 201-char rejection test above alone would still
    /// pass if the guard regressed from the inclusive `(2..=200)` to an exclusive
    /// `(2..200)` range — this pins the boundary from the other side, asserting a prefix
    /// of exactly 200 chars is still accepted and reaches the registry.
    #[tokio::test]
    async fn test_fallback_completion_accepts_prefix_at_200_char_boundary() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

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

        struct StubRegistry;
        impl Registry for StubRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("serde"),
                        latest_version: "1.0.0".into(),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let boundary_prefix: &'static str = Box::leak("a".repeat(200).into_boxed_str());
        let state = mock_cargo_state(Arc::new(StubRegistry), Some(boundary_prefix));
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(0, 0), "unused").await;
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn test_fallback_completion_passes_two_char_prefixes_to_search() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct StubRegistry;
        impl Registry for StubRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("serde"),
                        latest_version: "1.0.0".into(),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        // Two CJK characters: byte count (6) and char count (2) agree, so this was
        // never affected by the byte-length bug, but it must keep passing through to
        // search.
        let cjk_state = mock_cargo_state(Arc::new(StubRegistry), Some("日本"));
        let cjk_items = fallback_completion(
            &cjk_state,
            EcosystemId::Cargo,
            Position::new(1, 2),
            "unused",
        )
        .await;
        assert_eq!(cjk_items.len(), 1);
        assert_eq!(cjk_items[0].label, "serde");

        // Two ASCII chars: regression check that the char-count guard didn't change
        // behavior for the common case.
        let ascii_state = mock_cargo_state(Arc::new(StubRegistry), Some("se"));
        let ascii_items = fallback_completion(
            &ascii_state,
            EcosystemId::Cargo,
            Position::new(1, 2),
            "unused",
        )
        .await;
        assert_eq!(ascii_items.len(), 1);
        assert_eq!(ascii_items[0].label, "serde");
    }

    #[tokio::test]
    async fn test_fallback_completion_rejects_prefix_with_equals() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct PanicsIfSearchedRegistry;
        impl Registry for PanicsIfSearchedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                panic!("guard must short-circuit before reaching registry search");
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = mock_cargo_state(Arc::new(PanicsIfSearchedRegistry), Some("se = \"1.0"));
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(1, 9), "unused").await;
        assert!(items.is_empty());
    }

    /// #724/#728 end-to-end wiring guard: `fallback_completion` must actually reach
    /// `Ecosystem::fallback_completion_is_bare`/`fallback_bare_insert_text` when an
    /// ecosystem's prefix-extraction step reports `bare = true`, not just
    /// `create_package_completion_item` in isolation (see the unit-level
    /// `test_create_package_completion_item_bare_routes_to_fallback_bare_insert_text`).
    /// `insert_text` panics if invoked, so this fails loudly if the `bare` flag
    /// silently regresses to `false` on the wiring path (critic S1 on the #721/#722
    /// rebase: nothing in `deps-lsp` previously reached `fallback_completion` with
    /// `bare = true` at all, since `mock_cargo_state` always builds `is_bare: false`).
    #[tokio::test]
    async fn test_fallback_completion_bare_routes_through_to_fallback_bare_insert_text() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct StubRegistry;
        impl Registry for StubRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("guava"),
                        latest_version: "33.0.0".into(),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = ServerState::new();
        state.ecosystem_registry.register(Arc::new(MockEcosystem {
            id: "cargo",
            registry: Arc::new(StubRegistry),
            fallback_prefix: Some("gua"),
            insert_text: |_| panic!("bare=true must not call completion_insert_text"),
            is_bare: true,
            bare_insert_text: |metadata| Some(format!("bare:{}", metadata.name())),
        }));

        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(0, 0), "unused").await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].insert_text, Some("bare:guava".to_string()));
    }

    /// #724/#728 end-to-end wiring guard, the suppression half: when an ecosystem's
    /// `fallback_completion_prefix` returns `None` (Maven's open-non-`artifactId`-tag
    /// case), `fallback_completion` must return empty *without* ever reaching the
    /// registry — `search` panics here so this fails loudly if that short-circuit
    /// regresses (mirrors #728's own
    /// `test_fallback_completion_maven_in_open_group_id_tag_suppresses_item`).
    #[tokio::test]
    async fn test_fallback_completion_none_prefix_never_reaches_registry() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct PanicsIfSearchedRegistry;
        impl Registry for PanicsIfSearchedRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                panic!("None prefix must short-circuit before reaching registry search");
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = mock_cargo_state(Arc::new(PanicsIfSearchedRegistry), None);
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(0, 0), "unused").await;
        assert!(items.is_empty());
    }

    /// #118: a value this function interpolates into `insert_text` must fail its
    /// allowlist gate *before* the ecosystem's own `completion_insert_text` is ever
    /// called — proven here via a `MockEcosystem` whose `insert_text` panics if
    /// invoked, so the test fails loudly if the upfront gate regresses to running
    /// after (or not at all).
    #[test]
    fn test_create_package_completion_item_rejects_unsafe_latest_version() {
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
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata {
            name: deps_core::PackageName::new("serde"),
            latest_version: "1.0.0\", git = \"https://evil".into(),
        };
        let ecosystem = MockEcosystem {
            id: "cargo",
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("gate must reject before completion_insert_text runs"),
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        assert!(create_package_completion_item(&meta, &ecosystem, false).is_none());
    }

    /// Issue #336: a registry-reported name breaking out of a manifest string literal
    /// must be rejected before dispatch to any ecosystem's `completion_insert_text` —
    /// this is the single ecosystem-agnostic gate every ecosystem relies on, proven
    /// here with a `MockEcosystem` whose `insert_text` panics if invoked.
    #[test]
    fn test_create_package_completion_item_rejects_malicious_name() {
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
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let meta = MockMetadata {
            name: deps_core::PackageName::new("evil\"\nbackdoor = \"9.9.9"),
            latest_version: "9.9.9".into(),
        };
        let ecosystem = MockEcosystem {
            id: "cargo",
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("gate must reject before completion_insert_text runs"),
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        assert!(create_package_completion_item(&meta, &ecosystem, false).is_none());
    }

    struct NoopRegistry;
    impl deps_core::Registry for NoopRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a deps_core::PackageName,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }
        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a deps_core::PackageName,
            _req: &'a deps_core::VersionReq,
        ) -> deps_core::ecosystem::BoxFuture<
            'a,
            deps_core::Result<Option<Box<dyn deps_core::Version>>>,
        > {
            Box::pin(async move { Ok(None) })
        }
        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
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
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn test_search_packages_returns_results_within_timeout() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct FastRegistry;
        impl Registry for FastRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("express"),
                        latest_version: "4.18.2".into(),
                    }) as Box<dyn Metadata>])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let ecosystem = mock_ecosystem("npm", Arc::new(FastRegistry));
        let items = search_packages(ecosystem.as_ref(), "express", false).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "express");
    }

    /// `search_packages` drops any result whose `completion_insert_text` rejects it
    /// (e.g. a malicious/compromised registry response breaking out of the inserted
    /// snippet's syntax) but keeps the others — the ecosystem-specific *reasons* for a
    /// rejection (a Maven coordinate XML breakout, an unsafe Swift URL, ...) are
    /// covered directly in each owning ecosystem crate's own `completion_insert_text`
    /// tests (issue #722); this is the generic `filter_map` plumbing only.
    #[tokio::test]
    async fn test_search_packages_filters_rejected_completion_items_keeps_safe_ones() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct TwoResultRegistry;
        impl Registry for TwoResultRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new("safe-package"),
                            latest_version: "1.0.0".into(),
                        }) as Box<dyn Metadata>,
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new("rejected-package"),
                            latest_version: "1.0.0".into(),
                        }) as Box<dyn Metadata>,
                    ])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let ecosystem = Arc::new(MockEcosystem {
            id: "cargo",
            registry: Arc::new(TwoResultRegistry),
            fallback_prefix: None,
            insert_text: |metadata| {
                if metadata.name().as_str() == "rejected-package" {
                    None
                } else {
                    Some(metadata.name().to_string())
                }
            },
            is_bare: false,
            bare_insert_text: default_insert_text,
        });

        let items = search_packages(ecosystem.as_ref(), "package", false).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "safe-package");
    }

    /// #724/#728 plumbing guard: `create_package_completion_item` must route to
    /// `Ecosystem::fallback_bare_insert_text` when `bare` is `true`, never
    /// `completion_insert_text` — proven with a `MockEcosystem` whose
    /// `completion_insert_text` panics if invoked, so the test fails loudly if the
    /// routing regresses. The ecosystem-specific *reasons* a real ecosystem sets
    /// `fallback_completion_is_bare`/builds a bare insert (an already-open Maven
    /// `<artifactId>` tag, a NuGet attribute value) are covered directly in
    /// `deps-maven`'s and `deps-nuget`'s own tests.
    #[test]
    fn test_create_package_completion_item_bare_routes_to_fallback_bare_insert_text() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("guava"),
            latest_version: "33.0.0".into(),
        };
        let ecosystem = MockEcosystem {
            id: "maven",
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("bare=true must not call completion_insert_text"),
            is_bare: true,
            bare_insert_text: |metadata| Some(format!("bare:{}", metadata.name())),
        };

        assert_eq!(
            create_package_completion_item(&meta, &ecosystem, true)
                .and_then(|item| item.insert_text),
            Some("bare:guava".to_string())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_search_packages_times_out_and_returns_empty() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;
        use std::time::Duration;

        struct SlowRegistry;
        impl Registry for SlowRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    // Well beyond COMPLETION_SEARCH_TIMEOUT; paused time makes this
                    // resolve instantly instead of actually waiting.
                    tokio::time::sleep(Duration::from_mins(1)).await;
                    Ok(vec![])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let ecosystem = mock_ecosystem("npm", Arc::new(SlowRegistry));
        let items = search_packages(ecosystem.as_ref(), "expr", false).await;

        assert!(
            items.is_empty(),
            "should return empty on timeout, not block"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_handle_completion_primary_path_times_out_and_skips_fallback() {
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            OsvNaming, PackageNaming, PackageRendering, ParseResult, RequirementResolution,
            SourcePolicy,
        };
        use std::any::Any;
        use std::path::Path;
        use std::time::Duration;
        use tower_lsp_server::ls_types::Uri;

        struct MockFormatter;
        impl PackageNaming for MockFormatter {}

        impl PackageRendering for MockFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for MockFormatter {}

        impl DiagnosticMessages for MockFormatter {}

        impl DiagnosticPolicy for MockFormatter {}

        impl SourcePolicy for MockFormatter {}

        impl OsvNaming for MockFormatter {}

        // Deliberately `unimplemented!()`: if a primary-path timeout ever falls through
        // to `fallback_completion` again (the N1 double-timeout bug), that path calls
        // `registry()` and this test panics instead of just running slow.
        struct SlowEcosystem;
        impl deps_core::ecosystem::private::Sealed for SlowEcosystem {}
        impl Ecosystem for SlowEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "Cargo (slow mock)"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                unimplemented!()
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &MockFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                Box::pin(async move {
                    // Well beyond COMPLETION_SEARCH_TIMEOUT; paused time resolves
                    // this instantly instead of actually waiting.
                    tokio::time::sleep(Duration::from_mins(1)).await;
                    deps_core::completion::Completions::default()
                })
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

        // Overwrites the real Cargo ecosystem for this state instance only.
        state.ecosystem_registry.register(Arc::new(SlowEcosystem));

        let content = "[dependencies]\nserde = \"1\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
        state.update_document(uri.clone(), doc);

        let params = CompletionParams {
            text_document_position: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(1, 5), // after "serde"
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
            context: None,
        };

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;

        // Empty items collapse to `None` (see `handle_completion`'s tail); reaching
        // this at all (rather than hanging or panicking) is what this test checks.
        assert!(result.is_none());
    }

    /// #419 C1 regression, now driven by a per-call [`Completions::is_incomplete`]
    /// (#427) rather than a static per-ecosystem flag: an ecosystem whose
    /// `generate_completions` reports `is_incomplete: true` for the served context
    /// (PyPI's package-search-index-backed completion) must always get back
    /// `CompletionResponse::List { is_incomplete: true, .. }` — on the empty-items
    /// branch (the cold-start case rev 4's fix missed, since `None` serializes as
    /// LSP `null` and carries no `isIncomplete`) as well as the non-empty branch.
    /// An ecosystem that always reports `is_incomplete: false` (the
    /// `test_concurrent_document_write_not_blocked_by_in_flight_completion_search`
    /// test just above proves the empty case) keeps returning `None`/`Array`
    /// unchanged.
    #[tokio::test]
    async fn test_generate_completions_is_incomplete_flows_into_response_both_branches() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, DiagnosticMessages, DiagnosticPolicy, Ecosystem, EcosystemFormatter,
            Metadata, OsvNaming, PackageNaming, PackageRendering, ParseResult, Registry,
            RequirementResolution, SourcePolicy, Version,
        };
        use std::any::Any;
        use tower_lsp_server::ls_types::Uri;

        struct NoopRegistry;
        impl Registry for NoopRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a deps_core::PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move { Ok(vec![]) })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct NoopFormatter;
        impl PackageNaming for NoopFormatter {}

        impl PackageRendering for NoopFormatter {
            fn format_version_for_text_edit(&self, version: &deps_core::ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &deps_core::PackageName) -> String {
                format!("https://example.com/{name}")
            }
        }

        impl RequirementResolution for NoopFormatter {}

        impl DiagnosticMessages for NoopFormatter {}

        impl DiagnosticPolicy for NoopFormatter {}

        impl SourcePolicy for NoopFormatter {}

        impl OsvNaming for NoopFormatter {}

        /// Stands in for `PypiEcosystem`: always reports incomplete results, and
        /// returns either zero or one completion item depending on `has_item`.
        struct IncompleteEcosystem {
            has_item: bool,
        }
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn id(&self) -> &'static str {
                "cargo"
            }
            fn display_name(&self) -> &'static str {
                "cargo"
            }
            fn manifest_filenames(&self) -> &[&'static str] {
                &["Cargo.toml"]
            }
            fn parse_manifest<'a>(
                &'a self,
                _content: &'a str,
                _uri: &'a Uri,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &NoopFormatter
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                let items = if self.has_item {
                    vec![CompletionItem {
                        label: "requests".to_string(),
                        ..Default::default()
                    }]
                } else {
                    vec![]
                };
                Box::pin(async move {
                    Completions {
                        items,
                        is_incomplete: true,
                    }
                })
            }
            fn completion_insert_text(
                &self,
                _metadata: &dyn deps_core::Metadata,
            ) -> Option<String> {
                unimplemented!()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: Uri,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        async fn run(has_item: bool) -> Option<CompletionResponse> {
            let state = Arc::new(ServerState::new());
            state
                .ecosystem_registry
                .register(Arc::new(IncompleteEcosystem { has_item }));

            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: uri.clone() });
            let doc =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            state.update_document(uri.clone(), doc);

            let params = CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri },
                    position: Position::new(0, 0),
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
                context: None,
            };

            let (client, config) = create_test_client_and_config();
            handle_completion(state, params, client, config).await
        }

        match run(false).await {
            Some(CompletionResponse::List(list)) => {
                assert!(
                    list.is_incomplete,
                    "empty branch must still carry is_incomplete"
                );
                assert!(list.items.is_empty());
            }
            other => panic!("expected List{{is_incomplete:true, items:[]}}, got {other:?}"),
        }

        match run(true).await {
            Some(CompletionResponse::List(list)) => {
                assert!(list.is_incomplete);
                assert_eq!(list.items.len(), 1);
                assert_eq!(list.items[0].label, "requests");
            }
            other => panic!("expected List{{is_incomplete:true, items:[requests]}}, got {other:?}"),
        }
    }
}

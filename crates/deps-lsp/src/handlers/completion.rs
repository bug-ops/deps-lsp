//! Completion handler implementation.
//!
//! Delegates to ecosystem-specific completion logic.

use crate::config::DepsConfig;
use crate::document::{ServerState, ensure_document_loaded};
use deps_core::EcosystemId;
use deps_core::completion::{COMPLETION_SEARCH_TIMEOUT, is_valid_completion_prefix_len};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionList, CompletionParams, CompletionResponse,
};

// Keystroke-driven, so completion gets its own short timeout instead of sharing the 30s
// HTTP client timeout used elsewhere ([`COMPLETION_SEARCH_TIMEOUT`]).
//
// Shared with `deps_core::completion`, not kept local: registry paths that retry
// internally on failure (e.g. deps-maven's search, #274) size their retry budget against
// this same value.

/// Handles completion requests.
///
/// Delegates to the appropriate ecosystem implementation based on the document type.
/// Falls back to text-based completion when TOML parsing fails (user is still typing).
#[tracing::instrument(
    skip(state, params, client, config),
    fields(uri = ?params.text_document_position.text_document.uri, ecosystem = tracing::field::Empty)
)]
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

    // Acquires the config RwLock before the DashMap shard guard, never the reverse
    // (matches hover.rs/diagnostics.rs).
    let freshness = { config.read().await.policy.freshness.to_settings() };

    // Resolved from the URI alone via `for_uri`, not the loaded document's `ecosystem_id`
    // (only available after the load/lookup early returns below). `is_some_and`, not `?`,
    // so an unrecognized URI falls through to `false` instead of short-circuiting.
    let package_search_is_incomplete = crate::lsp_types_interop::from_lsp_uri(uri)
        .and_then(|domain_uri| state.ecosystem_registry.for_uri(&domain_uri))
        .is_some_and(|e| e.package_search_is_incomplete());

    // Shared by the early returns below so both report `isIncomplete` consistently when
    // `fallback_completion`'s package-name search may be truncated (#419 S1) — `None`
    // would serialize as LSP `null`, giving the client nothing to invalidate.
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

    // Latency-critical: the cold-start load is capped at 200ms.
    if state.get_document(uri).is_none() {
        tracing::info!("completion: document not loaded, loading from disk");

        let load_result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            ensure_document_loaded(uri, Arc::clone(&state), client.clone(), Arc::clone(&config)),
        )
        .await;

        match load_result {
            Ok(true) => {
                tracing::debug!("completion: document loaded successfully");
            }
            Ok(false) | Err(_) => {
                tracing::warn!("completion: document load failed or timed out");
                return context_less_response();
            }
        }
    }

    // A single shard acquisition, not two separate ones for `content` and `parse_result`:
    // a concurrent `didChange` between them could pair a `parse_result` with `content` from
    // a different revision, and `generate_completions` correlates the two (#319 review).
    // `with_document` makes releasing the guard structural, not a convention (#333).
    let Some((ecosystem_id, content, parse_result)) = state.with_document(uri, |doc| {
        (doc.ecosystem, doc.content.clone(), doc.parse_result_arc())
    }) else {
        tracing::warn!("completion: document not found: {:?}", uri);
        return context_less_response();
    };

    tracing::Span::current().record("ecosystem", ecosystem_id.id());

    tracing::info!(
        "completion: ecosystem={}, has_parse_result={}",
        ecosystem_id,
        parse_result.is_some()
    );

    // Try parse_result first, fall back to text-based detection. `is_incomplete` (#427) is
    // OR'd with `package_search_is_incomplete()` whenever `fallback_completion` actually
    // runs: it always does a raw package-name search regardless of the primary context, so
    // it only coincidentally inherits the primary's completeness signal.
    let (items, is_incomplete) = if let Some(parse_result) = parse_result {
        match state.ecosystem_registry.get(ecosystem_id) {
            Some(ecosystem) => {
                // The DashMap shard `Ref` was already dropped above: holding it across
                // this `COMPLETION_SEARCH_TIMEOUT`-bounded await would block a concurrent
                // `documents.get_mut` on the same shard for the duration (#319).
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
                    // Try fallback: handles the case where the user is typing a new package name.
                    // `CompletionOrigin::allows_package_name_fallback` (#1184 Gap 2, #1195) gates
                    // this: an ecosystem's `origin` blocks it when the cursor was positively
                    // resolved to a non-package-name context (e.g. `Version`) and the item was
                    // withheld deliberately, not because context detection came up empty.
                    Ok(completions)
                        if completions.items.is_empty()
                            && completions.origin.allows_package_name_fallback() =>
                    {
                        tracing::info!("completion: ecosystem returned empty, trying fallback");
                        let fallback_items =
                            fallback_completion(&state, ecosystem_id, position, &content).await;
                        (
                            fallback_items,
                            completions.is_incomplete || ecosystem.package_search_is_incomplete(),
                        )
                    }
                    Ok(completions) => (completions.items, completions.is_incomplete),
                    // Timed out, not genuinely empty: a fallback search against the same
                    // slow registry would likely time out too, doubling the worst case.
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
        // No `parse_result`: `generate_completions` was never called, so
        // `package_search_is_incomplete` (resolved above) is the only signal available —
        // matches the mid-typing, parse-failed state (`new_without_parse_result`).
        (
            fallback_completion(&state, ecosystem_id, position, &content).await,
            package_search_is_incomplete,
        )
    };

    tracing::info!("completion: returning {} items", items.len());

    if is_incomplete {
        // Must still be a `List` even when `items` is empty: `None` serializes as LSP
        // `null`, giving the client nothing to invalidate (#419 C1).
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

    let Some(ecosystem) = state.ecosystem_registry.get(ecosystem_kind) else {
        tracing::warn!(
            "fallback_completion: ecosystem not found for id: {}",
            ecosystem_kind
        );
        return vec![];
    };

    let Some(prefix) = ecosystem.fallback_completion_prefix(content, position.into()) else {
        tracing::info!("fallback_completion: no completable prefix at this position");
        return vec![];
    };

    // Same 2-200 char guard every primary completion path uses: an unbounded prefix here
    // would flow into the tracing logs below and into `registry.search`'s request/cache key (#739).
    if prefix.contains('=') || !is_valid_completion_prefix_len(prefix) {
        tracing::info!("fallback_completion: prefix rejected (contains =, or invalid length)");
        return vec![];
    }

    // #1206 S3: must run before this function's own `tracing::info!` below, not just inside `search_packages`.
    if let Some(rejected) =
        deps_core::completion::reject_credential_bearing_value(prefix, "fallback_completion prefix")
    {
        return rejected;
    }

    // Whether the cursor sits inside already-open manifest markup (an XML tag/attribute)
    // that can only safely hold bare candidate text — inserting the full snippet would
    // nest a duplicate copy of the markup already open around the cursor (#724/#728).
    let bare = ecosystem.fallback_completion_is_bare(content, position.into());

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
    // #1206: defense-in-depth gate, independent of `fallback_completion`'s own (#1206 S3).
    if let Some(rejected) =
        deps_core::completion::reject_credential_bearing_value(query, "search_packages query")
    {
        return rejected;
    }

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

    let mut items: Vec<CompletionItem> = results
        .iter()
        .enumerate()
        .filter_map(|(index, metadata)| {
            create_package_completion_item(metadata.as_ref(), ecosystem, bare, index, query)
        })
        .collect();
    deps_core::completion::apply_raw_prefix_filter_text(&mut items, registry.as_ref(), query);
    items
}

/// Creates a completion item for a package.
///
/// Delegates the shared fields (`label`, `kind`, `detail`, `documentation`, `sort_text`,
/// `filter_text`) to [`deps_core::completion::build_package_completion_fields`] — including
/// its [`deps_core::is_safe_package_name`]/[`deps_core::is_safe_version_string`] gates (issue
/// #1284: this fallback path and the primary completion path must reject the same unsafe
/// metadata and render the same fields the same way, not diverge silently) — then builds
/// `insert_text` itself, via the ecosystem's own manifest syntax
/// ([`deps_core::Ecosystem::completion_insert_text`] — required, no default, so a new
/// ecosystem must supply its own snippet instead of silently inheriting another ecosystem's
/// syntax, see issue #118). `text_edit` is left as the base builder leaves it (`None`) — this
/// path has no known insert range, so the client falls back to inserting `insert_text` at the
/// cursor.
///
/// Returns `None` when [`deps_core::completion::build_package_completion_fields`] does (see
/// its doc for the rejection gates), or when the ecosystem's own `completion_insert_text`/
/// `fallback_bare_insert_text` rejects the metadata for an ecosystem-specific reason (a
/// Maven `groupId`/`artifactId` breakout, an unsafe Swift repository URL, GitHub Actions'
/// `owner/repo` shape).
///
/// `bare` (from `fallback_completion`'s `Ecosystem::fallback_completion_is_bare`
/// call) selects which of the two ecosystem hooks builds `insert_text`: `true`
/// routes to `Ecosystem::fallback_bare_insert_text` (the cursor already sits inside
/// open manifest markup that can only safely hold the bare candidate text — #724/
/// #728), `false` to `Ecosystem::completion_insert_text` (the normal full snippet).
///
/// `index`/`prefix` are forwarded to
/// [`deps_core::completion::build_package_completion_fields`] unchanged — issue #1294: this
/// fallback path previously hardcoded `sort_text` to the package name (alphabetical,
/// discarding the registry's relevance ranking), the same #1282 shape bug already fixed on
/// the primary completion path but missed here since this path builds its `CompletionItem`
/// independently.
fn create_package_completion_item(
    metadata: &dyn deps_core::Metadata,
    ecosystem: &dyn deps_core::Ecosystem,
    bare: bool,
    index: usize,
    prefix: &str,
) -> Option<CompletionItem> {
    let mut item = deps_core::completion::build_package_completion_fields(metadata, index, prefix)?;

    item.insert_text = Some(if bare {
        ecosystem.fallback_bare_insert_text(metadata)?
    } else {
        ecosystem.completion_insert_text(metadata)?
    });

    Some(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::DocumentState;
    use crate::test_utils::test_helpers::create_test_client_and_config;
    use tower_lsp_server::ls_types::{
        CompletionItemKind, Position, TextDocumentIdentifier, TextDocumentPositionParams,
    };

    /// Generic test double for [`deps_core::Ecosystem`], configurable per test so
    /// `fallback_completion`/`search_packages` tests can observe (or forbid) a
    /// registry search, and control the resulting completion item's insert text,
    /// without hitting the network or depending on any real ecosystem's raw-text
    /// syntax — per-ecosystem section/prefix/insert-text syntax is now covered
    /// directly in each owning ecosystem crate (issue #722).
    struct MockEcosystem {
        ecosystem_id: deps_core::EcosystemId,
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
        fn ecosystem_id(&self) -> deps_core::EcosystemId {
            self.ecosystem_id
        }
        fn display_name(&self) -> &'static str {
            self.ecosystem_id.id()
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &["Cargo.toml"]
        }
        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a url::Url,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn deps_core::ParseResult>>>
        {
            Box::pin(async move { unimplemented!() })
        }
        fn registry(&self) -> Arc<dyn deps_core::Registry> {
            Arc::clone(&self.registry)
        }
        fn formatter(&self) -> &dyn deps_core::lsp_helpers::EcosystemFormatter {
            &deps_core::test_util::StubFormatter::DEFAULT
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
        fn complete_version<'a>(
            &'a self,
            _request: deps_core::completion::CompletionRequest<'a>,
            _package_name: deps_core::PackageName,
            _prefix: String,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions> {
            unimplemented!()
        }
        fn fallback_completion_prefix<'a>(
            &self,
            _content: &'a str,
            _position: deps_core::position::Position,
        ) -> Option<&'a str> {
            self.fallback_prefix
        }
        fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
            (self.insert_text)(metadata)
        }
        fn fallback_completion_is_bare(
            &self,
            _content: &str,
            _position: deps_core::position::Position,
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
        Some(metadata.name().as_str().to_string())
    }

    /// Builds a [`MockEcosystem`] with `ecosystem_id`, routing registry search through
    /// `registry`, using [`default_insert_text`].
    fn mock_ecosystem(
        ecosystem_id: deps_core::EcosystemId,
        registry: Arc<dyn deps_core::Registry>,
    ) -> Arc<dyn deps_core::Ecosystem> {
        Arc::new(MockEcosystem {
            ecosystem_id,
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
            ecosystem_id: deps_core::EcosystemId::Cargo,
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
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));

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
        use deps_core::{Ecosystem, EcosystemFormatter, Metadata, ParseResult, Registry, Version};
        use std::any::Any;

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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

        /// Stands in for `PypiEcosystem`: overrides `package_search_is_incomplete`
        /// the same way, and `generate_completions` is deliberately `unimplemented!()`
        /// since this test never lets it run.
        struct IncompleteEcosystem;
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
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
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                unimplemented!()
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
        // Deliberately never inserted into `state.documents`: the document-load below
        // must time out/fail against a nonexistent file.
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));

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

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_completion_delegates_to_ecosystem() {
        // Held per fs_probe::snapshot_guard's doc: parse_manifest touches fs_probe and
        // this test shares a binary with document/loader.rs's diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let content = "[dependencies]\nserde = \"1.0\"".to_string();

        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Cargo)
            .unwrap();
        let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();

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

        let (client, config) = create_test_client_and_config();
        let _result = handle_completion(state, params, client, config).await;
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

        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
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

        // Block until `handle_completion` has actually reached the search-bound await
        // before racing the writer below.
        started.wait().await;

        // Spawned as its own task deliberately: `DashMap::get_mut` blocks the OS thread
        // synchronously on a `parking_lot` lock with no `.await` point of its own, so
        // wrapping it directly in `tokio::time::timeout` wouldn't work — a `Future::poll`
        // that never returns can't be preempted between polls. Spawning gives the *join*
        // a real async yield point for the timeout below to race against.
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
    /// `handle_completion` (`completion.rs:47`) re-reads `config.policy.freshness` on *every*
    /// call, so a `workspace/didChangeConfiguration`-driven config update (simulated here
    /// by writing directly to the shared `Arc<RwLock<DepsConfig>>`, exactly what
    /// `Backend::did_change_configuration` does) changes completion's age-suffix presence
    /// on the very next request, with no server restart and no re-opening the document.
    #[tokio::test]
    async fn test_completion_freshness_enabled_live_reload_changes_label_details_on_next_request() {
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, Ecosystem, EcosystemFormatter, Metadata, ParseResult, Registry, Version,
        };
        use std::any::Any;
        use std::path::Path;
        use tower_lsp_server::ls_types::CompletionItemLabelDetails;

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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

        /// Stands in for a real ecosystem's `generate_completions`, echoing whatever
        /// `freshness.enabled` it was called with into `label_details` — exactly the
        /// signal real ecosystems derive from `build_version_completion`, without
        /// needing a real registry fetch or parsed manifest.
        struct FreshnessEchoEcosystem;
        impl Sealed for FreshnessEchoEcosystem {}
        impl Ecosystem for FreshnessEchoEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
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
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                unimplemented!()
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
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
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
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
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
            config.read().await.policy.freshness.enabled,
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
        config.write().await.policy.freshness.enabled = false;

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
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));

        let content = r"[dependencies]
ser"
        .to_string();

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

        let (client, config) = create_test_client_and_config();
        let result = handle_completion(state, params, client, config).await;
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

    /// #1206 S3: a credential-shaped raw-text prefix must be rejected inside
    /// `fallback_completion` itself, before its own `tracing::info!` log line — not only
    /// inside `search_packages` (checked separately by
    /// `test_search_packages_rejects_credential_bearing_query` below). `search` panics here,
    /// so this fails loudly if the earlier gate regresses and the credential-shaped prefix
    /// reaches the registry after all.
    #[tokio::test]
    async fn test_fallback_completion_rejects_credential_bearing_prefix() {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

        let state = mock_cargo_state(
            Arc::new(PanicsIfSearchedRegistry),
            Some("deploy:AUDITSENTINEL0000@git.internal.corp/team/x"),
        );
        let items =
            fallback_completion(&state, EcosystemId::Cargo, Position::new(0, 0), "unused").await;
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(StubRegistry),
            fallback_prefix: Some("gua"),
            insert_text: |_| panic!("bare=true must not call completion_insert_text"),
            is_bare: true,
            bare_insert_text: |metadata| Some(format!("bare:{}", metadata.name().as_str())),
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("gate must reject before completion_insert_text runs"),
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        assert!(create_package_completion_item(&meta, &ecosystem, false, 0, "").is_none());
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
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("gate must reject before completion_insert_text runs"),
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        assert!(create_package_completion_item(&meta, &ecosystem, false, 0, "").is_none());
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
            _selection_context: &'a deps_core::SelectionContext,
        ) -> deps_core::ecosystem::BoxFuture<
            'a,
            deps_core::Result<Option<Box<dyn deps_core::Version>>>,
        > {
            Box::pin(async move { Ok(None) })
        }
        fn search_raw<'a>(
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
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

        let ecosystem = mock_ecosystem(deps_core::EcosystemId::Npm, Arc::new(FastRegistry));
        let items = search_packages(ecosystem.as_ref(), "express", false).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "express");
    }

    /// #1289: `search_packages`'s raw-text fallback path must also rewrite `filter_text`
    /// to the raw typed prefix when the registry normalizes its search query — before this
    /// test, only the primary `complete_package_names_generic` path was covered end-to-end
    /// (via deps-pypi's own `PypiRegistry` test), leaving this second, independently-built
    /// call site of `apply_raw_prefix_filter_text` unverified.
    #[tokio::test]
    async fn test_search_packages_rewrites_filter_text_for_normalizing_registry() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct NormalizingRegistry;
        impl Registry for NormalizingRegistry {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("zope-interface"),
                        latest_version: "5.0.0".into(),
                    }) as Box<dyn Metadata>])
                })
            }

            fn search_normalizes_query(&self) -> bool {
                true
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let ecosystem = mock_ecosystem(deps_core::EcosystemId::Pypi, Arc::new(NormalizingRegistry));
        let items = search_packages(ecosystem.as_ref(), "zope.int", false).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "zope-interface");
        assert_eq!(items[0].filter_text.as_deref(), Some("zope.int"));
    }

    /// #1289: the negative case — a non-normalizing registry (the default) must leave
    /// `filter_text` alone through the whole fallback path, not just in isolation.
    #[tokio::test]
    async fn test_search_packages_leaves_filter_text_alone_for_non_normalizing_registry() {
        use deps_core::{Metadata, Registry, Version};
        use std::any::Any;

        struct PlainRegistry;
        impl Registry for PlainRegistry {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
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

        let ecosystem = mock_ecosystem(deps_core::EcosystemId::Npm, Arc::new(PlainRegistry));
        let items = search_packages(ecosystem.as_ref(), "exp", false).await;

        assert_eq!(items.len(), 1);
        // Unchanged from what `build_package_completion_fields` set: the package name,
        // not the raw typed prefix.
        assert_eq!(items[0].filter_text.as_deref(), Some("express"));
    }

    /// #1206: `search_packages`'s own gate, called directly rather than through
    /// `fallback_completion` (see `test_fallback_completion_rejects_credential_bearing_prefix`
    /// for that end-to-end path) — `search` panics here, so this fails loudly if the gate
    /// regresses.
    #[tokio::test]
    async fn test_search_packages_rejects_credential_bearing_query() {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

        let ecosystem = mock_ecosystem(
            deps_core::EcosystemId::Npm,
            Arc::new(PanicsIfSearchedRegistry),
        );
        let items = search_packages(
            ecosystem.as_ref(),
            "deploy:AUDITSENTINEL0000@git.internal.corp/team/x",
            false,
        )
        .await;

        assert!(items.is_empty());
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
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
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(TwoResultRegistry),
            fallback_prefix: None,
            insert_text: |metadata| {
                if metadata.name().as_str() == "rejected-package" {
                    None
                } else {
                    Some(metadata.name().as_str().to_string())
                }
            },
            is_bare: false,
            bare_insert_text: default_insert_text,
        });

        let items = search_packages(ecosystem.as_ref(), "package", false).await;

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "safe-package");
    }

    /// #1294: `search_packages` must thread each result's registry-response position
    /// through to `create_package_completion_item`/`build_package_completion` via
    /// `.enumerate()`, so `sort_text` preserves the registry's own relevance ranking
    /// instead of every item hardcoding the same value.
    #[tokio::test]
    async fn test_search_packages_preserves_registry_relevance_sort_text() {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new("serde"),
                            latest_version: "1.0.0".into(),
                        }) as Box<dyn Metadata>,
                        Box::new(MockMetadata {
                            name: deps_core::PackageName::new("serde_json"),
                            latest_version: "1.0.0".into(),
                        }) as Box<dyn Metadata>,
                    ])
                })
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let ecosystem = mock_ecosystem(deps_core::EcosystemId::Cargo, Arc::new(TwoResultRegistry));
        let items = search_packages(ecosystem.as_ref(), "serde", false).await;

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].sort_text, Some("00000000000".to_string()));
        assert_eq!(items[1].sort_text, Some("00000000001".to_string()));
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
            ecosystem_id: deps_core::EcosystemId::Maven,
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: |_| panic!("bare=true must not call completion_insert_text"),
            is_bare: true,
            bare_insert_text: |metadata| Some(format!("bare:{}", metadata.name().as_str())),
        };

        assert_eq!(
            create_package_completion_item(&meta, &ecosystem, true, 0, "")
                .and_then(|item| item.insert_text),
            Some("bare:guava".to_string())
        );
    }

    // #1284: fallback item must agree with the primary builder on every shared field.
    #[test]
    fn test_create_package_completion_item_agrees_with_primary_builder_on_shared_fields() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("serde"),
            latest_version: "1.0.214".into(),
        };
        let ecosystem = MockEcosystem {
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: default_insert_text,
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        let primary = deps_core::completion::build_package_completion(
            &meta,
            tower_lsp_server::ls_types::Range::default(),
            2,
            "ser",
        )
        .unwrap();
        let fallback = create_package_completion_item(&meta, &ecosystem, false, 2, "ser").unwrap();

        assert_eq!(fallback.label, primary.label);
        assert_eq!(fallback.kind, primary.kind);
        assert_eq!(fallback.sort_text, primary.sort_text);
        assert_eq!(fallback.filter_text, primary.filter_text);
        assert_eq!(fallback.detail, primary.detail);
        assert_eq!(fallback.documentation, primary.documentation);
        assert_eq!(fallback.insert_text_format, primary.insert_text_format);

        // Diverges by design: no known insert range in the fallback path.
        assert!(fallback.text_edit.is_none());
        assert!(primary.text_edit.is_some());
    }

    /// #1294: the fallback path previously hardcoded `sort_text` to the package name
    /// (forcing alphabetical client-side sorting, the same #1282 shape bug already fixed
    /// on the primary completion path) rather than threading `index`/`prefix` through to
    /// [`deps_core::completion::build_package_completion`] — pins the actual tiered value,
    /// not just that this path and the primary path happen to agree.
    #[test]
    fn test_create_package_completion_item_preserves_registry_relevance_sort_text() {
        let meta = MockMetadata {
            name: deps_core::PackageName::new("serde"),
            latest_version: "1.0.214".into(),
        };
        let ecosystem = MockEcosystem {
            ecosystem_id: deps_core::EcosystemId::Cargo,
            registry: Arc::new(NoopRegistry),
            fallback_prefix: None,
            insert_text: default_insert_text,
            is_bare: false,
            bare_insert_text: default_insert_text,
        };

        // "ser" is an exact prefix of "serde" -> tier 0, index 2.
        let item = create_package_completion_item(&meta, &ecosystem, false, 2, "ser").unwrap();
        assert_eq!(item.sort_text, Some("00000000002".to_string()));
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
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

        let ecosystem = mock_ecosystem(deps_core::EcosystemId::Npm, Arc::new(SlowRegistry));
        let items = search_packages(ecosystem.as_ref(), "expr", false).await;

        assert!(
            items.is_empty(),
            "should return empty on timeout, not block"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_handle_completion_primary_path_times_out_and_skips_fallback() {
        use deps_core::{Dependency, Ecosystem, EcosystemFormatter, ParseResult};
        use std::any::Any;
        use std::path::Path;
        use std::time::Duration;

        // Deliberately `unimplemented!()`: if a primary-path timeout ever falls through
        // to `fallback_completion` again (the N1 double-timeout bug), that path calls
        // `registry()` and this test panics instead of just running slow.
        struct SlowEcosystem;
        impl deps_core::ecosystem::private::Sealed for SlowEcosystem {}
        impl Ecosystem for SlowEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                unimplemented!()
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
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
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::completion::Completions>
            {
                unimplemented!()
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
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);

        // Overwrites the real Cargo ecosystem for this state instance only.
        state.ecosystem_registry.register(Arc::new(SlowEcosystem));

        let content = "[dependencies]\nserde = \"1\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
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
            Dependency, Ecosystem, EcosystemFormatter, Metadata, ParseResult, Registry, Version,
        };
        use std::any::Any;

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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
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

        /// Stands in for `PypiEcosystem`: always reports incomplete results, and
        /// returns either zero or one completion item depending on `has_item`.
        struct IncompleteEcosystem {
            has_item: bool,
        }
        impl Sealed for IncompleteEcosystem {}
        impl Ecosystem for IncompleteEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(NoopRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
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
                Box::pin(async move { Completions::new(items).with_incomplete(true) })
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                unimplemented!()
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
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
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

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
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

    /// #1184 Gap 2 / #1195 regression: an ecosystem that positively identified this cursor
    /// as a non-package-name context (and withheld the item, e.g. GitHub Actions'
    /// `position_past_sha_pin_own_ref`) stamps `Completions::origin` as
    /// `CompletionOrigin::Version`, which must stop `handle_completion` from re-entering
    /// `fallback_completion` on empty items. `fallback_completion_prefix` panics and
    /// `registry()` is `unimplemented!()` — either firing means `fallback_completion` ran
    /// despite the blocking origin.
    #[tokio::test]
    async fn test_origin_version_skips_fallback_search() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{Dependency, Ecosystem, EcosystemFormatter, ParseResult};
        use std::any::Any;
        use std::path::Path;

        struct SuppressFallbackEcosystem;
        impl Sealed for SuppressFallbackEcosystem {}
        impl Ecosystem for SuppressFallbackEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn deps_core::Registry> {
                unimplemented!(
                    "fallback_completion must not resolve a registry when origin blocks fallback"
                )
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                Box::pin(async move {
                    Completions::default()
                        .with_origin(deps_core::completion::CompletionOrigin::Version)
                })
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                unimplemented!()
            }
            fn fallback_completion_prefix<'a>(
                &self,
                _content: &'a str,
                _position: deps_core::position::Position,
            ) -> Option<&'a str> {
                panic!("fallback_completion must not run when origin blocks fallback")
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
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        state
            .ecosystem_registry
            .register(Arc::new(SuppressFallbackEcosystem));

        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
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
        let result = handle_completion(state, params, client, config).await;

        assert!(
            result.is_none(),
            "expected no completion response, got {result:?}"
        );
    }

    /// Tester-recommended counterpart to
    /// [`test_origin_version_skips_fallback_search`]: an ecosystem
    /// (`Completions::default()`'s `origin` field defaults `Unresolved`, matching every
    /// ecosystem except a context that positively resolved to `Version`/`Feature`) with
    /// empty `generate_completions` results must still reach `fallback_completion` through
    /// `handle_completion`'s real match arm, not a helper that calls `fallback_completion`
    /// directly — proves the `origin.allows_package_name_fallback()` guard added for #1184
    /// Gap 2 / #1195 is a no-op for the common case, as an executed behavioral check rather
    /// than by type/grep reasoning alone.
    #[tokio::test]
    async fn test_handle_completion_falls_back_when_origin_unresolved() {
        use deps_core::completion::Completions;
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, Ecosystem, EcosystemFormatter, Metadata, ParseResult, Registry, Version,
        };
        use std::any::Any;
        use std::path::Path;

        struct OneResultRegistry;
        impl Registry for OneResultRegistry {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("requests"),
                        latest_version: deps_core::ConcreteVersion::new("2.31.0"),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockMetadata {
            name: deps_core::PackageName,
            latest_version: deps_core::ConcreteVersion,
        }
        impl Metadata for MockMetadata {
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

        struct NotSuppressingEcosystem;
        impl Sealed for NotSuppressingEcosystem {}
        impl Ecosystem for NotSuppressingEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(OneResultRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                // `origin` defaults to `Unresolved` — this is the common case every
                // ecosystem except a positively-resolved `Version`/`Feature` context takes.
                Box::pin(async move { Completions::default() })
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                unimplemented!()
            }
            fn fallback_completion_prefix<'a>(
                &self,
                _content: &'a str,
                _position: deps_core::position::Position,
            ) -> Option<&'a str> {
                Some("req")
            }
            fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
                Some(metadata.name().as_str().to_string())
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let state = Arc::new(ServerState::new());
        state
            .ecosystem_registry
            .register(Arc::new(NotSuppressingEcosystem));

        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let content = "[dependencies]\nreq = \"1.0\"\n".to_string();
        let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
        let doc = DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
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
        let result = handle_completion(state, params, client, config).await;

        match result {
            Some(CompletionResponse::Array(items)) => {
                assert_eq!(items.len(), 1, "expected the fallback search's one item");
                assert_eq!(items[0].label, "requests");
            }
            other => panic!("expected Array([requests]) from the fallback path, got {other:?}"),
        }
    }

    /// Table-driven #1195 regression over every [`deps_core::completion::CompletionOrigin`]:
    /// `Version`/`Feature` must block `fallback_completion` on empty items (the mock's
    /// `fallback_completion_prefix` asserts it is never reached for those), while
    /// `Unresolved`/`PackageName` must still reach it — including the `PackageName` +
    /// empty-items row, the mid-typing path (prefix shorter than the 2-char minimum) a
    /// user actually hits, and the one row that fails if the gate is ever written inverted.
    #[tokio::test]
    async fn test_fallback_gate_across_all_origins() {
        use deps_core::completion::{CompletionOrigin, Completions};
        use deps_core::ecosystem::private::Sealed;
        use deps_core::{
            Dependency, Ecosystem, EcosystemFormatter, Metadata, ParseResult, Registry, Version,
        };
        use std::any::Any;
        use std::path::Path;

        struct OneResultRegistry;
        impl Registry for OneResultRegistry {
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
                _selection_context: &'a deps_core::SelectionContext,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>>
            {
                Box::pin(async move { Ok(None) })
            }
            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(MockMetadata {
                        name: deps_core::PackageName::new("requests"),
                        latest_version: deps_core::ConcreteVersion::new("2.31.0"),
                    }) as Box<dyn Metadata>])
                })
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockMetadata {
            name: deps_core::PackageName,
            latest_version: deps_core::ConcreteVersion,
        }
        impl Metadata for MockMetadata {
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

        struct OriginProbeEcosystem {
            origin: CompletionOrigin,
        }
        impl Sealed for OriginProbeEcosystem {}
        impl Ecosystem for OriginProbeEcosystem {
            fn ecosystem_id(&self) -> deps_core::EcosystemId {
                deps_core::EcosystemId::Cargo
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
                _uri: &'a url::Url,
            ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>>
            {
                Box::pin(async move { unimplemented!() })
            }
            fn registry(&self) -> Arc<dyn Registry> {
                Arc::new(OneResultRegistry)
            }
            fn formatter(&self) -> &dyn EcosystemFormatter {
                &deps_core::test_util::StubFormatter::DEFAULT
            }
            fn generate_completions<'a>(
                &'a self,
                _parse_result: &'a dyn ParseResult,
                _position: tower_lsp_server::ls_types::Position,
                _content: &'a str,
                _freshness: deps_core::FreshnessSettings,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                let origin = self.origin;
                Box::pin(async move { Completions::default().with_origin(origin) })
            }
            fn complete_version<'a>(
                &'a self,
                _request: deps_core::completion::CompletionRequest<'a>,
                _package_name: deps_core::PackageName,
                _prefix: String,
            ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
                unimplemented!()
            }
            fn fallback_completion_prefix<'a>(
                &self,
                _content: &'a str,
                _position: deps_core::position::Position,
            ) -> Option<&'a str> {
                assert!(
                    self.origin.allows_package_name_fallback(),
                    "fallback_completion must not run when origin={:?} blocks it",
                    self.origin
                );
                Some("req")
            }
            fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
                Some(metadata.name().as_str().to_string())
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct MockParseResult {
            uri: url::Url,
        }
        impl ParseResult for MockParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![]
            }
            fn workspace_root(&self) -> Option<&Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        for (origin, should_fall_back) in [
            (CompletionOrigin::Unresolved, true),
            (CompletionOrigin::PackageName, true),
            (CompletionOrigin::Version, false),
            (CompletionOrigin::Feature, false),
        ] {
            let state = Arc::new(ServerState::new());
            state
                .ecosystem_registry
                .register(Arc::new(OriginProbeEcosystem { origin }));

            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);
            let content = "[dependencies]\nreq = \"1.0\"\n".to_string();
            let parse_result: Box<dyn ParseResult> = Box::new(MockParseResult { uri: url });
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
            let result = handle_completion(state, params, client, config).await;

            if should_fall_back {
                match result {
                    Some(CompletionResponse::Array(items)) => {
                        assert_eq!(
                            items.len(),
                            1,
                            "origin={origin:?}: expected the fallback search's one item"
                        );
                        assert_eq!(items[0].label, "requests");
                    }
                    other => panic!(
                        "origin={origin:?}: expected Array([requests]) from the fallback \
                         path, got {other:?}"
                    ),
                }
            } else {
                assert!(
                    result.is_none(),
                    "origin={origin:?}: expected no completion response, got {result:?}"
                );
            }
        }
    }
}

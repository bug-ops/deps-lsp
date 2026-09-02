use crate::config::DepsConfig;
use crate::document::{ServerState, handle_document_change, handle_document_open};
use crate::file_watcher;
use crate::handlers::{
    code_actions, code_lens, completion, diagnostics, document_link, hover, inlay_hints,
};
use deps_core::{PackageName, is_safe_version_string};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::ls_types::{
    CodeActionOptions, CodeActionParams, CodeActionProviderCapability, CodeLens, CodeLensOptions,
    CodeLensParams, CompletionOptions, CompletionOptionsCompletionItem, CompletionParams,
    CompletionResponse, DiagnosticOptions, DiagnosticServerCapabilities,
    DidChangeConfigurationParams, DidChangeTextDocumentParams, DidChangeWatchedFilesParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, DocumentChanges,
    DocumentDiagnosticParams, DocumentDiagnosticReport, DocumentDiagnosticReportResult,
    DocumentLink, DocumentLinkOptions, DocumentLinkParams, ExecuteCommandOptions,
    ExecuteCommandParams, FullDocumentDiagnosticReport, Hover, HoverParams,
    HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams, InlayHint,
    InlayHintParams, MessageType, OneOf, OptionalVersionedTextDocumentIdentifier, Range,
    Registration, RelatedFullDocumentDiagnosticReport, ServerCapabilities, ServerInfo,
    TextDocumentEdit, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Uri,
    WorkspaceEdit,
};
use tower_lsp_server::{Client, LanguageServer, jsonrpc::Result};

/// LSP command identifiers.
mod commands {
    /// Command to update a dependency version.
    pub(super) const UPDATE_VERSION: &str = "deps-lsp.updateVersion";
    /// Command to update every outdated dependency in a document, bound to the code
    /// lens produced by `handlers::code_lens`.
    pub(super) const UPDATE_ALL_OUTDATED: &str = crate::handlers::code_lens::COMMAND_ID;
}

/// Parses a [`DepsConfig`] from a raw JSON settings payload (client
/// `initializationOptions` or `workspace/didChangeConfiguration` settings), warning and
/// returning `None` on any failure rather than silently substituting a default-valued
/// config for the caller to store.
///
/// `DepsConfig` carries `#[serde(deny_unknown_fields)]`, so any key that isn't one of its
/// own top-level fields fails deserialization here rather than being silently ignored —
/// this is what makes the "keep previous configuration" behavior below actually meaningful
/// (issue #227 C2). A weaker "at least one recognized key" check was tried first and
/// rejected: a client that flattens its whole settings tree (e.g. `{"editor": ...,
/// "diagnostics": ..., "python": ...}`) would still pass that check on the one generic key
/// it happens to share with `DepsConfig`, then silently reset every *other* section
/// (`freshness`, `inlay_hints`, ...) to its default — the same silent-wipe bug through a
/// different door. `deny_unknown_fields` closes it structurally: every unrecognized key,
/// anywhere in the payload, is a hard rejection. An empty object `{}` still parses fine —
/// it legitimately means "use every default" for every section.
fn parse_config(value: serde_json::Value) -> Option<DepsConfig> {
    match serde_json::from_value::<DepsConfig>(value) {
        Ok(config) => Some(config),
        Err(e) => {
            tracing::warn!(
                "failed to parse deps-lsp configuration: {e} (keeping previous configuration)"
            );
            None
        }
    }
}

pub struct Backend {
    pub(crate) client: Client,
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
    client_capabilities: Arc<RwLock<Option<tower_lsp_server::ls_types::ClientCapabilities>>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: Arc::new(ServerState::new()),
            config: Arc::new(RwLock::new(DepsConfig::default())),
            client_capabilities: Arc::new(RwLock::new(None)),
        }
    }

    /// Get a reference to the LSP client (primarily for testing/benchmarking).
    #[doc(hidden)]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Handles opening a document using unified ecosystem registry.
    async fn handle_open(
        &self,
        uri: tower_lsp_server::ls_types::Uri,
        content: String,
        version: i32,
    ) {
        match handle_document_open(
            uri.clone(),
            content,
            Some(version),
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        {
            Ok(task) => {
                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to open document {:?}: {}", uri, e);
                self.client
                    .log_message(MessageType::ERROR, format!("Parse error: {e}"))
                    .await;
            }
        }
    }

    /// Handles changes to a document using unified ecosystem registry.
    async fn handle_change(
        &self,
        uri: tower_lsp_server::ls_types::Uri,
        content: String,
        version: i32,
    ) {
        match handle_document_change(
            uri.clone(),
            content,
            Some(version),
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        {
            Ok(task) => {
                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to process document change {:?}: {}", uri, e);
                // Without this, a rejected change (e.g. oversized content) leaves the
                // client editing against a stale server-side DocumentState with no
                // indication the edit was never applied.
                self.client
                    .log_message(MessageType::ERROR, format!("Change rejected: {e}"))
                    .await;
            }
        }
    }

    async fn handle_lockfile_change(&self, lockfile_path: &std::path::Path, ecosystem_id: &str) {
        let Some(ecosystem) = self.state.ecosystem_registry.get(ecosystem_id) else {
            tracing::error!("Unknown ecosystem: {}", ecosystem_id);
            return;
        };

        let Some(lock_provider) = ecosystem.lockfile_provider() else {
            tracing::warn!("Ecosystem {} has no lock file provider", ecosystem_id);
            return;
        };

        // Find all open documents using this lock file
        let affected_uris: Vec<Uri> = self
            .state
            .documents
            .iter()
            .filter_map(|entry| {
                let uri = entry.key();
                let doc = entry.value();
                if doc.ecosystem_id() != ecosystem_id {
                    return None;
                }
                let doc_lockfile = lock_provider.locate_lockfile(uri)?;
                if doc_lockfile == lockfile_path {
                    Some(uri.clone())
                } else {
                    None
                }
            })
            .collect();

        if affected_uris.is_empty() {
            tracing::debug!(
                "No open manifests affected by lock file: {}",
                lockfile_path.display()
            );
            return;
        }

        tracing::info!(
            "Updating {} manifest(s) affected by lock file change",
            affected_uris.len()
        );

        // Reload lock file (cache was invalidated, so this re-parses)
        let resolved_versions = match self
            .state
            .lockfile_cache
            .get_or_parse(lock_provider.as_ref(), lockfile_path)
            .await
        {
            Ok(packages) => packages
                .iter()
                .map(|(name, pkg)| (PackageName::new(name.as_str()), pkg.version.clone().into()))
                .collect::<HashMap<PackageName, deps_core::ConcreteVersion>>(),
            Err(e) => {
                tracing::error!("Failed to reload lock file: {}", e);
                self.client
                    .log_message(
                        MessageType::ERROR,
                        format!("Failed to reload lock file: {e}"),
                    )
                    .await;
                HashMap::new()
            }
        };

        // Snapshot before the loop and drop the guard: `generate_diagnostics_internal`
        // doesn't touch `self.config`, but the affected documents are already open
        // (sourced from `self.state.documents` above), so re-loading them via
        // `handle_diagnostics` (which re-reads `self.config` per URI) would hold this
        // guard across a nested read of the same write-preferring `RwLock` — a writer
        // queued in between would then block that nested read forever.
        let (freshness, severities, offline) = {
            let config = self.config.read().await;
            (
                config.freshness.to_settings(),
                config.diagnostics.to_severities(),
                config.network.offline,
            )
        };

        for uri in affected_uris {
            if let Some(mut doc) = self.state.documents.get_mut(&uri) {
                doc.update_resolved_versions(resolved_versions.clone());
            }

            let items = diagnostics::generate_diagnostics_internal(
                Arc::clone(&self.state),
                &uri,
                freshness,
                severities,
                offline,
            )
            .await;

            self.client.publish_diagnostics(uri, items, None).await;
        }

        if let Err(e) = self.client.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
        if let Err(e) = self.client.code_lens_refresh().await {
            tracing::debug!("code_lens_refresh not supported: {:?}", e);
        }
    }

    /// Check if client supports work done progress.
    async fn supports_progress(&self) -> bool {
        let caps = self.client_capabilities.read().await;
        caps.as_ref()
            .and_then(|c| c.window.as_ref())
            .and_then(|w| w.work_done_progress)
            .unwrap_or(false)
    }

    /// Whether the client requires dynamic registration before it will send
    /// `workspace/didChangeConfiguration` notifications (M3): without this, some clients
    /// never send the notification at all, making live-reload unverifiable.
    async fn did_change_configuration_dynamic_registration_supported(&self) -> bool {
        let caps = self.client_capabilities.read().await;
        caps.as_ref()
            .and_then(|c| c.workspace.as_ref())
            .and_then(|w| w.did_change_configuration.as_ref())
            .and_then(|d| d.dynamic_registration)
            .unwrap_or(false)
    }

    /// Whether the client implements `workspace/diagnostic/refresh`, the notification
    /// used to nudge a pull-diagnostics client to re-request diagnostics after a
    /// configuration change (§2.1). Push-only clients are a known v1 gap (M2).
    async fn diagnostic_refresh_supported(&self) -> bool {
        let caps = self.client_capabilities.read().await;
        caps.as_ref()
            .and_then(|c| c.workspace.as_ref())
            .and_then(|w| w.diagnostics.as_ref())
            .and_then(|d| d.refresh_support)
            .unwrap_or(false)
    }

    fn server_capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            completion_provider: Some(CompletionOptions {
                trigger_characters: Some(vec!["\"".into(), "=".into(), ".".into()]),
                resolve_provider: Some(false),
                completion_item: Some(CompletionOptionsCompletionItem {
                    label_details_support: Some(true),
                }),
                ..Default::default()
            }),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            inlay_hint_provider: Some(OneOf::Left(true)),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(vec![
                    tower_lsp_server::ls_types::CodeActionKind::REFACTOR,
                    tower_lsp_server::ls_types::CodeActionKind::QUICKFIX,
                ]),
                ..Default::default()
            })),
            code_lens_provider: Some(CodeLensOptions {
                resolve_provider: Some(false),
            }),
            document_link_provider: Some(DocumentLinkOptions {
                resolve_provider: Some(false),
                work_done_progress_options: Default::default(),
            }),
            diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
                identifier: Some("deps".into()),
                inter_file_dependencies: false,
                workspace_diagnostics: false,
                ..Default::default()
            })),
            execute_command_provider: Some(ExecuteCommandOptions {
                commands: vec![
                    commands::UPDATE_VERSION.into(),
                    commands::UPDATE_ALL_OUTDATED.into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        tracing::info!("initializing deps-lsp server");

        // Store client capabilities
        *self.client_capabilities.write().await = Some(params.capabilities.clone());
        self.state
            .set_progress_supported(self.supports_progress().await);

        // Parse initialization options
        if let Some(init_options) = params.initialization_options
            && let Some(config) = parse_config(init_options)
        {
            tracing::debug!("loaded configuration: {:?}", config);
            self.state
                .cache
                .set_registry_policy(config.cargo.workspace_registries.to_policy());
            self.state.cache.set_offline(config.network.offline);
            self.state.cache.set_cache_enabled(config.cache.enabled);
            *self.config.write().await = config;
        }

        Ok(InitializeResult {
            capabilities: Self::server_capabilities(),
            server_info: Some(ServerInfo {
                name: "deps-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
            offset_encoding: None,
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        tracing::info!("deps-lsp server initialized");
        self.client
            .log_message(
                MessageType::INFO,
                format!(
                    "deps-lsp v{} ({} {})",
                    env!("CARGO_PKG_VERSION"),
                    env!("GIT_HASH"),
                    env!("BUILD_TIME")
                ),
            )
            .await;

        // Register lock file watchers using patterns from all ecosystems
        let patterns = self.state.ecosystem_registry.all_lockfile_patterns();
        if let Err(e) = file_watcher::register_lock_file_watchers(&self.client, &patterns).await {
            tracing::warn!("Failed to register file watchers: {}", e);
            self.client
                .log_message(MessageType::WARNING, format!("File watching disabled: {e}"))
                .await;
        }

        // Dynamically register for `workspace/didChangeConfiguration` so clients that
        // gate the notification on this (M3) actually send it — without it, a changed
        // `freshness.cooldown_secs` would never reach `did_change_configuration`.
        if self
            .did_change_configuration_dynamic_registration_supported()
            .await
        {
            let registration = Registration {
                id: "deps-lsp-did-change-configuration".to_string(),
                method: "workspace/didChangeConfiguration".to_string(),
                register_options: None,
            };
            if let Err(e) = self.client.register_capability(vec![registration]).await {
                tracing::warn!("Failed to register didChangeConfiguration: {}", e);
            }
        }

        // Spawn background cleanup task for cold start rate limiter, supervised so a
        // panic surfaces as an `error!` log instead of silently stopping cleanup forever.
        let state_clone = Arc::clone(&self.state);
        let cleanup_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(1));
            loop {
                interval.tick().await;
                state_clone
                    .cold_start_limiter
                    .cleanup_old_entries(std::time::Duration::from_mins(5));
                tracing::trace!("Cleaned up old cold start rate limit entries");
            }
        });
        tokio::spawn(async move {
            // Inner loop never returns (`JoinHandle<!>`), so `Ok` is unreachable and this pattern is irrefutable.
            let Err(e) = cleanup_task.await;
            tracing::error!("Cold start rate limiter cleanup task exited unexpectedly: {e}");
        });
    }

    /// Handles `workspace/didChangeConfiguration`, applying a live-reloaded
    /// [`DepsConfig`] without requiring an editor restart (issue #227 §2.1).
    ///
    /// Replace-whole-config semantics, matching [`Self::initialize`]. `null`/absent
    /// settings mean the client expects the pull form (`workspace/configuration`)
    /// instead, which is not implemented in v1 — logged at `debug` and otherwise a
    /// no-op. A payload that fails to parse (or has no keys `DepsConfig` recognizes,
    /// C2) keeps the previously stored configuration rather than silently resetting it
    /// to defaults.
    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        if params.settings.is_null() {
            tracing::debug!(
                "workspace/didChangeConfiguration received null settings; the \
                 workspace/configuration pull form is not implemented, ignoring"
            );
            return;
        }

        let Some(config) = parse_config(params.settings) else {
            return;
        };

        tracing::info!("configuration updated via workspace/didChangeConfiguration");
        self.state
            .cache
            .set_registry_policy(config.cargo.workspace_registries.to_policy());
        // Must land before `workspace_diagnostic_refresh` below, or the refresh re-renders
        // diagnostics under the stale flag values (critic M5).
        self.state.cache.set_offline(config.network.offline);
        self.state.cache.set_cache_enabled(config.cache.enabled);
        *self.config.write().await = config;

        // Hover/completion/code actions are computed on demand and pick up the new
        // config for free. Diagnostics are pull-based, so a pull-capable client must be
        // told to re-request them (push-only clients are a known v1 gap, M2).
        if self.diagnostic_refresh_supported().await
            && let Err(e) = self.client.workspace_diagnostic_refresh().await
        {
            tracing::debug!(
                "workspace/diagnostic/refresh failed or unsupported: {:?}",
                e
            );
        }
    }

    fn shutdown(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        tracing::info!("shutting down deps-lsp server");
        std::future::ready(Ok(()))
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;
        let version = params.text_document.version;

        tracing::info!("document opened: {:?}", uri);

        // Use ecosystem registry to check if we support this file type
        if self.state.ecosystem_registry.get_for_uri(&uri).is_none() {
            tracing::debug!("unsupported file type: {:?}", uri);
            return;
        }

        self.handle_open(uri, content, version).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let version = params.text_document.version;

        if let Some(change) = params.content_changes.first() {
            let content = change.text.clone();

            // Use ecosystem registry to check if we support this file type
            if self.state.ecosystem_registry.get_for_uri(&uri).is_none() {
                tracing::debug!("unsupported file type: {:?}", uri);
                return;
            }

            self.handle_change(uri, content, version).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        tracing::info!("document closed: {:?}", uri);

        self.state.remove_document(&uri);
        self.state.cancel_background_task(&uri).await;
    }

    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        tracing::debug!("Received {} file change events", params.changes.len());

        for change in params.changes {
            let Some(path) = change.uri.to_file_path() else {
                tracing::warn!("Invalid file path in change event: {:?}", change.uri);
                continue;
            };

            let Some(filename) = file_watcher::extract_lockfile_name(&path) else {
                continue;
            };

            let Some(ecosystem) = self.state.ecosystem_registry.get_for_lockfile(filename) else {
                tracing::debug!("Skipping non-lock-file change: {}", filename);
                continue;
            };

            tracing::info!(
                "Lock file changed: {} (ecosystem: {})",
                filename,
                ecosystem.id()
            );

            self.state.lockfile_cache.invalidate(&path);
            self.handle_lockfile_change(&path, ecosystem.id()).await;
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        Ok(hover::handle_hover(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        Ok(completion::handle_completion(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await)
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        // Clone config before async call to release lock early
        let inlay_config = { self.config.read().await.inlay_hints.clone() };
        let range = params.range;

        let hints: Vec<_> = inlay_hints::handle_inlay_hints(
            Arc::clone(&self.state),
            params,
            &inlay_config,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await
        .into_iter()
        .filter(|h| h.position.line >= range.start.line && h.position.line <= range.end.line)
        .collect();

        Ok(Some(hints))
    }

    async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> Result<Option<Vec<tower_lsp_server::ls_types::CodeActionOrCommand>>> {
        tracing::info!(
            "code_action request: uri={:?}, range={:?}",
            params.text_document.uri,
            params.range
        );
        let actions = code_actions::handle_code_actions(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        tracing::info!("code_action response: {} actions", actions.len());
        Ok(Some(actions))
    }

    async fn code_lens(&self, params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        let enabled = { self.config.read().await.code_lens.enabled };
        let lenses = code_lens::handle_code_lens(
            Arc::clone(&self.state),
            params,
            enabled,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        Ok(Some(lenses))
    }

    async fn document_link(&self, params: DocumentLinkParams) -> Result<Option<Vec<DocumentLink>>> {
        let links = document_link::handle_document_link(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        Ok(Some(links))
    }

    async fn diagnostic(
        &self,
        params: DocumentDiagnosticParams,
    ) -> Result<DocumentDiagnosticReportResult> {
        let uri = params.text_document.uri;
        tracing::info!("diagnostic request for: {:?}", uri);

        // Clone config before async call to release lock early
        let diagnostics_config = { self.config.read().await.diagnostics.clone() };

        let items = diagnostics::handle_diagnostics(
            Arc::clone(&self.state),
            &uri,
            &diagnostics_config,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;

        tracing::info!("returning {} diagnostics", items.len());

        Ok(DocumentDiagnosticReportResult::Report(
            DocumentDiagnosticReport::Full(RelatedFullDocumentDiagnosticReport {
                related_documents: None,
                full_document_diagnostic_report: FullDocumentDiagnosticReport {
                    result_id: None,
                    items,
                },
            }),
        ))
    }

    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> Result<Option<serde_json::Value>> {
        tracing::info!("execute_command: {:?}", params.command);

        if params.command == commands::UPDATE_VERSION
            && let Some(args) = params.arguments.first()
            && let Ok(update_args) = serde_json::from_value::<UpdateVersionArgs>(args.clone())
        {
            if let Some(edit) = build_update_version_edit(&update_args)
                && let Err(e) = self.client.apply_edit(edit).await
            {
                tracing::error!("Failed to apply edit: {:?}", e);
            }
        } else if params.command == commands::UPDATE_ALL_OUTDATED
            && let Some(args) = params.arguments.first()
            && let Ok(update_args) = serde_json::from_value::<UpdateAllOutdatedArgs>(args.clone())
        {
            self.execute_update_all_outdated(update_args.uri).await;
        }

        Ok(None)
    }
}

impl Backend {
    /// Warns the client that the "update all outdated" command was refused because the
    /// document's dependency data isn't safely usable (see the three-condition cold-start
    /// refusal below).
    async fn warn_update_all_outdated_not_ready(&self) {
        self.client
            .show_message(
                MessageType::WARNING,
                "deps-lsp: dependency data is not ready for this document",
            )
            .await;
    }

    /// Recomputes and applies the batch, version-guarded `WorkspaceEdit` for
    /// `deps-lsp.updateAllOutdated`.
    ///
    /// Refuses to act — no-op plus a `window/showMessage` — unless all of:
    /// - the document is present in `state` (never calls `ensure_document_loaded` — a
    ///   client-supplied URI must not trigger a cold disk read here);
    /// - [`DocumentState::is_ready_for_batch_update`](crate::document::DocumentState::is_ready_for_batch_update)
    ///   holds: `loading_state` is not `Loading`, and it has a known LSP `version`
    ///   (`None` means this state was populated from disk after a missed `didOpen` —
    ///   server restart/crash — where the client's buffer may hold unsaved edits disk
    ///   does not reflect). The same predicate gates whether `handlers::code_lens` even
    ///   renders the lens, so a visible lens never leads to this refusal;
    /// - the ecosystem and parse result are resolvable (in practice always true once
    ///   the above hold — surfaced with the same message as the conditions above, since
    ///   the caller cannot act on the difference);
    /// - recomputing the edits at click time still finds at least one outdated,
    ///   safely-editable dependency — a distinct, non-`WARNING` message covers the case
    ///   where the document changed between the lens render and this click.
    ///
    /// The edits are recomputed from the current document, not baked into the lens
    /// arguments, so a lens computed at T and clicked at T+n reflects the state at click
    /// time. When the client advertises `workspace.workspaceEdit.documentChanges`, the
    /// `WorkspaceEdit` also carries the document's LSP version, so the client rejects
    /// the whole batch if its buffer moved between computation and apply — this closes
    /// the remaining race for clients that support it. Clients that don't advertise the
    /// capability get the plain `changes` map instead, which carries no version; for
    /// those, this recompute-at-click-time step is the only staleness mitigation.
    // `doc` (a DashMap shard `Ref`) is dropped via an explicit `drop(doc)` before every
    // `.await` reachable from this point (see below) — clippy's `await_holding_invalid_type`
    // does not recognize a manual `drop()` in this control-flow shape and flags the
    // binding regardless. Verified as a false positive, not a real hazard: nothing to fix.
    #[allow(clippy::await_holding_invalid_type)]
    async fn execute_update_all_outdated(&self, uri: Uri) {
        let Some(doc) = self.state.get_document(&uri) else {
            self.warn_update_all_outdated_not_ready().await;
            return;
        };

        if !doc.is_ready_for_batch_update() {
            drop(doc);
            self.warn_update_all_outdated_not_ready().await;
            return;
        }

        let Some(ecosystem) = self.state.ecosystem_registry.get(doc.ecosystem_id()) else {
            tracing::warn!("Unknown ecosystem for {:?}", uri);
            drop(doc);
            self.warn_update_all_outdated_not_ready().await;
            return;
        };

        let Some(parse_result) = doc.parse_result() else {
            tracing::warn!("No parse result for {:?}", uri);
            drop(doc);
            self.warn_update_all_outdated_not_ready().await;
            return;
        };

        let edits = deps_core::collect_update_all_edits(
            parse_result,
            &doc.content,
            deps_core::VersionData::new(&doc.cached_versions, &doc.resolved_versions),
            ecosystem.formatter(),
        );
        let version = doc.version;
        drop(doc);

        if edits.is_empty() {
            // Not a failure — the document changed between the lens render and this
            // click (or the client sent a stale command), so there is nothing left to
            // apply. Still worth a message: a silent no-op after a visible click reads
            // as a broken button (§4.6's rationale for not swallowing failures here).
            self.client
                .show_message(
                    MessageType::INFO,
                    "deps-lsp: no outdated dependencies to update",
                )
                .await;
            return;
        }

        let supports_document_changes = self
            .client_capabilities
            .read()
            .await
            .as_ref()
            .and_then(|c| c.workspace.as_ref())
            .and_then(|w| w.workspace_edit.as_ref())
            .and_then(|we| we.document_changes)
            .unwrap_or(false);

        let edit = build_update_all_outdated_edit(&uri, version, edits, supports_document_changes);

        match self.client.apply_edit(edit).await {
            Ok(response) if response.applied => {}
            Ok(response) => {
                tracing::warn!(
                    "workspace/applyEdit for {:?} was rejected: {:?}",
                    uri,
                    response.failure_reason
                );
                self.client
                    .show_message(
                        MessageType::WARNING,
                        "deps-lsp: failed to apply dependency updates",
                    )
                    .await;
            }
            Err(e) => {
                tracing::error!("Failed to apply edit for {:?}: {:?}", uri, e);
                self.client
                    .show_message(
                        MessageType::WARNING,
                        "deps-lsp: failed to apply dependency updates",
                    )
                    .await;
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct UpdateVersionArgs {
    uri: Uri,
    range: Range,
    version: String,
}

/// Builds the `WorkspaceEdit` for `deps-lsp.updateVersion`, or `None` if `args.version`
/// fails [`is_safe_version_string`] — this command builds its `TextEdit` directly from a
/// client-supplied argument, bypassing `EcosystemFormatter` entirely, so the same
/// manifest-injection risk `is_safe_version_string` guards elsewhere applies here too.
fn build_update_version_edit(args: &UpdateVersionArgs) -> Option<WorkspaceEdit> {
    if !is_safe_version_string(&args.version) {
        tracing::error!(
            version = %args.version,
            "deps-lsp.updateVersion: rejecting unsafe version string"
        );
        return None;
    }

    let mut edits = HashMap::new();
    edits.insert(
        args.uri.clone(),
        vec![TextEdit {
            range: args.range,
            new_text: format!("\"{}\"", args.version),
        }],
    );

    Some(WorkspaceEdit {
        changes: Some(edits),
        ..Default::default()
    })
}

/// Arguments for `deps-lsp.updateAllOutdated` — the URI only. Ranges are recomputed at
/// execution time (see `Backend::execute_update_all_outdated`), never baked into the
/// command arguments.
#[derive(serde::Deserialize)]
struct UpdateAllOutdatedArgs {
    uri: Uri,
}

/// Builds the `WorkspaceEdit` for `deps-lsp.updateAllOutdated`.
///
/// Emits `document_changes` (versioned per `TextDocumentEdit`) when
/// `supports_document_changes` is `true` — gated on the client's
/// `workspace.workspaceEdit.documentChanges` capability — and falls back to the untyped
/// `changes` map otherwise.
fn build_update_all_outdated_edit(
    uri: &Uri,
    version: Option<i32>,
    edits: Vec<TextEdit>,
    supports_document_changes: bool,
) -> WorkspaceEdit {
    if supports_document_changes {
        WorkspaceEdit {
            document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier {
                    uri: uri.clone(),
                    version,
                },
                edits: edits.into_iter().map(OneOf::Left).collect(),
            }])),
            ..Default::default()
        }
    } else {
        let mut changes = HashMap::new();
        changes.insert(uri.clone(), edits);
        WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_capabilities() {
        let caps = Backend::server_capabilities();

        // Verify text document sync
        assert!(caps.text_document_sync.is_some());

        // Verify completion provider
        assert!(caps.completion_provider.is_some());
        let completion = caps.completion_provider.unwrap();
        assert!(!completion.resolve_provider.unwrap()); // resolve_provider is disabled

        // Verify hover provider
        assert!(caps.hover_provider.is_some());

        // Verify inlay hints
        assert!(caps.inlay_hint_provider.is_some());

        // Verify diagnostics
        assert!(caps.diagnostic_provider.is_some());
    }

    #[tokio::test]
    async fn test_backend_creation() {
        let (_service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        // Backend should be created successfully
        // This is a minimal smoke test
    }

    #[tokio::test]
    async fn test_initialize_without_options() {
        let (_service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        // Should initialize successfully with default config
        // Integration tests will test actual LSP protocol
    }

    #[test]
    fn test_server_capabilities_text_document_sync() {
        let caps = Backend::server_capabilities();

        match caps.text_document_sync {
            Some(TextDocumentSyncCapability::Kind(kind)) => {
                assert_eq!(kind, TextDocumentSyncKind::FULL);
            }
            _ => panic!("Expected text document sync kind to be FULL"),
        }
    }

    #[test]
    fn test_server_capabilities_completion_triggers() {
        let caps = Backend::server_capabilities();

        let completion = caps
            .completion_provider
            .expect("completion provider should exist");
        let triggers = completion
            .trigger_characters
            .expect("trigger characters should exist");

        assert!(triggers.contains(&"\"".to_string()));
        assert!(triggers.contains(&"=".to_string()));
        assert!(triggers.contains(&".".to_string()));
        assert_eq!(triggers.len(), 3);
    }

    #[test]
    fn test_server_capabilities_code_actions() {
        let caps = Backend::server_capabilities();

        match caps.code_action_provider {
            Some(CodeActionProviderCapability::Options(opts)) => {
                let kinds = opts
                    .code_action_kinds
                    .expect("code action kinds should exist");
                assert!(kinds.contains(&tower_lsp_server::ls_types::CodeActionKind::REFACTOR));
                assert!(kinds.contains(&tower_lsp_server::ls_types::CodeActionKind::QUICKFIX));
            }
            _ => panic!("Expected code action provider options"),
        }
    }

    #[test]
    fn test_server_capabilities_diagnostics_config() {
        let caps = Backend::server_capabilities();

        match caps.diagnostic_provider {
            Some(DiagnosticServerCapabilities::Options(opts)) => {
                assert_eq!(opts.identifier, Some("deps".to_string()));
                assert!(!opts.inter_file_dependencies);
                assert!(!opts.workspace_diagnostics);
            }
            _ => panic!("Expected diagnostic options"),
        }
    }

    #[test]
    fn test_server_capabilities_execute_command() {
        let caps = Backend::server_capabilities();

        let execute = caps
            .execute_command_provider
            .expect("execute command provider should exist");
        assert!(
            execute
                .commands
                .contains(&commands::UPDATE_VERSION.to_string())
        );
    }

    #[test]
    fn test_commands_constants() {
        assert_eq!(commands::UPDATE_VERSION, "deps-lsp.updateVersion");
    }

    #[tokio::test]
    async fn test_backend_state_initialization() {
        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        assert_eq!(backend.state.documents.len(), 0);
    }

    #[tokio::test]
    async fn test_backend_config_initialization() {
        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        let config = backend.config.read().await;
        assert!(config.inlay_hints.enabled);
    }

    #[test]
    fn test_update_version_args_deserialization() {
        let json = serde_json::json!({
            "uri": "file:///test/Cargo.toml",
            "range": {
                "start": {"line": 5, "character": 10},
                "end": {"line": 5, "character": 15}
            },
            "version": "1.0.0"
        });

        let args: UpdateVersionArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.version, "1.0.0");
        assert_eq!(args.range.start.line, 5);
        assert_eq!(args.range.start.character, 10);
    }

    #[tokio::test]
    async fn test_execute_command_update_version_with_unsafe_version_does_not_panic() {
        // Smoke test only: `execute_command` returns `Ok(None)` on this uninitialized-
        // backend harness whether `build_update_version_edit`'s guard fires or not
        // (`apply_edit` itself errors out on an uninitialized client, per
        // `test_execute_command_update_all_outdated_apply_edit_failure_does_not_panic`'s
        // own comment) — it cannot distinguish "guard fired" from "guard absent". The
        // actual regression coverage for the guard lives on `build_update_version_edit`
        // directly, below.
        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        let params = ExecuteCommandParams {
            command: commands::UPDATE_VERSION.to_string(),
            arguments: vec![serde_json::json!({
                "uri": "file:///test/Cargo.toml",
                "range": {
                    "start": {"line": 0, "character": 9},
                    "end": {"line": 0, "character": 14}
                },
                "version": "1.2.0\", \"evil\": \"true"
            })],
            work_done_progress_params: Default::default(),
        };

        let result = backend.execute_command(params).await;
        assert!(result.is_ok());
    }

    fn update_version_args(version: &str) -> UpdateVersionArgs {
        UpdateVersionArgs {
            uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
            range: Range::default(),
            version: version.to_string(),
        }
    }

    #[test]
    fn test_build_update_version_edit_rejects_unsafe_version() {
        // Regression for #302: an unsafe client-supplied version must never reach a
        // `TextEdit` via `deps-lsp.updateVersion`.
        let args = update_version_args("1.2.0\", \"evil\": \"true");
        assert!(build_update_version_edit(&args).is_none());
    }

    #[test]
    fn test_build_update_version_edit_accepts_safe_version() {
        let args = update_version_args("1.2.0");
        let edit = build_update_version_edit(&args).expect("a safe version must produce an edit");

        let changes = edit.changes.expect("changes present");
        let edits = changes.get(&args.uri).expect("edit for the given uri");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].range, args.range);
        assert_eq!(edits[0].new_text, "\"1.2.0\"");
    }

    #[test]
    fn test_server_capabilities_code_lens() {
        let caps = Backend::server_capabilities();
        let code_lens = caps
            .code_lens_provider
            .expect("code lens provider should exist");
        assert_eq!(code_lens.resolve_provider, Some(false));
    }

    #[test]
    fn test_server_capabilities_execute_command_includes_update_all_outdated() {
        let caps = Backend::server_capabilities();
        let execute = caps
            .execute_command_provider
            .expect("execute command provider should exist");
        assert!(
            execute
                .commands
                .contains(&commands::UPDATE_ALL_OUTDATED.to_string())
        );
    }

    #[test]
    fn test_commands_update_all_outdated_matches_code_lens_command_id() {
        assert_eq!(commands::UPDATE_ALL_OUTDATED, "deps-lsp.updateAllOutdated");
    }

    #[test]
    fn test_update_all_outdated_args_deserialization() {
        let json = serde_json::json!({ "uri": "file:///test/Cargo.toml" });
        let args: UpdateAllOutdatedArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.uri.as_str(), "file:///test/Cargo.toml");
    }

    #[test]
    fn test_build_update_all_outdated_edit_uses_document_changes_with_version() {
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let edits = vec![TextEdit {
            range: Range::default(),
            new_text: "1.2.0".into(),
        }];

        let edit = build_update_all_outdated_edit(&uri, Some(7), edits, true);

        assert!(edit.changes.is_none());
        let DocumentChanges::Edits(doc_edits) =
            edit.document_changes.expect("document_changes present")
        else {
            panic!("expected DocumentChanges::Edits variant");
        };
        assert_eq!(doc_edits.len(), 1);
        assert_eq!(doc_edits[0].text_document.uri, uri);
        assert_eq!(doc_edits[0].text_document.version, Some(7));
        assert_eq!(doc_edits[0].edits.len(), 1);
    }

    #[test]
    fn test_build_update_all_outdated_edit_falls_back_to_changes_map() {
        let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
        let edits = vec![TextEdit {
            range: Range::default(),
            new_text: "1.2.0".into(),
        }];

        let edit = build_update_all_outdated_edit(&uri, Some(7), edits, false);

        assert!(edit.document_changes.is_none());
        let changes = edit.changes.expect("changes present");
        assert_eq!(changes.get(&uri).map(Vec::len), Some(1));
    }

    // =========================================================================
    // Issue #227: `parse_config` (C2) and `did_change_configuration` live-reload
    // =========================================================================

    mod parse_config_tests {
        use super::*;

        #[test]
        fn test_parse_config_accepts_empty_object() {
            let config = parse_config(serde_json::json!({})).expect("empty object is valid");
            assert!(config.freshness.enabled);
        }

        #[test]
        fn test_parse_config_accepts_recognized_keys() {
            let config = parse_config(serde_json::json!({
                "freshness": { "cooldown_secs": 60 }
            }))
            .expect("payload with a recognized key is valid");
            assert_eq!(config.freshness.cooldown_secs, 60);
        }

        /// C2 regression: a section-wrapped payload (a real shape some clients send)
        /// has none of `DepsConfig`'s own keys, so it would otherwise deserialize
        /// silently into an all-defaults config, discarding the user's settings.
        /// `deny_unknown_fields` rejects it as `deps-lsp` not being a `DepsConfig` field.
        #[test]
        fn test_parse_config_rejects_section_wrapped_payload() {
            let result = parse_config(serde_json::json!({
                "deps-lsp": { "freshness": { "cooldown_secs": 60 } }
            }));
            assert!(
                result.is_none(),
                "a payload with no recognized top-level key must be rejected, not \
                 silently accepted as all-defaults"
            );
        }

        /// Security audit regression: the *previous* "at least one recognized key"
        /// positive-signal check would have accepted this payload outright (it does
        /// contain a real `diagnostics` key) and then silently reset `freshness` and
        /// every other unmentioned section to its default — the same C2 silent-wipe
        /// through a different door. `deny_unknown_fields` closes it: any unrecognized
        /// sibling key anywhere in the payload rejects the whole thing.
        #[test]
        fn test_parse_config_rejects_mixed_blob_with_one_recognized_key_and_unknown_siblings() {
            let result = parse_config(serde_json::json!({
                "diagnostics": { "outdated_severity": 1 },
                "editor": { "fontSize": 14 },
                "python": { "linting": true }
            }));
            assert!(
                result.is_none(),
                "a payload with unrecognized sibling keys must be rejected wholesale, \
                 not accepted because one key happens to match"
            );
        }

        #[test]
        fn test_parse_config_rejects_malformed_field_value() {
            let result = parse_config(serde_json::json!({ "freshness": "not an object" }));
            assert!(result.is_none());
        }

        #[test]
        fn test_parse_config_rejects_non_object_payload() {
            let result = parse_config(serde_json::json!(["not", "an", "object"]));
            assert!(result.is_none());
        }
    }

    /// Tester gap: only the `false`/absent branch of these two capability checks was
    /// incidentally covered (every other test builds a `Backend` that never sets
    /// `client_capabilities`). These pin the `true` branch directly.
    mod capability_support_tests {
        use super::*;
        use tower_lsp_server::ls_types::{
            ClientCapabilities, DiagnosticWorkspaceClientCapabilities,
            DynamicRegistrationClientCapabilities, WorkspaceClientCapabilities,
        };

        #[tokio::test]
        async fn test_did_change_configuration_dynamic_registration_supported_true_branch() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            *backend.client_capabilities.write().await = Some(ClientCapabilities {
                workspace: Some(WorkspaceClientCapabilities {
                    did_change_configuration: Some(DynamicRegistrationClientCapabilities {
                        dynamic_registration: Some(true),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });

            assert!(
                backend
                    .did_change_configuration_dynamic_registration_supported()
                    .await
            );
        }

        #[tokio::test]
        async fn test_diagnostic_refresh_supported_true_branch() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            *backend.client_capabilities.write().await = Some(ClientCapabilities {
                workspace: Some(WorkspaceClientCapabilities {
                    diagnostics: Some(DiagnosticWorkspaceClientCapabilities {
                        refresh_support: Some(true),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });

            assert!(backend.diagnostic_refresh_supported().await);
        }
    }

    mod initialize_tests {
        use super::*;

        /// Tester gap: `initialize` shares `parse_config` with `did_change_configuration`
        /// (only the latter had end-to-end coverage), so this exercises the same
        /// `deny_unknown_fields` positive-signal path through `Backend::initialize` itself
        /// — a section-wrapped `initializationOptions` payload must not silently reset the
        /// user's config to defaults.
        #[tokio::test]
        async fn test_initialize_applies_valid_initialization_options() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend
                .initialize(InitializeParams {
                    initialization_options: Some(
                        serde_json::json!({ "freshness": { "cooldown_secs": 60 } }),
                    ),
                    ..Default::default()
                })
                .await;

            assert!(result.is_ok());
            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 60);
        }

        /// C2 through `initialize`: a section-wrapped payload (`deny_unknown_fields`
        /// rejects `deps-lsp` as an unrecognized top-level key) must leave the
        /// already-`Default`-constructed config untouched, not reset it to some other
        /// all-defaults value silently.
        #[tokio::test]
        async fn test_initialize_keeps_default_config_on_malformed_initialization_options() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend
                .initialize(InitializeParams {
                    initialization_options: Some(
                        serde_json::json!({ "deps-lsp": { "freshness": { "cooldown_secs": 60 } } }),
                    ),
                    ..Default::default()
                })
                .await;

            assert!(result.is_ok());
            assert_eq!(
                backend.config.read().await.freshness.cooldown_secs,
                deps_core::DEFAULT_COOLDOWN_SECS,
                "malformed initializationOptions must not silently change the config"
            );
        }

        #[tokio::test]
        async fn test_initialize_without_initialization_options_keeps_defaults() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend.initialize(InitializeParams::default()).await;

            assert!(result.is_ok());
            assert!(backend.config.read().await.freshness.enabled);
        }
    }

    mod did_change_configuration_tests {
        use super::*;
        use tower_lsp_server::ls_types::DidChangeConfigurationParams;

        #[tokio::test]
        async fn test_did_change_configuration_applies_valid_payload() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "freshness": { "cooldown_secs": 60 } }),
                })
                .await;

            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 60);
        }

        /// C2 end-to-end: a section-wrapped payload must never wipe the previously
        /// stored configuration back to defaults.
        #[tokio::test]
        async fn test_did_change_configuration_keeps_previous_on_malformed_payload() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "freshness": { "cooldown_secs": 60 } }),
                })
                .await;
            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 60);

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "deps-lsp": { "freshness": { "cooldown_secs": 999 } } }),
                })
                .await;

            assert_eq!(
                backend.config.read().await.freshness.cooldown_secs,
                60,
                "a malformed/unrecognized payload must not overwrite the previous configuration"
            );
        }

        /// §2.1 point 4: `null` settings mean the client expects the pull form
        /// (`workspace/configuration`), which v1 does not implement — must be a no-op,
        /// not a reset to defaults.
        #[tokio::test]
        async fn test_did_change_configuration_null_settings_is_noop() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "freshness": { "cooldown_secs": 60 } }),
                })
                .await;
            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 60);

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::Value::Null,
                })
                .await;

            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 60);
        }

        /// Issue #483 (critic M6a): the primary UX of the flag — a live
        /// `workspace/didChangeConfiguration` toggle must both block fetches immediately
        /// when turned on and let them resume immediately when turned back off, with no
        /// editor restart.
        #[tokio::test]
        async fn test_did_change_configuration_offline_to_online_transition_resumes_fetching() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let mut server = mockito::Server::new_async().await;
            let url = format!("{}/api/data", server.url());

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "network": { "offline": true } }),
                })
                .await;
            assert!(backend.state.cache.is_offline());

            let blocked_mock = server
                .mock("GET", "/api/data")
                .with_status(200)
                .with_body("must not be fetched")
                .expect(0)
                .create_async()
                .await;
            let result = backend.state.cache.get_cached(&url).await;
            assert!(matches!(result, Err(deps_core::DepsError::Offline { .. })));
            blocked_mock.assert_async().await;

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "network": { "offline": false } }),
                })
                .await;
            assert!(!backend.state.cache.is_offline());

            let resumed_mock = server
                .mock("GET", "/api/data")
                .with_status(200)
                .with_body("fetched after returning online")
                .expect(1)
                .create_async()
                .await;
            let result = backend.state.cache.get_cached(&url).await.unwrap();
            assert_eq!(result.as_ref(), b"fetched after returning online");
            resumed_mock.assert_async().await;
        }

        /// C1 regression: `did_change_configuration` makes a concurrent `config.write()`
        /// reachable for the first time. Every handler that nested-reads `config` inside
        /// `ensure_document_loaded` must drop its own outer guard first — otherwise a
        /// writer queued in between permanently blocks the nested read (tokio's `RwLock`
        /// is write-preferring).
        ///
        /// An earlier version of this test used an unseeded `test_uri`, so both handlers
        /// bailed out of `ensure_document_loaded` on ENOENT *before* ever reaching their
        /// own config snapshot — it passed in 0.01s regardless of whether the deadlock
        /// existed. Fixed here by seeding the document directly (so the fast path in
        /// `ensure_document_loaded` returns without touching `config` at all, and both
        /// handlers reach their real snapshot reads), running on a multi-threaded runtime
        /// (genuine OS-thread concurrency, not `current_thread`'s single deterministic
        /// poll order), and lining hover/diagnostics/the config write up on a `Barrier` so
        /// all three contend for the lock at essentially the same instant every run.
        #[cfg(feature = "cargo")]
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn test_no_deadlock_between_config_write_and_concurrent_hover_and_diagnostics() {
            use crate::document::DocumentState;
            use crate::handlers::{diagnostics, hover};
            use deps_core::EcosystemId;
            use tokio::sync::Barrier;
            use tower_lsp_server::ls_types::{
                HoverParams, Position, TextDocumentIdentifier, TextDocumentPositionParams,
            };

            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Seed the document so `ensure_document_loaded`'s fast path (already loaded)
            // returns immediately, letting both handlers reach their own config reads.
            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            backend.state.update_document(uri.clone(), doc_state);

            let barrier = Arc::new(Barrier::new(3));

            let hover_task = tokio::spawn({
                let state = Arc::clone(&backend.state);
                let config = Arc::clone(&backend.config);
                let client = backend.client.clone();
                let uri = uri.clone();
                let barrier = Arc::clone(&barrier);
                async move {
                    barrier.wait().await;
                    // Cursor position outside any dependency's span — `generate_hover`
                    // returns immediately without a registry round trip, so this stays
                    // offline and fast while still exercising hover's own config read.
                    let params = HoverParams {
                        text_document_position_params: TextDocumentPositionParams {
                            text_document: TextDocumentIdentifier { uri },
                            position: Position::new(99, 0),
                        },
                        work_done_progress_params: Default::default(),
                    };
                    hover::handle_hover(state, params, client, config).await
                }
            });

            let diagnostics_config_snapshot = { backend.config.read().await.diagnostics.clone() };
            let diagnostics_task = tokio::spawn({
                let state = Arc::clone(&backend.state);
                let config = Arc::clone(&backend.config);
                let client = backend.client.clone();
                let uri = uri.clone();
                let barrier = Arc::clone(&barrier);
                async move {
                    barrier.wait().await;
                    diagnostics::handle_diagnostics(
                        state,
                        &uri,
                        &diagnostics_config_snapshot,
                        client,
                        config,
                    )
                    .await
                }
            });

            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                barrier.wait().await;
                backend
                    .did_change_configuration(DidChangeConfigurationParams {
                        settings: serde_json::json!({ "freshness": { "cooldown_secs": 42 } }),
                    })
                    .await;
                tokio::join!(hover_task, diagnostics_task)
            })
            .await
            .expect(
                "hover/diagnostics must not deadlock against a concurrent \
                 did_change_configuration write (issue #227 C1)",
            );

            outcome.0.expect("hover task panicked");
            outcome.1.expect("diagnostics task panicked");
            assert_eq!(backend.config.read().await.freshness.cooldown_secs, 42);
        }
    }

    #[cfg(feature = "cargo")]
    mod update_all_outdated_execute_command_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::EcosystemId;

        fn command_params(uri: &Uri) -> ExecuteCommandParams {
            ExecuteCommandParams {
                command: commands::UPDATE_ALL_OUTDATED.to_string(),
                arguments: vec![serde_json::json!({ "uri": uri.as_str() })],
                work_done_progress_params: Default::default(),
            }
        }

        #[tokio::test]
        async fn test_execute_command_update_all_outdated_closed_document_no_op() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            // Pin the precondition the refusal actually depends on: no document at all.
            assert!(backend.state.get_document(&uri).is_none());

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
            assert!(
                backend.state.get_document(&uri).is_none(),
                "a refused command must not create a document"
            );
        }

        #[tokio::test]
        async fn test_execute_command_update_all_outdated_loading_document_no_op() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.clone(),
                parse_result,
            );
            doc_state.set_version(Some(1));
            doc_state.set_loading();
            // Pin the precondition directly: this fixture must actually be "not ready"
            // per the same predicate `execute_command` consults, not just assumed to be.
            assert!(!doc_state.is_ready_for_batch_update());
            backend.state.update_document(uri.clone(), doc_state);

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
            assert_eq!(
                backend.state.get_document(&uri).unwrap().content,
                content,
                "a refused command must not touch document content"
            );
        }

        #[tokio::test]
        async fn test_execute_command_update_all_outdated_no_version_no_op() {
            // `version: None` mirrors a document populated from disk after a missed
            // didOpen (server restart/crash) — must be refused even though loaded and
            // not `Loading`.
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.set_loaded();
            // `version` deliberately left as `None`.
            assert!(!doc_state.is_ready_for_batch_update());
            backend.state.update_document(uri.clone(), doc_state);

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_execute_command_update_all_outdated_apply_edit_failure_does_not_panic() {
            // This test `Backend` is never `initialize`d, so `apply_edit` returns `Err`
            // (per its documented behavior) — exercises the failure/warning path.
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
            let mut doc_state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            doc_state.set_version(Some(1));
            doc_state.set_loaded();
            // This fixture must actually pass the readiness gate — the failure below is
            // from `apply_edit`, not from the refusal predicate this pins as satisfied.
            assert!(doc_state.is_ready_for_batch_update());
            let mut cached = HashMap::new();
            cached.insert(
                "serde".into(),
                deps_core::PackageVersions::latest_only("1.2.0"),
            );
            doc_state.update_cached_versions(cached);
            backend.state.update_document(uri.clone(), doc_state);

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
        }
    }
}

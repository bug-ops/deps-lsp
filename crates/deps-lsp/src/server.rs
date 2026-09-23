use crate::config::DepsConfig;
use crate::document::{
    CLIENT_REFRESH_TIMEOUT, ServerState, handle_document_change, handle_document_open,
};
use crate::file_watcher;
use crate::handlers::{
    code_actions, code_lens, completion, diagnostics, document_link, hover, inlay_hints,
};
use deps_core::is_safe_version_string;
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
    /// Command to pin every mutable-ref dependency an ecosystem can resolve to a commit
    /// SHA, bound to the bulk "Pin N {noun} to commit SHA" lens (issue #633, generalized
    /// cross-ecosystem in #640). Registered/dispatched unconditionally for every
    /// ecosystem through `Ecosystem::collect_pin_all_to_sha_edits` — its trait default
    /// returns no edits, so the command is simply always a no-op for an ecosystem with
    /// no mutable-ref pin concept, rather than needing its own feature gate.
    pub(super) const PIN_ALL_TO_SHA: &str = deps_core::lsp_helpers::PIN_ALL_TO_SHA_COMMAND_ID;
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

/// Builds the `window/showMessage` warning text for a rejected
/// `registries.gitlab_instance_host` value.
///
/// `raw` is redacted via [`deps_core::net_policy::RedactedUrl`] before being interpolated
/// (issue #808): `raw` is exactly the attacker/user-controlled config value
/// `deps_engine::setup::validate_gitlab_instance_host` rejected, which can be credential-shaped (e.g.
/// `user:hunter2@gitlab.corp`) — interpolating it verbatim into a message shown in the
/// editor UI is a second, user-visible sink for the same credential leak #808 closed in the
/// `tracing::warn!`/error-`Display` path, and arguably worse since it isn't just a log line.
/// Extracted as its own pure function so the redaction can be unit-tested without driving a
/// full LSP client transport.
#[cfg(feature = "gitlab-ci")]
fn gitlab_instance_host_invalid_message(
    raw: &str,
    error: &deps_core::net_policy::IndexUrlError,
) -> String {
    let redacted = deps_core::net_policy::RedactedUrl::new(raw);
    format!(
        "deps-lsp: registries.gitlab_instance_host value '{redacted}' is invalid \
         ({error}) and will be ignored — instance-host resolution stays \
         unresolved and GITLAB_TOKEN will not be sent to gitlab.com or any other \
         host until this is corrected"
    )
}

/// Validates a newly configured `registries.gitlab_instance_host` value and, when it is
/// rejected, surfaces the rejection to the user via `window/showMessage` rather than only
/// `tracing::warn` (security review, issue #466) — an invalid value silently redirecting
/// `PRIVATE-TOKEN` to `gitlab.com` (or disabling instance-host resolution entirely) with no
/// visible signal was the exact failure mode that review flagged.
///
/// The instance host is re-validated (and logged at `warn`) lazily on every read too, via
/// `deps_gitlab_ci::host::GitlabInstanceHost::get` — this duplicates just the validation
/// call, once per config update, to turn it into a one-time, user-visible notice instead of
/// a read that never surfaces past the log. The validation itself goes through
/// `deps_engine::setup::validate_gitlab_instance_host` rather than naming `deps_gitlab_ci`
/// directly, so this adapter-side notification does not need to depend on the concrete
/// ecosystem crate (`specs/062-cli-check-mode/architecture-decision.md` §3.3).
#[cfg(feature = "gitlab-ci")]
async fn warn_if_gitlab_instance_host_invalid(
    client: &Client,
    raw: &str,
    policy: &deps_core::net_policy::RegistryAccessPolicy,
) {
    if let Err(error) = deps_engine::setup::validate_gitlab_instance_host(raw, policy) {
        client
            .show_message(
                MessageType::WARNING,
                gitlab_instance_host_invalid_message(raw, &error),
            )
            .await;
    }
}

/// The `tower-lsp-server` [`LanguageServer`] implementation for `deps-lsp`.
///
/// Holds the LSP client handle, per-document [`ServerState`], the live
/// [`DepsConfig`], and the client's negotiated capabilities.
pub struct Backend {
    pub(crate) client: Client,
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
    client_capabilities: Arc<RwLock<Option<tower_lsp_server::ls_types::ClientCapabilities>>>,
}

impl Backend {
    /// Creates a new backend bound to the given LSP client handle.
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
                // Without this, a rejected change leaves the client editing against a
                // stale DocumentState with no indication the edit was never applied.
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

        // `locate_lockfile` does a synchronous ancestor-directory `stat` walk per candidate
        // document (#963), so scanning inline would block the tokio worker thread once per
        // document. Run the whole scan in `spawn_blocking` instead.
        let state = Arc::clone(&self.state);
        let lock_provider_for_scan = Arc::clone(&lock_provider);
        let ecosystem_id_owned = ecosystem_id.to_string();
        let lockfile_path_owned = lockfile_path.to_path_buf();
        let affected_uris: Vec<Uri> = tokio::task::spawn_blocking(move || {
            state
                .documents
                .iter()
                .filter_map(|entry| {
                    let uri = entry.key();
                    let doc = entry.value();
                    if doc.ecosystem_id() != ecosystem_id_owned {
                        return None;
                    }
                    let domain_uri = crate::lsp_types_interop::from_lsp_uri(uri)?;
                    let doc_lockfile = lock_provider_for_scan.locate_lockfile(&domain_uri)?;
                    if doc_lockfile == lockfile_path_owned {
                        Some(uri.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("lock file affected-document scan panicked: {}", e);
            Vec::new()
        });

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
        let (resolved_versions, resolved_version_candidates) = match self
            .state
            .lockfile_cache
            .get_or_parse(lock_provider.as_ref(), lockfile_path)
            .await
        {
            Ok(packages) => deps_engine::classify::resolved::split_resolved_packages(&packages),
            Err(e) => {
                tracing::error!("Failed to reload lock file: {}", e);
                self.client
                    .log_message(
                        MessageType::ERROR,
                        format!("Failed to reload lock file: {e}"),
                    )
                    .await;
                (HashMap::new(), HashMap::new())
            }
        };

        // Snapshot before the loop and drop the guard: re-reading `self.config` per URI
        // inside the loop would hold this guard across a nested read of the same
        // write-preferring `RwLock`, and a writer queued in between would block it forever.
        let (freshness, severities, offline, fetch_timeout_secs, max_concurrent_fetches) = {
            let config = self.config.read().await;
            (
                config.policy.freshness.to_settings(),
                config.policy.diagnostics.to_severities(),
                config.policy.network.offline,
                config.policy.cache.fetch_timeout_secs,
                config.policy.cache.max_concurrent_fetches,
            )
        };

        for uri in affected_uris {
            if let Some(mut doc) = self.state.documents.get_mut(&uri) {
                doc.update_resolved_versions(
                    resolved_versions.clone(),
                    resolved_version_candidates.clone(),
                );
            }

            // Computed per URI (#636): each affected document can produce a different
            // ceiling, so it can't be hoisted out of the loop.
            let dep_count = diagnostics::document_dependency_count(&self.state, &uri);
            let items = diagnostics::generate_diagnostics_internal(
                Arc::clone(&self.state),
                &uri,
                freshness,
                severities,
                offline,
                diagnostics::loading_ceiling(fetch_timeout_secs, dep_count, max_concurrent_fetches),
            )
            .await;

            self.client.publish_diagnostics(uri, items, None).await;
        }

        // Detached, capability-gated, timeout-bounded (#493): see
        // `ServerState::spawn_refresh_requests` for rationale.
        self.state.spawn_refresh_requests(&self.client);
    }

    /// Fully reparses every open document of `ecosystem_ids` (issue #590/#1232) under
    /// `refetch` — callers pass `AllDependencies` for a routing-only watched-config change
    /// (e.g. `.npmrc`), since a plain diff would treat it as a no-op.
    async fn handle_watched_config_change(
        &self,
        ecosystem_ids: Vec<&'static str>,
        refetch: crate::document::RefetchPolicy,
    ) {
        crate::document::reparse::reparse_open_documents(
            crate::config::ReparseScope::Ecosystems(ecosystem_ids),
            refetch,
            "watched config file change",
            Arc::clone(&self.state),
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
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

    /// Whether the client implements `workspace/inlayHint/refresh` (issue #493: a
    /// client that never declares this may also never reply, which would hang an
    /// unbounded `inlay_hint_refresh` await forever).
    async fn inlay_hint_refresh_supported(&self) -> bool {
        let caps = self.client_capabilities.read().await;
        caps.as_ref()
            .and_then(|c| c.workspace.as_ref())
            .and_then(|w| w.inlay_hint.as_ref())
            .and_then(|h| h.refresh_support)
            .unwrap_or(false)
    }

    /// Whether the client implements `workspace/codeLens/refresh`. See
    /// `inlay_hint_refresh_supported` for rationale.
    async fn code_lens_refresh_supported(&self) -> bool {
        let caps = self.client_capabilities.read().await;
        caps.as_ref()
            .and_then(|c| c.workspace.as_ref())
            .and_then(|w| w.code_lens.as_ref())
            .and_then(|c| c.refresh_support)
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
                    commands::PIN_ALL_TO_SHA.into(),
                ],
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl LanguageServer for Backend {
    #[tracing::instrument(skip(self, params))]
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        tracing::info!("initializing deps-lsp server");

        *self.client_capabilities.write().await = Some(params.capabilities.clone());
        self.state
            .set_progress_supported(self.supports_progress().await);
        let inlay_hint_refresh_supported = self.inlay_hint_refresh_supported().await;
        self.state
            .set_inlay_hint_refresh_supported(inlay_hint_refresh_supported);
        let code_lens_refresh_supported = self.code_lens_refresh_supported().await;
        self.state
            .set_code_lens_refresh_supported(code_lens_refresh_supported);
        // Mirrored onto `ServerState` (#592) so `reparse_open_documents` — a free function
        // with no access to `Backend::client_capabilities` — can gate its refresh on it.
        let diagnostic_refresh_supported = self.diagnostic_refresh_supported().await;
        self.state
            .set_diagnostic_refresh_supported(diagnostic_refresh_supported);
        // #493 M1: a client that implements refresh but never declares `refreshSupport` is
        // gated off here too, and won't see hints/lenses update until the document is reopened.
        if !inlay_hint_refresh_supported {
            tracing::debug!(
                "client did not declare workspace.inlayHint.refreshSupport; inlay hints won't auto-refresh after background fetches"
            );
        }
        if !code_lens_refresh_supported {
            tracing::debug!(
                "client did not declare workspace.codeLens.refreshSupport; code lenses won't auto-refresh after background fetches"
            );
        }

        if let Some(init_options) = params.initialization_options
            && let Some(config) = parse_config(init_options)
        {
            tracing::debug!("loaded configuration: {:?}", config);
            // `resolve()` (#1058 T009) is the single derivation of these values, shared with
            // `did_change_configuration` below and `EcosystemRuntime::from_policy` — only the
            // side-effect application here (state/cache writes, gitlab warning) is adapter-specific.
            let resolved = config.policy.registries.resolve();
            self.state
                .cache
                .set_registry_policy(resolved.workspace_registries);
            self.state.nuget_user_profile_sources.store(
                resolved.nuget_user_profile_sources,
                std::sync::atomic::Ordering::Relaxed,
            );
            #[cfg(feature = "gitlab-ci")]
            if let Some(raw) = &resolved.gitlab_instance_host {
                warn_if_gitlab_instance_host_invalid(
                    &self.client,
                    raw,
                    &self.state.registry_policy,
                )
                .await;
            }
            *self
                .state
                .gitlab_instance_host
                .write()
                // The write below is a single infallible assignment, so this lock can never
                // actually be poisoned; recover rather than propagate, for defense in depth.
                .unwrap_or_else(std::sync::PoisonError::into_inner) = resolved.gitlab_instance_host;
            self.state.cache.set_offline(config.policy.network.offline);
            self.state
                .cache
                .set_cache_enabled(config.policy.cache.enabled);
            self.state
                .cold_start_limiter
                .set_min_interval(std::time::Duration::from_millis(
                    config.cold_start.rate_limit_ms,
                ));
            // #660/#661 critic C1: mirrored onto `ServerState` so every diagnostics call
            // site (push and pull) reads the same resolved policy.
            self.state
                .set_license_policy(config.policy.license_policy.to_policy());
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

    #[tracing::instrument(skip(self))]
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

        // Supervised so a panic surfaces as an `error!` log instead of silently stopping
        // cleanup forever. Spawned before the registration requests below (#493 S1) so an
        // unresponsive client stalling those never delays this from starting.
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
            // Inner loop never returns, so `Ok` is unreachable and this pattern is irrefutable.
            let Err(e) = cleanup_task.await;
            tracing::error!("Cold start rate limiter cleanup task exited unexpectedly: {e}");
        });

        // Lockfile patterns plus each ecosystem's non-lockfile watched config files (e.g.
        // npm's pnpm-workspace.yaml/.npmrc, #590) in one registration — both are just
        // glob-pattern watches to the client. Timeout-bounded (#493 S1): tower-lsp-server
        // dispatches via `buffer_unordered(4)`, so a hanging client would permanently burn
        // one of only 4 concurrent message slots.
        let mut patterns = self.state.ecosystem_registry.all_lockfile_patterns();
        patterns.extend(self.state.ecosystem_registry.all_watched_config_patterns());
        match tokio::time::timeout(
            CLIENT_REFRESH_TIMEOUT,
            file_watcher::register_lock_file_watchers(&self.client, &patterns),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!("Failed to register file watchers: {}", e);
                self.client
                    .log_message(MessageType::WARNING, format!("File watching disabled: {e}"))
                    .await;
            }
            Err(_) => {
                tracing::warn!("Timed out registering file watchers");
                self.client
                    .log_message(
                        MessageType::WARNING,
                        "File watching disabled: registration timed out".to_string(),
                    )
                    .await;
            }
        }

        // Dynamically register so clients that gate the notification on this (M3) actually
        // send it — without it, a changed config would never reach `did_change_configuration`.
        // Timeout-bounded for the same reason as the file watcher registration above.
        if self
            .did_change_configuration_dynamic_registration_supported()
            .await
        {
            let registration = Registration {
                id: "deps-lsp-did-change-configuration".to_string(),
                method: "workspace/didChangeConfiguration".to_string(),
                register_options: None,
            };
            match tokio::time::timeout(
                CLIENT_REFRESH_TIMEOUT,
                self.client.register_capability(vec![registration]),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("Failed to register didChangeConfiguration: {}", e),
                Err(_) => tracing::warn!("Timed out registering didChangeConfiguration"),
            }
        }
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
    ///
    /// Issue #592: beyond applying the new config, a field that affects parse-time
    /// decisions (currently `registries.workspace_registries`,
    /// `registries.nuget_user_profile_sources`, `registries.gitlab_instance_host` — see
    /// `config::reparse_scope`) also
    /// re-parses every open document its `config::ReparseScope` covers, forcing a full
    /// re-fetch (`document::RefetchPolicy::AllDependencies`) since the routing changed, not
    /// the manifest content. A burst of config changes is coalesced into one debounced
    /// reparse (`ServerState::queue_reparse`) rather than firing once per notification.
    #[tracing::instrument(skip(self, params))]
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

        // Captured before `config` is moved into the write guard below (`DepsConfig` has no
        // `Clone`): applied *after* the swap but with no `.await` in between, so no other
        // task can observe `self.config` reflecting the new value while these shared
        // handles (M4) still reflect the old one.
        //
        // `resolve()` (#1058 T009) is the single derivation of these values, shared with
        // `initialize` above — only the side-effect application below is adapter-specific.
        let resolved = config.policy.registries.resolve();
        let offline = config.policy.network.offline;
        let cache_enabled = config.policy.cache.enabled;
        let cold_start_rate_limit_ms = config.cold_start.rate_limit_ms;
        // #660/#661 critic C1: see the mirroring call after the config swap below.
        let license_policy = config.policy.license_policy.to_policy();

        // Diff old vs new for parse-affecting changes (#592) under one write-guard
        // acquisition: `DepsConfig` has no `Clone`, so the diff must read the
        // not-yet-overwritten guard before `config` is moved into it.
        let scope = {
            let mut guard = self.config.write().await;
            let scope = crate::config::reparse_scope(
                &guard,
                &config,
                &self.state.workspace_registry_ecosystems,
            );
            *guard = config;
            scope
        };

        self.state
            .cache
            .set_registry_policy(resolved.workspace_registries);
        self.state.nuget_user_profile_sources.store(
            resolved.nuget_user_profile_sources,
            std::sync::atomic::Ordering::Relaxed,
        );
        #[cfg(feature = "gitlab-ci")]
        if let Some(raw) = &resolved.gitlab_instance_host {
            warn_if_gitlab_instance_host_invalid(&self.client, raw, &self.state.registry_policy)
                .await;
        }
        *self
            .state
            .gitlab_instance_host
            .write()
            // The write below is a single infallible assignment, so this lock can never
            // actually be poisoned; recover rather than propagate, for defense in depth.
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resolved.gitlab_instance_host;
        // Must land before either refresh notification below, or the refresh re-renders
        // diagnostics under the stale flag values (critic M5).
        self.state.cache.set_offline(offline);
        self.state.cache.set_cache_enabled(cache_enabled);
        self.state
            .cold_start_limiter
            .set_min_interval(std::time::Duration::from_millis(cold_start_rate_limit_ms));
        // #660/#661 critic C1: mirrored onto `ServerState` so every diagnostics call site
        // (push and pull) reads the same resolved policy.
        self.state.set_license_policy(license_policy);

        match scope {
            Some(scope) => {
                // Union into the pending scope and bump the generation before spawning a
                // debounced worker, so a burst of changes collapses into one reparse.
                let generation = self.state.queue_reparse(scope);
                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let config = Arc::clone(&self.config);
                let worker = tokio::spawn(async move {
                    tokio::time::sleep(crate::document::reparse::RECONFIGURE_DEBOUNCE).await;
                    let superseded = state.config_generation() != generation;
                    // Security M3: a superseded worker normally defers to the newer one, but
                    // under a continuous burst every worker would see itself superseded
                    // forever, starving the reparse indefinitely. Once the pending scope has
                    // waited at least `MAX_DEBOUNCE_WAIT`, drain it regardless of staleness.
                    if superseded
                        && !state
                            .pending_reparse_overdue(crate::document::reparse::MAX_DEBOUNCE_WAIT)
                    {
                        return;
                    }
                    let Some(scope) = state.take_pending_reparse() else {
                        return;
                    };
                    crate::document::reparse::reparse_open_documents(
                        scope,
                        crate::document::RefetchPolicy::AllDependencies,
                        "workspace/didChangeConfiguration",
                        state,
                        client,
                        config,
                    )
                    .await;
                });
                tokio::spawn(async move {
                    if let Err(e) = worker.await {
                        tracing::error!(
                            "workspace/didChangeConfiguration reparse worker panicked ({e}); \
                             open documents were not reparsed"
                        );
                    }
                });
            }
            None => {
                // Nothing parse-affecting changed. Hover/completion/code actions pick up
                // the new config for free on demand; diagnostics are pull-based, so a
                // pull-capable client must be told to re-request them (push-only clients
                // are a known v1 gap, M2). Timeout-bounded (#493) against a hanging client.
                if self.diagnostic_refresh_supported().await {
                    match tokio::time::timeout(
                        CLIENT_REFRESH_TIMEOUT,
                        self.client.workspace_diagnostic_refresh(),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            tracing::debug!("workspace/diagnostic/refresh failed: {:?}", e);
                        }
                        Err(_) => tracing::debug!("workspace/diagnostic/refresh timed out"),
                    }
                }
            }
        }
    }

    #[tracing::instrument(skip(self))]
    fn shutdown(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        tracing::info!("shutting down deps-lsp server");
        std::future::ready(Ok(()))
    }

    // Every `#[tracing::instrument(fields(uri = ...))]` on this and the other trait
    // methods below deliberately records the raw, pre-canonicalization request `Uri`
    // (evaluated before the body runs `canonicalize_uri`): the span correlates a
    // request with the client's own wire-format log, while body-level `tracing::info!`/
    // `tracing::warn!` calls after canonicalization use the resolved (canonical) form —
    // both are visible in `.local/testing/debug/session.log`, so this is not a gap.
    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
        let content = params.text_document.text;
        let version = params.text_document.version;

        tracing::info!("document opened: {:?}", uri);

        // `from_lsp_uri` returning `None` (a URI shape `url::Url` rejects, e.g. a `file:`
        // URI with a port) is treated the same as "no ecosystem handles this file type".
        let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
            tracing::debug!("unsupported file type: {:?}", uri);
            return;
        };
        if self.state.ecosystem_registry.for_uri(&domain_uri).is_none() {
            tracing::debug!("unsupported file type: {:?}", uri);
            return;
        }

        self.handle_open(uri, content, version).await;
    }

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
        let version = params.text_document.version;

        if let Some(change) = params.content_changes.first() {
            let content = change.text.clone();

            // See `did_open`'s equivalent check for why `from_lsp_uri` returning `None`
            // is treated the same as "no ecosystem handles this file type".
            let Some(domain_uri) = crate::lsp_types_interop::from_lsp_uri(&uri) else {
                tracing::debug!("unsupported file type: {:?}", uri);
                return;
            };
            if self.state.ecosystem_registry.for_uri(&domain_uri).is_none() {
                tracing::debug!("unsupported file type: {:?}", uri);
                return;
            }

            self.handle_change(uri, content, version).await;
        }
    }

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
        tracing::info!("document closed: {:?}", uri);

        self.state.remove_document(&uri);
        self.state.cancel_background_task(&uri).await;
    }

    /// Not routed through `canonicalize_uri` (#1086): `change.uri` here is a watched
    /// filesystem-event URI (lock file, config file), never looked up against
    /// `ServerState::documents` directly — it's converted to a path via `from_lsp_uri` and
    /// matched against already-canonical document keys inside `handle_lockfile_change`'s
    /// scan instead. Canonicalizing it here would be a no-op for correctness (the affected-
    /// document match already goes through the canonical map key) and would only churn the
    /// log/path-resolution value for no behavioral benefit.
    #[tracing::instrument(skip(self, params), fields(count = params.changes.len()))]
    async fn did_change_watched_files(&self, params: DidChangeWatchedFilesParams) {
        tracing::debug!("Received {} file change events", params.changes.len());

        for change in params.changes {
            // #1090: guards against a non-`file:` scheme, a remote-host `file:` URI, or a
            // relative path (e.g. `untitled:Cargo.lock`) rather than a bare `to_file_path()`
            // on this client-supplied URI.
            let Some(path) = crate::lsp_types_interop::from_lsp_uri(&change.uri)
                .and_then(|url| deps_core::lockfile::resolve_manifest_file_path(&url))
            else {
                tracing::warn!("Invalid file path in change event: {:?}", change.uri);
                continue;
            };

            let Some(filename) = file_watcher::extract_lockfile_name(&path) else {
                continue;
            };

            if let Some(ecosystem) = self.state.ecosystem_registry.for_lockfile(filename) {
                tracing::info!(
                    "Lock file changed: {} (ecosystem: {})",
                    filename,
                    ecosystem.id()
                );

                self.state.lockfile_cache.invalidate(&path);
                self.handle_lockfile_change(&path, ecosystem.id()).await;
                continue;
            }

            let ecosystems = self.state.ecosystem_registry.for_watched_config(filename);
            if !ecosystems.is_empty() {
                let ecosystem_ids: Vec<&'static str> = ecosystems.iter().map(|e| e.id()).collect();
                // A routing-only change (e.g. `.npmrc`) needs a full refetch, not a diff (issue #1232 S1).
                let refetch = if ecosystems
                    .iter()
                    .any(|e| e.routing_affecting_watched_configs().contains(&filename))
                {
                    crate::document::RefetchPolicy::AllDependencies
                } else {
                    crate::document::RefetchPolicy::Diff
                };
                tracing::info!(
                    "Watched config file changed: {} (ecosystems: {:?}, refetch: {:?})",
                    filename,
                    ecosystem_ids,
                    refetch
                );

                // No cache invalidation here (unlike the lock-file branch above): every
                // `MtimeFileCache`-backed config cache invalidates itself by mtime on its
                // next `get_or_parse`, which the reparse below triggers.
                self.handle_watched_config_change(ecosystem_ids, refetch)
                    .await;
                continue;
            }

            tracing::debug!("Skipping unrecognized watched-file change: {}", filename);
        }
    }

    #[tracing::instrument(
        skip(self, params),
        fields(uri = ?params.text_document_position_params.text_document.uri)
    )]
    async fn hover(&self, mut params: HoverParams) -> Result<Option<Hover>> {
        params.text_document_position_params.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(
                &params.text_document_position_params.text_document.uri,
            );
        Ok(hover::handle_hover(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await)
    }

    #[tracing::instrument(
        skip(self, params),
        fields(uri = ?params.text_document_position.text_document.uri)
    )]
    async fn completion(&self, mut params: CompletionParams) -> Result<Option<CompletionResponse>> {
        params.text_document_position.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(
                &params.text_document_position.text_document.uri,
            );
        Ok(completion::handle_completion(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await)
    }

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn inlay_hint(&self, mut params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        params.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
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

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn code_action(
        &self,
        mut params: CodeActionParams,
    ) -> Result<Option<Vec<tower_lsp_server::ls_types::CodeActionOrCommand>>> {
        params.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
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

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn code_lens(&self, mut params: CodeLensParams) -> Result<Option<Vec<CodeLens>>> {
        params.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
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

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn document_link(
        &self,
        mut params: DocumentLinkParams,
    ) -> Result<Option<Vec<DocumentLink>>> {
        params.text_document.uri =
            crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
        let links = document_link::handle_document_link(
            Arc::clone(&self.state),
            params,
            self.client.clone(),
            Arc::clone(&self.config),
        )
        .await;
        Ok(Some(links))
    }

    #[tracing::instrument(skip(self, params), fields(uri = ?params.text_document.uri))]
    async fn diagnostic(
        &self,
        params: DocumentDiagnosticParams,
    ) -> Result<DocumentDiagnosticReportResult> {
        let uri = crate::lsp_types_interop::canonicalize_uri(&params.text_document.uri);
        tracing::info!("diagnostic request for: {:?}", uri);

        // Clone config before async call to release lock early
        let diagnostics_config = { self.config.read().await.policy.diagnostics.clone() };

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

    #[tracing::instrument(skip(self, params), fields(command = %params.command))]
    async fn execute_command(
        &self,
        params: ExecuteCommandParams,
    ) -> Result<Option<serde_json::Value>> {
        tracing::info!("execute_command: {:?}", params.command);

        if params.command == commands::UPDATE_VERSION
            && let Some(args) = params.arguments.first()
            && let Ok(mut update_args) = serde_json::from_value::<UpdateVersionArgs>(args.clone())
        {
            update_args.uri = crate::lsp_types_interop::canonicalize_uri(&update_args.uri);
            if let Some(edit) = build_update_version_edit(&update_args) {
                match tokio::time::timeout(CLIENT_REFRESH_TIMEOUT, self.client.apply_edit(edit))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::error!("Failed to apply edit: {:?}", e),
                    Err(_) => tracing::warn!(
                        "apply_edit for deps-lsp.updateVersion timed out after {CLIENT_REFRESH_TIMEOUT:?}"
                    ),
                }
            }
        } else if params.command == commands::UPDATE_ALL_OUTDATED
            && let Some(args) = params.arguments.first()
            && let Ok(update_args) = serde_json::from_value::<UpdateAllOutdatedArgs>(args.clone())
        {
            self.execute_update_all_outdated(crate::lsp_types_interop::canonicalize_uri(
                &update_args.uri,
            ))
            .await;
        }

        if params.command == commands::PIN_ALL_TO_SHA
            && let Some(args) = params.arguments.first()
            && let Ok(pin_args) = serde_json::from_value::<PinAllToShaArgs>(args.clone())
        {
            self.execute_pin_all_to_sha(crate::lsp_types_interop::canonicalize_uri(&pin_args.uri))
                .await;
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
    // `doc` is explicitly `drop`ped before every `.await` reachable from here; clippy's
    // `await_holding_invalid_type` doesn't recognize a manual drop in this shape and flags
    // it anyway. Verified false positive.
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
            // Not a failure — the document changed since the lens render, or the command
            // is stale. Still worth a message: a silent no-op reads as a broken button (§4.6).
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

        let edit = build_batch_workspace_edit(&uri, version, edits, supports_document_changes);
        self.apply_batch_edit(&uri, edit, "dependency updates")
            .await;
    }

    /// Applies `edit` via `workspace/applyEdit`, warning the client through
    /// `window/showMessage` on rejection, error, or timeout.
    ///
    /// Shared by [`Self::execute_update_all_outdated`] and (when the `github-actions`
    /// feature is enabled) `execute_pin_all_to_sha` (issue #633): both bulk commands
    /// recompute their own edits, but converge on identical apply/response handling.
    /// `what` names the batch's contents for the user-facing failure messages (critic
    /// M2: the messages must not say "dependency updates" for a command that updates
    /// nothing, e.g. `deps-lsp.pinAllToSha`) — e.g. `"dependency updates"` or
    /// `"SHA pins"`.
    async fn apply_batch_edit(&self, uri: &Uri, edit: WorkspaceEdit, what: &str) {
        match tokio::time::timeout(CLIENT_REFRESH_TIMEOUT, self.client.apply_edit(edit)).await {
            Ok(Ok(response)) if response.applied => {}
            Ok(Ok(response)) => {
                tracing::warn!(
                    "workspace/applyEdit for {:?} was rejected: {:?}",
                    uri,
                    response.failure_reason
                );
                self.client
                    .show_message(
                        MessageType::WARNING,
                        format!("deps-lsp: failed to apply {what}"),
                    )
                    .await;
            }
            Ok(Err(e)) => {
                tracing::error!("Failed to apply edit for {:?}: {:?}", uri, e);
                self.client
                    .show_message(
                        MessageType::WARNING,
                        format!("deps-lsp: failed to apply {what}"),
                    )
                    .await;
            }
            Err(_) => {
                tracing::warn!(
                    "apply_edit for {:?} timed out after {CLIENT_REFRESH_TIMEOUT:?}",
                    uri
                );
                self.client
                    .show_message(
                        MessageType::WARNING,
                        format!(
                            "deps-lsp: the editor did not respond to the {what} within {CLIENT_REFRESH_TIMEOUT:?}"
                        ),
                    )
                    .await;
            }
        }
    }

    /// Recomputes and applies the batch, version-guarded `WorkspaceEdit` for
    /// `deps-lsp.pinAllToSha` (issue #633, generalized cross-ecosystem in #640) — the
    /// bulk counterpart of [`Self::execute_update_all_outdated`], sharing its readiness
    /// contract (see that method's doc comment) but sourcing edits from
    /// [`deps_core::Ecosystem::collect_pin_all_to_sha_edits`] instead of
    /// `deps_core::collect_update_all_edits`. Dispatched through the resolved
    /// `Arc<dyn Ecosystem>` for every document's own ecosystem — an ecosystem with no
    /// mutable-ref pin concept simply returns no edits from the trait default, taking
    /// the same "nothing to pin" INFO path below rather than a distinct refusal.
    #[allow(clippy::await_holding_invalid_type)]
    async fn execute_pin_all_to_sha(&self, uri: Uri) {
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

        let versions = deps_core::VersionData::new(&doc.cached_versions, &doc.resolved_versions);
        let edits = ecosystem.collect_pin_all_to_sha_edits(parse_result, versions);
        let version = doc.version;
        drop(doc);

        if edits.is_empty() {
            // M1 (#640): dispatched unconditionally for every ecosystem, so this log line
            // distinguishes "nothing to pin" from a misrouted/stale command — the
            // client-facing message can't say that.
            tracing::debug!(ecosystem = ecosystem.id(), "pinAllToSha: no edits");
            self.client
                .show_message(
                    MessageType::INFO,
                    format!(
                        "deps-lsp: no mutable-tag {} to pin to commit SHA",
                        ecosystem.pin_all_to_sha_noun().plural
                    ),
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

        let edit = build_batch_workspace_edit(&uri, version, edits, supports_document_changes);
        self.apply_batch_edit(&uri, edit, "SHA pins").await;
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

/// Arguments for `deps-lsp.pinAllToSha` (issue #633) — the URI only, same shape and
/// rationale as [`UpdateAllOutdatedArgs`]: edits are recomputed at execution time (see
/// `Backend::execute_pin_all_to_sha`), never baked into the command arguments.
#[derive(serde::Deserialize)]
struct PinAllToShaArgs {
    uri: Uri,
}

/// Builds the `WorkspaceEdit` for a bulk command (`deps-lsp.updateAllOutdated`,
/// `deps-lsp.pinAllToSha`) from its already-computed `edits`.
///
/// Emits `document_changes` (versioned per `TextDocumentEdit`) when
/// `supports_document_changes` is `true` — gated on the client's
/// `workspace.workspaceEdit.documentChanges` capability — and falls back to the untyped
/// `changes` map otherwise.
fn build_batch_workspace_edit(
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

    use std::assert_matches;

    #[test]
    fn test_server_capabilities() {
        let caps = Backend::server_capabilities();

        assert!(caps.text_document_sync.is_some());

        assert!(caps.completion_provider.is_some());
        let completion = caps.completion_provider.unwrap();
        assert!(!completion.resolve_provider.unwrap());

        assert!(caps.hover_provider.is_some());

        assert!(caps.inlay_hint_provider.is_some());

        assert!(caps.diagnostic_provider.is_some());
    }

    #[tokio::test]
    async fn test_backend_creation() {
        let (_service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
    }

    #[tokio::test]
    async fn test_initialize_without_options() {
        let (_service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
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

    /// #1090 S2: `did_change_watched_files` used a bare `change.uri.to_file_path()` on a
    /// client-supplied URI, accepting a non-`file:` scheme, a remote host, or (via
    /// `untitled:Cargo.lock`) a relative path. Seeds the lock file cache with a real entry,
    /// then proves a malicious-scheme/host `FileEvent` naming the same real path does not
    /// invalidate it, while an ordinary `file:` event for the same path does (positive
    /// control proving the fixture itself is live).
    ///
    /// Note on this test's `"file://attacker.example"` case and the guard-gap follow-up fix
    /// in `lsp_types_interop::from_lsp_uri`: this case's malicious `Uri` is built via
    /// `Uri::from_file_path(&lockfile_path).as_str().strip_prefix("file://")`, and
    /// `ls_types::Uri::from_file_path` always percent-encodes a Windows drive letter's colon
    /// (`C:` becomes `C%3A`, verified against `ls-types` 0.0.6's `ASCII_SET`/`from_file_path`
    /// source). A percent-encoded colon is never a bare 2-character `is_windows_drive_letter`
    /// segment, so this construction never reproduces
    /// `SyntaxViolation::FileWithHostAndWindowsDrive` and this case would not have failed on
    /// `windows-latest` CI even before `from_lsp_uri` was hardened — it is not a false
    /// negative, it is simply the wrong construction to exercise that specific bypass. It is
    /// kept as-is because it still verifies the ordinary "remote host with an intact path is
    /// rejected" case that `from_lsp_uri` also covers. The drive-letter bypass itself (a raw,
    /// unencoded-colon wire-format URI, which a malicious client is not obligated to
    /// percent-encode) is covered platform-independently by
    /// `lsp_types_interop::tests::test_from_lsp_uri_rejects_windows_drive_host_bypass`, which
    /// `did_change_watched_files` transitively relies on since it calls `from_lsp_uri` before
    /// this cache-invalidation logic ever runs.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_did_change_watched_files_rejects_malicious_uri() {
        // Held per fs_probe::snapshot_guard's doc: get_or_parse touches fs_probe and this
        // test shares a binary with other diffing tests.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use tower_lsp_server::ls_types::{FileChangeType, FileEvent};

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("Cargo.lock");
        std::fs::write(
            &lockfile_path,
            "# This file is automatically @generated by Cargo.\nversion = 3\n",
        )
        .unwrap();

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();
        let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
        let provider = ecosystem.lockfile_provider().unwrap();

        backend
            .state
            .lockfile_cache
            .get_or_parse(provider.as_ref(), &lockfile_path)
            .await
            .unwrap();
        assert_eq!(
            backend.state.lockfile_cache.len(),
            1,
            "test premise: the cache must hold the seeded entry"
        );

        let file_uri = Uri::from_file_path(&lockfile_path).unwrap();
        let path_part = file_uri.as_str().strip_prefix("file://").unwrap();

        for prefix in [
            "untitled:",
            "https://attacker.example",
            "file://attacker.example",
        ] {
            let uri: Uri = format!("{prefix}{path_part}").parse().unwrap();
            backend
                .did_change_watched_files(DidChangeWatchedFilesParams {
                    changes: vec![FileEvent {
                        uri,
                        typ: FileChangeType::CHANGED,
                    }],
                })
                .await;
            assert_eq!(
                backend.state.lockfile_cache.len(),
                1,
                "a malicious-scheme/host URI ({prefix}) must not invalidate a real cache entry"
            );
        }

        backend
            .did_change_watched_files(DidChangeWatchedFilesParams {
                changes: vec![FileEvent {
                    uri: file_uri,
                    typ: FileChangeType::CHANGED,
                }],
            })
            .await;
        assert_eq!(
            backend.state.lockfile_cache.len(),
            0,
            "an ordinary file: URI for the same real path must still invalidate the cache"
        );
    }

    /// Issue #590 end-to-end: an on-disk `pnpm-workspace.yaml` change, delivered via
    /// `workspace/didChangeWatchedFiles`, must reparse an already-open `package.json` that
    /// references its catalog — not just refresh cached resolved versions the way a lock
    /// file change does (`Self::handle_lockfile_change`), since catalog resolution is baked
    /// into the parse result itself (see `Self::handle_watched_config_change`'s doc).
    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_watched_config_change_reparses_open_document_with_catalog_dependency() {
        // Held per fs_probe::snapshot_guard's doc: did_open routes through npm's
        // parse_manifest, which touches fs_probe, and this test shares a binary with
        // document/loader.rs's diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use tower_lsp_server::ls_types::{
            FileChangeType, FileEvent, HoverContents, Position, TextDocumentIdentifier,
            TextDocumentItem, TextDocumentPositionParams,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let workspace_path = temp_dir.path().join("pnpm-workspace.yaml");
        std::fs::write(&workspace_path, "catalog:\n  react: ^17.0.0\n").unwrap();

        let manifest_path = temp_dir.path().join("package.json");
        let content = r#"{"dependencies": {"react": "catalog:"}}"#;
        std::fs::write(&manifest_path, content).unwrap();
        let uri = Uri::from_file_path(&manifest_path).unwrap();

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: uri.clone(),
                    language_id: "json".to_string(),
                    version: 1,
                    text: content.to_string(),
                },
            })
            .await;

        let hover_params = |uri: Uri| HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, 20), // inside "react"'s name
            },
            work_done_progress_params: Default::default(),
        };

        let hover = backend
            .hover(hover_params(uri.clone()))
            .await
            .unwrap()
            .expect("hover must fire for a catalog-resolved dependency");
        let HoverContents::Markup(before) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(before.value.contains("^17.0.0"), "{}", before.value);

        // Ensure a distinguishable mtime on filesystems with coarse timestamp resolution
        // (matches `mtime_cache::tests::forward_mtime_bump_invalidates`).
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(&workspace_path, "catalog:\n  react: ^18.3.0\n").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&workspace_path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        backend
            .did_change_watched_files(DidChangeWatchedFilesParams {
                changes: vec![FileEvent {
                    uri: Uri::from_file_path(&workspace_path).unwrap(),
                    typ: FileChangeType::CHANGED,
                }],
            })
            .await;

        let hover = backend
            .hover(hover_params(uri))
            .await
            .unwrap()
            .expect("hover must still fire after reparse");
        let HoverContents::Markup(after) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            after.value.contains("^18.3.0"),
            "watched config file change did not trigger a reparse of the open document: {}",
            after.value
        );
    }

    /// Issue #1232 end-to-end: a single `.npmrc` `didChangeWatchedFiles` event must reparse
    /// EVERY open document whose ecosystem watches `.npmrc` — not just whichever ecosystem a
    /// single-winner `for_watched_config` lookup happened to resolve to
    /// (`EcosystemRegistry::for_watched_config` now returns a `Vec`, see
    /// `ecosystem_registry.rs::test_for_watched_config_fans_out_to_all_matching_ecosystems`
    /// for the routing-layer proof). Opens both an npm `package.json` and a Deno `deno.json`
    /// referencing the same scoped package (Deno via an `npm:` specifier, which resolves
    /// `.npmrc` through the same `deps_npm::config` machinery `NpmEcosystem` uses), starts
    /// both unresolvable (`.npmrc` names an invalid registry URL, so hover has no live
    /// version data), then edits `.npmrc` to add a valid alternate-registry index and fires
    /// one `.npmrc` change event. Both documents' hover must pick up the live version list —
    /// proving both ecosystems' open documents were reparsed from that single event, not just
    /// one.
    #[cfg(all(feature = "npm", feature = "deno"))]
    #[tokio::test]
    async fn test_watched_config_change_reparses_all_matching_ecosystems_1232() {
        // Held per fs_probe::snapshot_guard's doc: did_open routes through npm's and deno's
        // parse_manifest, both of which touch fs_probe, and this test shares a binary with
        // other diffing/fs_probe tests.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use tower_lsp_server::ls_types::{
            FileChangeType, FileEvent, HoverContents, Position, TextDocumentIdentifier,
            TextDocumentItem, TextDocumentPositionParams,
        };

        let mut alt_server = mockito::Server::new_async().await;
        let alt_mock = alt_server
            .mock("GET", "/@acme-corp/secretpkg")
            .with_status(200)
            .with_body(r#"{"versions": {"1.0.0": {}, "2.0.0": {}}}"#)
            .expect_at_least(1)
            .create_async()
            .await;

        let temp_dir = tempfile::tempdir().unwrap();
        let npmrc_path = temp_dir.path().join(".npmrc");
        std::fs::write(&npmrc_path, "@acme-corp:registry=not-a-valid-url\n").unwrap();

        let npm_manifest_path = temp_dir.path().join("package.json");
        let npm_content = r#"{"dependencies": {"@acme-corp/secretpkg": "^1.0.0"}}"#;
        std::fs::write(&npm_manifest_path, npm_content).unwrap();
        let npm_uri = Uri::from_file_path(&npm_manifest_path).unwrap();

        let deno_manifest_path = temp_dir.path().join("deno.json");
        let deno_content = r#"{"imports": {"secret": "npm:@acme-corp/secretpkg@^1.0.0"}}"#;
        std::fs::write(&deno_manifest_path, deno_content).unwrap();
        let deno_uri = Uri::from_file_path(&deno_manifest_path).unwrap();

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        // Workspace-declared registries must be allowed for the `.npmrc` alternate index
        // (a loopback mockito URL) to be resolved at all.
        backend
            .did_change_configuration(DidChangeConfigurationParams {
                settings: serde_json::json!({ "registries": { "workspace_registries": "all" } }),
            })
            .await;

        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: npm_uri.clone(),
                    language_id: "json".to_string(),
                    version: 1,
                    text: npm_content.to_string(),
                },
            })
            .await;
        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: deno_uri.clone(),
                    language_id: "json".to_string(),
                    version: 1,
                    text: deno_content.to_string(),
                },
            })
            .await;

        let hover_params = |uri: Uri, character: u32| HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(0, character),
            },
            work_done_progress_params: Default::default(),
        };
        // Character offsets land inside each manifest's `@acme-corp/secretpkg` name range.
        let npm_before = backend
            .hover(hover_params(npm_uri.clone(), 25))
            .await
            .unwrap()
            .expect("npm hover must fire");
        let HoverContents::Markup(npm_before) = npm_before.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !npm_before.value.contains("2.0.0"),
            "npm hover must have no live version data before .npmrc resolves an index: {}",
            npm_before.value
        );

        let deno_before = backend
            .hover(hover_params(deno_uri.clone(), 35))
            .await
            .unwrap()
            .expect("deno hover must fire");
        let HoverContents::Markup(deno_before) = deno_before.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !deno_before.value.contains("2.0.0"),
            "deno hover must have no live version data before .npmrc resolves an index: {}",
            deno_before.value
        );

        // Ensure a distinguishable mtime on filesystems with coarse timestamp resolution
        // (matches `mtime_cache::tests::forward_mtime_bump_invalidates`).
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(
            &npmrc_path,
            format!("@acme-corp:registry={}\n", alt_server.url()),
        )
        .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&npmrc_path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        backend
            .did_change_watched_files(DidChangeWatchedFilesParams {
                changes: vec![FileEvent {
                    uri: Uri::from_file_path(&npmrc_path).unwrap(),
                    typ: FileChangeType::CHANGED,
                }],
            })
            .await;

        let npm_after = backend
            .hover(hover_params(npm_uri.clone(), 25))
            .await
            .unwrap()
            .expect("npm hover must still fire");
        let HoverContents::Markup(npm_after) = npm_after.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            npm_after.value.contains("2.0.0"),
            "a single .npmrc change did not reparse the open npm document: {}",
            npm_after.value
        );

        let deno_after = backend
            .hover(hover_params(deno_uri.clone(), 35))
            .await
            .unwrap()
            .expect("deno hover must still fire");
        let HoverContents::Markup(deno_after) = deno_after.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            deno_after.value.contains("2.0.0"),
            "a single .npmrc change did not reparse the open deno document \
             (issue #1232 regression — for_watched_config must fan out to every matching \
             ecosystem, not just npm): {}",
            deno_after.value
        );

        alt_mock.assert_async().await;
    }

    /// Issue #1232 S1 regression: a `.npmrc` change that alters registry *routing* only
    /// (same dependency name/version-requirement, different registry) must still force a
    /// refetch — it must not be silently skipped by `RefetchPolicy::Diff`'s empty-diff
    /// short-circuit. This reproduces the bug critic proved live (an open `deno.json`
    /// resolved against one registry kept serving that same data forever after an `.npmrc`
    /// scope override redirected `@acme-corp` to a different registry, because the
    /// dependency set itself never changed so `DependencyDiff` stayed empty).
    ///
    /// Seeds a `deno.json` document directly with `cached_versions` as if it were already
    /// successfully resolved under the *old* routing (mirroring
    /// `did_change_configuration_tests::test_rapid_config_changes_coalesce_into_a_union_scope_reparse`'s
    /// pattern for the same `RefetchPolicy::AllDependencies` bug class), then fires a single
    /// `.npmrc` watched-file change. Under the pre-fix unconditional `RefetchPolicy::Diff`,
    /// the dependency name/version-requirement here never changes, so the diff is empty, the
    /// fetch (and its cache drop) never runs, and `cached_versions` would stay stale forever.
    /// Under the fix, `DenoEcosystem::routing_affecting_watched_configs()` lists `.npmrc`, so
    /// the reparse uses `RefetchPolicy::AllDependencies`, which drops `cached_versions` unconditionally before
    /// attempting the (network, expected-to-fail in this sandboxed test) fetch — an empty
    /// map is proof the forced refetch actually ran, the same observation technique
    /// `test_rapid_config_changes_coalesce_into_a_union_scope_reparse` already uses.
    #[cfg(feature = "deno")]
    #[tokio::test]
    async fn test_npmrc_routing_only_change_forces_refetch_1232_s1() {
        // Held per fs_probe::snapshot_guard's doc: deno's parse_manifest touches fs_probe,
        // and this test shares a binary with other diffing/fs_probe tests.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use crate::document::DocumentState;
        use deps_core::{EcosystemId, PackageName, PackageVersions};
        use tower_lsp_server::ls_types::{FileChangeType, FileEvent};

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        let deno_url = deps_core::test_util::test_uri("/test/deno.json");
        let deno_uri = crate::lsp_types_interop::to_lsp_uri(&deno_url);
        let deno_ecosystem = backend.state.ecosystem_registry.get("deno").unwrap();
        let deno_content =
            r#"{"imports": {"secret": "npm:@acme-corp/secretpkg@^1.0.0"}}"#.to_string();
        let deno_parse = deno_ecosystem
            .parse_manifest(&deno_content, &deno_url)
            .await
            .unwrap();
        let mut deno_doc =
            DocumentState::new_from_parse_result(EcosystemId::Deno, deno_content, deno_parse);
        deno_doc.set_version(Some(1));
        // Simulates a document already successfully resolved under the OLD `.npmrc`
        // routing: the dependency name/version-requirement is identical before and after
        // the `.npmrc` change fired below, so `DependencyDiff` sees nothing added or
        // version-changed — the routing-only case `RefetchPolicy::Diff` cannot detect.
        deno_doc.update_cached_versions(HashMap::from([(
            PackageName::new("@acme-corp/secretpkg"),
            PackageVersions::latest_only("1.0.0"),
        )]));
        backend.state.update_document(deno_uri.clone(), deno_doc);

        let npmrc_url = deps_core::test_util::test_uri("/test/.npmrc");
        backend
            .did_change_watched_files(DidChangeWatchedFilesParams {
                changes: vec![FileEvent {
                    uri: crate::lsp_types_interop::to_lsp_uri(&npmrc_url),
                    typ: FileChangeType::CHANGED,
                }],
            })
            .await;

        // The forced refetch runs on a spawned background task (`spawn_background_task`),
        // not synchronously inside the awaited `did_change_watched_files` call above, so
        // polling with a bounded timeout is required rather than a single immediate check.
        let cleared = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if backend
                    .state
                    .get_document(&deno_uri)
                    .is_some_and(|d| d.cached_versions.is_empty())
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;

        assert!(
            cleared.is_ok(),
            "a routing-only `.npmrc` change did not force a refetch: stale cached_versions \
             from the old registry survived (RefetchPolicy must be AllDependencies for \
             `.npmrc`, not Diff, since the dependency set itself never changed)"
        );
    }

    /// Cross-handler dedup regression (issue #1086, US-001/FR-004): a client opening a
    /// document under one non-canonical `Uri` spelling and later requesting `hover` on the
    /// same physical file under a *different* non-canonical spelling must resolve the same
    /// `DocumentState` — not create a second, empty entry. Exercises two of the four
    /// documented spelling-variant classes (`file://localhost/...` on open, an uppercase
    /// `FILE:///...` scheme on hover) built from raw client-style strings (not
    /// `Uri::from_file_path`, which is always already canonical and so cannot exercise this
    /// divergence).
    ///
    /// Unix-only: the fixture path is drive-letter-less, so `url::Url::to_file_path` (which
    /// `parse_manifest`'s workspace-root discovery calls internally) always fails on Windows
    /// regardless of the URI's spelling — a fixture-portability limit, not a difference in
    /// the canonicalization mechanism under test, which the cross-platform
    /// `lsp_types_interop` round-trip tests already cover on Windows.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    #[cfg(not(windows))]
    async fn test_differently_spelled_uris_resolve_the_same_document() {
        // Held per fs_probe::snapshot_guard's doc: did_open routes through cargo's
        // parse_manifest, which touches fs_probe, and this test shares a binary with
        // document/loader.rs's diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use tower_lsp_server::ls_types::{
            HoverContents, Position, TextDocumentIdentifier, TextDocumentItem,
            TextDocumentPositionParams,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0.0\"\n";
        std::fs::write(&manifest_path, content).unwrap();
        let path_str = manifest_path.to_str().unwrap();

        let open_uri: Uri = format!("file://localhost{path_str}").parse().unwrap();
        let hover_uri: Uri = format!("FILE://{path_str}").parse().unwrap();
        let canonical = crate::lsp_types_interop::canonicalize_uri(&open_uri);
        assert_eq!(
            canonical,
            crate::lsp_types_interop::canonicalize_uri(&hover_uri),
            "test premise: both raw spellings must canonicalize to the same Uri"
        );
        assert_ne!(
            open_uri, hover_uri,
            "test premise: the two spellings must differ"
        );

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: open_uri,
                    language_id: "toml".to_string(),
                    version: 1,
                    text: content.to_string(),
                },
            })
            .await;
        assert_eq!(
            backend.state.document_count(),
            1,
            "did_open must store exactly one document, keyed by the canonical Uri"
        );

        let hover = backend
            .hover(HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri: hover_uri },
                    position: Position::new(1, 9), // inside "serde"'s name
                },
                work_done_progress_params: Default::default(),
            })
            .await
            .unwrap();
        assert!(
            hover.is_some(),
            "hover under a different non-canonical spelling must resolve the document \
             opened under the first spelling, not miss it as an unknown document"
        );
        let HoverContents::Markup(content) = hover.unwrap().contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("serde"), "{}", content.value);
        assert_eq!(
            backend.state.document_count(),
            1,
            "the hover request must not have created a second document entry"
        );
    }

    /// Chokepoint-enforcement regression (issue #1086, US-002, critic S2): proves the
    /// `canonicalize_uri` call is load-bearing at every `server.rs` entry point besides
    /// `hover` — deleting it from any one of these methods would fail zero tests
    /// otherwise, since every handler-level unit test passes an already-canonicalized
    /// `Uri` in directly. Each entry point below is driven with a *different*
    /// non-canonical spelling than the one `did_open` used, so a missing
    /// `canonicalize_uri` call surfaces structurally: `ensure_document_loaded` only
    /// cold-starts a second, disk-backed document when its `state.get_document(uri)`
    /// lookup misses, which only happens if the raw, non-canonical `Uri` reaches it
    /// instead of the canonical one already stored — `document_count()` jumps from 1 to
    /// 2 in that case, and `did_close`'s `remove_document` similarly leaves the original
    /// entry behind if its own `uri` isn't canonicalized to the same key.
    ///
    /// Does not cover the `updateAllOutdated`/`pinAllToSha` `executeCommand` arms: unlike
    /// every method here, neither ever creates or removes a `ServerState::documents`
    /// entry on a lookup miss (`execute_update_all_outdated`/`execute_pin_all_to_sha`
    /// just call `get_document` and refuse), so there is no `document_count()`-based (or
    /// otherwise state-observable) signal available without a message-capturing test
    /// client this codebase does not have; both call sites are covered by code
    /// inspection and `cargo clippy`/compilation only.
    ///
    /// Unix-only: the fixture path is drive-letter-less, so `url::Url::to_file_path`
    /// (which `parse_manifest`'s workspace-root discovery and `ensure_document_loaded`'s
    /// cold-start disk read both call internally) always fails on Windows regardless of
    /// the URI's spelling — a fixture-portability limit, not a difference in the
    /// canonicalization mechanism under test.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    #[cfg(not(windows))]
    async fn test_canonicalize_uri_chokepoint_covers_every_document_reading_entry_point() {
        // Held per fs_probe::snapshot_guard's doc: cold-start disk reads and
        // parse_manifest touch fs_probe, and this test shares a binary with
        // document/loader.rs's diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use tower_lsp_server::ls_types::{
            Position, TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams,
        };

        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("Cargo.toml");
        let content = "[dependencies]\nserde = \"1.0.0\"\n";
        std::fs::write(&manifest_path, content).unwrap();
        let path_str = manifest_path.to_str().unwrap();

        let open_uri: Uri = format!("file://localhost{path_str}").parse().unwrap();
        let other_spelling: Uri = format!("FILE://{path_str}").parse().unwrap();
        let canonical = crate::lsp_types_interop::canonicalize_uri(&open_uri);
        assert_eq!(
            canonical,
            crate::lsp_types_interop::canonicalize_uri(&other_spelling),
            "test premise: both raw spellings must canonicalize to the same Uri"
        );
        assert_ne!(
            open_uri, other_spelling,
            "test premise: the two spellings must differ"
        );

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();

        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: open_uri,
                    language_id: "toml".to_string(),
                    version: 1,
                    text: content.to_string(),
                },
            })
            .await;
        assert_eq!(
            backend.state.document_count(),
            1,
            "test premise: did_open stored one document"
        );

        backend
            .code_action(CodeActionParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling.clone(),
                },
                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                context: Default::default(),
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "code_action must resolve the existing document, not cold-start a second one"
        );

        backend
            .code_lens(CodeLensParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling.clone(),
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "code_lens must resolve the existing document, not cold-start a second one"
        );

        backend
            .completion(CompletionParams {
                text_document_position: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier {
                        uri: other_spelling.clone(),
                    },
                    position: Position::new(1, 9), // inside "serde"'s name
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
                context: None,
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "completion must resolve the existing document, not cold-start a second one"
        );

        backend
            .inlay_hint(InlayHintParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling.clone(),
                },
                work_done_progress_params: Default::default(),
                range: Range::new(Position::new(0, 0), Position::new(100, 0)),
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "inlay_hint must resolve the existing document, not cold-start a second one"
        );

        backend
            .document_link(DocumentLinkParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling.clone(),
                },
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "document_link must resolve the existing document, not cold-start a second one"
        );

        backend
            .diagnostic(DocumentDiagnosticParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling.clone(),
                },
                identifier: None,
                previous_result_id: None,
                work_done_progress_params: Default::default(),
                partial_result_params: Default::default(),
            })
            .await
            .unwrap();
        assert_eq!(
            backend.state.document_count(),
            1,
            "diagnostic must resolve the existing document, not cold-start a second one"
        );

        backend
            .did_close(DidCloseTextDocumentParams {
                text_document: TextDocumentIdentifier {
                    uri: other_spelling,
                },
            })
            .await;
        assert_eq!(
            backend.state.document_count(),
            0,
            "did_close under a different non-canonical spelling must remove the document \
             opened under the first spelling, not leave it behind under a mismatched key"
        );
    }

    /// Issue #636 impl-critic M1/N2: `handle_lockfile_change`'s diagnostics-refresh loop must
    /// compute `loading_ceiling` fresh for each affected document, not once outside the loop
    /// — two documents sharing one lock file with different dependency counts must reach a
    /// different ceiling. Uses `DocumentState::loading_started_at`'s public field to simulate
    /// elapsed loading time instead of a real 140s sleep.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_handle_lockfile_change_computes_ceiling_per_uri() {
        // Held per fs_probe::snapshot_guard's doc: parse_manifest touches fs_probe and
        // this test shares a binary with document/loader.rs's diffing test.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use crate::document::DocumentState;
        use deps_core::EcosystemId;
        use std::time::{Duration, Instant};

        let temp_dir = tempfile::tempdir().unwrap();
        let lockfile_path = temp_dir.path().join("Cargo.lock");
        std::fs::write(
            &lockfile_path,
            "# This file is automatically @generated by Cargo.\nversion = 3\n",
        )
        .unwrap();

        let small_dir = temp_dir.path().join("small");
        std::fs::create_dir(&small_dir).unwrap();
        let small_manifest_path = small_dir.join("Cargo.toml");
        let small_uri = Uri::from_file_path(&small_manifest_path).unwrap();
        let small_content = "[dependencies]\nserde = \"1.0\"\n".to_string();

        let large_dir = temp_dir.path().join("large");
        std::fs::create_dir(&large_dir).unwrap();
        let large_manifest_path = large_dir.join("Cargo.toml");
        let large_uri = Uri::from_file_path(&large_manifest_path).unwrap();
        // 15 dependencies at the config below (C=1, T=5s) yields ceil(15/1)*2*5s = 150s —
        // past the 120s floor, unlike the small manifest's ceil(1/1)*2*5s = 10s (floored to
        // 120s) — so the two documents must diverge under the same 140s elapsed duration.
        let mut large_content = "[dependencies]\n".to_string();
        for i in 0..15 {
            use std::fmt::Write as _;
            writeln!(large_content, "dep{i} = \"1.0\"").unwrap();
        }

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();
        {
            let mut config = backend.config.write().await;
            config.policy.cache.fetch_timeout_secs = 5;
            config.policy.cache.max_concurrent_fetches = 1;
        }

        let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
        for (uri, content) in [(&small_uri, &small_content), (&large_uri, &large_content)] {
            let parse_result = ecosystem
                .parse_manifest(
                    content,
                    &crate::lsp_types_interop::from_lsp_uri(uri).unwrap(),
                )
                .await
                .unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.clone(),
                parse_result,
            );
            doc_state.set_loading();
            // Simulate 140s of elapsed loading time without a real sleep: past the small
            // manifest's 120s (floored) ceiling, but short of the large manifest's 150s one.
            doc_state.loading_started_at = Some(
                Instant::now()
                    .checked_sub(Duration::from_secs(140))
                    .unwrap(),
            );
            backend.state.update_document(uri.clone(), doc_state);
        }

        backend
            .handle_lockfile_change(&lockfile_path, "cargo")
            .await;

        assert_eq!(
            backend
                .state
                .get_document(&small_uri)
                .unwrap()
                .loading_state,
            deps_core::LoadingState::Failed,
            "the 1-dependency document's 120s (floored) ceiling should have been exceeded \
             by 140s of elapsed loading time"
        );
        assert_eq!(
            backend
                .state
                .get_document(&large_uri)
                .unwrap()
                .loading_state,
            deps_core::LoadingState::Loading,
            "the 15-dependency document's 150s ceiling should NOT yet be exceeded by 140s \
             of elapsed loading time — if the ceiling were computed once outside the loop \
             (reusing whichever document's dependency count ran first) both documents would \
             reach the same verdict instead of diverging"
        );
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
        // Smoke test only: on this uninitialized backend, `execute_command` returns
        // `Ok(None)` whether the guard fired or not, so it can't distinguish the two.
        // Real regression coverage for the guard is on `build_update_version_edit` below.
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
            uri: crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            )),
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
    fn test_server_capabilities_execute_command_includes_pin_all_to_sha() {
        let caps = Backend::server_capabilities();
        let execute = caps
            .execute_command_provider
            .expect("execute command provider should exist");
        assert!(
            execute
                .commands
                .contains(&commands::PIN_ALL_TO_SHA.to_string())
        );
    }

    #[test]
    fn test_commands_pin_all_to_sha_matches_ecosystem_command_id() {
        assert_eq!(commands::PIN_ALL_TO_SHA, "deps-lsp.pinAllToSha");
        assert_eq!(
            commands::PIN_ALL_TO_SHA,
            deps_core::lsp_helpers::PIN_ALL_TO_SHA_COMMAND_ID
        );
    }

    #[test]
    fn test_pin_all_to_sha_args_deserialization() {
        let json = serde_json::json!({ "uri": "file:///repo/.github/workflows/ci.yml" });
        let args: PinAllToShaArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.uri.as_str(), "file:///repo/.github/workflows/ci.yml");
    }

    #[test]
    fn test_update_all_outdated_args_deserialization() {
        let json = serde_json::json!({ "uri": "file:///test/Cargo.toml" });
        let args: UpdateAllOutdatedArgs = serde_json::from_value(json).unwrap();
        assert_eq!(args.uri.as_str(), "file:///test/Cargo.toml");
    }

    #[test]
    fn test_build_batch_workspace_edit_uses_document_changes_with_version() {
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));
        let edits = vec![TextEdit {
            range: Range::default(),
            new_text: "1.2.0".into(),
        }];

        let edit = build_batch_workspace_edit(&uri, Some(7), edits, true);

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
    fn test_build_batch_workspace_edit_falls_back_to_changes_map() {
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));
        let edits = vec![TextEdit {
            range: Range::default(),
            new_text: "1.2.0".into(),
        }];

        let edit = build_batch_workspace_edit(&uri, Some(7), edits, false);

        assert!(edit.document_changes.is_none());
        let changes = edit.changes.expect("changes present");
        assert_eq!(changes.get(&uri).map(Vec::len), Some(1));
    }

    // Issue #227: `parse_config` (C2) and `did_change_configuration` live-reload
    mod parse_config_tests {
        use super::*;

        #[test]
        fn test_parse_config_accepts_empty_object() {
            let config = parse_config(serde_json::json!({})).expect("empty object is valid");
            assert!(config.policy.freshness.enabled);
        }

        #[test]
        fn test_parse_config_accepts_recognized_keys() {
            let config = parse_config(serde_json::json!({
                "freshness": { "cooldown_secs": 60 }
            }))
            .expect("payload with a recognized key is valid");
            assert_eq!(config.policy.freshness.cooldown_secs, 60);
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

        /// End-to-end regression for issue #1083 critic S1: `diagnostic::Severity`'s
        /// `Deserialize` clamps an out-of-range integer instead of failing, so this pins
        /// the *whole pipeline* — a raw JSON config payload with an out-of-range
        /// `unknown_severity` value must (a) still parse successfully through
        /// `parse_config`/`DepsConfig` rather than being rejected wholesale, and (b) the
        /// clamped severity must actually reach a real, published diagnostic's LSP wire
        /// representation, not just the intermediate `Severity` value.
        #[test]
        fn test_parse_config_clamps_out_of_range_severity_through_to_a_published_diagnostic() {
            let config = parse_config(serde_json::json!({
                "diagnostics": { "unknown_severity": 999 }
            }))
            .expect("an out-of-range severity must not fail the whole config parse");
            assert_eq!(
                config.policy.diagnostics.unknown_severity,
                deps_core::diagnostic::Severity::Hint,
                "999 must clamp to the least-severe defined variant"
            );

            let parse_result = deps_core::test_util::stub_parse_result_with_dependencies(1);
            let cached_versions = std::collections::HashMap::new();
            let resolved_versions = std::collections::HashMap::new();
            let diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached_versions, &resolved_versions),
                &crate::test_utils::blocking_ecosystem::NoopFormatter,
                parse_result.uri(),
                deps_core::FreshnessSettings::default(),
                config.policy.diagnostics.to_severities(),
                deps_core::PublishTime::now(),
            );
            let unknown_package_diagnostic = diagnostics
                .into_iter()
                .find(|d| d.message().contains("Unknown package"))
                .expect(
                    "the stub dependency has no cached versions, so it must be reported unknown",
                );
            assert_eq!(
                unknown_package_diagnostic.severity,
                Some(deps_core::diagnostic::Severity::Hint)
            );

            // The pipeline's final hop: the domain `Diagnostic` converts to the exact
            // LSP wire severity a real client would render.
            let ls_diagnostic =
                crate::lsp_types_interop::to_lsp_diagnostic(unknown_package_diagnostic);
            assert_eq!(
                ls_diagnostic.severity,
                Some(tower_lsp_server::ls_types::DiagnosticSeverity::HINT)
            );
        }
    }

    /// Tester gap: only the `false`/absent branch of these two capability checks was
    /// incidentally covered (every other test builds a `Backend` that never sets
    /// `client_capabilities`). These pin the `true` branch directly.
    mod capability_support_tests {
        use super::*;
        use tower_lsp_server::ls_types::{
            ClientCapabilities, CodeLensWorkspaceClientCapabilities,
            DiagnosticWorkspaceClientCapabilities, DynamicRegistrationClientCapabilities,
            InlayHintWorkspaceClientCapabilities, WorkspaceClientCapabilities,
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

        /// Issue #493: `inlay_hint_refresh`/`code_lens_refresh` are now capability-gated
        /// before being fired off, so a wrong reading here would either silently drop a
        /// refresh a client actually wants, or (pre-fix) let a client that never
        /// declared support hang the caller. Pin both branches for each helper.
        #[tokio::test]
        async fn test_inlay_hint_refresh_supported_true_branch() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            *backend.client_capabilities.write().await = Some(ClientCapabilities {
                workspace: Some(WorkspaceClientCapabilities {
                    inlay_hint: Some(InlayHintWorkspaceClientCapabilities {
                        refresh_support: Some(true),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });

            assert!(backend.inlay_hint_refresh_supported().await);
        }

        #[tokio::test]
        async fn test_inlay_hint_refresh_supported_false_when_absent() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            assert!(!backend.inlay_hint_refresh_supported().await);
        }

        #[tokio::test]
        async fn test_code_lens_refresh_supported_true_branch() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            *backend.client_capabilities.write().await = Some(ClientCapabilities {
                workspace: Some(WorkspaceClientCapabilities {
                    code_lens: Some(CodeLensWorkspaceClientCapabilities {
                        refresh_support: Some(true),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });

            assert!(backend.code_lens_refresh_supported().await);
        }

        #[tokio::test]
        async fn test_code_lens_refresh_supported_false_when_absent() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            assert!(!backend.code_lens_refresh_supported().await);
        }

        /// `initialize` must snapshot both flags into `ServerState` (mirroring
        /// `progress_supported`) so the fire-and-forget call sites in
        /// `document::lifecycle` can read them without an async `ClientCapabilities`
        /// lock (issue #493).
        #[tokio::test]
        async fn test_initialize_propagates_refresh_support_flags_into_state() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            assert!(!backend.state.inlay_hint_refresh_supported());
            assert!(!backend.state.code_lens_refresh_supported());

            let result = backend
                .initialize(InitializeParams {
                    capabilities: ClientCapabilities {
                        workspace: Some(WorkspaceClientCapabilities {
                            inlay_hint: Some(InlayHintWorkspaceClientCapabilities {
                                refresh_support: Some(true),
                            }),
                            code_lens: Some(CodeLensWorkspaceClientCapabilities {
                                refresh_support: Some(true),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .await;

            assert!(result.is_ok());
            assert!(backend.state.inlay_hint_refresh_supported());
            assert!(backend.state.code_lens_refresh_supported());
        }

        #[tokio::test]
        async fn test_initialize_without_refresh_capabilities_keeps_state_flags_false() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend.initialize(InitializeParams::default()).await;

            assert!(result.is_ok());
            assert!(!backend.state.inlay_hint_refresh_supported());
            assert!(!backend.state.code_lens_refresh_supported());
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
            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                60
            );
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
                backend.config.read().await.policy.freshness.cooldown_secs,
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
            assert!(backend.config.read().await.policy.freshness.enabled);
        }

        /// Tester gap (issue #660/#661): `initializationOptions.license_policy` had no
        /// coverage through the real JSON -> `parse_config` -> `LicensePolicyConfig`
        /// deserializer path — existing tests only constructed `LicensePolicyConfig` as a
        /// Rust struct literal. Also proves `initialize` mirrors the parsed policy onto
        /// `ServerState` (critic C1), not just `Backend::config`.
        #[tokio::test]
        async fn test_initialize_applies_valid_license_policy() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend
                .initialize(InitializeParams {
                    initialization_options: Some(serde_json::json!({
                        "license_policy": { "allow": ["MIT", "Apache-2.0"], "deny": ["GPL-3.0"] }
                    })),
                    ..Default::default()
                })
                .await;

            assert!(result.is_ok());
            let config = backend.config.read().await;
            assert_eq!(
                config.policy.license_policy.allow,
                vec!["MIT".to_string(), "Apache-2.0".to_string()]
            );
            assert_eq!(
                config.policy.license_policy.deny,
                vec!["GPL-3.0".to_string()]
            );
            drop(config);

            let mirrored = backend.state.license_policy();
            assert_eq!(
                mirrored.allow,
                vec!["MIT".to_string(), "Apache-2.0".to_string()]
            );
            assert_eq!(mirrored.deny, vec!["GPL-3.0".to_string()]);
        }

        /// Tester gap: an invalid SPDX entry must be dropped (with a warning) rather than
        /// rejecting the whole `initializationOptions` payload — `deserialize_spdx_list`
        /// filters at deserialize time, not `deny_unknown_fields`-style hard rejection.
        #[tokio::test]
        async fn test_initialize_drops_invalid_spdx_entry_keeps_rest_of_config() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            let result = backend
                .initialize(InitializeParams {
                    initialization_options: Some(serde_json::json!({
                        "license_policy": { "allow": ["MIT", "not a valid spdx expression"] },
                        "freshness": { "cooldown_secs": 60 }
                    })),
                    ..Default::default()
                })
                .await;

            assert!(result.is_ok());
            let config = backend.config.read().await;
            assert_eq!(
                config.policy.license_policy.allow,
                vec!["MIT".to_string()],
                "the invalid entry must be dropped, not reject the whole payload"
            );
            assert_eq!(
                config.policy.freshness.cooldown_secs, 60,
                "the rest of the config must still apply"
            );
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

            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                60
            );
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
            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                60
            );

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "deps-lsp": { "freshness": { "cooldown_secs": 999 } } }),
                })
                .await;

            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
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
            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                60
            );

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::Value::Null,
                })
                .await;

            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                60
            );
        }

        /// Tester gap (issue #660/#661): mirrors `initialize_tests::
        /// test_initialize_applies_valid_license_policy` for `did_change_configuration`,
        /// proving both `initializationOptions` and `workspace/didChangeConfiguration`
        /// reach the same `parse_config`/`LicensePolicyConfig` deserializer and both
        /// mirror the result onto `ServerState` (critic C1) — not just one of the two
        /// entry points.
        #[tokio::test]
        async fn test_did_change_configuration_applies_valid_license_policy() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "license_policy": { "allow": ["MIT"], "deny": ["GPL-3.0", "AGPL-3.0"] }
                    }),
                })
                .await;

            let config = backend.config.read().await;
            assert_eq!(config.policy.license_policy.allow, vec!["MIT".to_string()]);
            assert_eq!(
                config.policy.license_policy.deny,
                vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()]
            );
            drop(config);

            let mirrored = backend.state.license_policy();
            assert_eq!(mirrored.allow, vec!["MIT".to_string()]);
            assert_eq!(
                mirrored.deny,
                vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()]
            );
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
            assert_matches!(result, Err(deps_core::DepsError::Offline { .. }));
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

        /// Issue #499: `cold_start.rate_limit_ms` was parsed into `DepsConfig` but
        /// never reached the live `ColdStartLimiter`, which always used the
        /// hardcoded 100ms interval it was constructed with. A live-reloaded,
        /// shorter interval must actually change rate-limiting behavior.
        #[tokio::test]
        async fn test_did_change_configuration_updates_cold_start_rate_limit() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri =
                crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri("/test.toml"));

            assert!(backend.state.cold_start_limiter.allow_cold_start(&uri));
            assert!(
                !backend.state.cold_start_limiter.allow_cold_start(&uri),
                "second immediate request blocked under the default 100ms interval"
            );

            // `rate_limit_ms: 0` disables rate limiting entirely (`elapsed < ZERO` is
            // never true), so the assertion below is deterministic regardless of
            // scheduling jitter — no sleep, unlike a short nonzero interval would need.
            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "cold_start": { "rate_limit_ms": 0 } }),
                })
                .await;
            assert_eq!(backend.config.read().await.cold_start.rate_limit_ms, 0);

            assert!(
                backend.state.cold_start_limiter.allow_cold_start(&uri),
                "rate_limit_ms: 0 should allow a cold start immediately, with no wait"
            );
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
            // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
            // guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::document::DocumentState;
            use crate::handlers::{diagnostics, hover};
            use deps_core::EcosystemId;
            use tokio::sync::Barrier;
            use tower_lsp_server::ls_types::{
                HoverParams, Position, TextDocumentIdentifier, TextDocumentPositionParams,
            };

            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let uri = crate::lsp_types_interop::to_lsp_uri(&url);

            // Seed the document so `ensure_document_loaded`'s fast path (already loaded)
            // returns immediately, letting both handlers reach their own config reads.
            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem.parse_manifest(&content, &url).await.unwrap();
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

            let diagnostics_config_snapshot =
                { backend.config.read().await.policy.diagnostics.clone() };
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
            assert_eq!(
                backend.config.read().await.policy.freshness.cooldown_secs,
                42
            );
        }

        /// Issue #592 S1 regression: two rapid `didChangeConfiguration` notifications, each
        /// touching a *different* parse-affecting setting, must coalesce into one reparse
        /// that covers the union of both scopes — not just the second (narrower) one, which
        /// a naive "recompute against the immediately-previous config" coalescing scheme
        /// would lose.
        ///
        /// **Security review S5 correction**: the second payload must explicitly repeat
        /// `"workspace_registries": "off"`. `did_change_configuration` uses
        /// replace-whole-config semantics, so a payload that omits a `RegistriesConfig`
        /// field resets it to its type default (`PublicOnly`) — a second payload that only
        /// sets `nuget_user_profile_sources` would silently flip `workspace_registries` from
        /// `Off` (set by the first call) back to `PublicOnly`, which is *itself* a change
        /// and would independently re-trigger the full workspace-ecosystems scope on the
        /// second call alone. That would make this test pass even if `queue_reparse`
        /// replaced the pending scope instead of unioning it, since the second call's own
        /// (accidentally broad) scope would already cover the cargo document. Repeating
        /// `"off"` holds `workspace_registries` constant across both calls, so the second
        /// call's own scope is genuinely just `["nuget"]` — only a real union still covers
        /// cargo.
        ///
        /// Observed via `cached_versions` being cleared: `RefetchPolicy::AllDependencies`
        /// clears it unconditionally before attempting the (network, and in this sandboxed
        /// test environment expected-to-fail) fetch, so an empty map is proof the document's
        /// scope was actually reparsed, regardless of whether the fetch itself succeeds.
        #[cfg(all(feature = "cargo", feature = "nuget"))]
        #[tokio::test]
        async fn test_rapid_config_changes_coalesce_into_a_union_scope_reparse() {
            // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
            // guard is needed here (both the cargo and nuget ecosystem's `parse_manifest` calls in this
            // test transitively touch fs_probe).
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            use crate::document::DocumentState;
            use deps_core::{EcosystemId, PackageName, PackageVersions};

            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();

            // `cargo` is only ever in scope via the `workspace_registries` change (the
            // first call); `nuget_user_profile_sources` (the second call) never mentions
            // cargo at all — so cargo's `cached_versions` being cleared is proof the first
            // call's scope survived the union, not an artifact of the second call's own
            // (unrelated) scope.
            let cargo_url = deps_core::test_util::test_uri("/test/Cargo.toml");
            let cargo_uri = crate::lsp_types_interop::to_lsp_uri(&cargo_url);
            let cargo_ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let cargo_content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let cargo_parse = cargo_ecosystem
                .parse_manifest(&cargo_content, &cargo_url)
                .await
                .unwrap();
            let mut cargo_doc = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                cargo_content,
                cargo_parse,
            );
            cargo_doc.set_version(Some(1));
            cargo_doc.update_cached_versions(HashMap::from([(
                PackageName::new("serde"),
                PackageVersions::latest_only("1.0.999"),
            )]));
            backend.state.update_document(cargo_uri.clone(), cargo_doc);

            let nuget_url = deps_core::test_util::test_uri("/test/project.csproj");
            let nuget_uri = crate::lsp_types_interop::to_lsp_uri(&nuget_url);
            let nuget_ecosystem = backend.state.ecosystem_registry.get("nuget").unwrap();
            let nuget_content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>"#.to_string();
            let nuget_parse = nuget_ecosystem
                .parse_manifest(&nuget_content, &nuget_url)
                .await
                .unwrap();
            let mut nuget_doc = DocumentState::new_from_parse_result(
                EcosystemId::NuGet,
                nuget_content,
                nuget_parse,
            );
            nuget_doc.set_version(Some(1));
            nuget_doc.update_cached_versions(HashMap::from([(
                PackageName::new("Newtonsoft.Json"),
                PackageVersions::latest_only("99.0.0"),
            )]));
            backend.state.update_document(nuget_uri.clone(), nuget_doc);

            // Fired back-to-back, no `.await`ed sleep in between — the second call's
            // `queue_reparse` must union onto, not replace, the first's pending scope.
            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({ "registries": { "workspace_registries": "off" } }),
                })
                .await;
            backend
                .did_change_configuration(DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "registries": {
                            "workspace_registries": "off",
                            "nuget_user_profile_sources": true
                        }
                    }),
                })
                .await;

            let both_cleared = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let cargo_cleared = backend
                        .state
                        .get_document(&cargo_uri)
                        .is_some_and(|d| d.cached_versions.is_empty());
                    let nuget_cleared = backend
                        .state
                        .get_document(&nuget_uri)
                        .is_some_and(|d| d.cached_versions.is_empty());
                    if cargo_cleared && nuget_cleared {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await;

            assert!(
                both_cleared.is_ok(),
                "both documents' stale cached_versions must be dropped by the coalesced \
                 reparse — a lost scope would leave one of them untouched"
            );
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
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

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
            // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
            // guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(
                    &content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
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
            // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
            // guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // `version: None` mirrors a document populated from disk after a missed
            // didOpen (server restart/crash) — must be refused even though loaded and
            // not `Loading`.
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(
                    &content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
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
            // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
            // guard is needed here.
            let _guard = deps_core::fs_probe::snapshot_guard_async().await;
            // This test `Backend` is never `initialize`d, so `apply_edit` returns `Err`
            // (per its documented behavior) — exercises the failure/warning path.
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/test/Cargo.toml",
            ));

            let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(
                    &content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
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

    #[cfg(feature = "github-actions")]
    mod pin_all_to_sha_execute_command_tests {
        use super::*;
        use crate::document::DocumentState;
        use deps_core::EcosystemId;
        use std::sync::Arc;

        fn command_params(uri: &Uri) -> ExecuteCommandParams {
            ExecuteCommandParams {
                command: commands::PIN_ALL_TO_SHA.to_string(),
                arguments: vec![serde_json::json!({ "uri": uri.as_str() })],
                work_done_progress_params: Default::default(),
            }
        }

        /// Seeds `ecosystem`'s shared `TagIndex` for `name` with one `tag -> sha` entry —
        /// same pattern `handlers::code_lens::cross_ecosystem_tests::seed_gha_tag_index`
        /// uses, downcasting through `Ecosystem::registry()`/`Registry::as_any()` since
        /// this module never drives a live registry fetch.
        fn seed_gha_tag_index(
            ecosystem: &dyn deps_core::Ecosystem,
            name: &str,
            tag: &str,
            sha: &str,
        ) {
            let registry = ecosystem.registry();
            let gha_registry = registry
                .as_any()
                .downcast_ref::<deps_github_actions::GithubActionsRegistry>()
                .expect("github-actions ecosystem must back onto a GithubActionsRegistry");
            let mut index = deps_github_actions::registry::TagIndex::default();
            index.tag_to_sha.insert(tag.to_string(), sha.to_string());
            gha_registry
                .tag_index()
                .insert(deps_core::PackageName::new(name), Arc::new(index));
        }

        /// Recomputes the bulk pin-all-to-SHA edit count directly, the same call
        /// `Backend::execute_pin_all_to_sha` makes — used to pin each test's actual
        /// discriminating precondition (issue #633 critic S2: `execute_command` returns
        /// `Ok(None)` on every path, including every refusal branch, so asserting only
        /// `result.is_ok()` cannot tell "applied N edits" apart from "silently refused").
        /// Calls the trait method directly on `&dyn Ecosystem` (#640) — no downcast, since
        /// `collect_pin_all_to_sha_edits` is generic across every ecosystem now.
        fn gha_edit_count(
            ecosystem: &dyn deps_core::Ecosystem,
            parse_result: &dyn deps_core::ParseResult,
        ) -> usize {
            let cached = std::collections::HashMap::new();
            let resolved = std::collections::HashMap::new();
            ecosystem
                .collect_pin_all_to_sha_edits(
                    parse_result,
                    deps_core::VersionData::new(&cached, &resolved),
                )
                .len()
        }

        #[tokio::test]
        async fn test_execute_command_pin_all_to_sha_closed_document_no_op() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/repo/.github/workflows/ci.yml",
            ));

            assert!(backend.state.get_document(&uri).is_none());

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
            assert!(
                backend.state.get_document(&uri).is_none(),
                "a refused command must not create a document"
            );
        }

        /// Mirrors `execute_update_all_outdated`'s own
        /// `test_execute_command_update_all_outdated_loading_document_no_op`: the
        /// readiness-gate refusal branch (`!doc.is_ready_for_batch_update()`) had zero
        /// test coverage for this command before this test (tester finding).
        #[tokio::test]
        async fn test_execute_command_pin_all_to_sha_loading_document_no_op() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/repo/.github/workflows/ci.yml",
            ));

            let ecosystem = backend
                .state
                .ecosystem_registry
                .get("github-actions")
                .unwrap();
            let content = "steps:\n  - uses: actions/checkout@v4\n".to_string();
            let parse_result = ecosystem
                .parse_manifest(
                    &content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
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

        /// Mirrors `execute_update_all_outdated`'s own
        /// `test_execute_command_update_all_outdated_no_version_no_op` (tester finding).
        #[tokio::test]
        async fn test_execute_command_pin_all_to_sha_no_version_no_op() {
            // `version: None` mirrors a document populated from disk after a missed
            // didOpen (server restart/crash) — must be refused even though loaded and
            // not `Loading`.
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/repo/.github/workflows/ci.yml",
            ));

            let ecosystem = backend
                .state
                .ecosystem_registry
                .get("github-actions")
                .unwrap();
            let content = "steps:\n  - uses: actions/checkout@v4\n";
            let parse_result = ecosystem
                .parse_manifest(
                    content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content.to_string(),
                parse_result,
            );
            doc_state.set_loaded();
            // `version` deliberately left as `None`.
            assert!(!doc_state.is_ready_for_batch_update());
            backend.state.update_document(uri.clone(), doc_state);

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_execute_command_pin_all_to_sha_no_resolvable_step_shows_info_message() {
            // No `TagIndex` seeded: the one Tag-pinned step is a cache miss, so
            // `collect_pin_all_to_sha_edits` returns empty and the command must be a
            // no-op (informational message, not a warning/panic).
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/repo/.github/workflows/ci.yml",
            ));
            let content = "steps:\n  - uses: actions/checkout@v4\n";

            let ecosystem = backend
                .state
                .ecosystem_registry
                .get("github-actions")
                .unwrap();
            let parse_result = ecosystem
                .parse_manifest(
                    content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
            // Pin the precondition the refusal actually depends on: a genuine `TagIndex`
            // cache miss, not e.g. a wrong downcast or an empty method body.
            assert_eq!(
                gha_edit_count(ecosystem.as_ref(), parse_result.as_ref()),
                0,
                "fixture must have zero resolvable edits for this to test the no-op path"
            );
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content.to_string(),
                parse_result,
            );
            doc_state.set_version(Some(1));
            doc_state.set_loaded();
            backend.state.update_document(uri.clone(), doc_state);

            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_execute_command_pin_all_to_sha_applies_edit_for_resolvable_steps() {
            let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
            let backend = service.inner();
            let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
                "/repo/.github/workflows/ci.yml",
            ));
            let content = "steps:\n\
                 \x20 - uses: actions/checkout@v4\n\
                 \x20 - uses: actions/setup-node@v3\n";

            let ecosystem = backend
                .state
                .ecosystem_registry
                .get("github-actions")
                .unwrap();
            seed_gha_tag_index(
                ecosystem.as_ref(),
                "actions/checkout",
                "v4",
                &"a".repeat(40),
            );
            let parse_result = ecosystem
                .parse_manifest(
                    content,
                    &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
                )
                .await
                .unwrap();
            // Pin the precondition this test actually exercises: exactly one of the two
            // steps is resolvable (the other has no seeded `TagIndex` entry) — without
            // this, the test below cannot distinguish "applied 1 edit" from "refused,
            // showed an info message" (both return `Ok(None)`, critic S2).
            assert_eq!(
                gha_edit_count(ecosystem.as_ref(), parse_result.as_ref()),
                1,
                "fixture must have exactly one resolvable edit for this to test the \
                 apply-edit path, not the no-resolvable-step refusal"
            );
            let mut doc_state = DocumentState::new_from_parse_result(
                EcosystemId::GithubActions,
                content.to_string(),
                parse_result,
            );
            doc_state.set_version(Some(1));
            doc_state.set_loaded();
            backend.state.update_document(uri.clone(), doc_state);

            // This test `Backend` is never `initialize`d, so `apply_edit` returns `Err`
            // (documented `apply_edit` behavior) — exercises the same not-a-panic
            // apply-failure path `execute_update_all_outdated`'s own test covers,
            // proving the command reaches (and survives) the apply step rather than
            // being refused earlier.
            let result = backend.execute_command(command_params(&uri)).await;
            assert!(result.is_ok());
        }
    }

    /// #640: a stale/forged `deps-lsp.pinAllToSha` against a document whose ecosystem has
    /// no mutable-ref pin concept (e.g. Cargo) is a no-op, but — since the command is now
    /// dispatched through `Ecosystem::collect_pin_all_to_sha_edits`'s trait default rather
    /// than a GitHub-Actions-specific downcast — it takes the same INFO "nothing to pin"
    /// path an all-SHA-pinned GitHub Actions workflow would (Risk #2), not a distinct
    /// refusal. This intentionally supersedes the pre-#640 downcast-refusal test.
    ///
    /// S4 (impl-critic re-review): `execute_command` returns `Ok(None)` on every path
    /// (including every refusal), so asserting only `result.is_ok()` cannot distinguish
    /// "reached the INFO path" from "was refused earlier for an unrelated reason" — assert
    /// the M1 `tracing::debug!("pinAllToSha: no edits")` line actually fired instead.
    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_execute_command_pin_all_to_sha_non_pin_ecosystem_document_no_op() {
        // See the comment in `test_handle_lockfile_change_computes_ceiling_per_uri` on why this
        // guard is needed here.
        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        use crate::document::DocumentState;
        use deps_core::EcosystemId;

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/test/Cargo.toml",
        ));

        let ecosystem = backend.state.ecosystem_registry.get("cargo").unwrap();
        let content = "[dependencies]\nserde = \"1.0.0\"\n".to_string();
        let parse_result = ecosystem
            .parse_manifest(
                &content,
                &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
            )
            .await
            .unwrap();
        let mut doc_state =
            DocumentState::new_from_parse_result(EcosystemId::Cargo, content.clone(), parse_result);
        doc_state.set_version(Some(1));
        doc_state.set_loaded();
        backend.state.update_document(uri.clone(), doc_state);

        let output =
            deps_core::test_util::capture_tracing_output_async_at(tracing::Level::DEBUG, async {
                let result = backend
                    .execute_command(ExecuteCommandParams {
                        command: commands::PIN_ALL_TO_SHA.to_string(),
                        arguments: vec![serde_json::json!({ "uri": uri.as_str() })],
                        work_done_progress_params: Default::default(),
                    })
                    .await;
                assert!(result.is_ok());
            })
            .await;

        assert!(
            output.contains("pinAllToSha: no edits"),
            "expected the M1 debug! log confirming the INFO 'nothing to pin' path fired \
             (proving the generic dispatch reached the empty-edits branch, not some other \
             refusal): {output}"
        );
        assert_eq!(
            backend.state.get_document(&uri).unwrap().content,
            content,
            "a no-op command must not touch document content"
        );
    }

    /// #640: end-to-end mirror of
    /// `pin_all_to_sha_execute_command_tests::test_execute_command_pin_all_to_sha_applies_edit_for_resolvable_steps`
    /// for GitLab CI — proves the generic `deps-lsp.pinAllToSha` dispatch (no ecosystem
    /// downcast) reaches a non-GitHub-Actions ecosystem's own
    /// `collect_pin_all_to_sha_edits` override.
    #[cfg(feature = "gitlab-ci")]
    #[tokio::test]
    async fn test_execute_command_pin_all_to_sha_gitlab_ci_applies_edit_for_resolvable_tag_pin() {
        use crate::document::DocumentState;
        use deps_core::EcosystemId;
        use std::sync::Arc;

        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let backend = service.inner();
        let uri = crate::lsp_types_interop::to_lsp_uri(&deps_core::test_util::test_uri(
            "/repo/.gitlab-ci.yml",
        ));
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";

        let ecosystem = backend.state.ecosystem_registry.get("gitlab-ci").unwrap();
        let registry = ecosystem.registry();
        let gitlab_registry = registry
            .as_any()
            .downcast_ref::<deps_gitlab_ci::GitlabCiRegistry>()
            .expect("gitlab-ci ecosystem must back onto a GitlabCiRegistry");
        let parse_result = ecosystem
            .parse_manifest(
                content,
                &crate::lsp_types_interop::from_lsp_uri(&uri).unwrap(),
            )
            .await
            .unwrap();
        let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
            .name()
            .clone();
        let mut index = deps_gitlab_ci::registry::TagIndex::default();
        index
            .tag_to_sha
            .insert("v1.0.0".to_string(), "a".repeat(40));
        gitlab_registry
            .tag_index()
            .insert((deps_gitlab_ci::EndpointKind::Tags, name), Arc::new(index));

        // S4 (impl-critic re-review): pin the precondition this test actually depends on —
        // an empty-edit run also returns `Ok`, so without this the test cannot prove the
        // generic dispatch actually reached GitLab CI's `collect_pin_all_to_sha_edits`
        // override, only that *some* no-op-or-not path completed without erroring.
        let empty_cached = std::collections::HashMap::new();
        let empty_resolved = std::collections::HashMap::new();
        let versions = deps_core::VersionData::new(&empty_cached, &empty_resolved);
        assert_eq!(
            ecosystem
                .collect_pin_all_to_sha_edits(parse_result.as_ref(), versions)
                .len(),
            1,
            "fixture must have exactly one resolvable edit for this to test the \
             apply-edit path, not an empty-edits no-op"
        );

        let mut doc_state = DocumentState::new_from_parse_result(
            EcosystemId::GitlabCi,
            content.to_string(),
            parse_result,
        );
        doc_state.set_version(Some(1));
        doc_state.set_loaded();
        backend.state.update_document(uri.clone(), doc_state);

        // This test `Backend` is never `initialize`d, so `apply_edit` returns `Err`
        // (documented `apply_edit` behavior) — exercises the same not-a-panic
        // apply-failure path the GitHub Actions equivalent covers, proving the command
        // reaches (and survives) the apply step for a non-GitHub-Actions ecosystem too.
        let result = backend
            .execute_command(ExecuteCommandParams {
                command: commands::PIN_ALL_TO_SHA.to_string(),
                arguments: vec![serde_json::json!({ "uri": uri.as_str() })],
                work_done_progress_params: Default::default(),
            })
            .await;
        assert!(result.is_ok());
    }

    /// Issue #808 (critic S1 follow-up): the `window/showMessage` warning for a rejected
    /// `registries.gitlab_instance_host` value interpolates `raw` directly — a second,
    /// user-visible sink for the same credential leak #808 closed in the
    /// `tracing::warn!`/error-`Display` path. Asserts both that the raw credential never
    /// appears in the built message and that the redacted form *does* — a positive
    /// assertion, not just an absence check that would pass vacuously if the value were
    /// dropped from the message entirely.
    #[cfg(feature = "gitlab-ci")]
    #[test]
    fn test_gitlab_instance_host_invalid_message_redacts_credential() {
        let policy = deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        );
        let raw = "user:hunter2@gitlab.corp";
        let error = deps_engine::setup::validate_gitlab_instance_host(raw, &policy).unwrap_err();

        let message = gitlab_instance_host_invalid_message(raw, &error);

        assert!(!message.contains("hunter2"), "message: {message}");
        assert!(
            message.contains(&deps_core::net_policy::RedactedUrl::new(raw).into_inner()),
            "expected the redacted form to still be present: {message}"
        );
    }
}

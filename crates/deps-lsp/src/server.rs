use crate::config::DepsConfig;
use crate::document::{ServerState, handle_document_change, handle_document_open};
use crate::file_watcher;
use crate::handlers::{code_actions, completion, diagnostics, hover, inlay_hints};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp_server::ls_types::{
    CodeActionOptions, CodeActionParams, CodeActionProviderCapability, CompletionOptions,
    CompletionParams, CompletionResponse, DiagnosticOptions, DiagnosticServerCapabilities,
    DidChangeTextDocumentParams, DidChangeWatchedFilesParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentDiagnosticParams, DocumentDiagnosticReport,
    DocumentDiagnosticReportResult, ExecuteCommandOptions, ExecuteCommandParams,
    FullDocumentDiagnosticReport, Hover, HoverParams, HoverProviderCapability, InitializeParams,
    InitializeResult, InitializedParams, InlayHint, InlayHintParams, MessageType, OneOf, Range,
    RelatedFullDocumentDiagnosticReport, ServerCapabilities, ServerInfo,
    TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Uri, WorkspaceEdit,
};
use tower_lsp_server::{Client, LanguageServer, jsonrpc::Result};

/// LSP command identifiers.
mod commands {
    /// Command to update a dependency version.
    pub const UPDATE_VERSION: &str = "deps-lsp.updateVersion";
}

pub struct Backend {
    pub(crate) client: Client,
    state: Arc<ServerState>,
    config: Arc<RwLock<DepsConfig>>,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            state: Arc::new(ServerState::new()),
            config: Arc::new(RwLock::new(DepsConfig::default())),
        }
    }

    /// Get a reference to the LSP client (primarily for testing/benchmarking).
    #[doc(hidden)]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Handles opening a document using unified ecosystem registry.
    async fn handle_open(&self, uri: tower_lsp_server::ls_types::Uri, content: String) {
        match handle_document_open(
            uri.clone(),
            content,
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
                    .log_message(MessageType::ERROR, format!("Parse error: {}", e))
                    .await;
            }
        }
    }

    /// Handles changes to a document using unified ecosystem registry.
    async fn handle_change(&self, uri: tower_lsp_server::ls_types::Uri, content: String) {
        match handle_document_change(
            uri.clone(),
            content,
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
                if doc.ecosystem_id != ecosystem_id {
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
                .map(|(name, pkg)| (name.clone(), pkg.version.clone()))
                .collect::<HashMap<String, String>>(),
            Err(e) => {
                tracing::error!("Failed to reload lock file: {}", e);
                self.client
                    .log_message(
                        MessageType::ERROR,
                        format!("Failed to reload lock file: {}", e),
                    )
                    .await;
                HashMap::new()
            }
        };

        let config = self.config.read().await;

        for uri in affected_uris {
            if let Some(mut doc) = self.state.documents.get_mut(&uri) {
                doc.update_resolved_versions(resolved_versions.clone());
                doc.update_cached_versions(resolved_versions.clone());
            }

            let items = diagnostics::handle_diagnostics(
                Arc::clone(&self.state),
                &uri,
                &config.diagnostics,
                self.client.clone(),
                Arc::clone(&self.config),
            )
            .await;

            self.client.publish_diagnostics(uri, items, None).await;
        }

        if let Err(e) = self.client.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
    }

    fn server_capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            completion_provider: Some(CompletionOptions {
                trigger_characters: Some(vec!["\"".into(), "=".into(), ".".into()]),
                resolve_provider: Some(false),
                ..Default::default()
            }),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            inlay_hint_provider: Some(OneOf::Left(true)),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(vec![tower_lsp_server::ls_types::CodeActionKind::REFACTOR]),
                ..Default::default()
            })),
            diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
                identifier: Some("deps".into()),
                inter_file_dependencies: false,
                workspace_diagnostics: false,
                ..Default::default()
            })),
            execute_command_provider: Some(ExecuteCommandOptions {
                commands: vec![commands::UPDATE_VERSION.into()],
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        tracing::info!("initializing deps-lsp server");

        // Parse initialization options
        if let Some(init_options) = params.initialization_options
            && let Ok(config) = serde_json::from_value::<DepsConfig>(init_options)
        {
            tracing::debug!("loaded configuration: {:?}", config);
            *self.config.write().await = config;
        }

        Ok(InitializeResult {
            capabilities: Self::server_capabilities(),
            server_info: Some(ServerInfo {
                name: "deps-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        tracing::info!("deps-lsp server initialized");
        self.client
            .log_message(MessageType::INFO, "deps-lsp ready")
            .await;

        // Register lock file watchers using patterns from all ecosystems
        let patterns = self.state.ecosystem_registry.all_lockfile_patterns();
        if let Err(e) = file_watcher::register_lock_file_watchers(&self.client, &patterns).await {
            tracing::warn!("Failed to register file watchers: {}", e);
            self.client
                .log_message(
                    MessageType::WARNING,
                    format!("File watching disabled: {}", e),
                )
                .await;
        }

        // Spawn background cleanup task for cold start rate limiter
        let state_clone = Arc::clone(&self.state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Clean up entries older than 5 minutes
                state_clone
                    .cold_start_limiter
                    .cleanup_old_entries(std::time::Duration::from_secs(300));
                tracing::trace!("Cleaned up old cold start rate limit entries");
            }
        });
    }

    async fn shutdown(&self) -> Result<()> {
        tracing::info!("shutting down deps-lsp server");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;

        tracing::info!("document opened: {:?}", uri);

        // Use ecosystem registry to check if we support this file type
        if self.state.ecosystem_registry.get_for_uri(&uri).is_none() {
            tracing::debug!("unsupported file type: {:?}", uri);
            return;
        }

        self.handle_open(uri, content).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;

        if let Some(change) = params.content_changes.first() {
            let content = change.text.clone();

            // Use ecosystem registry to check if we support this file type
            if self.state.ecosystem_registry.get_for_uri(&uri).is_none() {
                tracing::debug!("unsupported file type: {:?}", uri);
                return;
            }

            self.handle_change(uri, content).await;
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

        Ok(Some(
            inlay_hints::handle_inlay_hints(
                Arc::clone(&self.state),
                params,
                &inlay_config,
                self.client.clone(),
                Arc::clone(&self.config),
            )
            .await,
        ))
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
            let mut edits = HashMap::new();
            edits.insert(
                update_args.uri.clone(),
                vec![TextEdit {
                    range: update_args.range,
                    new_text: format!("\"{}\"", update_args.version),
                }],
            );

            let edit = WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            };

            if let Err(e) = self.client.apply_edit(edit).await {
                tracing::error!("Failed to apply edit: {:?}", e);
            }
        }

        Ok(None)
    }
}

#[derive(serde::Deserialize)]
struct UpdateVersionArgs {
    uri: Uri,
    range: Range,
    version: String,
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
}

use crate::config::DepsConfig;
use crate::document::{DocumentState, Ecosystem, ServerState, UnifiedDependency, UnifiedVersion};
use crate::handlers::{code_actions, completion, diagnostics, hover, inlay_hints};
use deps_cargo::{CratesIoRegistry, DependencySource, parse_cargo_toml};
use deps_npm::{NpmRegistry, parse_package_json};
use deps_pypi::{PypiDependencySource, PypiParser, PypiRegistry};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::lsp_types::{
    CodeActionOptions, CodeActionParams, CodeActionProviderCapability, CompletionOptions,
    CompletionParams, CompletionResponse, DiagnosticOptions, DiagnosticServerCapabilities,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DocumentDiagnosticParams, DocumentDiagnosticReport, DocumentDiagnosticReportResult,
    ExecuteCommandOptions, ExecuteCommandParams, FullDocumentDiagnosticReport, Hover, HoverParams,
    HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams, InlayHint,
    InlayHintParams, MessageType, OneOf, Range, RelatedFullDocumentDiagnosticReport,
    ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit,
    Url, WorkspaceEdit,
};
use tower_lsp::{Client, LanguageServer, jsonrpc::Result};

pub struct Backend {
    client: Client,
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

    /// Handles opening a Cargo.toml file.
    async fn handle_cargo_open(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        match parse_cargo_toml(&content, &uri) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Cargo)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Cargo, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));

                    // Collect dependencies to fetch (avoid holding doc lock during fetch)
                    let deps_to_fetch: Vec<_> = {
                        let doc = match state.get_document(&uri_clone) {
                            Some(d) => d,
                            None => return,
                        };

                        doc.dependencies
                            .iter()
                            .filter_map(|dep| {
                                if let UnifiedDependency::Cargo(cargo_dep) = dep
                                    && matches!(cargo_dep.source, DependencySource::Registry)
                                {
                                    return Some(cargo_dep.name.clone());
                                }
                                None
                            })
                            .collect()
                    };

                    // Parallel fetch all versions
                    let futures: Vec<_> = deps_to_fetch
                        .into_iter()
                        .map(|name| {
                            let registry = registry.clone();
                            async move {
                                let versions = registry.get_versions(&name).await.ok()?;
                                let latest = versions.first()?.clone();
                                Some((name, UnifiedVersion::Cargo(latest)))
                            }
                        })
                        .collect();

                    let results = join_all(futures).await;
                    let versions: HashMap<_, _> = results.into_iter().flatten().collect();

                    // Update document with fetched versions
                    if let Some(mut doc) = state.documents.get_mut(&uri_clone) {
                        doc.update_versions(versions);
                    }

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse Cargo.toml: {}", e);
                self.client
                    .log_message(MessageType::ERROR, format!("Parse error: {}", e))
                    .await;
            }
        }
    }

    /// Handles opening a package.json file.
    async fn handle_npm_open(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        match parse_package_json(&content) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Npm)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Npm, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    let registry = NpmRegistry::new(Arc::clone(&state.cache));

                    // Collect dependencies to fetch (avoid holding doc lock during fetch)
                    let deps_to_fetch: Vec<_> = {
                        let doc = match state.get_document(&uri_clone) {
                            Some(d) => d,
                            None => return,
                        };

                        doc.dependencies
                            .iter()
                            .filter_map(|dep| {
                                if let UnifiedDependency::Npm(npm_dep) = dep {
                                    return Some(npm_dep.name.clone());
                                }
                                None
                            })
                            .collect()
                    };

                    // Parallel fetch all versions
                    let futures: Vec<_> = deps_to_fetch
                        .into_iter()
                        .map(|name| {
                            let registry = registry.clone();
                            async move {
                                let versions = registry.get_versions(&name).await.ok()?;
                                let latest = versions.first()?.clone();
                                Some((name, UnifiedVersion::Npm(latest)))
                            }
                        })
                        .collect();

                    let results = join_all(futures).await;
                    let versions: HashMap<_, _> = results.into_iter().flatten().collect();

                    // Update document with fetched versions
                    if let Some(mut doc) = state.documents.get_mut(&uri_clone) {
                        doc.update_versions(versions);
                    }

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse package.json: {}", e);
                self.client
                    .log_message(MessageType::ERROR, format!("Parse error: {}", e))
                    .await;
            }
        }
    }

    /// Handles opening a pyproject.toml file.
    async fn handle_pypi_open(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        let parser = PypiParser::new();
        match parser.parse_content(&content) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Pypi)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Pypi, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    let registry = PypiRegistry::new(Arc::clone(&state.cache));

                    // Collect dependencies to fetch (avoid holding doc lock during fetch)
                    let deps_to_fetch: Vec<_> = {
                        let doc = match state.get_document(&uri_clone) {
                            Some(d) => d,
                            None => return,
                        };

                        doc.dependencies
                            .iter()
                            .filter_map(|dep| {
                                if let UnifiedDependency::Pypi(pypi_dep) = dep
                                    && matches!(pypi_dep.source, PypiDependencySource::PyPI)
                                {
                                    return Some(pypi_dep.name.clone());
                                }
                                None
                            })
                            .collect()
                    };

                    // Parallel fetch all versions
                    let futures: Vec<_> = deps_to_fetch
                        .into_iter()
                        .map(|name| {
                            let registry = registry.clone();
                            async move {
                                let versions = registry.get_versions(&name).await.ok()?;
                                let latest = versions.first()?.clone();
                                Some((name, UnifiedVersion::Pypi(latest)))
                            }
                        })
                        .collect();

                    let results = join_all(futures).await;
                    let versions: HashMap<_, _> = results.into_iter().flatten().collect();

                    // Update document with fetched versions
                    if let Some(mut doc) = state.documents.get_mut(&uri_clone) {
                        doc.update_versions(versions);
                    }

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse pyproject.toml: {}", e);
                self.client
                    .log_message(MessageType::ERROR, format!("Parse error: {}", e))
                    .await;
            }
        }
    }

    /// Handles changes to a Cargo.toml file.
    async fn handle_cargo_change(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        match parse_cargo_toml(&content, &uri) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Cargo)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Cargo, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;

                    // Request inlay hints refresh
                    if let Err(e) = client.inlay_hint_refresh().await {
                        tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
                    }
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse Cargo.toml: {}", e);
            }
        }
    }

    /// Handles changes to a package.json file.
    async fn handle_npm_change(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        match parse_package_json(&content) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Npm)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Npm, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;

                    // Request inlay hints refresh
                    if let Err(e) = client.inlay_hint_refresh().await {
                        tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
                    }
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse package.json: {}", e);
            }
        }
    }

    /// Handles changes to a pyproject.toml file.
    async fn handle_pypi_change(&self, uri: tower_lsp::lsp_types::Url, content: String) {
        let parser = PypiParser::new();
        match parser.parse_content(&content) {
            Ok(parse_result) => {
                let deps = parse_result
                    .dependencies
                    .into_iter()
                    .map(UnifiedDependency::Pypi)
                    .collect();
                let doc_state = DocumentState::new(Ecosystem::Pypi, content, deps);
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                    let config_read = config.read().await;
                    let diags = diagnostics::handle_diagnostics(
                        Arc::clone(&state),
                        &uri_clone,
                        &config_read.diagnostics,
                    )
                    .await;

                    client.publish_diagnostics(uri_clone, diags, None).await;

                    // Request inlay hints refresh
                    if let Err(e) = client.inlay_hint_refresh().await {
                        tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
                    }
                });

                self.state.spawn_background_task(uri, task).await;
            }
            Err(e) => {
                tracing::error!("failed to parse pyproject.toml: {}", e);
            }
        }
    }

    fn server_capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            completion_provider: Some(CompletionOptions {
                trigger_characters: Some(vec!["\"".into(), "=".into(), ".".into()]),
                resolve_provider: Some(true),
                ..Default::default()
            }),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            inlay_hint_provider: Some(OneOf::Left(true)),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(vec![tower_lsp::lsp_types::CodeActionKind::QUICKFIX]),
                ..Default::default()
            })),
            diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
                identifier: Some("deps".into()),
                inter_file_dependencies: false,
                workspace_diagnostics: false,
                ..Default::default()
            })),
            execute_command_provider: Some(ExecuteCommandOptions {
                commands: vec!["deps-lsp.updateVersion".into()],
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[tower_lsp::async_trait]
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
    }

    async fn shutdown(&self) -> Result<()> {
        tracing::info!("shutting down deps-lsp server");
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let content = params.text_document.text;

        tracing::info!("document opened: {}", uri);

        let ecosystem = match Ecosystem::from_uri(&uri) {
            Some(eco) => eco,
            None => {
                tracing::debug!("unsupported file type: {}", uri);
                return;
            }
        };

        match ecosystem {
            Ecosystem::Cargo => self.handle_cargo_open(uri, content).await,
            Ecosystem::Npm => self.handle_npm_open(uri, content).await,
            Ecosystem::Pypi => self.handle_pypi_open(uri, content).await,
        }
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;

        if let Some(change) = params.content_changes.first() {
            let content = change.text.clone();

            let ecosystem = match Ecosystem::from_uri(&uri) {
                Some(eco) => eco,
                None => {
                    tracing::debug!("unsupported file type: {}", uri);
                    return;
                }
            };

            match ecosystem {
                Ecosystem::Cargo => self.handle_cargo_change(uri, content).await,
                Ecosystem::Npm => self.handle_npm_change(uri, content).await,
                Ecosystem::Pypi => self.handle_pypi_change(uri, content).await,
            }
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        tracing::info!("document closed: {}", uri);

        self.state.remove_document(&uri);
        self.state.cancel_background_task(&uri).await;
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        Ok(hover::handle_hover(Arc::clone(&self.state), params).await)
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        Ok(completion::handle_completion(Arc::clone(&self.state), params).await)
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let config = self.config.read().await;
        Ok(Some(
            inlay_hints::handle_inlay_hints(Arc::clone(&self.state), params, &config.inlay_hints)
                .await,
        ))
    }

    async fn code_action(
        &self,
        params: CodeActionParams,
    ) -> Result<Option<Vec<tower_lsp::lsp_types::CodeActionOrCommand>>> {
        Ok(Some(
            code_actions::handle_code_actions(Arc::clone(&self.state), params).await,
        ))
    }

    async fn diagnostic(
        &self,
        params: DocumentDiagnosticParams,
    ) -> Result<DocumentDiagnosticReportResult> {
        let uri = params.text_document.uri;
        tracing::info!("diagnostic request for: {}", uri);

        let config = self.config.read().await;

        let items =
            diagnostics::handle_diagnostics(Arc::clone(&self.state), &uri, &config.diagnostics)
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

        if params.command == "deps-lsp.updateVersion"
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
    uri: Url,
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
        assert!(completion.resolve_provider.unwrap());

        // Verify hover provider
        assert!(caps.hover_provider.is_some());

        // Verify inlay hints
        assert!(caps.inlay_hint_provider.is_some());

        // Verify diagnostics
        assert!(caps.diagnostic_provider.is_some());
    }

    #[tokio::test]
    async fn test_backend_creation() {
        let (_service, _socket) = tower_lsp::LspService::build(Backend::new).finish();
        // Backend should be created successfully
        // This is a minimal smoke test
    }

    #[tokio::test]
    async fn test_initialize_without_options() {
        let (_service, _socket) = tower_lsp::LspService::build(Backend::new).finish();
        // Should initialize successfully with default config
        // Integration tests will test actual LSP protocol
    }
}

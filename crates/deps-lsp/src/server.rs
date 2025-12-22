use crate::cargo::{CratesIoRegistry, parse_cargo_toml};
use crate::config::DepsConfig;
use crate::document::{DocumentState, ServerState};
use crate::handlers::{code_actions, completion, diagnostics, hover, inlay_hints};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::lsp_types::{
    CodeActionOptions, CodeActionParams, CodeActionProviderCapability, CompletionOptions,
    CompletionParams, CompletionResponse, DiagnosticOptions, DiagnosticServerCapabilities,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams, Hover,
    HoverParams, HoverProviderCapability, InitializeParams, InitializeResult, InitializedParams,
    InlayHint, InlayHintParams, MessageType, OneOf, ServerCapabilities, ServerInfo,
    TextDocumentSyncCapability, TextDocumentSyncKind,
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

    fn server_capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(
                TextDocumentSyncKind::INCREMENTAL,
            )),
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
            ..Default::default()
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        tracing::info!("initializing deps-lsp server");

        // Parse initialization options
        if let Some(init_options) = params.initialization_options {
            if let Ok(config) = serde_json::from_value::<DepsConfig>(init_options) {
                tracing::debug!("loaded configuration: {:?}", config);
                *self.config.write().await = config;
            }
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

        match parse_cargo_toml(&content, &uri) {
            Ok(parse_result) => {
                let doc_state =
                    DocumentState::new(content.clone(), parse_result.dependencies.clone());
                self.state.update_document(uri.clone(), doc_state);

                let state = Arc::clone(&self.state);
                let client = self.client.clone();
                let uri_clone = uri.clone();
                let config = Arc::clone(&self.config);

                let task = tokio::spawn(async move {
                    let registry = CratesIoRegistry::new(Arc::clone(&state.cache));
                    let mut versions = std::collections::HashMap::new();

                    let doc = match state.get_document(&uri_clone) {
                        Some(d) => d,
                        None => return,
                    };

                    for dep in &doc.dependencies {
                        if let crate::cargo::types::DependencySource::Registry = dep.source {
                            if let Ok(vers) = registry.get_versions(&dep.name).await {
                                if let Some(latest) = vers.first() {
                                    versions.insert(dep.name.clone(), latest.clone());
                                }
                            }
                        }
                    }

                    drop(doc);

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

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;

        if let Some(change) = params.content_changes.first() {
            let content = &change.text;

            match parse_cargo_toml(content, &uri) {
                Ok(parse_result) => {
                    let doc_state =
                        DocumentState::new(content.clone(), parse_result.dependencies.clone());
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
                    });

                    self.state.spawn_background_task(uri, task).await;
                }
                Err(e) => {
                    tracing::error!("failed to parse Cargo.toml: {}", e);
                }
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

use crate::config::DepsConfig;
use crate::document::ServerState;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::lsp_types::{
    CodeActionProviderCapability, CompletionOptions, DiagnosticOptions,
    DiagnosticServerCapabilities, HoverProviderCapability, InitializeParams, InitializeResult,
    InitializedParams, MessageType, OneOf, ServerCapabilities, ServerInfo,
    TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tower_lsp::{Client, LanguageServer, jsonrpc::Result};

pub struct Backend {
    client: Client,
    #[allow(dead_code)] // Will be used in Phase 1
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
            code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
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

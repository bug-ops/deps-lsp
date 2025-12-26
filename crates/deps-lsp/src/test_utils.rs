//! Test utilities for creating mock LSP clients and configs.

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::config::DepsConfig;
    use crate::server::Backend;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower_lsp_server::Client;

    /// Creates a test client and config for handler tests.
    ///
    /// Since handler tests pre-populate documents in state, the cold start
    /// logic is never triggered. These are just dummy values to satisfy
    /// the function signatures.
    pub fn create_test_client_and_config() -> (Client, Arc<RwLock<DepsConfig>>) {
        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let client = service.inner().client.clone();
        let config = Arc::new(RwLock::new(DepsConfig::default()));
        (client, config)
    }
}

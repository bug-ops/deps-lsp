use deps_lsp::server::Backend;
use std::fs::OpenOptions;
use tower_lsp::{LspService, Server};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Try to set up file-based logging for debugging
    let log_file = dirs::home_dir()
        .map(|h| h.join(".deps-lsp.log"))
        .and_then(|path| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
        });

    if let Some(file) = log_file {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);

    Server::new(stdin, stdout, socket).serve(service).await;
}

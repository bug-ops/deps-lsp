use deps_lsp::server::Backend;
use tower_lsp::{LspService, Server};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    // Initialize tracing with environment filter
    // Write to stderr to avoid interfering with JSON-RPC on stdout
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("starting deps-lsp server");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);

    Server::new(stdin, stdout, socket).serve(service).await;

    tracing::info!("deps-lsp server stopped");
}

use deps_lsp::server::Backend;
use std::env;
use tower_lsp::{LspService, Server};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    eprintln!("deps-lsp {VERSION} - Language Server for dependency management");
    eprintln!();
    eprintln!("Usage: deps-lsp [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --stdio     Use stdio transport (default)");
    eprintln!("  --version   Print version information");
    eprintln!("  --help      Print this help message");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    // Handle CLI flags
    for arg in &args {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("deps-lsp {VERSION}");
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--stdio" => {
                // Default mode, continue
            }
            arg if arg.starts_with('-') => {
                eprintln!("Unknown option: {arg}");
                eprintln!("Run 'deps-lsp --help' for usage information.");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    // Initialize tracing - write to stderr to avoid interfering with LSP on stdout
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting deps-lsp v{VERSION}");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);

    Server::new(stdin, stdout, socket).serve(service).await;
}

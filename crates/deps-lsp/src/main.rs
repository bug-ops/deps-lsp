use deps_lsp::server::Backend;
use std::env;
use tower_lsp_server::{LspService, Server};
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `tokio` worker thread stack size, matching the process main thread's
/// default (8 MiB on Linux/macOS) rather than `tokio`'s own 2 MiB default.
///
/// Background work — including lock file parsing via `toml_span::parse`,
/// which has no recursion limit of its own — runs on worker threads inside
/// `tokio::spawn`. `deps_core::check_toml_nesting_depth` is the primary
/// defense against a pathologically nested TOML document overflowing the
/// stack; matching the worker stack size to the main thread is
/// defense-in-depth on top of that guard, removing the thread-dependent
/// exposure asymmetry where identical content was safe on the 8 MiB main
/// thread but fatal on a 2 MiB worker.
const WORKER_THREAD_STACK_SIZE: usize = 8 * 1024 * 1024;

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

fn main() {
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

    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(WORKER_THREAD_STACK_SIZE)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(serve());
}

async fn serve() {
    // Initialize tracing - write to stderr to avoid interfering with LSP on stdout
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
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

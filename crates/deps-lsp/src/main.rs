//! Entry point for the `deps-lsp` binary: parses `--stdio`/`--version` flags,
//! sets up `tracing` logging, and serves [`Backend`] over stdin/stdout.

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
            "--stdio" => {}
            arg if arg.starts_with('-') => {
                eprintln!("Unknown option: {arg}");
                eprintln!("Run 'deps-lsp --help' for usage information.");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    // No fallback: startup failure before any LSP traffic is unrecoverable anyway.
    #[allow(clippy::expect_used)]
    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(WORKER_THREAD_STACK_SIZE)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(serve());
}

async fn serve() {
    // stderr, not stdout — stdout carries the LSP protocol stream.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .fmt_fields(sanitizing_field_format())
        .init();

    tracing::info!("Starting deps-lsp v{VERSION}");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);

    Server::new(stdin, stdout, socket).serve(service).await;
}

/// Sink-level defense-in-depth against CWE-117 log forging (#1505): every field value
/// (and the log message itself) is rendered via `Debug`, then swept for control/invisible
/// characters via [`deps_core::redact::sanitize_invisible`], before being written to the log
/// line — closing the class for every `tracing` call site, including third-party error
/// `Display` text this crate does not control, not just the ones fixed individually.
///
/// Skips `log.*` fields entirely (critic S1): `.init()` installs `tracing-log`'s `LogTracer`
/// bridge for the `log` crate's own events (e.g. from `reqwest`), which attaches metadata
/// fields (`log.file`, `log.line`, `log.module_path`, `log.target`) that the default
/// formatter hides but a custom one must hide explicitly, or every bridged event grows a
/// `log.file="/abs/path/to/.cargo/registry/..."` suffix leaking the build machine's path.
///
/// Exercised by this module's own `tests` module (critic S2) rather than
/// `deps_core::test_util::capture_tracing_output_at`, which installs its own formatter and so
/// can't observe this one.
fn sanitizing_field_format()
-> impl for<'writer> tracing_subscriber::fmt::FormatFields<'writer> + 'static {
    use tracing_subscriber::field::MakeExt;

    tracing_subscriber::fmt::format::debug_fn(|writer, field, value| {
        if field.name().starts_with("log.") {
            return Ok(());
        }
        let rendered = format!("{value:?}");
        let sanitized = deps_core::redact::sanitize_invisible(&rendered);
        if field.name() == "message" {
            write!(writer, "{sanitized}")
        } else {
            write!(writer, "{}={sanitized}", field.name())
        }
    })
    .delimited(" ")
}

#[cfg(test)]
mod tests {
    use super::sanitizing_field_format;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for BufWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Installs a scoped subscriber using the real `sanitizing_field_format()`, runs `f`, and
    /// returns everything written to its buffer as a `String`.
    fn capture(f: impl FnOnce()) -> String {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufWriter(Arc::clone(&buf)))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_level(false)
            .fmt_fields(sanitizing_field_format())
            .finish();

        let guard = tracing::subscriber::set_default(subscriber);
        f();
        drop(guard);

        let captured = buf.lock().unwrap().clone();
        String::from_utf8(captured).expect("log output is valid utf8")
    }

    /// #1505: a `%`-sigil field and the message text itself must both be swept of
    /// control/invisible characters (`\n`, `\r`, ESC, U+2028), collapsing to a single line.
    #[test]
    fn sanitizes_percent_field_and_message_control_chars() {
        let payload = "evil\r\x1b[31mred\u{2028}line";

        let log = capture(|| {
            tracing::warn!(field = %payload, "message with \nnewline");
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted field/message must not forge an extra log line: {log:?}"
        );
        assert!(!log.contains('\r'), "raw CR must not survive: {log:?}");
        assert!(!log.contains('\x1b'), "raw ESC must not survive: {log:?}");
        assert!(
            !log.contains('\u{2028}'),
            "raw line separator must not survive: {log:?}"
        );
    }

    /// #1505 critic S1 regression: `tracing-log`'s `LogTracer` bridge (installed by `.init()`
    /// in `serve()`) attaches `log.*` metadata fields to every `log`-crate event. These must
    /// be skipped entirely, not merely sanitized, or every bridged event (e.g. from
    /// `reqwest`) leaks the build machine's absolute source path via `log.file`.
    #[test]
    fn skips_log_crate_bridge_fields() {
        let log = capture(|| {
            tracing::warn!(
                log.file = "/home/builder/.cargo/registry/src/foo/connect.rs",
                log.line = 929,
                log.module_path = "reqwest::connect",
                log.target = "reqwest::connect",
                "bridged log-crate event"
            );
        });

        assert!(
            !log.contains("log.file"),
            "log.* bridge fields must be skipped, not rendered: {log:?}"
        );
        assert!(
            !log.contains(".cargo/registry"),
            "the build machine's absolute path must not leak: {log:?}"
        );
        assert!(
            log.contains("bridged log-crate event"),
            "the event's own message must still render: {log:?}"
        );
    }

    /// #1505: a span's own fields are rendered through the same `FormatFields` when the span
    /// context is printed alongside an event inside it, so they must be sanitized too.
    #[test]
    fn sanitizes_span_field_control_chars() {
        let log = capture(|| {
            let span = tracing::info_span!("crafted-span", value = %"evil\nvalue");
            let _enter = span.enter();
            tracing::warn!("event inside span");
        });

        assert_eq!(
            log.lines().count(),
            1,
            "a crafted span field must not forge an extra log line: {log:?}"
        );
    }
}

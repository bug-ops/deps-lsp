//! LSP handler performance benchmarks.
//!
//! Benchmarks end-to-end LSP handler performance to verify latency targets:
//! - Completion: < 50ms (max 200ms)
//! - Inlay hints: < 100ms (max 500ms)
//! - Hover: < 100ms (max 300ms)
//! - Diagnostics: < 500ms (max 2s)
//!
//! These benchmarks test user-facing performance - the most critical bottleneck.

use criterion::{Criterion, criterion_group, criterion_main};
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{DocumentState, ServerState};
use deps_lsp::handlers::{completion, hover, inlay_hints};
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::{
    CompletionParams, HoverParams, InlayHintParams, Position, TextDocumentIdentifier,
    TextDocumentPositionParams, Uri,
};

/// Small Cargo.toml fixture (5 dependencies).
const SMALL_CARGO: &str = include_str!("fixtures/small_cargo.toml");

/// Medium Cargo.toml fixture (25 dependencies).
const MEDIUM_CARGO: &str = include_str!("fixtures/medium_cargo.toml");

/// Generate large Cargo.toml with specified number of dependencies.
fn generate_large_cargo(num_deps: usize) -> String {
    let mut content = String::from(
        "[package]\nname = \"large-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    );

    for i in 0..num_deps {
        content.push_str(&format!("dep{} = \"1.{}.0\"\n", i, i % 20));
    }

    content
}

/// Create dummy client for benchmarks.
///
/// Since we're benchmarking handler logic that doesn't actually use the client
/// for network operations, we create a minimal dummy implementation.
fn create_dummy_client() -> Client {
    use deps_lsp::server::Backend;
    use tower_lsp_server::LspService;

    let (service, _socket) = LspService::build(Backend::new).finish();
    service.inner().client().clone()
}

/// Create test configuration.
fn create_test_config() -> Arc<RwLock<DepsConfig>> {
    Arc::new(RwLock::new(DepsConfig::default()))
}

/// Setup document state for benchmarks.
async fn setup_document(state: &ServerState, uri: &Uri, content: &str) {
    let ecosystem = state
        .ecosystem_registry
        .get("cargo")
        .expect("Cargo ecosystem not found");

    let parse_result = ecosystem
        .parse_manifest(content, uri)
        .await
        .expect("Parse failed");

    let doc_state =
        DocumentState::new_from_parse_result("cargo", content.to_string(), parse_result);
    state.update_document(uri.clone(), doc_state);
}

/// Benchmark completion handler end-to-end latency.
///
/// Target: < 50ms (max 200ms)
///
/// Tests completion performance for package name completion, which requires:
/// 1. Document lookup
/// 2. Parse result access
/// 3. Ecosystem delegation
/// 4. Potential registry search
fn bench_completion_handler(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("completion_handler");

    let state = Arc::new(ServerState::new());
    let client = create_dummy_client();
    let config = create_test_config();

    // Setup: Pre-load document with small manifest
    let uri = Uri::from_file_path("/bench/Cargo.toml").unwrap();
    rt.block_on(setup_document(&state, &uri, SMALL_CARGO));

    group.bench_function("small_manifest_5_deps", |b| {
        b.iter(|| {
            rt.block_on(async {
                let params = CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri: uri.clone() },
                        position: Position::new(6, 0),
                    },
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                    context: None,
                };

                completion::handle_completion(
                    black_box(Arc::clone(&state)),
                    black_box(params),
                    client.clone(),
                    Arc::clone(&config),
                )
                .await
            })
        });
    });

    // Setup: Pre-load document with medium manifest
    let uri_medium = Uri::from_file_path("/bench/medium/Cargo.toml").unwrap();
    rt.block_on(setup_document(&state, &uri_medium, MEDIUM_CARGO));

    group.bench_function("medium_manifest_25_deps", |b| {
        b.iter(|| {
            rt.block_on(async {
                let params = CompletionParams {
                    text_document_position: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier {
                            uri: uri_medium.clone(),
                        },
                        position: Position::new(21, 0),
                    },
                    work_done_progress_params: Default::default(),
                    partial_result_params: Default::default(),
                    context: None,
                };

                completion::handle_completion(
                    black_box(Arc::clone(&state)),
                    black_box(params),
                    client.clone(),
                    Arc::clone(&config),
                )
                .await
            })
        });
    });

    group.finish();
}

/// Benchmark inlay hints handler end-to-end latency.
///
/// Target: < 100ms (max 500ms)
///
/// Tests inlay hint generation which requires:
/// 1. Document lookup
/// 2. Parse result access
/// 3. Ecosystem delegation
/// 4. Version comparison for each dependency
fn bench_inlay_hints_handler(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("inlay_hints_handler");

    let state = Arc::new(ServerState::new());
    let client = create_dummy_client();
    let config_arc = create_test_config();

    let sizes = [
        ("small_5_deps", SMALL_CARGO, "/bench/small/Cargo.toml"),
        ("medium_25_deps", MEDIUM_CARGO, "/bench/medium/Cargo.toml"),
    ];

    for (name, content, path) in sizes {
        let uri = Uri::from_file_path(path).unwrap();
        rt.block_on(setup_document(&state, &uri, content));

        let config = rt.block_on(async { config_arc.read().await.inlay_hints.clone() });

        group.bench_function(name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let params = InlayHintParams {
                        text_document: TextDocumentIdentifier { uri: uri.clone() },
                        range: tower_lsp_server::ls_types::Range::new(
                            Position::new(0, 0),
                            Position::new(100, 0),
                        ),
                        work_done_progress_params: Default::default(),
                    };

                    inlay_hints::handle_inlay_hints(
                        black_box(Arc::clone(&state)),
                        black_box(params),
                        &config,
                        client.clone(),
                        Arc::clone(&config_arc),
                    )
                    .await
                })
            });
        });
    }

    // Benchmark large manifest (100 deps)
    let large_content = generate_large_cargo(100);
    let uri_large = Uri::from_file_path("/bench/large/Cargo.toml").unwrap();
    rt.block_on(setup_document(&state, &uri_large, &large_content));

    let config = rt.block_on(async { config_arc.read().await.inlay_hints.clone() });

    group.bench_function("large_100_deps", |b| {
        b.iter(|| {
            rt.block_on(async {
                let params = InlayHintParams {
                    text_document: TextDocumentIdentifier {
                        uri: uri_large.clone(),
                    },
                    range: tower_lsp_server::ls_types::Range::new(
                        Position::new(0, 0),
                        Position::new(200, 0),
                    ),
                    work_done_progress_params: Default::default(),
                };

                inlay_hints::handle_inlay_hints(
                    black_box(Arc::clone(&state)),
                    black_box(params),
                    &config,
                    client.clone(),
                    Arc::clone(&config_arc),
                )
                .await
            })
        });
    });

    group.finish();
}

/// Benchmark hover handler end-to-end latency.
///
/// Target: < 100ms (max 300ms)
///
/// Tests hover response generation which requires:
/// 1. Document lookup
/// 2. Parse result access
/// 3. Position-based dependency lookup
/// 4. Ecosystem delegation
/// 5. Version info retrieval
fn bench_hover_handler(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hover_handler");

    let state = Arc::new(ServerState::new());
    let client = create_dummy_client();
    let config = create_test_config();

    let uri = Uri::from_file_path("/bench/hover/Cargo.toml").unwrap();
    rt.block_on(setup_document(&state, &uri, SMALL_CARGO));

    group.bench_function("hover_on_package_name", |b| {
        b.iter(|| {
            rt.block_on(async {
                let params = HoverParams {
                    text_document_position_params: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri: uri.clone() },
                        position: Position::new(6, 0),
                    },
                    work_done_progress_params: Default::default(),
                };

                hover::handle_hover(
                    black_box(Arc::clone(&state)),
                    black_box(params),
                    client.clone(),
                    Arc::clone(&config),
                )
                .await
            })
        });
    });

    group.bench_function("hover_on_version_string", |b| {
        b.iter(|| {
            rt.block_on(async {
                let params = HoverParams {
                    text_document_position_params: TextDocumentPositionParams {
                        text_document: TextDocumentIdentifier { uri: uri.clone() },
                        position: Position::new(6, 10),
                    },
                    work_done_progress_params: Default::default(),
                };

                hover::handle_hover(
                    black_box(Arc::clone(&state)),
                    black_box(params),
                    client.clone(),
                    Arc::clone(&config),
                )
                .await
            })
        });
    });

    group.finish();
}

/// Benchmark document state access patterns.
///
/// Tests concurrent document access to verify DashMap performance under load.
fn bench_document_state_access(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("document_state");

    let state = Arc::new(ServerState::new());

    // Pre-populate with 10 documents
    for i in 0..10 {
        let uri = Uri::from_file_path(format!("/bench/doc{i}/Cargo.toml")).unwrap();
        rt.block_on(setup_document(&state, &uri, SMALL_CARGO));
    }

    group.bench_function("single_document_read", |b| {
        let uri = Uri::from_file_path("/bench/doc0/Cargo.toml").unwrap();

        b.iter(|| {
            let _doc = state.get_document(black_box(&uri));
        });
    });

    group.bench_function("concurrent_reads_10_documents", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();

                for i in 0..10 {
                    let state = Arc::clone(&state);
                    let handle = tokio::spawn(async move {
                        let uri = Uri::from_file_path(format!("/bench/doc{i}/Cargo.toml")).unwrap();
                        let _doc = state.get_document(&uri);
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let _ = handle.await;
                }
            });
        });
    });

    group.finish();
}

/// Benchmark cold start document loading.
///
/// Tests document loading from disk when not in cache (cold start scenario).
fn bench_cold_start_loading(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("cold_start");

    let sizes = [
        ("small_5_deps", SMALL_CARGO),
        ("medium_25_deps", MEDIUM_CARGO),
    ];

    for (name, content) in sizes {
        group.bench_function(name, |b| {
            b.iter(|| {
                rt.block_on(async {
                    let state = ServerState::new();
                    let uri = Uri::from_file_path("/bench/cold/Cargo.toml").unwrap();

                    let ecosystem = state
                        .ecosystem_registry
                        .get("cargo")
                        .expect("Cargo ecosystem not found");

                    let parse_result = ecosystem
                        .parse_manifest(black_box(content), &uri)
                        .await
                        .expect("Parse failed");

                    let _doc_state = DocumentState::new_from_parse_result(
                        "cargo",
                        content.to_string(),
                        parse_result,
                    );
                });
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_completion_handler,
    bench_inlay_hints_handler,
    bench_hover_handler,
    bench_document_state_access,
    bench_cold_start_loading
);
criterion_main!(benches);

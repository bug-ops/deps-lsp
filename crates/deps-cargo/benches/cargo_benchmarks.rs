//! Benchmarks for Cargo.toml parsing and registry operations.
//!
//! Performance targets (based on LSP latency requirements):
//! - Parsing small files: < 1ms
//! - Parsing medium files (20-50 deps): < 5ms
//! - Parsing large files (100+ deps): < 20ms
//! - Registry JSON parsing: < 1ms per package
//! - Version matching: < 100μs per operation

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_cargo::parse_cargo_toml;
use std::hint::black_box;
use tower_lsp::lsp_types::Url;

/// Small Cargo.toml file with 5 dependencies.
const SMALL_CARGO_TOML: &str = r#"
[package]
name = "small-project"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
reqwest = "0.12"
thiserror = "2.0"
anyhow = "1.0"
"#;

/// Medium Cargo.toml file with 25 dependencies.
const MEDIUM_CARGO_TOML: &str = r#"
[package]
name = "medium-project"
version = "0.1.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["macros", "rt-multi-thread"] }
reqwest = { version = "0.12", features = ["json", "gzip"] }
thiserror = "2.0"
anyhow = "1.0"
tower-lsp = "0.20"
dashmap = "6.0"
async-trait = "0.1"
semver = "1.0"
toml_edit = "0.24"
tracing = "0.1"
tracing-subscriber = "0.3"
futures = "0.3"
regex = "1.0"
url = "2.0"
uuid = "1.0"
chrono = "0.4"
parking_lot = "0.12"
rayon = "1.0"

[dev-dependencies]
criterion = "0.8"
insta = "1.0"
mockito = "1.0"
tokio-test = "0.4"
proptest = "1.0"
"#;

/// Large Cargo.toml file with 100 dependencies.
fn generate_large_cargo_toml() -> String {
    let mut content = String::from(
        r#"[package]
name = "large-project"
version = "0.1.0"

[dependencies]
"#,
    );

    // Generate 100 dependencies
    for i in 0..100 {
        content.push_str(&format!("dep{} = \"1.{}.0\"\n", i, i % 20));
    }

    content
}

/// Very large Cargo.toml with workspace and multiple sections.
fn generate_workspace_cargo_toml() -> String {
    let mut content = String::from(
        r#"[workspace]
members = ["crates/*"]
resolver = "2"

[workspace.dependencies]
"#,
    );

    // 50 workspace dependencies
    for i in 0..50 {
        content.push_str(&format!("workspace-dep{} = \"1.{}.0\"\n", i, i % 20));
    }

    content.push_str("\n[dependencies]\n");

    // 50 direct dependencies
    for i in 0..50 {
        if i % 3 == 0 {
            content.push_str(&format!(
                "dep{} = {{ version = \"1.{}.0\", features = [\"default\", \"extra\"] }}\n",
                i,
                i % 20
            ));
        } else if i % 3 == 1 {
            content.push_str(&format!("dep{} = {{ workspace = true }}\n", i));
        } else {
            content.push_str(&format!("dep{} = \"1.{}.0\"\n", i, i % 20));
        }
    }

    content
}

/// Realistic crates.io sparse index response for a popular crate.
///
/// Based on actual serde index format (newline-delimited JSON).
const SPARSE_INDEX_RESPONSE: &str = r#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}
{"name":"serde","vers":"1.0.1","deps":[],"cksum":"def","features":{},"yanked":false}
{"name":"serde","vers":"1.0.100","deps":[],"cksum":"123","features":{"derive":["serde_derive"]},"yanked":false}
{"name":"serde","vers":"1.0.150","deps":[],"cksum":"456","features":{"derive":["serde_derive"],"std":[]},"yanked":false}
{"name":"serde","vers":"1.0.200","deps":[],"cksum":"789","features":{"derive":["serde_derive"],"std":[],"alloc":[]},"yanked":false}
{"name":"serde","vers":"1.0.210","deps":[],"cksum":"abc","features":{"derive":["serde_derive"],"std":[],"alloc":[]},"yanked":false}
{"name":"serde","vers":"1.0.214","deps":[],"cksum":"def","features":{"derive":["serde_derive"],"std":[],"alloc":[],"rc":[]},"yanked":false}
"#;

fn test_url() -> Url {
    #[cfg(windows)]
    let url = "file:///C:/test/Cargo.toml";
    #[cfg(not(windows))]
    let url = "file:///test/Cargo.toml";
    Url::parse(url).unwrap()
}

/// Benchmark Cargo.toml parsing with different file sizes.
///
/// Measures parsing time including position tracking for LSP operations.
fn bench_cargo_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("cargo_parsing");

    group.bench_function("small_5_deps", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(SMALL_CARGO_TOML), black_box(&url)))
    });

    group.bench_function("medium_25_deps", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(MEDIUM_CARGO_TOML), black_box(&url)))
    });

    let large_toml = generate_large_cargo_toml();
    group.bench_function("large_100_deps", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(&large_toml), black_box(&url)))
    });

    let workspace_toml = generate_workspace_cargo_toml();
    group.bench_function("workspace_100_deps", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(&workspace_toml), black_box(&url)))
    });

    group.finish();
}

/// Benchmark position tracking overhead.
///
/// Measures the cost of calculating LSP positions for each dependency field.
fn bench_position_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("position_tracking");

    // Simple inline dependency
    let inline = r#"
[dependencies]
serde = "1.0"
"#;

    // Complex table dependency
    let table = r#"
[dependencies]
serde = { version = "1.0", features = ["derive", "std"], default-features = false }
"#;

    group.bench_function("inline_dependency", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(inline), black_box(&url)))
    });

    group.bench_function("table_dependency", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(table), black_box(&url)))
    });

    group.finish();
}

/// Benchmark registry JSON parsing.
///
/// Measures sparse index response parsing time by parsing the response
/// through serde_json. The actual internal parsing function is private,
/// so we simulate the workload using direct serde_json parsing.
fn bench_registry_parsing(c: &mut Criterion) {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct IndexEntry {
        name: String,
        vers: String,
        deps: Vec<serde_json::Value>,
        cksum: String,
        features: serde_json::Value,
        yanked: bool,
    }

    let mut group = c.benchmark_group("registry_parsing");

    group.bench_function("sparse_index_7_versions", |b| {
        b.iter(|| {
            let _versions: Vec<IndexEntry> = black_box(SPARSE_INDEX_RESPONSE)
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
        })
    });

    // Generate large sparse index response (100 versions)
    let mut large_index = String::new();
    for i in 0..100 {
        large_index.push_str(&format!(
            r#"{{"name":"crate","vers":"1.0.{}","deps":[],"cksum":"abc{}","features":{{}},"yanked":false}}"#,
            i, i
        ));
        large_index.push('\n');
    }

    group.bench_function("sparse_index_100_versions", |b| {
        b.iter(|| {
            let _versions: Vec<IndexEntry> = black_box(&large_index)
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
        })
    });

    group.finish();
}

/// Benchmark version matching operations.
///
/// Critical for inlay hints - needs to be fast as it runs on every hint.
fn bench_version_matching(c: &mut Criterion) {
    use semver::{Version, VersionReq};

    let mut group = c.benchmark_group("version_matching");

    let latest = Version::parse("1.0.214").unwrap();
    let versions = [
        Version::parse("1.0.0").unwrap(),
        Version::parse("1.0.100").unwrap(),
        Version::parse("1.0.150").unwrap(),
        Version::parse("1.0.200").unwrap(),
        Version::parse("1.0.214").unwrap(),
    ];

    // Simple version requirement
    let simple_req = VersionReq::parse("1.0").unwrap();
    group.bench_function("simple_version_req", |b| {
        b.iter(|| simple_req.matches(black_box(&latest)))
    });

    // Complex version requirement
    let complex_req = VersionReq::parse(">=1.0.100, <2.0, !=1.0.150").unwrap();
    group.bench_function("complex_version_req", |b| {
        b.iter(|| complex_req.matches(black_box(&latest)))
    });

    // Find latest matching version
    group.bench_function("find_latest_matching", |b| {
        b.iter(|| {
            versions
                .iter()
                .filter(|v| simple_req.matches(v))
                .max()
                .cloned()
        })
    });

    group.finish();
}

/// Benchmark different dependency formats.
///
/// Tests parsing performance for various Cargo.toml syntax patterns.
fn bench_dependency_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("dependency_formats");

    let formats = [
        (
            "inline_string",
            r#"[dependencies]
serde = "1.0""#,
        ),
        (
            "inline_table",
            r#"[dependencies]
serde = { version = "1.0" }"#,
        ),
        (
            "inline_table_features",
            r#"[dependencies]
serde = { version = "1.0", features = ["derive"] }"#,
        ),
        (
            "workspace_inheritance",
            r#"[dependencies]
serde = { workspace = true }"#,
        ),
        (
            "git_dependency",
            r#"[dependencies]
tower-lsp = { git = "https://github.com/ebkalderon/tower-lsp" }"#,
        ),
        (
            "path_dependency",
            r#"[dependencies]
local = { path = "../local" }"#,
        ),
        (
            "full_table",
            r#"
[dependencies.serde]
version = "1.0"
features = ["derive", "std"]
default-features = false"#,
        ),
    ];

    for (name, content) in formats {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            let url = test_url();
            b.iter(|| parse_cargo_toml(black_box(content), black_box(&url)))
        });
    }

    group.finish();
}

/// Benchmark parsing with Unicode content.
///
/// Ensures position tracking works correctly with multi-byte characters.
fn bench_unicode_parsing(c: &mut Criterion) {
    let unicode_toml = r#"
[package]
name = "unicode-project"
# Comment with Unicode: 日本語 🦀 Émojis

[dependencies]
serde = "1.0"  # Dependency with 中文 comment
tokio = "1.0"  # Зависимость с кириллицей
"#;

    c.bench_function("unicode_parsing", |b| {
        let url = test_url();
        b.iter(|| parse_cargo_toml(black_box(unicode_toml), black_box(&url)))
    });
}

criterion_group!(
    benches,
    bench_cargo_parsing,
    bench_position_tracking,
    bench_registry_parsing,
    bench_version_matching,
    bench_dependency_formats,
    bench_unicode_parsing
);
criterion_main!(benches);

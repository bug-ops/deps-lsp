//! Benchmarks for `pubspec.yaml` parsing scaling behavior.
//!
//! These replace the wall-clock-ratio assertions formerly embedded as unit tests in
//! `src/parser.rs` (flaky under CI scheduling contention — see #946). Scaling behavior here is
//! observed, not gated: CI only builds this crate (`cargo build --workspace --benches`), it
//! never runs the benchmarks or asserts on their output, and criterion's baseline comparison is
//! machine-local (`target/criterion`, wiped by `cargo clean`) — a regression is only surfaced
//! when a developer runs `cargo bench -p deps-dart` before and after a change on the same
//! machine. Nothing prompts that automatically.

#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use deps_dart::parse_pubspec_yaml;
use std::hint::black_box;
use url::Url;

fn test_uri() -> Url {
    #[cfg(windows)]
    let path = "C:/test/pubspec.yaml";
    #[cfg(not(windows))]
    let path = "/test/pubspec.yaml";
    Url::from_file_path(path).unwrap()
}

/// Builds a `pubspec.yaml` with `n` simple `dependencies` entries, for scaling benchmarks.
fn many_dependencies_yaml(n: usize) -> String {
    let mut yaml = String::from("name: my_app\ndependencies:\n");
    for i in 0..n {
        yaml.push_str(&format!("  dep_{i:05}: ^1.{i}.0\n"));
    }
    yaml
}

/// Builds a `pubspec.yaml` with `n` quoted-key `dependencies` entries.
fn many_quoted_dependencies_yaml(n: usize) -> String {
    let mut yaml = String::from("name: my_app\ndependencies:\n");
    for i in 0..n {
        yaml.push_str(&format!("  \"dep_{i:05}\": ^1.{i}.0\n"));
    }
    yaml
}

/// Builds a document with `depth` levels of nested, mutually-unrelated anchored mappings
/// (`a0: &a0\n  a1: &a1\n    ...`), each concurrently open while the innermost `inner_lines`
/// filler fields stream past, followed by a real `dependencies:` section.
fn nested_anchors_then_dependencies_yaml(depth: usize, inner_lines: usize) -> String {
    let mut yaml = String::from("padding:\n");
    for i in 0..depth {
        yaml.push_str(&"  ".repeat(i + 1));
        yaml.push_str(&format!("a{i}: &a{i}\n"));
    }
    let indent = "  ".repeat(depth + 1);
    for i in 0..inner_lines {
        yaml.push_str(&indent);
        yaml.push_str(&format!("field_{i:04}: value_{i:04}\n"));
    }
    yaml.push_str("dependencies:\n  http: ^1.0.0\n");
    yaml
}

/// Benchmark parse time as the number of concurrently-open (nested) anchors grows.
///
/// Recording is meant to be O(1) per event regardless of anchor nesting depth (see
/// `RecordingFrame`'s docs) — this should stay roughly flat between `depth=2` and `depth=40`.
fn bench_anchor_nesting(c: &mut Criterion) {
    const INNER_LINES: usize = 2000;

    let mut group = c.benchmark_group("anchor_nesting");
    for depth in [2, 40] {
        let yaml = nested_anchors_then_dependencies_yaml(depth, INNER_LINES);
        group.bench_with_input(BenchmarkId::from_parameter(depth), &yaml, |b, yaml| {
            let url = test_uri();
            b.iter(|| parse_pubspec_yaml(black_box(yaml), black_box(&url)));
        });
    }
    group.finish();
}

/// Benchmark parse time as the number of plain-key dependencies grows.
///
/// Dependency position lookup is meant to be O(1) per dependency, so cost should scale
/// linearly with `n`, not quadratically.
fn bench_many_dependencies_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("many_dependencies");
    for n in [1250, 2500, 5000] {
        let yaml = many_dependencies_yaml(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &yaml, |b, yaml| {
            let url = test_uri();
            b.iter(|| parse_pubspec_yaml(black_box(yaml), black_box(&url)));
        });
    }
    group.finish();
}

/// Benchmark parse time as the number of quoted-key dependencies grows.
///
/// Quoted keys (`"dep": ^1.0.0`) previously defeated an intermediate cursor-based fix's
/// line-start text check, reproducing near-quadratic scaling; the marker-based rewrite does
/// not distinguish quoted from plain keys.
fn bench_quoted_keys_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("quoted_keys");
    for n in [1250, 2500, 5000] {
        let yaml = many_quoted_dependencies_yaml(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &yaml, |b, yaml| {
            let url = test_uri();
            b.iter(|| parse_pubspec_yaml(black_box(yaml), black_box(&url)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_anchor_nesting,
    bench_many_dependencies_scaling,
    bench_quoted_keys_scaling
);
criterion_main!(benches);

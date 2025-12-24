//! Benchmarks for deps-core: HTTP caching and shared utilities.
//!
//! Performance targets:
//! - Cache lookup: < 10μs (hot path)
//! - Cache insert: < 50μs
//! - Cache eviction: < 1ms
//! - Arc cloning (for response bodies): < 10ns

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use deps_core::cache::{CachedResponse, HttpCache};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

/// Benchmark cache lookup operations.
///
/// Cache lookups are in the hot path for every LSP request.
fn bench_cache_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_lookup");

    let cache = HttpCache::new();
    let url = "https://index.crates.io/se/rd/serde";

    // Pre-populate cache
    let response = CachedResponse {
        body: Bytes::from_static(&[1, 2, 3, 4, 5]),
        etag: Some("\"abc123\"".into()),
        last_modified: None,
        fetched_at: Instant::now(),
    };

    cache.insert_for_bench(url.to_string(), response);

    group.bench_function("cache_hit", |b| {
        b.iter(|| cache.get_for_bench(black_box(url)))
    });

    group.bench_function("cache_miss", |b| {
        b.iter(|| cache.get_for_bench(black_box("https://nonexistent.url")))
    });

    group.finish();
}

/// Benchmark cache insert operations.
fn bench_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert");

    let response_small = CachedResponse {
        body: Bytes::from(vec![0u8; 100]),
        etag: Some("\"small\"".into()),
        last_modified: None,
        fetched_at: Instant::now(),
    };

    let response_medium = CachedResponse {
        body: Bytes::from(vec![0u8; 10_000]),
        etag: Some("\"medium\"".into()),
        last_modified: Some("Thu, 01 Jan 2024 00:00:00 GMT".into()),
        fetched_at: Instant::now(),
    };

    let response_large = CachedResponse {
        body: Bytes::from(vec![0u8; 1_000_000]),
        etag: Some("\"large\"".into()),
        last_modified: None,
        fetched_at: Instant::now(),
    };

    group.bench_function("insert_small_100B", |b| {
        let cache = HttpCache::new();
        let mut i = 0;
        b.iter(|| {
            cache.insert_for_bench(format!("https://url-{}", i), response_small.clone());
            i += 1;
        })
    });

    group.bench_function("insert_medium_10KB", |b| {
        let cache = HttpCache::new();
        let mut i = 0;
        b.iter(|| {
            cache.insert_for_bench(format!("https://url-{}", i), response_medium.clone());
            i += 1;
        })
    });

    group.bench_function("insert_large_1MB", |b| {
        let cache = HttpCache::new();
        let mut i = 0;
        b.iter(|| {
            cache.insert_for_bench(format!("https://url-{}", i), response_large.clone());
            i += 1;
        })
    });

    group.finish();
}

/// Benchmark Arc cloning for cached response bodies.
///
/// Critical for understanding zero-cost sharing of cached data.
fn bench_arc_cloning(c: &mut Criterion) {
    let mut group = c.benchmark_group("arc_cloning");

    let small_data = Arc::new(vec![0u8; 100]);
    let large_data = Arc::new(vec![0u8; 1_000_000]);

    group.bench_function("clone_small_100B", |b| {
        b.iter(|| Arc::clone(black_box(&small_data)))
    });

    group.bench_function("clone_large_1MB", |b| {
        b.iter(|| Arc::clone(black_box(&large_data)))
    });

    // Compare with actual Vec cloning to show the benefit
    let small_vec = vec![0u8; 100];
    let large_vec = vec![0u8; 1_000_000];

    group.bench_function("vec_clone_small_100B", |b| {
        b.iter(|| black_box(&small_vec).clone())
    });

    group.bench_function("vec_clone_large_1MB", |b| {
        b.iter(|| black_box(&large_vec).clone())
    });

    group.finish();
}

/// Benchmark concurrent cache access with DashMap.
///
/// Tests cache performance under concurrent LSP requests.
fn bench_concurrent_access(c: &mut Criterion) {
    use std::sync::Arc as StdArc;
    use tokio::runtime::Runtime;

    let mut group = c.benchmark_group("concurrent_access");

    let rt = Runtime::new().unwrap();

    // Pre-populate cache with 100 entries
    let cache = StdArc::new(HttpCache::new());
    for i in 0..100 {
        let response = CachedResponse {
            body: Bytes::from(vec![i as u8; 100]),
            etag: Some(format!("\"etag-{}\"", i)),
            last_modified: None,
            fetched_at: Instant::now(),
        };
        cache.insert_for_bench(format!("https://url-{}", i), response);
    }

    group.bench_function("concurrent_reads_10_tasks", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();

                for i in 0..10 {
                    let cache_clone = StdArc::clone(&cache);
                    let handle = tokio::spawn(async move {
                        cache_clone.get_for_bench(&format!("https://url-{}", i % 100))
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let _ = handle.await;
                }
            })
        })
    });

    group.finish();
}

/// Benchmark cache eviction when capacity is reached.
fn bench_cache_eviction(c: &mut Criterion) {
    let cache = HttpCache::new();

    // Pre-populate to near capacity (MAX_CACHE_ENTRIES = 1000)
    for i in 0..990 {
        let response = CachedResponse {
            body: Bytes::from(vec![i as u8; 100]),
            etag: Some(format!("\"etag-{}\"", i)),
            last_modified: None,
            fetched_at: Instant::now(),
        };
        cache.insert_for_bench(format!("https://url-{}", i), response);
    }

    c.bench_function("cache_eviction_trigger", |b| {
        let mut i = 990;
        b.iter(|| {
            let response = CachedResponse {
                body: Bytes::from(vec![i as u8; 100]),
                etag: Some(format!("\"etag-{}\"", i)),
                last_modified: None,
                fetched_at: Instant::now(),
            };
            cache.insert_for_bench(format!("https://url-{}", i), response);
            i += 1;
        })
    });
}

/// Benchmark string formatting for URLs.
///
/// Tests URL construction performance for registry requests.
fn bench_url_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_formatting");

    let package_name = "serde";

    // crates.io sparse index URL
    group.bench_function("crates_io_sparse_index", |b| {
        b.iter(|| {
            let path = format!(
                "{}/{}/{}",
                &package_name[0..2],
                &package_name[2..3],
                package_name
            );
            format!("https://index.crates.io/{}", path)
        })
    });

    // npm registry URL
    group.bench_function("npm_registry", |b| {
        b.iter(|| format!("https://registry.npmjs.org/{}", black_box(package_name)))
    });

    // PyPI simple API URL
    group.bench_function("pypi_simple_api", |b| {
        b.iter(|| format!("https://pypi.org/simple/{}/", black_box(package_name)))
    });

    // PyPI JSON API URL
    group.bench_function("pypi_json_api", |b| {
        b.iter(|| format!("https://pypi.org/pypi/{}/json", black_box(package_name)))
    });

    group.finish();
}

/// Benchmark JSON parsing for registry responses.
///
/// Tests serde_json performance with realistic registry data.
fn bench_json_parsing(c: &mut Criterion) {
    use serde_json::Value;

    let mut group = c.benchmark_group("json_parsing");

    let small_json = r#"{"name":"pkg","version":"1.0.0"}"#;

    let medium_json = r#"{
        "name": "express",
        "version": "4.18.2",
        "description": "Fast, unopinionated, minimalist web framework",
        "main": "index.js",
        "dependencies": {
            "accepts": "~1.3.8",
            "array-flatten": "1.1.1",
            "body-parser": "1.20.1",
            "content-disposition": "0.5.4",
            "cookie": "0.5.0"
        },
        "devDependencies": {
            "eslint": "^8.24.0",
            "mocha": "^10.0.0"
        }
    }"#;

    // Large JSON with 100 versions
    let mut large_json = String::from(r#"{"name":"pkg","versions":{"#);
    for i in 0..100 {
        large_json.push_str(&format!(
            r#""{}.0.0":{{"version":"{}.0.0","name":"pkg"}}{}"#,
            i,
            i,
            if i < 99 { "," } else { "" }
        ));
    }
    large_json.push_str("}}");

    group.bench_function("small_simple_object", |b| {
        b.iter(|| serde_json::from_str::<Value>(black_box(small_json)))
    });

    group.bench_function("medium_nested_object", |b| {
        b.iter(|| serde_json::from_str::<Value>(black_box(medium_json)))
    });

    group.bench_function("large_100_versions", |b| {
        b.iter(|| serde_json::from_str::<Value>(black_box(&large_json)))
    });

    group.finish();
}

/// Benchmark memory allocation patterns.
fn bench_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocations");

    // Pre-allocate Vec with capacity
    group.bench_function("vec_with_capacity", |b| {
        b.iter(|| {
            let mut v = Vec::with_capacity(100);
            for i in 0..100 {
                v.push(i);
            }
            v
        })
    });

    // Vec without capacity (multiple reallocations)
    group.bench_function("vec_without_capacity", |b| {
        b.iter(|| {
            let mut v = Vec::new();
            for i in 0..100 {
                v.push(i);
            }
            v
        })
    });

    // String with capacity
    group.bench_function("string_with_capacity", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(1000);
            for i in 0..100 {
                s.push_str(&format!("item-{}", i));
            }
            s
        })
    });

    // String without capacity
    group.bench_function("string_without_capacity", |b| {
        b.iter(|| {
            let mut s = String::new();
            for i in 0..100 {
                s.push_str(&format!("item-{}", i));
            }
            s
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cache_lookup,
    bench_cache_insert,
    bench_arc_cloning,
    bench_concurrent_access,
    bench_cache_eviction,
    bench_url_formatting,
    bench_json_parsing,
    bench_allocations
);
criterion_main!(benches);

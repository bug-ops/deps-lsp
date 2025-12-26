//! Benchmarks for go.mod parsing and Go registry operations.
//!
//! Performance targets (based on LSP latency requirements):
//! - Parsing small files: < 1ms
//! - Parsing medium files (20-50 deps): < 5ms
//! - Parsing large files (100+ deps): < 20ms
//! - go.sum parsing: < 10ms for 100 entries
//! - Version comparison: < 10μs per operation
//! - Module path escaping: < 1μs per operation

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_go::lockfile::parse_go_sum;
use deps_go::parser::parse_go_mod;
use deps_go::{compare_versions, escape_module_path, is_pseudo_version};
use std::hint::black_box;
use tower_lsp_server::ls_types::Uri;

fn bench_uri() -> Uri {
    Uri::from_file_path("/bench/go.mod").unwrap()
}

/// Small go.mod file with 5 dependencies.
const SMALL_GO_MOD: &str = r"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.17.0
    github.com/stretchr/testify v1.8.4
    github.com/joho/godotenv v1.5.1
)
";

/// Medium go.mod file with 25 dependencies.
const MEDIUM_GO_MOD: &str = r"module example.com/medium-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
    golang.org/x/crypto v0.17.0
    github.com/stretchr/testify v1.8.4
    github.com/joho/godotenv v1.5.1
    github.com/go-redis/redis/v8 v8.11.5
    github.com/gorilla/mux v1.8.1
    github.com/gorilla/sessions v1.2.2
    github.com/dgrijalva/jwt-go v3.2.0+incompatible
    github.com/golang-migrate/migrate/v4 v4.17.0
    github.com/google/uuid v1.6.0
    github.com/pkg/errors v0.9.1
    golang.org/x/sync v0.5.0 // indirect
    golang.org/x/text v0.14.0 // indirect
    golang.org/x/sys v0.15.0 // indirect
    github.com/mattn/go-sqlite3 v1.14.19
    github.com/sirupsen/logrus v1.9.3
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.2
    gopkg.in/yaml.v3 v3.0.1
)

require (
    github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
    github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
    golang.org/x/net v0.19.0 // indirect
    golang.org/x/time v0.5.0 // indirect
    google.golang.org/protobuf v1.32.0 // indirect
)
";

/// Large go.mod file with 100+ dependencies.
fn generate_large_go_mod() -> String {
    let mut content = String::from(
        r"module example.com/large-app

go 1.21

require (
",
    );

    // Generate 100 dependencies
    for i in 0..100 {
        let version = format!("v{}.{}.{}", i % 10, (i % 20) + 1, (i % 5));
        content.push_str(&format!(
            "    github.com/pkg/package-{} {}{}\n",
            i,
            version,
            if i % 3 == 0 { " // indirect" } else { "" }
        ));
    }

    content.push_str(")\n");
    content
}

/// Complex go.mod with all directive types.
const COMPLEX_GO_MOD: &str = r"module example.com/complex-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
    golang.org/x/tools v0.0.0-20191109021931-daa7c04131f5 // pseudo-version
)

replace (
    github.com/old/module => github.com/new/module v1.2.3
    github.com/another/old v1.0.0 => github.com/another/new v2.0.0
    golang.org/x/net => golang.org/x/net v0.1.0
)

exclude (
    github.com/bad/package v0.1.0
    github.com/vulnerable/lib v2.0.0+incompatible
)

retract v1.0.0
";

/// Benchmark go.mod parsing with different file sizes.
fn bench_go_mod_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("go_mod_parsing");
    let uri = bench_uri();

    group.bench_function("small_5_deps", |b| {
        b.iter(|| parse_go_mod(black_box(SMALL_GO_MOD), &uri));
    });

    group.bench_function("medium_25_deps", |b| {
        b.iter(|| parse_go_mod(black_box(MEDIUM_GO_MOD), &uri));
    });

    let large_mod = generate_large_go_mod();
    group.bench_function("large_100_deps", |b| {
        b.iter(|| parse_go_mod(black_box(&large_mod), &uri));
    });

    group.bench_function("complex_all_directives", |b| {
        b.iter(|| parse_go_mod(black_box(COMPLEX_GO_MOD), &uri));
    });

    group.finish();
}

/// Benchmark position tracking for go.mod dependencies.
///
/// Critical for LSP features (hover, completion, inlay hints).
fn bench_position_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("position_tracking");
    let uri = bench_uri();

    // Single require line
    let single = "require github.com/gin-gonic/gin v1.9.1\n";

    // Require block
    let block = r"require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0 // indirect
)
";

    // Replace directive
    let replace = "replace github.com/old/module => github.com/new/module v1.2.3\n";

    group.bench_function("single_require", |b| {
        b.iter(|| parse_go_mod(black_box(single), &uri));
    });

    group.bench_function("require_block", |b| {
        b.iter(|| parse_go_mod(black_box(block), &uri));
    });

    group.bench_function("replace_directive", |b| {
        b.iter(|| parse_go_mod(black_box(replace), &uri));
    });

    group.finish();
}

/// Small go.sum with 5 packages.
const SMALL_GO_SUM: &str = r"github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL9t9/HBtKc7e/Q7Nb2nqKqTW8mHZy6E7k8m4dLvs=
github.com/lib/pq v1.10.9 h1:YXG7RB+JIjhP29X+OtkiDnYaXQwpS4JEWq7dtCCRUEw=
github.com/lib/pq v1.10.9/go.mod h1:AlVN5x4E4T544tWzH6hKfbfQvm3HdbOxrmggDNAPY9o=
golang.org/x/crypto v0.17.0 h1:r8bRNjWL3GshPW3gkd+RpvzWrZAwPS49OmTGZ/uhM4k=
golang.org/x/crypto v0.17.0/go.mod h1:gCAAfMLgwOJRpTjQ2zCCt2OcSfYMTeZVSRtQlPC7Nq4=
github.com/stretchr/testify v1.8.4 h1:CcVxjf3Q8PM0mHUKJCdn+eZZtm5yQwehR5yeSVQQcUk=
github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
github.com/joho/godotenv v1.5.1 h1:7eLL/+HRGLY0ldzfGMeQkb7vMd0as4CfYvUVzLqw0N0=
github.com/joho/godotenv v1.5.1/go.mod h1:f4LDr5Voq0i2e/R5DDNOoa2zzDfwtkZa6DnEwAbqwq4=
";

/// Medium go.sum with 25 packages.
fn generate_medium_go_sum() -> String {
    let mut content = String::new();
    let packages = [
        "github.com/gin-gonic/gin",
        "github.com/lib/pq",
        "golang.org/x/crypto",
        "github.com/stretchr/testify",
        "github.com/joho/godotenv",
        "github.com/go-redis/redis/v8",
        "github.com/gorilla/mux",
        "github.com/gorilla/sessions",
        "github.com/dgrijalva/jwt-go",
        "github.com/golang-migrate/migrate/v4",
        "github.com/google/uuid",
        "github.com/pkg/errors",
        "golang.org/x/sync",
        "golang.org/x/text",
        "golang.org/x/sys",
        "github.com/mattn/go-sqlite3",
        "github.com/sirupsen/logrus",
        "github.com/spf13/cobra",
        "github.com/spf13/viper",
        "gopkg.in/yaml.v3",
        "github.com/davecgh/go-spew",
        "github.com/pmezard/go-difflib",
        "golang.org/x/net",
        "golang.org/x/time",
        "google.golang.org/protobuf",
    ];

    for (i, pkg) in packages.iter().enumerate() {
        let version = format!("v{}.{}.{}", i % 10, (i % 20) + 1, i % 5);
        content.push_str(&format!("{} {} h1:hash{}=\n", pkg, version, i));
        content.push_str(&format!("{} {}/go.mod h1:modhash{}=\n", pkg, version, i));
    }

    content
}

/// Large go.sum with 100 packages.
fn generate_large_go_sum() -> String {
    let mut content = String::new();

    for i in 0..100 {
        let pkg = format!("github.com/pkg/package-{}", i);
        let version = format!("v{}.{}.{}", i % 10, (i % 20) + 1, i % 5);
        content.push_str(&format!("{} {} h1:hash{}=\n", pkg, version, i));
        content.push_str(&format!("{} {}/go.mod h1:modhash{}=\n", pkg, version, i));
    }

    content
}

/// Benchmark go.sum parsing with different sizes.
fn bench_go_sum_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("go_sum_parsing");

    group.bench_function("small_5_packages", |b| {
        b.iter(|| parse_go_sum(black_box(SMALL_GO_SUM)));
    });

    let medium_sum = generate_medium_go_sum();
    group.bench_function("medium_25_packages", |b| {
        b.iter(|| parse_go_sum(black_box(&medium_sum)));
    });

    let large_sum = generate_large_go_sum();
    group.bench_function("large_100_packages", |b| {
        b.iter(|| parse_go_sum(black_box(&large_sum)));
    });

    group.finish();
}

/// Benchmark version comparison operations.
///
/// Critical for inlay hints - runs for every dependency.
fn bench_version_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_comparison");

    let versions = [
        "v1.0.0",
        "v1.9.1",
        "v2.0.0",
        "v2.5.0+incompatible",
        "v0.0.0-20191109021931-daa7c04131f5",
    ];

    group.bench_function("simple_versions", |b| {
        b.iter(|| compare_versions(black_box("v1.0.0"), black_box("v2.0.0")));
    });

    group.bench_function("incompatible_suffix", |b| {
        b.iter(|| {
            compare_versions(
                black_box("v2.0.0+incompatible"),
                black_box("v2.5.0+incompatible"),
            )
        });
    });

    group.bench_function("pseudo_version", |b| {
        b.iter(|| {
            compare_versions(
                black_box("v0.0.0-20191109021931-daa7c04131f5"),
                black_box("v1.0.0"),
            )
        });
    });

    // Find latest version from list
    group.bench_function("find_latest_version", |b| {
        b.iter(|| {
            versions
                .iter()
                .max_by(|a, b| compare_versions(black_box(a), black_box(b)))
                .copied()
        });
    });

    group.finish();
}

/// Benchmark pseudo-version detection.
fn bench_pseudo_version_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("pseudo_version_detection");

    let versions = [
        ("regular", "v1.2.3"),
        ("pseudo", "v0.0.0-20191109021931-daa7c04131f5"),
        ("pseudo_with_base", "v1.2.4-0.20191109021931-daa7c04131f5"),
        (
            "pseudo_incompatible",
            "v2.0.1-0.20191109021931-daa7c04131f5+incompatible",
        ),
        ("prerelease", "v1.2.3-beta.1"),
    ];

    for (name, version) in versions {
        group.bench_with_input(BenchmarkId::from_parameter(name), &version, |b, version| {
            b.iter(|| is_pseudo_version(black_box(version)));
        });
    }

    group.finish();
}

/// Benchmark module path escaping.
///
/// Required for proxy.golang.org API requests.
fn bench_module_path_escaping(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_path_escaping");

    let paths = [
        ("lowercase", "github.com/gin-gonic/gin"),
        ("uppercase", "github.com/User/Repo"),
        ("mixed", "github.com/MyUser/MyRepo"),
        ("special_chars", "github.com/user/repo-name_v2"),
        (
            "long_path",
            "github.com/organization/very-long-repository-name/pkg/subpkg/module",
        ),
    ];

    for (name, path) in paths {
        group.bench_with_input(BenchmarkId::from_parameter(name), &path, |b, path| {
            b.iter(|| escape_module_path(black_box(path)));
        });
    }

    group.finish();
}

/// Benchmark different go.mod directive types.
fn bench_directive_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("directive_types");
    let uri = bench_uri();

    let directives = [
        (
            "require_inline",
            "require github.com/gin-gonic/gin v1.9.1\n",
        ),
        (
            "require_block",
            r"require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.17.0
)
",
        ),
        (
            "replace",
            "replace github.com/old/module => github.com/new/module v1.2.3\n",
        ),
        ("exclude", "exclude github.com/bad/package v0.1.0\n"),
        (
            "with_indirect",
            "require golang.org/x/sync v0.5.0 // indirect\n",
        ),
        (
            "pseudo_version",
            "require golang.org/x/tools v0.0.0-20191109021931-daa7c04131f5\n",
        ),
        (
            "incompatible",
            "require github.com/dgrijalva/jwt-go v3.2.0+incompatible\n",
        ),
    ];

    for (name, content) in directives {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            b.iter(|| parse_go_mod(black_box(content), &uri));
        });
    }

    group.finish();
}

/// Benchmark parsing with comments.
fn bench_comment_handling(c: &mut Criterion) {
    let uri = bench_uri();

    let with_comments = r"// Package comment
module example.com/myapp

// Go version comment
go 1.21

// Dependencies
require (
    github.com/gin-gonic/gin v1.9.1 // Web framework
    golang.org/x/crypto v0.17.0 // Cryptography
    // github.com/old/package v1.0.0 // Commented out
)

// Replacements section
replace github.com/old/module => github.com/new/module v1.2.3 // Migration
";

    c.bench_function("parsing_with_comments", |b| {
        b.iter(|| parse_go_mod(black_box(with_comments), &uri));
    });
}

/// Benchmark Unicode handling in go.mod.
fn bench_unicode_parsing(c: &mut Criterion) {
    let uri = bench_uri();

    let unicode_mod = r"// Package with Unicode: 日本語 🐹 Émojis
module example.com/unicode-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1 // Comment with 中文
    golang.org/x/crypto v0.17.0 // Комментарий на русском
)
";

    c.bench_function("unicode_parsing", |b| {
        b.iter(|| parse_go_mod(black_box(unicode_mod), &uri));
    });
}

/// Benchmark go.sum special cases.
fn bench_go_sum_special_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("go_sum_special_cases");

    // Pseudo-version in go.sum
    let pseudo_sum = "golang.org/x/tools v0.0.0-20191109021931-daa7c04131f5 h1:hash=\n";

    // Incompatible version
    let incompatible_sum = "github.com/dgrijalva/jwt-go v3.2.0+incompatible h1:hash=\n";

    // Multiple versions (deduplication test)
    let duplicate_sum = r"github.com/pkg/errors v0.9.1 h1:hash1=
github.com/pkg/errors v0.9.1/go.mod h1:modhash=
github.com/pkg/errors v0.8.0 h1:hash2=
github.com/pkg/errors v0.8.0/go.mod h1:modhash2=
";

    group.bench_function("pseudo_version", |b| {
        b.iter(|| parse_go_sum(black_box(pseudo_sum)));
    });

    group.bench_function("incompatible_version", |b| {
        b.iter(|| parse_go_sum(black_box(incompatible_sum)));
    });

    group.bench_function("duplicate_versions", |b| {
        b.iter(|| parse_go_sum(black_box(duplicate_sum)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_go_mod_parsing,
    bench_position_tracking,
    bench_go_sum_parsing,
    bench_version_comparison,
    bench_pseudo_version_detection,
    bench_module_path_escaping,
    bench_directive_types,
    bench_comment_handling,
    bench_unicode_parsing,
    bench_go_sum_special_cases
);
criterion_main!(benches);

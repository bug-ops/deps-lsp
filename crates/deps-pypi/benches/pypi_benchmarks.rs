//! Benchmarks for pyproject.toml parsing and PyPI registry operations.
//!
//! Performance targets:
//! - Parsing small files: < 1ms
//! - Parsing medium files (20-50 deps): < 5ms
//! - Parsing large files (100+ deps): < 20ms
//! - PEP 508 parsing: < 100μs per dependency
//! - PEP 440 version matching: < 100μs per operation

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_pypi::parser::PypiParser;
use std::hint::black_box;
use tower_lsp::lsp_types::Url;

fn bench_uri() -> Url {
    Url::parse("file:///bench/pyproject.toml").unwrap()
}

/// Small pyproject.toml with PEP 621 format.
const SMALL_PEP621: &str = r#"
[project]
name = "small-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "flask>=3.0.0",
    "pydantic>=2.0.0",
    "sqlalchemy>=2.0.0",
    "pytest>=7.0.0"
]
"#;

/// Medium pyproject.toml with PEP 621 and optional dependencies.
const MEDIUM_PEP621: &str = r#"
[project]
name = "medium-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "flask[async]>=3.0.0",
    "pydantic>=2.0.0",
    "sqlalchemy>=2.0.0",
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "httpx>=0.25.0",
    "redis>=5.0.0",
    "celery>=5.3.0",
    "python-multipart>=0.0.6"
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "mypy>=1.0.0",
    "ruff>=0.1.0",
    "black>=23.0.0"
]
docs = [
    "sphinx>=7.0.0",
    "sphinx-rtd-theme>=1.3.0",
    "myst-parser>=2.0.0"
]
test = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "pytest-mock>=3.12.0",
    "hypothesis>=6.92.0"
]
"#;

/// Large pyproject.toml with Poetry format.
fn generate_large_poetry() -> String {
    let mut content = String::from(
        r#"[tool.poetry]
name = "large-project"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.9"
"#,
    );

    for i in 0..50 {
        content.push_str(&format!("package-{} = \"^{}.{}.0\"\n", i, i % 10, i % 20));
    }

    content.push_str("\n[tool.poetry.group.dev.dependencies]\n");

    for i in 0..30 {
        content.push_str(&format!(
            "dev-package-{} = \"^{}.{}.0\"\n",
            i,
            i % 10,
            i % 20
        ));
    }

    content.push_str("\n[tool.poetry.group.test.dependencies]\n");

    for i in 0..20 {
        content.push_str(&format!(
            "test-package-{} = \"^{}.{}.0\"\n",
            i,
            i % 10,
            i % 20
        ));
    }

    content
}

/// PEP 735 dependency-groups format.
const PEP735_FORMAT: &str = r#"
[dependency-groups]
dev = [
    "pytest>=8.0",
    "mypy>=1.0",
    "ruff>=0.8",
    "black>=24.0",
    "isort>=5.0"
]
test = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "pytest-asyncio>=0.23",
    "pytest-mock>=3.12"
]
docs = [
    "sphinx>=7.0",
    "sphinx-autodoc-typehints>=1.25",
    "myst-parser>=2.0"
]
"#;

/// Complex mixed format (PEP 621 + Poetry + PEP 735).
const MIXED_FORMAT: &str = r#"
[project]
name = "mixed-project"
version = "0.1.0"
dependencies = [
    "requests>=2.28.0",
    "flask>=3.0.0"
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]

[tool.poetry.dependencies]
python = "^3.9"
pydantic = "^2.0.0"

[dependency-groups]
test = ["pytest>=8.0", "coverage>=7.0"]
"#;

/// Benchmark pyproject.toml parsing with different formats.
fn bench_pypi_parsing(c: &mut Criterion) {
    let parser = PypiParser::new();
    let mut group = c.benchmark_group("pypi_parsing");
    let uri = bench_uri();

    group.bench_function("pep621_small_5_deps", |b| {
        b.iter(|| parser.parse_content(black_box(SMALL_PEP621), &uri))
    });

    group.bench_function("pep621_medium_25_deps", |b| {
        b.iter(|| parser.parse_content(black_box(MEDIUM_PEP621), &uri))
    });

    let large_poetry = generate_large_poetry();
    group.bench_function("poetry_large_100_deps", |b| {
        b.iter(|| parser.parse_content(black_box(&large_poetry), &uri))
    });

    group.bench_function("pep735_format", |b| {
        b.iter(|| parser.parse_content(black_box(PEP735_FORMAT), &uri))
    });

    group.bench_function("mixed_format", |b| {
        b.iter(|| parser.parse_content(black_box(MIXED_FORMAT), &uri))
    });

    group.finish();
}

/// Benchmark PEP 508 requirement parsing.
///
/// Critical for position tracking - runs for every dependency.
fn bench_pep508_parsing(c: &mut Criterion) {
    use pep508_rs::Requirement;
    use std::str::FromStr;

    let mut group = c.benchmark_group("pep508_parsing");

    let requirements = [
        ("simple", "requests>=2.28.0"),
        ("with_extras", "flask[async]>=3.0.0"),
        ("complex_version", "django>=4.0,<5.0,!=4.0.1"),
        ("with_markers", "numpy>=1.24; python_version>='3.9'"),
        (
            "complex_markers",
            "pywin32>=1.0; sys_platform == 'win32' and python_version >= '3.8'",
        ),
        (
            "git_url",
            "mylib @ git+https://github.com/user/mylib.git@main",
        ),
        ("url", "package @ https://example.com/package.whl"),
    ];

    for (name, req_str) in requirements {
        group.bench_with_input(BenchmarkId::from_parameter(name), &req_str, |b, req_str| {
            b.iter(|| {
                let _: Result<Requirement, _> = Requirement::from_str(black_box(req_str));
            })
        });
    }

    group.finish();
}

/// Benchmark PEP 440 version matching.
fn bench_pep440_version_matching(c: &mut Criterion) {
    use pep440_rs::{Version, VersionSpecifiers};
    use std::str::FromStr;

    let mut group = c.benchmark_group("pep440_version_matching");

    let latest = Version::from_str("2.28.2").unwrap();

    // Simple version specifier
    let simple = VersionSpecifiers::from_str(">=2.28.0").unwrap();
    group.bench_function("simple_specifier", |b| {
        b.iter(|| simple.contains(black_box(&latest)))
    });

    // Complex version specifier
    let complex = VersionSpecifiers::from_str(">=2.0,<3.0,!=2.28.1").unwrap();
    group.bench_function("complex_specifier", |b| {
        b.iter(|| complex.contains(black_box(&latest)))
    });

    // Pre-release handling
    let prerelease_version = Version::from_str("3.0.0b1").unwrap();
    let prerelease_spec = VersionSpecifiers::from_str(">=3.0.0").unwrap();
    group.bench_function("prerelease_check", |b| {
        b.iter(|| prerelease_spec.contains(black_box(&prerelease_version)))
    });

    // Find latest matching version
    let versions: Vec<Version> = ["2.0.0", "2.28.0", "2.28.1", "2.28.2", "2.29.0", "3.0.0b1"]
        .iter()
        .map(|v| Version::from_str(v).unwrap())
        .collect();

    group.bench_function("find_latest_matching", |b| {
        b.iter(|| {
            versions
                .iter()
                .filter(|v| simple.contains(v))
                .max()
                .cloned()
        })
    });

    group.finish();
}

/// Benchmark position tracking for PyPI dependencies.
fn bench_position_tracking(c: &mut Criterion) {
    let parser = PypiParser::new();
    let mut group = c.benchmark_group("position_tracking");
    let uri = bench_uri();

    // Simple dependency
    let simple = r#"
[project]
dependencies = ["requests>=2.28.0"]
"#;

    // With extras
    let with_extras = r#"
[project]
dependencies = ["flask[async,cors]>=3.0.0"]
"#;

    // With markers
    let with_markers = r#"
[project]
dependencies = ["numpy>=1.24; python_version>='3.9'"]
"#;

    group.bench_function("simple_dependency", |b| {
        b.iter(|| parser.parse_content(black_box(simple), &uri))
    });

    group.bench_function("with_extras", |b| {
        b.iter(|| parser.parse_content(black_box(with_extras), &uri))
    });

    group.bench_function("with_markers", |b| {
        b.iter(|| parser.parse_content(black_box(with_markers), &uri))
    });

    group.finish();
}

/// Benchmark different dependency source formats.
fn bench_dependency_sources(c: &mut Criterion) {
    let parser = PypiParser::new();
    let mut group = c.benchmark_group("dependency_sources");
    let uri = bench_uri();

    let sources = [
        (
            "pypi",
            r#"[project]
dependencies = ["requests>=2.28.0"]"#,
        ),
        (
            "git_url",
            r#"[project]
dependencies = ["mylib @ git+https://github.com/user/mylib.git@main"]"#,
        ),
        (
            "direct_url",
            r#"[project]
dependencies = ["package @ https://example.com/package-1.0.0.whl"]"#,
        ),
        (
            "poetry_git",
            r#"[tool.poetry.dependencies]
mylib = { git = "https://github.com/user/mylib.git", rev = "main" }"#,
        ),
        (
            "poetry_path",
            r#"[tool.poetry.dependencies]
local = { path = "../local-package" }"#,
        ),
        (
            "poetry_url",
            r#"[tool.poetry.dependencies]
package = { url = "https://example.com/package.whl" }"#,
        ),
    ];

    for (name, content) in sources {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            b.iter(|| parser.parse_content(black_box(content), &uri))
        });
    }

    group.finish();
}

/// Benchmark parsing with comments and whitespace.
fn bench_with_comments(c: &mut Criterion) {
    let parser = PypiParser::new();
    let uri = bench_uri();

    let with_comments = r#"
[project]
name = "test"
# Main dependencies
dependencies = [
    "django>=4.0",  # Web framework
    # "old-package>=1.0",  # Commented out
    "requests>=2.0",  # HTTP library
]

# Development dependencies
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    # More to come
]
"#;

    c.bench_function("parsing_with_comments", |b| {
        b.iter(|| parser.parse_content(black_box(with_comments), &uri))
    });
}

/// Benchmark Unicode handling in dependencies.
fn bench_unicode_parsing(c: &mut Criterion) {
    let parser = PypiParser::new();
    let uri = bench_uri();

    let unicode_toml = r#"
[project]
name = "unicode-project"
description = "Project with Unicode: 日本語 🐍 Émojis"
dependencies = [
    "requests>=2.28.0",  # Comment with 中文
    "flask>=3.0.0"  # Комментарий на русском
]
"#;

    c.bench_function("unicode_parsing", |b| {
        b.iter(|| parser.parse_content(black_box(unicode_toml), &uri))
    });
}

/// Benchmark Poetry version constraint formats.
fn bench_poetry_constraints(c: &mut Criterion) {
    let parser = PypiParser::new();
    let mut group = c.benchmark_group("poetry_constraints");
    let uri = bench_uri();

    let constraints = [
        (
            "caret",
            r#"[tool.poetry.dependencies]
django = "^4.0""#,
        ),
        (
            "tilde",
            r#"[tool.poetry.dependencies]
django = "~4.0""#,
        ),
        (
            "wildcard",
            r#"[tool.poetry.dependencies]
django = "4.*""#,
        ),
        (
            "exact",
            r#"[tool.poetry.dependencies]
django = "==4.2.7""#,
        ),
        (
            "range",
            r#"[tool.poetry.dependencies]
django = ">=4.0,<5.0""#,
        ),
    ];

    for (name, content) in constraints {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            b.iter(|| parser.parse_content(black_box(content), &uri))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pypi_parsing,
    bench_pep508_parsing,
    bench_pep440_version_matching,
    bench_position_tracking,
    bench_dependency_sources,
    bench_with_comments,
    bench_unicode_parsing,
    bench_poetry_constraints
);
criterion_main!(benches);

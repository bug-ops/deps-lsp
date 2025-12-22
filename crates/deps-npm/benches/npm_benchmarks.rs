//! Benchmarks for package.json parsing and npm registry operations.
//!
//! Performance targets:
//! - Parsing small files: < 1ms
//! - Parsing medium files (20-50 deps): < 5ms
//! - Parsing large files (100+ deps): < 20ms
//! - Registry JSON parsing: < 2ms per package
//! - Version matching with node-semver: < 100μs per operation

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use deps_npm::parser::parse_package_json;
use std::hint::black_box;

/// Small package.json with 5 dependencies.
const SMALL_PACKAGE_JSON: &str = r#"{
  "name": "small-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21",
    "axios": "^1.6.0",
    "dotenv": "^16.0.0",
    "cors": "^2.8.5"
  }
}"#;

/// Medium package.json with 25 dependencies.
const MEDIUM_PACKAGE_JSON: &str = r#"{
  "name": "medium-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21",
    "axios": "^1.6.0",
    "dotenv": "^16.0.0",
    "cors": "^2.8.5",
    "mongoose": "^8.0.0",
    "jsonwebtoken": "^9.0.0",
    "bcryptjs": "^2.4.3",
    "helmet": "^7.0.0",
    "morgan": "^1.10.0",
    "compression": "^1.7.4",
    "winston": "^3.11.0",
    "nodemailer": "^6.9.0",
    "multer": "^1.4.5",
    "sharp": "^0.33.0"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "supertest": "^6.3.0",
    "eslint": "^8.54.0",
    "prettier": "^3.1.0",
    "nodemon": "^3.0.0",
    "typescript": "^5.3.0",
    "@types/node": "^20.10.0",
    "@types/express": "^4.17.21",
    "ts-node": "^10.9.0",
    "@typescript-eslint/parser": "^6.13.0"
  }
}"#;

/// Large package.json with 100+ dependencies.
fn generate_large_package_json() -> String {
    let mut content = String::from(
        r#"{
  "name": "large-project",
  "version": "1.0.0",
  "dependencies": {
"#,
    );

    for i in 0..70 {
        content.push_str(&format!(
            "    \"package-{}\": \"^{}.{}.0\"{}\n",
            i,
            i % 10,
            i % 20,
            if i < 69 { "," } else { "" }
        ));
    }

    content.push_str("  },\n  \"devDependencies\": {\n");

    for i in 0..30 {
        content.push_str(&format!(
            "    \"dev-package-{}\": \"^{}.{}.0\"{}\n",
            i,
            i % 10,
            i % 20,
            if i < 29 { "," } else { "" }
        ));
    }

    content.push_str("  }\n}");
    content
}

/// Monorepo package.json with all dependency sections.
const MONOREPO_PACKAGE_JSON: &str = r#"{
  "name": "monorepo-root",
  "version": "1.0.0",
  "workspaces": [
    "packages/*"
  ],
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "next": "^14.0.0"
  },
  "devDependencies": {
    "typescript": "^5.3.0",
    "eslint": "^8.54.0",
    "prettier": "^3.1.0",
    "jest": "^29.7.0",
    "@types/react": "^18.2.0",
    "@types/node": "^20.10.0"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  },
  "optionalDependencies": {
    "fsevents": "^2.3.3"
  }
}"#;

/// Realistic npm registry response for a popular package.
///
/// Based on actual registry API response format.
const NPM_REGISTRY_RESPONSE: &str = r#"{
  "name": "express",
  "dist-tags": {
    "latest": "4.18.2",
    "next": "5.0.0-beta.1"
  },
  "versions": {
    "4.17.0": {
      "name": "express",
      "version": "4.17.0",
      "dist": {
        "tarball": "https://registry.npmjs.org/express/-/express-4.17.0.tgz"
      }
    },
    "4.18.0": {
      "name": "express",
      "version": "4.18.0",
      "dist": {
        "tarball": "https://registry.npmjs.org/express/-/express-4.18.0.tgz"
      }
    },
    "4.18.1": {
      "name": "express",
      "version": "4.18.1",
      "dist": {
        "tarball": "https://registry.npmjs.org/express/-/express-4.18.1.tgz"
      }
    },
    "4.18.2": {
      "name": "express",
      "version": "4.18.2",
      "dist": {
        "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
      }
    }
  }
}"#;

/// Benchmark package.json parsing with different file sizes.
fn bench_npm_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("npm_parsing");

    group.bench_function("small_5_deps", |b| {
        b.iter(|| parse_package_json(black_box(SMALL_PACKAGE_JSON)))
    });

    group.bench_function("medium_25_deps", |b| {
        b.iter(|| parse_package_json(black_box(MEDIUM_PACKAGE_JSON)))
    });

    let large_json = generate_large_package_json();
    group.bench_function("large_100_deps", |b| {
        b.iter(|| parse_package_json(black_box(&large_json)))
    });

    group.bench_function("monorepo_all_sections", |b| {
        b.iter(|| parse_package_json(black_box(MONOREPO_PACKAGE_JSON)))
    });

    group.finish();
}

/// Benchmark position tracking for npm dependencies.
///
/// Tests accuracy and performance of line/character position calculation.
fn bench_position_tracking(c: &mut Criterion) {
    let mut group = c.benchmark_group("position_tracking");

    // Single dependency
    let single = r#"{
  "dependencies": {
    "express": "^4.18.2"
  }
}"#;

    // Scoped package
    let scoped = r#"{
  "devDependencies": {
    "@types/node": "^20.10.0",
    "@typescript-eslint/parser": "^6.13.0"
  }
}"#;

    group.bench_function("single_dependency", |b| {
        b.iter(|| parse_package_json(black_box(single)))
    });

    group.bench_function("scoped_packages", |b| {
        b.iter(|| parse_package_json(black_box(scoped)))
    });

    group.finish();
}

/// Benchmark registry JSON parsing.
fn bench_registry_parsing(c: &mut Criterion) {
    use serde_json::Value;

    let mut group = c.benchmark_group("registry_parsing");

    group.bench_function("npm_registry_response", |b| {
        b.iter(|| {
            let _value: Value = serde_json::from_str(black_box(NPM_REGISTRY_RESPONSE)).unwrap();
        })
    });

    // Large registry response with 100 versions
    let mut large_response = String::from(
        r#"{
  "name": "large-package",
  "dist-tags": {"latest": "10.0.0"},
  "versions": {
"#,
    );

    for i in 0..100 {
        large_response.push_str(&format!(
            r#"    "{}.0.0": {{"name": "large-package", "version": "{}.0.0"}}{}"#,
            i,
            i,
            if i < 99 { ",\n" } else { "\n" }
        ));
    }
    large_response.push_str("  }\n}");

    group.bench_function("large_registry_100_versions", |b| {
        b.iter(|| {
            let _value: Value = serde_json::from_str(black_box(&large_response)).unwrap();
        })
    });

    group.finish();
}

/// Benchmark version matching with node-semver.
fn bench_version_matching(c: &mut Criterion) {
    use node_semver::{Range, Version};

    let mut group = c.benchmark_group("version_matching");

    let latest = Version::parse("4.18.2").unwrap();

    // Caret range (most common)
    let caret_range = Range::parse("^4.18.0").unwrap();
    group.bench_function("caret_range", |b| {
        b.iter(|| caret_range.satisfies(black_box(&latest)))
    });

    // Tilde range
    let tilde_range = Range::parse("~4.18.0").unwrap();
    group.bench_function("tilde_range", |b| {
        b.iter(|| tilde_range.satisfies(black_box(&latest)))
    });

    // Complex range
    let complex_range = Range::parse(">=4.17.0 <5.0.0").unwrap();
    group.bench_function("complex_range", |b| {
        b.iter(|| complex_range.satisfies(black_box(&latest)))
    });

    // Find latest matching version
    let versions: Vec<Version> = (0..20)
        .map(|i| Version::parse(format!("4.18.{}", i)).unwrap())
        .collect();

    group.bench_function("find_latest_matching", |b| {
        b.iter(|| {
            versions
                .iter()
                .filter(|v| caret_range.satisfies(v))
                .max()
                .cloned()
        })
    });

    group.finish();
}

/// Benchmark different version specifier formats.
fn bench_version_specifiers(c: &mut Criterion) {
    let mut group = c.benchmark_group("version_specifiers");

    let specifiers = [
        ("exact", r#"{"dependencies": {"pkg": "4.18.2"}}"#),
        ("caret", r#"{"dependencies": {"pkg": "^4.18.0"}}"#),
        ("tilde", r#"{"dependencies": {"pkg": "~4.18.0"}}"#),
        ("range", r#"{"dependencies": {"pkg": ">=4.0.0 <5.0.0"}}"#),
        ("wildcard", r#"{"dependencies": {"pkg": "4.x"}}"#),
        (
            "git_url",
            r#"{"dependencies": {"pkg": "git+https://github.com/user/repo.git"}}"#,
        ),
        (
            "file_path",
            r#"{"dependencies": {"pkg": "file:../local-package"}}"#,
        ),
        ("tag", r#"{"dependencies": {"pkg": "latest"}}"#),
    ];

    for (name, content) in specifiers {
        group.bench_with_input(BenchmarkId::from_parameter(name), &content, |b, content| {
            b.iter(|| parse_package_json(black_box(content)))
        });
    }

    group.finish();
}

/// Benchmark parsing with name collision scenarios.
///
/// Regression test for package names appearing in scripts.
fn bench_name_collision(c: &mut Criterion) {
    let collision_json = r#"{
  "name": "collision-test",
  "scripts": {
    "test": "vitest",
    "coverage": "vitest run --coverage"
  },
  "devDependencies": {
    "vitest": "^3.1.4",
    "@vitest/coverage-v8": "^3.1.4"
  }
}"#;

    c.bench_function("name_collision_in_scripts", |b| {
        b.iter(|| parse_package_json(black_box(collision_json)))
    });
}

/// Benchmark parsing with Unicode package names and versions.
fn bench_unicode_parsing(c: &mut Criterion) {
    let unicode_json = r#"{
  "name": "unicode-project",
  "description": "Project with Unicode: 日本語 🦀",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}"#;

    c.bench_function("unicode_parsing", |b| {
        b.iter(|| parse_package_json(black_box(unicode_json)))
    });
}

criterion_group!(
    benches,
    bench_npm_parsing,
    bench_position_tracking,
    bench_registry_parsing,
    bench_version_matching,
    bench_version_specifiers,
    bench_name_collision,
    bench_unicode_parsing
);
criterion_main!(benches);

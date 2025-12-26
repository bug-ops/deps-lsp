# deps-npm

[![Crates.io](https://img.shields.io/crates/v/deps-npm)](https://crates.io/crates/deps-npm)
[![docs.rs](https://img.shields.io/docsrs/deps-npm)](https://docs.rs/deps-npm)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-npm)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

npm/package.json support for deps-lsp.

This crate provides parsing and registry integration for the npm ecosystem.

## Features

- **JSON Parsing** — Parse `package.json` with position tracking
- **Lock File Parsing** — Extract resolved versions from `package-lock.json` (v2/v3)
- **npm Registry** — Client for npm registry API
- **Version Resolution** — Node semver-aware version matching (`^`, `~`, ranges)
- **Scoped Packages** — Support for `@scope/package` format
- **EcosystemHandler** — Implements `deps_core::EcosystemHandler` trait

## Usage

```toml
[dependencies]
deps-npm = "0.4"
```

```rust
use deps_npm::{parse_package_json, NpmRegistry};

let dependencies = parse_package_json(content)?;
let registry = NpmRegistry::new(cache);
let versions = registry.get_versions("express").await?;
```

## Benchmarks

```bash
cargo bench -p deps-npm
```

Parsing performance: ~3μs for small files, ~45μs for monorepo package.json.

## License

[MIT](../../LICENSE)

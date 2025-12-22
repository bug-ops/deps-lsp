# deps-cargo

[![Crates.io](https://img.shields.io/crates/v/deps-cargo)](https://crates.io/crates/deps-cargo)
[![docs.rs](https://img.shields.io/docsrs/deps-cargo)](https://docs.rs/deps-cargo)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-cargo)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Cargo.toml support for deps-lsp.

This crate provides parsing and registry integration for Rust's Cargo ecosystem.

## Features

- **TOML Parsing** — Parse `Cargo.toml` with position tracking using `toml_edit`
- **crates.io Registry** — Sparse index client for package metadata
- **Version Resolution** — Semver-aware version matching
- **Workspace Support** — Handle `workspace.dependencies` inheritance
- **EcosystemHandler** — Implements `deps_core::EcosystemHandler` trait

## Usage

```toml
[dependencies]
deps-cargo = "0.2"
```

```rust
use deps_cargo::{parse_cargo_toml, CratesIoRegistry};

let dependencies = parse_cargo_toml(content)?;
let registry = CratesIoRegistry::new(cache);
let versions = registry.get_versions("serde").await?;
```

## Benchmarks

```bash
cargo bench -p deps-cargo
```

Parsing performance: ~4μs for small files, ~55μs for large files (100+ dependencies).

## License

[MIT](../../LICENSE)

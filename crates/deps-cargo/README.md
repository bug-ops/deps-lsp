# deps-cargo

[![Crates.io](https://img.shields.io/crates/v/deps-cargo)](https://crates.io/crates/deps-cargo)
[![docs.rs](https://img.shields.io/docsrs/deps-cargo)](https://docs.rs/deps-cargo)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-cargo)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Cargo.toml support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the Rust/Cargo ecosystem and implements `deps_core::Ecosystem`.

## Features

- **TOML parsing** — Parse `Cargo.toml` with byte-accurate position tracking via `toml-span`
- **Lock file parsing** — Extract resolved versions from `Cargo.lock`
- **crates.io registry** — Sparse index client for version lookups and package metadata
- **Semver resolution** — Resolve `^`, `~`, `*`, and range specifiers against available versions
- **Workspace support** — Handle `workspace.dependencies` inheritance and `version.workspace = true`

## Installation

```toml
[dependencies]
deps-cargo = "0.9.3"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

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

Parsing performance: ~4 us for small files, ~55 us for large files (100+ dependencies).

## License

[MIT](../../LICENSE)

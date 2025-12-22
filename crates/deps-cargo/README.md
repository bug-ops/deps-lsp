# deps-cargo

[![Crates.io](https://img.shields.io/crates/v/deps-cargo)](https://crates.io/crates/deps-cargo)
[![docs.rs](https://img.shields.io/docsrs/deps-cargo)](https://docs.rs/deps-cargo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Cargo.toml support for deps-lsp.

This crate provides parsing and registry integration for Rust's Cargo ecosystem.

## Features

- **TOML Parsing** — Parse `Cargo.toml` with position tracking using `toml_edit`
- **crates.io Registry** — Sparse index client for package metadata
- **Version Resolution** — Semver-aware version matching
- **Workspace Support** — Handle `workspace.dependencies` inheritance

## Usage

```toml
[dependencies]
deps-cargo = "0.2"
```

```rust
use deps_cargo::{CargoParser, CratesIoRegistry};
```

## License

[MIT](../../LICENSE)

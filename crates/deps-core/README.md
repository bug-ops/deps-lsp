# deps-core

[![Crates.io](https://img.shields.io/crates/v/deps-core)](https://crates.io/crates/deps-core)
[![docs.rs](https://img.shields.io/docsrs/deps-core)](https://docs.rs/deps-core)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-core)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Core abstractions for deps-lsp: caching, errors, and traits.

This crate provides the shared infrastructure used by ecosystem-specific crates like `deps-cargo` and `deps-npm`.

## Features

- **HTTP Cache** — ETag/Last-Modified caching for registry requests
- **Error Types** — Unified error handling with `thiserror`
- **Traits** — `PackageRegistry` and `ManifestParser` abstractions
- **Document State** — Shared types for LSP document management

## Usage

```toml
[dependencies]
deps-core = "0.2"
```

```rust
use deps_core::{HttpCache, PackageRegistry, DepsError};
```

## License

[MIT](../../LICENSE)

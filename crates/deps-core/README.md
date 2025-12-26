# deps-core

[![Crates.io](https://img.shields.io/crates/v/deps-core)](https://crates.io/crates/deps-core)
[![docs.rs](https://img.shields.io/docsrs/deps-core)](https://docs.rs/deps-core)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-core)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Core abstractions for deps-lsp: traits, caching, and generic LSP handlers.

This crate provides the shared infrastructure used by ecosystem-specific crates (`deps-cargo`, `deps-npm`, `deps-pypi`).

## Features

- **EcosystemHandler Trait** — Unified interface for all package ecosystems
- **LockFileProvider Trait** — Abstract lock file parsing for resolved versions
- **Generic LSP Handlers** — `generate_inlay_hints`, `generate_hover`, `generate_code_actions`, `generate_diagnostics`
- **HTTP Cache** — ETag/Last-Modified caching for registry requests
- **Version Matchers** — Semver and PEP 440 version matching
- **Error Types** — Unified error handling with `thiserror`

## Usage

```toml
[dependencies]
deps-core = "0.4"
```

```rust
use deps_core::{EcosystemHandler, HttpCache, PackageRegistry};
```

## Architecture

```rust
// Implement EcosystemHandler for your ecosystem
#[async_trait]
impl EcosystemHandler for MyHandler {
    type Registry = MyRegistry;
    type Dependency = MyDependency;
    // ...
}

// Use generic handlers
let hints = generate_inlay_hints::<MyHandler>(&handler, &deps).await;
let hover = generate_hover_info::<MyHandler>(&handler, &dep, &versions);
```

## License

[MIT](../../LICENSE)

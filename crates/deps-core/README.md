# deps-core

[![Crates.io](https://img.shields.io/crates/v/deps-core)](https://crates.io/crates/deps-core)
[![docs.rs](https://img.shields.io/docsrs/deps-core)](https://docs.rs/deps-core)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-core)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Core abstractions for deps-lsp: traits, caching, and generic LSP handlers.

This crate provides the shared infrastructure used by all ecosystem-specific crates in the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. Every ecosystem crate depends on `deps-core` and implements its `Ecosystem` trait.

## What this crate provides

- **`Ecosystem` trait** — Unified interface for all package ecosystems (parse, registry, format)
- **`Registry` trait** — Abstraction over package registries with version lookup
- **`LockFileProvider` trait** — Abstract lock file parsing for resolved versions
- **Generic LSP handlers** — `generate_inlay_hints`, `generate_hover`, `generate_code_actions`, `generate_diagnostics`
- **`HttpCache`** — ETag/Last-Modified caching for registry HTTP requests
- **Error types** — Unified error handling with `thiserror`

## Installation

```toml
[dependencies]
deps-core = "0.9.2"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Implementing a new ecosystem

```rust
use deps_core::{Ecosystem, Registry, ParseResult};

pub struct MyEcosystem {
    registry: Arc<MyRegistry>,
}

impl Ecosystem for MyEcosystem {
    fn id(&self) -> &'static str { "my-ecosystem" }
    fn display_name(&self) -> &'static str { "My Ecosystem" }

    fn matches_uri(&self, uri: &Uri) -> bool {
        uri.path().ends_with("my-manifest.json")
    }

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<ParseResult> {
        // Parse the manifest and return dependencies with source positions
        todo!()
    }
}
```

## License

[MIT](../../LICENSE)

# deps-npm

[![Crates.io](https://img.shields.io/crates/v/deps-npm)](https://crates.io/crates/deps-npm)
[![docs.rs](https://img.shields.io/docsrs/deps-npm)](https://docs.rs/deps-npm)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-npm)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

npm/package.json support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the npm ecosystem and implements `deps_core::Ecosystem`.

## Features

- **JSON parsing** — Parse `package.json` with position tracking for `dependencies`, `devDependencies`, and `peerDependencies`
- **Lock file parsing** — Extract resolved versions from `package-lock.json` (v2/v3)
- **npm registry** — Client for npm registry API with metadata caching
- **Node semver resolution** — Full `^`, `~`, `>=`, `<`, range, and tag specifier support
- **Scoped packages** — Support for `@scope/package` format

## Installation

```toml
[dependencies]
deps-npm = "0.9.2"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

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

Parsing performance: ~3 us for small files, ~45 us for monorepo package.json.

## License

[MIT](../../LICENSE)

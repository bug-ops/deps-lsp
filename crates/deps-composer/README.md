# deps-composer

[![Crates.io](https://img.shields.io/crates/v/deps-composer)](https://crates.io/crates/deps-composer)
[![docs.rs](https://img.shields.io/docsrs/deps-composer)](https://docs.rs/deps-composer)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-composer)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

PHP/Composer support for deps-lsp.

This crate provides parsing and registry integration for the Composer ecosystem.

## Features

- **JSON Parsing** — Parse `composer.json` with position tracking for `require` and `require-dev`
- **Lock File Parsing** — Extract resolved versions from `composer.lock`
- **Packagist Registry** — Client for Packagist v2 API with metadata de-minification
- **Version Resolution** — Composer-specific version matching (`^`, `~`, `*`, `||`, ranges)
- **Platform Filtering** — Excludes `php`, `ext-*`, `lib-*` from registry lookups
- **Case-insensitive** — Package names normalized to lowercase (`vendor/package`)

## Usage

```toml
[dependencies]
deps-composer = "0.8"
```

```rust
use deps_composer::{parse_composer_json, PackagistRegistry};

let dependencies = parse_composer_json(content, &uri)?;
let registry = PackagistRegistry::new(cache);
let versions = registry.get_versions("monolog/monolog").await?;
```

## License

[MIT](../../LICENSE)

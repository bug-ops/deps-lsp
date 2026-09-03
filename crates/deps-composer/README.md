# deps-composer

[![Crates.io](https://img.shields.io/crates/v/deps-composer)](https://crates.io/crates/deps-composer)
[![docs.rs](https://img.shields.io/docsrs/deps-composer)](https://docs.rs/deps-composer)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-composer)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

PHP/Composer support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the Composer ecosystem and implements `deps_core::Ecosystem`.

## Features

- **JSON parsing** — Parse `composer.json` with position tracking for `require` and `require-dev` sections
- **Lock file parsing** — Extract resolved versions from `composer.lock`
- **Packagist registry** — Client for Packagist v2 API with metadata de-minification
- **Version resolution** — Composer-specific version matching (`^`, `~`, `*`, `||`, ranges)
- **Platform filtering** — Excludes `php`, `ext-*`, and `lib-*` pseudo-packages from registry lookups
- **Case-insensitive names** — Package names normalized to lowercase (`vendor/package`)
- **Stability-aware version selection** — "Latest version" excludes alpha/beta/RC releases by default (matching Composer's `minimum-stability: stable`), unless overridden by `composer.json`'s `minimum-stability` field or a per-dependency `@stability` flag (`^1.0@beta`); a wildcard requirement still resolves a prerelease-only package
- **Package-level abandonment diagnostic** — flags a Packagist-`abandoned` package, with a "Replace with X" code action when a successor package is named

> [!NOTE]
> Composer's tilde operator has different semantics from npm: `~1.2` means `>=1.2.0 <2.0.0` (not `>=1.2.0 <1.3.0`).

## Installation

```toml
[dependencies]
deps-composer = "0.12"
```

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Usage

```rust
use deps_composer::{parse_composer_json, PackagistRegistry};

let dependencies = parse_composer_json(content, &uri)?;
let registry = PackagistRegistry::new(cache);
let versions = registry.get_versions("monolog/monolog").await?;
```

## License

[MIT](../../LICENSE)

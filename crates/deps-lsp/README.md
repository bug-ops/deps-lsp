# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![docs.rs](https://img.shields.io/docsrs/deps-lsp)](https://docs.rs/deps-lsp)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-lsp)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Language Server Protocol implementation for dependency management across ten package ecosystems.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides the LSP server binary and the ecosystem orchestration layer that wires together ecosystem-specific crates (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-go`, `deps-bundler`, `deps-dart`, `deps-maven`, `deps-gradle`, `deps-swift`, `deps-composer`) via the `Ecosystem` trait from `deps-core`.

## Features

- **Multi-ecosystem** — Cargo.toml, package.json, pyproject.toml, go.mod, Gemfile, pubspec.yaml, pom.xml, libs.versions.toml, Package.swift, composer.json
- **Inlay hints** — Show latest versions inline with loading indicators
- **Hover info** — Package descriptions with resolved version from lock file
- **Code actions** — Quick fixes to update dependencies
- **Diagnostics** — Warnings for outdated, yanked, or unknown packages
- **Lock file support** — Reads resolved versions without network requests

## Installation

```bash
cargo install deps-lsp
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```bash
deps-lsp --stdio
```

## Feature flags

All ecosystems are enabled by default. Disable unused ones to reduce binary size:

```toml
[dependencies]
deps-lsp = { version = "0.9.3", default-features = false, features = ["cargo", "npm"] }
```

| Feature | Ecosystem | Default |
| ------- | --------- | ------- |
| `cargo` | Rust / Cargo.toml | Yes |
| `npm` | JavaScript / package.json | Yes |
| `pypi` | Python / pyproject.toml | Yes |
| `go` | Go / go.mod | Yes |
| `bundler` | Ruby / Gemfile | Yes |
| `dart` | Dart / pubspec.yaml | Yes |
| `maven` | Java / pom.xml | Yes |
| `gradle` | Java / Version Catalog + DSL | Yes |
| `swift` | Swift / Package.swift | Yes |
| `composer` | PHP / composer.json | Yes |

## Supported editors

- **Zed** — Install the "Deps" extension from the Zed Extensions marketplace
- **Neovim** — Configure with `nvim-lspconfig`
- **Helix** — Add to `languages.toml`
- **VS Code** — Configure via any LSP client extension

See the [main repository](https://github.com/bug-ops/deps-lsp) for full editor setup instructions and configuration reference.

## License

[MIT](../../LICENSE)

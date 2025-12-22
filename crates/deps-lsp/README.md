# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![docs.rs](https://img.shields.io/docsrs/deps-lsp)](https://docs.rs/deps-lsp)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-lsp)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Language Server Protocol implementation for dependency management.

## Features

- **Multi-ecosystem** — Cargo.toml, package.json, pyproject.toml
- **Inlay Hints** — Show latest versions inline
- **Hover Info** — Package descriptions and version lists
- **Code Actions** — Quick fixes to update dependencies
- **Diagnostics** — Warnings for outdated/yanked packages

## Installation

```bash
cargo install deps-lsp
```

## Usage

```bash
deps-lsp --stdio
```

## Supported Editors

- **Zed** — Install "Deps" extension
- **Neovim** — Configure with lspconfig
- **Helix** — Add to languages.toml

See the [main repository](https://github.com/bug-ops/deps-lsp) for full documentation.

## License

[MIT](../../LICENSE)

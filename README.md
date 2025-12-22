# deps-lsp

[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/deps-lsp/ci.yml?branch=main)](https://github.com/bug-ops/deps-lsp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](https://blog.rust-lang.org/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

A universal Language Server Protocol (LSP) server for dependency management across multiple package ecosystems.

## Features

- **Intelligent Autocomplete** — Package names, versions, and feature flags
- **Version Hints** — Inlay hints showing latest available versions
- **Diagnostics** — Warnings for outdated, unknown, or yanked dependencies
- **Hover Information** — Package descriptions, links to documentation
- **Code Actions** — Quick fixes to update dependencies

![deps-lsp in action](crates/deps-zed/assets/img.png)

## Supported Ecosystems

| Ecosystem | Manifest File | Status |
|-----------|---------------|--------|
| Rust/Cargo | `Cargo.toml` | Supported |
| npm | `package.json` | Supported |
| Python/PyPI | `pyproject.toml` | Planned |

## Installation

### From crates.io

```bash
cargo install deps-lsp
```

> [!TIP]
> Use `cargo binstall deps-lsp` for faster installation without compilation.

### From source

```bash
git clone https://github.com/bug-ops/deps-lsp
cd deps-lsp
cargo install --path crates/deps-lsp
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/bug-ops/deps-lsp/releases/latest):

| Platform | Architecture | Binary |
|----------|--------------|--------|
| Linux | x86_64 | `deps-lsp-x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `deps-lsp-aarch64-unknown-linux-gnu` |
| macOS | x86_64 | `deps-lsp-x86_64-apple-darwin` |
| macOS | Apple Silicon | `deps-lsp-aarch64-apple-darwin` |
| Windows | x86_64 | `deps-lsp-x86_64-pc-windows-msvc.exe` |

## Editor Setup

### Zed

Install the **Deps** extension from Zed Extensions marketplace.

### Neovim

```lua
require('lspconfig').deps_lsp.setup({
  cmd = { "deps-lsp", "--stdio" },
  filetypes = { "toml" },
})
```

### Helix

```toml
# ~/.config/helix/languages.toml
[[language]]
name = "toml"
language-servers = ["deps-lsp"]

[language-server.deps-lsp]
command = "deps-lsp"
args = ["--stdio"]
```

## Configuration

Configure via LSP initialization options:

```json
{
  "inlay_hints": {
    "enabled": true,
    "up_to_date_text": "✅",
    "needs_update_text": "❌ {}"
  },
  "diagnostics": {
    "outdated_severity": "hint",
    "unknown_severity": "warning",
    "yanked_severity": "warning"
  },
  "cache": {
    "refresh_interval_secs": 300
  }
}
```

## Development

> [!IMPORTANT]
> Requires Rust 1.89+ (Edition 2024).

### Build

```bash
cargo build --workspace
```

### Test

```bash
# Run tests with nextest
cargo nextest run

# Run tests with coverage
cargo llvm-cov nextest

# Generate HTML coverage report
cargo llvm-cov nextest --html
```

### Lint

```bash
# Format (requires nightly for Edition 2024)
cargo +nightly fmt

# Clippy
cargo clippy --workspace -- -D warnings

# Security audit
cargo deny check
```

### Project Structure

```
deps-lsp/
├── crates/
│   ├── deps-core/      # Shared types, cache, error handling
│   ├── deps-cargo/     # Cargo.toml parser + crates.io registry
│   ├── deps-npm/       # package.json parser + npm registry
│   ├── deps-lsp/       # Main LSP server
│   └── deps-zed/       # Zed extension (WASM)
├── .config/            # nextest configuration
└── .github/            # CI/CD workflows
```

## License

[MIT](LICENSE)

## Acknowledgments

Inspired by:

- [crates-lsp](https://github.com/MathiasPius/crates-lsp) — Cargo.toml LSP
- [dependi](https://github.com/filllabs/dependi) — Multi-ecosystem dependency management
- [taplo](https://github.com/tamasfe/taplo) — TOML toolkit

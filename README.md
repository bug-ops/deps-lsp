# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![docs.rs](https://img.shields.io/docsrs/deps-lsp)](https://docs.rs/deps-lsp)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ)](https://codecov.io/gh/bug-ops/deps-lsp)
[![CI](https://img.shields.io/github/actions/workflow/status/bug-ops/deps-lsp/ci.yml?branch=main)](https://github.com/bug-ops/deps-lsp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](https://blog.rust-lang.org/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

A universal Language Server Protocol (LSP) server for dependency management across Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Gradle, and Swift ecosystems.

## Features

- **Intelligent autocomplete** — Package names, versions, and feature flags
- **Version hints** — Inlay hints showing latest available versions
- **Loading indicators** — Visual feedback during registry fetches with LSP progress support
- **Lock file support** — Reads resolved versions from Cargo.lock, package-lock.json, poetry.lock, uv.lock, go.sum, Gemfile.lock, pubspec.lock, Package.resolved
- **Diagnostics** — Warnings for outdated, unknown, or yanked dependencies
- **Hover information** — Package descriptions with resolved version from lock file
- **Code actions** — Quick fixes to update dependencies
- **High performance** — Parallel fetching with per-dependency timeouts, optimized caching

![deps-lsp in action](https://raw.githubusercontent.com/bug-ops/deps-zed/main/assets/img.png)

## Performance

deps-lsp is optimized for responsiveness:

| Operation | Latency | Notes |
| ----------- | --------- | ------- |
| Document open (50 deps) | ~150ms | Parallel registry fetching |
| Inlay hints | <100ms | Cached version lookups |
| Hover | <50ms | Pre-fetched metadata |
| Code actions | <50ms | No network calls |

> [!TIP]
> Lock file support provides instant resolved versions without network requests.

## Supported ecosystems

| Language | Ecosystem | Manifest file | Status |
| ---------- | ----------- | --------------- | -------- |
| Rust | Cargo | `Cargo.toml` | ✅ Supported |
| JavaScript | npm | `package.json` | ✅ Supported |
| Python | PyPI | `pyproject.toml` | ✅ Supported |
| Go | Go Modules | `go.mod` | ✅ Supported |
| Ruby | Bundler | `Gemfile` | ✅ Supported |
| Dart | Pub | `pubspec.yaml` | ✅ Supported |
| Java | Maven | `pom.xml` | ✅ Supported |
| Java | Gradle | `libs.versions.toml`, `build.gradle.kts`, `build.gradle`, `settings.gradle` | ✅ Supported |
| Swift | SPM | `Package.swift` | ✅ Supported |

> [!NOTE]
> **Ecosystem details:**
> - **PyPI** — PEP 621, PEP 735 (dependency-groups), Poetry formats
> - **Go** — `require`, `replace`, `exclude` directives, pseudo-version handling
> - **Bundler** — git/path/GitHub sources, pessimistic operator (`~>`)
> - **Dart** — hosted, git, path, SDK sources, caret version semantics
> - **Maven** — `dependencies`, `dependencyManagement`, `build/plugins`, qualifier-aware version comparison
> - **Gradle** — Version Catalogs, Kotlin/Groovy DSL, `settings.gradle` plugins; resolves from Maven Central, Google Maven, Gradle Plugin Portal
> - **Swift** — all `.package()` forms (from, upToNextMajor/Minor, exact, range, branch, revision, path); versions via GitHub API tags

## Installation

### From crates.io

```bash
cargo install deps-lsp
```

Latest published crate version: `0.8.0`.

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
| ---------- | -------------- | -------- |
| Linux | x86_64 | `deps-lsp-x86_64-unknown-linux-gnu` |
| Linux | aarch64 | `deps-lsp-aarch64-unknown-linux-gnu` |
| macOS | x86_64 | `deps-lsp-x86_64-apple-darwin` |
| macOS | Apple Silicon | `deps-lsp-aarch64-apple-darwin` |
| Windows | x86_64 | `deps-lsp-x86_64-pc-windows-msvc.exe` |
| Windows | ARM64 | `deps-lsp-aarch64-pc-windows-msvc.exe` |

## Feature flags

By default, all ecosystems are enabled. To build with specific ecosystems only:

```bash
# Only Cargo and npm support
cargo install deps-lsp --no-default-features --features "cargo,npm"

# Only Python support
cargo install deps-lsp --no-default-features --features "pypi"
```

| Feature | Language | Manifest | Default |
| --------- | ---------- | ----------- | ------- |
| `cargo` | Rust | Cargo.toml | ✅ |
| `npm` | JavaScript | package.json | ✅ |
| `pypi` | Python | pyproject.toml | ✅ |
| `go` | Go | go.mod | ✅ |
| `bundler` | Ruby | Gemfile | ✅ |
| `dart` | Dart | pubspec.yaml | ✅ |
| `maven` | Java | pom.xml | ✅ |
| `gradle` | Java | libs.versions.toml, build.gradle.kts, build.gradle | ✅ |
| `swift` | Swift | Package.swift | ✅ |

## Usage

Run the server over stdio (typical editor integration):

```bash
deps-lsp --stdio
```

> [!TIP]
> Configure your editor to launch `deps-lsp` and connect over stdio. See the editor snippets below.

## Editor setup

> [!IMPORTANT]
> Inlay hints must be enabled in your editor to see version indicators. See configuration for each editor below.

### Zed

Install the **Deps** extension from Zed Extensions marketplace. Ruby support is enabled for Gemfile files.

Enable inlay hints in Zed settings:

```json
// settings.json
{
  "inlay_hints": {
    "enabled": true
  }
}
```

### Neovim

```lua
require('lspconfig').deps_lsp.setup({
  cmd = { "deps-lsp", "--stdio" },
  filetypes = { "toml", "json", "gomod", "ruby", "yaml", "xml", "swift" },
})

-- Enable inlay hints (Neovim 0.10+)
vim.lsp.inlay_hint.enable(true)
```

For older Neovim versions, use [nvim-lsp-inlayhints](https://github.com/lvimuser/lsp-inlayhints.nvim).

### Helix

```toml
# ~/.config/helix/languages.toml
[[language]]
name = "toml"
language-servers = ["deps-lsp"]

[[language]]
name = "json"
language-servers = ["deps-lsp"]

[language-server.deps-lsp]
command = "deps-lsp"
args = ["--stdio"]
```

Enable inlay hints in Helix config:

```toml
# ~/.config/helix/config.toml
[editor.lsp]
display-inlay-hints = true
```

### VS Code

Install an LSP client extension and configure deps-lsp. Enable inlay hints:

```json
// settings.json
{
  "editor.inlayHints.enabled": "on"
}
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
    "enabled": true,
    "refresh_interval_secs": 300,
    "fetch_timeout_secs": 5,
    "max_concurrent_fetches": 20
  },
  "loading_indicator": {
    "enabled": true,
    "fallback_to_hints": true,
    "loading_text": "⏳"
  },
  "cold_start": {
    "enabled": true,
    "rate_limit_ms": 100
  }
}
```

### Configuration reference

| Section | Option | Default | Description |
| --------- | -------- | --------- | ------------- |
| `cache` | `fetch_timeout_secs` | `5` | Per-package fetch timeout (1-300 seconds) |
| `cache` | `max_concurrent_fetches` | `20` | Concurrent registry requests (1-100) |
| `loading_indicator` | `enabled` | `true` | Show loading feedback during fetches |
| `loading_indicator` | `fallback_to_hints` | `true` | Show loading in inlay hints if LSP progress unsupported |
| `loading_indicator` | `loading_text` | `"⏳"` | Text shown during loading (max 100 chars) |

> [!TIP]
> Increase `fetch_timeout_secs` for slower networks. The per-dependency timeout prevents slow packages from blocking others. Cold start support ensures LSP features work immediately when your IDE restores previously opened files.

### GitHub API token

Some ecosystems (Swift) resolve versions via the GitHub API, which is limited to **60 requests/hour** without authentication. Set `GITHUB_TOKEN` to increase the limit to **5,000 requests/hour**:

```bash
# Using GitHub CLI (recommended)
export GITHUB_TOKEN=$(gh auth token)

# Or create a personal access token at https://github.com/settings/tokens
# No scopes required for public repository access
export GITHUB_TOKEN=ghp_...
```

For **Zed**, launch with the token so the LSP process inherits it:

```bash
# bash / zsh
alias zed='GITHUB_TOKEN="$(gh auth token)" command zed'

# fish
alias zed='env GITHUB_TOKEN=(gh auth token) command zed'
```

> [!TIP]
> Add the alias to your shell profile (`~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`) for persistence.

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
cargo +nightly fmt --check

# Clippy (all targets, all features)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
cargo deny check
```

### Project structure

```text
deps-lsp/
├── crates/
│   ├── deps-core/      # Shared traits, cache, generic handlers
│   ├── deps-cargo/     # Cargo.toml parser + crates.io registry
│   ├── deps-npm/       # package.json parser + npm registry
│   ├── deps-pypi/      # pyproject.toml parser + PyPI registry
│   ├── deps-go/        # go.mod parser + proxy.golang.org
│   ├── deps-bundler/   # Gemfile parser + rubygems.org registry
│   ├── deps-dart/      # pubspec.yaml parser + pub.dev registry
│   ├── deps-maven/     # pom.xml parser + Maven Central registry
│   ├── deps-gradle/    # Gradle parser (Version Catalog, Kotlin/Groovy DSL)
│   ├── deps-swift/     # Package.swift parser + GitHub API registry
│   ├── deps-lsp/       # Main LSP server
│   └── deps-zed/       # Zed extension (WASM)
├── .config/            # nextest configuration
└── .github/            # CI/CD workflows
```

### Architecture

The codebase uses a trait-based architecture with the `Ecosystem` trait providing a unified interface for all package ecosystems:

```rust
// Each ecosystem implements the Ecosystem trait
pub trait Ecosystem: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn matches_uri(&self, uri: &Uri) -> bool;
    fn registry(&self) -> Arc<dyn Registry>;
    fn formatter(&self) -> Arc<dyn EcosystemFormatter>;
    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<ParseResult>;
}

// EcosystemRegistry discovers the right handler for any manifest file
let ecosystem = registry.get_for_uri(&uri);
```

### Benchmarks

Run performance benchmarks with criterion:

```bash
cargo bench --workspace
```

View HTML report: `open target/criterion/report/index.html`

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, style, and testing expectations.

## License

[MIT](LICENSE)

## Acknowledgments

Inspired by:

- [crates-lsp](https://github.com/MathiasPius/crates-lsp) — Cargo.toml LSP
- [dependi](https://github.com/filllabs/dependi) — Multi-ecosystem dependency management
- [taplo](https://github.com/tamasfe/taplo) — TOML toolkit

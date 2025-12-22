# deps-npm

[![Crates.io](https://img.shields.io/crates/v/deps-npm)](https://crates.io/crates/deps-npm)
[![docs.rs](https://img.shields.io/docsrs/deps-npm)](https://docs.rs/deps-npm)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-npm)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

npm/package.json support for deps-lsp.

This crate provides parsing and registry integration for the npm ecosystem.

## Features

- **JSON Parsing** — Parse `package.json` with position tracking
- **npm Registry** — Client for npm registry API
- **Version Resolution** — Node semver-aware version matching
- **Scoped Packages** — Support for `@scope/package` format

## Usage

```toml
[dependencies]
deps-npm = "0.2"
```

```rust
use deps_npm::{NpmParser, NpmRegistry};
```

## License

[MIT](../../LICENSE)

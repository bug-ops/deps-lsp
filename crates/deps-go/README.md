# deps-go

[![Crates.io](https://img.shields.io/crates/v/deps-go)](https://crates.io/crates/deps-go)
[![docs.rs](https://img.shields.io/docsrs/deps-go)](https://docs.rs/deps-go)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-go)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Go modules support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for Go's module ecosystem and implements `deps_core::Ecosystem`.

## Features

- **go.mod parsing** — Parse all directives with byte-accurate position tracking
- **go.sum lock file** — Extract resolved versions from `go.sum`
- **Directive support** — Handle `require`, `replace`, `exclude`, and `retract` directives
- **Indirect dependencies** — Detect and mark `// indirect` annotations
- **Pseudo-versions** — Parse and validate the `v0.0.0-YYYYMMDDHHMMSS-hash` format
- **proxy.golang.org** — Fetch module versions from the Go module proxy
- **Module path escaping** — Proper URL encoding for uppercase characters per Go spec

## Installation

```toml
[dependencies]
deps-go = "0.9.3"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_go::{parse_go_mod, GoRegistry};

let dependencies = parse_go_mod(content, &uri)?;
let registry = GoRegistry::new(cache);
let versions = registry.get_versions("github.com/gin-gonic/gin").await?;
```

## Supported directives

### require

```go
require github.com/gin-gonic/gin v1.9.1
require (
    github.com/stretchr/testify v1.8.4
    golang.org/x/sync v0.5.0 // indirect
)
```

### replace

```go
replace github.com/old/module => github.com/new/module v1.0.0
replace github.com/local/module => ../local/module
```

### exclude

```go
exclude github.com/pkg/module v1.2.3
```

## Pseudo-version support

Handles Go's pseudo-version format for unreleased commits:

```
v0.0.0-20191109021931-daa7c04131f5
```

Extracts base version and timestamp for display.

## License

[MIT](../../LICENSE)

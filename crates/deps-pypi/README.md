# deps-pypi

[![Crates.io](https://img.shields.io/crates/v/deps-pypi)](https://crates.io/crates/deps-pypi)
[![docs.rs](https://img.shields.io/docsrs/deps-pypi)](https://docs.rs/deps-pypi)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-pypi)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

PyPI/Python support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for Python's PyPI ecosystem and implements `deps_core::Ecosystem`.

## Features

- **PEP 621** — Parse `[project.dependencies]` and `[project.optional-dependencies]`
- **PEP 735** — Parse `[dependency-groups]` (new standard)
- **Poetry** — Parse `[tool.poetry.dependencies]` and dependency groups
- **Lock file parsing** — Extract resolved versions from `poetry.lock` and `uv.lock`
- **PEP 508 parsing** — Handle complex dependency specifications with extras and environment markers
- **PEP 440 versions** — Validate and compare Python version specifiers
- **PyPI API client** — Fetch package metadata from the PyPI JSON API

## Installation

```toml
[dependencies]
deps-pypi = "0.9.2"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_pypi::{parse_pyproject_toml, PyPiRegistry};

let dependencies = parse_pyproject_toml(content)?;
let registry = PyPiRegistry::new(cache);
let versions = registry.get_versions("requests").await?;
```

## Supported formats

### PEP 621 (standard)

```toml
[project]
dependencies = [
    "requests>=2.28.0,<3.0",
    "flask[async]>=3.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "mypy>=1.0"]
```

### PEP 735 (dependency groups)

```toml
[dependency-groups]
test = ["pytest>=7.0", "coverage"]
dev = [{include-group = "test"}, "mypy>=1.0"]
```

### Poetry

```toml
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
```

## Benchmarks

```bash
cargo bench -p deps-pypi
```

Parsing performance: ~5 us for PEP 621, ~8 us for Poetry format.

## License

[MIT](../../LICENSE)

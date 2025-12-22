# deps-pypi

[![Crates.io](https://img.shields.io/crates/v/deps-pypi)](https://crates.io/crates/deps-pypi)
[![docs.rs](https://img.shields.io/docsrs/deps-pypi)](https://docs.rs/deps-pypi)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-pypi)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

PyPI/Python support for deps-lsp.

This crate provides parsing and registry integration for Python's PyPI ecosystem.

## Features

- **PEP 621 Support** — Parse `[project.dependencies]` and `[project.optional-dependencies]`
- **PEP 735 Support** — Parse `[dependency-groups]` (new standard)
- **Poetry Support** — Parse `[tool.poetry.dependencies]` and groups
- **PEP 508 Parsing** — Handle complex dependency specifications with extras and markers
- **PEP 440 Versions** — Validate and compare Python version specifiers
- **PyPI API Client** — Fetch package metadata from PyPI JSON API
- **EcosystemHandler** — Implements `deps_core::EcosystemHandler` trait

## Usage

```toml
[dependencies]
deps-pypi = "0.2"
```

```rust
use deps_pypi::{parse_pyproject_toml, PyPiRegistry};

let dependencies = parse_pyproject_toml(content)?;
let registry = PyPiRegistry::new(cache);
let versions = registry.get_versions("requests").await?;
```

## Supported Formats

### PEP 621 (Standard)

```toml
[project]
dependencies = [
    "requests>=2.28.0,<3.0",
    "flask[async]>=3.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "mypy>=1.0"]
```

### PEP 735 (Dependency Groups)

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

Parsing performance: ~5μs for PEP 621, ~8μs for Poetry format.

## License

[MIT](../../LICENSE)

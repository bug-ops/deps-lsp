# deps-pypi

[![Crates.io](https://img.shields.io/crates/v/deps-pypi)](https://crates.io/crates/deps-pypi)
[![docs.rs](https://img.shields.io/docsrs/deps-pypi)](https://docs.rs/deps-pypi)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-pypi)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

PyPI/Python support for deps-lsp.

This crate provides parsing, validation, and registry client functionality for Python dependency management in `pyproject.toml` files, supporting both PEP 621 and Poetry formats.

## Features

- **PEP 621 Support**: Parse `[project.dependencies]` and `[project.optional-dependencies]`
- **Poetry Support**: Parse `[tool.poetry.dependencies]` and `[tool.poetry.group.*.dependencies]`
- **PEP 508 Parsing**: Handle complex dependency specifications with extras and markers
- **PEP 440 Versions**: Validate and compare Python version specifiers
- **PyPI API Client**: Fetch package metadata from PyPI JSON API with HTTP caching

## Usage

```rust
use deps_pypi::{PypiParser, PypiRegistry};
use deps_core::PackageRegistry;

// Parse pyproject.toml
let content = std::fs::read_to_string("pyproject.toml")?;
let parser = PypiParser::new();
let dependencies = parser.parse(&content)?;

// Fetch versions from PyPI
let registry = PypiRegistry::new();
let versions = registry.get_versions("requests").await?;
```

## Supported Formats

### PEP 621 (Standard)

```toml
[project]
dependencies = [
    "requests>=2.28.0,<3.0",
    "flask[async]>=3.0",
    "numpy>=1.24; python_version>='3.9'",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "mypy>=1.0"]
```

### Poetry

```toml
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"
flask = {version = "^3.0", extras = ["async"]}

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
mypy = "^1.0"
```

## License

MIT

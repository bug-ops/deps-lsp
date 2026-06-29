# deps-dart

[![Crates.io](https://img.shields.io/crates/v/deps-dart)](https://crates.io/crates/deps-dart)
[![docs.rs](https://img.shields.io/docsrs/deps-dart)](https://docs.rs/deps-dart)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-dart)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

pubspec.yaml support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the Dart/Pub ecosystem and implements `deps_core::Ecosystem`.

## Features

- **YAML parsing** — Parse `pubspec.yaml` with position tracking for `dependencies`, `dev_dependencies`, and `dependency_overrides`
- **Lock file parsing** — Extract resolved versions from `pubspec.lock`
- **pub.dev registry** — Client for the pub.dev API with version lookups and package metadata
- **Dependency sources** — Support for hosted, git, path, and SDK sources
- **Caret semantics** — Dart-specific `^X.Y.Z` version constraint matching
- **Git sub-path** — Handle `path:` inside git repositories

## Installation

```toml
[dependencies]
deps-dart = "0.9.4"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_dart::{parse_pubspec_yaml, PubDevRegistry};

let result = parse_pubspec_yaml(content, &uri)?;
let registry = PubDevRegistry::new(cache);
let versions = registry.get_versions("flutter").await?;
```

## Supported pubspec.yaml syntax

```yaml
dependencies:
  flutter:
    sdk: flutter
  http: ^1.2.0
  provider: ">=6.0.0 <7.0.0"
  my_local_pkg:
    path: ../my_local_pkg
  my_git_pkg:
    git:
      url: https://github.com/user/my_git_pkg.git
      ref: main

dev_dependencies:
  flutter_test:
    sdk: flutter
  build_runner: ^2.4.0

dependency_overrides:
  some_package: 1.0.0
```

## License

[MIT](../../LICENSE)

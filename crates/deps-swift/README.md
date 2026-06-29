# deps-swift

[![Crates.io](https://img.shields.io/crates/v/deps-swift)](https://crates.io/crates/deps-swift)
[![docs.rs](https://img.shields.io/docsrs/deps-swift)](https://docs.rs/deps-swift)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-swift)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Swift Package Manager support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for the Swift/SPM ecosystem and implements `deps_core::Ecosystem`.

## Features

- **Regex-based parser** — Parse all 9 `.package()` call signatures without requiring a Swift toolchain
- **GitHub API registry** — Resolve versions from repository tags via the GitHub REST API
- **Lock file parsing** — Extract resolved versions from `Package.resolved`
- **All version forms** — `from`, `upToNextMajor`, `upToNextMinor`, `exact`, half-open range, closed range, `branch`, `revision`, `path`
- **GITHUB_TOKEN support** — Authenticated requests raise the rate limit from 60 to 5,000 requests/hour

> [!TIP]
> Set `GITHUB_TOKEN` in your environment to avoid GitHub API rate limits when working with many Swift dependencies.

## Installation

```toml
[dependencies]
deps-swift = "0.9.4"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_swift::{parse_package_swift, SwiftRegistry};

let result = parse_package_swift(content)?;
let registry = SwiftRegistry::new(cache);
let versions = registry.get_versions("apple/swift-nio").await?;
```

## Supported Package.swift syntax

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyPackage",
    dependencies: [
        // from (upToNextMajor implicit)
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        // explicit upToNextMajor
        .package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "4.99.0")),
        // upToNextMinor
        .package(url: "https://github.com/apple/swift-log.git", .upToNextMinor(from: "1.5.0")),
        // exact version
        .package(url: "https://github.com/nicklockwood/SwiftFormat.git", exact: "0.53.5"),
        // branch
        .package(url: "https://github.com/user/repo.git", branch: "main"),
        // path (local)
        .package(path: "../MyLocalPackage"),
    ]
)
```

## License

[MIT](../../LICENSE)

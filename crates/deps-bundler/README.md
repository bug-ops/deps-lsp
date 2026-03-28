# deps-bundler

[![Crates.io](https://img.shields.io/crates/v/deps-bundler)](https://crates.io/crates/deps-bundler)
[![docs.rs](https://img.shields.io/docsrs/deps-bundler)](https://docs.rs/deps-bundler)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-bundler)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Gemfile support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides Bundler-specific functionality including Gemfile DSL parsing, dependency extraction, and rubygems.org registry integration, and implements `deps_core::Ecosystem`.

## Features

- **Gemfile parsing** — Parse `Gemfile` with position tracking via a regex-based DSL parser
- **Lock file parsing** — Extract resolved versions from `Gemfile.lock`
- **rubygems.org registry** — HTTP client for version lookups and package search
- **Version resolution** — Ruby-aware version matching with pessimistic operator (`~>`)
- **Dependency sources** — Support for registry, git, path, and github dependencies
- **Group handling** — Handle `:development`, `:test`, `:production` groups

## Installation

```toml
[dependencies]
deps-bundler = "0.9.3"
```

> [!IMPORTANT]
> Requires Rust 1.89 or later.

## Usage

```rust
use deps_bundler::{parse_gemfile, RubyGemsRegistry};

let result = parse_gemfile(content, &uri)?;
let registry = RubyGemsRegistry::new(cache);
let versions = registry.get_versions("rails").await?;
```

## Supported Gemfile syntax

```ruby
source "https://rubygems.org"

gem "rails", "~> 7.0"
gem "pg", ">= 1.1"
gem "puma", require: false

group :development, :test do
  gem "rspec-rails"
end

gem "my_gem", git: "https://github.com/user/repo.git"
gem "local_gem", path: "../local_gem"
```

## License

[MIT](../../LICENSE)

# deps-bundler

[![Crates.io](https://img.shields.io/crates/v/deps-bundler)](https://crates.io/crates/deps-bundler)
[![docs.rs](https://img.shields.io/docsrs/deps-bundler)](https://docs.rs/deps-bundler)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-bundler)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Gemfile support for deps-lsp.

This crate provides Bundler-specific functionality for the deps-lsp server, including Gemfile DSL parsing, dependency extraction, and rubygems.org registry integration.

## Features

- **Gemfile Parsing** — Parse `Gemfile` with position tracking using regex-based DSL parser
- **Lock File Parsing** — Extract resolved versions from `Gemfile.lock`
- **rubygems.org Registry** — HTTP client for version lookups and package search
- **Version Resolution** — Ruby-aware version matching with pessimistic operator (`~>`)
- **Dependency Sources** — Support for registry, git, path, and github dependencies
- **Group Handling** — Handle `:development`, `:test`, `:production` groups
- **Ecosystem Trait** — Implements `deps_core::Ecosystem` trait

## Usage

```toml
[dependencies]
deps-bundler = "0.5"
```

```rust
use deps_bundler::{parse_gemfile, RubyGemsRegistry};

let result = parse_gemfile(content, &uri)?;
let registry = RubyGemsRegistry::new(cache);
let versions = registry.get_versions("rails").await?;
```

## Supported Gemfile Syntax

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

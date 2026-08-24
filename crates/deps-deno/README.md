# deps-deno

[![Crates.io](https://img.shields.io/crates/v/deps-deno)](https://crates.io/crates/deps-deno)
[![docs.rs](https://img.shields.io/docsrs/deps-deno)](https://docs.rs/deps-deno)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-deno)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Deno/JSR support for deps-lsp.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides parsing and registry integration for `deno.json`/`deno.jsonc` and implements `deps_core::Ecosystem`.

## Features

- **JSONC parsing** — Parse `deno.json`/`deno.jsonc` (comments tolerated) with exact position tracking for every `imports` entry, via `jsonc-parser`'s AST rather than text search
- **Dual registry routing** — `jsr:` specifiers resolve against the keyless JSR API; `npm:` specifiers reuse the existing `deps-npm` registry client unchanged, through one dispatching `Registry` facade
- **Node semver resolution** — Full `^`, `~`, `>=`, `<`, range support for both `jsr:` and `npm:` requirements (JSR mandates strict semver)
- **Scoped packages** — `@scope/pkg` names for both registries
- **Freshness at zero extra cost** — JSR's `meta.json` carries per-version publish dates in the same response `get_versions` already fetches

## Installation

```toml
[dependencies]
deps-deno = "0.11"
```

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Usage

```rust
use deps_deno::{parse_deno_json, DenoRegistry};
use std::sync::Arc;

let result = parse_deno_json(content, &uri)?;
let registry = DenoRegistry::new(Arc::new(deps_core::HttpCache::new()));
```

## Architecture

A `deno.json` `imports` map mixes two registries in one file, so a dependency's package
name is scheme-qualified (`"jsr:@std/fs"`, `"npm:react"`) rather than bare — this is what
lets `DenoRegistry` route each lookup to the right registry, and it is why hover/completion
render the scheme as part of the package name. See the crate's module docs
(`src/registry.rs`) for the full rationale.

## Known limitations

- No `deno.lock` support — hover/completion/diagnostics compare against the manifest
  requirement, not a resolved version (consistent with Gradle's lockfile-free MVP)
- The `scopes` field and `importMap` file are not parsed — only the `imports` map
- The yanked-only-match diagnostic is restricted to exact-pin requirements for both `jsr:`
  and `npm:` specifiers (matches `deps-npm`'s own restriction, for the same reason:
  avoiding false positives from package-wide deprecation)
- Package-name completion works for a bare, still-being-typed `jsr:`/`npm:` specifier
  (`"jsr:"`, `"jsr:@"`, `"jsr:@std"`, `"jsr:@std/"`): `partial_name_range` in
  `specifier.rs` models the in-progress name so completion has a dependency to attach to,
  even though `parse_specifier` itself correctly rejects those same values as incomplete

## License

[MIT](../../LICENSE)

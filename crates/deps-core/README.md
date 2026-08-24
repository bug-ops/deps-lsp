# deps-core

[![Crates.io](https://img.shields.io/crates/v/deps-core)](https://crates.io/crates/deps-core)
[![docs.rs](https://img.shields.io/docsrs/deps-core)](https://docs.rs/deps-core)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-core)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Core abstractions for deps-lsp: traits, caching, and generic LSP handlers.

This crate provides the shared infrastructure used by all ecosystem-specific crates in the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. Every ecosystem crate depends on `deps-core` and implements its `Ecosystem` trait.

## What this crate provides

- **`Ecosystem` trait** — Unified interface for all package ecosystems (parse, registry, format)
- **`EcosystemId` enum** — Exhaustive, typed identifier for every registered ecosystem, with `Display`/`FromStr` interop with `Ecosystem::id()`. Downstream code should match on this instead of the raw id string so a new ecosystem forces every relevant `match` to be updated at compile time
- **`PackageName`/`VersionReq` newtypes** — Distinguish a manifest package name from a version requirement string at the type level, threaded through `Registry`, `Ecosystem`, and `EcosystemFormatter` so the two cannot be swapped at a call site
- **`Registry` trait** — Abstraction over package registries with version lookup
- **`freshness` module** — Release-freshness signal (`PublishTime`, `FreshnessSettings`, `is_within_cooldown`) flagging a "latest" version still inside its cooldown window, mirroring GitHub Dependabot's default 3-day package cooldown
- **`LockFileProvider` trait** — Abstract lock file parsing for resolved versions
- **Generic LSP handlers** — `generate_inlay_hints`, `generate_hover`, `generate_code_actions`, `generate_diagnostics`, `generate_code_lenses`, taking a bundled `VersionData` (cached + resolved version maps) to avoid swapping same-typed arguments at call sites
- **`collect_update_all_edits`** — batch `TextEdit`s bringing every safely-editable outdated dependency to latest, shared across all ecosystems; guards against rewriting a `version_range` that isn't actually the version literal (property references, DSL variables, catalog aliases, synthesized range bounds)
- **`HttpCache`** — ETag/Last-Modified caching for registry HTTP requests, with a streaming 32 MiB response-size cap
- **`osv::OsvClient`** — batches dependency versions against the [OSV.dev](https://osv.dev) vulnerability database (`POST /v1/querybatch`), resolves matching advisories, and caches both queries and records independently of `HttpCache` (OSV sends no cache validators). `EcosystemId::osv_ecosystem()` and `EcosystemFormatter::osv_package_name()` provide the per-ecosystem mapping
- **`check_toml_nesting_depth`** — single-pass structural guard rejecting pathologically nested TOML (bracket depth and dotted-key/header segment count) before it reaches the recursive-descent `toml_span` parser
- **`check_yaml_nesting_depth`** — single-pass structural guard rejecting pathologically nested YAML (flow bracket depth and block-style indentation/dash-chain nesting) before it reaches the recursive-descent `yaml-rust2` parser
- **`check_yaml_expansion`** — streaming pre-pass over `yaml-rust2`'s own parser event stream rejecting YAML whose anchor/alias references would expand to an excessive number of allocated bytes (billion-laughs-style), independent of nesting depth
- **`lockfile::read_lockfile_content`** — shared read-and-error-wrap helper for lock file parsers
- **Error types** — Unified error handling with `thiserror`

## Installation

```toml
[dependencies]
deps-core = "0.11"
```

> [!IMPORTANT]
> Requires Rust 1.91 or later.

## Implementing a new ecosystem

```rust
use deps_core::{Ecosystem, Registry, ParseResult};

pub struct MyEcosystem {
    registry: Arc<MyRegistry>,
}

impl Ecosystem for MyEcosystem {
    fn id(&self) -> &'static str { "my-ecosystem" }
    fn display_name(&self) -> &'static str { "My Ecosystem" }

    fn matches_uri(&self, uri: &Uri) -> bool {
        uri.path().ends_with("my-manifest.json")
    }

    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<ParseResult> {
        // Parse the manifest and return dependencies with source positions
        todo!()
    }
}
```

## License

[MIT](../../LICENSE)

# deps-engine

[![Crates.io](https://img.shields.io/crates/v/deps-engine)](https://crates.io/crates/deps-engine)
[![docs.rs](https://img.shields.io/docsrs/deps-engine)](https://docs.rs/deps-engine)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-engine)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

The composition root for the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace.

This crate exists only because Cargo forbids a cycle: `deps-core` cannot depend on any
`deps-<ecosystem>` crate, since all 14 already depend on `deps-core`. `deps-engine` sits one
layer above `deps-core` and depends on every feature-gated `deps-<ecosystem>` crate instead,
so every driving adapter (`deps-lsp`, and future `deps-cli`/`deps-mcp`) shares one
registration instead of each reimplementing it independently.

Not a user-facing crate — nothing here is meant to be consumed directly outside this
workspace's own adapter crates.

## What this crate contains

- `setup::EcosystemRuntime` — bundles the live-updatable settings (`registries.*`) an adapter
  threads into the ecosystems that need them
- `setup::register_ecosystems` — wires every feature-enabled `deps-<ecosystem>` crate into a
  `deps_core::EcosystemRegistry`
- `setup::EcosystemRuntime::from_policy` — builds a runtime from a
  `deps_core::policy_config::PolicyConfig` snapshot

## Installation

```toml
[dependencies]
deps-engine = { version = "1.0", default-features = false, features = ["cargo", "npm"] }
```

> [!IMPORTANT]
> Requires Rust 1.98 or later. This crate deliberately declares no `default` feature list —
> a consuming adapter must forward the exact ecosystem features it wants (see
> `deps-lsp/Cargo.toml`'s `cargo = ["deps-engine/cargo"]`-style forwarding), or Cargo would
> otherwise activate every ecosystem feature regardless of the adapter's own selection.

## Feature flags

One flag per ecosystem — `cargo`, `npm`, `pypi`, `go`, `bundler`, `dart`, `maven`, `gradle`,
`swift`, `composer`, `nuget`, `deno`, `github-actions`, `gitlab-ci` — each gating that
ecosystem crate's optional dependency and its `ecosystem!`-generated re-exports.

## License

MIT — see [LICENSE](../../LICENSE).

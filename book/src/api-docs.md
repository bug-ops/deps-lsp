# API Documentation

This book covers ecosystem behavior and how to extend `deps-lsp`. Generated Rust API
documentation (rustdoc) for every crate in the workspace is published on
[docs.rs](https://docs.rs), since every crate is published to crates.io independently. There is
no single combined API-docs page — each crate has its own docs.rs entry, following the pattern
`https://docs.rs/<crate-name>`:

- [`deps-lsp`](https://docs.rs/deps-lsp) — the LSP binary
- [`deps-core`](https://docs.rs/deps-core) — shared abstractions (the `Ecosystem` trait, registry
  client contracts, OSV.dev/deps.dev clients, LSP response helpers)
- [`deps-cli`](https://docs.rs/deps-cli) — the CLI
- [`deps-engine`](https://docs.rs/deps-engine) — the shared classification pipeline behind both
  `deps-lsp` and `deps-cli`
- Each ecosystem crate: `https://docs.rs/deps-<ecosystem>`, e.g.
  [`deps-cargo`](https://docs.rs/deps-cargo), [`deps-npm`](https://docs.rs/deps-npm),
  [`deps-pypi`](https://docs.rs/deps-pypi) — substitute the ecosystem name from the
  [Ecosystem Reference](ecosystems/index.md) for any of the 14 supported ecosystems

Use the API docs when you need exact type signatures, trait bounds, or module-level rustdoc;
use this book when you need to understand ecosystem-level behavior or the reasoning behind a
design decision.

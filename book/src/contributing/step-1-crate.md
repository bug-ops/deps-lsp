# Step 1: Create the Crate

Create a new crate with workspace dependencies:

```toml
# crates/deps-{ecosystem}/Cargo.toml
[package]
name = "deps-{ecosystem}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
description = "{Ecosystem} support for deps-lsp"
publish = true

[lints]
workspace = true

[features]
# Gates this crate's own `tower-lsp-server` dependency and LSP-response-shaped code
# (issue #1083, spec 064) — NOT `default`, since Cargo does not allow a `workspace = true`
# dependency edge to turn off a default feature, which would make this inescapable for
# `deps-engine`. `deps-lsp` requests it (directly or via `deps-engine`'s own
# `lsp-responses` feature); `deps-cli` never does, keeping `tower-lsp-server` out of its
# dependency tree entirely. Forward it to `deps-core` too: `lsp-responses = ["dep:tower-lsp-server", "deps-core/lsp-responses"]`.
lsp-responses = ["dep:tower-lsp-server", "deps-core/lsp-responses"]

[dependencies]
deps-core = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tower-lsp-server = { workspace = true, optional = true }
tracing = { workspace = true }
url = { workspace = true }

[dev-dependencies]
deps-core = { workspace = true, features = ["test-util"] }
tokio-test = { workspace = true }
url = { workspace = true }
```

> **Note:** every `#[cfg(feature = "lsp-responses")]`-gated item in this crate (LSP
> `CompletionItem`/`Range`/`Position` construction, `generate_completions`, etc.) needs this
> feature enabled to compile and to be exercised by tests — see the `lsp-responses`
> feature comment above and [Step 6](step-6-ecosystem-trait.md) for what it gates in practice.

No workspace-membership edit is needed: root `Cargo.toml`'s `[workspace] members` is the glob
`crates/*`, so a new `crates/deps-{ecosystem}` directory with a `Cargo.toml` is picked up
automatically. It only needs an explicit mention in root `Cargo.toml` if it should be
*excluded* from the workspace instead (like `crates/deps-zed`, a separate git submodule, or
`crates/github-action`, a plain Docker action with no `Cargo.toml` at all) — see that file's
`exclude` list.


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

[dependencies]
deps-core = { path = "../deps-core" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tower-lsp-server = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio-test = { workspace = true }
```

Add to workspace in root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members
    "crates/deps-{ecosystem}",
]
```


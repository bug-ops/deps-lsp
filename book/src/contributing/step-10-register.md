# Step 10: Register the Ecosystem

> **Note:** this composition root lives in `crates/deps-engine/src/setup.rs`, not in
> `deps-lsp` itself — see [The deps-engine crate](../engine.md) for why. `deps-lsp` and
> `deps-cli` both call the same [`deps_engine::setup::register_ecosystems`] function instead
> of each maintaining their own registration list, so a new ecosystem crate only needs to be
> wired in once for both adapters to pick it up.

In `crates/deps-engine/src/setup.rs`, add your ecosystem using the macros:

```rust
// 1. Add a re-export block using the ecosystem! macro
ecosystem!(
    "{ecosystem_id}",        // Feature flag name (crates/deps-engine/Cargo.toml and
                              // crates/deps-lsp/Cargo.toml/crates/deps-cli/Cargo.toml must
                              // all declare/forward it)
    deps_{ecosystem},        // Crate name
    {Ecosystem}Ecosystem,    // Main ecosystem type
    [
        {Ecosystem}Dependency,
        {Ecosystem}Version,
        {Ecosystem}Registry,
        // ... every other public type this crate exports that a caller of
        // deps_engine might need, e.g. its ParseResult/Formatter/LockParser types
    ]
);

// 2. Add a registration line inside register_ecosystems()
pub fn register_ecosystems(
    registry: &EcosystemRegistry,
    cache: Arc<HttpCache>,
    runtime: &EcosystemRuntime,
) -> Vec<&'static str> {
    // ... existing #[cfg(feature = "...")] blocks for cargo/npm/pypi/go/... ...

    // Add your ecosystem here. Most ecosystems use the plain register! macro:
    #[cfg(feature = "{ecosystem_id}")]
    register!("{ecosystem_id}", {Ecosystem}Ecosystem, registry, &cache);

    // ... existing workspace_registry_ecosystems tracking, if your ecosystem consumes
    // RegistryAccessPolicy (see the EcosystemRuntime note below) ...
}
```

The `ecosystem!`/`register!` macros handle feature-gating automatically — when the feature is
disabled, both the re-export and the registration are compiled out. Most ecosystems register
with the plain `register!("{ecosystem_id}", {Ecosystem}Ecosystem, registry, &cache)` call
shown above; a handful (Cargo, npm, Deno) are special-cased directly in
`register_ecosystems`'s body instead, because they need extra construction-time context
(`EcosystemRuntime`'s `RegistryAccessPolicy`, an `npm`/`deno` shared registry client) that
`register!`'s generic `Ecosystem::new(cache)` call can't thread through — only follow one of
those special-cased patterns if your ecosystem genuinely needs live-updatable policy or a
shared client; otherwise the plain macro call is correct.

If your ecosystem needs to consult `registries.workspace_registries` (custom/private registry
host reachability — see [Cargo](../ecosystems/cargo.md#customprivate-registries)), push its id
onto the `Vec<&'static str>` this function returns, and thread `EcosystemRuntime`'s `policy`
field into your parser the same way Cargo's `#[cfg(feature = "cargo")]` block does.

[`deps_engine::setup::register_ecosystems`]: https://github.com/bug-ops/deps-lsp/blob/main/crates/deps-engine/src/setup.rs


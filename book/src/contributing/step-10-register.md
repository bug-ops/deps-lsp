# Step 10: Register the Ecosystem

In `deps-lsp/src/lib.rs`, add your ecosystem using the macros:

```rust
// 1. Add re-exports using the ecosystem! macro
ecosystem!(
    "{ecosystem_id}",        // Feature flag name
    deps_{ecosystem},        // Crate name
    {Ecosystem}Ecosystem,    // Main ecosystem type
    [
        {Ecosystem}Dependency,
        {Ecosystem}Version,
        {Ecosystem}Registry,
        // ... other public types
    ]
);

// 2. Add registration in register_ecosystems() using the register! macro
pub fn register_ecosystems(registry: &EcosystemRegistry, cache: Arc<HttpCache>) {
    register!("cargo", CargoEcosystem, registry, &cache);
    register!("npm", NpmEcosystem, registry, &cache);
    register!("pypi", PypiEcosystem, registry, &cache);
    register!("go", GoEcosystem, registry, &cache);
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);

    // Add your ecosystem here:
    register!("{ecosystem_id}", {Ecosystem}Ecosystem, registry, &cache);
}
```

The macros handle feature-gating automatically. When the feature is disabled, both the re-exports and registration are compiled out.


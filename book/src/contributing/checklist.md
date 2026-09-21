# Checklist

Before submitting a PR for a new ecosystem:

- [ ] Error types with conversions to `deps_core::DepsError`
- [ ] Every public type prefixed with `<Ecosystem>` (`NpmDependency`, not `Dependency`) — see
      Step 3
- [ ] Types implementing `Dependency` and `Version` traits (with `source()` method)
- [ ] A new variant added to `deps_core::EcosystemId` (`crates/deps-core/src/ecosystem.rs`'s
      `ecosystem_ids!` invocation) — `Ecosystem::ecosystem_id()` returns this variant, and
      every existing exhaustive `match` on `EcosystemId` across the workspace must be updated
      to handle it
- [ ] Parser with accurate position tracking for names AND versions
- [ ] Lock file parser implementing `LockFileProvider` trait (`locate_lockfile` + `parse_lockfile`)
- [ ] Formatter implementing `PackageRendering` (`format_version_for_text_edit` + `package_url`)
      plus the other six `EcosystemFormatter` concern traits — never `impl EcosystemFormatter`
      directly, it is a blanket impl
- [ ] Registry client implementing `deps_core::Registry` trait with BoxFuture signatures
- [ ] Ecosystem impl with `impl deps_core::ecosystem::private::Sealed` block (the workspace's
      documented-contract sealing convention, not a compiler-enforced restriction)
- [ ] `completion_insert_text` implemented (required, no default — issue #722); override
      `fallback_completion_prefix` too if this manifest format has a raw-text
      dependencies-section boundary to detect, reusing `deps_core::fallback_completion`'s
      shared TOML/JSON/XML-tag scanners where the syntax shape matches an existing one
- [ ] Unit tests for parser edge cases
- [ ] Integration tests for registry (can be `#[ignore]`)
- [ ] Documentation in lib.rs with examples
- [ ] No workspace-members edit needed (root `Cargo.toml`'s `members` is the `crates/*` glob —
      see [Step 1](step-1-crate.md)); do add an `lsp-responses` feature forwarding to
      `deps-core/lsp-responses`, gating this crate's own `tower-lsp-server` dependency
- [ ] `[lints] workspace = true` in the new crate's Cargo.toml (otherwise it silently gets
      none of the `indexing_slicing`/`unwrap_used`/`expect_used`/`string_slice` restriction
      lints consolidated into `[workspace.lints.clippy]` by #689, and CI stays green)
- [ ] Feature flag added in `crates/deps-engine/Cargo.toml`, forwarded from
      `crates/deps-lsp/Cargo.toml` and (if the CLI should support it too)
      `crates/deps-cli/Cargo.toml`
- [ ] Re-exports via `ecosystem!()` macro in `crates/deps-engine/src/setup.rs`
- [ ] Registration via `register!()` macro inside `register_ecosystems()` in
      `crates/deps-engine/src/setup.rs` — see [Step 10](step-10-register.md)


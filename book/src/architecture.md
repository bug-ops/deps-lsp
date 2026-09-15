# Architecture Overview

Every ecosystem is a thin, independent implementation of a small set of shared abstractions
defined in `crates/deps-core`. The binary, `crates/deps-lsp`, wires ecosystem crates into a
running LSP server via `tower-lsp-server` and does not itself know anything ecosystem-specific.

## The `Ecosystem` trait

`Ecosystem` (`crates/deps-core/src/ecosystem.rs`) is the extension point every ecosystem crate
implements — see `crates/deps-cargo/src/ecosystem.rs` for a concrete example. It is a sealed
trait (`ecosystem::private::Sealed`), so it can only be implemented from inside this workspace.
Key pieces:

- **`EcosystemId`** — an exhaustive enum of every supported ecosystem, used anywhere code needs
  to branch on ecosystem identity instead of re-deriving a partial string match. Adding a new
  ecosystem forces every exhaustive `match` on this type to be updated at compile time.
- **`ParseResult` / `Dependency`** — trait-object interfaces a parser returns; ecosystem-specific
  dependency types are exposed generically but remain downcastable via `as_any()`.
- **Routing** — `manifest_filenames()` (exact match) → `manifest_patterns()` (basename glob) →
  `manifest_extensions()` (e.g. `.csproj`) → `manifest_directory_patterns()` (path-suffix match,
  e.g. `.github/workflows/*.yml`) — checked in that order by `EcosystemRegistry`.
- **`generate_hover` / `generate_diagnostics` / `generate_code_actions` / `generate_code_lenses`
  / `generate_inlay_hints`** all have default implementations delegating to shared logic in
  `deps-core::lsp_helpers`, driven by the ecosystem's own `formatter()` (an `EcosystemFormatter`
  implementation) and `registry()` (a `Registry` implementation) — most ecosystem crates only
  need to supply parsing plus a formatter and a registry client, not reimplement LSP response
  generation. Override a `generate_*` method only for genuine ecosystem-specific behavior.
- **`generate_completions`** has no default — every ecosystem must implement it directly (see
  `deps-core::completion::complete_versions_generic` for the shared version-completion helper
  most ecosystems build on).

## `Registry` and `EcosystemFormatter`

- **`Registry`** (`deps-core::registry`) is the trait every ecosystem's registry client
  implements for version lookup and search.
- **`EcosystemFormatter`** governs version display formatting (the `EcosystemFormatter`
  contract lives under `deps-core::lsp_helpers`).

## Cross-ecosystem consistency is a first-class design rule

A feature implemented for one ecosystem but not shared through `deps-core` — instead of
reimplemented per-crate — is treated as a bug class in this project. Concretely: JSON
position/AST parsing (`deps-core::json_ast`), non-string dependency-value guards
(`deps-core::json_helpers`), file-size-capped reads (`deps-core::fs_probe::read_to_string_capped`
— the single TOCTOU-safe read path), and ancestor-config-search depth
(`MAX_CONFIG_ANCESTOR_DEPTH`) are all centralized in `deps-core` specifically because the same
fix was independently needed in two or more ecosystem crates at some point. When adding logic
that touches more than one ecosystem crate, check `deps-core::json_ast`, `json_helpers`,
`fs_probe`, `pagination`, `git_ref`, and `lsp_helpers` first for an existing shared helper before
writing ecosystem-local code.

## Crate layout

Each ecosystem is implemented as a separate crate under `crates/deps-{ecosystem}/` with the
following structure:

```text
crates/deps-{ecosystem}/
├── Cargo.toml
└── src/
    ├── lib.rs          # Re-exports and module declarations
    ├── ecosystem.rs    # Ecosystem trait implementation
    ├── error.rs        # Ecosystem-specific error types
    ├── formatter.rs    # Version display formatting
    ├── lockfile.rs     # Lock file parsing
    ├── parser.rs       # Manifest file parsing with position tracking
    ├── registry.rs     # Package registry API client
    └── types.rs        # Dependency, Version, and other types
```

The [Adding a New Ecosystem](contributing/index.md) chapters walk through building one of these
crates from scratch, step by step.

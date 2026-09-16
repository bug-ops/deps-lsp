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
  `deps-core::completion::complete_versions_at_position` for the shared, source-gated
  version-completion helper most ecosystems build on).

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

## Project Structure

```text
deps-lsp/
├── crates/
│   ├── deps-core/      # Shared traits, cache, generic handlers
│   ├── deps-cargo/     # Cargo.toml parser + crates.io registry
│   ├── deps-npm/       # package.json parser + npm registry
│   ├── deps-pypi/      # pyproject.toml/requirements.txt parser + PyPI registry
│   ├── deps-go/        # go.mod parser + proxy.golang.org
│   ├── deps-bundler/   # Gemfile parser + rubygems.org registry
│   ├── deps-dart/      # pubspec.yaml parser + pub.dev registry
│   ├── deps-maven/     # pom.xml parser + Maven Central registry
│   ├── deps-gradle/    # Gradle parser (Version Catalog, Kotlin/Groovy DSL)
│   ├── deps-swift/     # Package.swift parser + GitHub API registry
│   ├── deps-composer/  # composer.json parser + Packagist registry
│   ├── deps-nuget/     # .csproj/packages.config parser + NuGet V3 registry
│   ├── deps-deno/      # deno.json parser + JSR registry (npm: delegates to deps-npm)
│   ├── deps-github-actions/ # workflow YAML parser + GitHub tags API registry
│   ├── deps-gitlab-ci/ # .gitlab-ci.yml parser + GitLab tags/releases API registry
│   ├── deps-engine/    # Internal: ecosystem registration + verdict classification, shared by deps-lsp/deps-cli
│   ├── deps-lsp/       # Main LSP server
│   ├── deps-cli/       # `deps-cli check` — CLI for CI/pre-commit/shell workflows
│   ├── github-action/  # Docker-based GitHub Action wrapping `deps-cli check --format sarif`
│   └── deps-zed/       # Zed extension (WASM)
├── .config/            # nextest configuration
└── .github/            # CI/CD workflows
```

## Performance

`deps-lsp` is optimized for responsiveness — parallel per-dependency fetching, aggressive
caching, and non-blocking handlers keep the interactive paths fast even on a manifest with
hundreds of dependencies:

| Operation | Latency | Notes |
| ----------- | --------- | ------- |
| Document open (50 deps) | ~150ms | Parallel registry fetching |
| Inlay hints | <100ms | Cached version lookups |
| Hover | <50ms | Pre-fetched metadata |
| Code actions | <50ms | No network calls |
| Code lens | <50ms | No network calls; in-memory only |

Lock file support provides instant resolved versions without network requests.

Run performance benchmarks with criterion:

```bash
cargo bench --workspace
```

View the HTML report at `target/criterion/report/index.html`.

## Versioning Policy

`deps-core`'s public trait signatures (`Ecosystem`, `Dependency`, `ParseResult`,
`EcosystemFormatter`) — and its public `lsp_helpers` / `completion` helper functions — are typed
directly against `tower_lsp_server::ls_types` types. `tower-lsp-server` is pinned pre-1.0, so a
`tower-lsp-server` minor bump (e.g. 0.23 → 0.24) is not an implementation detail `deps-core` can
absorb silently — it forces a breaking release of `deps-core`: a minor version bump while
`deps-core` itself remains pre-1.0, a major version bump once `deps-core` reaches 1.0.

If you implement `Ecosystem` outside this workspace, depend on the exact matching
`tower-lsp-server` version via `deps_core::tower_lsp_server` rather than adding your own separate
direct dependency on `tower-lsp-server`, to avoid it drifting out of sync with the version
`deps-core` was built against.

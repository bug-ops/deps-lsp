# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.91-blue)](https://blog.rust-lang.org/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

A universal Language Server Protocol (LSP) server for dependency management across Cargo, npm, PyPI, Go, Bundler, Dart, Maven, Gradle, Swift, Composer, NuGet, Deno, and GitHub Actions ecosystems.

![deps-lsp in action](https://raw.githubusercontent.com/bug-ops/deps-zed/main/assets/img.png)

## Features

- **Intelligent autocomplete** — Package names, versions, and feature flags
- **Version hints** — Inlay hints showing latest available versions
- **Loading indicators** — Visual feedback during registry fetches with LSP progress support
- **Lock file support** — Reads resolved versions from Cargo.lock, package-lock.json, poetry.lock, uv.lock, go.sum, Gemfile.lock, pubspec.lock, Package.resolved, composer.lock
- **Diagnostics** — Warnings for outdated, unknown, yanked, unsatisfiable-requirement, or deprecated/abandoned dependencies
- **Vulnerability scanning** — OSV.dev-backed advisories in diagnostics and hover, across all supported ecosystems
- **Supply-chain trust signal** — OpenSSF Scorecard score and SLSA/attestation provenance status in hover, via deps.dev, for npm, Cargo, Go, Maven, PyPI, Bundler, and NuGet
- **Release-freshness signal** — Flags a "latest" version still within a cooldown window in hover and completion, mirroring GitHub Dependabot's default 3-day package cooldown
- **Hover information** — Package descriptions with resolved version from lock file
- **Code actions** — Quick fixes to update dependencies, resolve unsatisfiable version requirements, and upgrade to a patched version for known vulnerabilities
- **Code lens** — "Update N outdated dependencies" batch update on every open manifest
- **High performance** — Parallel fetching with per-dependency timeouts, optimized caching

## Supported ecosystems

| Language | Ecosystem | Manifest file | Status |
| ---------- | ----------- | --------------- | -------- |
| Rust | Cargo | `Cargo.toml` | Supported |
| JavaScript | npm | `package.json` | Supported |
| JavaScript/TypeScript | Deno (JSR/npm) | `deno.json`, `deno.jsonc` | Supported |
| Python | PyPI | `pyproject.toml`, `requirements.txt`, `constraints.txt` | Supported |
| Go | Go Modules | `go.mod` | Supported |
| Ruby | Bundler | `Gemfile` | Supported |
| Dart | Pub | `pubspec.yaml` | Supported |
| Java | Maven | `pom.xml` | Supported |
| Java | Gradle | `libs.versions.toml`, `build.gradle.kts`, `build.gradle`, `settings.gradle` | Supported |
| Swift | SPM | `Package.swift` | Supported |
| PHP | Composer | `composer.json` | Supported |
| C# | NuGet | `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`, `packages.config` | Supported |
| YAML | GitHub Actions | `.github/workflows/*.yml`, `*.yaml` | Supported |

> [!NOTE]
> **Ecosystem details:**
> - **PyPI** — PEP 621, PEP 735 (dependency-groups), Poetry formats
> - **Go** — `require`, `replace`, `exclude` directives, pseudo-version handling
> - **Bundler** — git/path/GitHub sources, pessimistic operator (`~>`)
> - **Dart** — hosted, git, path, SDK sources, caret version semantics
> - **Maven** — `dependencies`, `dependencyManagement`, `build/plugins`, qualifier-aware version comparison
> - **Gradle** — Version Catalogs, Kotlin/Groovy DSL, `settings.gradle` plugins; resolves from Maven Central, Google Maven, Gradle Plugin Portal
> - **Swift** — all `.package()` forms (from, upToNextMajor/Minor, exact, range, branch, revision, path); versions via GitHub API tags
> - **Composer** — `require`/`require-dev` sections, Packagist v2 API with metadata de-minification, Composer-specific tilde semantics (`~1.2` = `>=1.2.0 <2.0.0`)
> - **NuGet** — `PackageReference` (attribute and child-element form), Central Package Management (`Directory.Packages.props`), legacy `packages.config`, `packages.lock.json`; NuGet V3 registry (service index, flat container, search); private/custom feed resolution via `NuGet.Config`
> - **Deno** — `imports` map only (`scopes`/`importMap` not yet supported); `jsr:` specifiers via the keyless JSR API, `npm:` specifiers reuse the existing npm registry client; no `deno.lock` support yet
> - **GitHub Actions** — `uses:` steps and reusable-workflow calls across every job; tag, commit-SHA (optionally `# vX.Y.Z`-annotated), and branch pins via the GitHub tags API; release-age hint and cooldown diagnostic require `GITHUB_TOKEN` (partial coverage, like Swift); no lock file, no package-name search completion

## Installation

### From crates.io

```bash
cargo install deps-lsp
```

> [!TIP]
> Use `cargo binstall deps-lsp` for faster installation without compilation.

### Pre-built binaries

Download from [GitHub Releases](https://github.com/bug-ops/deps-lsp/releases/latest):

| Platform | Architecture | Binary |
| ---------- | -------------- | -------- |
| Linux | x86_64 (glibc) | `deps-lsp-x86_64-unknown-linux-gnu` |
| Linux | aarch64 (glibc) | `deps-lsp-aarch64-unknown-linux-gnu` |
| Linux | x86_64 (musl) | `deps-lsp-x86_64-unknown-linux-musl` |
| Linux | aarch64 (musl) | `deps-lsp-aarch64-unknown-linux-musl` |
| macOS | x86_64 | `deps-lsp-x86_64-apple-darwin` |
| macOS | Apple Silicon | `deps-lsp-aarch64-apple-darwin` |
| Windows | x86_64 | `deps-lsp-x86_64-pc-windows-msvc.exe` |
| Windows | ARM64 | `deps-lsp-aarch64-pc-windows-msvc.exe` |

### From source

```bash
git clone https://github.com/bug-ops/deps-lsp
cd deps-lsp
cargo install --path crates/deps-lsp
```

## Feature flags

By default, all ecosystems are enabled. To build with specific ecosystems only:

```bash
# Only Cargo and npm support
cargo install deps-lsp --no-default-features --features "cargo,npm"

# Only Python support
cargo install deps-lsp --no-default-features --features "pypi"
```

| Feature | Language | Manifest | Default |
| --------- | ---------- | ----------- | ------- |
| `cargo` | Rust | Cargo.toml | Yes |
| `npm` | JavaScript | package.json | Yes |
| `deno` | JavaScript/TypeScript (Deno) | deno.json, deno.jsonc | Yes |
| `pypi` | Python | pyproject.toml, requirements.txt, constraints.txt | Yes |
| `go` | Go | go.mod | Yes |
| `bundler` | Ruby | Gemfile | Yes |
| `dart` | Dart | pubspec.yaml | Yes |
| `maven` | Java | pom.xml | Yes |
| `gradle` | Java | libs.versions.toml, build.gradle.kts, build.gradle | Yes |
| `swift` | Swift | Package.swift | Yes |
| `composer` | PHP | composer.json | Yes |
| `nuget` | C# | .csproj, Directory.Packages.props, packages.config | Yes |
| `github-actions` | YAML | .github/workflows/*.yml, *.yaml | Yes |

## Usage

Run the server over stdio (typical editor integration):

```bash
deps-lsp --stdio
```

> [!TIP]
> Configure your editor to launch `deps-lsp` and connect over stdio. See the editor snippets below.

## Editor setup

> [!IMPORTANT]
> Inlay hints, code lens, and (in some editors) inline diagnostics are off by default at the *editor* level, independent of `deps-lsp`'s own [`initialization_options`](#configuration). The server always advertises support for all three — each section below covers the editor-side toggle needed to actually see them.

### Zed

Install the **Deps** extension from Zed Extensions marketplace. Ruby support is enabled for Gemfile files.

Enable inlay hints, code lens, and (optionally) inline diagnostics in Zed settings:

```json
{
  "inlay_hints": {
    "enabled": true
  },
  "code_lens": "on",
  "diagnostics": {
    "inline": {
      "enabled": true
    }
  }
}
```

`code_lens` accepts `"on"`, `"off"` (default), or `"menu"`, and is required for the "Update N outdated dependencies" lens to appear. `diagnostics.inline` is optional — diagnostics already show in the gutter and Problems panel without it; this additionally renders `deps-lsp`'s short one-line messages inline next to each dependency.

### Neovim

```lua
require('lspconfig').deps_lsp.setup({
  cmd = { "deps-lsp", "--stdio" },
  filetypes = { "toml", "json", "gomod", "ruby", "yaml", "xml", "swift", "php", "requirements" },
})

-- Enable inlay hints (Neovim 0.10+)
vim.lsp.inlay_hint.enable(true)
```

For older Neovim versions, use [nvim-lsp-inlayhints](https://github.com/lvimuser/lsp-inlayhints.nvim).

**Code lens** is not refreshed or rendered automatically by Neovim's built-in client — wire it up via an `LspAttach` autocommand:

```lua
vim.api.nvim_create_autocmd("LspAttach", {
  callback = function(args)
    local client = vim.lsp.get_client_by_id(args.data.client_id)
    if client and client:supports_method("textDocument/codeLens") then
      vim.lsp.codelens.refresh({ bufnr = args.buf })
      vim.api.nvim_create_autocmd({ "BufEnter", "CursorHold", "InsertLeave" }, {
        buffer = args.buf,
        callback = function() vim.lsp.codelens.refresh({ bufnr = args.buf }) end,
      })
    end
  end,
})

vim.keymap.set("n", "<leader>cl", vim.lsp.codelens.run, { desc = "Run code lens" })
```

> [!WARNING]
> Neovim 0.11 changed diagnostic virtual text (inline diagnostics) from opt-out to opt-in. On 0.11+, run `vim.diagnostic.config({ virtual_text = true })` if `deps-lsp`'s warnings aren't appearing inline — on 0.10 and earlier this was already the default.

### Helix

```toml
# ~/.config/helix/languages.toml
[[language]]
name = "toml"
language-servers = ["deps-lsp"]

[[language]]
name = "json"
language-servers = ["deps-lsp"]

[language-server.deps-lsp]
command = "deps-lsp"
args = ["--stdio"]
```

Enable inlay hints in Helix config:

```toml
# ~/.config/helix/config.toml
[editor.lsp]
display-inlay-hints = true
```

Diagnostics render inline by default with no configuration needed.

> [!NOTE]
> Helix does not implement `textDocument/codeLens` — the "Update N outdated dependencies" batch action is unavailable there; use the per-dependency code action (`Cmd+.`/`Ctrl+.` equivalent) instead.

### VS Code

Install an LSP client extension and configure deps-lsp. Enable inlay hints:

```json
{
  "editor.inlayHints.enabled": "on"
}
```

`editor.codeLens` is `true` by default in VS Code itself, so `deps-lsp`'s code lens should appear automatically — provided your chosen generic LSP client extension forwards the `codeLens` capability (most do; check its documentation if the lens doesn't show up). Diagnostics render as squiggles plus entries in the Problems panel by default; for an always-visible inline message next to each dependency, install the third-party [Error Lens](https://marketplace.visualstudio.com/items?itemName=usernamehw.errorlens) extension.

## Configuration

Configure via LSP initialization options:

```json
{
  "inlay_hints": {
    "enabled": true,
    "up_to_date_text": "✅",
    "needs_update_text": "❌ {}"
  },
  "diagnostics": {
    "outdated_severity": "hint",
    "unknown_severity": "warning",
    "yanked_severity": "warning",
    "unsatisfiable_severity": "warning",
    "deprecated_severity": "warning",
    "mutable_ref_pin_severity": "hint",
    "mutable_ref_pin_enabled": true,
    "vulnerabilities_enabled": true
  },
  "freshness": {
    "enabled": true,
    "cooldown_secs": 259200
  },
  "cache": {
    "enabled": true,
    "fetch_timeout_secs": 5,
    "max_concurrent_fetches": 20
  },
  "loading_indicator": {
    "enabled": true,
    "fallback_to_hints": true,
    "loading_text": "..."
  },
  "cold_start": {
    "enabled": true,
    "rate_limit_ms": 100
  },
  "code_lens": {
    "enabled": true
  },
  "registries": {
    "workspace_registries": "public_only"
  },
  "network": {
    "offline": false
  },
  "supply_chain": {
    "enabled": true
  }
}
```

> [!NOTE]
> `diagnostics.outdated_severity`, `diagnostics.unknown_severity`, `diagnostics.unsatisfiable_severity`, and `diagnostics.yanked_severity` are all honored end-to-end. The yanked diagnostic fires in two independent cases (never both at once for the same dependency): (1) the dependency's in-use version — lock-file-resolved, or an exact pin such as `requirements.txt`'s `==1.2.3` — is itself reported as yanked/deprecated/retracted, supported for **Cargo, npm, PyPI, Bundler, and Dart**; or (2) the dependency's declared version *requirement* (a range) is currently satisfiable only by yanked versions, even with no lock file at all. See [Yanked Version Diagnostic](docs/ECOSYSTEM_GUIDE.md#yanked-version-diagnostic) for exact semantics and per-ecosystem coverage of each case (RubyGems cannot be detected by either mechanism, since its registry omits yanked versions from the list entirely rather than flagging them).

> [!NOTE]
> `diagnostics.deprecated_severity` flags a dependency whose *package* — not a specific version — is reported as deprecated/abandoned (`This package is deprecated: <reason>`), with a matching hover section and, for Composer packages naming a successor, a "Replace with X" quick fix. Currently sourced from **npm**'s `deprecated` field and **Composer**'s `abandoned` field only. See [Package Deprecation Diagnostics](docs/ECOSYSTEM_GUIDE.md#package-deprecation-diagnostics-issue-205) for the full ecosystem coverage table and how this differs from the yanked diagnostic above.

> [!NOTE]
> `diagnostics.mutable_ref_pin_severity` flags a **GitHub Actions** `uses:` step pinned to a mutable ref (a tag, e.g. `actions/checkout@v4`) instead of a full commit SHA — a supply-chain hardening recommendation independent of the outdated-version check above (a step can be both up to date *and* mutable). Comes with a "Pin `<name>` to commit SHA" quick fix that rewrites the ref to `<sha> # <tag>`, when the tag's commit SHA is already known. Set `diagnostics.mutable_ref_pin_enabled` to `false` to turn the diagnostic off entirely — unlike the other diagnostics above, severity alone cannot silence it. GitHub Actions only; see [Mutable-Ref-Pin Diagnostic](docs/ECOSYSTEM_GUIDE.md#mutable-ref-pin-diagnostic-issue-473) for full details.

### Configuration reference

| Section | Option | Default | Description |
| --------- | -------- | --------- | ------------- |
| `cache` | `enabled` | `true` | Whether the HTTP entry-map cache is used at all; `false` fetches fresh on every request and never stores. Overridden to behave as `true` while `network.offline` is set |
| `cache` | `fetch_timeout_secs` | `5` | Per-package fetch timeout (1-300 seconds) |
| `cache` | `max_concurrent_fetches` | `20` | Concurrent registry requests (1-100) |
| `loading_indicator` | `enabled` | `true` | Show loading feedback during fetches |
| `loading_indicator` | `fallback_to_hints` | `true` | Show loading in inlay hints if LSP progress unsupported |
| `loading_indicator` | `loading_text` | `"..."` | Text shown during loading (max 100 chars) |
| `code_lens` | `enabled` | `true` | Show the "Update N outdated dependencies" code lens |
| `freshness` | `enabled` | `true` | Flag a "latest" version still inside its cooldown window |
| `freshness` | `cooldown_secs` | `259200` | Cooldown window in seconds (3 days), clamped to 0-30 days |
| `registries` | `workspace_registries` | `"public_only"` | Which workspace-declared registry index hosts are ever fetched, across every ecosystem (Cargo's `.cargo/config.toml`/`[source]`, npm's `.npmrc`, PyPI's `--index-url`/Poetry/uv sources, Go's `$GOENV` `GOPROXY`, NuGet's `NuGet.Config`) — `"public_only"`, `"off"`, or `"all"`; see [Cargo Custom/Private Registries](docs/ECOSYSTEM_GUIDE.md#cargo-customprivate-registries), [npm Custom/Private Registries](docs/ECOSYSTEM_GUIDE.md#npm-customprivate-registries), [PyPI Custom/Private Indexes](docs/ECOSYSTEM_GUIDE.md#pypi-customprivate-indexes), [Go GOPROXY/GOPRIVATE Support](docs/ECOSYSTEM_GUIDE.md#go-goproxygoprivate-support), and [NuGet Private/Custom Feeds](docs/ECOSYSTEM_GUIDE.md#nuget-privatecustom-feeds). **Breaking rename** from `cargo.workspace_registries` — see CHANGELOG |
| `network` | `offline` | `false` | Block every outbound registry/OSV/GitHub request; already-cached data still serves, uncached dependencies show an offline marker |
| `supply_chain` | `enabled` | `true` | Show the OpenSSF Scorecard/build-provenance hover line, backed by deps.dev requests; `false` disables the requests and the section entirely |

> [!NOTE]
> The release-freshness signal applies uniformly across all ecosystems — there is no per-ecosystem override. Coverage depth varies with what each registry exposes (e.g. Deno's `jsr:` specifiers get full coverage at no extra request cost; Swift, GitHub Actions, and Maven/Gradle have partial coverage since their APIs don't expose per-version publish dates directly). See [Swift/GitHub Actions Release-Freshness Coverage](docs/ECOSYSTEM_GUIDE.md#swift-and-github-actions-release-freshness-coverage) and [Maven/Gradle Release-Freshness Coverage](docs/ECOSYSTEM_GUIDE.md#mavengradle-release-freshness-coverage) for per-ecosystem details.

> [!NOTE]
> `network.offline` blocks every outbound request the server makes (registry, OSV vulnerability, and GitHub tags), across every ecosystem. Already-cached data keeps serving; an uncached dependency shows an offline marker in inlay hints, and hover appends a footer stating that version *and* vulnerability data were not checked. Toggling it via `workspace/didChangeConfiguration` takes effect immediately, with no editor restart.

> [!NOTE]
> The supply-chain trust signal only appears for **npm, Cargo, Go, Maven, PyPI, Bundler, and NuGet** (Composer, Dart, and Swift have no deps.dev coverage) and only for a dependency with a concrete in-use version — a lock-file-resolved version, or an exact requirement pin. It shows the linked source repository's OpenSSF Scorecard score and the resolved version's SLSA/attestation provenance status; a Scorecard fetched via a package-self-reported (rather than attested) repository link is marked `*(self-reported repo)*`. Informational only — a low score never becomes a diagnostic. See [Supply-Chain Trust Signal](docs/ECOSYSTEM_GUIDE.md#supply-chain-trust-signal-issue-543) for the full details.

> [!TIP]
> Increase `fetch_timeout_secs` for slower networks. The per-dependency timeout prevents slow packages from blocking others. Cold start support ensures LSP features work immediately when your IDE restores previously opened files.

### GitHub API token

Some ecosystems (Swift) resolve versions via the GitHub API, which is limited to **60 requests/hour** without authentication. Set `GITHUB_TOKEN` to increase the limit to **5,000 requests/hour**:

```bash
# Using GitHub CLI (recommended)
export GITHUB_TOKEN=$(gh auth token)

# Or create a personal access token at https://github.com/settings/tokens
# No scopes required for public repository access
export GITHUB_TOKEN=ghp_...
```

For **Zed**, launch with the token so the LSP process inherits it:

```bash
# bash / zsh
alias zed='GITHUB_TOKEN="$(gh auth token)" command zed'

# fish
alias zed='env GITHUB_TOKEN=(gh auth token) command zed'
```

> [!TIP]
> Add the alias to your shell profile (`~/.zshrc`, `~/.bashrc`, `~/.config/fish/config.fish`) for persistence.

## Performance

deps-lsp is optimized for responsiveness:

| Operation | Latency | Notes |
| ----------- | --------- | ------- |
| Document open (50 deps) | ~150ms | Parallel registry fetching |
| Inlay hints | <100ms | Cached version lookups |
| Hover | <50ms | Pre-fetched metadata |
| Code actions | <50ms | No network calls |
| Code lens | <50ms | No network calls; in-memory only |

> [!TIP]
> Lock file support provides instant resolved versions without network requests.

## Development

> [!IMPORTANT]
> Requires Rust 1.91+ (Edition 2024).

### Build

```bash
cargo build --workspace
```

### Test

```bash
# Run tests with nextest
cargo nextest run

# Run tests with coverage
cargo llvm-cov nextest

# Generate HTML coverage report
cargo llvm-cov nextest --html
```

### Lint

```bash
# Format (requires nightly for Edition 2024)
cargo +nightly fmt --check

# Clippy (all targets, all features)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
cargo deny check
```

### Project structure

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
│   ├── deps-lsp/       # Main LSP server
│   └── deps-zed/       # Zed extension (WASM)
├── .config/            # nextest configuration
└── .github/            # CI/CD workflows
```

### Architecture

The codebase uses a trait-based architecture with the `Ecosystem` trait providing a unified interface for all package ecosystems:

```rust
// Each ecosystem implements the Ecosystem trait
pub trait Ecosystem: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn matches_uri(&self, uri: &Uri) -> bool;
    fn registry(&self) -> Arc<dyn Registry>;
    fn formatter(&self) -> Arc<dyn EcosystemFormatter>;
    async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<ParseResult>;
}

// EcosystemRegistry discovers the right handler for any manifest file
let ecosystem = registry.get_for_uri(&uri);
```

### Benchmarks

Run performance benchmarks with criterion:

```bash
cargo bench --workspace
```

View HTML report: `open target/criterion/report/index.html`

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, style, and testing expectations.

## License

[MIT](LICENSE)

## Acknowledgments

Inspired by:

- [crates-lsp](https://github.com/MathiasPius/crates-lsp) — Cargo.toml LSP
- [dependi](https://github.com/filllabs/dependi) — Multi-ecosystem dependency management
- [taplo](https://github.com/tamasfe/taplo) — TOML toolkit

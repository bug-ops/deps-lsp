# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![docs.rs](https://img.shields.io/docsrs/deps-lsp)](https://docs.rs/deps-lsp)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&component=deps-lsp)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Language Server Protocol implementation for dependency management across fourteen package ecosystems.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. It provides the LSP server binary and the ecosystem orchestration layer that wires together ecosystem-specific crates (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-go`, `deps-bundler`, `deps-dart`, `deps-maven`, `deps-gradle`, `deps-swift`, `deps-composer`, `deps-nuget`, `deps-deno`, `deps-github-actions`, `deps-gitlab-ci`) via the `Ecosystem` trait from `deps-core`.

## Features

- **Multi-ecosystem** — Cargo.toml, package.json, pyproject.toml, go.mod, Gemfile, pubspec.yaml, pom.xml, libs.versions.toml, Package.swift, composer.json, .csproj/.fsproj/.vbproj, deno.json/deno.jsonc, .github/workflows/*.yml, action.yml, .gitlab-ci.yml
- **Inlay hints** — Show latest versions inline with loading indicators
- **Hover info** — Package descriptions with resolved version from lock file
- **License hover & policy** — SPDX license for the resolved and latest version in hover, plus an optional `license_policy` allow/deny-list diagnostic
- **Diagnostics** — Warnings for outdated, unknown, yanked, or unsatisfiable-requirement dependencies
- **Vulnerability scanning** — OSV.dev-backed advisories in diagnostics and hover, across all supported ecosystems; every version offered as an "update to X" action or completion item is OSV-checked too, so a flagged or unverified release is never suggested as a safe upgrade
- **Typosquat detection (opt-in)** — `typosquat.enabled` flags a declared dependency whose name deps.dev reports as suspiciously similar to a much more popular package, for Cargo, npm, PyPI, Go, Bundler, Maven, and NuGet
- **deps.dev GOSSIP signals (opt-in)** — `gossip.enabled` sources the outdated-cooldown callout from deps.dev's Dynamic Cooldown data and adds a low-usage / slopsquatting-risk hover warning; completion gains a per-candidate cooldown badge
- **CI SHA-pin awareness** — GitHub Actions and GitLab CI/CD SHA pins are classified through the tag index, with a `sha-comment-mismatch` diagnostic (`diagnostics.sha_comment_mismatch_severity`) for a `# vX` comment that does not match the pinned commit
- **Supply-chain trust signal** — OpenSSF Scorecard score and SLSA/attestation provenance status in hover, via deps.dev, for npm, Cargo, Go, Maven, PyPI, Bundler, and NuGet
- **Release-freshness signal** — Flags a "latest" version still within a cooldown window in hover and completion, mirroring GitHub Dependabot's default 3-day package cooldown
- **Safe edits** — Fixes never overwrite an unresolved version placeholder (`${VAR}`, `$(VAR)`, `%VAR%`, string interpolation), and tracing output neutralizes control characters and masks token-shaped URL segments
- **Code actions** — Quick fixes to update dependencies, resolve unsatisfiable version requirements, and upgrade to a patched version for known vulnerabilities
- **Code lens** — "Update N outdated dependencies" batch update on every open manifest
- **Lock file support** — Reads resolved versions without network requests
- **Live config reload** — Configuration changes apply without restarting the server

## Installation

```bash
cargo install deps-lsp
```

> [!IMPORTANT]
> Requires Rust 1.98 or later.

## Usage

```bash
deps-lsp --stdio
```

## Feature flags

All ecosystems are enabled by default. Disable unused ones to reduce binary size:

```toml
[dependencies]
deps-lsp = { version = "2.0", default-features = false, features = ["cargo", "npm"] }
```

| Feature | Ecosystem | Default |
| ------- | --------- | ------- |
| `cargo` | Rust / Cargo.toml | Yes |
| `npm` | JavaScript / package.json | Yes |
| `pypi` | Python / pyproject.toml | Yes |
| `go` | Go / go.mod | Yes |
| `bundler` | Ruby / Gemfile | Yes |
| `dart` | Dart / pubspec.yaml | Yes |
| `maven` | Java / pom.xml | Yes |
| `gradle` | Java / Version Catalog + DSL | Yes |
| `swift` | Swift / Package.swift | Yes |
| `composer` | PHP / composer.json | Yes |
| `nuget` | C# / .csproj, Directory.Packages.props, packages.config | Yes |
| `deno` | Deno (JSR/npm) / deno.json, deno.jsonc | Yes |
| `github-actions` | YAML / .github/workflows/*.yml, *.yaml | Yes |
| `gitlab-ci` | YAML / .gitlab-ci.yml, .gitlab/ci/*.yml | Yes |

`deno` pulls in `deps-npm` transitively (`DenoRegistry` delegates `npm:` specifiers to it, per its D3 architecture), even when the `npm` feature itself is disabled.

## Supported editors

- **Zed** — Install the "Deps" extension from the Zed Extensions marketplace
- **Neovim** — Configure with `nvim-lspconfig`
- **Helix** — Add to `languages.toml`
- **VS Code** — Configure via any LSP client extension

See the [main repository](https://github.com/bug-ops/deps-lsp) for full editor setup instructions and configuration reference.

## License

[MIT](../../LICENSE)

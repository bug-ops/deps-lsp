# deps-lsp

[![Crates.io](https://img.shields.io/crates/v/deps-lsp)](https://crates.io/crates/deps-lsp)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ)](https://codecov.io/gh/bug-ops/deps-lsp)
[![Tests](https://img.shields.io/badge/tests-5891%20passed-brightgreen)](https://github.com/bug-ops/deps-lsp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue)](https://blog.rust-lang.org/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Know whether a dependency is safe to bump — without leaving your editor. `deps-lsp` is a
universal Language Server Protocol (LSP) server that brings hover, completion, diagnostics, and
quick fixes for outdated, vulnerable, yanked, and unsatisfiable dependencies to any manifest file,
across 14 package ecosystems: Cargo, npm, Deno, PyPI, Go, Bundler, Dart, Maven, Gradle, Swift,
Composer, NuGet, GitHub Actions, and GitLab CI/CD. One binary, no per-language extensions to
install and keep in sync.

![deps-lsp in action](https://raw.githubusercontent.com/bug-ops/deps-zed/main/assets/img.png)

## Features

- **Inline version awareness** — Inlay hints show at a glance which dependencies are current and
  which have a newer release, right next to the version you wrote.
- **Rich hover** — Package description, resolved vs. latest version, license, and security
  advisories, without leaving the manifest.
- **Vulnerability & license scanning** — OSV.dev-backed advisories and SPDX license/policy checks
  surface as diagnostics and quick fixes, not just as a separate CI step you find out about later.
- **Supply-chain trust signal** — OpenSSF Scorecard and SLSA/attestation provenance in hover, so
  you can judge a dependency's health before pulling it in.
- **Lock-file aware** — Reads the version you actually have installed, not just the range you
  wrote, across every ecosystem that has a lock file.
- **One-click fixes** — Code actions to bump a version, resolve an unsatisfiable range, or patch a
  known vulnerability; a code lens batch-updates every outdated dependency in the file at once.
- **Fast** — Parallel registry fetching and aggressive caching keep hover and inlay hints
  responsive even on manifests with hundreds of dependencies.

## Supported ecosystems

| Language | Ecosystem | Manifest file |
| ---------- | ----------- | --------------- |
| Rust | Cargo | `Cargo.toml` |
| JavaScript | npm | `package.json` |
| JavaScript/TypeScript | Deno (JSR/npm) | `deno.json`, `deno.jsonc` |
| Python | PyPI | `pyproject.toml`, `requirements.txt`, `constraints.txt` |
| Go | Go Modules | `go.mod` |
| Ruby | Bundler | `Gemfile` |
| Dart | Pub | `pubspec.yaml` |
| Java | Maven | `pom.xml` |
| Java | Gradle | `libs.versions.toml`, `build.gradle.kts`, `build.gradle`, `settings.gradle` |
| Swift | SPM | `Package.swift` |
| PHP | Composer | `composer.json` |
| C# | NuGet | `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`, `packages.config` |
| YAML | GitHub Actions | `.github/workflows/*.yml`, `*.yaml`; `action.yml`, `action.yaml` |
| YAML | GitLab CI/CD | `.gitlab-ci.yml`, `.gitlab/ci/*.yml`, `*.yaml` |

Coverage depth (custom registries, lock file support, pseudo-versions, and other per-ecosystem
detail) is documented per ecosystem in the
[**Ecosystem Reference**](https://bug-ops.github.io/deps-lsp/ecosystems/index.html).

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

### Building with fewer ecosystems

All 14 ecosystems are enabled by default. Build with only the ones you need via Cargo feature
flags, e.g. `cargo install deps-lsp --no-default-features --features "cargo,npm"` — the flag name
always matches the ecosystem's row in the table above (`cargo`, `npm`, `pypi`, `go`, ...). See
`crates/deps-lsp/Cargo.toml` for the full flag list.

## Usage

Run the server over stdio (typical editor integration):

```bash
deps-lsp --stdio
```

## Editor setup

Install the **Deps** extension from the Zed Extensions marketplace (Ruby support included for
`Gemfile`), then enable inlay hints and code lens in Zed settings:

```json
{
  "inlay_hints": { "enabled": true },
  "code_lens": "on"
}
```

Every other editor with an LSP client — Neovim, Helix, VS Code, Emacs, Sublime Text, Kate,
coc.nvim — works the same way: point it at `deps-lsp --stdio`. Full copy-paste config for each one
lives in the book's
[**Editor Setup**](https://bug-ops.github.io/deps-lsp/editor-setup.html#neovim) chapter.

## CLI & CI

[`deps-cli`](crates/deps-cli/README.md) runs the same dependency checks as an editor-free
command-line tool, for CI pipelines, pre-commit hooks, and shell scripts. Every verdict comes
from the identical classification function `deps-lsp` uses for its diagnostics, so a
`deps-cli check` result and an editor's diagnostics for the same manifest never disagree.

```bash
curl -fsSL https://raw.githubusercontent.com/bug-ops/deps-lsp/main/scripts/install-deps-cli.sh | sh
deps-cli check --format sarif > results.sarif
```

- **Output formats**: human-readable table (default), versioned JSON, or SARIF 2.1.0 for
  `github/codeql-action/upload-sarif`
- **[Pre-commit hook](.pre-commit-hooks.yaml)**: `deps-lsp-check`, runs `deps-cli check`
  against staged files
- **[GitHub Action](crates/github-action/README.md)**: a composite action wrapping
  `deps-cli check --format sarif`, leaving `upload-sarif` to your own workflow

See [`crates/deps-cli/README.md`](crates/deps-cli/README.md) for other install options
(`cargo install`, pre-built binaries, from source), the full flag reference, `deps.toml` schema,
and exit-code contract.

## Configuration

Everything is configured through LSP `initializationOptions` — no separate config file. A typical
setup only touches a handful of options:

```json
{
  "inlay_hints": { "enabled": true },
  "diagnostics": { "outdated_severity": "hint", "vulnerabilities_enabled": true },
  "freshness": { "enabled": true, "cooldown_secs": 259200 },
  "network": { "offline": false },
  "license_policy": { "allow": [], "deny": [] }
}
```

Every section, option, default, and edge case — including the inlay hint icon legend and the
hover/diagnostic text conventions — is documented in the book's
[**Configuration**](https://bug-ops.github.io/deps-lsp/configuration.html#configuration-reference)
chapter.

### GitHub API token

Some ecosystems (Swift, GitHub Actions) resolve versions via the GitHub API, which is limited to
**60 requests/hour** without authentication. Set `GITHUB_TOKEN` to raise the limit to **5,000
requests/hour**:

```bash
export GITHUB_TOKEN=$(gh auth token)   # or a PAT from https://github.com/settings/tokens — no scopes required
```

### GitLab API token

Set `GITLAB_TOKEN` to a GitLab Personal or Project Access Token to raise GitLab CI/CD's
unauthenticated rate limit and access private projects. It is sent as `PRIVATE-TOKEN` only to
`gitlab.com` (default) or, once configured, to `registries.gitlab_instance_host` — never both:

```bash
export GITLAB_TOKEN=glpat-...
```

## Development

Requires Rust 1.98+ (Edition 2024). See [CONTRIBUTING.md](CONTRIBUTING.md) for the full setup,
build, test, and lint commands, and the book's
[**Architecture Overview**](https://bug-ops.github.io/deps-lsp/architecture.html#the-ecosystem-trait)
for how the `Ecosystem` trait ties ecosystem crates into the LSP server, the workspace's
[project structure](https://bug-ops.github.io/deps-lsp/architecture.html#project-structure), and
its
[performance characteristics](https://bug-ops.github.io/deps-lsp/architecture.html#performance).

`deps-core`'s public trait signatures are typed directly against pre-1.0 `tower-lsp-server` types,
which has consequences for anyone implementing `Ecosystem` outside this workspace — see the book's
[**Versioning Policy**](https://bug-ops.github.io/deps-lsp/architecture.html#versioning-policy).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, style, and testing expectations.

## License

[MIT](LICENSE)

## Acknowledgments

Inspired by:

- [crates-lsp](https://github.com/MathiasPius/crates-lsp) — Cargo.toml LSP
- [dependi](https://github.com/filllabs/dependi) — Multi-ecosystem dependency management
- [taplo](https://github.com/tamasfe/taplo) — TOML toolkit

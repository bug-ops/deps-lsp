# Introduction

`deps-lsp` is a universal Language Server Protocol server for dependency management. A single
binary provides hover, completion, diagnostics, code actions, code lens, and inlay hints for
outdated, unknown, yanked, vulnerable, and unsatisfiable dependencies across 14 package
ecosystems — Cargo, npm, Deno, PyPI, Go, Bundler, Dart, Maven, Gradle, Swift, Composer, NuGet,
GitHub Actions, and GitLab CI/CD — instead of requiring a separate extension per language.

A companion binary, [`deps-cli`](cli.md), runs the same checks from the command line —
routing every manifest through the identical classification pipeline — for CI pipelines,
pre-commit hooks, and shell scripts where an editor isn't involved.

For installation, editor setup, and LSP configuration options, see the root
[`README.md`](https://github.com/bug-ops/deps-lsp#readme). This book does not duplicate that
material; it covers instead:

- **What each ecosystem supports today** — the [Ecosystem Reference](ecosystems/index.md)
  chapters, and the cross-cutting behaviors ([Cross-Ecosystem Features](cross-ecosystem/index.md))
  that apply the same way across most or all of them.
- **`deps-cli`** — the [command-line reference](cli.md) for CI/pre-commit/shell use.
- **How to add support for a new ecosystem** — the
  [Adding a New Ecosystem](contributing/index.md) contributor track, for anyone extending
  `deps-lsp` itself.

> **Note:** API documentation generated from the Rust source (`cargo doc`) is published
> separately — see [API Documentation](api-docs.md).

## Supported Ecosystems

| Ecosystem | Language | Manifest File(s) | Lock File(s) | Highlights |
|-----------|----------|-----------------|--------------|----------|
| **[Cargo](ecosystems/cargo.md)** | Rust | `Cargo.toml` | `Cargo.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens, feature flag completion, alternate/private registry resolution via `.cargo/config.toml` |
| **[npm](ecosystems/npm.md)** | JavaScript/TypeScript | `package.json` | `package-lock.json`, `pnpm-lock.yaml` | Hover, inlay hints, completion, code actions, diagnostics, code lens, custom/private registry resolution via `.npmrc`, pnpm workspace catalog (`catalog:`/`catalog:<name>`) resolution via `pnpm-workspace.yaml` |
| **[PyPI](ecosystems/pypi.md)** | Python | `pyproject.toml`, `requirements.txt`, `constraints.txt` (also recognized under a `requirements/` directory, e.g. `requirements/base.txt`) | `poetry.lock`, `uv.lock` | Hover with PEP 508 environment marker display ("Active when: `<marker>`"), inlay hints, completion, code actions, diagnostics, code lens, document links for `-r`/`-c`/`--requirement`/`--constraint` file references, private/custom index resolution via `--index-url`/`--extra-index-url`, Poetry `[[tool.poetry.source]]`, and uv `[tool.uv.index]`/`[tool.uv.sources]` |
| **[Go](ecosystems/go.md)** | Go | `go.mod` | `go.sum` | Hover, inlay hints, completion, code actions, diagnostics, code lens, pseudo-version support, `$GOENV` `GOPROXY`/`GOPRIVATE` proxy-chain resolution |
| **[Bundler](ecosystems/bundler.md)** | Ruby | `Gemfile` | `Gemfile.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens, custom-source classification (`source`/`git`/`path` blocks and per-gem options, modern and legacy hash-rocket syntax) |
| **[Dart](ecosystems/dart.md)** | Dart | `pubspec.yaml` | `pubspec.lock` | Hover with corrected version ordering (prereleases sort below base release), inlay hints, completion, code actions, diagnostics, code lens, YAML anchor/alias resolution for whole dependency sections and `environment:`, `hosted:` custom-registry classification |
| **[Maven](ecosystems/maven-gradle.md)** | Java | `pom.xml` | `maven-metadata.xml` (CDN) | Hover with corrected version ordering (numeric segments outrank qualifiers, prereleases sort below base release), inlay hints, completion, code actions, diagnostics, code lens (property-versioned dependencies not covered) |
| **[Gradle](ecosystems/maven-gradle.md)** | Kotlin/Groovy | `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` | — | Hover with corrected version ordering (same as Maven), inlay hints, completion, code actions, diagnostics, code lens (variable/catalog-versioned dependencies not covered), variable resolution (`gradle.properties`) |
| **[Composer](ecosystems/composer.md)** | PHP | `composer.json` | `composer.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens (requirement matching and "latest version" selection both use corrected stability-qualifier ordering) |
| **[Swift](ecosystems/swift.md)** | Swift | `Package.swift` | `Package.resolved` | Hover, inlay hints, completion, code actions, diagnostics, code lens (range-form dependencies not covered), GitHub API support |
| **[NuGet](ecosystems/nuget.md)** | .NET | `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`, `packages.config` | `packages.lock.json`, `packages.<project>.lock.json` (multi-project) | Hover, inlay hints, completion, code actions, diagnostics, code lens, central package management support, SemVer2 prerelease handling, hover-only unlisted-version marker, private/custom feed resolution via `NuGet.Config` |
| **[Deno](ecosystems/deno.md)** | JavaScript/TypeScript (Deno runtime) | `deno.json`, `deno.jsonc` | — (no `deno.lock` support yet) | Hover, inlay hints, completion, code actions, diagnostics, code lens — `jsr:` specifiers via the keyless JSR API, `npm:` specifiers delegate to the same registry client `npm` uses; `imports` map only, `scopes`/`importMap` not covered |
| **[GitHub Actions](ecosystems/github-actions.md)** | YAML | `.github/workflows/*.yml`, `*.yaml`; `action.yml`, `action.yaml` (composite/Docker/JS actions — a repository root or `.github/actions/<name>/`, issue #706) | — (no lock file) | Hover, inlay hints, code actions, diagnostics, code lens (package-name completion not covered); tag/commit-SHA/branch `uses:` pins via the GitHub tags API; reusable-workflow calls recognized but not version-resolved; release-age hint and cooldown diagnostic require `GITHUB_TOKEN` |
| **[GitLab CI/CD](ecosystems/gitlab-ci.md)** | YAML | `.gitlab-ci.yml`, `.gitlab/ci/*.yml`, `*.yaml` | — (no lock file) | Hover, inlay hints, code actions, diagnostics, code lens (package-name completion not covered); `project:`+`ref:` pins via the GitLab repository-tags API, `component:` CI/CD Catalog pins via the GitLab project-releases API (SHA/exact-release/`~latest`/partial-semver priority ladder); self-hosted instances via `registries.gitlab_instance_host`; scalar YAML anchor/alias resolution within `include:` |

Many of the behaviors above are shared across several ecosystems rather than reimplemented per
crate — see [Cross-Ecosystem Features](cross-ecosystem/index.md) for the conventions and
diagnostics that apply the same way everywhere they're listed.

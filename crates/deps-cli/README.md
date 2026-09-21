# deps-cli

[![Crates.io](https://img.shields.io/crates/v/deps-cli)](https://crates.io/crates/deps-cli)
[![docs.rs](https://img.shields.io/docsrs/deps-cli)](https://docs.rs/deps-cli)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&component=deps-cli)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Run deps-lsp's dependency-health checks from the command line, in CI, or in a shell script —
no editor required.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. `deps-cli
check` walks a workspace, routes every manifest it finds through the same 14-ecosystem
classification pipeline (`deps-engine`) that powers `deps-lsp`'s hover and diagnostics, and
reports outdated/yanked/vulnerable/unsatisfiable/deprecated/license/mutable-ref-pin findings as
a table, as JSON, or as SARIF 2.1.0, with a CI-friendly exit code.

> [!IMPORTANT]
> `deps-cli` implements no classification logic of its own — every verdict comes from the exact
> function `deps-lsp` calls for its LSP diagnostics, so a `deps-cli check` result and an editor's
> diagnostics for the same manifest never disagree.

## Features

- **Security-hardened workspace walk** — routes every discovered file through the same
  `EcosystemRegistry` the LSP server uses, across all 14 supported ecosystems (Cargo, npm,
  PyPI, Go, Bundler, Dart, Maven, Gradle, Swift, Composer, NuGet, Deno, GitHub Actions,
  GitLab CI/CD). `check` does **not** honor `.gitignore`/`.ignore` by default, because in a CI
  gate (`git checkout && deps-cli check .` against an untrusted fork PR) both files are
  attacker-controlled input — a one-line addition to either would otherwise silently remove a
  manifest from the scan with no warning and exit code `0`. A compiled-in denylist
  (`node_modules`, `target`, `vendor`, `.venv`, and other common dependency/build/VCS
  directories) still keeps the scan fast and on-signal without depending on either file. Pass
  `--respect-gitignore` to restore standard `.gitignore`/`.ignore` awareness when scanning a
  target you trust as much as your own `deps.toml`. A manifest reachable only through a
  symlink is detected and reported the same way regardless of this flag; pass
  `--follow-symlinks` to also resolve and scan it, bounded so it can never escape the walked
  root or loop forever.
- **Table, JSON, or SARIF output** — a human-readable table (default) grouped by file and
  severity, a versioned JSON document for machine consumption, or a SARIF 2.1.0 document for
  `github/codeql-action/upload-sarif` and other SARIF consumers
- **Configurable failure policy** — `--fail-on` picks which finding categories make the run
  exit non-zero, so a pipeline can gate on vulnerabilities without failing on merely-outdated
  dependencies
- **CI-safe by construction** — a `deps.toml` auto-discovered from the scanned repository
  itself can never weaken what `--fail-on` observes or redirect credentials to an attacker
  host; only an explicitly-passed `--config` is trusted with the full policy (see
  [Configuration](#configuration))
- **Offline mode** — `--offline` serves only already-cached registry data, useful for
  air-gapped CI runners or fast local iteration

## Installation

### From crates.io

```bash
cargo install deps-cli
```

> [!TIP]
> Use `cargo binstall deps-cli` for faster installation without compilation.

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/bug-ops/deps-lsp/main/scripts/install-deps-cli.sh | sh
```

Detects your OS and CPU architecture, downloads the matching release archive, verifies its
SHA256 checksum, and installs `deps-cli` to `${CARGO_HOME:-~/.cargo}/bin` (falling back to
`~/.local/bin`) — no Rust toolchain required. Pin a release with `--tag <version>` (or the
`DEPS_CLI_VERSION` env var); override the install directory with `--install-dir <dir>` (or
`DEPS_CLI_INSTALL_DIR`).

> [!IMPORTANT]
> Windows is not supported by the script — download the `.zip` release asset from the table
> below instead.

### Pre-built binaries

Download from [GitHub Releases](https://github.com/bug-ops/deps-lsp/releases/latest):

| Platform | Architecture | Binary |
| ---------- | -------------- | -------- |
| Linux | x86_64 (glibc) | `deps-cli-x86_64-unknown-linux-gnu` |
| Linux | aarch64 (glibc) | `deps-cli-aarch64-unknown-linux-gnu` |
| Linux | x86_64 (musl) | `deps-cli-x86_64-unknown-linux-musl` |
| Linux | aarch64 (musl) | `deps-cli-aarch64-unknown-linux-musl` |
| macOS | x86_64 | `deps-cli-x86_64-apple-darwin` |
| macOS | Apple Silicon | `deps-cli-aarch64-apple-darwin` |
| Windows | x86_64 | `deps-cli-x86_64-pc-windows-msvc.exe` |
| Windows | ARM64 | `deps-cli-aarch64-pc-windows-msvc.exe` |

### Docker

The [GitHub Action image](#github-action) (`ghcr.io/bug-ops/deps-lsp-github-action`) also
bundles a prebuilt `deps-cli` binary, SHA256-verified against the matching GitHub release — no
Rust toolchain, and nothing to trust beyond the image itself. Its default entrypoint is fixed to
the Action's own `check --format sarif` contract, so override it to run `deps-cli` directly:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace \
  --entrypoint deps-cli ghcr.io/bug-ops/deps-lsp-github-action:1 check
```

`linux/amd64` and `linux/arm64` only. Tags: `latest`, `X`, `X.Y`, `X.Y.Z` — see
[Image tags](../github-action/README.md#image-tags).

### From source

```bash
git clone https://github.com/bug-ops/deps-lsp
cd deps-lsp
cargo install --path crates/deps-cli
```

### As a workspace dependency

To drive the `check` pipeline programmatically:

```toml
[dependencies]
deps-cli = "1.2"
```

> [!IMPORTANT]
> Requires Rust 1.98 or later.

## Usage

```bash
# Check the current directory, human-readable table output (default)
deps-cli check

# Check specific paths
deps-cli check Cargo.toml package.json services/api/

# Fail the run only on real vulnerabilities and unsatisfiable requirements
deps-cli check --fail-on vulnerable,unsatisfiable

# Machine-readable output for a CI step that parses results
deps-cli check --format json

# SARIF 2.1.0 output for github/codeql-action/upload-sarif
deps-cli check --format sarif > results.sarif

# CI-friendly: never touch the network, use only what's already cached
deps-cli check --offline

# Loosen the freshness window for this run only
deps-cli check --cooldown 3d

# Use an explicit, fully-trusted config file
deps-cli check --config ./ci/deps-strict.toml

# Restore .gitignore/.ignore awareness (only for a fully-trusted scan target — see Features)
deps-cli check --respect-gitignore

# Resolve and scan a symlinked manifest (only for a fully-trusted scan target — see Features)
deps-cli check --follow-symlinks
```

### Exit codes

CI pipelines script against the exit code directly:

| Code | Meaning |
|---|---|
| `0` | Clean — no finding matched the `--fail-on` policy |
| `1` | Policy violation — at least one finding matched `--fail-on` |
| `2` | Execution error — a registry was unreachable, a `deps.toml`/manifest failed to parse, or a walked path was unreadable |

A real policy violation (`1`) always takes precedence over an unrelated execution error
elsewhere in the run — one malformed manifest in a large workspace never hides a genuine
`--fail-on` hit behind a less specific `2`.

### `--fail-on` categories

`outdated`, `yanked`, `vulnerable`, `unsatisfiable`, `mutable-ref`, `license`, `deprecated`.
Defaults to `vulnerable,yanked,unsatisfiable` when the flag is omitted. A finding that matches
none of these seven categories (for example, an unresolved or unknown package) is always
reported in the output but can never fail a run through this flag.

## Pre-commit hook

This repository ships a [`.pre-commit-hooks.yaml`](../../.pre-commit-hooks.yaml) at its root
defining a `deps-lsp-check` hook (`language: system`, `entry: deps-cli check`), per FR-017.

> [!NOTE]
> `language: system` means pre-commit does not install anything for this hook — `deps-cli`
> must already be on your `PATH`. The fastest way to get it there is the
> [install script](#installation) (`curl -fsSL .../install-deps-cli.sh | sh`); `cargo install
> deps-cli` and `cargo install --path crates/deps-cli` from a checkout also work. An earlier
> `language: rust` hook definition could not install from this repository's root at all, since
> it is a virtual workspace manifest (no `[package]`) — see
> [#1074](https://github.com/bug-ops/deps-lsp/issues/1074).

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bug-ops/deps-lsp
    rev: <tag>
    hooks:
      - id: deps-lsp-check
```

## GitHub Action

[`crates/github-action`](../github-action/README.md) wraps `deps-cli check --format sarif` as
a composite action. It writes a SARIF file but does not upload it — wire
`github/codeql-action/upload-sarif` after it in your own workflow:

```yaml
- uses: bug-ops/deps-lsp/crates/github-action@v1.2.0
  id: deps-check
  with:
    fail-on: vulnerable,yanked,unsatisfiable
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.deps-check.outputs.sarif-file }}
- name: Fail the build on a policy violation
  if: steps.deps-check.outputs.exit-code == '1'
  run: exit 1
```

The action itself only fails the job on an execution error — any exit code other than `0`
(clean) or `1` (a `--fail-on` category matched), including a `deps-cli` panic or a refused
SARIF output path. A `--fail-on` policy violation (`exit-code` `1`) does not fail the step;
`sarif-file` is usually still produced and uploaded then too, though it may be unset even at
`exit-code` `0` or `1` if the output path couldn't be written. It is your own workflow's
decision — shown above — whether to fail the build on a policy violation. See
[`crates/github-action/README.md`](../github-action/README.md) for the full input/output
reference.

> [!NOTE]
> Piping stdout directly to a file, as in `deps-cli check --format sarif > results.sarif`
> above, is at risk of truncation if `deps-cli` crashes mid-write — a partial SARIF file handed
> to `upload-sarif` fails confusingly rather than cleanly. The GitHub Action wrapper does not
> have this risk: it captures `deps-cli`'s exit code before deciding whether `sarif-file` is
> set, so a crash leaves `sarif-file` unset instead of pointing at a truncated file (#1063).
> Prefer the Action, or apply the same exit-code check yourself, when scripting
> the CLI form directly in CI.

## Configuration

`deps-cli` reuses `deps-lsp`'s own [`PolicyConfig`](../deps-core/src/policy_config.rs) schema,
loaded from a `deps.toml` file:

```toml
[diagnostics]
vulnerabilities_enabled = true
mutable_ref_pin_enabled = true

[freshness]
cooldown_secs = 259200 # 3 days, Dependabot's default

[network]
offline = false

[license_policy]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause"]
```

`deps-cli` looks for `./deps.toml` (relative to the walked root) when `--config` is not given.

> [!WARNING]
> An auto-discovered `deps.toml` — one found by this default lookup, not passed explicitly via
> `--config` — has its `registries`, `network`, and `diagnostics.*_enabled` sections (and a few
> other gate-relevant fields) reset to their safe defaults before use. This is deliberate: the
> repository a CI job is checking is not a trusted source for the policy that judges it, and a
> checked-in `deps.toml` on an attacker-controlled branch must not be able to disable the check
> or redirect a registry credential to another host. Any section ignored this way is named in a
> warning on stderr. Only a config path given explicitly via `--config` (the operator's own
> choice, not the scanned repository's) is trusted in full.

## License

[MIT](../../LICENSE)

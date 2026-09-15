# deps-cli

[![Crates.io](https://img.shields.io/crates/v/deps-cli)](https://crates.io/crates/deps-cli)
[![docs.rs](https://img.shields.io/docsrs/deps-cli)](https://docs.rs/deps-cli)
[![CI](https://github.com/bug-ops/deps-lsp/actions/workflows/ci.yml/badge.svg)](https://github.com/bug-ops/deps-lsp/actions)
[![codecov](https://codecov.io/gh/bug-ops/deps-lsp/graph/badge.svg?token=S71PTINTGQ&flag=deps-cli)](https://codecov.io/gh/bug-ops/deps-lsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

Run deps-lsp's dependency-health checks from the command line, in CI, or in a shell script —
no editor required.

This crate is part of the [deps-lsp](https://github.com/bug-ops/deps-lsp) workspace. `deps-cli
check` walks a workspace, routes every manifest it finds through the same 14-ecosystem
classification pipeline (`deps-engine`) that powers `deps-lsp`'s hover and diagnostics, and
reports outdated/yanked/vulnerable/unsatisfiable/deprecated/license/mutable-ref-pin findings as
a table or as JSON, with a CI-friendly exit code.

> [!IMPORTANT]
> `deps-cli` implements no classification logic of its own — every verdict comes from the exact
> function `deps-lsp` calls for its LSP diagnostics, so a `deps-cli check` result and an editor's
> diagnostics for the same manifest never disagree.

## Features

- **`.gitignore`-aware workspace walk** — routes every discovered file through the same
  `EcosystemRegistry` the LSP server uses, across all 14 supported ecosystems (Cargo, npm,
  PyPI, Go, Bundler, Dart, Maven, Gradle, Swift, Composer, NuGet, Deno, GitHub Actions,
  GitLab CI/CD)
- **Table or JSON output** — a human-readable table (default) grouped by file and severity, or
  a versioned JSON document for machine consumption
- **Configurable failure policy** — `--fail-on` picks which finding categories make the run
  exit non-zero, so a pipeline can gate on vulnerabilities without failing on merely-outdated
  dependencies
- **CI-safe by construction** — a `deps.toml` auto-discovered from the scanned repository
  itself can never weaken what `--fail-on` observes or redirect credentials to an attacker
  host; only an explicitly-passed `--config` is trusted with the full policy (see
  [Configuration](#configuration))
- **Offline mode** — `--offline` serves only already-cached registry data, useful for
  air-gapped CI runners or fast local iteration

> [!NOTE]
> `--format sarif`, a `.pre-commit-hooks.yaml` entry, and a GitHub Action wrapper are planned
> as a follow-up ([#1063](https://github.com/bug-ops/deps-lsp/issues/1063)) and not yet
> available in this release.

## Installation

```bash
cargo install deps-cli
```

Or as a workspace dependency, to drive the `check` pipeline programmatically:

```toml
[dependencies]
deps-cli = "1.0"
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

# CI-friendly: never touch the network, use only what's already cached
deps-cli check --offline

# Loosen the freshness window for this run only
deps-cli check --cooldown 3d

# Use an explicit, fully-trusted config file
deps-cli check --config ./ci/deps-strict.toml
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

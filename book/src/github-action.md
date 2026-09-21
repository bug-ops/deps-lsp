# GitHub Action

`crates/github-action` ships a ready-made, Docker-based GitHub Action that runs
[`deps-cli check --format sarif`](cli.md) against your repository and writes the result to a
SARIF 2.1.0 file — the same dependency-health checks `deps-lsp` surfaces in your editor,
running as a CI gate with zero Rust toolchain setup.

## Quick start

```yaml
name: Dependency check

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  deps-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bug-ops/deps-lsp/crates/github-action@v1.2.0
        id: deps-check
        with:
          fail-on: vulnerable,yanked,unsatisfiable
      - uses: github/codeql-action/upload-sarif@v3
        if: steps.deps-check.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.deps-check.outputs.sarif-file }}
      - name: Fail the build on a policy violation
        if: steps.deps-check.outputs.exit-code == '1'
        run: exit 1
```

The action itself does **not** fail the job on a policy violation (`exit-code: 1`) — only on
an execution error (anything other than exit code `0` or `1`, e.g. a `deps-cli` panic or a
missing binary). Whether a policy violation should fail your build is your own workflow's
decision, made explicit by the last step above. Drop that step if you only want the SARIF
findings uploaded to GitHub's code scanning UI, without failing the build.

This action requires a Linux runner (`runs-on: ubuntu-latest` or similar) — it is a Docker
action, which GitHub Actions only runs on Linux.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Space-separated paths to walk | `deps-cli`'s own default (repository root) |
| `fail-on` | Comma-separated categories that make `deps-cli` exit `1` — `outdated`, `yanked`, `vulnerable`, `unsatisfiable`, `mutable-ref`, `license`, `deprecated` | `vulnerable,yanked,unsatisfiable` |
| `cooldown` | Overrides `freshness.cooldown_secs` for this run only (e.g. `3d`) | unset |
| `config` | Path to a **fully-trusted** `deps.toml` — see the warning below | unset (falls back to `deps-cli`'s own hardened auto-discovery) |

> **Warning:** `deps-cli` treats an explicit `--config` path (which `config` here maps to) as
> fully trusted — unlike an auto-discovered `deps.toml`, whose `registries`/`network`/
> `diagnostics.*_enabled` sections are reset to safe defaults specifically because the scanned
> repository is not a trusted source for the policy that judges it (see
> [Configuration (`deps.toml`)](cli.md#configuration-depstoml)). Passing `config` here
> re-establishes that full trust, so only point it at a file outside the scanned checkout and
> under your own control — never at a path inside the repository you are scanning, especially
> in a `pull_request_target` workflow scanning a fork.

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the produced SARIF file (`deps-lsp-results.sarif`). Set only when a non-empty, regular SARIF file was produced — may be unset even for exit code `0`/`1` (e.g. an unwritable output path), and is always unset for an execution error |
| `exit-code` | `deps-cli check`'s own exit code (`0` clean, `1` a `--fail-on` category matched, `2` execution error), or the raw exit code from an abnormal termination. Set whenever `deps-cli` ran; unset only if the action refused to start before running it at all |

## How it maps to `deps-cli`

The action is a thin wrapper: `action.yml` declares `using: docker`, pointing at
`ghcr.io/bug-ops/deps-lsp-github-action:1` — an image that bundles a prebuilt `deps-cli`
binary, fetched from the matching GitHub release and SHA256-verified at build time. Each
input becomes a `DEPS_CLI_*` environment variable the image's entrypoint script reads and
translates into the equivalent `deps-cli check` flag:

| Input | Environment variable | `deps-cli` flag |
|-------|----------------------|------------------|
| `paths` | `DEPS_CLI_PATHS` | positional paths |
| `fail-on` | `DEPS_CLI_FAIL_ON` | `--fail-on` |
| `cooldown` | `DEPS_CLI_COOLDOWN` | `--cooldown` |
| `config` | `DEPS_CLI_CONFIG` | `--config` |

The entrypoint always runs `deps-cli check --format sarif`, redirecting the output to
`deps-lsp-results.sarif` in the scanned checkout. That output path is removed before every
run — including a pre-existing regular file left by a prior step or a symlink placed there by
the scanned checkout itself — so a stale or hostile file never leaks into the result; a
**directory** at that path cannot be removed this way, so the action refuses to start before
`deps-cli` even runs, leaving both outputs unset.

You can run the exact same image directly with plain `docker run` (useful for reproducing a
CI failure locally) — see [deps-cli's Docker section](cli.md#docker) for the command.

## Image tags and supply-chain hardening

Pin the `uses:` ref itself to a release tag (`@v1.2.0`, as in the examples above), not `@main` —
per the [CI/CD Pinning](cross-ecosystem/ci-pinning.md) guidance `deps-lsp` itself gives for your
other GitHub Actions dependencies, a branch ref can start running different code with no change
to your workflow file. This is separate from the Docker image tag discussed next, which
`action.yml` pins on your behalf.

The image is rebuilt whenever a new `deps-lsp`/`deps-cli` release is tagged. Tags published:
`latest`, a rolling major (`1`), and exact per-release tags (`X.Y`, `X.Y.Z`). `action.yml`
pins the rolling major tag (`:1`) so this action tracks the latest `1.x.y` release without a
manual bump; pin an exact tag yourself in your own workflow if you need full reproducibility.
Every image is scanned with Trivy for CRITICAL/HIGH vulnerabilities before publish — a finding
blocks the publish and is reported to the repository's Security tab.

## See also

- [deps-cli](cli.md) — the CLI this action wraps, including its own SARIF output format,
  exit-code contract, and `deps.toml` configuration and its auto-discovery hardening.
- [The deps-engine crate](engine.md) — the shared classification layer `deps-cli` (and thus
  this action) uses, guaranteeing its findings never disagree with `deps-lsp`'s editor
  diagnostics for the same manifest.

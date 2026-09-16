# deps-lsp check (GitHub Action)

A Docker-based action wrapping [`deps-cli check --format sarif`](../deps-cli/README.md). The
published image (`ghcr.io/bug-ops/deps-lsp-github-action`) already bundles a `deps-cli`
binary — no toolchain setup or `cargo install` step required. It runs the check and writes a
SARIF 2.1.0 file — it does **not** upload that file to GitHub code scanning itself (spec 062
FR-018); wire [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action)
after it in your own workflow.

> [!IMPORTANT]
> **Breaking change (Docker packaging):** this action now runs `using: docker` instead of
> `using: composite`. Docker-based actions only run on Linux runners
> (`runs-on: ubuntu-latest` or similar) — `macos-latest` and `windows-latest` are no longer
> supported, unlike the previous composite version. If your workflow ran this action on a
> non-Linux runner, move it to a Linux job. The `version` input has also been removed: the
> `deps-cli` version is now baked into the image at build time — pin a specific version via
> the image tag instead (see below).

## Usage

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
      - uses: bug-ops/deps-lsp/crates/github-action@main
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

## Image tags

The action's `image:` pins `ghcr.io/bug-ops/deps-lsp-github-action:1`, a rolling major-version
tag that tracks the latest `deps-cli` release published under `1.x.y`. It is rebuilt whenever a
new `deps-lsp`/`deps-cli` release is tagged (`.github/workflows/release.yml`). More specific
tags are also published for each release: `X`, `X.Y`, `X.Y.Z`, and `latest`.

Every image is scanned with [Trivy](https://github.com/aquasecurity/trivy) for CRITICAL/HIGH
vulnerabilities before it's pushed — a finding blocks the publish and is reported to this
repository's Security tab. Every pull request touching `crates/github-action/` is scanned the
same way, without publishing.

Per FR-018, this action only fails the job itself on `exit-code` `2` (an execution error —
`sarif-file` is left unset in that case, since the file may be missing or truncated, so the
`upload-sarif` step above is skipped automatically for you). A `--fail-on` policy violation
(`exit-code` `1`) does **not** fail the step — `sarif-file` is still produced and uploaded,
and it is your own workflow's decision whether to fail the build on it, as shown by the final
step above. Drop that step if you only want the SARIF upload, not a build failure, on a
policy violation.

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Space-separated paths to walk | `deps-cli`'s own default (repository root) |
| `fail-on` | Comma-separated categories that exit 1 (`outdated,yanked,vulnerable,unsatisfiable,mutable-ref,license,deprecated`) | `vulnerable,yanked,unsatisfiable` |
| `cooldown` | Overrides `freshness.cooldown_secs` (e.g. `3d`) | unset |
| `config` | Path to a **fully-trusted** `deps.toml` config file — see warning below | unset (`deps-cli`'s own hardened auto-discovery of `./deps.toml`) |

> [!WARNING]
> `deps-cli` treats an *explicit* `--config` path as fully trusted — unlike an
> auto-discovered `deps.toml`, which has its `registries`/`network`/`diagnostics.*_enabled`
> sections reset to safe defaults specifically because the scanned repository is not a
> trusted source for the policy that judges it. Passing `config` here re-establishes that
> full trust, so only point it at a file outside the scanned checkout and under your own
> control (e.g. a path in a separate, trusted repository checked out earlier in the job) —
> never at a path inside the checkout you are scanning, especially in a
> `pull_request_target` workflow scanning a fork.

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the produced SARIF file (`deps-lsp-results.sarif`). Set for `exit-code` `0`/`1`; unset for `2` |
| `exit-code` | `deps-cli check`'s own exit code (`0` clean, `1` a `--fail-on` category matched, `2` execution error). Always set |

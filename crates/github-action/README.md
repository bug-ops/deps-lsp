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

> [!TIP]
> Pin `uses:` to a released tag (e.g. `@v1.2.0`) rather than `@main` — `main` is a mutable ref,
> so a workflow pinned to it re-runs whatever is currently on that branch, including unreviewed
> or in-progress changes. Check the [releases page](https://github.com/bug-ops/deps-lsp/releases)
> for the latest tag.

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

## Image tags

The action's `image:` pins `ghcr.io/bug-ops/deps-lsp-github-action:1`, a rolling major-version
tag that tracks the latest `deps-cli` release published under `1.x.y`. It is rebuilt whenever a
new `deps-lsp`/`deps-cli` release is tagged (`.github/workflows/release.yml`). More specific
tags are also published for each release: `X`, `X.Y`, `X.Y.Z`, and `latest`.

Every image is scanned with [Trivy](https://github.com/aquasecurity/trivy) for CRITICAL/HIGH
vulnerabilities before it's pushed — a finding blocks the publish and is reported to this
repository's Security tab. Every pull request touching `crates/github-action/` is scanned the
same way, without publishing.

Per FR-018, this action only fails the job itself on an execution error — any exit code other
than `0` (clean) or `1` (a `--fail-on` category matched), including a `deps-cli` panic, a
missing binary, or a refused/unwritable SARIF path. `sarif-file` is left unset in that case,
since the file may be missing, truncated, or unsafe to trust, so the `upload-sarif` step above
is skipped automatically for you via its `if:` guard. A `--fail-on` policy violation
(`exit-code` `1`) does **not** fail the step — `sarif-file` is still produced and uploaded,
and it is your own workflow's decision whether to fail the build on it, as shown by the final
step above. Drop that step if you only want the SARIF upload, not a build failure, on a
policy violation.

The SARIF output path (`deps-lsp-results.sarif`) is removed before every run — including a
pre-existing regular file left by a prior step, and a symlink placed there by the scanned
checkout (#1132) — so a stale or hostile file never leaks into the result. A **directory** at
that path cannot be removed this way, so the action refuses to start before `deps-cli` even
runs; neither `sarif-file` nor `exit-code` is set in that case.

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
| `sarif-file` | Path to the produced SARIF file (`deps-lsp-results.sarif`). Set only when a non-empty regular SARIF file was produced by the run; it may be unset even when `exit-code` is `0` or `1` (e.g. an unwritable output path or an empty result), and is always unset for any other exit code (execution error) |
| `exit-code` | `deps-cli check`'s own exit code (`0` clean, `1` a `--fail-on` category matched, `2` execution error), or the raw exit code from an abnormal `deps-cli` termination. Set whenever `deps-cli` ran; unset only if the action refused to start before running it (e.g. a directory pre-placed at the SARIF output path) |

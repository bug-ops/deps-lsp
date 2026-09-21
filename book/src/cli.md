# deps-cli

`deps-cli` runs `deps-lsp`'s dependency-health checks from the command line — no editor
required. It walks a workspace, routes every manifest it finds through the exact same
14-ecosystem classification pipeline (`deps-engine`) that powers `deps-lsp`'s hover and
diagnostics, and reports outdated/yanked/vulnerable/unsatisfiable/deprecated/license/
mutable-ref-pin findings as a table, as JSON, or as SARIF 2.1.0, with a CI-friendly exit
code.

> **Note:** `deps-cli` implements no classification logic of its own — every verdict comes
> from the same function `deps-lsp` calls for its LSP diagnostics, so a `deps-cli check`
> result and an editor's diagnostics for the same manifest never disagree.

## Installation

```bash
cargo install deps-cli
```

Or, without a Rust toolchain, the install script detects your OS/architecture, downloads
the matching release archive, verifies its SHA256 checksum, and installs to
`${CARGO_HOME:-~/.cargo}/bin` (falling back to `~/.local/bin`):

```bash
curl -fsSL https://raw.githubusercontent.com/bug-ops/deps-lsp/main/scripts/install-deps-cli.sh | sh
```

Pin a release with `--tag <version>` (or `DEPS_CLI_VERSION`); override the install directory
with `--install-dir <dir>` (or `DEPS_CLI_INSTALL_DIR`). The script does not support Windows —
download the `.zip` asset from [GitHub Releases](https://github.com/bug-ops/deps-lsp/releases/latest)
instead. Pre-built binaries are published for 8 targets: Linux x86_64/aarch64 (glibc and
musl), macOS x86_64/Apple Silicon, and Windows x86_64/ARM64.

### Docker

The image published for the [GitHub Action](#github-action) below
(`ghcr.io/bug-ops/deps-lsp-github-action`) also bundles a prebuilt `deps-cli` binary, fetched
from the matching GitHub release and SHA256-verified at build time — no Rust toolchain to
install, and nothing to trust beyond the image itself. Its default `ENTRYPOINT` is hardcoded to
the GitHub Action's own contract (`deps-cli check --format sarif`, driven by `DEPS_CLI_*` env
vars — see [GitHub Action](#github-action)), so running `deps-cli` directly means overriding it:

```bash
docker run --rm -v "$PWD:/workspace" -w /workspace \
  --entrypoint deps-cli ghcr.io/bug-ops/deps-lsp-github-action:1 check
```

Mount the directory you want to scan at `/workspace`, then pass any normal `deps-cli`
subcommand and flags after `check` — table output by default, or `--format json`/
`--format sarif` as described under [Output formats](#output-formats). The image is
Alpine-based, built for `linux/amd64` and `linux/arm64`, and tagged `latest`, major (`X`),
minor (`X.Y`), and exact (`X.Y.Z`) — `ghcr.io/bug-ops/deps-lsp-github-action:1` tracks the
latest `1.x.y` release, the same tag `action.yml` pins for the GitHub Action itself.

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
```

`check` is currently the only subcommand. Paths default to the current directory when
none are given.

### Output formats

- **`table`** (default) — human-readable, grouped by file then severity.
- **`json`** — a versioned document (`schema_version`, currently `1`) with a `findings`
  array and a per-category `summary` count map; `schema_version` is bumped, and the bump
  documented as `Breaking` in `CHANGELOG.md`, whenever a field is renamed or removed.
- **`sarif`** — a SARIF 2.1.0 document. A vulnerability finding becomes its own SARIF rule
  (keyed by its OSV advisory id, e.g. `RUSTSEC-...`/`GHSA-...`) with a `helpUri` to the
  advisory page and a `security-severity` score; every other category collapses to one rule
  per category token. Each result carries a `partialFingerprints` entry derived from
  manifest path, dependency identity, rule id, and an occurrence ordinal — not the line
  range — so an unrelated line shift elsewhere in the file doesn't make GitHub treat an
  existing alert as new.

### `--fail-on` categories and exit codes

`--fail-on` takes a comma-separated list of: `outdated`, `yanked`, `vulnerable`,
`unsatisfiable`, `mutable-ref`, `license`, `deprecated`. It defaults to
`vulnerable,yanked,unsatisfiable` when omitted. A finding that matches none of these seven
(e.g. an unresolved/unknown package) is always reported but can never fail a run through
this flag.

| Exit code | Meaning |
|---|---|
| `0` | Clean — no finding matched the `--fail-on` policy |
| `1` | Policy violation — at least one finding matched `--fail-on` |
| `2` | Execution error — a registry was unreachable, a `deps.toml`/manifest failed to parse, or a walked path was unreadable |

A real policy violation (`1`) always takes precedence over an unrelated execution error
elsewhere in the run — one malformed manifest in a large workspace never hides a genuine
`--fail-on` hit behind a less specific `2`.

## Workspace walk and symlink handling

`check` does **not** honor `.gitignore`/`.ignore` by default. In a CI gate
(`git checkout && deps-cli check .` against an untrusted fork PR), both files are
attacker-controlled input — a one-line addition to either would otherwise silently drop a
manifest from the scan with no warning and exit code `0`. A compiled-in denylist
(`node_modules`, `target`, `vendor`, `.venv`, and other common dependency/build/VCS
directories) still keeps the scan fast without depending on either file. Pass
`--respect-gitignore` to restore standard `.gitignore`/`.ignore` awareness when scanning a
target you trust as much as your own `deps.toml`.

A manifest reachable only through a symlink is detected and reported (a warning, non-zero
exit code) regardless of this flag; it is not resolved and scanned unless
`--follow-symlinks` is also passed. A symlink whose resolved, canonicalized target falls
outside the walked root is never followed, and the walk is bounded so a symlink loop can't
run unbounded, regardless of the flag.

A single `check` invocation inspects at most 50,000 files across every walked root; beyond
that the walk stops and the report is marked truncated rather than silently
under-reporting.

## Configuration (`deps.toml`)

`deps-cli` reuses `deps-lsp`'s own `PolicyConfig` schema — the same `diagnostics`, `cache`,
`freshness`, `supply_chain`, `registries`, `network`, and `license_policy` sections
documented in [Configuration](configuration.md) — loaded from a `deps.toml` file instead of
LSP `initializationOptions`:

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

`deps-cli` looks for `./deps.toml` relative to the walked root when `--config` is not
given. `--offline` and `--cooldown` override the loaded config for that run only.

> **Warning:** An auto-discovered `deps.toml` — found by the default lookup, not passed
> explicitly via `--config` — has its `registries`, `network`, and
> `diagnostics.*_enabled` sections (and cache/freshness/license_policy/supply_chain) reset
> to their safe defaults before use; only the six `*_severity` display values are kept
> (they're cosmetic and can never suppress a `--fail-on` match). This is deliberate: the
> repository a CI job is checking is not a trusted source for the policy that judges it. A
> checked-in `deps.toml` on an attacker-controlled branch must not be able to disable the
> vulnerability scan, force `network.offline` to hide every registry/OSV-derived finding, or
> redirect `GITLAB_TOKEN` to another host via `registries.gitlab_instance_host`. Any section
> ignored this way is named in a warning on stderr. Only a config path given explicitly via
> `--config` — the operator's own choice, not the scanned repository's — is trusted in
> full.

## Pre-commit hook

This repository ships a [`.pre-commit-hooks.yaml`](https://github.com/bug-ops/deps-lsp/blob/main/.pre-commit-hooks.yaml)
at its root defining a `deps-lsp-check` hook (`language: system`, `entry: deps-cli check`).
`language: system` means pre-commit installs nothing for this hook — `deps-cli` must
already be on `PATH` (the [install script](#installation) or `cargo install deps-cli` both
work).

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bug-ops/deps-lsp
    rev: <tag>
    hooks:
      - id: deps-lsp-check
```

## GitHub Action

[`crates/github-action`](https://github.com/bug-ops/deps-lsp/blob/main/crates/github-action)
is a Docker-based action wrapping `deps-cli check --format sarif`. The published image
(`ghcr.io/bug-ops/deps-lsp-github-action`) already bundles a `deps-cli` binary — no toolchain
setup or install step required. It runs the check and writes a SARIF file — it does **not**
upload it to GitHub code scanning itself; wire `github/codeql-action/upload-sarif` after it in
your own workflow. Every published image is Trivy-scanned for CRITICAL/HIGH vulnerabilities
before publish, and on every PR touching `crates/github-action/`.

> **Note:** Docker-based actions only run on Linux runners (`runs-on: ubuntu-latest` or
> similar) — `macos-latest` and `windows-latest` are not supported.

> **Tip:** Pin `uses:` to a released tag (e.g. `@v1.2.0`) rather than `@main` — `main` is a
> mutable ref, so a workflow pinned to it re-runs whatever is currently on that branch,
> including unreviewed or in-progress changes.

```yaml
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
        with:
          sarif_file: ${{ steps.deps-check.outputs.sarif-file }}
      - name: Fail the build on a policy violation
        if: steps.deps-check.outputs.exit-code == '1'
        run: exit 1
```

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Space-separated paths to walk | repository root |
| `fail-on` | Comma-separated categories that exit 1 | `vulnerable,yanked,unsatisfiable` |
| `cooldown` | Overrides `freshness.cooldown_secs` (e.g. `3d`) | unset |
| `config` | Path to a **fully-trusted** `deps.toml` — see warning below | unset |

The `deps-cli` version is baked into the image at build time — pin a specific version via the
image tag (`ghcr.io/bug-ops/deps-lsp-github-action:X.Y.Z`) instead of a `version` input.

The action only fails the job itself on an execution error — any exit code other than `0`
(clean) or `1` (a `--fail-on` category matched), including a `deps-cli` panic or a refused
SARIF output path. `sarif-file` is left unset in that case, since the file may be missing or
truncated, but it can also be unset at `exit-code` `0` or `1` if the output path couldn't be
written. A `--fail-on` policy violation (`exit-code` `1`) does not fail the step; `sarif-file`
is otherwise still produced and uploaded, and it's your own workflow's decision whether to
fail the build on it, as shown above.

> **Warning:** the `config` input is treated as fully trusted, unlike an auto-discovered
> `deps.toml` — only point it at a file outside the scanned checkout and under your own
> control, never at a path inside the checkout you're scanning, especially in a
> `pull_request_target` workflow scanning a fork.
